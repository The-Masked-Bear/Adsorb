/**
 * ============================================================================
 * ESP32-S3 N16R8 High-Performance DNS Ad Blocker
 * Full Firmware: DNS Sinkhole + Web Dashboard + PSRAM Blocklist
 * ============================================================================
 * Hardware: ESP32-S3 (Dual-Core LX7 @ 240MHz), 16MB Flash, 8MB Octal PSRAM
 * Architecture:
 *   Core 1 (High Priority): DNS Engine — UDP port 53 packet processing
 *   Core 0 (Normal Priority): Wi-Fi, Web Dashboard, LittleFS, System
 * ============================================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp32-hal-psram.h>

#include "Config.hpp"
#include "Blocklist.hpp"
#include "DnsServer.hpp"
#include "DnsCache.hpp"
#include "EncryptedDns.hpp"
#include "OledDisplay.hpp"
#include "WebDashboard.hpp"

// ============================================================================
// Global Instances
// ============================================================================
static Blocklist    g_blocklist;
static DnsCache     g_cache;
static EncryptedDns g_encryptedDns;
static OledDisplay  g_oled;
static DnsEngine    g_dns;
static WebDashboard g_dashboard;

// FreeRTOS task handles
static TaskHandle_t g_dnsTaskHandle = nullptr;
static TaskHandle_t g_oledTaskHandle = nullptr;

// ============================================================================
// DNS Engine Task — Pinned to Core 1 (Real-Time)
// ============================================================================
static void dnsTask(void* param) {
    Serial.printf("[DNS Task] Started on Core %d (Priority %d)\n",
                  xPortGetCoreID(), uxTaskPriorityGet(nullptr));

    for (;;) {
        if (!g_dns.processPacket()) {
            vTaskDelay(pdMS_TO_TICKS(1));
        } else {
            taskYIELD();
        }
    }
}

// ============================================================================
// OLED Display Task — Pinned to Core 0 (Low Priority UI Telemetry)
// ============================================================================
static void oledTask(void* param) {
    Serial.printf("[OLED Task] Started on Core %d (Priority %d)\n",
                  xPortGetCoreID(), uxTaskPriorityGet(nullptr));

    for (;;) {
        g_oled.render(g_dns.totalQueries, g_dns.blockedQueries, g_cache, g_encryptedDns);
        vTaskDelay(pdMS_TO_TICKS(Config::OLED_REFRESH_MS));
    }
}

// ============================================================================
// Hardware Boot Banner
// ============================================================================
static void printBootBanner() {
    Serial.println();
    Serial.println("================================================================================");
    Serial.println("  ESP32-S3 N16R8 High-Performance DNS Ad Blocker");
    Serial.printf("  Firmware: %s v%s\n", Config::FIRMWARE_NAME, Config::FIRMWARE_VERSION);
    Serial.println("  Build: " __DATE__ " " __TIME__);
    Serial.println("================================================================================");
    Serial.printf("  Chip: %s | CPU: %u MHz | Cores: 2\n", ESP.getChipModel(), ESP.getCpuFreqMHz());

    if (psramFound()) {
        Serial.printf("  PSRAM: %.2f MB detected (Free: %.2f MB)\n",
                      ESP.getPsramSize() / (1024.0f * 1024.0f),
                      ESP.getFreePsram() / (1024.0f * 1024.0f));
    } else {
        Serial.println("  [CRITICAL] PSRAM NOT DETECTED! Check board configuration.");
    }

    Serial.printf("  Flash: %.2f MB | Mode: QIO\n", ESP.getFlashChipSize() / (1024.0f * 1024.0f));
    Serial.println("================================================================================");
}

// ============================================================================
// Wi-Fi Connection (Station mode with AP fallback)
// ============================================================================
static bool connectWiFi() {
    Serial.printf("[WiFi] Connecting to '%s'...\n", Config::WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.setHostname("esp32-adblocker");
    WiFi.begin(Config::WIFI_SSID, Config::WIFI_PASSWORD);

    uint32_t start = millis();
    while (millis() - start < Config::WIFI_CONNECT_TIMEOUT_MS) {
        if (WiFi.status() == WL_CONNECTED) {
            Serial.printf("[WiFi] Connected!\n");
            Serial.printf("[WiFi]   IP Address : %s\n", WiFi.localIP().toString().c_str());
            Serial.printf("[WiFi]   Gateway    : %s\n", WiFi.gatewayIP().toString().c_str());
            Serial.printf("[WiFi]   DNS        : %s\n", WiFi.dnsIP().toString().c_str());
            Serial.printf("[WiFi]   RSSI       : %d dBm\n", WiFi.RSSI());
            Serial.printf("[WiFi]   MAC        : %s\n", WiFi.macAddress().c_str());
            configTime(0, 0, "216.239.35.0", "129.6.15.28", "time.google.com");
            uint32_t startNtp = millis();
            while (time(nullptr) < 1700000000 && (millis() - startNtp < 3000)) {
                delay(100);
            }
            Serial.printf("[NTP] Current epoch: %lu\n", (unsigned long)time(nullptr));
            return true;
        }
        delay(500);
        Serial.print(".");
    }
    Serial.println();

    // Fallback to AP mode
    Serial.printf("[WiFi] Station timeout. Starting AP '%s'...\n", Config::AP_SSID);
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP(Config::AP_SSID, Config::AP_PASSWORD, Config::AP_CHANNEL, 0, Config::AP_MAX_CLIENTS);
    Serial.printf("[WiFi] AP active at %s\n", WiFi.softAPIP().toString().c_str());

    // Keep trying station in background
    WiFi.begin(Config::WIFI_SSID, Config::WIFI_PASSWORD);
    return false;
}

// ============================================================================
// LittleFS Initialization
// ============================================================================
static bool initFilesystem() {
    Serial.println("[FS] Mounting LittleFS...");

    if (!LittleFS.begin(true, Config::FS_MOUNT_POINT, 10, "littlefs")) {
        // Try with "spiffs" label (partition table uses subtype spiffs)
        if (!LittleFS.begin(true, Config::FS_MOUNT_POINT, 10, "spiffs")) {
            Serial.println("[FS] FATAL: LittleFS mount failed!");
            return false;
        }
    }

    size_t total = LittleFS.totalBytes();
    size_t used  = LittleFS.usedBytes();
    Serial.printf("[FS] Mounted! Total: %.2f MB | Used: %.2f MB | Free: %.2f MB\n",
                  total / (1024.0f * 1024.0f),
                  used / (1024.0f * 1024.0f),
                  (total - used) / (1024.0f * 1024.0f));

    // Check for blocklist file
    if (LittleFS.exists(Config::PATH_ADS_DOMAINS)) {
        File f = LittleFS.open(Config::PATH_ADS_DOMAINS, "r");
        Serial.printf("[FS] Blocklist file found: %s (%u bytes)\n",
                      Config::PATH_ADS_DOMAINS, (unsigned)f.size());
        f.close();
    } else {
        Serial.printf("[FS] WARNING: Blocklist file '%s' not found!\n", Config::PATH_ADS_DOMAINS);
        Serial.println("[FS]          Upload via: python -m platformio run --target uploadfs");
    }

    return true;
}

// ============================================================================
// Arduino Setup — Runs on Core 0
// ============================================================================
void setup() {
    Serial.begin(Config::SERIAL_BAUD_RATE);
    delay(1500); // Allow USB-UART to stabilize

    printBootBanner();

    // 1. Initialize Physical 1.3" I2C OLED Display (Early splash screen)
    g_oled.begin();

    // 2. Verify PSRAM
    if (!psramFound()) {
        Serial.println("[BOOT] CRITICAL: No PSRAM! Cannot operate. Halting.");
        while (true) delay(1000);
    }

    // 3. Connect to Wi-Fi
    connectWiFi();

    // 4. Mount LittleFS
    if (!initFilesystem()) {
        Serial.println("[BOOT] CRITICAL: Filesystem failed! Halting.");
        while (true) delay(1000);
    }

    // 5. Initialize PSRAM LRU DNS Cache (Sub-millisecond repeat queries)
    Serial.println();
    if (!g_cache.begin()) {
        Serial.println("[BOOT] WARNING: DNS Cache failed to allocate in PSRAM.");
    }

    // 6. Initialize Encrypted Upstream DNS (RFC 8484 DoH)
    Serial.println();
    g_encryptedDns.begin();

    // 7. Initialize Blocklist (loads domains into PSRAM hash set)
    Serial.println();
    if (!g_blocklist.init()) {
        Serial.println("[BOOT] WARNING: Blocklist loaded 0 domains. DNS will forward all queries.");
    }

    // 8. Start DNS Engine with PSRAM Cache & DoH Upstream
    Serial.println();
    if (!g_dns.begin(g_blocklist, &g_cache, &g_encryptedDns)) {
        Serial.println("[BOOT] CRITICAL: DNS engine failed to start! Halting.");
        while (true) delay(1000);
    }

    // 9. Start Web Dashboard
    Serial.println();
    g_dashboard.begin(g_dns, g_blocklist, &g_cache, &g_encryptedDns, &g_oled);

    // 10. Launch DNS task on Core 1 (real-time high priority)
    Serial.println();
    xTaskCreatePinnedToCore(
        dnsTask,                    // Task function
        "DNS_Engine",               // Name
        8192,                       // Stack size (bytes)
        nullptr,                    // Parameter
        Config::PRIORITY_DNS,       // Priority (5 = high)
        &g_dnsTaskHandle,           // Handle
        Config::CORE_DNS_ENGINE     // Core 1
    );

    // 11. Launch OLED task on Core 0 (low priority UI telemetry)
    if (g_oled.isConnected()) {
        xTaskCreatePinnedToCore(
            oledTask,
            "OLED_Display",
            4096,
            nullptr,
            Config::PRIORITY_SYSTEM,
            &g_oledTaskHandle,
            Config::CORE_SYSTEM_WEB
        );
    }

    Serial.println("================================================================================");
    Serial.println("  SYSTEM READY — DNS Ad Blocker is operational!");
    Serial.printf("  Set your router/device DNS to: %s\n",
                  (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString().c_str()
                                                   : WiFi.softAPIP().toString().c_str());
    Serial.printf("  Dashboard : http://%s/\n",
                  (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString().c_str()
                                                   : WiFi.softAPIP().toString().c_str());
    Serial.printf("  Blocking  : %u domains in Octal PSRAM\n",
                  (unsigned)g_blocklist.blockedCount());
    Serial.printf("  RAM Cache : %u entries in Octal PSRAM (<0.2ms latency)\n",
                  (unsigned)Config::DNS_CACHE_CAPACITY);
    Serial.printf("  Upstream  : %s (%s / %s)\n",
                  (Config::UPSTREAM_MODE == Config::UPSTREAM_MODE_DOH) ? "Encrypted DoH" : "Plain UDP",
                  Config::DOH_PRIMARY_URL, Config::UPSTREAM_DNS_PRIMARY);
    Serial.printf("  OLED 1.3\" : %s (SDA:%d, SCL:%d)\n",
                  g_oled.isConnected() ? "ACTIVE (SH1106)" : "DISCONNECTED (Idling)",
                  Config::OLED_SDA_PIN, Config::OLED_SCL_PIN);
    Serial.println("================================================================================");
}

// ============================================================================
// Arduino Loop — Runs on Core 0 (Web Dashboard + System Monitoring)
// ============================================================================
void loop() {
    // Handle web dashboard requests
    g_dashboard.handleClient();

    // Periodic heartbeat every 30 seconds
    static uint32_t lastHeartbeat = 0;
    if (millis() - lastHeartbeat >= 30000) {
        lastHeartbeat = millis();

        Serial.printf("[STATUS] Uptime: %lus | Queries: %u (Blocked: %u, %.1f%%) | "
                      "Heap: %uKB | PSRAM: %.1fMB | WiFi: %s\n",
                      (unsigned long)(millis() / 1000),
                      g_dns.totalQueries,
                      g_dns.blockedQueries,
                      (g_dns.totalQueries > 0) ?
                          (100.0f * g_dns.blockedQueries / g_dns.totalQueries) : 0.0f,
                      ESP.getFreeHeap() / 1024,
                      ESP.getFreePsram() / (1024.0f * 1024.0f),
                      (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString().c_str() : "AP Mode");
    }

    // Wi-Fi reconnection check every 60 seconds
    static uint32_t lastWifiCheck = 0;
    if (millis() - lastWifiCheck >= 60000) {
        lastWifiCheck = millis();
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println("[WiFi] Disconnected! Attempting reconnection...");
            WiFi.reconnect();
        }
    }

    delay(1); // Yield to FreeRTOS scheduler
}
