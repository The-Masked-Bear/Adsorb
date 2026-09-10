#pragma once

#include <Arduino.h>

namespace Config {

// Firmware metadata
constexpr const char* FIRMWARE_VERSION = "1.2.0";
constexpr const char* FIRMWARE_NAME    = "ESP32-S3 High-Performance DNS Ad Blocker";
constexpr uint32_t    SERIAL_BAUD_RATE = 115200;

// Hardware specifications
constexpr uint32_t FLASH_SIZE_BYTES    = 16777216; // 16 MB
constexpr uint32_t PSRAM_SIZE_BYTES    = 8388608;  // 8 MB
constexpr size_t   PSRAM_TEST_BYTES    = 512 * 1024; // 512 KB

#if __has_include("credentials.h")
#include "credentials.h"
#else
// Wi-Fi Station Configuration (Replace with your Wi-Fi credentials)
constexpr const char* WIFI_SSID        = "YOUR_WIFI_SSID";
constexpr const char* WIFI_PASSWORD    = "YOUR_WIFI_PASSWORD";
#endif
constexpr uint32_t    WIFI_CONNECT_TIMEOUT_MS = 10000; // 10s connection timeout before fallback

// Static IP Configuration (Guarantees zero DNS interruptions at 192.168.1.101)
constexpr bool        USE_STATIC_IP          = true;
const IPAddress       STATIC_IP(192, 168, 1, 101);
const IPAddress       STATIC_GATEWAY(192, 168, 1, 1);
const IPAddress       STATIC_SUBNET(255, 255, 255, 0);
const IPAddress       STATIC_DNS_PRIMARY(1, 1, 1, 1);
const IPAddress       STATIC_DNS_SECONDARY(8, 8, 8, 8);

// Zero-Config mDNS & Captive Portal
constexpr const char* MDNS_HOSTNAME          = "adsorb"; // http://adsorb.local/

// Wi-Fi Access Point (Fallback) Configuration
constexpr const char* AP_SSID          = "ESP32-DNS-AdBlocker";
constexpr const char* AP_PASSWORD      = "admin1234";
constexpr uint8_t     AP_CHANNEL       = 1;
constexpr uint8_t     AP_MAX_CLIENTS   = 4;

// Network Services
constexpr uint16_t    DNS_PORT         = 53;
constexpr uint16_t    WEB_PORT         = 80;
constexpr const char* UPSTREAM_DNS_PRIMARY   = "1.1.1.1";
constexpr const char* UPSTREAM_DNS_SECONDARY = "8.8.8.8";


// Filesystem Paths (LittleFS)
constexpr const char* FS_MOUNT_POINT         = "/littlefs";
constexpr const char* PATH_ADS_DOMAINS       = "/ads-domains.txt";
constexpr const char* PATH_ADS_DOMAINS_2     = "/ad-domains2.0.txt";
constexpr const char* PATH_ADS_DOMAINS_2_ALT = "/ad-domains2.0";
constexpr const char* PATH_CUSTOM_WHITELIST  = "/custom_whitelist.txt";
constexpr const char* PATH_CUSTOM_BLACKLIST  = "/custom_blacklist.txt";

// Task & Multi-Core FreeRTOS Configuration
constexpr BaseType_t  CORE_SYSTEM_WEB  = 0; // Core 0: Wi-Fi, Web Server, LittleFS, System
constexpr BaseType_t  CORE_DNS_ENGINE  = 1; // Core 1: Real-time UDP 53 DNS Engine
constexpr UBaseType_t PRIORITY_SYSTEM  = 1;
constexpr UBaseType_t PRIORITY_DNS     = 5;

// Ring Buffer & Cache Configuration
constexpr size_t      RING_BUFFER_CAPACITY = 1000;

// PSRAM LRU DNS Cache Configuration
constexpr size_t      DNS_CACHE_CAPACITY   = 2048; // 2,048 entries in Octal PSRAM (~1.1 MB)
constexpr uint32_t    DNS_CACHE_MIN_TTL    = 30;   // Minimum TTL 30s
constexpr uint32_t    DNS_CACHE_MAX_TTL    = 86400; // Maximum TTL 24h

// Encrypted & High-Speed Upstream DNS Configuration
enum UpstreamMode {
    UPSTREAM_MODE_PARALLEL_UDP, // Ultra-Fast Parallel UDP 53 (1.1.1.1 + 8.8.8.8) [Default - Highest Speed & Reliability]
    UPSTREAM_MODE_DOH           // Encrypted DNS-over-HTTPS (RFC 8484) with fast parallel fallback
};
constexpr UpstreamMode UPSTREAM_MODE          = UPSTREAM_MODE_PARALLEL_UDP;
constexpr uint32_t     UPSTREAM_UDP_TIMEOUT_MS = 800;  // 800ms parallel race timeout (prevents Wi-Fi packet drop)
constexpr const char*  DOH_PRIMARY_URL         = "https://1.1.1.1/dns-query";
constexpr const char*  DOH_SECONDARY_URL       = "https://8.8.8.8/dns-query";
constexpr uint32_t     DOH_TIMEOUT_MS          = 400;  // 400ms max before fast UDP fallback

// Physical 1.3" I2C OLED Display Configuration (SH1106 / SSD1306 128x64)
constexpr int         OLED_SDA_PIN         = 8;  // Default ESP32-S3 I2C SDA
constexpr int         OLED_SCL_PIN         = 9;  // Default ESP32-S3 I2C SCL
constexpr uint8_t     OLED_I2C_ADDR        = 0x3C; // Standard I2C address (0x3C or 0x3D)
constexpr uint32_t    OLED_REFRESH_MS      = 1000; // 1s refresh interval
constexpr uint32_t    OLED_PAGE_CYCLE_MS   = 5000; // Cycle telemetry screens every 5s

} // namespace Config
