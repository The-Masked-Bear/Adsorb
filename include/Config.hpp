#pragma once

#include <Arduino.h>

namespace Config {

// Firmware metadata
constexpr const char* FIRMWARE_VERSION = "1.0.0";
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

} // namespace Config
