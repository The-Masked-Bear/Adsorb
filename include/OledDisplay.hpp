#pragma once

#include <Arduino.h>
#include <U8g2lib.h>
#include <WiFi.h>

#include "Config.hpp"
#include "DnsCache.hpp"
#include "EncryptedDns.hpp"

// ============================================================================
// Physical 1.3" I2C OLED Status Display Engine (SH1106 / SSD1306 128x64)
// High-Density Telemetry Carousel with I2C Auto-Detection & Hot-Plug Safety
// ============================================================================
class OledDisplay {
public:
    OledDisplay()
        : _u8g2(U8G2_R0, /* clock=*/ Config::OLED_SCL_PIN, /* data=*/ Config::OLED_SDA_PIN, /* reset=*/ U8X8_PIN_NONE) {}

    bool begin() {
        // Physical detection: OLED breakout modules feature 4.7k - 10k pullup resistors to VCC (3.3V).
        // By setting internal weak pulldowns (~45k), a connected OLED will pull the lines HIGH.
        pinMode(Config::OLED_SDA_PIN, INPUT_PULLDOWN);
        pinMode(Config::OLED_SCL_PIN, INPUT_PULLDOWN);
        delay(10);

        bool hasOledPullup = (digitalRead(Config::OLED_SDA_PIN) == HIGH && digitalRead(Config::OLED_SCL_PIN) == HIGH);

        // Restore pins to high-impedance input
        pinMode(Config::OLED_SDA_PIN, INPUT);
        pinMode(Config::OLED_SCL_PIN, INPUT);

        if (!hasOledPullup) {
            Serial.printf("[OLED] Notice: No physical I2C display detected on SDA:%d SCL:%d (Gracefully idling)\n",
                          Config::OLED_SDA_PIN, Config::OLED_SCL_PIN);
            _connected = false;
            return false;
        }

        _connected = true;
        _u8g2.begin();
        _u8g2.setContrast(255); // Maximum contrast

        // Draw Startup Splash
        _u8g2.clearBuffer();
        _u8g2.setFont(u8g2_font_7x14B_tf);
        _u8g2.drawStr(16, 18, "ADSORB v1.2");
        _u8g2.setFont(u8g2_font_6x10_tf);
        _u8g2.drawStr(12, 34, "ESP32-S3 N16R8");
        _u8g2.drawStr(10, 48, "128b SIMD + TRNG");
        _u8g2.drawFrame(0, 56, 128, 6);
        _u8g2.drawBox(2, 58, 124, 2);
        _u8g2.sendBuffer();

        Serial.printf("[OLED] 1.3\" I2C OLED initialized on SDA:%d SCL:%d (SH1106)\n",
                      Config::OLED_SDA_PIN, Config::OLED_SCL_PIN);
        return true;
    }

    bool isConnected() const { return _connected; }

    // -----------------------------------------------------------------------
    // Render Multi-Screen Telemetry Carousel
    // -----------------------------------------------------------------------
    void render(uint32_t totalQueries, uint32_t blockedQueries,
                const DnsCache& cache, const EncryptedDns& doh) {
        if (!_connected) return;

        uint32_t now = millis();
        if (now - _lastPageSwitch >= Config::OLED_PAGE_CYCLE_MS) {
            _lastPageSwitch = now;
            _screenPage = (_screenPage + 1) % 3;
        }

        _u8g2.clearBuffer();

        switch (_screenPage) {
            case 0: _renderDashboard(totalQueries, blockedQueries, cache); break;
            case 1: _renderCacheAndDoh(cache, doh); break;
            case 2: _renderSiliconMetrics(); break;
        }

        _u8g2.sendBuffer();
    }

private:
    U8G2_SH1106_128X64_NONAME_F_SW_I2C _u8g2;
    bool _connected = false;
    uint8_t _screenPage = 0;
    uint32_t _lastPageSwitch = 0;

    // -----------------------------------------------------------------------
    // Screen 0: Executive Status Dashboard
    // -----------------------------------------------------------------------
    void _renderDashboard(uint32_t total, uint32_t blocked, const DnsCache& cache) {
        // Top Header Bar
        _u8g2.drawBox(0, 0, 128, 11);
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.setDrawColor(0); // Inverted text
        _u8g2.drawStr(2, 8, "ADSORB v1.2 SINK");
        if (WiFi.isConnected()) {
            _u8g2.drawStr(98, 8, "ONLINE");
        } else {
            _u8g2.drawStr(98, 8, "NO-NET");
        }
        _u8g2.setDrawColor(1); // Normal draw color

        // Row 1: IP Address
        _u8g2.setFont(u8g2_font_6x10_tf);
        char ipBuf[32];
        snprintf(ipBuf, sizeof(ipBuf), "IP: %s", WiFi.isConnected() ? WiFi.localIP().toString().c_str() : "Connecting...");
        _u8g2.drawStr(2, 23, ipBuf);

        // Row 2: Blocked Rate & Counts
        float blockRate = total > 0 ? ((float)blocked / (float)total) * 100.0f : 0.0f;
        char blkBuf[32];
        snprintf(blkBuf, sizeof(blkBuf), "BLK: %u (%.1f%%)", blocked, blockRate);
        _u8g2.drawStr(2, 36, blkBuf);

        // Row 3: PSRAM Cache Hit Rate
        char cacheBuf[32];
        snprintf(cacheBuf, sizeof(cacheBuf), "RAM CACHE: %.1f%%", cache.getHitRatePercent());
        _u8g2.drawStr(2, 49, cacheBuf);

        // Footer: Total Queries & mDNS Hostname
        _u8g2.setFont(u8g2_font_4x6_tf);
        char qBuf[32];
        snprintf(qBuf, sizeof(qBuf), "TOTAL: %u | adsorb.local", total);
        _u8g2.drawStr(2, 60, qBuf);

        // Page Indicator Dots
        _drawPageDots(0);
    }

    // -----------------------------------------------------------------------
    // Screen 1: PSRAM LRU Cache & Encrypted DoH Telemetry
    // -----------------------------------------------------------------------
    void _renderCacheAndDoh(const DnsCache& cache, const EncryptedDns& doh) {
        _u8g2.drawBox(0, 0, 128, 11);
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.setDrawColor(0);
        _u8g2.drawStr(2, 8, "PSRAM CACHE + DoH");
        _u8g2.drawStr(94, 8, "<0.2ms");
        _u8g2.setDrawColor(1);

        _u8g2.setFont(u8g2_font_6x10_tf);
        char buf[32];

        // Cache Entries
        snprintf(buf, sizeof(buf), "ENTRIES: %u / %u", cache.getActiveCount(), (unsigned)Config::DNS_CACHE_CAPACITY);
        _u8g2.drawStr(2, 23, buf);

        // Cache Hits
        snprintf(buf, sizeof(buf), "RAM HITS: %u", cache.getTotalHits());
        _u8g2.drawStr(2, 36, buf);

        // Upstream Status
        const char* modeLabel = (Config::UPSTREAM_MODE == Config::UPSTREAM_MODE_DOH) ? "UPSTREAM: DoH TLS" : "UPSTREAM: RACE UDP";
        _u8g2.drawStr(2, 49, modeLabel);

        // Telemetry Subtext: Hardware TRNG & 128-bit SIMD Accelerator
        _u8g2.setFont(u8g2_font_4x6_tf);
        snprintf(buf, sizeof(buf), "TRNG: HW-RND | SIMD: 128b PIE");
        _u8g2.drawStr(2, 60, buf);

        _drawPageDots(1);
    }

    // -----------------------------------------------------------------------
    // Screen 2: ESP32-S3 Hardware Silicon Metrics
    // -----------------------------------------------------------------------
    void _renderSiliconMetrics() {
        _u8g2.drawBox(0, 0, 128, 11);
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.setDrawColor(0);
        _u8g2.drawStr(2, 8, "SILICON v1.2 TELEM");
        _u8g2.drawStr(88, 8, "240 MHz");
        _u8g2.setDrawColor(1);

        _u8g2.setFont(u8g2_font_6x10_tf);
        char buf[32];

        // Free PSRAM
        float freePsramMb = ESP.getFreePsram() / (1024.0f * 1024.0f);
        snprintf(buf, sizeof(buf), "PSRAM: %.2f MB FREE", freePsramMb);
        _u8g2.drawStr(2, 23, buf);

        // Free SRAM Heap
        snprintf(buf, sizeof(buf), "SRAM : %u KB FREE", ESP.getFreeHeap() / 1024);
        _u8g2.drawStr(2, 36, buf);

        // Static IP & Hostname
        snprintf(buf, sizeof(buf), "STATIC: 192.168.1.101");
        _u8g2.drawStr(2, 49, buf);

        // Cores & WiFi RSSI
        _u8g2.setFont(u8g2_font_4x6_tf);
        snprintf(buf, sizeof(buf), "XTENSA DUAL-CORE | %d dBm", WiFi.isConnected() ? WiFi.RSSI() : 0);
        _u8g2.drawStr(2, 60, buf);

        _drawPageDots(2);
    }

    void _drawPageDots(uint8_t activePage) {
        for (uint8_t i = 0; i < 3; ++i) {
            int x = 114 + (i * 4);
            int y = 58;
            if (i == activePage) {
                _u8g2.drawDisc(x, y, 1);
            } else {
                _u8g2.drawPixel(x, y);
            }
        }
    }
};
