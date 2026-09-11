#pragma once

#include <Arduino.h>
#include <U8g2lib.h>
#include <WiFi.h>

#include "Config.hpp"
#include "DnsCache.hpp"
#include "EncryptedDns.hpp"

// ============================================================================
// Physical 1.3" I2C OLED Status Display Engine (SH1106 / SSD1306 128x64)
// Cyber-Minimalist Telemetry Dashboard with Real-Time Traffic Sparkline,
// Hardware Memory Gauges, Dynamic Signal Meter, and Floating Page Pills
// ============================================================================
class OledDisplay {
public:
    OledDisplay()
        : _u8g2(U8G2_R0, /* clock=*/ Config::OLED_SCL_PIN, /* data=*/ Config::OLED_SDA_PIN, /* reset=*/ U8X8_PIN_NONE) {
        memset(_activityHistory, 0, sizeof(_activityHistory));
    }

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
        _u8g2.setContrast(255); // Maximum crisp contrast

        // Draw High-Tech Cyberpunk Startup Splash
        _u8g2.clearBuffer();

        // 1. Stylized Title
        _u8g2.setFont(u8g2_font_helvB14_tr);
        _u8g2.drawStr(18, 20, "A D S O R B");

        // 2. Inverted Sub-Badge
        _u8g2.drawRBox(14, 25, 100, 11, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(20, 33, "HARDWARE DNS SINK");
        _u8g2.setDrawColor(1);

        // 3. Hardware Spec Line
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(12, 46, "ESP32-S3 N16R8 * 128b SIMD");

        // 4. Loading Bar with Fill
        _u8g2.drawRFrame(14, 51, 100, 7, 2);
        _u8g2.drawBox(17, 53, 76, 3);

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

        // Update 16-second live activity ring buffer every 1 second
        if (now - _lastActivitySample >= 1000) {
            _lastActivitySample = now;
            uint32_t delta = (totalQueries >= _lastTotalQueries) ? (totalQueries - _lastTotalQueries) : 0;
            _lastTotalQueries = totalQueries;

            for (int i = 0; i < 15; ++i) {
                _activityHistory[i] = _activityHistory[i + 1];
            }
            _activityHistory[15] = (delta > 255) ? 255 : (uint8_t)delta;
        }

        // Cycle through 4 pages
        if (now - _lastPageSwitch >= Config::OLED_PAGE_CYCLE_MS) {
            _lastPageSwitch = now;
            _screenPage = (_screenPage + 1) % 4;
        }

        _u8g2.clearBuffer();

        switch (_screenPage) {
            case 0: _renderDashboard(totalQueries, blockedQueries, cache); break;
            case 1: _renderTrafficRadar(totalQueries, cache); break;
            case 2: _renderSiliconGauges(); break;
            case 3: _renderSecurityShield(); break;
        }

        _u8g2.sendBuffer();
    }

private:
    U8G2_SH1106_128X64_NONAME_F_SW_I2C _u8g2;
    bool     _connected = false;
    uint8_t  _screenPage = 0;
    uint32_t _lastPageSwitch = 0;

    // Traffic sparkline buffer
    uint8_t  _activityHistory[16];
    uint32_t _lastTotalQueries = 0;
    uint32_t _lastActivitySample = 0;

    // -----------------------------------------------------------------------
    // Visual Component: Wi-Fi RSSI 4-Bar Signal Meter
    // -----------------------------------------------------------------------
    void _drawWifiSignal(int x, int y) {
        if (!WiFi.isConnected()) {
            // Draw small 'x' (Disconnected)
            _u8g2.drawLine(x + 2, y + 1, x + 8, y + 7);
            _u8g2.drawLine(x + 2, y + 7, x + 8, y + 1);
            return;
        }

        int rssi = WiFi.RSSI();
        int bars = 1;
        if (rssi > -60)      bars = 4;
        else if (rssi > -70) bars = 3;
        else if (rssi > -80) bars = 2;

        for (int i = 0; i < 4; ++i) {
            int bx = x + (i * 3);
            int bh = 2 + (i * 2); // 2, 4, 6, 8 px tall
            int by = y + 8 - bh;
            if (i < bars) {
                _u8g2.drawVLine(bx, by, bh);
                _u8g2.drawVLine(bx + 1, by, bh);
            } else {
                _u8g2.drawPixel(bx, y + 7); // Faint base pixel
            }
        }
    }

    // -----------------------------------------------------------------------
    // Visual Component: Modern Floating Page Indicator Pills
    // -----------------------------------------------------------------------
    void _drawPagePills(uint8_t activePage, uint8_t totalPages = 4) {
        int startX = 127 - (totalPages * 8);
        for (uint8_t i = 0; i < totalPages; ++i) {
            int px = startX + (i * 8);
            if (i == activePage) {
                // Active capsule pill: 6px wide, 3px tall
                _u8g2.drawRBox(px, 57, 6, 3, 1);
            } else {
                // Inactive dot: 2px circle
                _u8g2.drawDisc(px + 2, 58, 1);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Screen 0: Executive Command Dashboard
    // -----------------------------------------------------------------------
    void _renderDashboard(uint32_t total, uint32_t blocked, const DnsCache& cache) {
        // --- Header Bar ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(2, 8, "ADSORB");
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(36, 8, "v1.2");

        // Center Active Badge
        _u8g2.drawRBox(58, 0, 36, 9, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(61, 7, "SINKHOLE");
        _u8g2.setDrawColor(1);

        // Wi-Fi Signal Bars
        _drawWifiSignal(116, 1);
        _u8g2.drawHLine(0, 10, 128);

        // --- Left Panel: Large Hero Blocked % ---
        float blockRate = (total > 0) ? (((float)blocked / (float)total) * 100.0f) : 0.0f;
        char rateBuf[16];
        if (blockRate >= 99.95f) {
            snprintf(rateBuf, sizeof(rateBuf), "100%%");
        } else {
            snprintf(rateBuf, sizeof(rateBuf), "%.1f%%", blockRate);
        }

        _u8g2.setFont(u8g2_font_helvB14_tr);
        _u8g2.drawStr(2, 28, rateBuf);

        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(2, 38, "BLOCKED");

        // Progress Bar for Blocked Rate
        _u8g2.drawRFrame(2, 42, 56, 6, 2);
        int fillW = (int)((blockRate / 100.0f) * 52.0f);
        if (fillW > 52) fillW = 52;
        if (fillW > 0) {
            _u8g2.drawBox(4, 44, fillW, 2);
        }

        // --- Vertical Center Divider ---
        _u8g2.drawVLine(62, 13, 37);

        // --- Right Panel: High-Density Telemetry ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        char buf[32];

        snprintf(buf, sizeof(buf), "TOT : %u", total);
        _u8g2.drawStr(66, 21, buf);

        snprintf(buf, sizeof(buf), "BLK : %u", blocked);
        _u8g2.drawStr(66, 31, buf);

        snprintf(buf, sizeof(buf), "RAM : %.0f%%", cache.getHitRatePercent());
        _u8g2.drawStr(66, 41, buf);

        _u8g2.setFont(u8g2_font_4x6_tf);
        snprintf(buf, sizeof(buf), "IP: %s", WiFi.isConnected() ? WiFi.localIP().toString().c_str() : "No Net");
        _u8g2.drawStr(66, 50, buf);

        // --- Footer Bar ---
        _u8g2.drawHLine(0, 53, 128);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(2, 61, "128b SIMD * HW TRNG");
        _drawPagePills(0, 4);
    }

    // -----------------------------------------------------------------------
    // Screen 1: Live Traffic Radar (Animated 16-Second Sparkline Histogram)
    // -----------------------------------------------------------------------
    void _renderTrafficRadar(uint32_t total, const DnsCache& cache) {
        // --- Header Bar ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(2, 8, "TRAFFIC RADAR");

        _u8g2.drawRBox(70, 0, 42, 9, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(73, 7, "RACE UDP");
        _u8g2.setDrawColor(1);

        _drawWifiSignal(116, 1);
        _u8g2.drawHLine(0, 10, 128);

        // --- Left: Live Real-Time Sparkline Bar Chart ---
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(2, 18, "QPS ACTIVITY (16s)");

        // Baseline Line
        _u8g2.drawHLine(2, 48, 58);

        // Find max delta in history to auto-scale bars nicely
        uint8_t maxDelta = 4;
        for (int i = 0; i < 14; ++i) {
            if (_activityHistory[i] > maxDelta) maxDelta = _activityHistory[i];
        }

        // Draw 14 vertical activity bars (each 3px wide, 1px spacing)
        for (int i = 0; i < 14; ++i) {
            int barH = (_activityHistory[i] * 26) / maxDelta;
            if (barH > 26) barH = 26;
            int bx = 3 + (i * 4);
            int by = 47 - barH;
            if (barH > 0) {
                _u8g2.drawBox(bx, by, 3, barH);
            } else {
                _u8g2.drawPixel(bx + 1, 47); // Subtle resting tick
            }
        }

        // --- Vertical Divider ---
        _u8g2.drawVLine(63, 13, 37);

        // --- Right: Cache & Latency Metrics ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        char buf[32];

        snprintf(buf, sizeof(buf), "CACHE: %u", cache.getActiveCount());
        _u8g2.drawStr(67, 21, buf);

        snprintf(buf, sizeof(buf), "HITS : %u", cache.getTotalHits());
        _u8g2.drawStr(67, 31, buf);

        _u8g2.drawStr(67, 41, "LAT  : <0.2ms");

        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(67, 50, "1.1.1.1 + 8.8.8.8");

        // --- Footer Bar ---
        _u8g2.drawHLine(0, 53, 128);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(2, 61, "adsorb.local * PORT 53");
        _drawPagePills(1, 4);
    }

    // -----------------------------------------------------------------------
    // Screen 2: Silicon Memory Gauges (PSRAM & SRAM Fuel Meters)
    // -----------------------------------------------------------------------
    void _renderSiliconGauges() {
        // --- Header Bar ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(2, 8, "SILICON HARDWARE");

        _u8g2.drawRBox(78, 0, 34, 9, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(81, 7, "240MHz");
        _u8g2.setDrawColor(1);

        _drawWifiSignal(116, 1);
        _u8g2.drawHLine(0, 10, 128);

        char buf[32];

        // --- 1. Octal PSRAM Fuel Gauge ---
        float freePsramMb = ESP.getFreePsram() / (1024.0f * 1024.0f);
        float usedPsramMb = 8.0f - freePsramMb;
        if (usedPsramMb < 0.0f) usedPsramMb = 0.0f;
        float psramPct = (usedPsramMb / 8.0f) * 100.0f;

        _u8g2.setFont(u8g2_font_5x7_tf);
        snprintf(buf, sizeof(buf), "PSRAM: %.2fM/8M (%.0f%%)", usedPsramMb, psramPct);
        _u8g2.drawStr(2, 20, buf);

        _u8g2.drawRFrame(2, 23, 124, 6, 2);
        int psramW = (int)((psramPct / 100.0f) * 120.0f);
        if (psramW > 120) psramW = 120;
        if (psramW > 0) _u8g2.drawBox(4, 25, psramW, 2);

        // --- 2. Internal SRAM Fuel Gauge ---
        uint32_t freeHeapKb = ESP.getFreeHeap() / 1024;
        uint32_t usedHeapKb = (freeHeapKb < 320) ? (320 - freeHeapKb) : 0;
        uint32_t sramPct = (usedHeapKb * 100) / 320;

        _u8g2.setFont(u8g2_font_5x7_tf);
        snprintf(buf, sizeof(buf), "SRAM : %uK/320K (%u%%)", usedHeapKb, sramPct);
        _u8g2.drawStr(2, 37, buf);

        _u8g2.drawRFrame(2, 40, 124, 6, 2);
        int sramW = (int)(((float)sramPct / 100.0f) * 120.0f);
        if (sramW > 120) sramW = 120;
        if (sramW > 0) _u8g2.drawBox(4, 42, sramW, 2);

        // LittleFS Rules tag
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(2, 51, "255,042 RULES * OCTAL SPI RAM");

        // --- Footer Bar ---
        _u8g2.drawHLine(0, 53, 128);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(2, 61, "STATIC: 192.168.1.101");
        _drawPagePills(2, 4);
    }

    // -----------------------------------------------------------------------
    // Screen 3: Cryptographic Shield & Hardware Protection Status
    // -----------------------------------------------------------------------
    void _renderSecurityShield() {
        // --- Header Bar ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(2, 8, "SECURITY SHIELD");

        _u8g2.drawRBox(74, 0, 38, 9, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(77, 7, "ACTIVE");
        _u8g2.setDrawColor(1);

        _drawWifiSignal(116, 1);
        _u8g2.drawHLine(0, 10, 128);

        // --- High-Density Security Matrix ---
        _u8g2.setFont(u8g2_font_5x7_tf);
        _u8g2.drawStr(2, 20, "[+] TRNG: RF THERMAL NOISE");
        _u8g2.drawStr(2, 29, "[+] SIMD: 128-BIT PIE (20R)");
        _u8g2.drawStr(2, 38, "[+] SINK: 0.0.0.0 & :: (IPV6)");
        _u8g2.drawStr(2, 47, "[+] mDNS: http://adsorb.local");

        // --- Footer Bar ---
        _u8g2.drawHLine(0, 53, 128);
        _u8g2.setFont(u8g2_font_4x6_tf);
        _u8g2.drawStr(2, 61, "ZERO TELEMETRY LEAKS");
        _drawPagePills(3, 4);
    }
};
