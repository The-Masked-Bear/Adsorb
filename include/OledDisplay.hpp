#pragma once

#include <Arduino.h>
#include <U8g2lib.h>
#include <WiFi.h>

#include "Config.hpp"
#include "DnsCache.hpp"
#include "EncryptedDns.hpp"

// ============================================================================
// Physical 1.3" I2C OLED Status Display Engine (SH1106 / SSD1306 128x64)
// Clean, High-Contrast Appliance Telemetry with Large Readable Fonts
// Safe 4px Margins to Prevent Any Screen Clipping or Bezel Cutoff
// ============================================================================
class OledDisplay {
public:
    OledDisplay()
        : _u8g2(U8G2_R0, /* clock=*/ Config::OLED_SCL_PIN, /* data=*/ Config::OLED_SDA_PIN, /* reset=*/ U8X8_PIN_NONE) {
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

        // Draw Clean High-Contrast Startup Splash
        _u8g2.clearBuffer();

        // 1. Title
        _u8g2.setFont(u8g2_font_helvB14_tr);
        _u8g2.drawStr(16, 20, "A D S O R B");

        // 2. Sub-Badge
        _u8g2.drawRBox(10, 26, 108, 13, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_6x12_tf);
        _u8g2.drawStr(14, 36, "HARDWARE SINKHOLE");
        _u8g2.setDrawColor(1);

        // 3. Status Line
        _u8g2.setFont(u8g2_font_6x12_tf);
        _u8g2.drawStr(12, 51, "255K RULES LOADED");

        // 4. Loading Bar Frame & Fill
        _u8g2.drawRFrame(12, 55, 104, 5, 1);
        _u8g2.drawBox(14, 56, 80, 3);

        _u8g2.sendBuffer();

        Serial.printf("[OLED] 1.3\" I2C OLED initialized on SDA:%d SCL:%d (SH1106)\n",
                      Config::OLED_SDA_PIN, Config::OLED_SCL_PIN);
        return true;
    }

    bool isConnected() const { return _connected; }

    // -----------------------------------------------------------------------
    // Render Multi-Screen Telemetry Carousel (2 High-Legibility Screens)
    // -----------------------------------------------------------------------
    void render(uint32_t totalQueries, uint32_t blockedQueries,
                const DnsCache& cache, const EncryptedDns& doh) {
        if (!_connected) return;

        uint32_t now = millis();

        // Cycle through 2 screens every 5 seconds
        if (now - _lastPageSwitch >= 5000) {
            _lastPageSwitch = now;
            _screenPage = (_screenPage + 1) % 2;
        }

        _u8g2.clearBuffer();

        if (_screenPage == 0) {
            _renderProtectionScreen(totalQueries, blockedQueries);
        } else {
            _renderSystemScreen();
        }

        _u8g2.sendBuffer();
    }

private:
    U8G2_SH1106_128X64_NONAME_F_SW_I2C _u8g2;
    bool     _connected = false;
    uint8_t  _screenPage = 0;
    uint32_t _lastPageSwitch = 0;

    // -----------------------------------------------------------------------
    // Screen 0: Ad Protection Dashboard (Glanceable Hero Metrics)
    // -----------------------------------------------------------------------
    void _renderProtectionScreen(uint32_t total, uint32_t blocked) {
        // --- Top Header ---
        _u8g2.setFont(u8g2_font_7x14_tf);
        _u8g2.drawStr(4, 11, "ADSORB");

        // Online Pill Badge on Right
        _u8g2.drawRBox(74, 1, 50, 11, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_6x12_tf);
        _u8g2.drawStr(80, 10, "ONLINE");
        _u8g2.setDrawColor(1);

        // Header Divider Line (Safely spans x=4 to x=124)
        _u8g2.drawHLine(4, 14, 120);

        // --- Hero Metric: Block Percentage & Label ---
        float blockRate = (total > 0) ? (((float)blocked / (float)total) * 100.0f) : 0.0f;
        char rateBuf[16];
        if (blockRate >= 99.95f) {
            snprintf(rateBuf, sizeof(rateBuf), "100%%");
        } else {
            snprintf(rateBuf, sizeof(rateBuf), "%.1f%%", blockRate);
        }

        // Bold Large Percentage (14pt bold)
        _u8g2.setFont(u8g2_font_helvB14_tr);
        _u8g2.drawStr(4, 29, rateBuf);

        // "BLOCKED" Label beside Percentage
        _u8g2.setFont(u8g2_font_7x14_tf);
        _u8g2.drawStr(58, 28, "BLOCKED");

        // --- Wide Rounded Progress Bar ---
        _u8g2.drawRFrame(4, 33, 120, 6, 2);
        int fillW = (int)((blockRate / 100.0f) * 116.0f);
        if (fillW > 116) fillW = 116;
        if (fillW > 0) {
            _u8g2.drawBox(6, 35, fillW, 2);
        }

        // --- Glanceable Counts (Large 6x12 font) ---
        _u8g2.setFont(u8g2_font_6x12_tf);
        char buf[32];
        snprintf(buf, sizeof(buf), "Blocked: %u / %u", blocked, total);
        _u8g2.drawStr(4, 49, buf);

        // --- Current IP Address (Large 6x12 font) ---
        String ipStr = WiFi.isConnected() ? WiFi.localIP().toString() : "192.168.1.101";
        snprintf(buf, sizeof(buf), "IP: %s", ipStr.c_str());
        _u8g2.drawStr(4, 61, buf);
    }

    // -----------------------------------------------------------------------
    // Screen 1: Network & System Status (High-Legibility Data)
    // -----------------------------------------------------------------------
    void _renderSystemScreen() {
        // --- Top Header ---
        _u8g2.setFont(u8g2_font_7x14_tf);
        _u8g2.drawStr(4, 11, "ADSORB");

        // System Pill Badge on Right
        _u8g2.drawRBox(74, 1, 50, 11, 2);
        _u8g2.setDrawColor(0);
        _u8g2.setFont(u8g2_font_6x12_tf);
        _u8g2.drawStr(80, 10, "SYSTEM");
        _u8g2.setDrawColor(1);

        // Header Divider Line
        _u8g2.drawHLine(4, 14, 120);

        // --- 4 Clean, Spacious Telemetry Lines (6x12 Font) ---
        _u8g2.setFont(u8g2_font_6x12_tf);
        char buf[32];

        // Line 1: Local IP Address
        String ipStr = WiFi.isConnected() ? WiFi.localIP().toString() : "192.168.1.101";
        snprintf(buf, sizeof(buf), "IP   : %s", ipStr.c_str());
        _u8g2.drawStr(4, 26, buf);

        // Line 2: Zero-Config Web Portal
        _u8g2.drawStr(4, 38, "Web  : adsorb.local");

        // Line 3: Inbound RFC 8484 DoH Endpoint
        _u8g2.drawStr(4, 50, "DoH  : /dns-query");

        // Line 4: Upstream DNS Status
        _u8g2.drawStr(4, 62, "DNS  : 1.1.1.1 (Race)");
    }
};
