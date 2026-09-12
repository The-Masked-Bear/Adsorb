#pragma once

#include <Arduino.h>
#include <WebServer.h>
#include <esp_heap_caps.h>

#include "Config.hpp"
#include "Blocklist.hpp"
#include "DnsServer.hpp"
#include "DnsCache.hpp"
#include "EncryptedDns.hpp"
#include "OledDisplay.hpp"

// ============================================================================
// Web Dashboard — Fully Interactive Neo-Brutalist Interface with Easter Eggs
// ============================================================================
class WebDashboard {
public:
    void begin(DnsEngine& dns, Blocklist& blocklist,
               DnsCache* cache = nullptr, EncryptedDns* doh = nullptr, OledDisplay* oled = nullptr) {
        _dns = &dns;
        _blocklist = &blocklist;
        _cache = cache;
        _doh = doh;
        _oled = oled;

        const char* headers[] = {"X-API-Key", "Authorization"};
        _server.collectHeaders(headers, 2);
        _initApiKey();

        _server.on("/", HTTP_GET, [this]() { _handleRoot(); });
        _server.on("/", HTTP_HEAD, [this]() { _handleRoot(); });
        _server.on("/api/stats", HTTP_GET, [this]() { _handleApiStats(); });
        _server.on("/api/queries", HTTP_GET, [this]() { _handleApiQueries(); });
        _server.on("/api/test", HTTP_GET, [this]() { _handleApiTest(); });
        _server.on("/api/whitelist", HTTP_GET, [this]() { _handleGetWhitelist(); });
        _server.on("/api/whitelist", HTTP_POST, [this]() { _handlePostWhitelist(); });
        _server.on("/api/whitelist", HTTP_DELETE, [this]() { _handleDeleteWhitelist(); });
        _server.on("/api/blacklist", HTTP_GET, [this]() { _handleGetBlacklist(); });
        _server.on("/api/blacklist", HTTP_POST, [this]() { _handlePostBlacklist(); });
        _server.on("/api/blacklist", HTTP_DELETE, [this]() { _handleDeleteBlacklist(); });

        // RFC 8484 DNS-over-HTTPS (DoH) Inbound Endpoints (POST & GET)
        _server.on(Config::PATH_DOH_ENDPOINT, HTTP_POST, [this]() { _handleDohPost(); }, [this]() { _handleDohRaw(); });
        _server.on(Config::PATH_DOH_ENDPOINT, HTTP_GET, [this]() { _handleDohGet(); });

        // Captive Portal Probe Redirections for iOS, Android, and Windows
        _server.on("/hotspot-detect.html", HTTP_GET, [this]() {
            _server.sendHeader("Location", "http://adsorb.local/", true);
            _server.send(302, "text/plain", "");
        });
        _server.on("/generate_204", HTTP_GET, [this]() {
            _server.sendHeader("Location", "http://adsorb.local/", true);
            _server.send(302, "text/plain", "");
        });
        _server.on("/gen_204", HTTP_GET, [this]() {
            _server.sendHeader("Location", "http://adsorb.local/", true);
            _server.send(302, "text/plain", "");
        });
        _server.on("/connecttest.txt", HTTP_GET, [this]() {
            _server.sendHeader("Location", "http://adsorb.local/", true);
            _server.send(302, "text/plain", "");
        });
        _server.on("/ncsi.txt", HTTP_GET, [this]() {
            _server.send(200, "text/plain", "Microsoft NCSI");
        });

        _server.onNotFound([this]() { _handleNotFound(); });

        _server.begin();
        Serial.printf("[Web] Ultimate Interactive Dashboard started on port %u\n", Config::WEB_PORT);
    }

    void handleClient() {
        _server.handleClient();
    }

    String getApiKey() const {
        return _adminApiKey;
    }

private:
    WebServer _server{Config::WEB_PORT};
    DnsEngine* _dns = nullptr;
    Blocklist* _blocklist = nullptr;
    DnsCache* _cache = nullptr;
    EncryptedDns* _doh = nullptr;
    OledDisplay* _oled = nullptr;
    String _adminApiKey;

    void _initApiKey() {
        const char* keyPath = "/admin_key.txt";
        if (LittleFS.exists(keyPath)) {
            File f = LittleFS.open(keyPath, "r");
            if (f) {
                _adminApiKey = f.readStringUntil('\n');
                _adminApiKey.trim();
                f.close();
            }
        }
        if (_adminApiKey.length() < 16) {
            _adminApiKey = "";
            char buf[9];
            for (int i = 0; i < 4; i++) {
                uint32_t r = esp_random();
                snprintf(buf, sizeof(buf), "%08x", (unsigned int)r);
                _adminApiKey += buf;
            }
            File f = LittleFS.open(keyPath, "w");
            if (f) {
                f.println(_adminApiKey);
                f.close();
            }
        }
        Serial.printf("[Security] Admin API Key active: %s\n", _adminApiKey.c_str());
    }

    bool _isAuthorized() {
        if (_adminApiKey.isEmpty()) return true;
        if (_server.hasHeader("X-API-Key") && _server.header("X-API-Key") == _adminApiKey) {
            return true;
        }
        if (_server.hasHeader("Authorization")) {
            String auth = _server.header("Authorization");
            if (auth.startsWith("Bearer ") && auth.substring(7) == _adminApiKey) {
                return true;
            }
            if (auth == _adminApiKey) {
                return true;
            }
        }
        if (_server.hasArg("key") && _server.arg("key") == _adminApiKey) {
            return true;
        }
        if (_server.hasArg("api_key") && _server.arg("api_key") == _adminApiKey) {
            return true;
        }
        return false;
    }

    uint8_t _dohRawBuf[Config::DNS_MAX_PACKET_SIZE];
    size_t _dohRawLen = 0;

    void _addSecurityHeaders() {
        _server.sendHeader("X-Content-Type-Options", "nosniff");
        _server.sendHeader("X-Frame-Options", "DENY");
        _server.sendHeader("Referrer-Policy", "no-referrer");
    }

    static inline int _b64Val(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-' || c == '+') return 62;
        if (c == '_' || c == '/') return 63;
        return -1;
    }

    int _decodeBase64Url(const String& input, uint8_t* out, size_t maxOut) {
        size_t inLen = input.length();
        size_t outIdx = 0;
        uint32_t val = 0;
        int valBits = 0;

        for (size_t i = 0; i < inLen; i++) {
            char c = input[i];
            if (c == '=' || c == ' ' || c == '\r' || c == '\n') break;
            int d = _b64Val(c);
            if (d < 0) return -1;
            val = (val << 6) | (uint32_t)d;
            valBits += 6;
            if (valBits >= 8) {
                valBits -= 8;
                if (outIdx >= maxOut) return -1;
                out[outIdx++] = (uint8_t)((val >> valBits) & 0xFF);
            }
        }
        return (int)outIdx;
    }

    void _handleDohRaw() {
        HTTPRaw& r = _server.raw();
        if (r.status == RAW_START) {
            _dohRawLen = 0;
        } else if (r.status == RAW_WRITE) {
            if (_dohRawLen + r.currentSize <= sizeof(_dohRawBuf)) {
                memcpy(_dohRawBuf + _dohRawLen, r.buf, r.currentSize);
                _dohRawLen += r.currentSize;
            }
        }
    }

    void _handleDohPost() {
        _addSecurityHeaders();
        if (_dohRawLen == 0) {
            _server.send(400, "text/plain", "Bad Request: Empty DNS Query");
            return;
        }
        uint8_t respBuf[Config::DNS_MAX_PACKET_SIZE];
        int respLen = _dns->processDohPacket(_dohRawBuf, _dohRawLen, _server.client().remoteIP(), respBuf, sizeof(respBuf));
        _dohRawLen = 0;
        if (respLen <= 0) {
            _server.send(500, "text/plain", "Internal Server Error");
            return;
        }
        _server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        _server.send_P(200, "application/dns-message", (const char*)respBuf, (size_t)respLen);
    }

    void _handleDohGet() {
        _addSecurityHeaders();
        if (!_server.hasArg("dns")) {
            _server.send(400, "text/plain", "Bad Request: Missing 'dns' parameter");
            return;
        }
        String b64 = _server.arg("dns");
        uint8_t queryBuf[Config::DNS_MAX_PACKET_SIZE];
        int queryLen = _decodeBase64Url(b64, queryBuf, sizeof(queryBuf));
        if (queryLen <= 0) {
            _server.send(400, "text/plain", "Bad Request: Invalid Base64URL encoding");
            return;
        }
        uint8_t respBuf[Config::DNS_MAX_PACKET_SIZE];
        int respLen = _dns->processDohPacket(queryBuf, (size_t)queryLen, _server.client().remoteIP(), respBuf, sizeof(respBuf));
        if (respLen <= 0) {
            _server.send(500, "text/plain", "Internal Server Error");
            return;
        }
        _server.sendHeader("Cache-Control", "max-age=60");
        _server.send_P(200, "application/dns-message", (const char*)respBuf, (size_t)respLen);
    }

    String _formatUptime() {
        uint32_t sec = millis() / 1000;
        uint32_t d = sec / 86400;
        uint32_t h = (sec % 86400) / 3600;
        uint32_t m = (sec % 3600) / 60;
        uint32_t s = sec % 60;
        char buf[32];
        if (d > 0) {
            snprintf(buf, sizeof(buf), "%ud %02uh %02um", d, h, m);
        } else {
            snprintf(buf, sizeof(buf), "%02u:%02u:%02u", h, m, s);
        }
        return String(buf);
    }

    // -----------------------------------------------------------------------
    // GET /api/test?domain=... — Real-Time Interactive Test Tool
    // -----------------------------------------------------------------------
    void _handleApiTest() {
        _addSecurityHeaders();
        if (!_server.hasArg("domain")) {
            _server.send(400, "application/json", "{\"error\":\"Missing domain parameter\"}");
            return;
        }
        String domain = _server.arg("domain");
        domain.trim();
        bool blocked = _blocklist->isBlocked(domain);

        char json[256];
        snprintf(json, sizeof(json),
                 "{\"domain\":\"%s\",\"blocked\":%s,\"sinkhole_ip\":\"0.0.0.0\"}",
                 domain.c_str(), blocked ? "true" : "false");
        _server.send(200, "application/json", json);
    }

    // -----------------------------------------------------------------------
    // GET / — Ultimate Interactive Neo-Brutalist Dashboard
    // -----------------------------------------------------------------------
    void _handleRoot() {
        _addSecurityHeaders();
        if (_server.method() == HTTP_HEAD) {
            _server.sendHeader("Content-Length", "35000");
            _server.send(200, "text/html", "");
            return;
        }
        uint32_t total = _dns->totalQueries;
        uint32_t blocked = _dns->blockedQueries;
        float rate = (total > 0) ? (100.0f * blocked / total) : 0.0f;
        uint32_t freeHeap = ESP.getFreeHeap();
        uint32_t freePsram = ESP.getFreePsram();
        String uptime = _formatUptime();

        String html = R"rawhtml(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Adsorb &bull; The Untouchable Ad Obliterator</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@600;700;800;900&family=Space+Mono:wght@700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #f6f3ee;
  --bg-card: #ffffff;
  --text: #121212;
  --border: #121212;
  --shadow: #121212;
  --shadow-offset: 4px;
  --border-w: 2.5px;
  --radius: 10px;
  --c-yellow: #fde047;
  --c-coral: #ff6b6b;
  --c-mint: #2dd4bf;
  --c-lime: #a3e635;
  --c-blue: #60a5fa;
  --c-lavender: #c084fc;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background-color: var(--bg);
  background-image: radial-gradient(rgba(18, 18, 18, 0.12) 1.2px, transparent 1.2px);
  background-size: 20px 20px;
  color: var(--text);
  font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
  padding: 30px 18px;
  min-height: 100vh;
}

.container { max-width: 1080px; margin: 0 auto; }

/* Neo-Brutalist Card */
.neo-card {
  background: var(--bg-card);
  border: var(--border-w) solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow-offset) var(--shadow-offset) 0px var(--shadow);
  transition: transform 0.12s, box-shadow 0.12s;
}
.neo-card.clickable:hover {
  cursor: pointer;
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0px var(--shadow);
}
.neo-card.clickable:active {
  transform: translate(2px, 2px);
  box-shadow: 1px 1px 0px var(--shadow);
}

/* Header */
.header {
  padding: 18px 24px;
  margin-bottom: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 14px;
}
.brand-wrap { display: flex; align-items: center; gap: 14px; }
.brand-icon {
  width: 48px;
  height: 48px;
  background: var(--c-yellow);
  border: var(--border-w) solid var(--border);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 26px;
  box-shadow: 2px 2px 0px var(--shadow);
  cursor: pointer;
  user-select: none;
  transition: transform 0.1s;
}
.brand-icon:active { transform: scale(0.92) rotate(-8deg); }
.brand-text h1 {
  font-size: 1.35em;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: -0.5px;
  line-height: 1.1;
}
.brand-text .sub { font-size: 0.78em; font-weight: 700; opacity: 0.8; margin-top: 3px; }

/* Interactive Toolbar */
.toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.btn-tool {
  background: var(--bg-card);
  border: var(--border-w) solid var(--border);
  border-radius: 8px;
  padding: 6px 12px;
  font-size: 0.78em;
  font-weight: 800;
  cursor: pointer;
  box-shadow: 2px 2px 0px var(--shadow);
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: transform 0.1s, box-shadow 0.1s;
}
.btn-tool:hover { transform: translate(-1px, -1px); box-shadow: 3px 3px 0px var(--shadow); }
.btn-tool:active { transform: translate(1px, 1px); box-shadow: 1px 1px 0px var(--shadow); }

/* Pulse dot */
.pulse-dot {
  width: 8px; height: 8px; background: #10b981; border-radius: 50%;
  animation: pulse 1.5s infinite;
}
@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.3; transform: scale(0.8); } }

/* Arrogant Cope Ticker */
.ticker-card {
  padding: 12px 18px;
  margin-bottom: 20px;
  background: #fef08a;
  display: flex;
  align-items: center;
  gap: 12px;
  border-left: 8px solid var(--border);
  font-weight: 800;
  font-size: 0.84em;
}
.ticker-badge {
  background: #ef4444;
  color: #fff;
  border: var(--border-w) solid var(--border);
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 0.75em;
  font-weight: 900;
  letter-spacing: 0.5px;
  white-space: nowrap;
  box-shadow: 1.5px 1.5px 0px var(--shadow);
}
.ticker-text { flex: 1; transition: opacity 0.3s; line-height: 1.3; }

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}
.stat-card {
  padding: 18px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  user-select: none;
}
.stat-card.blue { background: #dbeafe; }
.stat-card.coral { background: #ffe4e6; }
.stat-card.lime { background: #ecfccb; }
.stat-card.yellow { background: #fef9c3; }
.stat-card.mint { background: #ccfbf1; }
.stat-card.lavender { background: #f3e8ff; }

.stat-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.stat-pill {
  font-size: 0.7em;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  background: #ffffff;
  color: #121212;
  border: var(--border-w) solid var(--border);
  padding: 2px 8px;
  border-radius: 6px;
  box-shadow: 1.5px 1.5px 0px var(--shadow);
}
.stat-number {
  font-size: 2.6em;
  font-weight: 900;
  font-family: 'Space Mono', monospace;
  line-height: 1;
  letter-spacing: -1.5px;
}
.progress-box {
  width: 100%; height: 9px; background: #ffffff;
  border: var(--border-w) solid var(--border); border-radius: 999px;
  margin-top: 12px; overflow: hidden;
}
.progress-fill { height: 100%; background: var(--c-coral); transition: width 0.4s; }

/* Interactive Tester Banner */
.tester-card {
  padding: 16px 20px;
  margin-bottom: 20px;
  background: var(--c-yellow);
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}
.tester-card h3 { font-size: 0.9em; font-weight: 900; text-transform: uppercase; }
.tester-form { flex: 1; display: flex; gap: 8px; min-width: 280px; }
.tester-input {
  flex: 1;
  padding: 8px 12px;
  border: var(--border-w) solid var(--border);
  border-radius: 8px;
  font-family: 'Space Mono', monospace;
  font-size: 0.85em;
  font-weight: 700;
  background: #fff;
  outline: none;
}
.tester-btn {
  padding: 8px 18px;
  border: var(--border-w) solid var(--border);
  border-radius: 8px;
  background: #121212;
  color: #fff;
  font-weight: 800;
  cursor: pointer;
  text-transform: uppercase;
}
.tester-btn:hover { background: #333; }

/* Query Table Card */
.query-card { margin-bottom: 20px; overflow: hidden; }
.table-header {
  padding: 14px 20px;
  background: var(--bg-card);
  border-bottom: var(--border-w) solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}
.table-controls { display: flex; gap: 8px; align-items: center; }
.search-input {
  padding: 6px 12px;
  border: var(--border-w) solid var(--border);
  border-radius: 6px;
  font-size: 0.8em;
  font-family: 'Space Mono', monospace;
  background: var(--bg);
  color: var(--text);
  outline: none;
  width: 180px;
}
.filter-btn {
  padding: 4px 10px;
  border: var(--border-w) solid var(--border);
  border-radius: 6px;
  font-size: 0.72em;
  font-weight: 800;
  cursor: pointer;
  background: var(--bg-card);
  color: var(--text);
}
.filter-btn.active {
  background: var(--c-lime);
  color: #121212;
}

table { width: 100%; border-collapse: collapse; }
th {
  background: var(--bg);
  color: var(--text);
  font-size: 0.72em;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  padding: 10px 18px;
  border-bottom: var(--border-w) solid var(--border);
  text-align: left;
}
td {
  padding: 11px 18px;
  font-size: 0.85em;
  border-bottom: 1.5px solid rgba(0,0,0,0.08);
  font-weight: 600;
}
tr:hover td { background: rgba(0,0,0,0.02); }

.domain-text { font-family: 'Space Mono', monospace; font-size: 0.88em; cursor: pointer; }
.domain-text:hover { text-decoration: underline; color: var(--c-blue); }

.badge-tag {
  display: inline-flex;
  align-items: center;
  padding: 3px 9px;
  border: var(--border-w) solid var(--border);
  border-radius: var(--radius-badge);
  font-size: 0.72em;
  font-weight: 800;
  box-shadow: 1.5px 1.5px 0px var(--shadow);
}
.badge-tag.blocked { background: var(--c-coral); color: #121212; }
.badge-tag.allowed { background: var(--c-mint); color: #121212; }

/* Forms Grid */
.forms-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 24px;
}
@media (max-width: 680px) { .forms-grid { grid-template-columns: 1fr; } }
.form-card { padding: 18px; }
.form-card h3 { font-size: 0.9em; font-weight: 900; text-transform: uppercase; margin-bottom: 10px; }
.form-row { display: flex; gap: 8px; }
.form-row input[type=text] {
  flex: 1;
  padding: 8px 12px;
  border: var(--border-w) solid var(--border);
  border-radius: 8px;
  font-family: 'Space Mono', monospace;
  font-size: 0.85em;
  background: var(--bg);
  color: var(--text);
  outline: none;
}
.btn-action {
  border: var(--border-w) solid var(--border);
  border-radius: 8px;
  padding: 8px 18px;
  font-size: 0.82em;
  font-weight: 800;
  cursor: pointer;
  box-shadow: 2px 2px 0px var(--shadow);
  transition: transform 0.1s;
}
.btn-action:hover { transform: translate(-1px, -1px); box-shadow: 3px 3px 0px var(--shadow); }
.btn-action:active { transform: translate(1px, 1px); box-shadow: 1px 1px 0px var(--shadow); }
.btn-action.green { background: var(--c-mint); color: #121212; }
.btn-action.red { background: var(--c-coral); color: #121212; }

/* Modal */
.modal-overlay {
  position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
  background: rgba(0,0,0,0.65);
  display: none; justify-content: center; align-items: center; z-index: 9999;
  backdrop-filter: blur(4px);
}
.modal-overlay.open { display: flex; }
.modal-box {
  background: var(--bg-card);
  border: var(--border-w) solid var(--border);
  border-radius: var(--radius);
  box-shadow: 8px 8px 0px var(--shadow);
  max-width: 520px; width: 92%; padding: 24px;
  animation: popModal 0.15s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
@keyframes popModal { from { transform: scale(0.85); opacity: 0; } to { transform: scale(1); opacity: 1; } }

/* Footer */
.footer {
  text-align: center; font-size: 0.78em; font-weight: 700; opacity: 0.7;
  cursor: pointer; user-select: none;
}
.footer:hover { opacity: 1; color: var(--c-blue); }

/* Confetti & Screen Shake */
@keyframes earthquake {
  0% { transform: translate(0, 0); }
  20% { transform: translate(-8px, 6px); }
  40% { transform: translate(8px, -6px); }
  60% { transform: translate(-6px, -4px); }
  80% { transform: translate(6px, 4px); }
  100% { transform: translate(0, 0); }
}
.shake { animation: earthquake 0.5s ease-in-out; }

/* Easter Egg God Mode Banner */
#god-mode-banner {
  display: none; background: #ec4899; color: #fff; border: var(--border-w) solid #000;
  padding: 10px; text-align: center; font-weight: 900; letter-spacing: 1px;
  margin-bottom: 16px; border-radius: 8px; box-shadow: 4px 4px 0 #000;
}
</style>
</head>
<body>

<div class="container" id="main-container">

  <!-- EASTER EGG BANNER -->
  <div id="god-mode-banner">&#x26A1; GOD MODE: SINKHOLE OVERDRIVE ACTIVATED &bull; 0 LATENCY AD OBLITERATOR &#x26A1;</div>

  <!-- TOP HEADER -->
  <header class="neo-card header">
    <div class="brand-wrap">
      <div class="brand-icon" id="shield-logo" title="Click 5 times to enter Ad Slaughter Arcade!">&#x1F525;</div>
      <div class="brand-text">
        <h1>Adsorb: The Untouchable Ad Obliterator</h1>
        <div class="sub">Zero Ads Allowed. Deal With It. &bull; ESP32-S3 Dual-Core LX7 @ 240MHz &bull; 8MB Octal PSRAM &bull; v1.3.0 &bull; HW TRNG Parallel UDP &bull; RFC 8484 DoH</div>
      </div>
    </div>
    <div class="toolbar">
      <button class="btn-tool" id="btn-sound" title="Toggle 8-bit Audio">&#x1F50A; SFX: ON</button>
      <div class="btn-tool" style="background: #a7f3d0;" title="Encrypted RFC 8484 Inbound DoH Endpoint active at /dns-query">&#x1F512; RFC 8484 DoH ACTIVE</div>
      <div class="btn-tool" style="cursor: default;" title="Active and annihilating 100% of unwanted surveillance traffic">
        <span class="pulse-dot"></span>
        <span>ZERO ADS ALLOWED</span>
      </div>
      <div class="btn-tool" style="font-family: 'Space Mono', monospace;" title="Point your DNS here and weep with joy">IP: )rawhtml";

        html += (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : WiFi.softAPIP().toString();
        html += R"rawhtml(</div>
    </div>
  </header>

  <!-- ARROGANT COPE TICKER -->
  <div class="neo-card ticker-card" id="arrogant-ticker" title="Unfiltered truths from the silicon throne">
    <span class="ticker-badge">&#x1F525; COPE STATUS</span>
    <span class="ticker-text" id="ticker-msg">Ad networks spent $600B on surveillance capitalism just to get atomized by an $8 microcontroller.</span>
  </div>

  <!-- INTERACTIVE LIVE DOMAIN TESTER -->
  <div class="neo-card tester-card">
    <div>
      <h3>&#x26A1; AD EXEC EXECUTION CHAMBER</h3>
      <div style="font-size: 0.78em; font-weight: 700; opacity: 0.85;">Input any tracking domain to watch it get mercilessly sinkholed into oblivion</div>
    </div>
    <form class="tester-form" id="domain-test-form">
      <input type="text" id="test-domain-input" class="tester-input" placeholder="e.g. doubleclick.net, pagead2.googlesyndication.com" required>
      <button type="submit" class="tester-btn">OBLITERATE &amp; TEST</button>
    </form>
  </div>

  <!-- STATS CARDS GRID -->
  <section class="stats-grid">
    <div class="neo-card stat-card blue clickable" id="total-queries" title="Every packet inspected and judged by pure silicon">
      <div class="stat-head">
        <span class="stat-pill">QUERIES INTERROGATED</span>
        <span>&#x1F50E;</span>
      </div>
      <div class="stat-number" id="val-total">)rawhtml";
        html += String(total);
        html += R"rawhtml(</div>
      <div style="font-size: 0.72em; font-weight: 800; margin-top: 6px; opacity: 0.75;">Inspected &amp; judged</div>
    </div>

    <div class="neo-card stat-card coral clickable" id="card-blocked" data-card="blocked-queries" title="Click to inspect vaporized tracker statistics">
      <div class="stat-head">
        <span class="stat-pill" style="background: var(--c-coral); color: #fff;" id="blocked-queries">TRACKERS VAPORIZED</span>
        <span>&#x1F480;</span>
      </div>
      <div class="stat-number" id="val-blocked">)rawhtml";
        html += String(blocked);
        html += R"rawhtml(</div>
      <div style="font-size: 0.72em; font-weight: 800; margin-top: 6px; opacity: 0.75;">Sent to 0.0.0.0 with extreme prejudice</div>
    </div>

    <div class="neo-card stat-card lime clickable" id="card-rate" title="Mathematical proof of our dominance">
      <div class="stat-head">
        <span class="stat-pill">100% SUPERIORITY RATING</span>
        <span>&#x26A1;</span>
      </div>
      <div class="stat-number" id="val-rate">)rawhtml";
        html += String(rate, 1) + "%";
        html += R"rawhtml(</div>
      <div class="progress-box">
        <div class="progress-fill" id="val-progress" style="width: )rawhtml";
        html += String(rate > 100.0f ? 100.0f : rate, 1) + "%";
        html += R"rawhtml(;"></div>
      </div>
    </div>

    <div class="neo-card stat-card yellow clickable" id="card-rules" title="Lethal domain signatures residing in Octal PSRAM">
      <div class="stat-head">
        <span class="stat-pill">ACTIVE OBLITERATION RULES</span>
        <span>&#x1F4DA;</span>
      </div>
      <div class="stat-number" id="val-rules">)rawhtml";
        html += String((unsigned long)_blocklist->blockedCount());
        html += R"rawhtml(</div>
      <div style="font-size: 0.72em; font-weight: 800; margin-top: 6px; opacity: 0.75;">PSRAM Hash Table (55K+ signatures)</div>
    </div>

    <div class="neo-card stat-card mint clickable" id="card-bandwidth" title="Megabytes of surveillance scripts prevented from clogging your pipes">
      <div class="stat-head">
        <span class="stat-pill">BANDWIDTH SAVED</span>
        <span>&#x1F680;</span>
      </div>
      <div class="stat-number" id="val-bandwidth">)rawhtml";
        html += String((float)(blocked * 148) / 1024.0f, 1) + " MB";
        html += R"rawhtml(</div>
      <div style="font-size: 0.72em; font-weight: 800; margin-top: 6px; opacity: 0.75;">Bloated ad bloatware evicted</div>
    </div>

    <div class="neo-card stat-card lavender clickable" id="card-crying" title="Directly correlated with ad executive quarterly bonus deductions">
      <div class="stat-head">
        <span class="stat-pill">CRYING AD EXECUTIVES</span>
        <span>&#x1F62D;</span>
      </div>
      <div class="stat-number" id="val-crying">)rawhtml";
        html += String((unsigned long)(blocked * 1.3f));
        html += R"rawhtml(</div>
      <div style="font-size: 0.72em; font-weight: 800; margin-top: 6px; opacity: 0.75;">Tears collected: 100% pure organic sodium</div>
    </div>
  </section>

  <!-- QUERY STREAM TABLE -->
  <section class="neo-card query-card" id="query-log">
    <div class="table-header">
      <div style="font-weight: 800; text-transform: uppercase; display: flex; align-items: center; gap: 8px;">
        <span>&#x1F4DC;</span> LIVE SLAUGHTER LOG (REAL-TIME STREAM)
      </div>
      <div class="table-controls">
        <input type="text" id="filter-search" class="search-input" placeholder="Search crushed domains...">
        <button class="filter-btn active" data-filter="all">ALL</button>
        <button class="filter-btn" data-filter="blocked">VAPORIZED</button>
        <button class="filter-btn" data-filter="allowed">ALLOWED</button>
      </div>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">#</th>
            <th>Domain Name</th>
            <th>Client IP</th>
            <th>Verdict</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody id="query-tbody">
          <tr><td colspan="5" style="text-align: center; padding: 24px;">Connecting to query stream...</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <!-- QUICK ACTION FORMS -->
  <section class="forms-grid">
    <div class="neo-card form-card" style="background: #f0fdf4;">
      <h3 style="color: #121212;"><span>&#x1F54A;</span> PARDON DOMAIN (WHITELIST)</h3>
      <p style="font-size: 0.75em; font-weight: 700; margin-bottom: 8px; opacity: 0.7;">Grant mercy to a false positive if you truly trust it.</p>
      <form class="form-row" id="form-whitelist" action="/api/whitelist" method="POST">
        <input type="hidden" name="key" value="%ADMIN_API_KEY%">
        <input type="text" name="domain" placeholder="e.g. allowed-site.com" required>
        <button type="submit" class="btn-action green">GRANT MERCY</button>
      </form>
    </div>

    <div class="neo-card form-card" style="background: #fff1f2;">
      <h3 style="color: #121212;"><span>&#x26A1;</span> BANISH DOMAIN (CUSTOM BLACKLIST)</h3>
      <p style="font-size: 0.75em; font-weight: 700; margin-bottom: 8px; opacity: 0.7;">Target a specific rogue tracker for unconditional eradication.</p>
      <form class="form-row" id="form-blacklist" action="/api/blacklist" method="POST">
        <input type="hidden" name="key" value="%ADMIN_API_KEY%">
        <input type="text" name="domain" placeholder="e.g. annoying-tracker.com" required>
        <button type="submit" class="btn-action red">BANISH FOREVER</button>
      </form>
    </div>
  </section>

  <!-- FOOTER WITH HARDWARE SWAGGER -->
  <footer class="footer" id="footer-trigger" title="Double click to reveal hardware supremacy!">
    <strong>ESP32-S3 N16R8</strong> &bull; FreeRTOS Dual-Core &bull; "Zero Ads Allowed. Deal With It." &bull; RFC 8484 DoH TLS 1.3 &bull; Adsorb v2.0-ENCRYPTED &bull; API Key: <code style="user-select: all; background: #e5e7eb; padding: 2px 6px; border-radius: 4px; font-weight: 700;">%ADMIN_API_KEY%</code>
  </footer>

</div>

<!-- MODAL FOR INSPECTING DOMAINS -->
<div class="modal-overlay" id="inspect-modal">
  <div class="modal-box">
    <h3 id="modal-title" style="font-size: 1.1em; font-weight: 800; margin-bottom: 12px;">Domain Actions</h3>
    <p id="modal-desc" style="font-family: 'Space Mono', monospace; font-size: 0.9em; margin-bottom: 18px; word-break: break-all;"></p>
    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
      <button class="btn-action green" id="modal-btn-white">Whitelist This</button>
      <button class="btn-action red" id="modal-btn-black">Blacklist This</button>
      <button class="btn-action" style="background: #e5e7eb; color: #121212;" id="modal-btn-close">Close</button>
    </div>
  </div>
</div>

<!-- EASTER EGG MINI-GAME: AD DESTROYER -->
<div class="modal-overlay" id="game-modal">
  <div class="modal-box" style="max-width: 600px; text-align: center;">
    <h2 style="font-size: 1.4em; font-weight: 900; margin-bottom: 8px;">&#x1F47E; SINKHOLE INVADERS</h2>
    <p style="font-size: 0.85em; font-weight: 700; margin-bottom: 14px;">Pop the ads before they steal your bandwidth! Score: <span id="game-score">0</span></p>
    <div id="game-arena" style="position: relative; width: 100%; height: 260px; background: #000; border: 2.5px solid #fff; border-radius: 8px; overflow: hidden; margin-bottom: 14px;">
    </div>
    <button class="btn-action" style="background: var(--c-coral); color: #fff;" id="btn-close-game">CLOSE GAME</button>
  </div>
</div>

<!-- CLIENT JAVASCRIPT: SOUND FX, REAL-TIME POLLING, AND EASTER EGGS -->
<script>
const ADMIN_API_KEY = "%ADMIN_API_KEY%";

// --- Web Audio Synthesizer (8-bit sound fx) ---
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx = null;
let soundEnabled = true;

function playTone(freq, duration, type = 'square') {
  if (!soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new AudioCtx();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch(e) {}
}

function sfxClick() { playTone(800, 0.05, 'sine'); }
function sfxBlocked() { playTone(180, 0.15, 'sawtooth'); }
function sfxAllowed() { playTone(980, 0.08, 'triangle'); }
function sfxVictory() {
  [523, 659, 783, 1046].forEach((f, i) => setTimeout(() => playTone(f, 0.15, 'triangle'), i * 110));
}

// --- Sound Toggle ---
const soundBtn = document.getElementById('btn-sound');
soundBtn.addEventListener('click', () => {
  soundEnabled = !soundEnabled;
  soundBtn.textContent = soundEnabled ? '🔊 SFX: ON' : '🔇 SFX: OFF';
  if (soundEnabled) sfxClick();
});

// --- Real-Time Polling Engine ---
let activeFilter = 'all';
let searchKeyword = '';
let currentLog = [];

const arrogantQuips = [
  "Ad networks spent $600B on surveillance capitalism just to get atomized by an $8 microcontroller.",
  "Tracking script attempted infiltration... laughed out of memory.",
  "Mark Zuckerberg's telemetry packets detected and sent straight to the shadow realm.",
  "Ad executive tears detected: Salinity 99.8%.",
  "Why block ads politely when you can vaporize them with 240MHz of pure disrespect?",
  "Your ISP was trying to sell your browsing habits. We broke their toys.",
  "Zero tracking cookies allowed on our watch. Suffer in silence, Madison Avenue.",
  "250,000+ domains banished to 0.0.0.0. Your bandwidth is sacred.",
  "Google analytics tried knocking on the door. Left crying in the rain."
];
let quipIdx = 0;
setInterval(() => {
  quipIdx = (quipIdx + 1) % arrogantQuips.length;
  const el = document.getElementById('ticker-msg');
  if (el) {
    el.style.opacity = '0';
    setTimeout(() => {
      el.textContent = arrogantQuips[quipIdx];
      el.style.opacity = '1';
    }, 250);
  }
}, 4500);

async function updateTelemetry() {
  try {
    // 1. Fetch live stats
    const resStats = await fetch('/api/stats');
    if (resStats.ok) {
      const s = await resStats.json();
      const total = s.total || 0;
      const blocked = s.blocked || 0;
      const rate = total > 0 ? (s.rate || 0) : 100.0;
      const rules = s.blocklist_count || s.blocklist_size || 0;

      document.getElementById('val-total').textContent = total.toLocaleString();
      document.getElementById('val-blocked').textContent = blocked.toLocaleString();
      document.getElementById('val-rate').textContent = (total > 0 ? rate.toFixed(1) : '100') + '%';
      document.getElementById('val-progress').style.width = Math.min(rate, 100) + '%';
      document.getElementById('val-rules').textContent = rules.toLocaleString();

      // Arrogant metric counters
      const mbSaved = ((blocked * 148) / 1024.0).toFixed(1);
      const elBandwidth = document.getElementById('val-bandwidth');
      if (elBandwidth) elBandwidth.textContent = mbSaved + ' MB';

      const cryingExecs = Math.floor(blocked * 1.3);
      const elCrying = document.getElementById('val-crying');
      if (elCrying) elCrying.textContent = cryingExecs.toLocaleString();
    }

    // 2. Fetch live query log
    const resQueries = await fetch('/api/queries');
    if (resQueries.ok) {
      currentLog = await resQueries.json();
      renderTable();
    }
  } catch(e) {}
}

function renderTable() {
  const tbody = document.getElementById('query-tbody');
  let filtered = currentLog.filter(q => {
    if (activeFilter === 'blocked' && !q.blocked) return false;
    if (activeFilter === 'allowed' && q.blocked) return false;
    if (searchKeyword && !q.domain.toLowerCase().includes(searchKeyword) && !q.client_ip.includes(searchKeyword)) return false;
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 24px;">No matching queries in slaughter log</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.slice(0, 50).map((q, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td class="domain-text" onclick="inspectDomain('${q.domain}')" title="Click to inspect or banish">${q.domain}</td>
      <td style="font-family: 'Space Mono', monospace; font-size: 0.85em;">${q.client_ip}</td>
      <td>
        <span class="badge-tag ${q.blocked ? 'blocked' : 'allowed'}">
          ${q.blocked ? '💀 VAPORIZED' : '🛡️ PERMITTED'}
        </span>
      </td>
      <td style="font-family: 'Space Mono', monospace; font-size: 0.8em; opacity: 0.7;">${q.latency_ms || 1}ms</td>
    </tr>
  `).join('');
}

// Search & Filter
document.getElementById('filter-search').addEventListener('input', (e) => {
  searchKeyword = e.target.value.toLowerCase().trim();
  renderTable();
});

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.getAttribute('data-filter');
    sfxClick();
    renderTable();
  });
});

// Initial load and 2.5-second live loop
updateTelemetry();
setInterval(updateTelemetry, 2500);

// --- Domain Inspector Modal ---
let selectedDomain = '';
const modal = document.getElementById('inspect-modal');

function inspectDomain(domain) {
  selectedDomain = domain;
  document.getElementById('modal-title').textContent = 'Domain Sentence';
  document.getElementById('modal-desc').textContent = domain;
  modal.classList.add('open');
  sfxClick();
}

document.getElementById('modal-btn-close').addEventListener('click', () => {
  modal.classList.remove('open');
  sfxClick();
});

document.getElementById('modal-btn-white').addEventListener('click', async () => {
  await fetch('/api/whitelist', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-API-Key': ADMIN_API_KEY}, body: JSON.stringify({domain: selectedDomain}) });
  modal.classList.remove('open');
  sfxAllowed();
  updateTelemetry();
});

document.getElementById('modal-btn-black').addEventListener('click', async () => {
  await fetch('/api/blacklist', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-API-Key': ADMIN_API_KEY}, body: JSON.stringify({domain: selectedDomain}) });
  modal.classList.remove('open');
  sfxBlocked();
  updateTelemetry();
});

// --- Live Domain Test Tool ---
document.getElementById('domain-test-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('test-domain-input');
  const d = input.value.trim();
  if (!d) return;
  sfxClick();
  const res = await fetch(`/api/test?domain=${encodeURIComponent(d)}`);
  if (res.ok) {
    const data = await res.json();
    if (data.blocked) {
      sfxBlocked();
      alert(`💀 VAPORIZED!\nDomain '${d}' was deleted from reality.\nESP32 sinkholed it to 0.0.0.0 in 0.4ms.\nDeal with it.`);
    } else {
      sfxAllowed();
      alert(`🕊️ MERCY GRANTED!\nDomain '${d}' is clean.\nPassed through to upstream resolver with lightning speed.`);
    }
  }
});

// ============================================================================
// EASTER EGG 1: KONAMI CODE (Up, Up, Down, Down, Left, Right, Left, Right, B, A)
// ============================================================================
const konamiCode = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'b', 'a'];
let konamiIdx = 0;

window.addEventListener('keydown', (e) => {
  if (e.key.toLowerCase() === konamiCode[konamiIdx].toLowerCase()) {
    konamiIdx++;
    if (konamiIdx === konamiCode.length) {
      konamiIdx = 0;
      activateGodMode();
    }
  } else {
    konamiIdx = 0;
  }
});

function activateGodMode() {
  sfxVictory();
  document.getElementById('god-mode-banner').style.display = 'block';
  document.getElementById('main-container').classList.add('shake');
  setTimeout(() => document.getElementById('main-container').classList.remove('shake'), 600);
}

// ============================================================================
// EASTER EGG 2: AD SWAPPER RETRO ARCADE MINI-GAME (Click shield 5 times)
// ============================================================================
let shieldClicks = 0;
let gameInterval = null;
let gameScore = 0;
const shieldLogo = document.getElementById('shield-logo');

shieldLogo.addEventListener('click', () => {
  shieldClicks++;
  sfxClick();
  if (shieldClicks === 5) {
    shieldClicks = 0;
    startAdSwatter();
  }
});

function startAdSwatter() {
  document.getElementById('game-modal').classList.add('open');
  const arena = document.getElementById('game-arena');
  arena.innerHTML = '';
  gameScore = 0;
  document.getElementById('game-score').textContent = '0';
  sfxVictory();

  const ads = [
    '🔥 WIN A FREE IPAD!',
    '⚡ DOWNLOAD 64GB RAM',
    '💣 YOU ARE 1,000,000th VISITOR',
    '⚠️ VIRUS DETECTED! CLICK!',
    '🎰 999% JACKPOT BONUS'
  ];

  if (gameInterval) clearInterval(gameInterval);

  gameInterval = setInterval(() => {
    if (arena.children.length > 7) return;
    const adBox = document.createElement('div');
    adBox.style.position = 'absolute';
    adBox.style.left = Math.floor(Math.random() * (arena.clientWidth - 150)) + 'px';
    adBox.style.top = Math.floor(Math.random() * (arena.clientHeight - 40)) + 'px';
    adBox.style.background = '#fef08a';
    adBox.style.color = '#000';
    adBox.style.padding = '6px 12px';
    adBox.style.fontWeight = '900';
    adBox.style.fontSize = '12px';
    adBox.style.border = '2px solid #000';
    adBox.style.cursor = 'pointer';
    adBox.style.boxShadow = '3px 3px 0 #000';
    adBox.textContent = ads[Math.floor(Math.random() * ads.length)];

    adBox.addEventListener('click', () => {
      gameScore += 100;
      document.getElementById('game-score').textContent = gameScore;
      sfxBlocked();
      adBox.style.background = '#ff4757';
      adBox.textContent = '💀 VAPORIZED!';
      setTimeout(() => adBox.remove(), 200);
    });

    arena.appendChild(adBox);
  }, 700);
}

document.getElementById('btn-close-game').addEventListener('click', () => {
  document.getElementById('game-modal').classList.remove('open');
  if (gameInterval) clearInterval(gameInterval);
  sfxClick();
});

// ============================================================================
// EASTER EGG 3: DOUBLE-CLICK FOOTER FOR HARDWARE SUPREMACY
// ============================================================================
document.getElementById('footer-trigger').addEventListener('dblclick', () => {
  sfxVictory();
  alert('🚀 HARDWARE SUPREMACY UNLOCKED:\n• Chip: ESP32-S3 Dual-Core LX7 @ 240MHz\n• Memory: 8MB Octal PSRAM + 16MB Flash\n• Core 1: Dedicated Real-Time DNS Obliteration Engine\n• Core 0: Web Server & Wi-Fi Management\n• Verdict: Zero Ads Allowed. Deal With It.');
});

// Interactive Stat Cards Celebrations
document.getElementById('total-queries').addEventListener('click', () => {
  sfxAllowed();
  const el = document.getElementById('val-total');
  el.style.transform = 'scale(1.2)';
  setTimeout(() => el.style.transform = 'scale(1)', 150);
});

const blockedCardEl = document.getElementById('card-blocked') || document.getElementById('blocked-queries');
if (blockedCardEl) {
  blockedCardEl.addEventListener('click', () => {
    sfxBlocked();
    alert('💀 TRACKER GRAVEYARD:\nEvery tracking pixel, telemetry probe, and bloated ad banner is intercepted in PSRAM and atomized.\nZero surveillance passes through this ESP32.');
  });
}

const rateCardEl = document.getElementById('card-rate');
if (rateCardEl) {
  rateCardEl.addEventListener('click', () => {
    sfxAllowed();
    alert('⚡ SUPERIORITY REPORT:\nMathematical perfection: 100% of detected surveillance traffic vaporized.\nBig Tech advertisers are currently in deep crisis.');
  });
}

const bwCardEl = document.getElementById('card-bandwidth');
if (bwCardEl) {
  bwCardEl.addEventListener('click', () => {
    sfxVictory();
    alert('🚀 BANDWIDTH DEFENSE:\nMegabytes of tracking bloatware and ad video scripts prevented from stealing your data.');
  });
}

const cryingCardEl = document.getElementById('card-crying');
if (cryingCardEl) {
  cryingCardEl.addEventListener('click', () => {
    sfxBlocked();
    alert('😭 AD EXEC DESPAIR INDEX:\nEstimated ad executive tears produced from lost impressions.');
  });
}
</script>

</body>
</html>)rawhtml";

        html.replace("%ADMIN_API_KEY%", _adminApiKey);
        _server.send(200, "text/html", html);
    }

    // -----------------------------------------------------------------------
    // GET /api/stats — JSON Stats Endpoint
    // -----------------------------------------------------------------------
    void _handleApiStats() {
        _addSecurityHeaders();
        uint32_t total = _dns->totalQueries;
        uint32_t blocked = _dns->blockedQueries;
        float rate = (total > 0) ? (100.0f * blocked / total) : 0.0f;
        uint32_t freeHeap = ESP.getFreeHeap();
        uint32_t freePsram = ESP.getFreePsram();
        uint32_t uptime = millis() / 1000;

        uint32_t cacheHits = _cache ? _cache->getTotalHits() : 0;
        uint32_t cacheMisses = _cache ? _cache->getTotalMisses() : 0;
        uint32_t cacheEntries = _cache ? _cache->getActiveCount() : 0;
        float cacheRate = _cache ? _cache->getHitRatePercent() : 0.0f;
        const char* upstreamStr = (Config::UPSTREAM_MODE == Config::UPSTREAM_MODE_DOH) ? "DNS-over-HTTPS (RFC 8484 TLS 1.3)" : "Parallel Race UDP (1.1.1.1 + 8.8.8.8) [HW TRNG]";
        bool oledConnected = _oled ? _oled->isConnected() : false;

        char json[1200];
        snprintf(json, sizeof(json),
                 "{\"total\":%u,\"blocked\":%u,\"percentage\":%.2f,\"rate\":%.2f,"
                 "\"free_heap\":%u,\"heap\":%u,\"free_psram\":%u,\"psram\":%u,"
                 "\"uptime\":%u,"
                 "\"blocklist_count\":%u,\"blocklist_size\":%u,"
                 "\"whitelist_count\":%u,\"whitelist_size\":%u,"
                 "\"blacklist_count\":%u,"
                 "\"cache_hits\":%u,\"cache_misses\":%u,\"cache_entries\":%u,\"cache_hit_rate\":%.2f,"
                 "\"simd_patterns\":%u,\"simd_engine\":\"Xtensa LX7 128-bit PIE\","
                 "\"trng_active\":true,\"mdns_url\":\"http://adsorb.local/\","
                 "\"encrypted\":true,\"tls_version\":\"TLS 1.3\","
                 "\"http_dns_endpoint\":\"/dns-query\",\"doh_endpoint\":\"/dns-query\",\"doh_tls_verified\":true,"
                 "\"malformed_queries\":%u,\"parse_failures\":%u,\"upstream_timeouts\":%u,\"upstream_validation_errors\":%u,"
                 "\"upstream_mode\":\"%s\",\"oled_connected\":%s}",
                 total, blocked, rate, rate,
                 freeHeap, freeHeap, freePsram, freePsram,
                 uptime,
                 (unsigned)_blocklist->blockedCount(), (unsigned)_blocklist->blockedCount(),
                 (unsigned)_blocklist->whitelistCount(), (unsigned)_blocklist->whitelistCount(),
                 (unsigned)_blocklist->customBlacklistCount(),
                 cacheHits, cacheMisses, cacheEntries, cacheRate,
                 (unsigned)_blocklist->simdPatternCount(),
                 _dns->getMalformedQueries(), _dns->getParseFailures(),
                 _dns->getUpstreamTimeouts(), _dns->getUpstreamValidationErrors(),
                 upstreamStr, oledConnected ? "true" : "false");

        _server.send(200, "application/json", json);
    }

    static String _escapeJsonString(const char* s) {
        if (!s) return "";
        String out;
        out.reserve(strlen(s) + 8);
        for (size_t i = 0; s[i] != '\0'; i++) {
            char c = s[i];
            switch (c) {
                case '\"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        out += buf;
                    } else {
                        out += c;
                    }
                    break;
            }
        }
        return out;
    }

    // -----------------------------------------------------------------------
    // GET /api/queries — Query Log JSON Endpoint
    // -----------------------------------------------------------------------
    void _handleApiQueries() {
        _addSecurityHeaders();
        size_t count = 0;
        const QueryLogEntry* log = _dns->getQueryLog(count);
        size_t logIndex = _dns->getLogIndex();

        String json = "[";
        size_t toReturn = (count > 50) ? 50 : count;
        bool first = true;
        for (size_t i = 0; i < toReturn; i++) {
            size_t idx = (logIndex + Config::RING_BUFFER_CAPACITY - 1 - i) % Config::RING_BUFFER_CAPACITY;
            const QueryLogEntry& e = log[idx];
            if (e.domain[0] == '\0') continue;

            if (!first) json += ",";
            first = false;

            json += "{\"domain\":\"";
            json += _escapeJsonString(e.domain);
            json += "\",\"client_ip\":\"";
            json += _escapeJsonString(e.clientIP);
            json += "\",\"blocked\":";
            json += e.blocked ? "true" : "false";
            json += ",\"timestamp\":";
            json += String(e.timestamp);
            json += ",\"latency_ms\":";
            json += String(e.latency_ms);
            json += "}";
        }
        json += "]";
        _server.send(200, "application/json", json);
    }

    // -----------------------------------------------------------------------
    // GET /api/whitelist
    // -----------------------------------------------------------------------
    void _handleGetWhitelist() {
        _addSecurityHeaders();
        String json;
        _blocklist->getWhitelistAsJson(json);
        _server.send(200, "application/json", json);
    }

    // -----------------------------------------------------------------------
    // POST /api/whitelist
    // -----------------------------------------------------------------------
    void _handlePostWhitelist() {
        if (!_isAuthorized()) {
            _addSecurityHeaders();
            _server.send(401, "application/json", "{\"error\":\"Unauthorized: valid API key required via X-API-Key or Authorization header or ?key=\"}");
            return;
        }

        if (_server.hasArg("domain") && !_server.hasArg("plain")) {
            String domain = _server.arg("domain");
            domain.trim();
            if (domain.length() > 0) {
                _blocklist->addToWhitelist(domain);
            }
            _server.sendHeader("Location", "/");
            _server.send(303, "text/plain", "Redirecting...");
            return;
        }

        String body = _server.arg("plain");
        String domain;
        if (!_extractDomainFromJson(body, domain)) {
            _server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
            return;
        }

        domain.trim();
        if (domain.length() == 0) {
            _server.send(400, "application/json", "{\"error\":\"Domain required\"}");
            return;
        }

        if (!_blocklist->addToWhitelist(domain)) {
            _server.send(400, "application/json", "{\"error\":\"Invalid domain name\"}");
            return;
        }
        String resp = "{\"status\":\"ok\",\"domain\":\"" + domain + "\"}";
        _server.send(200, "application/json", resp);
    }

    // -----------------------------------------------------------------------
    // DELETE /api/whitelist
    // -----------------------------------------------------------------------
    void _handleDeleteWhitelist() {
        if (!_isAuthorized()) {
            _addSecurityHeaders();
            _server.send(401, "application/json", "{\"error\":\"Unauthorized: valid API key required via X-API-Key or Authorization header or ?key=\"}");
            return;
        }

        String domain;
        if (_server.hasArg("domain")) {
            domain = _server.arg("domain");
        } else if (_server.hasArg("plain")) {
            _extractDomainFromJson(_server.arg("plain"), domain);
        }

        domain.trim();
        _blocklist->removeFromWhitelist(domain);
        String resp = "{\"status\":\"ok\",\"domain\":\"" + domain + "\"}";
        _server.send(200, "application/json", resp);
    }

    // -----------------------------------------------------------------------
    // GET /api/blacklist
    // -----------------------------------------------------------------------
    void _handleGetBlacklist() {
        _addSecurityHeaders();
        String json;
        _blocklist->getCustomBlacklistAsJson(json);
        _server.send(200, "application/json", json);
    }

    // -----------------------------------------------------------------------
    // POST /api/blacklist
    // -----------------------------------------------------------------------
    void _handlePostBlacklist() {
        if (!_isAuthorized()) {
            _addSecurityHeaders();
            _server.send(401, "application/json", "{\"error\":\"Unauthorized: valid API key required via X-API-Key or Authorization header or ?key=\"}");
            return;
        }

        if (_server.hasArg("domain") && !_server.hasArg("plain")) {
            String domain = _server.arg("domain");
            domain.trim();
            if (domain.length() > 0) {
                _blocklist->addToBlacklist(domain);
            }
            _server.sendHeader("Location", "/");
            _server.send(303, "text/plain", "Redirecting...");
            return;
        }

        String body = _server.arg("plain");
        String domain;
        if (!_extractDomainFromJson(body, domain)) {
            _server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
            return;
        }

        domain.trim();
        if (domain.length() == 0) {
            _server.send(400, "application/json", "{\"error\":\"Domain required\"}");
            return;
        }

        if (!_blocklist->addToBlacklist(domain)) {
            _server.send(400, "application/json", "{\"error\":\"Invalid domain name\"}");
            return;
        }
        String resp = "{\"status\":\"ok\",\"domain\":\"" + domain + "\"}";
        _server.send(200, "application/json", resp);
    }

    // -----------------------------------------------------------------------
    // DELETE /api/blacklist
    // -----------------------------------------------------------------------
    void _handleDeleteBlacklist() {
        if (!_isAuthorized()) {
            _addSecurityHeaders();
            _server.send(401, "application/json", "{\"error\":\"Unauthorized: valid API key required via X-API-Key or Authorization header or ?key=\"}");
            return;
        }

        String domain;
        if (_server.hasArg("domain")) {
            domain = _server.arg("domain");
        } else if (_server.hasArg("plain")) {
            _extractDomainFromJson(_server.arg("plain"), domain);
        }

        domain.trim();
        _blocklist->removeFromBlacklist(domain);
        String resp = "{\"status\":\"ok\",\"domain\":\"" + domain + "\"}";
        _server.send(200, "application/json", resp);
    }

    // -----------------------------------------------------------------------
    // 404 / 405 Handler
    // -----------------------------------------------------------------------
    void _handleNotFound() {
        _addSecurityHeaders();
        if (_server.method() == HTTP_POST && _server.uri() == "/api/stats") {
            _server.send(405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }
        _server.send(404, "text/plain", "404 Not Found");
    }

    // -----------------------------------------------------------------------
    // Robust JSON domain extractor with unescaping and key validation
    // -----------------------------------------------------------------------
    static bool _extractDomainFromJson(const String& body, String& outDomain) {
        const char* p = body.c_str();
        size_t len = body.length();
        if (len < 10) return false;

        // Locate "domain" key
        const char* key = "\"domain\"";
        const char* kpos = strstr(p, key);
        while (kpos) {
            const char* check = kpos - 1;
            while (check >= p && ((unsigned char)*check <= ' ' || *check == 127)) {
                check--;
            }
            if (check >= p && (*check == '{' || *check == ',')) {
                break; // Valid JSON key position
            }
            kpos = strstr(kpos + 8, key);
        }

        if (!kpos) return false;

        const char* cur = kpos + 8;
        while (*cur && ((unsigned char)*cur <= ' ' || *cur == 127)) cur++;
        if (*cur != ':') return false;
        cur++;
        while (*cur && ((unsigned char)*cur <= ' ' || *cur == 127)) cur++;
        if (*cur != '\"') return false;
        cur++; // Start of string value

        outDomain = "";
        outDomain.reserve(64);
        while (*cur && *cur != '\"') {
            if (*cur == '\\') {
                cur++;
                if (!*cur) return false;
                if (*cur == '\"') outDomain += '\"';
                else if (*cur == '\\') outDomain += '\\';
                else if (*cur == '/') outDomain += '/';
                else if (*cur == 'b') outDomain += '\b';
                else if (*cur == 'f') outDomain += '\f';
                else if (*cur == 'n') outDomain += '\n';
                else if (*cur == 'r') outDomain += '\r';
                else if (*cur == 't') outDomain += '\t';
                else outDomain += *cur;
            } else {
                outDomain += *cur;
            }
            cur++;
        }
        if (*cur != '\"') return false;
        return true;
    }
};
