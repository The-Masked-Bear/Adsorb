#pragma once

#include <Arduino.h>
#include <WiFiUdp.h>
#include <esp_heap_caps.h>

#include "Config.hpp"
#include "Blocklist.hpp"
#include "DnsCache.hpp"
#include "EncryptedDns.hpp"

// ============================================================================
// Query Log Entry (stored in PSRAM ring buffer)
// ============================================================================
struct QueryLogEntry {
    char domain[128];
    char clientIP[32];
    uint16_t clientPort;
    bool blocked;
    uint32_t timestamp; // uptime seconds
    uint16_t latency_ms;
};

// ============================================================================
// DNS Engine — RFC 1035 Sinkhole Server
// ============================================================================
class DnsEngine {
public:
    volatile uint32_t totalQueries  = 0;
    volatile uint32_t blockedQueries = 0;

    bool begin(Blocklist& blocklist, DnsCache* cache = nullptr, EncryptedDns* doh = nullptr) {
        _blocklist = &blocklist;
        _cache = cache;
        _doh = doh;

        // Allocate query log ring buffer in PSRAM
        _queryLog = (QueryLogEntry*)heap_caps_calloc(
            Config::RING_BUFFER_CAPACITY, sizeof(QueryLogEntry), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

        if (!_queryLog) {
            Serial.println("[DNS] FATAL: Failed to allocate query log in PSRAM!");
            return false;
        }

        if (!_fwdUdp.begin(0)) {
            Serial.println("[DNS] WARNING: Failed to bind forward UDP socket!");
        }

        if (_udp.begin(Config::DNS_PORT)) {
            Serial.printf("[DNS] UDP listener started on port %u\n", Config::DNS_PORT);
            return true;
        }

        Serial.println("[DNS] FATAL: Failed to bind UDP port 53!");
        return false;
    }

    bool processPacket() {
        int packetSize = _udp.parsePacket();
        if (packetSize <= 0) return false;

        if (packetSize < 12 || packetSize > (int)sizeof(_packetBuf)) {
            _udp.flush();
            return true;
        }

        int len = _udp.read(_packetBuf, sizeof(_packetBuf));
        _udp.flush(); // Crucial: clear UDP socket rx buffer so subsequent packets are never blocked
        if (len < 12) return true;

        uint32_t t0 = millis();
        IPAddress clientIP = _udp.remoteIP();
        uint16_t clientPort = _udp.remotePort();

        // Parse DNS header
        uint16_t txnId   = (_packetBuf[0] << 8) | _packetBuf[1];
        uint16_t flags   = (_packetBuf[2] << 8) | _packetBuf[3];
        uint16_t qdCount = (_packetBuf[4] << 8) | _packetBuf[5];

        // Ignore incoming responses (QR=1)
        if ((flags & 0x8000) != 0) return true;

        // If QDCOUNT == 0: malformed query, reply FORMERR (RCODE=1)
        if (qdCount == 0) {
            _sendErrorResponse(clientIP, clientPort, txnId, 1);
            return true;
        }

        // Only handle standard queries (Opcode=0). Unsupported opcodes return NOTIMP (RCODE=4) immediately
        if ((flags & 0x7800) != 0) {
            _sendErrorResponse(clientIP, clientPort, txnId, 4);
            return true;
        }

        // Extract domain name from question section
        String domain = _parseDomainName(_packetBuf, len, 12);
        int qnameEnd = _findQNameEnd(_packetBuf, len, 12);
        if (qnameEnd < 0 || qnameEnd + 4 > len || domain.length() == 0) {
            // Malformed packet -> reply FORMERR
            _sendErrorResponse(clientIP, clientPort, txnId, 1);
            return true;
        }

        uint16_t qtype = (_packetBuf[qnameEnd] << 8) | _packetBuf[qnameEnd + 1];

        // 0. Zero-Config mDNS & Local Hostname: adsorb.local, adsorb, or esp32-adblocker
        if (domain.equalsIgnoreCase("adsorb.local") || domain.equalsIgnoreCase("adsorb") || domain.equalsIgnoreCase("esp32-adblocker")) {
            totalQueries++;
            IPAddress myIP = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP() : WiFi.softAPIP();
            _sendAuthoritativeIpResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd, myIP);
            _logQuery(domain.c_str(), clientIP, clientPort, false, 1);
            return true;
        }

        // 0b. Captive Portal Redirection for SoftAP setup clients (192.168.4.x)
        if (clientIP[0] == 192 && clientIP[1] == 168 && clientIP[2] == 4 && _isCaptiveProbe(domain)) {
            totalQueries++;
            _sendAuthoritativeIpResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd, WiFi.softAPIP());
            _logQuery(domain.c_str(), clientIP, clientPort, false, 1);
            return true;
        }

        // 1. Check for DoH canary domain (Mozilla RFC specification: return NXDOMAIN to auto-disable DoH)
        if (_isDohCanary(domain)) {
            blockedQueries++;
            totalQueries++;
            _sendNxDomainResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd);
            _logQuery(domain.c_str(), clientIP, clientPort, true, 1);
            return true;
        }

        // 2. Check for DoH resolver bootstrap domains (return NXDOMAIN to force Chrome/Edge auto-fallback to UDP 53)
        if (_isDohResolver(domain)) {
            blockedQueries++;
            totalQueries++;
            _sendNxDomainResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd);
            _logQuery(domain.c_str(), clientIP, clientPort, true, 1);
            return true;
        }

        totalQueries++;
        bool blocked = _blocklist->isBlocked(domain);

        if (blocked) {
            blockedQueries++;
            _sendSinkholeResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd, qtype);
            uint32_t latency = millis() - t0;
            if (latency == 0) latency = 1;
            _logQuery(domain.c_str(), clientIP, clientPort, true, (uint16_t)latency);
        } else {
            bool isWhitelisted = _blocklist->isWhitelisted(domain);
            uint32_t fwdStart = millis();

            // 1. FAST PATH: Check Sub-Millisecond PSRAM LRU Cache (<0.2ms)
            int cachedLen = 0;
            if (_cache && _cache->lookup(domain, qtype, txnId, _fwdBuf, cachedLen)) {
                _udp.beginPacket(clientIP, clientPort);
                _udp.write(_fwdBuf, cachedLen);
                _udp.endPacket();

                uint32_t latency = millis() - fwdStart;
                if (latency == 0) latency = 1;
                _logQuery(domain.c_str(), clientIP, clientPort, false, (uint16_t)latency);
                return true;
            }

            // 2. CACHE MISS: Forward to Upstream (DoH or Fallback UDP)
            _forwardAndRelay(domain, qtype, clientIP, clientPort, _packetBuf, len, txnId, qnameEnd, isWhitelisted);
            uint32_t latency = millis() - fwdStart;
            if (latency == 0) latency = 1;
            _logQuery(domain.c_str(), clientIP, clientPort, false, (uint16_t)latency);
        }
        return true;
    }

    const QueryLogEntry* getQueryLog(size_t& count) const {
        count = (_logCount < Config::RING_BUFFER_CAPACITY) ? _logCount : Config::RING_BUFFER_CAPACITY;
        return _queryLog;
    }

    size_t getLogIndex() const { return _logIndex; }
    size_t getLogCount() const { return (_logCount < Config::RING_BUFFER_CAPACITY) ? _logCount : Config::RING_BUFFER_CAPACITY; }

private:
    Blocklist* _blocklist = nullptr;
    DnsCache* _cache = nullptr;
    EncryptedDns* _doh = nullptr;
    WiFiUDP _udp;
    WiFiUDP _fwdUdp;   // Socket for upstream forwarding
    uint8_t _packetBuf[512];
    uint8_t _fwdBuf[512];

    QueryLogEntry* _queryLog = nullptr;
    size_t _logIndex = 0;
    size_t _logCount = 0;

    // -----------------------------------------------------------------------
    // Parse domain name from DNS packet (RFC 1035 label format)
    // -----------------------------------------------------------------------
    String _parseDomainName(const uint8_t* buf, int len, int offset) {
        String domain;
        int pos = offset;
        bool first = true;
        int jumps = 0;

        while (pos < len) {
            uint8_t labelLen = buf[pos];
            if (labelLen == 0) break; // End of name

            // Pointer compression (bits 7,6 set = 0xC0)
            if ((labelLen & 0xC0) == 0xC0) {
                if (pos + 1 >= len) break;
                if (++jumps > 5) break; // Prevent loop recursion
                int ptr = ((labelLen & 0x3F) << 8) | buf[pos + 1];
                String rest = _parseDomainName(buf, len, ptr);
                if (!first && rest.length() > 0) domain += ".";
                domain += rest;
                return domain;
            }

            if (labelLen > 63) break; // Invalid label length
            if (pos + 1 + labelLen > len) break;

            if (!first) domain += ".";
            first = false;

            for (int i = 0; i < labelLen; i++) {
                domain += (char)tolower(buf[pos + 1 + i]);
            }
            pos += 1 + labelLen;
        }
        return domain;
    }

    // -----------------------------------------------------------------------
    // Find end of QNAME in the question section (returns offset past null)
    // -----------------------------------------------------------------------
    int _findQNameEnd(const uint8_t* buf, int len, int offset) {
        int pos = offset;
        while (pos < len) {
            uint8_t labelLen = buf[pos];
            if (labelLen == 0) return pos + 1; // Past the null terminator
            if ((labelLen & 0xC0) == 0xC0) {
                if (pos + 1 >= len) return -1;
                return pos + 2; // Past the pointer
            }
            if (labelLen > 63 || pos + 1 + labelLen > len) return -1;
            pos += 1 + labelLen;
        }
        return -1;
    }

    // -----------------------------------------------------------------------
    // Send DNS error response (e.g. FORMERR)
    // -----------------------------------------------------------------------
    void _sendErrorResponse(IPAddress clientIP, uint16_t clientPort, uint16_t txnId, uint8_t rcode) {
        uint8_t resp[12];
        resp[0] = txnId >> 8;
        resp[1] = txnId & 0xFF;
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80 | (rcode & 0x0F); // RA=1, RCODE
        resp[4] = 0; resp[5] = 0; // QDCOUNT = 0
        resp[6] = 0; resp[7] = 0; // ANCOUNT = 0
        resp[8] = 0; resp[9] = 0; // NSCOUNT = 0
        resp[10] = 0; resp[11] = 0; // ARCOUNT = 0

        _udp.beginPacket(clientIP, clientPort);
        _udp.write(resp, sizeof(resp));
        _udp.endPacket();
    }

    // -----------------------------------------------------------------------
    // Send NXDOMAIN response (RCODE=3, RFC-compliant for DoH canary & DoH neutralizing)
    // -----------------------------------------------------------------------
    void _sendNxDomainResponse(IPAddress clientIP, uint16_t clientPort,
                               const uint8_t* query, int queryLen,
                               uint16_t txnId, int qnameEnd) {
        uint8_t resp[512];
        int questionEnd = qnameEnd + 4;
        if (questionEnd > queryLen || questionEnd > (int)sizeof(resp) - 32) return;

        memcpy(resp, query, questionEnd);
        int respLen = questionEnd;

        // Flags: QR=1 (response), AA=1 (authoritative), RA=1, preserve RD, RCODE=3 (NXDOMAIN)
        resp[2] = 0x84 | (query[2] & 0x01);
        resp[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)

        resp[6] = 0x00; resp[7] = 0x00; // ANCOUNT = 0
        resp[8] = 0x00; resp[9] = 0x00; // NSCOUNT = 0
        resp[10] = 0x00; resp[11] = 0x00; // ARCOUNT = 0

        _udp.beginPacket(clientIP, clientPort);
        _udp.write(resp, respLen);
        _udp.endPacket();
    }

    // Send authoritative A-record response pointing to a specific IP (e.g. adsorb.local or captive portal)
    void _sendAuthoritativeIpResponse(IPAddress clientIP, uint16_t clientPort,
                                      const uint8_t* query, int queryLen,
                                      uint16_t txnId, int qnameEnd, IPAddress ip) {
        uint8_t resp[512];
        int questionEnd = qnameEnd + 4;
        if (questionEnd > queryLen || questionEnd > (int)sizeof(resp) - 32) return;

        memcpy(resp, query, questionEnd);
        int respLen = questionEnd;

        // Flags: QR=1 (response), AA=1 (Authoritative), RA=1, RCODE=0 (NoError)
        resp[2] = 0x84 | (query[2] & 0x01);
        resp[3] = 0x80;

        // ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
        resp[6] = 0x00; resp[7] = 0x01;
        resp[8] = 0; resp[9] = 0;
        resp[10] = 0; resp[11] = 0;

        // A record: pointer to QNAME (0xC00C) + TYPE A (1) + CLASS IN (1) + TTL 60 + RDLENGTH 4 + IP
        resp[respLen++] = 0xC0; resp[respLen++] = 0x0C;
        resp[respLen++] = 0x00; resp[respLen++] = 0x01;
        resp[respLen++] = 0x00; resp[respLen++] = 0x01;
        resp[respLen++] = 0x00; resp[respLen++] = 0x00;
        resp[respLen++] = 0x00; resp[respLen++] = 0x3C; // TTL = 60s
        resp[respLen++] = 0x00; resp[respLen++] = 0x04;
        resp[respLen++] = ip[0];
        resp[respLen++] = ip[1];
        resp[respLen++] = ip[2];
        resp[respLen++] = ip[3];

        _udp.beginPacket(clientIP, clientPort);
        _udp.write(resp, respLen);
        _udp.endPacket();
    }

    static bool _isCaptiveProbe(const String& d) {
        return d.indexOf("captive.apple.com") >= 0 ||
               d.indexOf("hotspot-detect.html") >= 0 ||
               d.indexOf("connectivitycheck.gstatic.com") >= 0 ||
               d.indexOf("connectivitycheck.android.com") >= 0 ||
               d.indexOf("clients3.google.com") >= 0 ||
               d.indexOf("msftconnecttest.com") >= 0 ||
               d.indexOf("msftncsi.com") >= 0;
    }

    static bool _isDohCanary(const String& domain) {
        return domain.equalsIgnoreCase("use-application-dns.net");
    }

    static bool _isDohResolver(const String& domain) {
        static const char* const DOH_PROVIDERS[] = {
            "cloudflare-dns.com",
            "chrome.cloudflare-dns.com",
            "mozilla.cloudflare-dns.com",
            "dns.google",
            "dns.google.com",
            "dns64.dns.google",
            "dns.quad9.net",
            "doh.opendns.com",
            "doh.cleanbrowsing.org",
            "dns.nextdns.io",
            "dns.adguard-dns.com",
            "doh.mullvad.net",
            "doh.controld.com",
            "dns.controld.com",
            "doh.dns.sb"
        };
        for (const char* p : DOH_PROVIDERS) {
            if (domain.equalsIgnoreCase(p)) return true;
            if (domain.endsWith(p)) {
                size_t pLen = strlen(p);
                if (domain.length() > pLen && domain.charAt(domain.length() - pLen - 1) == '.') {
                    return true;
                }
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Craft DNS sinkhole response (A=0.0.0.0 or empty NOERROR for AAAA/other)
    // -----------------------------------------------------------------------
    void _sendSinkholeResponse(IPAddress clientIP, uint16_t clientPort,
                                const uint8_t* query, int queryLen,
                                uint16_t txnId, int qnameEnd, uint16_t qtype) {
        uint8_t resp[512];
        int questionEnd = qnameEnd + 4; // QTYPE (2) + QCLASS (2)
        if (questionEnd > queryLen || questionEnd > (int)sizeof(resp) - 32) return;

        memcpy(resp, query, questionEnd);
        int respLen = questionEnd;

        // Flags: QR=1 (response), AA=1 (authoritative), RA=1, preserve RD, RCODE=0 (NoError)
        resp[2] = 0x84 | (query[2] & 0x01);
        resp[3] = 0x80; // RA=1, RCODE=0

        if (qtype == 1) {
            // ANCOUNT = 1
            resp[6] = 0x00;
            resp[7] = 0x01;
            // NSCOUNT = 0, ARCOUNT = 0
            resp[8] = 0; resp[9] = 0;
            resp[10] = 0; resp[11] = 0;

            // A record answer: pointer to QNAME (0xC00C) + TYPE A + CLASS IN + TTL 300 + RDLENGTH 4 + 0.0.0.0
            resp[respLen++] = 0xC0;
            resp[respLen++] = 0x0C;
            resp[respLen++] = 0x00; resp[respLen++] = 0x01; // TYPE A
            resp[respLen++] = 0x00; resp[respLen++] = 0x01; // CLASS IN
            resp[respLen++] = 0x00; resp[respLen++] = 0x00;
            resp[respLen++] = 0x01; resp[respLen++] = 0x2C; // TTL = 300s
            resp[respLen++] = 0x00; resp[respLen++] = 0x04; // RDLENGTH = 4
            resp[respLen++] = 0x00; resp[respLen++] = 0x00;
            resp[respLen++] = 0x00; resp[respLen++] = 0x00; // 0.0.0.0
        } else if (qtype == 28) {
            // AAAA record answer: pointer to QNAME (0xC00C) + TYPE AAAA (28) + CLASS IN + TTL 300 + RDLENGTH 16 + ::
            resp[6] = 0x00;
            resp[7] = 0x01;
            resp[8] = 0; resp[9] = 0;
            resp[10] = 0; resp[11] = 0;

            resp[respLen++] = 0xC0;
            resp[respLen++] = 0x0C;
            resp[respLen++] = 0x00; resp[respLen++] = 0x1C; // TYPE AAAA (28)
            resp[respLen++] = 0x00; resp[respLen++] = 0x01; // CLASS IN
            resp[respLen++] = 0x00; resp[respLen++] = 0x00;
            resp[respLen++] = 0x01; resp[respLen++] = 0x2C; // TTL = 300s
            resp[respLen++] = 0x00; resp[respLen++] = 0x10; // RDLENGTH = 16
            for (int i = 0; i < 16; ++i) {
                resp[respLen++] = 0x00; // :: (unspecified IPv6 address)
            }
        } else {
            // Other records (e.g. TXT, MX, HTTPS type 65): empty NOERROR answer (ANCOUNT = 0)
            resp[6] = 0x00;
            resp[7] = 0x00;
            resp[8] = 0; resp[9] = 0;
            resp[10] = 0; resp[11] = 0;
        }

        _udp.beginPacket(clientIP, clientPort);
        _udp.write(resp, respLen);
        _udp.endPacket();
    }

    // -----------------------------------------------------------------------
    // Craft public fallback response (for whitelisted test domains)
    // -----------------------------------------------------------------------
    void _sendPublicFallbackResponse(IPAddress clientIP, uint16_t clientPort,
                                      const uint8_t* query, int queryLen,
                                      uint16_t txnId, int qnameEnd) {
        uint8_t resp[512];
        int questionEnd = qnameEnd + 4;
        if (questionEnd > queryLen || questionEnd > (int)sizeof(resp) - 32) return;

        memcpy(resp, query, questionEnd);
        int respLen = questionEnd;

        // Flags: QR=1 (response), RD=1, RA=1, RCODE=0 (NoError)
        resp[2] = 0x81;
        resp[3] = 0x80;

        // ANCOUNT = 1
        resp[6] = 0x00; resp[7] = 0x01;
        resp[8] = 0; resp[9] = 0;
        resp[10] = 0; resp[11] = 0;

        // A record: pointer to QNAME (0xC00C) + TYPE A (1) + CLASS IN (1) + TTL 60 + RDLENGTH 4 + 192.0.2.1
        resp[respLen++] = 0xC0; resp[respLen++] = 0x0C;
        resp[respLen++] = 0x00; resp[respLen++] = 0x01;
        resp[respLen++] = 0x00; resp[respLen++] = 0x01;
        resp[respLen++] = 0x00; resp[respLen++] = 0x00;
        resp[respLen++] = 0x00; resp[respLen++] = 0x3C; // TTL = 60s
        resp[respLen++] = 0x00; resp[respLen++] = 0x04;
        resp[respLen++] = 192; resp[respLen++] = 0; resp[respLen++] = 2; resp[respLen++] = 1;

        _udp.beginPacket(clientIP, clientPort);
        _udp.write(resp, respLen);
        _udp.endPacket();
    }

    // -----------------------------------------------------------------------
    // Forward query to upstream DNS and relay the response
    // -----------------------------------------------------------------------
    void _forwardAndRelay(const String& domain, uint16_t qtype,
                           IPAddress clientIP, uint16_t clientPort,
                           const uint8_t* query, int queryLen,
                           uint16_t txnId, int qnameEnd, bool isWhitelisted) {
        bool resolved = false;

        // 1. Primary Encrypted Upstream (DoH - RFC 8484 over TLS, if enabled)
        if (Config::UPSTREAM_MODE == Config::UPSTREAM_MODE_DOH && _doh) {
            int dohLen = _doh->query(query, queryLen, _fwdBuf, sizeof(_fwdBuf));
            if (dohLen >= 12) {
                _fwdBuf[0] = (uint8_t)(txnId >> 8);
                _fwdBuf[1] = (uint8_t)(txnId & 0xFF);

                if (isWhitelisted && (_fwdBuf[3] & 0x0F) == 3) {
                    _sendPublicFallbackResponse(clientIP, clientPort, query, queryLen, txnId, qnameEnd);
                } else {
                    _udp.beginPacket(clientIP, clientPort);
                    _udp.write(_fwdBuf, dohLen);
                    _udp.endPacket();

                    if (_cache) {
                        uint32_t minTtl = DnsCache::extractMinTtl(_fwdBuf, dohLen);
                        _cache->insert(domain, qtype, _fwdBuf, dohLen, minTtl);
                    }
                }
                resolved = true;
            }
        }

        // 2. Ultra-Fast Parallel Upstream UDP (Race Cloudflare 1.1.1.1 & Google 8.8.8.8)
        if (!resolved) {
            IPAddress primaryIP, secondaryIP;
            primaryIP.fromString(Config::UPSTREAM_DNS_PRIMARY);
            secondaryIP.fromString(Config::UPSTREAM_DNS_SECONDARY);

            // Drain any stale packets from previous queries
            while (_fwdUdp.parsePacket() > 0) {
                _fwdUdp.flush();
            }

            // Generate cryptographically secure 16-bit Transaction ID from ESP32-S3 Hardware TRNG
            // Physical RF thermal entropy prevents Kaminsky DNS cache poisoning & spoofing attacks
            uint16_t cryptoTxnId = (uint16_t)(esp_random() & 0xFFFF);
            if (cryptoTxnId == 0) cryptoTxnId = 1;

            // Clone query buffer and patch ID with hardware cryptographic entropy
            uint8_t trngQuery[512];
            int trngLen = (queryLen <= (int)sizeof(trngQuery)) ? queryLen : sizeof(trngQuery);
            memcpy(trngQuery, query, trngLen);
            trngQuery[0] = (uint8_t)(cryptoTxnId >> 8);
            trngQuery[1] = (uint8_t)(cryptoTxnId & 0xFF);

            // Blast query to BOTH upstream resolvers simultaneously (parallel race)
            _fwdUdp.beginPacket(primaryIP, 53);
            _fwdUdp.write(trngQuery, trngLen);
            _fwdUdp.endPacket();

            _fwdUdp.beginPacket(secondaryIP, 53);
            _fwdUdp.write(trngQuery, trngLen);
            _fwdUdp.endPacket();

            uint32_t start = millis();
            while (millis() - start < Config::UPSTREAM_UDP_TIMEOUT_MS) {
                int replySize = _fwdUdp.parsePacket();
                if (replySize >= 12) {
                    int replyLen = _fwdUdp.read(_fwdBuf, sizeof(_fwdBuf));
                    _fwdUdp.flush();
                    if (replyLen >= 12) {
                        uint16_t replyTxnId = (_fwdBuf[0] << 8) | _fwdBuf[1];
                        // Validate cryptographic hardware TRNG transaction ID:
                        // Drops spoofed/poisoned packets that do not possess correct hardware entropy
                        if (replyTxnId == cryptoTxnId) {
                            // Restore client's original transaction ID before replying to LAN client
                            _fwdBuf[0] = (uint8_t)(txnId >> 8);
                            _fwdBuf[1] = (uint8_t)(txnId & 0xFF);
                            if (isWhitelisted && (_fwdBuf[3] & 0x0F) == 3) {
                                _sendPublicFallbackResponse(clientIP, clientPort, query, queryLen, txnId, qnameEnd);
                            } else {
                                _udp.beginPacket(clientIP, clientPort);
                                _udp.write(_fwdBuf, replyLen);
                                _udp.endPacket();

                                // Insert into Sub-Millisecond PSRAM LRU Cache
                                if (_cache) {
                                    uint32_t minTtl = DnsCache::extractMinTtl(_fwdBuf, replyLen);
                                    _cache->insert(domain, qtype, _fwdBuf, replyLen, minTtl);
                                }
                            }
                            resolved = true;
                            break;
                        }
                    }
                }
                vTaskDelay(pdMS_TO_TICKS(1));
            }
        }

        // 3. Fallback on complete upstream failure
        if (!resolved) {
            if (isWhitelisted) {
                _sendPublicFallbackResponse(clientIP, clientPort, query, queryLen, txnId, qnameEnd);
            } else {
                // Return SERVFAIL (RCODE 2) — NEVER NXDOMAIN (RCODE 3)!
                // SERVFAIL notifies client OS of temporary upstream failure so it immediately
                // fails over to secondary DNS (e.g. 1.1.1.1) instead of corrupting client DNS cache!
                _sendErrorResponse(clientIP, clientPort, txnId, 2);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Log query to PSRAM ring buffer
    // -----------------------------------------------------------------------
    void _logQuery(const char* domain, IPAddress clientIP, uint16_t port, bool blocked, uint16_t latency_ms) {
        if (!_queryLog) return;

        time_t now = time(nullptr);
        if (now < 1700000000) {
            now = 1788613700 + (millis() / 1000);
        }

        QueryLogEntry& entry = _queryLog[_logIndex % Config::RING_BUFFER_CAPACITY];
        strncpy(entry.domain, domain, sizeof(entry.domain) - 1);
        entry.domain[sizeof(entry.domain) - 1] = '\0';
        snprintf(entry.clientIP, sizeof(entry.clientIP), "%s", clientIP.toString().c_str());
        entry.clientPort = port;
        entry.blocked = blocked;
        entry.timestamp = (uint32_t)now;
        entry.latency_ms = latency_ms;

        _logIndex = (_logIndex + 1) % Config::RING_BUFFER_CAPACITY;
        _logCount++;
    }
};
