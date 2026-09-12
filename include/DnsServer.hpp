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
    volatile uint32_t malformedQueries = 0;
    volatile uint32_t parseFailures = 0;
    volatile uint32_t upstreamTimeouts = 0;
    volatile uint32_t upstreamValidationErrors = 0;

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
            _sendAuthoritativeIpResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd, qtype, myIP);
            _logQuery(domain.c_str(), clientIP, clientPort, false, 1);
            return true;
        }

        // 0b. Captive Portal Redirection for SoftAP setup clients (192.168.4.x)
        if (clientIP[0] == 192 && clientIP[1] == 168 && clientIP[2] == 4 && _isCaptiveProbe(domain)) {
            totalQueries++;
            _sendAuthoritativeIpResponse(clientIP, clientPort, _packetBuf, len, txnId, qnameEnd, qtype, WiFi.softAPIP());
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

    // -----------------------------------------------------------------------
    // Inbound RFC 8484 DNS-over-HTTPS (DoH) Processor for LAN Clients
    // Processes raw binary DNS queries received via HTTP POST or GET
    // -----------------------------------------------------------------------
    int processDohPacket(const uint8_t* queryPacket, int queryLen, IPAddress clientIP,
                         uint8_t* outBuf, size_t maxOutLen) {
        if (!queryPacket || queryLen < 12 || !outBuf || maxOutLen < 12) return -1;

        uint32_t t0 = millis();
        uint16_t txnId   = (queryPacket[0] << 8) | queryPacket[1];
        uint16_t flags   = (queryPacket[2] << 8) | queryPacket[3];
        uint16_t qdCount = (queryPacket[4] << 8) | queryPacket[5];

        if ((flags & 0x8000) != 0 || qdCount == 0 || (flags & 0x7800) != 0) {
            return _buildErrorResponse(queryPacket, queryLen, txnId, 1, outBuf, maxOutLen);
        }

        String domain = _parseDomainName(queryPacket, queryLen, 12);
        int qnameEnd = _findQNameEnd(queryPacket, queryLen, 12);
        if (qnameEnd < 0 || qnameEnd + 4 > queryLen || domain.length() == 0) {
            return _buildErrorResponse(queryPacket, queryLen, txnId, 1, outBuf, maxOutLen);
        }

        uint16_t qtype = (queryPacket[qnameEnd] << 8) | queryPacket[qnameEnd + 1];

        // 0. Zero-Config mDNS & Local Hostname: adsorb.local, adsorb, or esp32-adblocker
        if (domain.equalsIgnoreCase("adsorb.local") || domain.equalsIgnoreCase("adsorb") || domain.equalsIgnoreCase("esp32-adblocker")) {
            totalQueries++;
            IPAddress myIP = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP() : WiFi.softAPIP();
            int respLen = _buildAuthoritativeIpResponse(queryPacket, queryLen, txnId, qnameEnd, qtype, myIP, outBuf, maxOutLen);
            _logQuery(domain.c_str(), clientIP, 443, false, 1);
            return respLen;
        }

        totalQueries++;
        bool blocked = _blocklist->isBlocked(domain);

        if (blocked) {
            blockedQueries++;
            int respLen = _buildSinkholeResponse(queryPacket, queryLen, txnId, qnameEnd, qtype, outBuf, maxOutLen);
            uint32_t latency = millis() - t0;
            if (latency == 0) latency = 1;
            _logQuery(domain.c_str(), clientIP, 443, true, (uint16_t)latency);
            return respLen;
        }

        bool isWhitelisted = _blocklist->isWhitelisted(domain);

        // 1. FAST PATH: Check Sub-Millisecond PSRAM LRU Cache (<0.2ms)
        int cachedLen = 0;
        if (_cache && _cache->lookup(domain, qtype, txnId, outBuf, cachedLen)) {
            uint32_t latency = millis() - t0;
            if (latency == 0) latency = 1;
            _logQuery(domain.c_str(), clientIP, 443, false, (uint16_t)latency);
            return cachedLen;
        }

        // 2. CACHE MISS: Forward to Upstream DoH
        int respLen = -1;
        if (_doh) {
            respLen = _doh->query(queryPacket, queryLen, outBuf, maxOutLen);
            if (respLen >= 12) {
                outBuf[0] = (uint8_t)(txnId >> 8);
                outBuf[1] = (uint8_t)(txnId & 0xFF);
                if (_cache) {
                    uint32_t minTtl = DnsCache::extractMinTtl(outBuf, respLen);
                    _cache->insert(domain, qtype, outBuf, respLen, minTtl);
                }
            }
        }

        // 3. Fallback: Ultra-Fast Parallel Upstream UDP Race if DoH timed out
        if (respLen < 12) {
            respLen = _resolveUpstreamUdp(queryPacket, queryLen, txnId, outBuf, maxOutLen);
            if (respLen >= 12 && _cache) {
                uint32_t minTtl = DnsCache::extractMinTtl(outBuf, respLen);
                _cache->insert(domain, qtype, outBuf, respLen, minTtl);
            }
        }

        if (respLen < 12) {
            if (isWhitelisted) {
                respLen = _buildAuthoritativeIpResponse(queryPacket, queryLen, txnId, qnameEnd, qtype, IPAddress(192, 0, 2, 1), outBuf, maxOutLen);
            } else {
                respLen = _buildErrorResponse(queryPacket, queryLen, txnId, 2, outBuf, maxOutLen);
            }
        }

        uint32_t latency = millis() - t0;
        if (latency == 0) latency = 1;
        _logQuery(domain.c_str(), clientIP, 443, false, (uint16_t)latency);
        return respLen;
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
    // Hardened Iterative RFC 1035 Domain Name Parser with Cycle & Loop Defense
    // Bounded jump counter (<=8), visited offset cycle detection, strict bounds checks
    // -----------------------------------------------------------------------
    bool _parseDomainNameIterative(const uint8_t* buf, int len, int offset, String& outDomain) {
        outDomain = "";
        if (!buf || offset < 12 || offset >= len) {
            malformedQueries++;
            return false;
        }

        int pos = offset;
        bool first = true;
        int jumps = 0;
        uint16_t visited[8];
        size_t totalLen = 0;

        while (pos < len) {
            uint8_t labelLen = buf[pos];
            if (labelLen == 0) {
                return (totalLen > 0 && totalLen <= 253);
            }

            // Pointer compression (bits 7,6 set = 0xC0)
            if ((labelLen & 0xC0) == 0xC0) {
                if (pos + 1 >= len) {
                    malformedQueries++;
                    return false; // Truncated pointer
                }
                if (jumps >= 8) {
                    parseFailures++;
                    return false; // Exceeded maximum pointer jump limit
                }

                int ptr = ((labelLen & 0x3F) << 8) | buf[pos + 1];
                if (ptr < 12 || ptr >= len) {
                    malformedQueries++;
                    return false; // Pointer out of packet bounds or into 12-byte DNS header
                }

                // Cycle detection: check if ptr was already visited in this query chain
                for (int j = 0; j < jumps; j++) {
                    if (visited[j] == (uint16_t)ptr) {
                        parseFailures++;
                        return false; // Pointer cycle/loop detected!
                    }
                }
                visited[jumps++] = (uint16_t)ptr;
                pos = ptr;
                continue;
            }

            // Standard label (upper 2 bits must be 00)
            if ((labelLen & 0xC0) != 0) {
                malformedQueries++;
                return false; // Unsupported/reserved label type
            }
            if (labelLen > 63 || pos + 1 + labelLen > len) {
                malformedQueries++;
                return false; // Label length overflow or extends beyond packet
            }

            if (!first) {
                if (totalLen + 1 > 253) return false;
                outDomain += '.';
                totalLen++;
            }
            first = false;

            if (totalLen + labelLen > 253) return false;
            for (int i = 0; i < labelLen; i++) {
                outDomain += (char)tolower(buf[pos + 1 + i]);
            }
            totalLen += labelLen;
            pos += 1 + labelLen;
        }

        malformedQueries++;
        return false; // Reached end of packet without terminating null
    }

    String _parseDomainName(const uint8_t* buf, int len, int offset) {
        String domain;
        if (!_parseDomainNameIterative(buf, len, offset, domain)) {
            return "";
        }
        return domain;
    }

    // -----------------------------------------------------------------------
    // Find end of QNAME in question section with strict bounds checking
    // -----------------------------------------------------------------------
    int _findQNameEnd(const uint8_t* buf, int len, int offset) {
        if (!buf || offset < 12 || offset >= len) return -1;
        int pos = offset;
        while (pos < len) {
            uint8_t labelLen = buf[pos];
            if (labelLen == 0) return pos + 1; // Past the null terminator
            if ((labelLen & 0xC0) == 0xC0) {
                if (pos + 1 >= len) return -1;
                return pos + 2; // Past pointer in question section
            }
            if ((labelLen & 0xC0) != 0 || labelLen > 63 || pos + 1 + labelLen > len) {
                return -1;
            }
            pos += 1 + labelLen;
        }
        return -1;
    }

    // -----------------------------------------------------------------------
    // Buffer Response Builders (Shared by UDP Engine & Inbound DoH Server)
    // -----------------------------------------------------------------------
    static int _buildErrorResponse(const uint8_t* query, int queryLen, uint16_t txnId, uint8_t rcode,
                                   uint8_t* outBuf, size_t maxOutLen) {
        if (maxOutLen < 12) return -1;
        outBuf[0] = (uint8_t)(txnId >> 8);
        outBuf[1] = (uint8_t)(txnId & 0xFF);
        outBuf[2] = 0x81; // QR=1, RD=1
        outBuf[3] = 0x80 | (rcode & 0x0F); // RA=1, RCODE
        outBuf[4] = 0; outBuf[5] = 0;
        outBuf[6] = 0; outBuf[7] = 0;
        outBuf[8] = 0; outBuf[9] = 0;
        outBuf[10] = 0; outBuf[11] = 0;
        return 12;
    }

    static int _buildNxDomainResponse(const uint8_t* query, int queryLen, uint16_t txnId, int qnameEnd,
                                      uint8_t* outBuf, size_t maxOutLen) {
        int questionEnd = qnameEnd + 4;
        if (questionEnd > queryLen || questionEnd > (int)maxOutLen - 32) return -1;
        memcpy(outBuf, query, questionEnd);
        int respLen = questionEnd;
        outBuf[2] = 0x84 | (query[2] & 0x01);
        outBuf[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
        outBuf[6] = 0; outBuf[7] = 0;
        outBuf[8] = 0; outBuf[9] = 0;
        outBuf[10] = 0; outBuf[11] = 0;
        return respLen;
    }

    // Authoritative IP response with correct RFC QTYPE/QCLASS handling
    static int _buildAuthoritativeIpResponse(const uint8_t* query, int queryLen, uint16_t txnId, int qnameEnd,
                                            uint16_t qtype, IPAddress ip, uint8_t* outBuf, size_t maxOutLen) {
        int questionEnd = qnameEnd + 4;
        if (questionEnd > queryLen || questionEnd > (int)maxOutLen - 32) return -1;
        memcpy(outBuf, query, questionEnd);
        int respLen = questionEnd;
        outBuf[0] = (uint8_t)(txnId >> 8);
        outBuf[1] = (uint8_t)(txnId & 0xFF);
        outBuf[2] = 0x84 | (query[2] & 0x01); // QR=1, AA=1, preserve RD
        outBuf[3] = 0x80; // RA=1, RCODE=0
        outBuf[4] = 0; outBuf[5] = 1; // QDCOUNT = 1
        outBuf[8] = 0; outBuf[9] = 0; // NSCOUNT = 0
        outBuf[10] = 0; outBuf[11] = 0; // ARCOUNT = 0

        if (qtype == 1) { // Type A (IPv4)
            outBuf[6] = 0x00; outBuf[7] = 0x01; // ANCOUNT = 1
            outBuf[respLen++] = 0xC0; outBuf[respLen++] = 0x0C; // Pointer to QNAME
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x01; // TYPE A
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x01; // CLASS IN
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x00;
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x3C; // TTL 60s
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x04; // RDLENGTH = 4
            outBuf[respLen++] = ip[0];
            outBuf[respLen++] = ip[1];
            outBuf[respLen++] = ip[2];
            outBuf[respLen++] = ip[3];
        } else {
            // Type AAAA or other: RFC authoritative NODATA response (NOERROR, ANCOUNT = 0)
            outBuf[6] = 0x00; outBuf[7] = 0x00; // ANCOUNT = 0
        }
        return respLen;
    }

    void _sendErrorResponse(IPAddress clientIP, uint16_t clientPort, uint16_t txnId, uint8_t rcode) {
        uint8_t resp[12];
        int len = _buildErrorResponse(nullptr, 0, txnId, rcode, resp, sizeof(resp));
        if (len > 0) {
            _udp.beginPacket(clientIP, clientPort);
            _udp.write(resp, len);
            _udp.endPacket();
        }
    }

    void _sendNxDomainResponse(IPAddress clientIP, uint16_t clientPort,
                               const uint8_t* query, int queryLen,
                               uint16_t txnId, int qnameEnd) {
        uint8_t resp[512];
        int len = _buildNxDomainResponse(query, queryLen, txnId, qnameEnd, resp, sizeof(resp));
        if (len > 0) {
            _udp.beginPacket(clientIP, clientPort);
            _udp.write(resp, len);
            _udp.endPacket();
        }
    }

    void _sendAuthoritativeIpResponse(IPAddress clientIP, uint16_t clientPort,
                                      const uint8_t* query, int queryLen,
                                      uint16_t txnId, int qnameEnd, uint16_t qtype, IPAddress ip) {
        uint8_t resp[512];
        int len = _buildAuthoritativeIpResponse(query, queryLen, txnId, qnameEnd, qtype, ip, resp, sizeof(resp));
        if (len > 0) {
            _udp.beginPacket(clientIP, clientPort);
            _udp.write(resp, len);
            _udp.endPacket();
        }
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
    static int _buildSinkholeResponse(const uint8_t* query, int queryLen,
                                      uint16_t txnId, int qnameEnd, uint16_t qtype,
                                      uint8_t* outBuf, size_t maxOutLen) {
        int questionEnd = qnameEnd + 4; // QTYPE (2) + QCLASS (2)
        if (questionEnd > queryLen || questionEnd > (int)maxOutLen - 32) return -1;

        memcpy(outBuf, query, questionEnd);
        int respLen = questionEnd;

        // Flags: QR=1 (response), AA=1 (authoritative), RA=1, preserve RD, RCODE=0 (NoError)
        outBuf[2] = 0x84 | (query[2] & 0x01);
        outBuf[3] = 0x80; // RA=1, RCODE=0

        if (qtype == 1) {
            // ANCOUNT = 1
            outBuf[6] = 0x00;
            outBuf[7] = 0x01;
            outBuf[8] = 0; outBuf[9] = 0;
            outBuf[10] = 0; outBuf[11] = 0;

            outBuf[respLen++] = 0xC0;
            outBuf[respLen++] = 0x0C;
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x01; // TYPE A
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x01; // CLASS IN
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x00;
            outBuf[respLen++] = 0x01; outBuf[respLen++] = 0x2C; // TTL = 300s
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x04; // RDLENGTH = 4
            outBuf[respLen++] = 0x00; respLen++;                // 0.0.0.0
            outBuf[respLen - 1] = 0;
            outBuf[respLen++] = 0;
            outBuf[respLen++] = 0;
        } else if (qtype == 28) {
            // AAAA record answer: pointer to QNAME (0xC00C) + TYPE AAAA (28) + CLASS IN + TTL 300 + RDLENGTH 16 + ::
            outBuf[6] = 0x00;
            outBuf[7] = 0x01;
            outBuf[8] = 0; outBuf[9] = 0;
            outBuf[10] = 0; outBuf[11] = 0;

            outBuf[respLen++] = 0xC0;
            outBuf[respLen++] = 0x0C;
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x1C; // TYPE AAAA (28)
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x01; // CLASS IN
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x00;
            outBuf[respLen++] = 0x01; outBuf[respLen++] = 0x2C; // TTL = 300s
            outBuf[respLen++] = 0x00; outBuf[respLen++] = 0x10; // RDLENGTH = 16
            for (int i = 0; i < 16; ++i) {
                outBuf[respLen++] = 0x00; // :: (unspecified IPv6 address)
            }
        } else {
            outBuf[6] = 0x00;
            outBuf[7] = 0x00;
            outBuf[8] = 0; outBuf[9] = 0;
            outBuf[10] = 0; outBuf[11] = 0;
        }
        return respLen;
    }

    void _sendSinkholeResponse(IPAddress clientIP, uint16_t clientPort,
                                const uint8_t* query, int queryLen,
                                uint16_t txnId, int qnameEnd, uint16_t qtype) {
        uint8_t resp[512];
        int respLen = _buildSinkholeResponse(query, queryLen, txnId, qnameEnd, qtype, resp, sizeof(resp));
        if (respLen > 0) {
            _udp.beginPacket(clientIP, clientPort);
            _udp.write(resp, respLen);
            _udp.endPacket();
        }
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
    // Ultra-Fast Parallel Upstream UDP Race (Cloudflare 1.1.1.1 & Google 8.8.8.8)
    // Protected by Hardware TRNG Cryptographic Transaction ID Randomization
    // -----------------------------------------------------------------------
    int _resolveUpstreamUdp(const uint8_t* query, int queryLen, uint16_t txnId,
                            uint8_t* outBuf, size_t maxOutLen) {
        IPAddress primaryIP, secondaryIP;
        primaryIP.fromString(Config::UPSTREAM_DNS_PRIMARY);
        secondaryIP.fromString(Config::UPSTREAM_DNS_SECONDARY);

        while (_fwdUdp.parsePacket() > 0) {
            _fwdUdp.flush();
        }

        uint16_t cryptoTxnId = (uint16_t)(esp_random() & 0xFFFF);
        if (cryptoTxnId == 0) cryptoTxnId = 1;

        uint8_t trngQuery[512];
        int trngLen = (queryLen <= (int)sizeof(trngQuery)) ? queryLen : sizeof(trngQuery);
        memcpy(trngQuery, query, trngLen);
        trngQuery[0] = (uint8_t)(cryptoTxnId >> 8);
        trngQuery[1] = (uint8_t)(cryptoTxnId & 0xFF);

        _fwdUdp.beginPacket(primaryIP, 53);
        _fwdUdp.write(trngQuery, trngLen);
        _fwdUdp.endPacket();

        _fwdUdp.beginPacket(secondaryIP, 53);
        _fwdUdp.write(trngQuery, trngLen);
        _fwdUdp.endPacket();

        uint32_t start = millis();
        while (millis() - start < Config::UPSTREAM_UDP_TIMEOUT_MS) {
            int replySize = _fwdUdp.parsePacket();
            if (replySize >= 12 && replySize <= (int)maxOutLen) {
                IPAddress senderIP = _fwdUdp.remoteIP();
                uint16_t senderPort = _fwdUdp.remotePort();

                // Validate Source IP: must originate strictly from primary or secondary upstream resolver
                if (senderIP != primaryIP && senderIP != secondaryIP) {
                    upstreamValidationErrors++;
                    _fwdUdp.flush();
                    continue;
                }

                // Validate Source Port: must be standard DNS port 53
                if (senderPort != 53) {
                    upstreamValidationErrors++;
                    _fwdUdp.flush();
                    continue;
                }

                int replyLen = _fwdUdp.read(outBuf, maxOutLen);
                _fwdUdp.flush();

                if (replyLen >= 12) {
                    // 1. Transaction ID matching
                    uint16_t replyTxnId = (outBuf[0] << 8) | outBuf[1];
                    if (replyTxnId != cryptoTxnId) {
                        upstreamValidationErrors++;
                        continue;
                    }

                    // 2. Validate QR bit: bit 7 of byte 2 must be 1 (Response)
                    if ((outBuf[2] & 0x80) == 0) {
                        upstreamValidationErrors++;
                        continue;
                    }

                    // 3. Validate Opcode: bits 6..3 of byte 2 must be 0 (Standard query)
                    if ((outBuf[2] & 0x78) != 0) {
                        upstreamValidationErrors++;
                        continue;
                    }

                    // 4. Validate QDCOUNT: response question count must match (1)
                    uint16_t respQdCount = (outBuf[4] << 8) | outBuf[5];
                    if (respQdCount != 1) {
                        upstreamValidationErrors++;
                        continue;
                    }

                    // Rewrite Transaction ID to match client's query
                    outBuf[0] = (uint8_t)(txnId >> 8);
                    outBuf[1] = (uint8_t)(txnId & 0xFF);
                    return replyLen;
                }
            }
            vTaskDelay(pdMS_TO_TICKS(1));
        }
        upstreamTimeouts++;
        return -1;
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

        // 2. Ultra-Fast Parallel Upstream UDP Race Fallback
        if (!resolved) {
            int replyLen = _resolveUpstreamUdp(query, queryLen, txnId, _fwdBuf, sizeof(_fwdBuf));
            if (replyLen >= 12) {
                if (isWhitelisted && (_fwdBuf[3] & 0x0F) == 3) {
                    _sendPublicFallbackResponse(clientIP, clientPort, query, queryLen, txnId, qnameEnd);
                } else {
                    _udp.beginPacket(clientIP, clientPort);
                    _udp.write(_fwdBuf, replyLen);
                    _udp.endPacket();

                    if (_cache) {
                        uint32_t minTtl = DnsCache::extractMinTtl(_fwdBuf, replyLen);
                        _cache->insert(domain, qtype, _fwdBuf, replyLen, minTtl);
                    }
                }
                resolved = true;
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

public:
    uint32_t getMalformedQueries() const { return malformedQueries; }
    uint32_t getParseFailures() const { return parseFailures; }
    uint32_t getUpstreamTimeouts() const { return upstreamTimeouts; }
    uint32_t getUpstreamValidationErrors() const { return upstreamValidationErrors; }
};
