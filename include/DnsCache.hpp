#pragma once

#include <Arduino.h>
#include <esp_heap_caps.h>
#include "Config.hpp"

// ============================================================================
// Cache Entry Structure — Stored in Octal PSRAM
// ============================================================================
struct CacheEntry {
    uint64_t hash;          // 64-bit FNV-1a hash of lowercased domain + qtype (0 = empty)
    uint16_t qtype;         // Query Type (A=1, AAAA=28, etc.)
    uint16_t packetLen;     // Raw DNS response byte length
    uint32_t expiresAt;     // Expiration timestamp in uptime seconds
    uint32_t lastAccess;    // Last access timestamp in uptime seconds for LRU eviction
    uint32_t hits;          // Number of times this cached entry was served
    uint8_t  packet[512];   // Cached RFC 1035 response payload
};

// ============================================================================
// Sub-Millisecond PSRAM LRU DNS Cache
// 2-Way Set-Associative Architecture with O(1) Lookup Speed
// ============================================================================
class DnsCache {
public:
    DnsCache() = default;

    bool begin() {
        // Allocate cache in external Octal PSRAM
        size_t totalBytes = Config::DNS_CACHE_CAPACITY * sizeof(CacheEntry);
        _entries = (CacheEntry*)heap_caps_calloc(
            Config::DNS_CACHE_CAPACITY, sizeof(CacheEntry), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

        if (!_entries) {
            Serial.println("[DNS Cache] FATAL: Failed to allocate cache in Octal PSRAM!");
            return false;
        }

        _numSets = Config::DNS_CACHE_CAPACITY / 2; // 2-way associative (1024 sets)
        Serial.printf("[DNS Cache] Initialized %u entries (%.2f MB) in Octal PSRAM. 2-way associative.\n",
                      (unsigned)Config::DNS_CACHE_CAPACITY,
                      totalBytes / (1024.0f * 1024.0f));
        return true;
    }

    // -----------------------------------------------------------------------
    // Fast O(1) Cache Lookup (< 2 microseconds)
    // -----------------------------------------------------------------------
    bool lookup(const String& domain, uint16_t qtype, uint16_t txnId, uint8_t* outBuf, int& outLen) {
        if (!_entries) return false;

        _totalLookups++;
        uint64_t h = _computeHash(domain, qtype);
        uint32_t setIdx = ((uint32_t)(h ^ (h >> 32))) % _numSets;
        uint32_t baseIdx = setIdx * 2;
        uint32_t now = millis() / 1000;

        portENTER_CRITICAL(&_mux);
        for (uint32_t way = 0; way < 2; ++way) {
            CacheEntry& entry = _entries[baseIdx + way];
            if (entry.hash == h && entry.qtype == qtype) {
                if (now < entry.expiresAt) {
                    // Cache HIT!
                    entry.hits++;
                    entry.lastAccess = now;
                    _totalHits++;
                    uint32_t remainingTtl = entry.expiresAt - now;

                    outLen = entry.packetLen;
                    memcpy(outBuf, entry.packet, outLen);
                    portEXIT_CRITICAL(&_mux);

                    // Rewrite Transaction ID to match client's query
                    outBuf[0] = (uint8_t)(txnId >> 8);
                    outBuf[1] = (uint8_t)(txnId & 0xFF);

                    // Update TTLs in the answer section so client gets remaining TTL
                    _updateRemainingTtl(outBuf, outLen, remainingTtl);
                    return true;
                } else {
                    // Entry has expired
                    entry.hash = 0; // Invalidate
                    if (_activeEntries > 0) _activeEntries--;
                    break;
                }
            }
        }
        _totalMisses++;
        portEXIT_CRITICAL(&_mux);
        return false;
    }

    // -----------------------------------------------------------------------
    // Cache Insertion with LRU Eviction Policy
    // -----------------------------------------------------------------------
    void insert(const String& domain, uint16_t qtype, const uint8_t* packet, int packetLen, uint32_t ttl) {
        // RFC 1035 §3.2.1 / RFC 2181 §8: TTL == 0 MUST NOT be cached
        if (ttl == 0) return;
        if (!_entries || packetLen < 12 || packetLen > 512) return;

        // Verify response is valid (QR=1, RCODE=0 NoError or RCODE=3 NXDomain)
        if ((packet[2] & 0x80) == 0) return; // Must be a response
        uint8_t rcode = packet[3] & 0x0F;
        if (rcode != 0 && rcode != 3) return; // Only cache NoError and NXDomain

        // Respect authoritative TTL; only enforce upper boundary
        if (ttl > Config::DNS_CACHE_MAX_TTL) ttl = Config::DNS_CACHE_MAX_TTL;

        uint64_t h = _computeHash(domain, qtype);
        uint32_t setIdx = ((uint32_t)(h ^ (h >> 32))) % _numSets;
        uint32_t baseIdx = setIdx * 2;
        uint32_t now = millis() / 1000;

        portENTER_CRITICAL(&_mux);

        // Select which way to replace:
        // 1. Existing matching hash
        // 2. Empty slot (hash == 0)
        // 3. Expired slot (now >= expiresAt)
        // 4. LRU slot (least recently accessed)
        int targetWay = -1;
        for (int way = 0; way < 2; ++way) {
            CacheEntry& entry = _entries[baseIdx + way];
            if (entry.hash == h && entry.qtype == qtype) {
                targetWay = way;
                break;
            }
            if (entry.hash == 0 || now >= entry.expiresAt) {
                targetWay = way;
            }
        }

        if (targetWay < 0) {
            // Both ways occupied: evict LRU (older lastAccess)
            targetWay = (_entries[baseIdx + 0].lastAccess <= _entries[baseIdx + 1].lastAccess) ? 0 : 1;
            _totalEvictions++;
        } else if (_entries[baseIdx + targetWay].hash == 0) {
            _activeEntries++;
        }

        CacheEntry& dst = _entries[baseIdx + targetWay];
        dst.hash = h;
        dst.qtype = qtype;
        dst.packetLen = (uint16_t)packetLen;
        dst.expiresAt = now + ttl;
        dst.lastAccess = now;
        dst.hits = 0;
        memcpy(dst.packet, packet, packetLen);

        portEXIT_CRITICAL(&_mux);
    }

    // -----------------------------------------------------------------------
    // Helper: Extract Minimum TTL from DNS Response Packet Answers
    // -----------------------------------------------------------------------
    static uint32_t extractMinTtl(const uint8_t* buf, int len) {
        if (len < 12) return 0;

        uint16_t qdcount = (buf[4] << 8) | buf[5];
        uint16_t ancount = (buf[6] << 8) | buf[7];
        if (ancount == 0) return 0;

        // Skip Question Section
        int pos = 12;
        for (int q = 0; q < qdcount && pos < len; ++q) {
            while (pos < len) {
                uint8_t l = buf[pos];
                if (l == 0) { pos++; break; }
                if ((l & 0xC0) == 0xC0) { pos += 2; break; }
                pos += 1 + l;
            }
            pos += 4; // QTYPE (2) + QCLASS (2)
        }

        uint32_t minTtl = 0xFFFFFFFF;
        bool foundAnswer = false;

        // Parse Answer Section RRs
        for (int a = 0; a < ancount && pos < len; ++a) {
            // Skip Name (label or pointer)
            while (pos < len) {
                uint8_t l = buf[pos];
                if (l == 0) { pos++; break; }
                if ((l & 0xC0) == 0xC0) { pos += 2; break; }
                pos += 1 + l;
            }

            if (pos + 10 > len) break;
            uint32_t rrTtl = ((uint32_t)buf[pos + 4] << 24) |
                             ((uint32_t)buf[pos + 5] << 16) |
                             ((uint32_t)buf[pos + 6] << 8)  |
                             ((uint32_t)buf[pos + 7]);
            uint16_t rdlength = (buf[pos + 8] << 8) | buf[pos + 9];
            pos += 10 + rdlength;

            foundAnswer = true;
            if (rrTtl < minTtl) {
                minTtl = rrTtl;
            }
        }

        if (!foundAnswer || minTtl == 0xFFFFFFFF) {
            return 0;
        }
        return minTtl;
    }

    // -----------------------------------------------------------------------
    // Telemetry & Metrics
    // -----------------------------------------------------------------------
    uint32_t getTotalLookups() const { return _totalLookups; }
    uint32_t getTotalHits()    const { return _totalHits; }
    uint32_t getTotalMisses()  const { return _totalMisses; }
    uint32_t getEvictions()    const { return _totalEvictions; }
    uint32_t getActiveCount()  const { return _activeEntries; }

    float getHitRatePercent() const {
        if (_totalLookups == 0) return 0.0f;
        return ((float)_totalHits / (float)_totalLookups) * 100.0f;
    }

private:
    CacheEntry* _entries = nullptr;
    uint32_t _numSets = 0;
    portMUX_TYPE _mux = portMUX_INITIALIZER_UNLOCKED;

    volatile uint32_t _totalLookups   = 0;
    volatile uint32_t _totalHits      = 0;
    volatile uint32_t _totalMisses    = 0;
    volatile uint32_t _totalEvictions = 0;
    volatile uint32_t _activeEntries  = 0;

    // 64-bit FNV-1a Hash of domain + qtype
    static uint64_t _computeHash(const String& domain, uint16_t qtype) {
        uint64_t hash = 14695981039346656037ULL;
        for (size_t i = 0; i < domain.length(); ++i) {
            char c = tolower(domain[i]);
            hash ^= (uint64_t)(uint8_t)c;
            hash *= 1099511628211ULL;
        }
        hash ^= (uint64_t)(qtype & 0xFF);
        hash *= 1099511628211ULL;
        hash ^= (uint64_t)((qtype >> 8) & 0xFF);
        hash *= 1099511628211ULL;
        return hash;
    }

    static void _updateRemainingTtl(uint8_t* buf, int len, uint32_t remainingTtl) {
        if (len < 12) return;
        uint16_t qdcount = (buf[4] << 8) | buf[5];
        uint16_t ancount = (buf[6] << 8) | buf[7];
        if (ancount == 0) return;

        int pos = 12;
        for (int q = 0; q < qdcount && pos < len; ++q) {
            while (pos < len) {
                uint8_t l = buf[pos];
                if (l == 0) { pos++; break; }
                if ((l & 0xC0) == 0xC0) { pos += 2; break; }
                pos += 1 + l;
            }
            pos += 4;
        }

        for (int a = 0; a < ancount && pos < len; ++a) {
            while (pos < len) {
                uint8_t l = buf[pos];
                if (l == 0) { pos++; break; }
                if ((l & 0xC0) == 0xC0) { pos += 2; break; }
                pos += 1 + l;
            }

            if (pos + 10 > len) break;
            buf[pos + 4] = (uint8_t)(remainingTtl >> 24);
            buf[pos + 5] = (uint8_t)(remainingTtl >> 16);
            buf[pos + 6] = (uint8_t)(remainingTtl >> 8);
            buf[pos + 7] = (uint8_t)(remainingTtl & 0xFF);

            uint16_t rdlength = (buf[pos + 8] << 8) | buf[pos + 9];
            pos += 10 + rdlength;
        }
    }
};
