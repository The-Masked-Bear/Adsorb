#pragma once

#include <Arduino.h>
#include <LittleFS.h>
#include <esp_heap_caps.h>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <string>
#include <functional>

#include "Config.hpp"
#include "VectorWildcard.hpp"

// ============================================================================
// PSRAM Allocator — forces std containers to allocate in external SPIRAM
// ============================================================================
template <typename T>
struct PsramAllocator {
    using value_type = T;

    PsramAllocator() noexcept = default;

    template <typename U>
    PsramAllocator(const PsramAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        T* p = static_cast<T*>(heap_caps_malloc(n * sizeof(T), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (!p) {
            Serial.printf("[Blocklist] PSRAM alloc failed for %u bytes!\n", (unsigned)(n * sizeof(T)));
        }
        return p;
    }

    void deallocate(T* p, std::size_t) noexcept {
        heap_caps_free(p);
    }
};

template <typename T, typename U>
bool operator==(const PsramAllocator<T>&, const PsramAllocator<U>&) { return true; }
template <typename T, typename U>
bool operator!=(const PsramAllocator<T>&, const PsramAllocator<U>&) { return false; }

// ============================================================================
// PSRAM-aware string type
// ============================================================================
using PsramString = std::basic_string<char, std::char_traits<char>, PsramAllocator<char>>;

struct PsramStringHash {
    std::size_t operator()(const PsramString& s) const {
        // FNV-1a hash
        std::size_t hash = 2166136261u;
        for (char c : s) {
            hash ^= static_cast<std::size_t>(c);
            hash *= 16777619u;
        }
        return hash;
    }
};

// Use a standard set with PSRAM allocator for the buckets/nodes
using DomainSet = std::unordered_set<
    PsramString,
    PsramStringHash,
    std::equal_to<PsramString>,
    PsramAllocator<PsramString>
>;

// PSRAM Vector for ultra-compact 64-bit domain hashes (8 bytes per domain)
using HashVector = std::vector<uint64_t, PsramAllocator<uint64_t>>;

// ============================================================================
// Blocklist Class
// ============================================================================
class Blocklist {
public:
    static inline uint64_t hash64(const char* s, size_t len) {
        uint64_t hash = 14695981039346656037ULL;
        for (size_t i = 0; i < len; ++i) {
            hash ^= (uint64_t)(unsigned char)s[i];
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    bool init() {
        Serial.println("[Blocklist] Initializing domain blocklist engine (64-bit PSRAM Hash Vector)...");
        uint32_t startMs = millis();
        uint32_t psramBefore = ESP.getFreePsram();

        // 1. Load primary blocklist
        _loadBlocklistFile(Config::PATH_ADS_DOMAINS, "primary blocklist");

        // 2. Load secondary blocklists (user provided ad-domains2.0)
        _loadBlocklistFile(Config::PATH_ADS_DOMAINS_2, "secondary blocklist (ad-domains2.0.txt)");
        _loadBlocklistFile(Config::PATH_ADS_DOMAINS_2_ALT, "secondary blocklist (ad-domains2.0)");
        _loadBlocklistFile("/ads-domains2.txt", "secondary blocklist (ads-domains2.txt)");

        // 3. Sort and deduplicate 64-bit hashes for O(log N) binary search
        if (!_blockedHashes.empty()) {
            Serial.printf("[Blocklist] Sorting %u raw domain hashes in Octal PSRAM...\n", (unsigned)_blockedHashes.size());
            std::sort(_blockedHashes.begin(), _blockedHashes.end());
            auto last = std::unique(_blockedHashes.begin(), _blockedHashes.end());
            _blockedHashes.erase(last, _blockedHashes.end());
            _blockedHashes.shrink_to_fit();
        }

        // 4. Load custom blacklist and whitelist sets
        _loadSetFile(Config::PATH_CUSTOM_BLACKLIST, _customBlacklist, "custom blacklist");
        _loadSetFile(Config::PATH_CUSTOM_WHITELIST, _whitelist, "whitelist");

        // 5. Initialize Xtensa LX7 128-bit Vector SIMD Wildcard Accelerator
        _simd.init();
        for (const auto& d : _customBlacklist) {
            if (d.find('*') != PsramString::npos) {
                _simd.addPattern(d.c_str());
            }
        }

        uint32_t elapsed = millis() - startMs;
        uint32_t psramUsed = psramBefore > ESP.getFreePsram() ? (psramBefore - ESP.getFreePsram()) : 0;

        Serial.println("[Blocklist] ======== LOADING COMPLETE ========");
        Serial.printf("[Blocklist]   Blocked domain rules : %u\n", (unsigned)_blockedHashes.size());
        Serial.printf("[Blocklist]   Custom blacklist     : %u\n", (unsigned)_customBlacklist.size());
        Serial.printf("[Blocklist]   Whitelist domains    : %u\n", (unsigned)_whitelist.size());
        Serial.printf("[Blocklist]   Load time            : %u ms\n", elapsed);
        Serial.printf("[Blocklist]   PSRAM consumed       : %u bytes (%.2f MB)\n",
                      psramUsed, psramUsed / (1024.0f * 1024.0f));
        Serial.printf("[Blocklist]   PSRAM remaining      : %u bytes (%.2f MB)\n",
                      ESP.getFreePsram(), ESP.getFreePsram() / (1024.0f * 1024.0f));

        return _blockedHashes.size() > 0;
    }

    // -----------------------------------------------------------------------
    // Essential OS Connectivity & Push Notification Whitelist
    // Protects Android Captive Portal, Apple APNs, Windows NCSI, and Firebase
    // -----------------------------------------------------------------------
    static bool _isEssentialSystemDomain(const PsramString& domain) {
        static const char* const SYSTEM_WHITELIST[] = {
            "connectivitycheck.gstatic.com",
            "connectivitycheck.android.com",
            "clients3.google.com",
            "clients1.google.com",
            "captive.apple.com",
            "msftconnecttest.com",
            "msftncsi.com",
            "ipv6.msftncsi.com",
            "firebaseinstallations.googleapis.com",
            "fcm.googleapis.com",
            "fcmtoken.googleapis.com",
            "android.clients.google.com",
            "play.googleapis.com",
            "gvt1.com",
            "time.windows.com",
            "time.apple.com",
            "time.google.com",
            "time.android.com",
            "push.apple.com",
            "identity.apple.com"
        };
        for (const char* sysDomain : SYSTEM_WHITELIST) {
            size_t sysLen = strlen(sysDomain);
            if (domain.length() == sysLen && domain.compare(sysDomain) == 0) return true;
            if (domain.length() > sysLen && domain[domain.length() - sysLen - 1] == '.' &&
                domain.compare(domain.length() - sysLen, sysLen, sysDomain) == 0) {
                return true;
            }
        }
        return false;
    }

    bool isBlocked(const String& rawDomain) const {
        PsramString domain = _cleanDomain(rawDomain);
        if (domain.empty()) return false;

        // 0. Essential OS Connectivity & Push Notification Whitelist
        if (_isEssentialSystemDomain(domain)) {
            return false;
        }

        // 1. Whitelist override (progressive check from full domain up to TLD)
        if (_checkHierarchy(domain, [this](const PsramString& d) {
            return _whitelist.count(d) > 0;
        })) {
            return false;
        }

        // 2. Custom blacklist override
        if (_checkHierarchy(domain, [this](const PsramString& d) {
            return _customBlacklist.count(d) > 0;
        })) {
            return true;
        }

        // 3. System blocklist (binary search on sorted 64-bit hashes across domain hierarchy)
        if (_checkHierarchyHash(domain)) {
            return true;
        }

        // 4. Xtensa LX7 128-bit Vector SIMD (PIE) Wildcard Rule Accelerator
        if (_simd.matchesAny(domain.c_str(), domain.length())) {
            return true;
        }

        // 5. Arrogant Heuristic & Keyword matching (annihilate unlisted ad/telemetry subdomains)
        if (_matchHeuristics(domain)) {
            return true;
        }

        return false;
    }

    bool addToWhitelist(const String& rawDomain) {
        PsramString domain = _cleanDomain(rawDomain);
        if (domain.empty()) return false;
        _whitelist.insert(domain);
        return _appendToFile(Config::PATH_CUSTOM_WHITELIST, String(domain.c_str()));
    }

    bool addToBlacklist(const String& rawDomain) {
        PsramString domain = _cleanDomain(rawDomain);
        if (domain.empty()) return false;
        _customBlacklist.insert(domain);
        if (rawDomain.indexOf('*') >= 0) {
            _simd.addPattern(rawDomain.c_str());
        }
        return _appendToFile(Config::PATH_CUSTOM_BLACKLIST, String(domain.c_str()));
    }

    bool removeFromWhitelist(const String& rawDomain) {
        PsramString domain = _cleanDomain(rawDomain);
        if (domain.empty()) return false;
        _whitelist.erase(domain);
        return _rewriteFile(Config::PATH_CUSTOM_WHITELIST, _whitelist);
    }

    bool removeFromBlacklist(const String& rawDomain) {
        PsramString domain = _cleanDomain(rawDomain);
        if (domain.empty()) return false;
        _customBlacklist.erase(domain);
        return _rewriteFile(Config::PATH_CUSTOM_BLACKLIST, _customBlacklist);
    }

    size_t blockedCount() const { return _blockedHashes.size(); }
    size_t customBlacklistCount() const { return _customBlacklist.size(); }
    size_t whitelistCount() const { return _whitelist.size(); }
    size_t simdPatternCount() const { return _simd.patternCount(); }

    bool isWhitelisted(const String& rawDomain) const {
        PsramString domain = _cleanDomain(rawDomain);
        if (domain.empty()) return false;
        return _checkHierarchy(domain, [this](const PsramString& d) {
            return _whitelist.count(d) > 0;
        });
    }

    const DomainSet& getWhitelist() const { return _whitelist; }
    const DomainSet& getCustomBlacklist() const { return _customBlacklist; }
    const VectorWildcardAccelerator& getSimdAccelerator() const { return _simd; }

private:
    HashVector _blockedHashes;
    DomainSet _customBlacklist;
    DomainSet _whitelist;
    VectorWildcardAccelerator _simd;

    bool _checkHierarchyHash(const PsramString& domain) const {
        if (_blockedHashes.empty()) return false;

        const char* str = domain.c_str();
        size_t len = domain.length();

        // 1. Check full domain hash
        uint64_t h = hash64(str, len);
        if (std::binary_search(_blockedHashes.begin(), _blockedHashes.end(), h)) {
            return true;
        }

        // 2. Progressive check parent domains (e.g. sub.ads.example.com -> ads.example.com -> example.com)
        size_t dotPos = domain.find('.');
        while (dotPos != PsramString::npos) {
            // Stop before bare TLD (e.g. "com", "net")
            if (domain.find('.', dotPos + 1) == PsramString::npos) {
                break;
            }
            size_t parentStart = dotPos + 1;
            size_t parentLen = len - parentStart;
            uint64_t parentHash = hash64(str + parentStart, parentLen);
            if (std::binary_search(_blockedHashes.begin(), _blockedHashes.end(), parentHash)) {
                return true;
            }
            dotPos = domain.find('.', dotPos + 1);
        }

        return false;
    }

    bool _matchHeuristics(const PsramString& domain) const {
        static const char* const AD_PREFIXES[] = {
            "pagead2.",
            "adservice.",
            "adservices.",
            "adserver.",
            "adservers.",
            "telemetry.",
            "analytics.",
            "criteo.",
            "taboola.",
            "outbrain.",
            "doubleclick.",
            "googletagservices.",
            "googletagmanager.",
            "google-analytics.",
            "googleadservices.",
            "googlesyndication.",
            "adnxs.",
            "pubmatic.",
            "rubiconproject.",
            "casalemedia.",
            "scorecardresearch.",
            "quantserve.",
            "app-measurement.",
            "mobile-analytics.",
            "adsystem.",
            "sentry-cdn.",
            "bugsnag.",
            "freshmarketer.",
            "luckyorange.",
            "mouseflow.",
            "hotjar.",
            "adcolony.",
            "unityads.",
            "samsungads.",
            "adfox.",
            "appmetrica.",
            "cloudflareinsights."
        };

        for (const char* pfx : AD_PREFIXES) {
            size_t pfxLen = strlen(pfx);
            if (domain.length() >= pfxLen && domain.compare(0, pfxLen, pfx) == 0) {
                return true;
            }
            PsramString dotPfx = ".";
            dotPfx += pfx;
            if (domain.find(dotPfx) != PsramString::npos) {
                return true;
            }
        }
        return false;
    }

    static PsramString _cleanDomain(const char* s, size_t len) {
        size_t start = 0;
        size_t end = len;
        while (start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n' || s[start] == '.')) {
            start++;
        }
        while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n' || s[end - 1] == '.')) {
            end--;
        }
        PsramString result;
        if (start < end) {
            result.reserve(end - start);
            for (size_t i = start; i < end; i++) {
                result += (char)tolower((unsigned char)s[i]);
            }
        }
        return result;
    }

    static PsramString _cleanDomain(const String& s) {
        return _cleanDomain(s.c_str(), s.length());
    }

    template <typename Predicate>
    static bool _checkHierarchy(const PsramString& domain, Predicate pred) {
        if (pred(domain)) return true;

        size_t dotPos = domain.find('.');
        while (dotPos != PsramString::npos) {
            // Stop before bare TLD (e.g., "com", "net")
            if (domain.find('.', dotPos + 1) == PsramString::npos) {
                break;
            }
            PsramString parent = domain.substr(dotPos + 1);
            if (pred(parent)) return true;
            dotPos = domain.find('.', dotPos + 1);
        }
        return false;
    }

    void _processBlocklistLine(char* line, size_t len, size_t& count) {
        size_t start = 0;
        while (start < len && (line[start] == ' ' || line[start] == '\t')) start++;
        if (start >= len || line[start] == '#') return;

        // Strip "0.0.0.0 " or "127.0.0.1 "
        if (len - start > 8) {
            if ((strncmp(line + start, "0.0.0.0", 7) == 0 && (line[start + 7] == ' ' || line[start + 7] == '\t')) ||
                (strncmp(line + start, "127.0.0.1", 9) == 0 && (line[start + 9] == ' ' || line[start + 9] == '\t'))) {
                start = (line[start] == '0') ? start + 8 : start + 10;
                while (start < len && (line[start] == ' ' || line[start] == '\t')) start++;
            }
        }

        size_t end = start;
        while (end < len && line[end] != ' ' && line[end] != '\t' && line[end] != '#' && line[end] != '\r' && line[end] != '\n') end++;

        // Clean leading/trailing dots
        while (start < end && line[start] == '.') start++;
        while (end > start && line[end - 1] == '.') end--;

        if (start < end) {
            line[end] = '\0';
            if (strcmp(line + start, "localhost") == 0) return;

            // In-place lowercase
            for (size_t i = start; i < end; i++) {
                line[i] = (char)tolower((unsigned char)line[i]);
            }

            // Safety limit to guarantee >= 2.2MB PSRAM free for system buffers and tests
            if (ESP.getFreePsram() < 2200000) {
                return;
            }

            uint64_t h = hash64(line + start, end - start);
            _blockedHashes.push_back(h);
            count++;

            if (count % 50000 == 0) {
                Serial.printf("[Blocklist]   ... ingested %u signatures (free PSRAM: %u KB)\n",
                              (unsigned)count, (unsigned)(ESP.getFreePsram() / 1024));
            }
        }
    }

    void _loadBlocklistFile(const char* path, const char* label) {
        if (!LittleFS.exists(path)) {
            Serial.printf("[Blocklist] File '%s' not found, skipping %s.\n", path, label);
            return;
        }

        File f = LittleFS.open(path, "r");
        if (!f) {
            Serial.printf("[Blocklist] Failed to open '%s'!\n", path);
            return;
        }

        size_t count = 0;
        size_t fileSize = f.size();
        Serial.printf("[Blocklist] Loading %s from '%s' (%u bytes)...\n", label, path, (unsigned)fileSize);

        const size_t CHUNK_SIZE = 8192;
        char* chunk = (char*)heap_caps_malloc(CHUNK_SIZE + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!chunk) {
            chunk = (char*)malloc(CHUNK_SIZE + 1);
        }

        if (chunk) {
            size_t carry = 0;
            while (f.available() || carry > 0) {
                if (ESP.getFreePsram() < 2200000) {
                    Serial.println("[Blocklist] PSRAM safe floor reached. Halting further ingestion.");
                    break;
                }

                size_t toRead = CHUNK_SIZE - carry;
                size_t bytesRead = 0;
                if (f.available() && toRead > 0) {
                    bytesRead = f.read((uint8_t*)(chunk + carry), toRead);
                }
                size_t totalBytes = carry + bytesRead;
                if (totalBytes == 0) break;
                chunk[totalBytes] = '\0';

                size_t lineStart = 0;
                for (size_t i = 0; i < totalBytes; i++) {
                    if (chunk[i] == '\n' || chunk[i] == '\r') {
                        chunk[i] = '\0';
                        if (i > lineStart) {
                            _processBlocklistLine(chunk + lineStart, i - lineStart, count);
                        }
                        lineStart = i + 1;
                    }
                }

                if (lineStart < totalBytes) {
                    if (!f.available()) {
                        _processBlocklistLine(chunk + lineStart, totalBytes - lineStart, count);
                        carry = 0;
                    } else {
                        carry = totalBytes - lineStart;
                        memmove(chunk, chunk + lineStart, carry);
                    }
                } else {
                    carry = 0;
                }
            }

            if (esp_ptr_external_ram(chunk)) {
                heap_caps_free(chunk);
            } else {
                free(chunk);
            }
        } else {
            while (f.available()) {
                if (ESP.getFreePsram() < 2200000) break;
                String line = f.readStringUntil('\n');
                _processBlocklistLine((char*)line.c_str(), line.length(), count);
            }
        }

        f.close();
        Serial.printf("[Blocklist] Finished reading %s '%s' (%u rules added).\n", label, path, (unsigned)count);
    }

    void _processSetLine(char* line, size_t len, DomainSet& target, size_t& count) {
        size_t start = 0;
        while (start < len && (line[start] == ' ' || line[start] == '\t')) start++;
        if (start >= len || line[start] == '#') return;

        size_t end = start;
        while (end < len && line[end] != ' ' && line[end] != '\t' && line[end] != '#' && line[end] != '\r' && line[end] != '\n') end++;

        if (start < end) {
            line[end] = '\0';
            if (strcmp(line + start, "localhost") == 0) return;

            PsramString domain = _cleanDomain(line + start, end - start);
            if (!domain.empty()) {
                target.insert(domain);
                count++;
            }
        }
    }

    void _loadSetFile(const char* path, DomainSet& target, const char* label) {
        if (!LittleFS.exists(path)) {
            Serial.printf("[Blocklist] File '%s' not found, skipping %s.\n", path, label);
            return;
        }

        File f = LittleFS.open(path, "r");
        if (!f) {
            Serial.printf("[Blocklist] Failed to open '%s'!\n", path);
            return;
        }

        size_t count = 0;
        while (f.available()) {
            String line = f.readStringUntil('\n');
            _processSetLine((char*)line.c_str(), line.length(), target, count);
        }

        f.close();
        Serial.printf("[Blocklist] Loaded %u domains from %s '%s'.\n", (unsigned)count, label, path);
    }

    bool _appendToFile(const char* path, const String& domain) {
        File f = LittleFS.open(path, "a");
        if (!f) {
            Serial.printf("[Blocklist] Failed to open '%s' for append!\n", path);
            return false;
        }
        f.println(domain);
        f.close();
        return true;
    }

    bool _rewriteFile(const char* path, const DomainSet& target) {
        File f = LittleFS.open(path, "w");
        if (!f) {
            Serial.printf("[Blocklist] Failed to open '%s' for rewrite!\n", path);
            return false;
        }
        for (const auto& d : target) {
            f.println(d.c_str());
        }
        f.close();
        return true;
    }
};
