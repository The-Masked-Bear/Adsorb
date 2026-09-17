#pragma once

#include <Arduino.h>
#include <vector>
#include <esp_heap_caps.h>
#include "Config.hpp"

// ============================================================================
// Dual 64-bit SWAR (SIMD Within A Register) Parallel Bitwise Pattern Matcher
// Leverages parallel 128-bit chunk scanning with zero-byte detection idiom
// and domain boundary validation to prevent false-positive over-blocking.
// ============================================================================
class VectorWildcardAccelerator {
public:
    enum PatternType {
        PATTERN_SUBDOMAIN,  // *.domain.com -> matches domain.com and sub.domain.com
        PATTERN_PREFIX,     // prefix.* -> starts with prefix.
        PATTERN_LABEL       // label -> matches label as exact label boundary
    };

    struct Rule {
        String pattern;
        PatternType type;
    };

    bool init(bool enableHeuristics = Config::ENABLE_HEURISTIC_BLOCKING) {
        Serial.println("[SWAR] Initializing Dual 64-bit SWAR Parallel Bitwise Accelerator...");
        _rules.clear();
        static const char* const verifiedAdSignatures[] = {
            "doubleclick",
            "adservice",
            "adservices",
            "adserver",
            "adservers",
            "adnxs",
            "pagead",
            "pagead2",
            "app-measurement",
            "googleads",
            "googletagservices",
            "google-analytics",
            "trafficjunky",
            "quantserve",
            "scorecardresearch",
            "moatads",
            "outbrain",
            "taboola",
            "criteo",
            "adcolony",
            "chartbeat",
            "pubmatic",
            "rubiconproject",
            "casalemedia",
            "adsystem"
        };
        const size_t numVerified = sizeof(verifiedAdSignatures) / sizeof(verifiedAdSignatures[0]);
        _rules.reserve(numVerified + 32);
        for (size_t i = 0; i < numVerified; ++i) {
            addPattern(verifiedAdSignatures[i]);
        }

        if (enableHeuristics) {
            static const char* const heuristicSignatures[] = {
                "telemetry",
                "analytics",
                "advertising",
                "mobile-analytics"
            };
            const size_t numHeuristics = sizeof(heuristicSignatures) / sizeof(heuristicSignatures[0]);
            for (size_t i = 0; i < numHeuristics; ++i) {
                addPattern(heuristicSignatures[i]);
            }
            Serial.printf("[SWAR] Loaded %u verified ad signatures + %u heuristic signatures.\n",
                          (unsigned)numVerified, (unsigned)numHeuristics);
        } else {
            Serial.printf("[SWAR] Loaded %u verified dual 64-bit SWAR ad signatures (heuristics gated).\n",
                          (unsigned)_rules.size());
        }
        return true;
    }

    void addPattern(const char* pat) {
        if (!pat || strlen(pat) == 0) return;
        String p = pat;
        p.toLowerCase();
        p.trim();

        Rule r;
        if (p.startsWith("*.") && p.length() > 2) {
            r.pattern = p.substring(2);
            r.type = PATTERN_SUBDOMAIN;
        } else if (p.endsWith(".*") && p.length() > 2) {
            r.pattern = p.substring(0, p.length() - 2);
            r.type = PATTERN_PREFIX;
        } else {
            p.replace("*", "");
            p.trim();
            if (p.length() < 3) return;
            r.pattern = p;
            r.type = PATTERN_LABEL;
        }

        if (r.pattern.length() >= 3) {
            _rules.push_back(r);
        }
    }

    size_t patternCount() const {
        return _rules.size();
    }

    // Parallel SWAR accelerated pattern scanning with boundary validation
    bool matchesAny(const char* domain, size_t domainLen) const {
        if (!domain || domainLen < 4) return false;

        for (const auto& r : _rules) {
            const char* pat = r.pattern.c_str();
            size_t patLen = r.pattern.length();

            // Quick rejection via Dual 64-bit SWAR bitwise scanner
            if (!_swarContains(domain, domainLen, pat, patLen)) {
                continue;
            }

            // Boundary validation to prevent false-positive over-blocking
            if (r.type == PATTERN_SUBDOMAIN) {
                if (domainLen == patLen && memcmp(domain, pat, patLen) == 0) return true;
                if (domainLen > patLen && domain[domainLen - patLen - 1] == '.' &&
                    memcmp(domain + (domainLen - patLen), pat, patLen) == 0) {
                    return true;
                }
            } else if (r.type == PATTERN_PREFIX) {
                if (domainLen >= patLen && memcmp(domain, pat, patLen) == 0 &&
                    (domainLen == patLen || domain[patLen] == '.')) {
                    return true;
                }
            } else {
                // PATTERN_LABEL: Must match as a discrete domain label
                for (size_t pos = 0; pos + patLen <= domainLen; ++pos) {
                    if (domain[pos] == pat[0] && memcmp(domain + pos, pat, patLen) == 0) {
                        bool leftBoundary = (pos == 0 || domain[pos - 1] == '.');
                        bool rightBoundary = (pos + patLen == domainLen || domain[pos + patLen] == '.');
                        if (leftBoundary && rightBoundary) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

private:
    std::vector<Rule> _rules;

    // Dual 64-bit SWAR vector chunk substring search
    static inline bool _swarContains(const char* text, size_t textLen, const char* pattern, size_t patLen) {
        if (patLen > textLen) return false;
        if (patLen == 0) return true;

        size_t limit = textLen - patLen;
        char firstChar = pattern[0];
        size_t i = 0;

        // Process in 16-byte (dual 64-bit register) vector chunks
        while (i + 16 <= textLen) {
            uint64_t lowChunk, highChunk;
            memcpy(&lowChunk, text + i, 8);
            memcpy(&highChunk, text + i + 8, 8);

            // Broadcast firstChar across 64-bit vector lanes
            uint64_t mask = 0x0101010101010101ULL * (uint8_t)firstChar;
            uint64_t diffLow = lowChunk ^ mask;
            uint64_t diffHigh = highChunk ^ mask;

            // Zero-byte detection idiom: haszero(v) = (v - 0x01010101) & ~v & 0x80808080
            bool hasLow = ((diffLow - 0x0101010101010101ULL) & ~diffLow & 0x8080808080808080ULL) != 0;
            bool hasHigh = ((diffHigh - 0x0101010101010101ULL) & ~diffHigh & 0x8080808080808080ULL) != 0;

            if (hasLow || hasHigh) {
                size_t windowLimit = (i + 16 <= limit) ? (i + 16) : (limit + 1);
                for (size_t j = i; j < windowLimit; ++j) {
                    if (text[j] == firstChar && memcmp(text + j, pattern, patLen) == 0) {
                        return true;
                    }
                }
            }
            i += 16;
        }

        // Check scalar trailing boundary
        for (; i <= limit; ++i) {
            if (text[i] == firstChar && memcmp(text + i, pattern, patLen) == 0) {
                return true;
            }
        }

        return false;
    }
};
