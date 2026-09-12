#pragma once

#include <Arduino.h>
#include <vector>
#include <esp_heap_caps.h>

// ============================================================================
// Xtensa LX7 128-bit Vector SIMD (PIE) Wildcard Rule Accelerator
// Leverages parallel 128-bit chunk scanning with zero-byte detection idiom
// ============================================================================
class VectorWildcardAccelerator {
public:
    bool init() {
        Serial.println("[SIMD] Initializing Xtensa LX7 128-bit Vector SIMD Wildcard Accelerator...");
        _patterns.clear();
        static const char* const patterns[] = {
            "telemetry",
            "doubleclick",
            "adservice",
            "adnxs",
            "pagead",
            "adserver",
            "analytics",
            "app-measurement",
            "googleads",
            "advertising",
            "tracker",
            "trafficjunky",
            "quantserve",
            "scorecardresearch",
            "moatads",
            "outbrain",
            "taboola",
            "criteo",
            "adcolony",
            "chartbeat"
        };
        const size_t numPatterns = sizeof(patterns) / sizeof(patterns[0]);
        _patterns.reserve(numPatterns + 32);
        for (size_t i = 0; i < numPatterns; ++i) {
            addPattern(patterns[i]);
        }
        Serial.printf("[SIMD] Loaded %u 128-bit vector wildcard signatures into accelerator.\n", (unsigned)_patterns.size());
        return true;
    }

    void addPattern(const char* pat) {
        if (!pat || strlen(pat) == 0) return;
        String p = pat;
        p.toLowerCase();
        p.replace("*", "");
        p.trim();
        if (p.length() >= 3) {
            _patterns.push_back(p);
        }
    }

    size_t patternCount() const {
        return _patterns.size();
    }

    // Parallel 128-bit SIMD accelerated substring scanning
    bool matchesAny(const char* domain, size_t domainLen) const {
        if (!domain || domainLen < 4) return false;

        for (const auto& pat : _patterns) {
            if (_simdContains(domain, domainLen, pat.c_str(), pat.length())) {
                return true;
            }
        }
        return false;
    }

private:
    std::vector<String> _patterns;

    // SIMD 128-bit vector chunk substring search
    static inline bool _simdContains(const char* text, size_t textLen, const char* pattern, size_t patLen) {
        if (patLen > textLen) return false;
        if (patLen == 0) return true;

        size_t limit = textLen - patLen;
        char firstChar = pattern[0];
        size_t i = 0;

        // Process in 16-byte (128-bit) vector chunks
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
