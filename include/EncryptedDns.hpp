#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "Config.hpp"
#include "TrustedCaRoots.hpp"

// ============================================================================
// Encrypted DNS Client (RFC 8484 DNS-over-HTTPS)
// Uses Hardware-Accelerated TLS (AES-256 / SHA-256) to Upstream Providers
// Cryptographically verified against Cloudflare & Google trusted Root CAs
// ============================================================================
class EncryptedDns {
public:
    EncryptedDns() = default;

    bool begin() {
        _client.setCACert(DOH_ROOT_CA_PEM); // Strict cryptographic Root CA verification
        _client.setTimeout(Config::DOH_TIMEOUT_MS);
        Serial.printf("[DoH] Initialized Encrypted DNS Engine (CA Verified). Primary: %s | Fallback: %s\n",
                      Config::DOH_PRIMARY_URL, Config::DOH_SECONDARY_URL);
        return true;
    }

    // -----------------------------------------------------------------------
    // Resolve DNS Query over HTTPS (Binary Wire Format)
    // -----------------------------------------------------------------------
    int query(const uint8_t* queryPacket, int queryLen, uint8_t* outBuf, size_t maxOutLen) {
        if (!WiFi.isConnected() || queryLen < 12 || maxOutLen < 12) return -1;

        _totalQueries++;

        // 1. Try Primary DoH (Cloudflare 1.1.1.1)
        int len = _doHttpPost(Config::DOH_PRIMARY_URL, "cloudflare-dns.com", queryPacket, queryLen, outBuf, maxOutLen);
        if (len >= 12) {
            _successfulQueries++;
            return len;
        }

        // 2. Try Secondary DoH (Google 8.8.8.8)
        len = _doHttpPost(Config::DOH_SECONDARY_URL, "dns.google", queryPacket, queryLen, outBuf, maxOutLen);
        if (len >= 12) {
            _successfulQueries++;
            return len;
        }

        _failedQueries++;
        return -1; // Indicates caller should fallback to plain UDP 53
    }

    // Telemetry & Metrics
    uint32_t getTotalQueries()      const { return _totalQueries; }
    uint32_t getSuccessfulQueries() const { return _successfulQueries; }
    uint32_t getFailedQueries()     const { return _failedQueries; }

    float getSuccessRate() const {
        if (_totalQueries == 0) return 100.0f;
        return ((float)_successfulQueries / (float)_totalQueries) * 100.0f;
    }

private:
    WiFiClientSecure _client;
    volatile uint32_t _totalQueries      = 0;
    volatile uint32_t _successfulQueries = 0;
    volatile uint32_t _failedQueries     = 0;

    int _doHttpPost(const char* url, const char* hostHdr,
                    const uint8_t* queryPacket, int queryLen,
                    uint8_t* outBuf, size_t maxOutLen) {
        HTTPClient http;
        http.setReuse(true); // Reuse TLS connection when possible
        http.setTimeout(Config::DOH_TIMEOUT_MS);

        if (!http.begin(_client, url)) {
            return -1;
        }

        http.addHeader("Content-Type", "application/dns-message");
        http.addHeader("Accept", "application/dns-message");
        http.addHeader("Host", hostHdr);

        int httpCode = http.POST((uint8_t*)queryPacket, queryLen);
        int resultLen = -1;

        if (httpCode == HTTP_CODE_OK) {
            int payloadSize = http.getSize();
            WiFiClient* stream = http.getStreamPtr();

            if (payloadSize > 0 && payloadSize <= (int)maxOutLen && stream) {
                int bytesRead = stream->readBytes(outBuf, payloadSize);
                if (bytesRead == payloadSize) {
                    resultLen = bytesRead;
                }
            } else if (stream && payloadSize < 0) {
                // Chunked transfer encoding
                int bytesRead = 0;
                while (http.connected() && bytesRead < (int)maxOutLen) {
                    size_t avail = stream->available();
                    if (avail > 0) {
                        int r = stream->readBytes(outBuf + bytesRead, min(avail, maxOutLen - bytesRead));
                        bytesRead += r;
                    } else {
                        delay(2);
                        if (!stream->available()) break;
                    }
                }
                if (bytesRead >= 12) resultLen = bytesRead;
            }
        } else {
            // Non-200 response or connection dropped -> reset client socket
            _client.stop();
        }

        http.end();
        if (resultLen < 12) {
            _client.stop(); // Cleanly close socket on partial or broken read
        }
        return resultLen;
    }
};
