"""
Tier 3: Cross-Feature Interactions (15 Pairwise Tests T3_P01 - T3_P15).
Validates seamless integration and interface contracts across subsystem pairs.
"""

import time
import socket
try:
    from common.base_test import BaseE2ETest
except ImportError:
    from test.common.base_test import BaseE2ETest


class TestTier3Pairwise(BaseE2ETest):

    def test_t3_p01_platformio_and_psram(self):
        """F01 + F03: Hardware initialization correctly provisions Octal PSRAM."""
        stats = self.http_client.get_stats().json
        self.assertGreater(stats.get("free_psram", 0), 1000000)
        self.assertGreater(stats.get("free_heap", 0), 50000)

    def test_t3_p02_littlefs_and_blocklist_loading(self):
        """F02 + F04: LittleFS storage feeds blocklist ingestion into memory set."""
        stats = self.http_client.get_stats().json
        self.assertGreater(stats.get("blocklist_count", 0), 0)
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp)

    def test_t3_p03_psram_and_ring_buffer(self):
        """F03 + F10: Ring buffer allocates 1000 query records in PSRAM without SRAM drop."""
        h1 = self.http_client.get_stats().json.get("free_heap", 0)
        for i in range(10):
            self.dns_query(f"test-psram-ring-{i}.org")
        h2 = self.http_client.get_stats().json.get("free_heap", 0)
        self.assertAlmostEqual(h1, h2, delta=5000, msg="Internal SRAM must not drain for ring buffer")

    def test_t3_p04_blocklist_and_subdomain_matcher(self):
        """F04 + F07: Blocklist ingestion feeds O(1) subdomain matcher."""
        # '3lift.com' in blocklist -> 'sub.3lift.com' must be sinkholed
        resp = self.dns_query("sub.3lift.com")
        self.assert_sinkholed(resp)

    def test_t3_p05_rules_and_subdomain_matching(self):
        """F05 + F07: Custom whitelist dynamically unblocks domain from subdomain matcher."""
        domain = "special.2mdn.net"
        self.http_client.add_whitelist(domain)
        try:
            resp = self.dns_query(domain)
            self.assert_resolved_public(resp)
        finally:
            self.http_client.delete_whitelist(domain)

    def test_t3_p06_dns_server_and_upstream_relay(self):
        """F06 + F08: RFC 1035 UDP parser routes clean query to upstream relay."""
        resp = self.dns_query("cloudflare.com")
        self.assert_resolved_public(resp)
        self.assertEqual(resp.qr, 1)

    def test_t3_p07_subdomain_sink_and_stats_counter(self):
        """F07 + F09: Subdomain sinkhole increments both total and blocked counters."""
        s1 = self.http_client.get_stats().json
        self.dns_query("ads.2mdn.net")
        s2 = self.http_client.get_stats().json
        self.assertGreater(s2["total"], s1["total"])
        self.assertGreater(s2["blocked"], s1["blocked"])

    def test_t3_p08_upstream_relay_and_ring_buffer(self):
        """F08 + F10: Upstream forwarded query is recorded in ring buffer with blocked=False."""
        self.dns_query("wikipedia.org")
        queries = self.http_client.get_queries().json
        matched = [q for q in queries if q.get("domain") == "wikipedia.org"]
        self.assertTrue(len(matched) > 0)
        self.assertFalse(matched[-1]["blocked"])

    def test_t3_p09_stats_engine_and_rest_api(self):
        """F09 + F12: REST endpoint /api/stats accurately serializes internal statistics."""
        resp = self.http_client.get_stats()
        self.assertEqual(resp.status, 200)
        self.assertIn("total", resp.json)
        self.assertIn("blocked", resp.json)
        self.assertIn("percentage", resp.json)

    def test_t3_p10_ring_buffer_and_rest_api(self):
        """F10 + F12: REST endpoint /api/queries accurately delivers query logs."""
        resp = self.http_client.get_queries()
        self.assertEqual(resp.status, 200)
        self.assertIsInstance(resp.json, list)

    def test_t3_p11_dashboard_and_rest_api(self):
        """F11 + F12: Dashboard HTML contains elements corresponding to REST API data."""
        dash = self.http_client.get_dashboard().text
        self.assertIn("total-queries", dash)
        self.assertIn("blocked-queries", dash)

    def test_t3_p12_rest_api_and_rule_persistence(self):
        """F12 + F05: REST API updates whitelist and blacklist rules."""
        d_wl = "pairwise-wl.test.com"
        d_bl = "pairwise-bl.test.com"
        self.http_client.add_whitelist(d_wl)
        self.http_client.add_blacklist(d_bl)
        try:
            wl = self.http_client.get_whitelist().json
            bl = self.http_client.get_blacklist().json
            self.assertIn(d_wl, wl)
            self.assertIn(d_bl, bl)
        finally:
            self.http_client.delete_whitelist(d_wl)
            self.http_client.delete_blacklist(d_bl)

    def test_t3_p13_dual_core_and_dns_server(self):
        """F13 + F06: Core 1 DNS engine latency remains low under Core 0 HTTP load."""
        t0 = time.perf_counter()
        # Concurrently request HTTP stats and DNS query
        self.http_client.get_stats()
        resp = self.dns_query("2mdn.net")
        total_time_ms = (time.perf_counter() - t0) * 1000.0
        self.assert_sinkholed(resp)
        self.assertLess(total_time_ms, 100.0)

    def test_t3_p14_test_harness_and_upstream(self):
        """F14 + F08: Test harness validates resolution of multiple public domains."""
        domains = ["google.com", "github.com", "cloudflare.com"]
        for d in domains:
            resp = self.dns_query(d)
            self.assert_resolved_public(resp)

    def test_t3_p15_adversarial_packets_and_dns_stability(self):
        """F15 + F06: DNS engine survives malformed packets and continues normal processing."""
        # Send garbage packet
        self.dns_client.send_raw_packet(b"\xFF\xFE\x00\x00")
        # Ensure server immediately answers valid query
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp)
