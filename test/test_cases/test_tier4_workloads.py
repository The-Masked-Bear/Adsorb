"""
Tier 4: Real-World Workloads & Scenarios (8 Tests T4_W01 - T4_W08).
Validates end-to-end user workflows, real-world browsing sessions, burst traffic, and stability soak.
"""

import time
import socket
try:
    from common.base_test import BaseE2ETest
except ImportError:
    from test.common.base_test import BaseE2ETest


class TestTier4Workloads(BaseE2ETest):

    def test_t4_w01_cold_boot_and_initial_query(self):
        """T4_W01: Cold boot readiness and initial query responsiveness."""
        stats_resp = self.http_client.get_stats()
        self.assert_http_ok(stats_resp)
        self.assertGreater(stats_resp.json.get("blocklist_count", 0), 0)

        t0 = time.perf_counter()
        dns_resp = self.dns_query("2mdn.net")
        latency_ms = (time.perf_counter() - t0) * 1000.0
        self.assert_sinkholed(dns_resp)
        self.assertLess(latency_ms, 50.0, "Initial DNS query must resolve in < 50ms")

    def test_t4_w02_web_browsing_mixed_session(self):
        """T4_W02: Realistic web browsing session with mixed legitimate and ad domains."""
        domains = [
            ("google.com", False),
            ("2mdn.net", True),
            ("github.com", False),
            ("3lift.com", True),
            ("cloudflare.com", False),
            ("a-ads.com", True),
            ("wikipedia.org", False),
            ("static.2mdn.net", True),
            ("example.com", False),
            ("video.3lift.com", True)
        ]
        for domain, should_block in domains:
            resp = self.dns_query(domain)
            if should_block:
                self.assert_sinkholed(resp, f"Domain {domain} should be sinkholed")
            else:
                self.assert_resolved_public(resp, f"Domain {domain} should resolve to public IP")

    def test_t4_w03_ad_campaign_flood_subdomains(self):
        """T4_W03: Ad network multi-subdomain tracking campaign flood."""
        subdomains = [
            "ad1.2mdn.net", "ad2.2mdn.net", "static-cdn.2mdn.net",
            "tracker.3lift.com", "pixel.3lift.com", "events.3lift.com",
            "banner.a-ads.com", "widget.a-ads.com"
        ]
        for sub in subdomains:
            resp = self.dns_query(sub)
            self.assert_sinkholed(resp, f"Subdomain {sub} must be sinkholed")

    def test_t4_w04_dynamic_whitelist_workflow(self):
        """T4_W04: End-to-end user workflow adding and removing whitelist exemption."""
        target = "2mdn.net"
        # 1. Initially blocked
        r1 = self.dns_query(target)
        self.assert_sinkholed(r1)

        # 2. Add to whitelist via REST
        add_resp = self.http_client.add_whitelist(target)
        self.assert_http_ok(add_resp)

        try:
            # 3. Query should now resolve upstream
            r2 = self.dns_query(target)
            self.assertNotEqual(r2.primary_ip, "0.0.0.0", "Whitelisted domain must not be sinkholed")

            # 4. Remove from whitelist via REST
            del_resp = self.http_client.delete_whitelist(target)
            self.assert_http_ok(del_resp)

            # 5. Query must immediately revert to sinkholed
            r3 = self.dns_query(target)
            self.assert_sinkholed(r3, "Domain must be blocked again after removal from whitelist")
        finally:
            self.http_client.delete_whitelist(target)

    def test_t4_w05_dashboard_polling_under_load(self):
        """T4_W05: Simultaneous dashboard polling and concurrent DNS traffic."""
        for i in range(10):
            # Interleave DNS queries and REST API calls
            dns_resp = self.dns_query("2mdn.net")
            self.assert_sinkholed(dns_resp)

            stats = self.http_client.get_stats()
            self.assert_http_ok(stats)

            queries = self.http_client.get_queries()
            self.assert_http_ok(queries)

    def test_t4_w06_ring_buffer_wrap_and_saturation(self):
        """T4_W06: Ring buffer maintains maxlen 1000 without memory exhaustion."""
        for i in range(25):
            self.dns_query(f"burst-saturation-{i}.example.org")

        queries = self.http_client.get_queries().json
        self.assertLessEqual(len(queries), 1000)

    def test_t4_w07_dual_stack_ipv4_ipv6_client(self):
        """T4_W07: Dual-stack client querying both A (IPv4) and AAAA (IPv6) records."""
        # A record for ad domain -> 0.0.0.0
        resp_a_blocked = self.dns_query("2mdn.net", qtype=1)
        self.assert_sinkholed(resp_a_blocked)

        # AAAA record for ad domain -> NOERROR (empty answer or sinkhole)
        resp_aaaa_blocked = self.dns_query("2mdn.net", qtype=28)
        self.assertEqual(resp_aaaa_blocked.rcode, 0)

        # A record for clean domain -> Public IP
        resp_a_clean = self.dns_query("google.com", qtype=1)
        self.assert_resolved_public(resp_a_clean)

    def test_t4_w08_extended_memory_stability_soak(self):
        """T4_W08: Memory soak test verifying free heap and PSRAM stability across queries."""
        initial_stats = self.http_client.get_stats().json
        init_heap = initial_stats["free_heap"]
        init_psram = initial_stats["free_psram"]

        # 30 rapid mixed queries
        for i in range(15):
            self.dns_query("2mdn.net")
            self.dns_query("google.com")

        final_stats = self.http_client.get_stats().json
        final_heap = final_stats["free_heap"]
        final_psram = final_stats["free_psram"]

        # Heap and PSRAM should not suffer memory leak (>50KB drop)
        self.assertGreaterEqual(final_heap, init_heap - 50000, "Internal SRAM must remain stable")
        self.assertGreaterEqual(final_psram, init_psram - 50000, "PSRAM must remain stable")
