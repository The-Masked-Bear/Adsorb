"""
Tier 1: Feature Coverage Test Suite (75 Tests across Features F01 - F15).
Validates nominal behavior and primary interface contracts for all R1-R5 requirements.
"""

import time
import socket
try:
    from common.base_test import BaseE2ETest
except ImportError:
    from test.common.base_test import BaseE2ETest


class TestTier1Features(BaseE2ETest):

    # ==================== F01: PlatformIO & Hardware Config ====================
    def test_t1_f01_01_hardware_stats_endpoint(self):
        resp = self.http_client.get_stats()
        self.assert_http_ok(resp)
        self.assertIsInstance(resp.json, dict)

    def test_t1_f01_02_heap_memory_baseline(self):
        resp = self.http_client.get_stats()
        self.assert_http_ok(resp)
        free_heap = resp.json.get("free_heap", 0)
        self.assertGreater(free_heap, 50000, "Free internal SRAM must be > 50KB")

    def test_t1_f01_03_psram_memory_baseline(self):
        resp = self.http_client.get_stats()
        self.assert_http_ok(resp)
        free_psram = resp.json.get("free_psram", 0)
        self.assertGreater(free_psram, 1000000, "Free PSRAM must be > 1MB")

    def test_t1_f01_04_system_uptime_reporting(self):
        resp = self.http_client.get_stats()
        self.assert_http_ok(resp)
        uptime = resp.json.get("uptime", -1)
        self.assertGreaterEqual(uptime, 0, "Uptime must be non-negative integer")

    def test_t1_f01_05_hardware_identification(self):
        resp = self.http_client.get_dashboard()
        self.assert_http_ok(resp)
        self.assertIn("ESP32-S3", resp.text)

    # ==================== F02: Custom 16MB Partition Table & LittleFS ====================
    def test_t1_f02_01_littlefs_blocklist_loaded(self):
        resp = self.http_client.get_stats()
        self.assert_http_ok(resp)
        blocklist_count = resp.json.get("blocklist_count", 0)
        self.assertGreater(blocklist_count, 0, "Blocklist must be ingested from LittleFS")

    def test_t1_f02_02_littlefs_whitelist_endpoint(self):
        resp = self.http_client.get_whitelist()
        self.assert_http_ok(resp)
        self.assertIsInstance(resp.json, list)

    def test_t1_f02_03_littlefs_blacklist_endpoint(self):
        resp = self.http_client.get_blacklist()
        self.assert_http_ok(resp)
        self.assertIsInstance(resp.json, list)

    def test_t1_f02_04_storage_capacity_stats(self):
        resp = self.http_client.get_stats()
        self.assert_http_ok(resp)
        stats = resp.json
        self.assertIn("free_heap", stats)
        self.assertIn("free_psram", stats)

    def test_t1_f02_05_custom_rules_initial_valid(self):
        resp = self.http_client.get_whitelist()
        self.assert_http_ok(resp)
        self.assertTrue(isinstance(resp.json, list))

    # ==================== F03: PSRAM Custom C++ Allocator ====================
    def test_t1_f03_01_psram_capacity_retention(self):
        resp = self.http_client.get_stats()
        free_psram = resp.json.get("free_psram", 0)
        self.assertGreater(free_psram, 2000000, "PSRAM free space should exceed 2MB")

    def test_t1_f03_02_internal_sram_preservation(self):
        resp = self.http_client.get_stats()
        free_heap = resp.json.get("free_heap", 0)
        self.assertGreater(free_heap, 100000, "Internal SRAM must be preserved for networking stack")

    def test_t1_f03_03_psram_heap_ratio(self):
        resp = self.http_client.get_stats()
        stats = resp.json
        self.assertGreater(stats.get("free_psram", 0), stats.get("free_heap", 0),
                            "Free PSRAM must be significantly greater than free internal SRAM")

    def test_t1_f03_04_dynamic_rule_allocation(self):
        test_domain = "psram-alloc-test.com"
        resp = self.http_client.add_whitelist(test_domain)
        self.assert_http_ok(resp)
        # Cleanup
        self.http_client.delete_whitelist(test_domain)

    def test_t1_f03_05_dynamic_rule_deallocation(self):
        test_domain = "psram-dealloc-test.com"
        self.http_client.add_whitelist(test_domain)
        del_resp = self.http_client.delete_whitelist(test_domain)
        self.assert_http_ok(del_resp)

    # ==================== F04: Blocklist Ingestion & Caching ====================
    def test_t1_f04_01_known_ad_domain_2mdn(self):
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp, "2mdn.net must be sinkholed to 0.0.0.0")

    def test_t1_f04_02_known_ad_domain_3lift(self):
        resp = self.dns_query("3lift.com")
        self.assert_sinkholed(resp, "3lift.com must be sinkholed to 0.0.0.0")

    def test_t1_f04_03_known_ad_domain_a_ads(self):
        resp = self.dns_query("a-ads.com")
        self.assert_sinkholed(resp, "a-ads.com must be sinkholed to 0.0.0.0")

    def test_t1_f04_04_case_insensitivity(self):
        resp = self.dns_query("2MDN.NET")
        self.assert_sinkholed(resp, "Uppercase domain 2MDN.NET must be sinkholed")

    def test_t1_f04_05_unblocked_domain_pass(self):
        resp = self.dns_query("google.com")
        self.assert_resolved_public(resp, "google.com must resolve to public IP")

    # ==================== F05: Custom Whitelist & Blacklist Storage ====================
    def test_t1_f05_01_add_custom_whitelist(self):
        domain = "safe-api.test.org"
        resp = self.http_client.add_whitelist(domain)
        self.assert_http_ok(resp)
        self.http_client.delete_whitelist(domain)

    def test_t1_f05_02_verify_whitelist_retrieval(self):
        domain = "safe-retrieve.test.org"
        self.http_client.add_whitelist(domain)
        resp = self.http_client.get_whitelist()
        self.assertIn(domain, resp.json)
        self.http_client.delete_whitelist(domain)

    def test_t1_f05_03_delete_custom_whitelist(self):
        domain = "safe-del.test.org"
        self.http_client.add_whitelist(domain)
        self.http_client.delete_whitelist(domain)
        resp = self.http_client.get_whitelist()
        self.assertNotIn(domain, resp.json)

    def test_t1_f05_04_add_custom_blacklist(self):
        domain = "bad-ad.test.org"
        resp = self.http_client.add_blacklist(domain)
        self.assert_http_ok(resp)
        self.http_client.delete_blacklist(domain)

    def test_t1_f05_05_delete_custom_blacklist(self):
        domain = "bad-del.test.org"
        self.http_client.add_blacklist(domain)
        self.http_client.delete_blacklist(domain)
        resp = self.http_client.get_blacklist()
        self.assertNotIn(domain, resp.json)

    # ==================== F06: RFC 1035 UDP Port 53 DNS Server ====================
    def test_t1_f06_01_tx_id_echo(self):
        tx_id = 0x5432
        resp = self.dns_client.query("2mdn.net", tx_id=tx_id)
        self.assertEqual(resp.tx_id, tx_id, "Response transaction ID must echo query ID")

    def test_t1_f06_02_qr_flag_set(self):
        resp = self.dns_query("2mdn.net")
        self.assertEqual(resp.qr, 1, "Response bit QR must be set to 1")

    def test_t1_f06_03_ra_flag_set(self):
        resp = self.dns_query("2mdn.net")
        self.assertEqual(resp.ra, 1, "Recursion Available bit RA must be 1")

    def test_t1_f06_04_qdcount_preserved(self):
        resp = self.dns_query("2mdn.net")
        self.assertEqual(resp.qdcount, 1, "QDCOUNT in response must be 1")

    def test_t1_f06_05_standard_udp_transport(self):
        raw_pkt = self.dns_client.build_query_packet("2mdn.net")
        data, latency = self.dns_client.send_raw_packet(raw_pkt)
        self.assertIsNotNone(data, "UDP socket must receive response packet")
        self.assertGreater(len(data), 12, "Packet must contain header")

    # ==================== F07: Subdomain Sinking & Matching Engine ====================
    def test_t1_f07_01_exact_domain_sunk(self):
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp)

    def test_t1_f07_02_single_subdomain_sunk(self):
        resp = self.dns_query("static.2mdn.net")
        self.assert_sinkholed(resp, "Subdomain static.2mdn.net must be sinkholed")

    def test_t1_f07_03_nested_subdomain_sunk(self):
        resp = self.dns_query("video.ads.3lift.com")
        self.assert_sinkholed(resp, "Multi-level subdomain must be sinkholed")

    def test_t1_f07_04_ttl_300_enforced(self):
        resp = self.dns_query("2mdn.net")
        self.assertEqual(resp.primary_ttl, 300, "Sinkholed A-record TTL must be exactly 300 seconds")

    def test_t1_f07_05_rcode_noerror_enforced(self):
        resp = self.dns_query("2mdn.net")
        self.assertEqual(resp.rcode, 0, "Sinkhole response RCODE must be NOERROR (0)")

    # ==================== F08: Upstream DNS Forwarder & Relay ====================
    def test_t1_f08_01_upstream_google_resolution(self):
        resp = self.dns_query("google.com")
        self.assert_resolved_public(resp)

    def test_t1_f08_02_upstream_github_resolution(self):
        resp = self.dns_query("github.com")
        self.assert_resolved_public(resp)

    def test_t1_f08_03_upstream_cloudflare_resolution(self):
        resp = self.dns_query("cloudflare.com")
        self.assert_resolved_public(resp)

    def test_t1_f08_04_upstream_wikipedia_resolution(self):
        resp = self.dns_query("wikipedia.org")
        self.assert_resolved_public(resp)

    def test_t1_f08_05_upstream_non_blocked_ttl(self):
        resp = self.dns_query("google.com")
        self.assertGreaterEqual(resp.ancount, 1, "Upstream response must contain at least 1 answer")

    # ==================== F09: Real-Time Statistics Engine ====================
    def test_t1_f09_01_stats_json_schema(self):
        resp = self.http_client.get_stats()
        stats = resp.json
        for key in ["total", "blocked", "percentage", "free_heap", "free_psram", "uptime"]:
            self.assertIn(key, stats, f"Stats missing key: {key}")

    def test_t1_f09_02_total_counter_increment(self):
        s1 = self.http_client.get_stats().json["total"]
        self.dns_query("google.com")
        s2 = self.http_client.get_stats().json["total"]
        self.assertGreater(s2, s1, "Total query count must increment")

    def test_t1_f09_03_blocked_counter_increment(self):
        b1 = self.http_client.get_stats().json["blocked"]
        self.dns_query("2mdn.net")
        b2 = self.http_client.get_stats().json["blocked"]
        self.assertGreater(b2, b1, "Blocked query count must increment on sinkholed query")

    def test_t1_f09_04_percentage_calculation(self):
        stats = self.http_client.get_stats().json
        tot = stats["total"]
        blk = stats["blocked"]
        expected_pct = round((blk / tot * 100.0) if tot > 0 else 0.0, 2)
        self.assertAlmostEqual(stats["percentage"], expected_pct, places=1)

    def test_t1_f09_05_uptime_monotonic(self):
        u1 = self.http_client.get_stats().json["uptime"]
        time.sleep(0.05)
        u2 = self.http_client.get_stats().json["uptime"]
        self.assertGreaterEqual(u2, u1, "Uptime must be monotonically non-decreasing")

    # ==================== F10: Recent Query Ring Buffer ====================
    def test_t1_f10_01_ring_buffer_structure(self):
        resp = self.http_client.get_queries()
        self.assert_http_ok(resp)
        self.assertIsInstance(resp.json, list)

    def test_t1_f10_02_record_domain_field(self):
        self.dns_query("2mdn.net")
        queries = self.http_client.get_queries().json
        self.assertTrue(any(q.get("domain") == "2mdn.net" for q in queries))

    def test_t1_f10_03_record_client_ip_field(self):
        self.dns_query("google.com")
        queries = self.http_client.get_queries().json
        self.assertTrue(any("client_ip" in q for q in queries))

    def test_t1_f10_04_record_blocked_flag(self):
        self.dns_query("3lift.com")
        queries = self.http_client.get_queries().json
        blocked_records = [q for q in queries if q.get("domain") == "3lift.com"]
        self.assertTrue(len(blocked_records) > 0 and blocked_records[-1]["blocked"] is True)

    def test_t1_f10_05_record_latency_field(self):
        self.dns_query("google.com")
        queries = self.http_client.get_queries().json
        self.assertTrue(any(q.get("latency_ms", 0) >= 0 for q in queries))

    # ==================== F11: Local Web Dashboard UI ====================
    def test_t1_f11_01_dashboard_http_200(self):
        resp = self.http_client.get_dashboard()
        self.assert_http_ok(resp)

    def test_t1_f11_02_dashboard_html_content_type(self):
        resp = self.http_client.get_dashboard()
        ct = resp.headers.get("content-type", "")
        self.assertIn("text/html", ct)

    def test_t1_f11_03_dashboard_title_element(self):
        resp = self.http_client.get_dashboard()
        self.assertIn("<title>", resp.text)

    def test_t1_f11_04_dashboard_stats_elements(self):
        resp = self.http_client.get_dashboard()
        self.assertIn("total-queries", resp.text)

    def test_t1_f11_05_dashboard_query_log_element(self):
        resp = self.http_client.get_dashboard()
        self.assertIn("query-log", resp.text)

    # ==================== F12: Management REST APIs ====================
    def test_t1_f12_01_get_stats_status(self):
        resp = self.http_client.get_stats()
        self.assertEqual(resp.status, 200)

    def test_t1_f12_02_get_queries_status(self):
        resp = self.http_client.get_queries()
        self.assertEqual(resp.status, 200)

    def test_t1_f12_03_get_whitelist_status(self):
        resp = self.http_client.get_whitelist()
        self.assertEqual(resp.status, 200)

    def test_t1_f12_04_get_blacklist_status(self):
        resp = self.http_client.get_blacklist()
        self.assertEqual(resp.status, 200)

    def test_t1_f12_05_invalid_endpoint_404(self):
        resp = self.http_client.request("GET", "/api/invalid_path_404")
        self.assertEqual(resp.status, 404)

    # ==================== F13: Dual-Core FreeRTOS Task Segregation ====================
    def test_t1_f13_01_concurrent_dns_and_http(self):
        dns_resp = self.dns_query("2mdn.net")
        http_resp = self.http_client.get_stats()
        self.assert_sinkholed(dns_resp)
        self.assert_http_ok(http_resp)

    def test_t1_f13_02_dns_latency_under_50ms(self):
        resp = self.dns_query("2mdn.net")
        self.assertLess(resp.latency_ms, 50.0, "Core 1 DNS query must be served under 50ms")

    def test_t1_f13_03_http_response_under_200ms(self):
        t0 = time.perf_counter()
        resp = self.http_client.get_stats()
        duration_ms = (time.perf_counter() - t0) * 1000.0
        self.assert_http_ok(resp)
        self.assertLess(duration_ms, 200.0, "Core 0 HTTP API should respond under 200ms")

    def test_t1_f13_04_dual_core_stats_accuracy(self):
        self.dns_query("2mdn.net")
        stats = self.http_client.get_stats().json
        self.assertGreater(stats["total"], 0)

    def test_t1_f13_05_continuous_query_stability(self):
        for _ in range(5):
            resp = self.dns_query("google.com")
            self.assert_resolved_public(resp)

    # ==================== F14: Automated E2E Test Suite Harness ====================
    def test_t1_f14_01_dns_client_connectivity(self):
        self.assertIsNotNone(self.dns_client)
        resp = self.dns_query("example.com")
        self.assertIsNotNone(resp)

    def test_t1_f14_02_http_client_connectivity(self):
        self.assertIsNotNone(self.http_client)
        resp = self.http_client.get_stats()
        self.assertEqual(resp.status, 200)

    def test_t1_f14_03_response_packet_parsing(self):
        resp = self.dns_query("2mdn.net")
        self.assertGreater(len(resp.raw_data), 0)
        self.assertEqual(resp.opcode, 0)

    def test_t1_f14_04_http_response_parsing(self):
        resp = self.http_client.get_stats()
        self.assertTrue(len(resp.text) > 0)
        self.assertIsInstance(resp.json, dict)

    def test_t1_f14_05_test_harness_assertions(self):
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp)

    # ==================== F15: Adversarial Coverage Hardening Prep ====================
    def test_t1_f15_01_aaaa_query_handling(self):
        resp = self.dns_query("2mdn.net", qtype=28)  # AAAA
        self.assertEqual(resp.rcode, 0, "AAAA query on blocked domain should return NOERROR")

    def test_t1_f15_02_mx_query_handling(self):
        resp = self.dns_query("google.com", qtype=15)  # MX
        self.assertIn(resp.rcode, [0, 3])

    def test_t1_f15_03_empty_question_safety(self):
        # 12 bytes header with QDCOUNT=0
        raw_pkt = b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        data, _ = self.dns_client.send_raw_packet(raw_pkt)
        # Server should reply FORMERR or safely ignore
        if data:
            resp = self.dns_client.parse_response_packet(data)
            self.assertIn(resp.rcode, [0, 1])

    def test_t1_f15_04_short_packet_safety(self):
        raw_pkt = b"\x12\x34\x01\x00"  # Truncated header
        data, _ = self.dns_client.send_raw_packet(raw_pkt)
        # Server should drop truncated packet without crashing

    def test_t1_f15_05_service_survives_adversarial_packet(self):
        # Send garbage packet
        self.dns_client.send_raw_packet(b"INVALID_DNS_GARBAGE_PACKET_!!!")
        # Ensure server immediately serves normal query
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp, "Server must remain functional after invalid packet")
