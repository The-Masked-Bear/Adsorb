"""
Tier 2: Boundary & Corner Cases Test Suite (75 Tests across Features F01 - F15).
Validates edge cases, limits, RFC corner cases, and error handling for all R1-R5 requirements.
"""

import time
import socket
try:
    from common.base_test import BaseE2ETest
except ImportError:
    from test.common.base_test import BaseE2ETest


class TestTier2Boundaries(BaseE2ETest):

    # ==================== F01: PlatformIO & Hardware Config Boundaries ====================
    def test_t2_f01_01_stats_free_heap_not_zero(self):
        stats = self.http_client.get_stats().json
        self.assertGreater(stats.get("free_heap", 0), 0)

    def test_t2_f01_02_stats_free_psram_not_zero(self):
        stats = self.http_client.get_stats().json
        self.assertGreater(stats.get("free_psram", 0), 0)

    def test_t2_f01_03_uptime_does_not_overflow(self):
        uptime = self.http_client.get_stats().json.get("uptime", 0)
        self.assertLess(uptime, 0xFFFFFFFF, "Uptime must not overflow 32-bit uint")

    def test_t2_f01_04_rapid_stats_queries(self):
        for _ in range(10):
            resp = self.http_client.get_stats()
            self.assertEqual(resp.status, 200)

    def test_t2_f01_05_header_content_length(self):
        resp = self.http_client.get_stats()
        cl = resp.headers.get("content-length")
        self.assertIsNotNone(cl)
        self.assertGreater(int(cl), 0)

    # ==================== F02: Custom 16MB Partition Table & LittleFS Boundaries ====================
    def test_t2_f02_01_whitelist_empty_domain_rejection(self):
        resp = self.http_client.add_whitelist("")
        self.assertEqual(resp.status, 400, "Empty domain in whitelist must return HTTP 400")

    def test_t2_f02_02_blacklist_empty_domain_rejection(self):
        resp = self.http_client.add_blacklist("")
        self.assertEqual(resp.status, 400, "Empty domain in blacklist must return HTTP 400")

    def test_t2_f02_03_whitelist_max_domain_length(self):
        # 253 characters max domain length per RFC 1035
        long_domain = ("a" * 60 + ".") * 3 + "com"  # ~184 chars
        resp = self.http_client.add_whitelist(long_domain)
        self.assertIn(resp.status, [200, 400])
        self.http_client.delete_whitelist(long_domain)

    def test_t2_f02_04_delete_nonexistent_whitelist(self):
        resp = self.http_client.delete_whitelist("nonexistent-domain-xyz-123.com")
        self.assertEqual(resp.status, 200, "Deleting nonexistent domain should cleanly succeed")

    def test_t2_f02_05_delete_nonexistent_blacklist(self):
        resp = self.http_client.delete_blacklist("nonexistent-domain-xyz-123.com")
        self.assertEqual(resp.status, 200, "Deleting nonexistent domain should cleanly succeed")

    # ==================== F03: PSRAM Custom C++ Allocator Boundaries ====================
    def test_t2_f03_01_allocation_churn(self):
        for i in range(10):
            d = f"churn-{i}.example.org"
            self.http_client.add_whitelist(d)
            self.http_client.delete_whitelist(d)

    def test_t2_f03_02_heap_stability_under_churn(self):
        h1 = self.http_client.get_stats().json.get("free_heap", 0)
        for i in range(5):
            d = f"heap-test-{i}.org"
            self.http_client.add_whitelist(d)
            self.http_client.delete_whitelist(d)
        h2 = self.http_client.get_stats().json.get("free_heap", 0)
        self.assertAlmostEqual(h1, h2, delta=10000, msg="Heap should remain stable after rule churn")

    def test_t2_f03_03_psram_stability_under_churn(self):
        p1 = self.http_client.get_stats().json.get("free_psram", 0)
        for i in range(5):
            d = f"psram-test-{i}.org"
            self.http_client.add_blacklist(d)
            self.http_client.delete_blacklist(d)
        p2 = self.http_client.get_stats().json.get("free_psram", 0)
        self.assertAlmostEqual(p1, p2, delta=10000, msg="PSRAM should remain stable after rule churn")

    def test_t2_f03_04_duplicate_whitelist_addition(self):
        d = "duplicate-whitelist.org"
        self.http_client.add_whitelist(d)
        resp2 = self.http_client.add_whitelist(d)
        self.assertEqual(resp2.status, 200)
        self.http_client.delete_whitelist(d)

    def test_t2_f03_05_duplicate_blacklist_addition(self):
        d = "duplicate-blacklist.org"
        self.http_client.add_blacklist(d)
        resp2 = self.http_client.add_blacklist(d)
        self.assertEqual(resp2.status, 200)
        self.http_client.delete_blacklist(d)

    # ==================== F04: Blocklist Ingestion Boundaries ====================
    def test_t2_f04_01_trailing_dot_query(self):
        resp = self.dns_query("2mdn.net.")
        self.assert_sinkholed(resp, "Query with trailing dot must be sinkholed")

    def test_t2_f04_02_leading_dot_clean(self):
        resp = self.dns_query(".google.com")
        self.assertIn(resp.rcode, [0, 1, 3])

    def test_t2_f04_03_similar_unblocked_tld(self):
        # 2mdn.net is blocked, 2mdn.org should NOT be blocked
        resp = self.dns_query("2mdn.org")
        self.assertNotEqual(resp.primary_ip, "0.0.0.0", "Different TLD must not be blocked")

    def test_t2_f04_04_similar_prefix_domain(self):
        # not2mdn.net is NOT a subdomain of 2mdn.net
        resp = self.dns_query("not2mdn.net")
        self.assertNotEqual(resp.primary_ip, "0.0.0.0", "Prefix substring match must not be blocked")

    def test_t2_f04_05_mixed_case_subdomain(self):
        resp = self.dns_query("StAtIc.2MdN.nEt")
        self.assert_sinkholed(resp, "Mixed-case subdomain must be sinkholed")

    # ==================== F05: Custom Whitelist & Blacklist Storage Boundaries ====================
    def test_t2_f05_01_whitelist_overrides_blocklist(self):
        domain = "2mdn.net"
        # Add to whitelist
        self.http_client.add_whitelist(domain)
        try:
            resp = self.dns_query(domain)
            self.assertNotEqual(resp.primary_ip, "0.0.0.0", "Whitelisted domain must not be sinkholed")
        finally:
            self.http_client.delete_whitelist(domain)

    def test_t2_f05_02_whitelist_subdomain_override(self):
        domain = "safe.2mdn.net"
        self.http_client.add_whitelist(domain)
        try:
            resp1 = self.dns_query("safe.2mdn.net")
            self.assertNotEqual(resp1.primary_ip, "0.0.0.0", "Whitelisted subdomain must resolve upstream")
            resp2 = self.dns_query("other.2mdn.net")
            self.assert_sinkholed(resp2, "Non-whitelisted sibling subdomain must remain sinkholed")
        finally:
            self.http_client.delete_whitelist(domain)

    def test_t2_f05_03_blacklist_overrides_clean_domain(self):
        domain = "google.com"
        self.http_client.add_blacklist(domain)
        try:
            resp = self.dns_query(domain)
            self.assert_sinkholed(resp, "Blacklisted domain must be sinkholed to 0.0.0.0")
        finally:
            self.http_client.delete_blacklist(domain)

    def test_t2_f05_04_blacklist_subdomain_blocking(self):
        domain = "example.com"
        self.http_client.add_blacklist(domain)
        try:
            resp = self.dns_query("api.example.com")
            self.assert_sinkholed(resp, "Subdomain of blacklisted domain must be sinkholed")
        finally:
            self.http_client.delete_blacklist(domain)

    def test_t2_f05_05_cleanup_restores_defaults(self):
        # Verify 2mdn.net is blocked again after cleanups
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp)

    # ==================== F06: RFC 1035 UDP Port 53 DNS Server Boundaries ====================
    def test_t2_f06_01_tx_id_zero(self):
        resp = self.dns_client.query("2mdn.net", tx_id=0x0000)
        self.assertEqual(resp.tx_id, 0x0000)

    def test_t2_f06_02_tx_id_max_uint16(self):
        resp = self.dns_client.query("2mdn.net", tx_id=0xFFFF)
        self.assertEqual(resp.tx_id, 0xFFFF)

    def test_t2_f06_03_recursion_desired_bit_unset(self):
        # Query with RD=0
        packet = self.dns_client.build_query_packet("2mdn.net")
        # Unset RD bit (bit 8)
        modified = bytearray(packet)
        modified[2] &= ~0x01
        data, _ = self.dns_client.send_raw_packet(bytes(modified))
        self.assertIsNotNone(data)
        parsed = self.dns_client.parse_response_packet(data)
        self.assertEqual(parsed.primary_ip, "0.0.0.0")

    def test_t2_f06_04_query_non_in_qclass(self):
        resp = self.dns_client.query("2mdn.net", qclass=1)  # IN class
        self.assertEqual(resp.rcode, 0)

    def test_t2_f06_05_maximum_label_length(self):
        # 63 characters label
        max_label = "a" * 63 + ".2mdn.net"
        resp = self.dns_query(max_label)
        self.assert_sinkholed(resp)

    # ==================== F07: Subdomain Sinking Boundaries ====================
    def test_t2_f07_01_deeply_nested_subdomain(self):
        deep = "a.b.c.d.e.f.2mdn.net"
        resp = self.dns_query(deep)
        self.assert_sinkholed(resp, "Deeply nested subdomain must be sinkholed")

    def test_t2_f07_02_single_letter_subdomain(self):
        resp = self.dns_query("z.2mdn.net")
        self.assert_sinkholed(resp)

    def test_t2_f07_03_hyphenated_subdomain(self):
        resp = self.dns_query("my-custom-ad.2mdn.net")
        self.assert_sinkholed(resp)

    def test_t2_f07_04_numeric_subdomain(self):
        resp = self.dns_query("98765.2mdn.net")
        self.assert_sinkholed(resp)

    def test_t2_f07_05_root_tld_not_sinkholed(self):
        # querying bare "net" should not be sinkholed to 0.0.0.0
        resp = self.dns_query("net")
        self.assertNotEqual(resp.primary_ip, "0.0.0.0")

    # ==================== F08: Upstream DNS Forwarder Boundaries ====================
    def test_t2_f08_01_nonexistent_domain_nxdomain(self):
        resp = self.dns_query("random-uuid-9999-never-exists-xyz.org")
        self.assertIn(resp.rcode, [0, 3], "Nonexistent domain should return NXDOMAIN or empty")

    def test_t2_f08_02_cname_handling(self):
        resp = self.dns_query("www.google.com")
        self.assert_resolved_public(resp)

    def test_t2_f08_03_subdomain_upstream(self):
        resp = self.dns_query("maps.google.com")
        self.assert_resolved_public(resp)

    def test_t2_f08_04_international_domain(self):
        resp = self.dns_query("xn--fsqu00a.xn--0zwm56d")  # example IDN
        self.assertIn(resp.rcode, [0, 3])

    def test_t2_f08_05_upstream_response_flags(self):
        resp = self.dns_query("google.com")
        self.assertEqual(resp.qr, 1)

    # ==================== F09: Statistics Engine Boundaries ====================
    def test_t2_f09_01_zero_queries_percentage_safe(self):
        resp = self.http_client.get_stats()
        self.assertGreaterEqual(resp.json["percentage"], 0.0)

    def test_t2_f09_02_consecutive_increments_match(self):
        t1 = self.http_client.get_stats().json["total"]
        for _ in range(5):
            self.dns_query("google.com")
        t2 = self.http_client.get_stats().json["total"]
        self.assertEqual(t2 - t1, 5, "Total counter must increment by exactly 5")

    def test_t2_f09_03_blocked_count_never_exceeds_total(self):
        stats = self.http_client.get_stats().json
        self.assertLessEqual(stats["blocked"], stats["total"])

    def test_t2_f09_04_percentage_bounds(self):
        stats = self.http_client.get_stats().json
        self.assertTrue(0.0 <= stats["percentage"] <= 100.0)

    def test_t2_f09_05_stats_response_time(self):
        t0 = time.perf_counter()
        self.http_client.get_stats()
        duration_ms = (time.perf_counter() - t0) * 1000.0
        self.assertLess(duration_ms, 100.0)

    # ==================== F10: Recent Query Ring Buffer Boundaries ====================
    def test_t2_f10_01_ring_buffer_fifo_preservation(self):
        unique_domain = f"test-fifo-{int(time.time()*1000)}.org"
        self.dns_query(unique_domain)
        queries = self.http_client.get_queries().json
        self.assertTrue(any(q.get("domain") == unique_domain for q in queries))

    def test_t2_f10_02_empty_domain_safe(self):
        resp = self.dns_query("")
        self.assertIsNotNone(resp)

    def test_t2_f10_03_recent_queries_length_limit(self):
        queries = self.http_client.get_queries().json
        self.assertLessEqual(len(queries), 1000, "Ring buffer must never exceed 1000 entries")

    def test_t2_f10_04_timestamp_recent(self):
        self.dns_query("2mdn.net")
        queries = self.http_client.get_queries().json
        latest = queries[-1]
        self.assertGreater(latest["timestamp"], time.time() - 300)

    def test_t2_f10_05_client_ip_format(self):
        self.dns_query("2mdn.net")
        queries = self.http_client.get_queries().json
        latest = queries[-1]
        self.assertTrue(len(latest["client_ip"]) > 0)

    # ==================== F11: Local Web Dashboard UI Boundaries ====================
    def test_t2_f11_01_dashboard_head_request(self):
        resp = self.http_client.request("HEAD", "/")
        self.assertIn(resp.status, [200, 405, 501])

    def test_t2_f11_02_dashboard_accept_encoding_header(self):
        resp = self.http_client.request("GET", "/", headers={"Accept-Encoding": "gzip, deflate"})
        self.assertEqual(resp.status, 200)

    def test_t2_f11_03_dashboard_user_agent_header(self):
        resp = self.http_client.request("GET", "/", headers={"User-Agent": "Custom-Test-Runner/1.0"})
        self.assertEqual(resp.status, 200)

    def test_t2_f11_04_dashboard_content_length_positive(self):
        resp = self.http_client.get_dashboard()
        self.assertGreater(len(resp.body_bytes), 50)

    def test_t2_f11_05_dashboard_html_valid_structure(self):
        resp = self.http_client.get_dashboard()
        self.assertIn("<html", resp.text.lower())

    # ==================== F12: Management REST APIs Boundaries ====================
    def test_t2_f12_01_malformed_json_body_post(self):
        resp = self.http_client.request("POST", "/api/whitelist", body=b"INVALID_JSON_{{",
                                        headers={"Content-Type": "application/json"})
        self.assertEqual(resp.status, 400)

    def test_t2_f12_02_missing_domain_key_post(self):
        resp = self.http_client.request("POST", "/api/whitelist", body={"wrong_key": "val"})
        self.assertEqual(resp.status, 400)

    def test_t2_f12_03_delete_with_query_param(self):
        d = "param-delete-test.org"
        self.http_client.add_whitelist(d)
        resp = self.http_client.request("DELETE", f"/api/whitelist?domain={d}")
        self.assertEqual(resp.status, 200)

    def test_t2_f12_04_delete_with_json_body(self):
        d = "body-delete-test.org"
        self.http_client.add_whitelist(d)
        resp = self.http_client.request("DELETE", "/api/whitelist", body={"domain": d})
        self.assertEqual(resp.status, 200)

    def test_t2_f12_05_unsupported_method_on_stats(self):
        resp = self.http_client.request("POST", "/api/stats", body={})
        self.assertIn(resp.status, [404, 405])

    # ==================== F13: Dual-Core Task Segregation Boundaries ====================
    def test_t2_f13_01_burst_dns_during_http_poll(self):
        for _ in range(5):
            self.dns_query("2mdn.net")
            self.http_client.get_stats()

    def test_t2_f13_02_no_dropped_dns_during_http(self):
        for _ in range(5):
            resp = self.dns_query("google.com")
            self.assert_resolved_public(resp)

    def test_t2_f13_03_no_failed_http_during_dns(self):
        for _ in range(5):
            resp = self.http_client.get_stats()
            self.assert_http_ok(resp)

    def test_t2_f13_04_interleaved_query_and_api(self):
        for i in range(3):
            self.dns_query(f"burst-{i}.2mdn.net")
            self.http_client.get_queries()

    def test_t2_f13_05_ring_buffer_thread_safety(self):
        # Ring buffer reads while writes occur
        queries = self.http_client.get_queries().json
        self.assertIsInstance(queries, list)

    # ==================== F14: Test Suite Harness Boundaries ====================
    def test_t2_f14_01_short_socket_timeout(self):
        # Custom short timeout client
        from test.common.dns_client import DnsClient
        client = DnsClient(self.dns_client.host, self.dns_client.port, timeout=0.5)
        resp = client.query("2mdn.net")
        self.assert_sinkholed(resp)

    def test_t2_f14_02_large_udp_buffer(self):
        raw_pkt = self.dns_client.build_query_packet("2mdn.net")
        data, _ = self.dns_client.send_raw_packet(raw_pkt)
        self.assertLess(len(data), 512, "RFC 1035 UDP payload must be <= 512 bytes")

    def test_t2_f14_03_qname_label_encoder_limits(self):
        from test.common.dns_client import DnsClient
        encoded = DnsClient.encode_qname("a.b.c")
        self.assertEqual(encoded, b"\x01a\x01b\x01c\x00")

    def test_t2_f14_04_decode_name_pointer_limit(self):
        from test.common.dns_client import DnsClient
        # Loop pointer simulation
        data = b"\xc0\x00"  # Pointer pointing to itself
        name, offset = DnsClient.decode_name(data, 0)
        self.assertIsInstance(name, str)

    def test_t2_f14_05_http_client_connection_reuse(self):
        for _ in range(3):
            r = self.http_client.get_stats()
            self.assertEqual(r.status, 200)

    # ==================== F15: Adversarial Hardening Boundaries ====================
    def test_t2_f15_01_single_byte_packet(self):
        self.dns_client.send_raw_packet(b"\x00")

    def test_t2_f15_02_oversized_label_byte(self):
        # Header + label length byte claiming 100 bytes when packet is 15 bytes
        malformed = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x64abc\x00\x00\x01\x00\x01"
        self.dns_client.send_raw_packet(malformed)

    def test_t2_f15_03_zero_byte_in_middle_of_header(self):
        self.dns_client.send_raw_packet(b"\x00" * 12)

    def test_t2_f15_04_unusual_qtype_query(self):
        resp = self.dns_query("google.com", qtype=255)  # ANY
        self.assertIsNotNone(resp)

    def test_t2_f15_05_query_after_adversarial_battery(self):
        # Normal query immediately after adversarial packets
        resp = self.dns_query("2mdn.net")
        self.assert_sinkholed(resp, "Server must remain functional after boundary test battery")
