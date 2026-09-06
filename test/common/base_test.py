"""
Base test case class providing test harness integration and assertion helpers.
"""

import unittest
from typing import Optional, Any

try:
    from common.dns_client import DnsClient, DnsResponse
    from common.http_client import HttpClient, HttpResponse
except ImportError:
    from test.common.dns_client import DnsClient, DnsResponse
    from test.common.http_client import HttpClient, HttpResponse


class BaseE2ETest(unittest.TestCase):
    """Base test case for all Tier 1-4 tests."""
    dns_client: Optional[DnsClient] = None
    http_client: Optional[HttpClient] = None

    @classmethod
    def set_clients(cls, dns_client: DnsClient, http_client: HttpClient):
        cls.dns_client = dns_client
        cls.http_client = http_client

    def setUp(self):
        if self.dns_client is None or self.http_client is None:
            # Fallback for standalone unittest runner using defaults
            self.dns_client = DnsClient(host="127.0.0.1", port=53)
            self.http_client = HttpClient(host="127.0.0.1", port=80)

    def dns_query(self, domain: str, qtype: int = 1, qclass: int = 1) -> DnsResponse:
        """Helper to send DNS query via the configured client."""
        return self.dns_client.query(domain, qtype=qtype, qclass=qclass)

    def assert_sinkholed(self, resp: DnsResponse, msg: Optional[str] = None):
        """Assert that DNS response sinkholes domain to 0.0.0.0 with TTL 300 and NOERROR."""
        detail = f" (answers={resp.answers}, rcode={resp.rcode})"
        self.assertEqual(resp.rcode, 0, (msg or "DNS RCODE must be NOERROR") + detail)
        self.assertGreaterEqual(resp.ancount, 1, (msg or "Answer count must be >= 1") + detail)
        self.assertEqual(resp.primary_ip, "0.0.0.0", (msg or "Sinkholed IP must be 0.0.0.0") + detail)
        self.assertEqual(resp.primary_ttl, 300, (msg or "Sinkholed TTL must be 300s") + detail)

    def assert_resolved_public(self, resp: DnsResponse, msg: Optional[str] = None):
        """Assert that DNS response resolves to a valid public IP address (not 0.0.0.0)."""
        detail = f" (answers={resp.answers}, rcode={resp.rcode})"
        self.assertEqual(resp.rcode, 0, (msg or "DNS RCODE must be NOERROR") + detail)
        self.assertIsNotNone(resp.primary_ip, (msg or "Resolved IP must not be None") + detail)
        self.assertNotEqual(resp.primary_ip, "0.0.0.0", (msg or "Resolved IP must not be 0.0.0.0") + detail)
        # Verify valid IPv4 format
        parts = resp.primary_ip.split(".")
        self.assertEqual(len(parts), 4, f"Invalid IPv4 string: {resp.primary_ip}")
        for part in parts:
            val = int(part)
            self.assertTrue(0 <= val <= 255, f"Octet out of range: {val}")

    def assert_http_ok(self, resp: HttpResponse, msg: Optional[str] = None):
        """Assert that HTTP response status is 200 OK."""
        self.assertEqual(resp.status, 200, (msg or f"Expected HTTP 200, got {resp.status} (body={resp.text[:100]})"))
