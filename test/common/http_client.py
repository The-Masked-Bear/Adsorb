"""
Pure-Python HTTP REST Client for ESP32-S3 Ad Blocker Web Dashboard E2E Testing.
Uses only Python standard library (http.client, urllib, json).
"""

import http.client
import json
import urllib.parse
from typing import Tuple, Dict, Any, Optional, Union


class HttpResponse:
    """Represents an HTTP response."""
    def __init__(self, status: int, headers: Dict[str, str], body: bytes):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body_bytes = body
        self._body_text = None
        self._json_data = None

    @property
    def text(self) -> str:
        if self._body_text is None:
            self._body_text = self.body_bytes.decode("utf-8", errors="replace")
        return self._body_text

    @property
    def json(self) -> Any:
        if self._json_data is None:
            try:
                self._json_data = json.loads(self.text)
            except Exception as e:
                raise ValueError(f"Failed to parse JSON response (body={self.text[:200]!r}): {e}")
        return self._json_data


class HttpClient:
    """HTTP client communicating with ESP32-S3 Web server."""
    def __init__(self, host: str = "127.0.0.1", port: int = 80, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method: str, path: str, body: Optional[Union[str, bytes, dict]] = None,
                headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Send an HTTP request and return HttpResponse."""
        if headers is None:
            headers = {}

        payload: Optional[bytes] = None
        if isinstance(body, dict):
            payload = json.dumps(body).encode("utf-8")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            payload = body.encode("utf-8")
        elif isinstance(body, bytes):
            payload = body

        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=payload, headers=headers)
            res = conn.getresponse()
            res_headers = dict(res.getheaders())
            res_body = res.read()
            return HttpResponse(res.status, res_headers, res_body)
        finally:
            conn.close()

    def get_dashboard(self) -> HttpResponse:
        """Fetch root SPA dashboard page."""
        return self.request("GET", "/")

    def get_stats(self) -> HttpResponse:
        """Fetch system and query statistics."""
        return self.request("GET", "/api/stats")

    def get_queries(self) -> HttpResponse:
        """Fetch recent query logs."""
        return self.request("GET", "/api/queries")

    def get_whitelist(self) -> HttpResponse:
        """Fetch current whitelist entries."""
        return self.request("GET", "/api/whitelist")

    def add_whitelist(self, domain: str) -> HttpResponse:
        """Add a domain to custom whitelist."""
        return self.request("POST", "/api/whitelist", body={"domain": domain})

    def delete_whitelist(self, domain: str) -> HttpResponse:
        """Remove a domain from custom whitelist."""
        return self.request("DELETE", f"/api/whitelist?domain={urllib.parse.quote(domain)}",
                            body={"domain": domain})

    def get_blacklist(self) -> HttpResponse:
        """Fetch current custom blacklist entries."""
        return self.request("GET", "/api/blacklist")

    def add_blacklist(self, domain: str) -> HttpResponse:
        """Add a domain to custom blacklist."""
        return self.request("POST", "/api/blacklist", body={"domain": domain})

    def delete_blacklist(self, domain: str) -> HttpResponse:
        """Remove a domain from custom blacklist."""
        return self.request("DELETE", f"/api/blacklist?domain={urllib.parse.quote(domain)}",
                            body={"domain": domain})
