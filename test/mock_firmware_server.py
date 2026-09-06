"""
High-Fidelity Mock Firmware Server for ESP32-S3 DNS Ad Blocker.
Emulates Core 1 (UDP Port 53 DNS Engine) and Core 0 (HTTP Port 80 Web Dashboard & REST APIs)
in pure standard library Python.
"""

import socket
import struct
import threading
import time
import json
import os
import urllib.parse
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Set, Dict, Any, List, Optional, Tuple


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockFirmwareServer:
    """
    Dual-Core ESP32-S3 Firmware Emulator.
    - Core 1: UDP DNS server with RFC 1035 wire parser, 0.0.0.0 sinkholing, upstream forwarding.
    - Core 0: HTTP server with dark-mode SPA dashboard, stats, ring buffer, whitelist/blacklist CRUD.
    """
    def __init__(self, host: str = "127.0.0.1", dns_port: int = 0, http_port: int = 0,
                 blocklist_path: Optional[str] = None):
        self.host = host
        self.requested_dns_port = dns_port
        self.requested_http_port = http_port
        self.dns_port = dns_port
        self.http_port = http_port

        self.blocklist_path = blocklist_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ads-domains.txt"
        )

        self.lock = threading.Lock()
        self.blocklist: Set[str] = set()
        self.custom_whitelist: Set[str] = set()
        self.custom_blacklist: Set[str] = set()

        # 1,000 entry PSRAM Ring Buffer
        self.ring_buffer = deque(maxlen=1000)

        # Atomic statistics
        self.start_time = time.time()
        self.total_queries = 0
        self.blocked_queries = 0
        self.simulated_free_heap = 245760  # ~240 KB internal SRAM
        self.simulated_free_psram = 7340032  # ~7 MB octal PSRAM

        self.running = False
        self.dns_sock: Optional[socket.socket] = None
        self.dns_thread: Optional[threading.Thread] = None
        self.http_server: Optional[ThreadedHTTPServer] = None
        self.http_thread: Optional[threading.Thread] = None

        self._load_blocklist()

    def _load_blocklist(self):
        """Load blocklist domains from file into memory set."""
        if os.path.exists(self.blocklist_path):
            with open(self.blocklist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.blocklist.add(line)
        else:
            # Fallback default ad domains
            self.blocklist.update([
                "2mdn.net", "3lift.com", "a-ads.com", "doubleclick.net",
                "adservice.google.com", "google-analytics.com", "pagead2.googlesyndication.com"
            ])

        # Also load user-provided ad-domains2.0
        v2_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ad-domains2.0.txt")
        if os.path.exists(v2_path):
            with open(v2_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.blocklist.add(line)

    def is_domain_blocked(self, domain: str) -> bool:
        """
        Progressive Subdomain Matcher:
        1. Check whitelist override (e.g. safe.2mdn.net or 2mdn.net).
        2. Check custom blacklist.
        3. Check system blocklist.
        """
        domain = domain.lower().strip(".")
        if not domain:
            return False

        labels = domain.split(".")

        with self.lock:
            # Whitelist override check (most specific to least specific)
            for i in range(len(labels) - 1):
                candidate = ".".join(labels[i:])
                if candidate in self.custom_whitelist:
                    return False

            # Custom blacklist check
            for i in range(len(labels) - 1):
                candidate = ".".join(labels[i:])
                if candidate in self.custom_blacklist:
                    return True

            # Blocklist check
            for i in range(len(labels) - 1):
                candidate = ".".join(labels[i:])
                if candidate in self.blocklist:
                    return True

            # Arrogant Heuristic rules
            if self._match_heuristics(domain):
                return True

        return False

    def _match_heuristics(self, domain: str) -> bool:
        ad_prefixes = [
            "pagead2.", "adservice.", "adservices.", "adserver.", "adservers.",
            "telemetry.", "analytics.", "criteo.", "taboola.", "outbrain.",
            "doubleclick.", "googletagservices.", "google-analytics.", "adnxs.",
            "pubmatic.", "rubiconproject.", "casalemedia.", "scorecardresearch.",
            "quantserve.", "app-measurement.", "mobile-analytics.", "adsystem."
        ]
        for pfx in ad_prefixes:
            if domain.startswith(pfx) or ("." + pfx) in domain:
                return True
        return False

    def record_query(self, domain: str, client_ip: str, blocked: bool, latency_ms: int):
        """Append record to 1,000 entry circular buffer and update counters."""
        with self.lock:
            self.total_queries += 1
            if blocked:
                self.blocked_queries += 1

            self.ring_buffer.append({
                "domain": domain,
                "client_ip": client_ip,
                "blocked": blocked,
                "timestamp": int(time.time()),
                "latency_ms": latency_ms
            })

    # ------------------ Core 1: DNS Server ------------------
    def _dns_worker(self):
        self.dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dns_sock.bind((self.host, self.requested_dns_port))
        self.dns_port = self.dns_sock.getsockname()[1]
        self.dns_sock.settimeout(0.5)

        while self.running:
            try:
                data, addr = self.dns_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception:
                break

            try:
                response = self._handle_dns_packet(data, addr[0])
                if response:
                    self.dns_sock.sendto(response, addr)
            except Exception:
                pass

    def _decode_qname(self, data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                # Compression pointer in question is rare, skip
                offset += 2
                break
            else:
                offset += 1
                label = data[offset:offset+length].decode("ascii", errors="replace")
                labels.append(label)
                offset += length
        return ".".join(labels), offset

    def _handle_dns_packet(self, data: bytes, client_ip: str) -> Optional[bytes]:
        t0 = time.perf_counter()
        if len(data) < 12:
            return None

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        if qdcount < 1:
            # Return FORMERR
            err_flags = 0x8181  # QR=1, RCODE=1 (FORMERR)
            return struct.pack("!HHHHHH", tx_id, err_flags, 0, 0, 0, 0)

        domain, offset = self._decode_qname(data, 12)
        if offset + 4 > len(data):
            return None

        qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
        question_section = data[12:offset+4]

        blocked = self.is_domain_blocked(domain)

        if blocked and qtype == 1:  # Type A (IPv4)
            # Synthesize 0.0.0.0 A-record answer with TTL=300
            resp_flags = 0x8580  # QR=1, AA=1, RD=1, RA=1, NOERROR
            header = struct.pack("!HHHHHH", tx_id, resp_flags, 1, 1, 0, 0)
            # Answer: Name pointer to QNAME (0xC00C), Type A (1), Class IN (1), TTL 300, Rdlength 4, IP 0.0.0.0
            answer = struct.pack("!HHHIHBBBB", 0xC00C, 1, 1, 300, 4, 0, 0, 0, 0)
            latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
            self.record_query(domain, client_ip, True, latency_ms)
            return header + question_section + answer

        elif blocked and qtype == 28:  # Type AAAA (IPv6)
            # Empty NOERROR response for blocked AAAA
            resp_flags = 0x8580
            header = struct.pack("!HHHHHH", tx_id, resp_flags, 1, 0, 0, 0)
            latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
            self.record_query(domain, client_ip, True, latency_ms)
            return header + question_section

        else:
            # Legitimate query -> Forward to upstream resolver or simulate upstream resolution
            resolved_ip = self._resolve_upstream(domain)
            latency_ms = max(2, int((time.perf_counter() - t0) * 1000))
            self.record_query(domain, client_ip, False, latency_ms)

            if resolved_ip and qtype == 1:
                resp_flags = 0x8180  # QR=1, RD=1, RA=1, NOERROR
                header = struct.pack("!HHHHHH", tx_id, resp_flags, 1, 1, 0, 0)
                ip_bytes = [int(p) for p in resolved_ip.split(".")]
                answer = struct.pack("!HHHIHBBBB", 0xC00C, 1, 1, 60, 4,
                                     ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
                return header + question_section + answer
            elif resolved_ip:
                # Valid domain queried for non-A type (e.g. MX, TXT) -> return NOERROR with 0 answers
                resp_flags = 0x8180
                header = struct.pack("!HHHHHH", tx_id, resp_flags, 1, 0, 0, 0)
                return header + question_section
            else:
                # Upstream NXDOMAIN or empty response
                resp_flags = 0x8183  # NXDOMAIN
                header = struct.pack("!HHHHHH", tx_id, resp_flags, 1, 0, 0, 0)
                return header + question_section

    def _resolve_upstream(self, domain: str) -> Optional[str]:
        # Fast deterministic resolution for test reproducibility
        known = {
            "google.com": "142.250.190.46",
            "github.com": "140.82.121.4",
            "cloudflare.com": "104.16.132.229",
            "wikipedia.org": "198.35.26.96",
            "example.com": "93.184.216.34"
        }
        if domain.lower() in known:
            return known[domain.lower()]

        # Try host system getaddrinfo
        try:
            addrinfo = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
            if addrinfo:
                return addrinfo[0][4][0]
        except Exception:
            pass

        return "192.0.2.1"  # TEST-NET-1 deterministic fallback

    # ------------------ Core 0: HTTP Server ------------------
    def _create_http_handler(server_instance):
        class HttpHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress console log spam

            def _send_json(self, status: int, data: Any):
                body = json.dumps(data).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> Dict[str, Any]:
                content_len = int(self.headers.get("Content-Length", 0))
                if content_len > 0:
                    body = self.rfile.read(content_len).decode("utf-8", errors="replace")
                    return json.loads(body)
                return {}

            def do_HEAD(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", "364")
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path

                if path == "/":
                    html = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>ESP32-S3 AdBlocker Dashboard</title></head>
<body style="background:#121212;color:#fff;">
  <h1>ESP32-S3 AdBlocker</h1>
  <div>Total Queries: <span id="total-queries">0</span></div>
  <div>Blocked Queries: <span id="blocked-queries">0</span></div>
  <table id="query-log"><tbody></tbody></table>
  <form id="whitelist-form"><input id="wl-input"></form>
  <form id="blacklist-form"><input id="bl-input"></form>
</body></html>"""
                    body = html.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                elif path == "/api/stats":
                    with server_instance.lock:
                        tot = server_instance.total_queries
                        blk = server_instance.blocked_queries
                        pct = round((blk / tot * 100.0) if tot > 0 else 0.0, 2)
                        data = {
                            "total": tot,
                            "blocked": blk,
                            "percentage": pct,
                            "free_heap": server_instance.simulated_free_heap,
                            "free_psram": server_instance.simulated_free_psram,
                            "uptime": int(time.time() - server_instance.start_time),
                            "blocklist_count": len(server_instance.blocklist),
                            "whitelist_count": len(server_instance.custom_whitelist),
                            "blacklist_count": len(server_instance.custom_blacklist)
                        }
                    self._send_json(200, data)

                elif path == "/api/queries":
                    with server_instance.lock:
                        queries = list(server_instance.ring_buffer)
                    self._send_json(200, queries)

                elif path == "/api/whitelist":
                    with server_instance.lock:
                        wl = sorted(list(server_instance.custom_whitelist))
                    self._send_json(200, wl)

                elif path == "/api/blacklist":
                    with server_instance.lock:
                        bl = sorted(list(server_instance.custom_blacklist))
                    self._send_json(200, bl)

                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                try:
                    data = self._read_json()
                except Exception:
                    self._send_json(400, {"error": "Invalid JSON"})
                    return

                domain = data.get("domain", "").strip().lower()

                if path == "/api/whitelist":
                    if not domain:
                        self._send_json(400, {"error": "Domain required"})
                        return
                    with server_instance.lock:
                        server_instance.custom_whitelist.add(domain)
                    self._send_json(200, {"status": "ok", "domain": domain})

                elif path == "/api/blacklist":
                    if not domain:
                        self._send_json(400, {"error": "Domain required"})
                        return
                    with server_instance.lock:
                        server_instance.custom_blacklist.add(domain)
                    self._send_json(200, {"status": "ok", "domain": domain})

                else:
                    self.send_response(404)
                    self.end_headers()

            def do_DELETE(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                query_params = urllib.parse.parse_qs(parsed.query)

                domain = ""
                if "domain" in query_params:
                    domain = query_params["domain"][0].strip().lower()
                else:
                    try:
                        data = self._read_json()
                        domain = data.get("domain", "").strip().lower()
                    except Exception:
                        pass

                if path == "/api/whitelist":
                    with server_instance.lock:
                        server_instance.custom_whitelist.discard(domain)
                    self._send_json(200, {"status": "ok", "domain": domain})

                elif path == "/api/blacklist":
                    with server_instance.lock:
                        server_instance.custom_blacklist.discard(domain)
                    self._send_json(200, {"status": "ok", "domain": domain})

                else:
                    self.send_response(404)
                    self.end_headers()

        return HttpHandler

    # ------------------ Lifecycle ------------------
    def start(self):
        """Start both DNS (Core 1) and Web (Core 0) background servers."""
        self.running = True

        # Start DNS
        self.dns_thread = threading.Thread(target=self._dns_worker, daemon=True, name="Core1-DNSTask")
        self.dns_thread.start()

        # Wait for DNS socket bind
        while self.dns_port == 0:
            time.sleep(0.01)

        # Start HTTP
        handler_cls = self._create_http_handler()
        self.http_server = ThreadedHTTPServer((self.host, self.requested_http_port), handler_cls)
        self.http_port = self.http_server.server_port
        self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True, name="Core0-WebTask")
        self.http_thread.start()

    def stop(self):
        """Stop both servers and release sockets."""
        self.running = False
        if self.dns_sock:
            try:
                self.dns_sock.close()
            except Exception:
                pass
        if self.http_server:
            try:
                self.http_server.shutdown()
                self.http_server.server_close()
            except Exception:
                pass
        if self.dns_thread and self.dns_thread.is_alive():
            self.dns_thread.join(timeout=1.0)
        if self.http_thread and self.http_thread.is_alive():
            self.http_thread.join(timeout=1.0)
