"""
Pure-Python RFC 1035 DNS UDP Client for ESP32-S3 Ad Blocker E2E Testing.
Uses only Python standard library (socket, struct, random, time).
"""

import socket
import struct
import random
import time
from typing import List, Tuple, Optional, Dict, Any


class DnsRecord:
    """Represents a parsed DNS Resource Record."""
    def __init__(self, name: str, rtype: int, rclass: int, ttl: int, rdata: bytes, ip_str: Optional[str] = None):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        self.ip_str = ip_str

    def __repr__(self):
        return f"DnsRecord(name={self.name}, type={self.rtype}, ttl={self.ttl}, ip={self.ip_str})"


class DnsResponse:
    """Represents a parsed DNS Response packet."""
    def __init__(self):
        self.tx_id: int = 0
        self.flags: int = 0
        self.qr: int = 0
        self.opcode: int = 0
        self.aa: int = 0
        self.tc: int = 0
        self.rd: int = 0
        self.ra: int = 0
        self.rcode: int = 0
        self.qdcount: int = 0
        self.ancount: int = 0
        self.nscount: int = 0
        self.arcount: int = 0
        self.questions: List[Tuple[str, int, int]] = []
        self.answers: List[DnsRecord] = []
        self.raw_data: bytes = b""
        self.latency_ms: float = 0.0

    @property
    def is_sinkholed(self) -> bool:
        """Returns True if any answer resolves to 0.0.0.0."""
        return any(rec.ip_str == "0.0.0.0" for rec in self.answers)

    @property
    def primary_ip(self) -> Optional[str]:
        """Returns the IPv4 string of the first A record, if present."""
        for rec in self.answers:
            if rec.rtype == 1 and rec.ip_str:
                return rec.ip_str
        return None

    @property
    def primary_ttl(self) -> Optional[int]:
        """Returns TTL of the first answer, if present."""
        if self.answers:
            return self.answers[0].ttl
        return None


class DnsClient:
    """UDP DNS client to send and parse RFC 1035 packets."""
    def __init__(self, host: str = "127.0.0.1", port: int = 53, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    @staticmethod
    def encode_qname(domain: str) -> bytes:
        """Encode domain name into RFC 1035 wire format labels."""
        domain = domain.strip(".")
        if not domain:
            return b"\x00"
        parts = domain.split(".")
        encoded = bytearray()
        for part in parts:
            part_bytes = part.encode("ascii", errors="replace")
            encoded.append(len(part_bytes))
            encoded.extend(part_bytes)
        encoded.append(0)
        return bytes(encoded)

    @staticmethod
    def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
        """Decode a domain name from DNS packet starting at offset, handling pointers."""
        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 10
        jumps = 0

        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer
                jumps += 1
                if jumps > max_jumps:
                    # Pointer loop prevention
                    break
            else:
                offset += 1
                label = data[offset:offset+length].decode("ascii", errors="replace")
                labels.append(label)
                offset += length

        domain_str = ".".join(labels)
        final_offset = original_offset if jumped else offset
        return domain_str, final_offset

    def build_query_packet(self, domain: str, qtype: int = 1, qclass: int = 1, tx_id: Optional[int] = None) -> bytes:
        """Construct raw RFC 1035 UDP query packet."""
        if tx_id is None:
            tx_id = random.randint(1, 65535)

        flags = 0x0100  # QR=0, RD=1 (Recursion Desired)
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0

        header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
        question = self.encode_qname(domain) + struct.pack("!HH", qtype, qclass)
        return header + question

    def parse_response_packet(self, data: bytes) -> DnsResponse:
        """Parse raw DNS response byte array into DnsResponse object."""
        resp = DnsResponse()
        resp.raw_data = data
        if len(data) < 12:
            return resp

        resp.tx_id, flags, resp.qdcount, resp.ancount, resp.nscount, resp.arcount = struct.unpack("!HHHHHH", data[:12])
        resp.flags = flags
        resp.qr = (flags >> 15) & 1
        resp.opcode = (flags >> 11) & 0xF
        resp.aa = (flags >> 10) & 1
        resp.tc = (flags >> 9) & 1
        resp.rd = (flags >> 8) & 1
        resp.ra = (flags >> 7) & 1
        resp.rcode = flags & 0xF

        offset = 12
        # Parse Questions
        for _ in range(resp.qdcount):
            if offset >= len(data):
                break
            qname, offset = self.decode_name(data, offset)
            if offset + 4 <= len(data):
                qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
                offset += 4
                resp.questions.append((qname, qtype, qclass))

        # Parse Answers
        for _ in range(resp.ancount):
            if offset >= len(data):
                break
            aname, offset = self.decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlength]
            offset += rdlength

            ip_str = None
            if rtype == 1 and rdlength == 4:
                ip_str = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlength == 16:
                try:
                    ip_str = socket.inet_ntop(socket.AF_INET6, rdata)
                except Exception:
                    pass

            record = DnsRecord(name=aname, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata, ip_str=ip_str)
            resp.answers.append(record)

        return resp

    def query(self, domain: str, qtype: int = 1, qclass: int = 1, tx_id: Optional[int] = None) -> DnsResponse:
        """Send DNS query over UDP and return parsed DnsResponse."""
        if tx_id is None:
            tx_id = random.randint(1, 65535)

        packet = self.build_query_packet(domain, qtype=qtype, qclass=qclass, tx_id=tx_id)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        t_start = time.perf_counter()
        try:
            sock.sendto(packet, (self.host, self.port))
            data, _ = sock.recvfrom(2048)
            latency = (time.perf_counter() - t_start) * 1000.0
            resp = self.parse_response_packet(data)
            resp.latency_ms = latency
            return resp
        finally:
            sock.close()

    def send_raw_packet(self, packet: bytes) -> Tuple[Optional[bytes], float]:
        """Send raw bytes over UDP and return response bytes and latency in ms."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        t_start = time.perf_counter()
        try:
            sock.sendto(packet, (self.host, self.port))
            data, _ = sock.recvfrom(2048)
            latency = (time.perf_counter() - t_start) * 1000.0
            return data, latency
        except socket.timeout:
            return None, (time.perf_counter() - t_start) * 1000.0
        finally:
            sock.close()
