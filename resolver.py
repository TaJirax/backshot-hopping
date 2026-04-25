"""
HopShot Resolver — DNS resolution with user-defined resolvers.

Supports:
  - Custom DNS resolvers (e.g. 1.1.1.1, 8.8.8.8, 9.9.9.9)
  - Multi-destination: resolve a hostname to multiple IPs
  - Resolver failover: try each resolver in order
  - Per-resolver loss probing: pick the best-performing destination
  - Result caching with TTL

Usage:
    r = Resolver(resolvers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    ips = r.resolve("myserver.example.com")
    best = r.best_destination(ips, port=10000, seed=b"s", obfs=False)
"""

import logging
import socket
import struct
import threading
import time
from typing import List, Optional

log = logging.getLogger("hopshot.resolver")

# ─── Default resolvers ────────────────────────────────────────────────────────

DEFAULT_RESOLVERS = [
    "1.1.1.1",    # Cloudflare
    "1.0.0.1",    # Cloudflare secondary
    "8.8.8.8",    # Google
    "8.8.4.4",    # Google secondary
    "9.9.9.9",    # Quad9
    "149.112.112.112",  # Quad9 secondary
]

DNS_PORT    = 53
DNS_TIMEOUT = 3.0
CACHE_TTL   = 300   # seconds


# ─── Minimal DNS query builder (stdlib only) ──────────────────────────────────

def _build_dns_query(hostname: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS A (qtype=1) or AAAA (qtype=28) query packet."""
    txid   = struct.pack("!H", 0x1234)
    flags  = struct.pack("!H", 0x0100)   # standard query, recursion desired
    qdcnt  = struct.pack("!H", 1)
    zeros  = struct.pack("!HHH", 0, 0, 0)

    labels = b""
    for part in hostname.rstrip(".").split("."):
        enc = part.encode()
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"

    question = labels + struct.pack("!HH", qtype, 1)   # qtype, class IN
    return txid + flags + qdcnt + zeros + question


def _parse_dns_response(data: bytes) -> List[str]:
    """Parse A records from a raw DNS response. Returns list of IP strings."""
    if len(data) < 12:
        return []

    ancount = struct.unpack_from("!H", data, 6)[0]
    if ancount == 0:
        return []

    # Skip header (12) + question section (find first \x00 after offset 12)
    pos = 12
    # Skip question labels
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:   # pointer
            pos += 2
            break
        pos += length + 1
    pos += 4   # skip qtype + qclass

    ips = []
    for _ in range(ancount):
        if pos >= len(data):
            break
        # Skip name (may be pointer or labels)
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                if data[pos] & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += data[pos] + 1
            else:
                pos += 1

        if pos + 10 > len(data):
            break

        rtype  = struct.unpack_from("!H", data, pos)[0]
        rdlen  = struct.unpack_from("!H", data, pos + 8)[0]
        rdata  = data[pos + 10: pos + 10 + rdlen]
        pos   += 10 + rdlen

        if rtype == 1 and rdlen == 4:   # A record
            ips.append(socket.inet_ntoa(rdata))

    return ips


def _query_resolver(hostname: str, resolver_ip: str, timeout: float = DNS_TIMEOUT) -> List[str]:
    """Send a DNS query to a specific resolver. Returns list of A record IPs."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        query = _build_dns_query(hostname, qtype=1)
        sock.sendto(query, (resolver_ip, DNS_PORT))
        resp, _ = sock.recvfrom(512)
        sock.close()
        return _parse_dns_response(resp)
    except Exception as e:
        log.debug(f"[resolver] {resolver_ip} query for {hostname}: {e}")
        return []


# ─── Resolver class ───────────────────────────────────────────────────────────

class Resolver:
    """
    DNS resolver with custom resolver list, caching, and multi-IP support.

    If the hostname is already an IP address, returns it directly.
    Tries each resolver in order until one responds.
    """

    def __init__(self, resolvers: Optional[List[str]] = None):
        self.resolvers = resolvers if resolvers else DEFAULT_RESOLVERS
        self._cache: dict = {}      # hostname → (ips, expires_at)
        self._lock = threading.Lock()
        log.info(f"[resolver] using: {', '.join(self.resolvers)}")

    def resolve(self, hostname: str) -> List[str]:
        """
        Resolve hostname → list of IPs.
        Returns [hostname] unchanged if it's already an IP.
        """
        # Already an IP?
        try:
            socket.inet_aton(hostname)
            return [hostname]
        except OSError:
            pass

        # Cache hit?
        with self._lock:
            entry = self._cache.get(hostname)
            if entry and time.monotonic() < entry[1]:
                log.debug(f"[resolver] cache hit: {hostname} → {entry[0]}")
                return entry[0]

        # Try each resolver
        for r in self.resolvers:
            ips = _query_resolver(hostname, r)
            if ips:
                log.info(f"[resolver] {hostname} → {ips} (via {r})")
                with self._lock:
                    self._cache[hostname] = (ips, time.monotonic() + CACHE_TTL)
                return ips

        # Fallback: system resolver
        log.warning(f"[resolver] custom resolvers failed for {hostname}, trying system")
        try:
            info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips  = list({i[4][0] for i in info})
            if ips:
                with self._lock:
                    self._cache[hostname] = (ips, time.monotonic() + CACHE_TTL)
                return ips
        except Exception as e:
            log.error(f"[resolver] system resolve failed: {e}")

        return []

    def resolve_all(self, hostnames: List[str]) -> List[str]:
        """Resolve a list of hostnames/IPs and return all unique IPs."""
        all_ips = []
        seen    = set()
        for h in hostnames:
            for ip in self.resolve(h):
                if ip not in seen:
                    seen.add(ip)
                    all_ips.append(ip)
        return all_ips

    def best_destination(
        self,
        ips:      List[str],
        port:     int,
        seed:     bytes,
        obfs:     bool,
        count:    int   = 8,
        timeout:  int   = 1000,
        verbose:  bool  = False,
    ) -> str:
        """
        Quick-probe each IP and return the one with lowest packet loss.
        Falls back to first IP if all fail.
        """
        if len(ips) == 1:
            return ips[0]

        # Import here to avoid circular import
        from client import probe_port

        best_ip   = ips[0]
        best_loss = 101.0

        results = {}
        lock    = threading.Lock()

        def probe_one(ip):
            r = probe_port(ip, port, count=count, timeout_ms=timeout,
                           seed=seed, obfs=obfs, verbose=verbose)
            with lock:
                results[ip] = r["loss_pct"]

        threads = [threading.Thread(target=probe_one, args=(ip,), daemon=True)
                   for ip in ips]
        for t in threads: t.start()
        for t in threads: t.join(timeout=timeout / 1000.0 + 0.5)

        for ip, loss in results.items():
            log.info(f"[resolver] {ip}:{port} loss={loss:.1f}%")
            if loss < best_loss:
                best_loss = loss
                best_ip   = ip

        log.info(f"[resolver] best destination: {best_ip} (loss={best_loss:.1f}%)")
        return best_ip

    def add_resolver(self, ip: str):
        if ip not in self.resolvers:
            self.resolvers.insert(0, ip)   # prepend — user-added get priority
            log.info(f"[resolver] added: {ip}")

    def remove_resolver(self, ip: str):
        if ip in self.resolvers:
            self.resolvers.remove(ip)
            log.info(f"[resolver] removed: {ip}")

    def list_resolvers(self) -> List[str]:
        return list(self.resolvers)

    def flush_cache(self):
        with self._lock:
            self._cache.clear()
        log.info("[resolver] cache flushed")
