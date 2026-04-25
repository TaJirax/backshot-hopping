"""
HopShot MTU Prober — KCP-style path MTU discovery.

KCP avoids IP fragmentation by probing the path MTU before sending.
Fragmented UDP packets are easy to throttle, reassemble-and-inspect,
or simply drop — especially across port hops where each hop looks like
a new flow to the ISP.

This module implements binary-search MTU probing:
  1. Send probe packets of increasing size.
  2. Server echoes back a MTU_REPLY with the received size.
  3. Client records the largest size that made it through.
  4. MTU is cached per (server_ip, port) pair with a TTL.

The discovered MTU is then used to size FEC shards so no shard exceeds
the path MTU, preventing IP fragmentation entirely.

Usage:
    prober = MTUProber(seed=b"my-seed", obfs=False)
    mtu    = prober.probe(server_ip, server_port)   # blocks ~2s
    # mtu is the safe max payload size (already subtracts UDP + IP overhead)
"""

import logging
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

import common

log = logging.getLogger("hopshot.mtu")

# ─── Constants ────────────────────────────────────────────────────────────────

UDP_IP_OVERHEAD  = 28    # 20 IP + 8 UDP
MTU_PROBE_SIZES  = [576, 800, 1000, 1100, 1200, 1280, 1350, 1400, 1450, 1480, 1500]
MTU_CACHE_TTL    = 600   # 10 minutes
MTU_PROBE_TIMEOUT = 0.5  # seconds per size
MTU_DEFAULT      = 1200  # conservative fallback


class MTUProber:
    """
    Discover path MTU via binary-search probe packets.

    Thread-safe. Results are cached per (ip, port) for MTU_CACHE_TTL seconds.
    """

    def __init__(self, seed: bytes, obfs: bool = False):
        self._seed  = seed
        self._obfs  = obfs
        self._cache: Dict[Tuple[str, int], Tuple[int, float]] = {}
        self._lock  = threading.Lock()

    def probe(self, server_ip: str, server_port: int,
              timeout: float = MTU_PROBE_TIMEOUT) -> int:
        """
        Discover the path MTU to (server_ip, server_port).
        Returns safe payload size = MTU - UDP/IP overhead.
        Blocks for at most len(MTU_PROBE_SIZES) * timeout seconds.
        """
        key = (server_ip, server_port)
        with self._lock:
            entry = self._cache.get(key)
            if entry and time.monotonic() < entry[1]:
                log.debug(f"[MTU] cache hit {key}: {entry[0]}")
                return entry[0]

        log.info(f"[MTU] probing {server_ip}:{server_port} ...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((server_ip, server_port))
            sock.settimeout(timeout)
        except Exception as e:
            log.warning(f"[MTU] socket error: {e} — using default {MTU_DEFAULT}")
            return MTU_DEFAULT - UDP_IP_OVERHEAD

        received_sizes: set = set()
        stop_ev = threading.Event()

        def reader():
            buf = bytearray(2048)
            while not stop_ev.is_set():
                try:
                    n = sock.recv_into(buf)
                    pkt = bytes(buf[:n])
                    if self._obfs:
                        pkt = common.salamander(pkt, self._seed)
                    hdr, payload = common.unpack_header(pkt)
                    if hdr and hdr["type"] == common.TYPE_MTU_REPLY and len(payload) >= 2:
                        echoed_size = struct.unpack_from("!H", payload)[0]
                        received_sizes.add(echoed_size)
                except socket.timeout:
                    pass
                except Exception:
                    break

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        # Send probes from small to large
        for probe_size in MTU_PROBE_SIZES:
            pkt = common.build_mtu_probe(probe_size, probe_size)
            if self._obfs:
                pkt = common.salamander(pkt, self._seed)
            # Pad to exact probe_size if packet is smaller
            if len(pkt) < probe_size:
                pkt = pkt + bytes(probe_size - len(pkt))
            try:
                sock.send(pkt[:probe_size])
            except Exception as e:
                log.debug(f"[MTU] send {probe_size}: {e}")
            time.sleep(timeout / len(MTU_PROBE_SIZES))

        time.sleep(timeout)
        stop_ev.set()
        sock.close()
        t.join(timeout=0.5)

        if received_sizes:
            best_mtu = max(received_sizes)
        else:
            log.warning("[MTU] no replies — using conservative default")
            best_mtu = MTU_DEFAULT

        # Safe payload = MTU - IP - UDP headers
        safe_payload = best_mtu - UDP_IP_OVERHEAD
        log.info(f"[MTU] discovered: {best_mtu} bytes  safe_payload={safe_payload}")

        with self._lock:
            self._cache[key] = (safe_payload, time.monotonic() + MTU_CACHE_TTL)

        return safe_payload

    def invalidate(self, server_ip: str, server_port: int):
        """Force re-probe on next call (e.g. after a path change)."""
        with self._lock:
            self._cache.pop((server_ip, server_port), None)

    def get_cached(self, server_ip: str, server_port: int) -> Optional[int]:
        """Return cached MTU without probing, or None if not cached."""
        with self._lock:
            entry = self._cache.get((server_ip, server_port))
            if entry and time.monotonic() < entry[1]:
                return entry[0]
        return None
