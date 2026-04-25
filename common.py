"""
HopShot — common protocol definitions.
Shared between client and server.
"""

import hashlib
import hmac as _hmac
import random
import struct
import time

# ─── Magic & packet types ─────────────────────────────────────────────────────

MAGIC = 0x4855

TYPE_PROBE       = 0x01
TYPE_PROBE_REPLY = 0x02
TYPE_DATA        = 0x03
TYPE_BW_FEEDBACK = 0x04
TYPE_BW_REPORT   = 0x05
TYPE_MTU_PROBE   = 0x06
TYPE_MTU_REPLY   = 0x07

TRANSPORT_RAW  = 0x00
TRANSPORT_QUIC = 0x01

MAX_PACKET  = 1400
HEADER_SIZE = 16

# ─── Loss thresholds → mode ───────────────────────────────────────────────────

MODE_NORMAL   = 0   # loss < 30%  | no hop       | burst x1
MODE_MODERATE = 1   # loss 30-60% | hop 3000 ms  | burst x2
MODE_HIGH     = 2   # loss 60-80% | hop 1500 ms  | burst x4
MODE_NUCLEAR  = 3   # loss > 80%  | hop 1000 ms  | burst x8

MODE_NAMES = {
    MODE_NORMAL:   "normal",
    MODE_MODERATE: "moderate",
    MODE_HIGH:     "high",
    MODE_NUCLEAR:  "NUCLEAR",
}

MODE_PARAMS = {
    # mode: (hop_interval_ms, burst_multiplier)
    MODE_NORMAL:   (0,    1),
    MODE_MODERATE: (3000, 2),
    MODE_HIGH:     (1500, 4),
    MODE_NUCLEAR:  (1000, 8),
}

# Pre-emptive hop: hop this many ms BEFORE the throttle window expires.
# Your logs show ISP throttles after ~2-3s on a single flow.
# We hop at 800ms by default so we never stay long enough to get classified.
PREEMPTIVE_HOP_MS = 800

# ─── Randomized Hop Interval (Hysteria2-style) ────────────────────────────────
# Instead of a fixed interval, each hop slot has a ±JITTER_RATIO random variance.
# e.g. 1000ms ± 30% → next hop is anywhere from 700ms to 1300ms.
# This makes flow-fingerprinting by interval analysis impossible.
HOP_JITTER_RATIO = 0.30   # 30% variance — matches Hysteria2 changelog default

def randomized_hop_interval(base_ms: int) -> int:
    """
    Return a randomized hop interval: base_ms ± HOP_JITTER_RATIO.
    Each call produces a different value so the hop schedule is unpredictable.
    """
    if base_ms <= 0:
        return 0
    delta = int(base_ms * HOP_JITTER_RATIO)
    return base_ms + random.randint(-delta, delta)

def time_slot_randomized(base_ms: int, seed: bytes, seq: int) -> int:
    """
    Compute a time slot using a randomized interval derived deterministically
    from (seed, seq). Both client and server agree on the same jitter because
    they share the seed and the wall-clock slot boundary — no out-of-band
    signaling needed.
    """
    if base_ms <= 0:
        return 0
    now_ms = int(time.time() * 1000)
    base_slot = now_ms // base_ms
    # Deterministic jitter from seed+seq so both sides agree on the slot.
    mac = _hmac.new(seed, struct.pack("!qI", base_slot, seq),
                    hashlib.sha256).digest()
    jitter_val = struct.unpack_from("!I", mac)[0]
    delta      = int(base_ms * HOP_JITTER_RATIO)
    jitter_ms  = (jitter_val % (2 * delta + 1)) - delta
    effective  = max(100, base_ms + jitter_ms)
    return now_ms // effective

# Reactive probe: if burst-test loss exceeds this before sending, hop immediately
REACTIVE_LOSS_THRESHOLD = 30.0

def classify_loss(loss_pct: float) -> int:
    if loss_pct < 30:   return MODE_NORMAL
    elif loss_pct < 60: return MODE_MODERATE
    elif loss_pct < 80: return MODE_HIGH
    else:               return MODE_NUCLEAR

# ─── Packet header (16 bytes) ─────────────────────────────────────────────────
# magic:2  type:1  transport:1  seq:4
# shard_idx:1  total_shards:1  session_id:2  flags:1  reserved:3

HDR_FMT = "!HBBIBBHBxxx"
assert struct.calcsize(HDR_FMT) == HEADER_SIZE

def pack_header(pkt_type, seq, shard_idx=0, total_shards=1,
                session_id=0, transport=TRANSPORT_RAW, flags=0):
    return struct.pack(HDR_FMT, MAGIC, pkt_type, transport, seq,
                       shard_idx, total_shards, session_id, flags)

def unpack_header(data: bytes):
    if len(data) < HEADER_SIZE:
        return None, None
    magic, pkt_type, transport, seq, shard_idx, total_shards, session_id, flags = \
        struct.unpack_from(HDR_FMT, data)
    if magic != MAGIC:
        return None, None
    return {
        "type": pkt_type, "transport": transport, "seq": seq,
        "shard_idx": shard_idx, "total_shards": total_shards,
        "session_id": session_id, "flags": flags,
    }, data[HEADER_SIZE:]

# ─── BW feedback payload ──────────────────────────────────────────────────────

BW_FMT  = "!IHBx"
BW_SIZE = struct.calcsize(BW_FMT)

def pack_bw_feedback(recv_rate_kbps, rtt_ms, loss_pct):
    return struct.pack(BW_FMT, recv_rate_kbps, rtt_ms, loss_pct)

def unpack_bw_feedback(data):
    if len(data) < BW_SIZE:
        return None
    return struct.unpack_from(BW_FMT, data)

# ─── Deterministic port hopping ───────────────────────────────────────────────

def deterministic_port(seed: bytes, slot: int, port_min: int, port_max: int) -> int:
    spread = port_max - port_min
    if spread <= 0:
        return port_min
    mac = _hmac.new(seed, struct.pack("!q", slot), hashlib.sha256).digest()
    val = struct.unpack_from("!Q", mac)[0]
    return port_min + (val % spread)

def time_slot(interval_ms: int) -> int:
    if interval_ms <= 0:
        return 0
    return int(time.time() * 1000) // interval_ms

# ─── Packet size jitter ───────────────────────────────────────────────────────

def add_jitter_padding(data: bytes, max_jitter: int = 64) -> bytes:
    """
    Append a random-length random-content padding block.
    Format: [original_data][padding][1-byte: pad_len]
    Server strips it before FEC decode.
    max_jitter=0 disables padding.
    """
    if max_jitter <= 0:
        return data
    pad_len = random.randint(0, max_jitter)
    padding = bytes(random.getrandbits(8) for _ in range(pad_len))
    return data + padding + bytes([pad_len])

def strip_jitter_padding(data: bytes, max_jitter: int = 64) -> bytes:
    """Strip padding added by add_jitter_padding."""
    if max_jitter <= 0 or len(data) < 1:
        return data
    pad_len = data[-1]
    if pad_len > max_jitter or len(data) < pad_len + 1:
        return data   # not padded or corrupt — return as-is
    return data[:-(pad_len + 1)]

# ─── MTU Probing (KCP-style) ──────────────────────────────────────────────────
# Discover the real path MTU by sending progressively larger probe packets.
# Avoids IP fragmentation, which destroys port-hop stealth.
# Server echoes back the MTU_PROBE with the same payload size; client
# records the largest size that got through.

MTU_PROBE_MIN   = 576     # minimum safe MTU (RFC 791)
MTU_PROBE_MAX   = 1500    # standard Ethernet MTU
MTU_PROBE_STEP  = 32      # probe step size in bytes
MTU_PROBE_SIZES = list(range(MTU_PROBE_MIN, MTU_PROBE_MAX + 1, MTU_PROBE_STEP)) + [MTU_PROBE_MAX]

def build_mtu_probe(seq: int, payload_size: int) -> bytes:
    """Build an MTU probe packet of exactly `payload_size` bytes."""
    hdr     = pack_header(TYPE_MTU_PROBE, seq=seq)
    # Fill remainder with pattern bytes so the size is exact
    pad_sz  = max(0, payload_size - HEADER_SIZE - 2)
    payload = struct.pack("!H", payload_size) + bytes(pad_sz)
    return hdr + payload

# ─── Salamander obfuscation ───────────────────────────────────────────────────

def salamander(data: bytes, key: bytes) -> bytes:
    out    = bytearray(len(data))
    digest = hashlib.sha256(key).digest()
    for i, b in enumerate(data):
        out[i] = b ^ digest[i % 32]
        if i % 32 == 31:
            digest = hashlib.sha256(digest).digest()
    return bytes(out)
