"""
Brutal Congestion Control — inspired by Hysteria2.

Unlike TCP which halves send rate on any loss, Brutal CC:
  - Starts at a base rate and ramps up aggressively
  - Server measures actual recv rate + packet loss each 200ms
  - Server sends BWFeedback to client
  - Client adjusts rate: ramp up on low loss, ramp down on high loss
  - Both raw UDP and QUIC stacks share ONE Brutal CC instance

Sender side: rate pacing (Sender class)
Receiver/server side: measurement + feedback generation (Receiver class)
"""

import time
import threading

# ─── Tuning constants ─────────────────────────────────────────────────────────

INITIAL_RATE_KBPS  = 1_000.0
MAX_RATE_KBPS      = 500_000.0
MIN_RATE_KBPS      = 64.0
RAMP_UP_FACTOR     = 1.25
RAMP_DOWN_FACTOR   = 0.85
FEEDBACK_INTERVAL  = 0.200   # seconds
GOOD_LOSS_THRESH   = 2.0     # % — below this → ramp up
BAD_LOSS_THRESH    = 15.0    # % — above this → ramp down

# ─── Sender ───────────────────────────────────────────────────────────────────

class BrutalSender:
    """
    Sits on the client side. Call pace(sz) before sending each packet.
    Call on_feedback() when a BWFeedback packet arrives from the server.
    Both raw UDP and QUIC paths share this single instance.

    User-declared bandwidth (Hysteria2-style):
        Pass declared_up_kbps > 0 to override the initial rate and set an
        upper ceiling.  The CC still ramps/backs off dynamically, but will
        never exceed what the user declared (their uplink capacity).
        This prevents the "spray and pray" behaviour that triggers ISP QoS.
    """

    def __init__(self, declared_up_kbps: float = 0):
        self._lock         = threading.Lock()
        self._declared     = float(declared_up_kbps)   # 0 = auto
        init_rate          = declared_up_kbps if declared_up_kbps > 0 else INITIAL_RATE_KBPS
        self._rate         = min(init_rate, MAX_RATE_KBPS)
        self._ceil         = declared_up_kbps if declared_up_kbps > 0 else MAX_RATE_KBPS
        self._rtt_ms       = 0.0
        self._last_fb      = 0.0
        self._bytes_sent   = 0

    def on_feedback(self, recv_rate_kbps: int, rtt_ms: int, loss_pct: int):
        """Called when a BW_FEEDBACK packet arrives from server."""
        with self._lock:
            self._last_fb = time.monotonic()
            self._rtt_ms  = float(rtt_ms)
            loss          = float(loss_pct)
            recv          = float(recv_rate_kbps)

            if loss < GOOD_LOSS_THRESH:
                # Excellent — push harder
                self._rate *= RAMP_UP_FACTOR
                if recv > 0 and recv * 1.1 > self._rate:
                    self._rate = recv * 1.2
            elif loss > BAD_LOSS_THRESH:
                # Too much loss — back off slightly
                self._rate *= RAMP_DOWN_FACTOR
                if recv > 0:
                    self._rate = min(self._rate, recv * 0.9)
            else:
                # Moderate — hold and track recv
                if recv > 0:
                    self._rate = self._rate * 0.7 + recv * 0.3

            self._rate = max(MIN_RATE_KBPS, min(self._ceil, self._rate))

    def pace(self, sz: int):
        """Sleep to honour current send rate before transmitting sz bytes."""
        with self._lock:
            rate = self._rate
        if rate <= 0:
            return
        # delay = bits / (kbps * 1000 bit/s)
        delay = (sz * 8) / (rate * 1000.0)
        delay = min(delay, 0.1)     # cap at 100 ms per packet
        if delay > 0.001:
            time.sleep(delay)

    def record_sent(self, sz: int):
        with self._lock:
            self._bytes_sent += sz

    @property
    def rate_kbps(self) -> float:
        with self._lock:
            return self._rate

    @property
    def rtt_ms(self) -> float:
        with self._lock:
            return self._rtt_ms

    def stats(self):
        with self._lock:
            return self._rate, self._rtt_ms


# ─── Receiver ─────────────────────────────────────────────────────────────────

class BrutalReceiver:
    """
    Sits on the server side. Call on_packet() for each arriving data packet.
    Call feedback() every FEEDBACK_INTERVAL seconds to get the BWFeedback tuple.
    """

    def __init__(self, declared_down_kbps: float = 0):
        self._lock       = threading.Lock()
        self._bytes      = 0
        self._win_start  = time.monotonic()
        self._seen_seqs  = set()
        self._min_seq    = None
        self._max_seq    = None
        self._last_rtt   = 0.0
        self._declared   = float(declared_down_kbps)
        self._ceil       = float(declared_down_kbps) if declared_down_kbps > 0 else 0.0

    def on_packet(self, seq: int, sz: int, rtt_ms: float = 0.0):
        with self._lock:
            self._bytes += sz
            if rtt_ms > 0:
                self._last_rtt = rtt_ms
            self._seen_seqs.add(seq)
            if self._min_seq is None:
                self._min_seq = seq
                self._max_seq = seq
            else:
                if seq > self._max_seq:
                    self._max_seq = seq

    def feedback(self):
        """
        Returns (recv_rate_kbps, rtt_ms, loss_pct) and resets the window.
        Returns None if the window is too short to be meaningful.
        """
        with self._lock:
            elapsed = time.monotonic() - self._win_start
            if elapsed < 0.05:
                return None

            recv_kbps = int((self._bytes * 8) / (elapsed * 1000.0))
            if self._ceil > 0:
                recv_kbps = int(min(recv_kbps, self._ceil))

            # Loss estimate from seq gaps
            loss_pct = 0
            if self._min_seq is not None and self._max_seq is not None:
                span = self._max_seq - self._min_seq + 1
                seen = len(self._seen_seqs)
                if span > 1 and seen < span:
                    loss_pct = int(100.0 * (span - seen) / span)
                    loss_pct = min(loss_pct, 100)

            rtt_ms = int(self._last_rtt)

            # Reset window
            self._bytes     = 0
            self._win_start = time.monotonic()
            self._seen_seqs = set()
            self._min_seq   = None
            self._max_seq   = None

            return recv_kbps, rtt_ms, loss_pct
