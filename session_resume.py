"""
HopShot Session Resumption — 0-RTT inspired by TUIC.

TUIC's key insight: embed a session token in the very first data packet so
the server can recognise a returning client WITHOUT a handshake round-trip.
This eliminates the probe→handshake→send sequence on reconnect, which is
especially valuable after a port hop (the client appears on a new port and
the server must not require a fresh handshake).

Protocol:
  - On first connection the server issues a 32-byte session token
    (HMAC-SHA256 of (seed, session_id, timestamp_bucket)).
  - The token has a validity window (default 5 minutes).
  - On reconnect the client includes the token in a TYPE_RESUME packet.
  - The server verifies the HMAC and, if valid, skips the probe phase and
    immediately accepts data — 0-RTT.
  - The session token is rotated every TOKEN_WINDOW_SEC to bound replay risk.

Token format (32 bytes):
  [session_id: 2][timestamp_bucket: 4][hmac_truncated: 26]

Usage:
    # Server side
    mgr  = SessionTokenManager(seed=b"my-secret")
    tok  = mgr.issue(session_id)           # give to client after first probe
    ok   = mgr.verify(tok, session_id)     # returns True on reconnect

    # Client side — store token across reconnects
    client.resume_token = tok
    # Include tok in TYPE_RESUME packet header (see common.py TYPE_RESUME)
"""

import hashlib
import hmac as _hmac
import struct
import time
import threading
from typing import Optional

TOKEN_SIZE       = 32
TOKEN_WINDOW_SEC = 300    # 5-minute validity window (two buckets accepted)
TOKEN_HDR_SIZE   = 6      # session_id(2) + bucket(4)

# Add to common.py TYPE_* constants — we define it here to avoid circular import
TYPE_RESUME       = 0x08
TYPE_RESUME_ACK   = 0x09


def _bucket(ts: float = None) -> int:
    """Current time bucket (rounded to TOKEN_WINDOW_SEC)."""
    if ts is None:
        ts = time.time()
    return int(ts) // TOKEN_WINDOW_SEC


def _sign(seed: bytes, session_id: int, bucket: int) -> bytes:
    """26-byte HMAC truncation over (session_id, bucket)."""
    msg = struct.pack("!HI", session_id, bucket)
    return _hmac.new(seed, msg, hashlib.sha256).digest()[:26]


class SessionTokenManager:
    """
    Server-side token issuing and verification.
    Thread-safe. Accepts tokens from the current AND previous bucket
    to tolerate clients near a rotation boundary.
    """

    def __init__(self, seed: bytes):
        self._seed  = seed
        self._lock  = threading.Lock()
        # session_id → (token_bytes, issued_at)
        self._issued: dict = {}

    def issue(self, session_id: int) -> bytes:
        """Issue a fresh 32-byte session token for session_id."""
        b    = _bucket()
        sig  = _sign(self._seed, session_id, b)
        tok  = struct.pack("!HI", session_id, b) + sig
        assert len(tok) == TOKEN_SIZE
        with self._lock:
            self._issued[session_id] = (tok, time.monotonic())
        return tok

    def verify(self, token: bytes, session_id: int) -> bool:
        """
        Verify a token presented by a reconnecting client.
        Accepts current and previous bucket (clock-skew tolerance).
        """
        if len(token) != TOKEN_SIZE:
            return False
        try:
            sid, b = struct.unpack_from("!HI", token)
        except struct.error:
            return False

        if sid != session_id:
            return False

        sig_recv = token[TOKEN_HDR_SIZE:]
        now_b    = _bucket()

        # Accept current or previous bucket
        for test_b in (now_b, now_b - 1):
            if test_b < 0:
                continue
            expected = _sign(self._seed, session_id, test_b)
            if _hmac.compare_digest(sig_recv, expected):
                return True
        return False

    def revoke(self, session_id: int):
        """Explicitly revoke a session token (e.g. on graceful disconnect)."""
        with self._lock:
            self._issued.pop(session_id, None)

    def cleanup(self, max_age_sec: float = TOKEN_WINDOW_SEC * 3):
        """Remove old issued records."""
        now = time.monotonic()
        with self._lock:
            dead = [sid for sid, (_, ts) in self._issued.items()
                    if now - ts > max_age_sec]
            for sid in dead:
                del self._issued[sid]


class ResumeTokenStore:
    """
    Client-side: store the token received from the server and include it
    in reconnect packets.
    """

    def __init__(self):
        self._token: Optional[bytes] = None
        self._lock = threading.Lock()

    def store(self, token: bytes):
        with self._lock:
            self._token = token

    def get(self) -> Optional[bytes]:
        with self._lock:
            return self._token

    def clear(self):
        with self._lock:
            self._token = None

    @property
    def has_token(self) -> bool:
        with self._lock:
            return self._token is not None
