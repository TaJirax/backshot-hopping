"""
Pure-Python Reed-Solomon FEC over GF(2^8).
No external dependencies — works on Termux/Android out of the box.

Public API:
    split_and_encode(data, k, m)  → (shards, orig_len)
    reconstruct_data(shards, k, m, orig_len) → bytes
"""

# ─── GF(2^8) arithmetic ───────────────────────────────────────────────────────

_POLY = 0x11d   # x^8 + x^4 + x^3 + x^2 + 1

_EXP = [0] * 512
_LOG = [0] * 256

def _gf_init():
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _POLY
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]

_gf_init()

def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]

def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF div by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]

def _inv(a: int) -> int:
    return _EXP[255 - _LOG[a]]

# ─── Matrix ops over GF(2^8) ──────────────────────────────────────────────────

def _matmul_vec(mat, vec, k):
    """Matrix (n×k) times column vector (k) → column vector (n), all GF(2^8)."""
    n = len(mat)
    result = [0] * n
    for i in range(n):
        acc = 0
        for j in range(k):
            acc ^= _mul(mat[i][j], vec[j])
        result[i] = acc
    return result

def _invert_matrix(m, n):
    """Gauss-Jordan inversion over GF(2^8). m is list of lists (n×n)."""
    # Build augmented matrix [m | I]
    aug = [row[:] + ([1 if j == i else 0 for j in range(n)]) for i, row in enumerate(m)]
    for col in range(n):
        # Find pivot
        pivot = next((r for r in range(col, n) if aug[r][col] != 0), -1)
        if pivot == -1:
            raise ValueError(f"Singular matrix at col {col}")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        sc = aug[col][col]
        aug[col] = [_div(v, sc) for v in aug[col]]
        for row in range(n):
            if row == col or aug[row][col] == 0:
                continue
            f = aug[row][col]
            aug[row] = [aug[row][j] ^ _mul(f, aug[col][j]) for j in range(2 * n)]
    return [row[n:] for row in aug]

# ─── Cauchy-based systematic encoding matrix ──────────────────────────────────
#   Top k rows = identity  (data shards pass through unchanged)
#   Bottom m rows = Cauchy (parity)

def _build_enc_matrix(k, m):
    mat = []
    # Identity block
    for i in range(k):
        row = [1 if j == i else 0 for j in range(k)]
        mat.append(row)
    # Cauchy block: entry = 1 / (x_i XOR y_j),  x_i = i+k,  y_j = j
    for i in range(m):
        row = [_inv((i + k) ^ j) for j in range(k)]
        mat.append(row)
    return mat   # (k+m) × k

# Pre-build matrices for common (k=4, m=4) — avoids rebuilding every call
_ENC_CACHE = {}

def _get_enc_matrix(k, m):
    key = (k, m)
    if key not in _ENC_CACHE:
        _ENC_CACHE[key] = _build_enc_matrix(k, m)
    return _ENC_CACHE[key]

# ─── Encode ───────────────────────────────────────────────────────────────────

def _encode(data_shards, k, m):
    """data_shards: list of k equal-length bytes objects → list of m parity bytearray."""
    shard_len = len(data_shards[0])
    mat = _get_enc_matrix(k, m)
    parity = [bytearray(shard_len) for _ in range(m)]
    for pi in range(m):
        row = mat[k + pi]
        for di in range(k):
            coef = row[di]
            if coef == 0:
                continue
            src = data_shards[di]
            dst = parity[pi]
            for j in range(shard_len):
                dst[j] ^= _mul(coef, src[j])
    return [bytes(p) for p in parity]

# ─── Reconstruct ──────────────────────────────────────────────────────────────

def _reconstruct(all_shards, k, m):
    """
    all_shards: list of (k+m) items, None = lost.
    Returns list of k recovered data shards (bytes).
    """
    mat = _get_enc_matrix(k, m)
    shard_len = next(len(s) for s in all_shards if s is not None)

    # Check if data shards already complete
    if all(all_shards[i] is not None for i in range(k)):
        return list(all_shards[:k])

    # Collect k present shards
    present = [i for i, s in enumerate(all_shards) if s is not None]
    if len(present) < k:
        raise ValueError(f"Need {k} shards, have {len(present)}")
    present = present[:k]

    # Build k×k sub-matrix and input vectors
    sub = [mat[idx][:] for idx in present]
    inputs = [all_shards[idx] for idx in present]

    inv = _invert_matrix(sub, k)

    # Recover each data shard
    result = []
    for i in range(k):
        out = bytearray(shard_len)
        for j in range(k):
            coef = inv[i][j]
            if coef == 0:
                continue
            src = inputs[j]
            for p in range(shard_len):
                out[p] ^= _mul(coef, src[p])
        result.append(bytes(out))
    return result

# ─── Public API ───────────────────────────────────────────────────────────────

def split_and_encode(data: bytes, k: int = 4, m: int = 4):
    """
    Split data into k data shards and produce m parity shards.
    Returns (all_shards, orig_len) where all_shards is a list of k+m bytes objects.
    """
    orig_len = len(data)
    # Pad to multiple of k
    pad = (-len(data)) % k
    if pad:
        data = data + b'\x00' * pad
    shard_len = len(data) // k
    data_shards = [data[i * shard_len:(i + 1) * shard_len] for i in range(k)]
    parity_shards = _encode(data_shards, k, m)
    return data_shards + parity_shards, orig_len


def reconstruct_data(shards, k: int, m: int, orig_len: int) -> bytes:
    """
    Reconstruct original bytes from available shards (None = lost).
    shards must be a list of k+m items.
    """
    recovered = _reconstruct(list(shards), k, m)
    data = b''.join(recovered)
    return data[:orig_len]


# ─── KCP-style Selective ARQ tracker ─────────────────────────────────────────
#
# FEC alone handles random loss; ARQ handles the remaining gaps when FEC fails
# (i.e. more than `m` shards were lost from the same group).
#
# This is "selective" ARQ — we only NACK the specific missing shards, not the
# entire window. This is far more efficient than Go-Back-N under burst loss.
#
# Usage (sender side):
#     arq = SelectiveARQ(k=4, m=4)
#     arq.on_send(seq, shards)                  # record what we sent
#     nacks = arq.pending_nacks()               # poll periodically
#     for seq, shard_idx in nacks:
#         resend(shards[shard_idx])             # resend only the missing one
#
# Usage (receiver side):
#     arq = SelectiveARQ(k=4, m=4)
#     arq.on_receive(seq, shard_idx, data)
#     if arq.is_complete(seq):
#         payload = reconstruct_data(arq.get_shards(seq), k, m, orig_len)
#     else:
#         for missing in arq.missing_shards(seq):
#             send_nack(seq, missing)           # tell sender what we need

import threading as _threading
import time as _time


class SelectiveARQ:
    """
    KCP-inspired Selective ARQ window manager.

    Tracks which shards have been seen for each sequence number and computes
    the minimum NACK set needed to recover any un-decodable group.

    Parameters
    ----------
    k, m        FEC data/parity counts — must match the FEC encoder.
    window      How many sequence numbers to track simultaneously.
    ack_timeout Seconds before an un-acked shard triggers a NACK.
    max_retries Per-shard retransmission limit (avoids infinite loops on loss).
    """

    def __init__(self, k: int = 4, m: int = 4,
                 window: int = 64, ack_timeout: float = 0.3,
                 max_retries: int = 3):
        self.k           = k
        self.m           = m
        self.total       = k + m
        self.window      = window
        self.ack_timeout = ack_timeout
        self.max_retries = max_retries

        self._lock       = _threading.Lock()
        # seq → {"shards": [data|None, ...], "ts": float, "retries": [int, ...], "done": bool}
        self._groups: dict = {}

    # ── Sender side ───────────────────────────────────────────────────────────

    def on_send(self, seq: int, shards: list):
        """Record that we sent `shards` for `seq`. Call once per send."""
        with self._lock:
            self._groups[seq] = {
                "shards":  list(shards),
                "ts":      _time.monotonic(),
                "retries": [0] * len(shards),
                "done":    False,
            }
            self._evict()

    def on_ack(self, seq: int):
        """Mark seq as fully acknowledged — stop tracking."""
        with self._lock:
            if seq in self._groups:
                self._groups[seq]["done"] = True

    def pending_retransmits(self) -> list:
        """
        Returns list of (seq, shard_idx, shard_data) that should be retransmitted.
        Advances retry counter; entries that hit max_retries are dropped.
        """
        now = _time.monotonic()
        result = []
        with self._lock:
            for seq, grp in list(self._groups.items()):
                if grp["done"]:
                    continue
                if now - grp["ts"] < self.ack_timeout:
                    continue
                for i, shard in enumerate(grp["shards"]):
                    if shard is not None and grp["retries"][i] < self.max_retries:
                        grp["retries"][i] += 1
                        result.append((seq, i, shard))
                grp["ts"] = now   # reset window
        return result

    # ── Receiver side ─────────────────────────────────────────────────────────

    def on_receive(self, seq: int, shard_idx: int, data: bytes):
        """Record receipt of shard `shard_idx` for `seq`."""
        with self._lock:
            if seq not in self._groups:
                self._groups[seq] = {
                    "shards":  [None] * self.total,
                    "ts":      _time.monotonic(),
                    "retries": [0] * self.total,
                    "done":    False,
                }
                self._evict()
            grp = self._groups[seq]
            if 0 <= shard_idx < self.total:
                grp["shards"][shard_idx] = data

    def is_decodable(self, seq: int) -> bool:
        """True if we have at least k shards — FEC can reconstruct."""
        with self._lock:
            grp = self._groups.get(seq)
            if not grp:
                return False
            present = sum(1 for s in grp["shards"] if s is not None)
            return present >= self.k

    def missing_shards(self, seq: int) -> list:
        """Return list of shard indices we have NOT received for seq."""
        with self._lock:
            grp = self._groups.get(seq)
            if not grp:
                return list(range(self.total))
            return [i for i, s in enumerate(grp["shards"]) if s is None]

    def get_shards(self, seq: int) -> list:
        """Return the shard list for seq (items may be None)."""
        with self._lock:
            grp = self._groups.get(seq)
            return list(grp["shards"]) if grp else [None] * self.total

    def mark_done(self, seq: int):
        """Mark seq as fully delivered — stop tracking."""
        with self._lock:
            if seq in self._groups:
                self._groups[seq]["done"] = True

    # ── Internal ──────────────────────────────────────────────────────────────

    def _evict(self):
        """Evict oldest groups when window is full (called under lock)."""
        done = [s for s, g in self._groups.items() if g["done"]]
        for s in done:
            del self._groups[s]
        while len(self._groups) > self.window:
            oldest = min(self._groups, key=lambda s: self._groups[s]["ts"])
            del self._groups[oldest]

