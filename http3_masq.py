"""
HopShot HTTP/3 Masquerading — inspired by Hysteria2.

Wraps HopShot UDP payloads inside a convincing HTTP/3 (QUIC) outer frame
so that shallow DPI sees what looks like normal web traffic.

Two layers:
  1. QUIC Initial Packet header (fake)  — carries the DCIDs, packet number,
     token field, and length prefix that every real QUIC Initial packet has.
  2. HTTP/3 HEADERS frame (fake)        — wraps the HopShot payload inside a
     byte sequence that looks like a compressed HTTP/3 request/response.

Stripping is deterministic: both sides know the shared seed, so the fake
headers are reproduced identically and stripped without any extra signaling.

IMPORTANT: This is *packet-level* camouflage, not a real QUIC/HTTP3 stack.
It does not implement QUIC crypto or HTTP/3 semantics — it only makes the
raw bytes resemble that traffic to non-decrypting middleboxes.

Usage:
    # Wrap before sending
    wrapped = HTTP3Masq.wrap(payload, seed, seq)

    # Unwrap after receiving
    original = HTTP3Masq.unwrap(wrapped, seed, seq)
    # Returns None if the packet is not a masqueraded HopShot packet.
"""

import hashlib
import hmac as _hmac
import os
import struct
import time

# ─── QUIC Initial Packet constants ────────────────────────────────────────────
# RFC 9000 §17.2.2
QUIC_LONG_HEADER_FIXED  = 0b11000000   # Long header, type = Initial (00)
QUIC_VERSION_1          = b"\x00\x00\x00\x01"
QUIC_DCID_LEN           = 8            # 8-byte destination CID (plausible)
QUIC_SCID_LEN           = 8            # 8-byte source CID

# ─── HTTP/3 frame types ───────────────────────────────────────────────────────
H3_FRAME_HEADERS = 0x01
H3_FRAME_DATA    = 0x00

# ─── Marker so we can detect our own wrapped packets ─────────────────────────
# Embedded in the QUIC token field (variable-length, usually 0 in Initial pkts)
_MARKER_MAGIC = b"\x48\x53"   # "HS" — HopShot marker in token


def _derive_ids(seed: bytes, seq: int) -> tuple:
    """Derive deterministic DCID, SCID, and packet number from (seed, seq)."""
    mac = _hmac.new(seed, struct.pack("!I", seq & 0xFFFFFFFF), hashlib.sha256).digest()
    dcid   = mac[0:QUIC_DCID_LEN]
    scid   = mac[8:8 + QUIC_SCID_LEN]
    pn     = struct.unpack_from("!I", mac, 16)[0] & 0x00FFFFFF   # 3-byte packet number
    return dcid, scid, pn


def _encode_varint(n: int) -> bytes:
    """QUIC variable-length integer encoding (RFC 9000 §16)."""
    if n < 64:
        return bytes([n])
    elif n < 16384:
        return struct.pack("!H", n | 0x4000)
    elif n < 1073741824:
        return struct.pack("!I", n | 0x80000000)
    else:
        return struct.pack("!Q", n | 0xC000000000000000)


def _decode_varint(data: bytes, offset: int) -> tuple:
    """Decode QUIC varint at offset. Returns (value, new_offset)."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    prefix = first >> 6
    if prefix == 0:
        return first & 0x3F, offset + 1
    elif prefix == 1:
        if offset + 2 > len(data):
            return 0, offset
        return struct.unpack_from("!H", bytes([first & 0x3F]) + data[offset+1:offset+2])[0], offset + 2
    elif prefix == 2:
        if offset + 4 > len(data):
            return 0, offset
        raw = struct.unpack_from("!I", data, offset)[0]
        return raw & 0x3FFFFFFF, offset + 4
    else:
        if offset + 8 > len(data):
            return 0, offset
        raw = struct.unpack_from("!Q", data, offset)[0]
        return raw & 0x3FFFFFFFFFFFFFFF, offset + 8


class HTTP3Masq:
    """
    Static helpers for HTTP/3 masquerading of HopShot packets.
    """

    @staticmethod
    def wrap(payload: bytes, seed: bytes, seq: int) -> bytes:
        """
        Wrap a HopShot payload inside a fake QUIC Initial + HTTP/3 frame.

        Output layout:
          [QUIC long header first byte: 1]
          [QUIC version: 4]
          [DCID length: 1][DCID: 8]
          [SCID length: 1][SCID: 8]
          [Token length varint][Token: marker(2) + pn_bytes(3)]
          [Payload length varint]
          [Packet number: 3]
          [H3 DATA frame type varint]
          [H3 DATA frame length varint]
          [HopShot payload]
        """
        dcid, scid, pn = _derive_ids(seed, seq)

        pn_bytes = struct.pack("!I", pn)[1:]   # 3 bytes

        # Token field carries our marker + payload HMAC so unwrap can verify
        # the packet without brute-forcing seq values.
        token    = _MARKER_MAGIC + _hmac.new(seed, payload, hashlib.sha256).digest()[:8]
        token_len = _encode_varint(len(token))

        # H3 DATA frame wrapping the actual payload
        h3_frame = (
            _encode_varint(H3_FRAME_DATA) +
            _encode_varint(len(payload)) +
            payload
        )

        # QUIC packet number (3 bytes) + h3_frame
        quic_payload = pn_bytes + h3_frame
        payload_len  = _encode_varint(len(quic_payload))

        return (
            bytes([QUIC_LONG_HEADER_FIXED]) +
            QUIC_VERSION_1 +
            bytes([QUIC_DCID_LEN]) + dcid +
            bytes([QUIC_SCID_LEN]) + scid +
            token_len + token +
            payload_len +
            quic_payload
        )

    @staticmethod
    def unwrap(data: bytes, seed: bytes, seq: int | None = None):
        """
        Unwrap a masqueraded packet. Returns the original HopShot payload,
        or None if data is not a valid masqueraded packet (plain UDP or corrupt).
        If seq is provided, the outer QUIC identifiers are also validated.
        """
        try:
            pos = 0
            # First byte: long header flag
            if len(data) < 1 or data[pos] != QUIC_LONG_HEADER_FIXED:
                return None
            pos += 1

            # Version
            if data[pos:pos+4] != QUIC_VERSION_1:
                return None
            pos += 4

            # DCID
            if pos >= len(data):
                return None
            dcid_len = data[pos]; pos += 1
            if pos + dcid_len > len(data):
                return None
            dcid     = data[pos:pos+dcid_len]; pos += dcid_len

            # SCID
            if pos >= len(data):
                return None
            scid_len = data[pos]; pos += 1
            if pos + scid_len > len(data):
                return None
            scid = data[pos:pos+scid_len]; pos += scid_len

            # Token
            token_len, pos = _decode_varint(data, pos)
            if token_len < len(_MARKER_MAGIC) or pos + token_len > len(data):
                return None
            token = data[pos:pos+token_len]; pos += token_len
            if not token.startswith(_MARKER_MAGIC):
                return None   # not a HopShot masqueraded packet

            # Payload length
            plen, pos = _decode_varint(data, pos)
            if pos + plen > len(data):
                return None

            # Packet number (3 bytes)
            if pos + 3 > len(data):
                return None
            pn_bytes = data[pos:pos+3]
            pos += 3

            # H3 frame type
            frame_type, pos = _decode_varint(data, pos)
            if frame_type != H3_FRAME_DATA:
                return None

            # H3 frame length + payload
            frame_len, pos = _decode_varint(data, pos)
            if pos + frame_len > len(data):
                return None
            frame_payload = data[pos:pos+frame_len]

            if seq is not None:
                exp_dcid, exp_scid, exp_pn = _derive_ids(seed, seq)
                if dcid != exp_dcid or scid != exp_scid:
                    return None
                if pn_bytes != struct.pack("!I", exp_pn)[1:]:
                    return None

            expected_token = _MARKER_MAGIC + _hmac.new(
                seed, frame_payload, hashlib.sha256
            ).digest()[:len(token) - len(_MARKER_MAGIC)]
            if not _hmac.compare_digest(token, expected_token):
                return None

            return frame_payload

        except Exception:
            return None

    @staticmethod
    def is_masqueraded(data: bytes) -> bool:
        """Quick check: does this packet look like one of ours?"""
        if len(data) < 20:
            return False
        if data[0] != QUIC_LONG_HEADER_FIXED:
            return False
        if data[1:5] != QUIC_VERSION_1:
            return False
        # Check for marker in token area (approximate — full decode in unwrap)
        return _MARKER_MAGIC in data[14:32]
