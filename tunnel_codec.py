"""Shared sharded packet codec for tunnel mode.

The codec keeps the existing HopShot packet framing so tunnel packets can use
all of the current transport behavior while still being reassembled into raw
payload bytes.
"""

from __future__ import annotations

import threading
import struct
import time
from dataclasses import dataclass
from typing import Dict, Optional

import common
import fec as fecmod
from http3_masq import HTTP3Masq


@dataclass
class EncodedDatagrams:
    datagrams: list[bytes]
    total_shards: int
    orig_len: int


def stream_id_from_ip_packet(packet: bytes) -> int:
    if not packet:
        return 0
    version = packet[0] >> 4
    stream_bytes = b""
    if version == 4 and len(packet) >= 20:
        stream_bytes = packet[16:20]
    elif version == 6 and len(packet) >= 40:
        stream_bytes = packet[24:40]
    else:
        return 0
    if not stream_bytes:
        return 0
    return 1 + (sum(stream_bytes) % 255)


def encode_datagrams(
    payload: bytes,
    seq: int,
    session_id: int,
    seed: bytes,
    fec_k: int,
    fec_m: int,
    jitter: int,
    obfs: bool,
    masquerade: bool,
    transport: int = common.TRANSPORT_RAW,
    max_datagram_size: int = common.MAX_PACKET,
    stream_id: int = 0,
) -> EncodedDatagrams:
    shards, orig_len = fecmod.split_and_encode(payload, fec_k, fec_m)
    total_shards = len(shards)
    max_body_size = max(1, int(max_datagram_size) - common.HEADER_SIZE)
    orig_len_bytes = struct.pack("!I", orig_len)
    datagrams: list[bytes] = []

    for shard_idx, shard_data in enumerate(shards):
        padded = common.add_jitter_padding(shard_data, jitter)
        shard_payload = orig_len_bytes + padded
        fragments = [
            shard_payload[i:i + max_body_size]
            for i in range(0, len(shard_payload), max_body_size)
        ]
        frag_count = max(1, len(fragments))

        for frag_id, frag_payload in enumerate(fragments):
            hdr = common.pack_header(
                pkt_type=common.TYPE_DATA,
                seq=seq,
                shard_idx=shard_idx,
                total_shards=total_shards,
                session_id=session_id,
                transport=transport,
                frag_id=frag_id,
                frag_count=frag_count,
                stream_id=stream_id,
            )
            pkt = hdr + frag_payload
            if obfs:
                pkt = common.salamander(pkt, seed)
            if masquerade:
                masq_seq = (seq * total_shards * 256) + (shard_idx * 256) + frag_id
                pkt = HTTP3Masq.wrap(pkt, seed, masq_seq)
            datagrams.append(pkt)

    return EncodedDatagrams(datagrams=datagrams, total_shards=total_shards, orig_len=orig_len)


class DataReassembler:
    def __init__(self, fec_k: int, fec_m: int, jitter: int, group_ttl_sec: float = 30.0):
        self.fec_k = fec_k
        self.fec_m = fec_m
        self.jitter = jitter
        self._group_ttl_sec = max(1.0, float(group_ttl_sec))
        self._groups: Dict[tuple[int, int], dict] = {}
        self._lock = threading.Lock()

    def _cleanup_stale_groups(self, now: float) -> None:
        stale = [
            seq for seq, grp in self._groups.items()
            if (now - grp["ts"]) > self._group_ttl_sec
        ]
        for seq in stale:
            self._groups.pop(seq, None)

    def push(self, hdr: dict, payload: bytes) -> Optional[bytes]:
        seq = hdr["seq"]
        shard_idx = hdr["shard_idx"]
        total = hdr["total_shards"]
        stream_id = int(hdr.get("stream_id", 0) or 0)
        frag_id = int(hdr.get("frag_id", 0) or 0)
        frag_count = int(hdr.get("frag_count", 1) or 1)
        if frag_count <= 0:
            frag_count = 1
            frag_id = 0
        elif frag_id < 0 or frag_id >= frag_count:
            return None

        with self._lock:
            now = time.time()
            self._cleanup_stale_groups(now)

            key = (seq, stream_id)
            grp = self._groups.get(key)
            if grp is None:
                grp = {
                    "shards": [None] * total,
                    "orig_len": 0,
                    "received": 0,
                    "delivered": False,
                    "fragments": {},
                    "ts": now,
                }
                self._groups[key] = grp

            if grp["delivered"]:
                return None

            if grp["shards"][shard_idx] is not None:
                return None

            if frag_count == 1:
                shard_payload = payload
            else:
                shard_frag = grp["fragments"].get(shard_idx)
                if shard_frag is None or shard_frag["count"] != frag_count:
                    shard_frag = {
                        "count": frag_count,
                        "parts": [None] * frag_count,
                        "received": 0,
                    }
                    grp["fragments"][shard_idx] = shard_frag

                if shard_frag["parts"][frag_id] is not None:
                    return None
                shard_frag["parts"][frag_id] = payload
                shard_frag["received"] += 1
                if shard_frag["received"] < frag_count:
                    return None

                shard_payload = b"".join(shard_frag["parts"])
                grp["fragments"].pop(shard_idx, None)

            if len(shard_payload) < 4:
                return None

            orig_len = struct.unpack_from("!I", shard_payload)[0]
            shard_data = common.strip_jitter_padding(shard_payload[4:], max_jitter=self.jitter)

            grp["orig_len"] = orig_len
            grp["shards"][shard_idx] = shard_data
            grp["received"] += 1

            if grp["received"] < self.fec_k:
                return None

            try:
                recovered = fecmod.reconstruct_data(grp["shards"], self.fec_k, self.fec_m, grp["orig_len"])
            except Exception:
                return None

            grp["delivered"] = True
            return recovered
