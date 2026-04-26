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
) -> EncodedDatagrams:
    shards, orig_len = fecmod.split_and_encode(payload, fec_k, fec_m)
    total_shards = len(shards)
    orig_len_bytes = struct.pack("!I", orig_len)
    datagrams: list[bytes] = []

    for shard_idx, shard_data in enumerate(shards):
        padded = common.add_jitter_padding(shard_data, jitter)
        hdr = common.pack_header(
            pkt_type=common.TYPE_DATA,
            seq=seq,
            shard_idx=shard_idx,
            total_shards=total_shards,
            session_id=session_id,
            transport=transport,
        )
        pkt = hdr + orig_len_bytes + padded
        if obfs:
            pkt = common.salamander(pkt, seed)
        if masquerade:
            pkt = HTTP3Masq.wrap(pkt, seed, seq * total_shards + shard_idx)
        datagrams.append(pkt)

    return EncodedDatagrams(datagrams=datagrams, total_shards=total_shards, orig_len=orig_len)


class DataReassembler:
    def __init__(self, fec_k: int, fec_m: int, jitter: int):
        self.fec_k = fec_k
        self.fec_m = fec_m
        self.jitter = jitter
        self._groups: Dict[int, dict] = {}
        self._lock = threading.Lock()

    def push(self, hdr: dict, payload: bytes) -> Optional[bytes]:
        if len(payload) < 4:
            return None

        orig_len = struct.unpack_from("!I", payload)[0]
        shard_data = common.strip_jitter_padding(payload[4:], max_jitter=self.jitter)
        seq = hdr["seq"]
        shard_idx = hdr["shard_idx"]
        total = hdr["total_shards"]

        with self._lock:
            grp = self._groups.get(seq)
            if grp is None:
                grp = {"shards": [None] * total, "orig_len": orig_len, "received": 0, "delivered": False, "ts": time.time()}
                self._groups[seq] = grp

            if grp["delivered"] or grp["shards"][shard_idx] is not None:
                return None

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
