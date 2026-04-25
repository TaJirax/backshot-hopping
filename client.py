#!/usr/bin/env python3
"""
HopShot Client — full pipeline with all features:

  Port Probe (reactive: quick burst test before every send)
       |
  Pick mode (normal / moderate / high / NUCLEAR)
       |
  Dual stack: raw UDP + QUIC (TLS 1.3) simultaneously
       |
  Brutal CC (paces sends, adjusts from server BWFeedback)
       |
  FEC encode (Reed-Solomon k+m shards)
       |
  Packet size jitter (random padding per packet)
       |
  Burst sender x N copies across multiple ports AND multiple IPs
       |
  Pre-emptive hopping (hop BEFORE ISP flow-throttle window)
  Deterministic hop sequence (shared_seed + time_slot -> port)
  Source port randomization [optional --rand-src-port]
       |
  Salamander obfuscation (optional)
       |
  ======== NETWORK ========
"""

import argparse
import json
import logging
import os
import random
import socket
import struct
import sys
import threading
import time

import common
import fec as fecmod
import brutal
from quic_transport import QUICClient
from resolver import Resolver, DEFAULT_RESOLVERS
from http3_masq import HTTP3Masq
from mtu_probe import MTUProber
from session_resume import ResumeTokenStore, TOKEN_SIZE
from terminal_ui import configure_logging, colorize, title

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hopshot.client")


PROFILE_PRESETS = {
    "balanced": {},
    "reliable": {
        "disable_hop": True,
        "obfs": False,
        "masquerade": False,
        "rand_src_port": False,
        "jitter_bytes": 0,
        "preemptive_hop_ms": 0,
    },
    "stealth": {
        "obfs": True,
        "masquerade": True,
        "rand_src_port": True,
        "jitter_bytes": 64,
        "preemptive_hop_ms": common.PREEMPTIVE_HOP_MS,
    },
    "throughput": {
        "obfs": False,
        "masquerade": False,
        "rand_src_port": False,
        "jitter_bytes": 0,
        "preemptive_hop_ms": 0,
    },
}


def apply_profile_overrides(cfg: dict) -> dict:
    profile = cfg.get("profile", "balanced")
    preset = PROFILE_PRESETS.get(profile)
    if preset is None:
        raise ValueError(f"Unknown profile: {profile}")
    merged = dict(cfg)
    merged.update(preset)
    merged["profile"] = profile
    return merged


def render_config_summary(cfg: dict) -> str:
    lines = [
        title("HopShot Client", "cyan"),
        f"profile: {colorize(cfg['profile'], 'green', bold=True)}",
        f"server: {cfg['server_port']}  quic: {cfg['quic_port']}  dests: {len(cfg['destinations'])}",
        f"port-range: {cfg['port_min']}-{cfg['port_max']}  hop-disabled: {cfg.get('disable_hop', False)}",
        f"obfs: {cfg['obfs']}  masquerade: {cfg['masquerade']}  rand-src: {cfg['rand_src_port']}",
        f"jitter: {cfg['jitter_bytes']}B  preemptive-hop: {cfg['preemptive_hop_ms']}ms",
        f"fec: {cfg['fec_k']}x{cfg['fec_m']}  declared-up: {cfg['declared_up_kbps']}kbps",
        f"log-file: {cfg.get('log_file') or '-'}  metrics-file: {cfg.get('metrics_file') or '-'}",
    ]
    return "\n".join(lines)


# ─── Port prober (also used by resolver.py) ───────────────────────────────────

def probe_port(server_ip, port, count=20, timeout_ms=2000,
               seed=b"hopshot", obfs=False, resume_store=None,
               verbose=False):
    """
    Send count probe packets, measure loss% and RTT.
    If resume_store is provided, cache any 0-RTT token carried in the reply.
    Returns dict with port, loss_pct, rtt_ms, sent, received.
    """
    log.info(f"[probe] -> {server_ip}:{port}  ({count} pkts, {timeout_ms}ms)")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((server_ip, port))
        sock.settimeout(timeout_ms / 1000.0)
        if verbose:
            log.debug(f"[probe] socket connected to {server_ip}:{port}")
    except Exception as e:
        log.warning(f"[probe] socket: {e}")
        return {"port": port, "loss_pct": 100.0, "rtt_ms": 0,
                "sent": 0, "received": 0}

    sess_id    = random.randint(0, 0xFFFF)
    send_times = {}
    replies    = {}
    stop_ev    = threading.Event()

    def reader():
        buf = bytearray(256)
        while not stop_ev.is_set():
            try:
                n = sock.recv_into(buf)
                pkt = bytes(buf[:n])
                if obfs:
                    pkt = common.salamander(pkt, seed)
                hdr, payload = common.unpack_header(pkt)
                if hdr and hdr["type"] == common.TYPE_PROBE_REPLY:
                    replies[hdr["seq"]] = time.monotonic()
                    if verbose:
                        log.debug(f"[probe] rx seq={hdr['seq']} {len(pkt)}B")
                    if resume_store is not None and len(payload) >= TOKEN_SIZE:
                        resume_store.store(payload[:TOKEN_SIZE])
                        if verbose:
                            log.debug(f"[probe] cached resume token {len(payload[:TOKEN_SIZE])}B")
            except socket.timeout:
                pass
            except Exception:
                if verbose:
                    log.exception("[probe] reader loop failed")
                break

    threading.Thread(target=reader, daemon=True).start()

    interval = max((timeout_ms / count) / 1000.0, 0.01)
    sent = 0
    for i in range(count):
        hdr = common.pack_header(common.TYPE_PROBE, seq=i, session_id=sess_id)
        if obfs:
            hdr = common.salamander(hdr, seed)
        send_times[i] = time.monotonic()
        try:
            sock.send(hdr)
            sent += 1
            if verbose:
                log.debug(f"[probe] tx seq={i} {len(hdr)}B")
        except Exception:
            pass
        time.sleep(interval)

    time.sleep(min(0.5, timeout_ms / 2000.0))
    stop_ev.set()
    sock.close()

    received = 0
    rtt_sum  = 0.0
    for seq, recv_t in replies.items():
        if seq in send_times:
            received += 1
            rtt_sum  += (recv_t - send_times[seq]) * 1000.0

    loss = 100.0 * max(sent - received, 0) / max(sent, 1)
    rtt  = rtt_sum / max(received, 1)
    log.info(f"[probe] loss={loss:.1f}%  rtt={rtt:.1f}ms  rx={received}/{sent}")
    if verbose:
        missing = sorted(set(send_times) - set(replies))
        log.debug(f"[probe] summary sent={sent} received={received} missing={missing}")
    return {"port": port, "loss_pct": loss, "rtt_ms": rtt,
            "sent": sent, "received": received}


# ─── Reactive pre-probe ───────────────────────────────────────────────────────

def reactive_probe(server_ip, port, seed, obfs,
                   threshold=common.REACTIVE_LOSS_THRESHOLD,
                   resume_store=None, verbose=False):
    """
    Quick 5-packet burst to check if current port is being throttled.
    Returns (loss_pct, should_hop).
    Used right before sending real data.
    """
    r = probe_port(server_ip, port, count=5, timeout_ms=800,
                   seed=seed, obfs=obfs, resume_store=resume_store,
                   verbose=verbose)
    should_hop = r["loss_pct"] >= threshold
    if should_hop:
        log.warning(
            f"[reactive] port {port} loss={r['loss_pct']:.1f}% "
            f">= {threshold}% -> hopping now"
        )
    elif verbose:
        log.debug(f"[reactive] port {port} loss={r['loss_pct']:.1f}% < {threshold}%")
    return r["loss_pct"], should_hop


# ─── Client ───────────────────────────────────────────────────────────────────

class HopShotClient:

    def __init__(self, cfg: dict):
        self.cfg          = cfg
        self.seed         = cfg["shared_seed"].encode()
        self.obfs         = cfg.get("obfs", False)
        self.fec_k        = cfg.get("fec_k", 4)
        self.fec_m        = cfg.get("fec_m", 4)
        self.verbose      = cfg.get("verbose", False)
        self.server_port  = cfg["server_port"]
        self.port_min     = cfg.get("port_min", 10000)
        self.port_max     = cfg.get("port_max", 65000)
        self.quic_port    = cfg.get("quic_port", self.server_port + 1)
        self.rand_src     = cfg.get("rand_src_port", False)   # optional
        self.jitter       = cfg.get("jitter_bytes", 64)       # 0 = disabled
        self.preemptive   = cfg.get("preemptive_hop_ms",
                                    common.PREEMPTIVE_HOP_MS)
        self.disable_hop  = cfg.get("disable_hop", False)

        # Resolver + multi-destination
        self.resolver     = Resolver(cfg.get("resolvers", DEFAULT_RESOLVERS))
        raw_dests         = cfg.get("destinations",
                                    [cfg.get("server_addr", "127.0.0.1")])
        self.dest_ips     = self.resolver.resolve_all(raw_dests)
        if not self.dest_ips:
            raise RuntimeError(f"Could not resolve any destination: {raw_dests}")
        log.info(f"[client] destinations: {self.dest_ips}")

        # Pick primary (lowest loss) — others used for multi-dest burst
        self.primary_ip   = self.dest_ips[0]

        self.session_id   = random.randint(0, 0xFFFF)
        self._seq         = 0
        self._seq_lock    = threading.Lock()

        # Brutal CC — single instance shared by both transports
        self.cc           = brutal.BrutalSender(
            declared_up_kbps=cfg.get("declared_up_kbps", 0)
        )

        # Current mode
        self.mode         = common.MODE_NORMAL
        self.hop_ms       = 0
        self.burst_mult   = 1
        self._mode_lock   = threading.Lock()

        # HTTP/3 masquerading (optional)
        self.masquerade   = cfg.get("masquerade", False)

        # MTU probing (KCP-style)
        self._mtu_prober  = MTUProber(self.seed, obfs=self.obfs)
        self._mtu         = cfg.get("mtu", 0)   # 0 = auto-probe

        # 0-RTT session resumption (TUIC-style)
        self._resume_store = ResumeTokenStore()

        # Selective ARQ
        self._arq         = fecmod.SelectiveARQ(k=self.fec_k, m=self.fec_m)

        self.metrics_file = cfg.get("metrics_file")
        self._metrics_lock = threading.Lock()
        self._metrics_fp   = None
        if self.metrics_file:
            self._metrics_fp = open(self.metrics_file, "a", encoding="utf-8")

        # QUIC
        self.quic         = None
        self.quic_ok      = False

        self._running     = False

        if self.verbose:
            log.debug(
                "[client] config: "
                f"server_port={self.server_port} quic_port={self.quic_port} "
                f"dests={self.dest_ips} port_range={self.port_min}-{self.port_max} "
                f"obfs={self.obfs} masq={self.masquerade} rand_src={self.rand_src} "
                f"jitter={self.jitter} preemptive={self.preemptive} "
                f"disable_hop={self.disable_hop} profile={self.cfg.get('profile', 'balanced')} "
                f"fec={self.fec_k}x{self.fec_m} declared_up={cfg.get('declared_up_kbps', 0)} "
                f"resume_store={self._resume_store.has_token}"
            )

    def _record_metric(self, event: str, **fields):
        if not self._metrics_fp:
            return
        payload = {
            "ts": time.time(),
            "event": event,
            "session_id": self.session_id,
            "mode": common.MODE_NAMES.get(self.mode, str(self.mode)),
        }
        payload.update(fields)
        with self._metrics_lock:
            self._metrics_fp.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._metrics_fp.flush()

    # ── Startup ───────────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        if self.verbose:
            log.debug("[client] startup phase=probe")

        # Phase 1: probe primary port
        result = probe_port(
            self.primary_ip, self.server_port,
            count      = self.cfg.get("probe_count", 20),
            timeout_ms = self.cfg.get("probe_timeout_ms", 2000),
            seed       = self.seed,
            obfs       = self.obfs,
            resume_store=self._resume_store,
            verbose    = self.verbose,
        )
        if self.verbose:
            log.debug(f"[client] probe result: {result}")
        self._record_metric("probe", **result)

        # If multiple destinations, pick the best one
        if len(self.dest_ips) > 1:
            self.primary_ip = self.resolver.best_destination(
                self.dest_ips, self.server_port, self.seed, self.obfs,
                verbose=self.verbose,
            )
            log.info(f"[client] primary IP selected: {self.primary_ip}")

        # Phase 2: classify mode
        self._set_mode(result["loss_pct"])

        # Phase 3: MTU probe (KCP-style) — determine safe shard size
        if self._mtu == 0:
            if self.verbose:
                log.debug("[client] startup phase=mtu-probe")
            self._mtu = self._mtu_prober.probe(
                self.primary_ip, self.server_port
            )
            log.info(f"[MTU] path MTU discovered: {self._mtu + 28} bytes "
                     f"(safe payload={self._mtu})")
            self._record_metric("mtu", safe_payload=self._mtu, configured=False)
        else:
            log.info(f"[MTU] using user-configured MTU payload={self._mtu}")
            self._record_metric("mtu", safe_payload=self._mtu, configured=True)

        # Phase 4: connect QUIC alongside raw UDP
        if self.verbose:
            log.debug("[client] startup phase=quic-connect")
        self._connect_quic()

        # Background loops
        threading.Thread(target=self._feedback_listener, daemon=True).start()
        threading.Thread(target=self._monitor_loop,      daemon=True).start()

        log.info(
            f"[client] ready | mode={common.MODE_NAMES[self.mode]} "
            f"| hop={self.hop_ms}ms | burst=x{self.burst_mult} "
            f"| jitter={self.jitter}B | rand_src={self.rand_src} "
            f"| preemptive={self.preemptive}ms"
        )
        self._record_metric("ready", hop_ms=self.hop_ms, burst_mult=self.burst_mult)

    def _set_mode(self, loss_pct: float):
        with self._mode_lock:
            self.mode      = common.classify_loss(loss_pct)
            self.hop_ms, self.burst_mult = common.MODE_PARAMS[self.mode]
        log.info(
            f"[mode] -> {common.MODE_NAMES[self.mode]}  "
            f"hop={self.hop_ms}ms  burst=x{self.burst_mult}"
        )
        self._record_metric("mode", loss_pct=loss_pct, hop_ms=self.hop_ms, burst_mult=self.burst_mult)
        if self.verbose:
            log.debug(
                f"[mode] loss={loss_pct:.1f}% mode={self.mode} "
                f"hop_ms={self.hop_ms} burst_mult={self.burst_mult}"
            )

    def _connect_quic(self):
        try:
            if self.verbose:
                log.debug(f"[QUIC] connecting to {self.primary_ip}:{self.quic_port}")
            self.quic    = QUICClient(self.primary_ip, self.quic_port, verify=False)
            self.quic_ok = self.quic.connect()
            if self.quic_ok:
                log.info("[QUIC] connected (TLS 1.3)")
                self._record_metric("quic_connect", ok=True)
            else:
                log.warning("[QUIC] failed -> raw UDP only")
                self._record_metric("quic_connect", ok=False)
        except Exception as e:
            log.warning(f"[QUIC] unavailable: {e}")
            self.quic_ok = False
            if self.verbose:
                log.exception("[QUIC] connect exception")
            self._record_metric("quic_connect", ok=False, error=str(e))

    # ── Core send ─────────────────────────────────────────────────────────────

    def send(self, payload: bytes):
        """Full pipeline: reactive probe -> FEC -> jitter -> burst -> hop -> obfs."""

        with self._seq_lock:
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            seq = self._seq

        with self._mode_lock:
            mode       = self.mode
            hop_ms     = self.hop_ms
            burst_mult = self.burst_mult

        if self.verbose:
            log.debug(
                f"[send] seq={seq} payload={len(payload)}B mode={common.MODE_NAMES[mode]} "
                f"hop_ms={hop_ms} burst_mult={burst_mult} dests={self.dest_ips} "
                f"obfs={self.obfs} masq={self.masquerade} resume={self._resume_store.has_token}"
            )
        self._record_metric(
            "send_start",
            seq=seq,
            payload=len(payload),
            mode=common.MODE_NAMES[mode],
            hop_ms=hop_ms,
            burst_mult=burst_mult,
            dests=len(self.dest_ips),
        )

        # ── Reactive pre-probe: check current port before sending ─────────────
        cur_port = self._hop_port(0, hop_ms)
        _, should_hop = reactive_probe(
            self.primary_ip, cur_port, self.seed, self.obfs,
            resume_store=self._resume_store, verbose=self.verbose,
        )
        if should_hop:
            # Force immediate slot advance so next hop_port() gives a new port
            log.info("[reactive] forcing immediate port hop")
            # We advance the slot offset — next call will land on next slot
            cur_port = self._hop_port(1, hop_ms)
            self._record_metric("reactive_hop", port=cur_port)

        # ── FEC encode ────────────────────────────────────────────────────────
        shards, orig_len = fecmod.split_and_encode(payload, self.fec_k, self.fec_m)
        total_shards     = len(shards)

        if self.verbose:
            log.debug(f"[send] FEC shards={total_shards} orig_len={orig_len}")

        log.info(
            f"[send] {len(payload)}B seq={seq} "
            f"mode={common.MODE_NAMES[mode]} "
            f"shards={total_shards} burst=x{burst_mult} "
            f"dests={len(self.dest_ips)} "
            f"masq={self.masquerade} "
            f"resume={self._resume_store.has_token}"
        )

        orig_len_bytes = struct.pack("!I", orig_len)

        # Register with ARQ tracker (for potential retransmit)
        self._arq.on_send(seq, shards)

        for shard_idx, shard_data in enumerate(shards):

            # ── Jitter padding ────────────────────────────────────────────────
            padded = common.add_jitter_padding(shard_data, self.jitter)
            if self.verbose:
                log.debug(
                    f"[send] shard={shard_idx}/{total_shards-1} raw={len(shard_data)}B "
                    f"padded={len(padded)}B"
                )

            hdr = common.pack_header(
                pkt_type     = common.TYPE_DATA,
                seq          = seq,
                shard_idx    = shard_idx,
                total_shards = total_shards,
                session_id   = self.session_id,
                transport    = common.TRANSPORT_RAW,
            )
            pkt = hdr + orig_len_bytes + padded

            if self.obfs:
                pkt = common.salamander(pkt, self.seed)

            # ── HTTP/3 masquerading (optional) ────────────────────────────────
            if self.masquerade:
                pkt = HTTP3Masq.wrap(pkt, self.seed, seq * total_shards + shard_idx)
                if self.verbose:
                    log.debug(f"[send] shard={shard_idx} wrapped for HTTP/3 masquerade")

            # ── Brutal CC pacing ──────────────────────────────────────────────
            self.cc.pace(len(pkt))

            # ── Burst across ports AND destinations ───────────────────────────
            self._burst_send(pkt, shard_idx, seq, hop_ms, burst_mult)

            # ── QUIC path simultaneously ──────────────────────────────────────
            if self.quic_ok and self.quic:
                quic_hdr = common.pack_header(
                    pkt_type     = common.TYPE_DATA,
                    seq          = seq,
                    shard_idx    = shard_idx,
                    total_shards = total_shards,
                    session_id   = self.session_id,
                    transport    = common.TRANSPORT_QUIC,
                )
                quic_pkt = quic_hdr + orig_len_bytes + padded
                if self.obfs:
                    quic_pkt = common.salamander(quic_pkt, self.seed)
                try:
                    self.quic.send(quic_pkt)
                    self.cc.record_sent(len(quic_pkt))
                    if self.verbose:
                        log.debug(f"[QUIC] shard={shard_idx} sent {len(quic_pkt)}B")
                except Exception as e:
                    log.debug(f"[QUIC] shard {shard_idx}: {e}")

        rate, rtt = self.cc.stats()
        log.info(f"[BrutalCC] rate={rate:.0f}kbps  rtt={rtt:.0f}ms")
        self._record_metric("send_done", seq=seq, rate=rate, rtt=rtt)

    # ── Burst + hop + multi-dest ──────────────────────────────────────────────

    def _burst_send(self, pkt: bytes, shard_idx: int, seq: int,
                    hop_ms: int, burst_mult: int):
        """
        Send pkt x burst_mult times.
        Each copy goes to a DIFFERENT (deterministic) port.
        Copies are also spread across all destination IPs.
        Source port is randomized per packet if --rand-src-port is set.
        """
        dest_count = len(self.dest_ips)
        for burst in range(burst_mult):
            dest_ip  = self.dest_ips[burst % dest_count]
            dst_port = self._hop_port(shard_idx * burst_mult + burst, hop_ms)
            src_port = random.randint(1024, 65535) if self.rand_src else 0

            if self.verbose:
                log.debug(
                    f"[burst] shard={shard_idx} burst={burst} dest={dest_ip}:{dst_port} "
                    f"src={src_port if self.rand_src else 'auto'} len={len(pkt)}"
                )

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                if self.rand_src and src_port:
                    try:
                        s.bind(("", src_port))
                    except OSError:
                        pass   # port in use — OS picks one
                s.settimeout(0.05)
                s.sendto(pkt, (dest_ip, dst_port))
                s.close()
                self.cc.record_sent(len(pkt))
                if self.verbose:
                    log.debug(
                        f"  shard={shard_idx} burst={burst} "
                        f"-> {dest_ip}:{dst_port}"
                        + (f" src={src_port}" if self.rand_src else "")
                    )
            except Exception as e:
                if self.verbose:
                    log.exception(f"[burst] send {dest_ip}:{dst_port} failed: {e}")

    def _hop_port(self, offset: int, hop_ms: int) -> int:
        """
        Pre-emptive hopping with randomized interval (Hysteria2-style).
        Uses a jittered hop interval so ISPs can't fingerprint by timing.
        Both client and server derive the same jitter from the shared seed.
        """
        if self.mode == common.MODE_NORMAL or hop_ms == 0:
            return self.server_port
        if self.disable_hop:
            return self.server_port
        eff_ms = min(hop_ms, self.preemptive)
        # Use randomized slot on the shared wall-clock epoch.
        slot   = common.time_slot_randomized(eff_ms, self.seed, offset)
        port = common.deterministic_port(
            self.seed, slot, self.port_min, self.port_max
        )
        if self.verbose:
            log.debug(
                f"[hop] offset={offset} hop_ms={hop_ms} eff_ms={eff_ms} slot={slot} port={port}"
            )
        return port

    # ── Brutal CC feedback listener ───────────────────────────────────────────

    def _feedback_listener(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 0))
            sock.settimeout(1.0)
        except Exception as e:
            log.warning(f"[BrutalCC] listener init: {e}")
            return

        buf = bytearray(256)
        while self._running:
            try:
                n, _ = sock.recvfrom_into(buf)
                pkt  = bytes(buf[:n])
                if self.obfs:
                    pkt = common.salamander(pkt, self.seed)
                hdr, payload = common.unpack_header(pkt)
                if hdr and hdr["type"] == common.TYPE_BW_FEEDBACK:
                    fb = common.unpack_bw_feedback(payload)
                    if fb:
                        recv_kbps, rtt_ms, loss_pct = fb
                        self.cc.on_feedback(recv_kbps, rtt_ms, loss_pct)
                        log.info(
                            f"[BrutalCC] <- recv={recv_kbps}kbps "
                            f"rtt={rtt_ms}ms loss={loss_pct}% "
                            f"-> rate={self.cc.rate_kbps:.0f}kbps"
                        )
                        if self.verbose:
                            log.debug(f"[BrutalCC] feedback raw={fb}")
                        self._record_metric(
                            "bw_feedback",
                            recv_kbps=recv_kbps,
                            rtt_ms=rtt_ms,
                            loss_pct=loss_pct,
                        )
            except socket.timeout:
                pass
            except Exception as e:
                if self.verbose:
                    log.exception(f"[BrutalCC] feedback loop: {e}")

    # ── Monitor: re-probe every 30s and re-select best dest ──────────────────

    def _monitor_loop(self):
        while self._running:
            time.sleep(30)
            # Re-probe primary
            result = probe_port(
                self.primary_ip, self.server_port,
                count=10, timeout_ms=1500,
                seed=self.seed, obfs=self.obfs,
                verbose=self.verbose,
            )
            if self.verbose:
                log.debug(f"[monitor] probe result: {result}")
            self._record_metric("monitor_probe", **result)
            new_mode = common.classify_loss(result["loss_pct"])
            with self._mode_lock:
                old = self.mode
            if new_mode != old:
                log.info(
                    f"[monitor] {common.MODE_NAMES[old]} -> "
                    f"{common.MODE_NAMES[new_mode]} "
                    f"(loss={result['loss_pct']:.1f}%)"
                )
                self._set_mode(result["loss_pct"])

            # Re-select best destination if multiple available
            if len(self.dest_ips) > 1:
                best = self.resolver.best_destination(
                    self.dest_ips, self.server_port, self.seed, self.obfs,
                    verbose=self.verbose,
                )
                if best != self.primary_ip:
                    log.info(f"[monitor] switching primary: "
                             f"{self.primary_ip} -> {best}")
                    self.primary_ip = best
                    self._record_metric("primary_ip", ip=best)
                elif self.verbose:
                    log.debug(f"[monitor] primary unchanged: {self.primary_ip}")

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def stop(self):
        self._running = False
        if self.quic:
            self.quic.close()
        if self._metrics_fp:
            try:
                self._metrics_fp.close()
            except Exception:
                pass
        if self.verbose:
            log.debug("[client] shutdown complete")
        log.info("[client] stopped.")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="HopShot Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic
  python3 client.py --server 1.2.3.4 --port 10000 --seed "mysecret"

  # Multiple destinations (burst across all IPs simultaneously)
  python3 client.py --dest 1.2.3.4 --dest 5.6.7.8 --port 10000 --seed "s"

  # Custom DNS resolvers
  python3 client.py --server vpn.example.com --port 10000 \\
      --resolver 1.1.1.1 --resolver 8.8.8.8 --resolver 9.9.9.9

  # Full nuclear setup
  python3 client.py --server 1.2.3.4 --port 10000 --seed "s" \\
      --port-min 10000 --port-max 65000 --obfs \\
      --rand-src-port --jitter 64 --preemptive-hop 800

  # Send one message and exit
  python3 client.py --server 1.2.3.4 --port 10000 --seed "s" --msg "hello"
""")

    p.add_argument("--config",          default=None,
                   help="JSON config file")
    p.add_argument("--server",          default=None,
                   help="Server IP or hostname (single destination)")
    p.add_argument("--dest",            action="append", dest="destinations",
                   default=[], metavar="IP_OR_HOST",
                   help="Destination IP/hostname (repeat for multi-dest burst)")
    p.add_argument("--port",            type=int, default=10000,
                   help="Server base UDP port")
    p.add_argument("--quic-port",       type=int, default=None,
                   help="Server QUIC/TLS port (default: --port + 1)")
    p.add_argument("--port-min",        type=int, default=10000,
                   help="Hop port range minimum")
    p.add_argument("--port-max",        type=int, default=65000,
                   help="Hop port range maximum")
    p.add_argument("--seed",            default="hopshot-default-seed",
                   help="Shared secret seed (must match server)")
    p.add_argument("--profile",        choices=sorted(PROFILE_PRESETS.keys()),
                   default="balanced",
                   help="Preset profile: balanced, reliable, stealth, or throughput")
    p.add_argument("--obfs",            action="store_true",
                   help="Enable Salamander obfuscation")
    p.add_argument("--rand-src-port",   action="store_true",
                   help="[optional] Randomize UDP source port per packet")
    p.add_argument("--jitter",          type=int, default=64,
                   help="Packet size jitter: random padding bytes (0=off, default=64)")
    p.add_argument("--preemptive-hop",  type=int,
                   default=common.PREEMPTIVE_HOP_MS,
                   help=f"Pre-emptive hop interval ms (default={common.PREEMPTIVE_HOP_MS}). "
                        "Hop before ISP throttle window (~800ms beats most DPI)")
    p.add_argument("--declared-up",     type=int, default=0,
                   help="User-declared uplink bandwidth in kbps (0=auto). "
                        "Sets Brutal CC ceiling — prevents ISP QoS triggers. "
                        "Example: --declared-up 50000 for 50Mbps uplink.")
    p.add_argument("--masquerade",      action="store_true",
                   help="Wrap packets in HTTP/3 QUIC frames for DPI evasion")
    p.add_argument("--mtu",             type=int, default=0,
                   help="Override MTU payload size (0=auto-probe, default=0)")
    p.add_argument("--resolver",        action="append", dest="resolvers",
                   default=[], metavar="DNS_IP",
                   help="Custom DNS resolver IP (repeat for multiple, "
                        "e.g. --resolver 1.1.1.1 --resolver 9.9.9.9)")
    p.add_argument("--fec-k",           type=int, default=4,
                   help="FEC data shards (default=4)")
    p.add_argument("--fec-m",           type=int, default=4,
                   help="FEC parity shards (default=4)")
    p.add_argument("--probe-count",     type=int, default=20)
    p.add_argument("--probe-ms",        type=int, default=2000)
    p.add_argument("--log-file",       default=None,
                   help="Write logs to a file in addition to the terminal")
    p.add_argument("--json-logs",      action="store_true",
                   help="Write file logs as JSON lines")
    p.add_argument("--metrics-file",   default=None,
                   help="Append runtime metrics as JSON lines")
    p.add_argument("--diagnose",       action="store_true",
                   help="Print the resolved config and exit")
    p.add_argument("--msg",             default=None,
                   help="Single message to send and exit")
    p.add_argument("-v", "--verbose",   action="store_true")
    args = p.parse_args()

    # ── Build config ──────────────────────────────────────────────────────────
    cfg = {
        "server_port":       args.port,
        "quic_port":         args.quic_port or args.port + 1,
        "port_min":          args.port_min,
        "port_max":          args.port_max,
        "shared_seed":       args.seed,
        "profile":           args.profile,
        "obfs":              args.obfs,
        "rand_src_port":     args.rand_src_port,
        "jitter_bytes":      args.jitter,
        "preemptive_hop_ms": args.preemptive_hop,
        "declared_up_kbps":  args.declared_up,
        "masquerade":        args.masquerade,
        "mtu":               args.mtu,
        "fec_k":             args.fec_k,
        "fec_m":             args.fec_m,
        "probe_count":       args.probe_count,
        "probe_timeout_ms":  args.probe_ms,
        "verbose":           args.verbose,
        "resolvers":         args.resolvers or DEFAULT_RESOLVERS,
        "log_file":          args.log_file,
        "json_logs":         args.json_logs,
        "metrics_file":      args.metrics_file,
    }

    # Destinations: --dest wins over --server
    dests = list(args.destinations)
    if not dests and args.server:
        dests = [args.server]
    if not dests:
        p.error("Specify --server or at least one --dest")
    cfg["destinations"] = dests

    # JSON config overrides
    if args.config:
        with open(args.config) as f:
            cfg.update(json.load(f))

    cfg = apply_profile_overrides(cfg)

    configure_logging(args.verbose, log_file=cfg.get("log_file"), json_logs=cfg.get("json_logs", False))

    if args.verbose:
        log.debug("[client] cli config resolved")

    if args.diagnose:
        print(render_config_summary(cfg))
        return

    print(title("HopShot Client", "cyan"))
    print(colorize(f"profile: {cfg['profile']}", "green", bold=True))
    if cfg.get("disable_hop"):
        print(colorize("hop routing disabled by profile", "yellow", bold=True))

    # ── Start ──────────────────────────────────────────────────────────────────
    client = HopShotClient(cfg)
    client.start()

    if args.msg:
        client.send(args.msg.encode())
        time.sleep(1.5)
        client.stop()
        return

    log.info("Interactive mode — type a message and Enter. Ctrl+C to quit.")
    try:
        while True:
            try:
                line = input("> ")
                if line.strip():
                    client.send(line.encode())
            except EOFError:
                break
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()


if __name__ == "__main__":
    main()
