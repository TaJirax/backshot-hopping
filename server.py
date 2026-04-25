#!/usr/bin/env python3
"""
HopShot Server
==============
Implements the full server-side pipeline:

  iptables/nftables wide port range → this listener
         ↓
  Burst receiver (deduplicates redundant copies)
         ↓
  FEC decode (Reed-Solomon, reconstructs lost packets)
         ↓
  Brutal CC feedback loop (measures recv rate + loss → sends BWFeedback)
         ↓
  QUIC or raw UDP stream delivered to application

Both raw UDP and QUIC (TLS 1.3) transports run simultaneously.
The first copy of each payload to arrive wins.
"""

import argparse
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict

import common
import fec as fecmod
import brutal
from quic_transport import QUICServer, generate_selfsigned_cert
from http3_masq import HTTP3Masq
from session_resume import SessionTokenManager
from terminal_ui import configure_logging, colorize, title

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hopshot.server")


# ─── Shard group ──────────────────────────────────────────────────────────────

class ShardGroup:
    __slots__ = ("shards", "orig_len", "total", "received", "delivered", "ts")

    def __init__(self, total: int, orig_len: int):
        self.shards    = [None] * total
        self.orig_len  = orig_len
        self.total     = total
        self.received  = 0
        self.delivered = False
        self.ts        = time.monotonic()


# ─── Session ──────────────────────────────────────────────────────────────────

class Session:
    def __init__(self, session_id: int, addr, declared_down_kbps: float = 0):
        self.session_id = session_id
        self.addr       = addr
        self.groups     = {}          # seq → ShardGroup
        self.lock       = threading.Lock()
        self.last_seen  = time.monotonic()
        self.receiver   = brutal.BrutalReceiver(
            declared_down_kbps=declared_down_kbps
        )


# ─── Server ───────────────────────────────────────────────────────────────────

class HopShotServer:

    def __init__(self, cfg: dict):
        self.cfg         = cfg
        self.seed        = cfg["shared_seed"].encode()
        self.obfs        = cfg.get("obfs", False)
        self.fec_k       = cfg.get("fec_k", 4)
        self.fec_m       = cfg.get("fec_m", 4)
        self.jitter      = cfg.get("jitter_bytes", 64)
        self.verbose     = cfg.get("verbose", False)
        self.listen_port = cfg.get("listen_port", 10000)
        self.quic_port   = cfg.get("quic_port", 10001)
        self.port_min    = cfg.get("port_min", 10000)
        self.port_max    = cfg.get("port_max", 65000)
        self.certfile    = cfg.get("certfile", "/tmp/hopshot.crt")
        self.keyfile     = cfg.get("keyfile",  "/tmp/hopshot.key")
        self.declared_down_kbps = cfg.get("declared_down_kbps", 0)

        self.sessions    = {}         # session_id → Session
        self.sess_lock   = threading.Lock()
        self.delivered   = set()      # (session_id, seq) already delivered
        self.del_lock    = threading.Lock()
        self._running    = False
        self.masquerade  = cfg.get("masquerade", False)

        # 0-RTT session resumption (TUIC-style)
        self._token_mgr  = SessionTokenManager(self.seed)

        # Raw UDP socket
        self.udp_sock = None

        # QUIC server
        self.quic_srv = None

        if self.verbose:
            log.debug(
                "[server] config: "
                f"listen={self.listen_port} quic={self.quic_port} "
                f"port_range={self.port_min}-{self.port_max} obfs={self.obfs} "
                f"masq={self.masquerade} jitter={self.jitter} "
                f"declared_down={self.declared_down_kbps} fec={self.fec_k}x{self.fec_m}"
            )

    # ── Startup ───────────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        if self.verbose:
            log.debug("[server] startup phase=udp-bind")

        # Raw UDP
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock.bind(("0.0.0.0", self.listen_port))
        log.info(f"Raw UDP listening on :{self.listen_port}")

        # QUIC (TLS 1.3)
        try:
            if self.verbose:
                log.debug("[server] startup phase=quic-listen")
            generate_selfsigned_cert(self.certfile, self.keyfile)
            self.quic_srv = QUICServer(
                "0.0.0.0", self.quic_port, self.certfile, self.keyfile
            )
            self.quic_srv.data_callback = self._on_quic_data
            self.quic_srv.start()
            log.info(f"QUIC (TLS 1.3) listening on :{self.quic_port}")
        except Exception as e:
            log.warning(f"QUIC init failed (continuing raw-UDP only): {e}")

        # iptables
        if self.cfg.get("setup_iptables", False):
            self._setup_iptables()

        # Threads
        threading.Thread(target=self._udp_loop,     daemon=True).start()
        threading.Thread(target=self._cleanup_loop,  daemon=True).start()

        log.info("Server ready.")

    # ── UDP receive loop ──────────────────────────────────────────────────────

    def _udp_loop(self):
        buf = bytearray(common.MAX_PACKET + 64)
        while self._running:
            try:
                n, addr = self.udp_sock.recvfrom_into(buf)
                pkt = bytes(buf[:n])
                if self.verbose:
                    log.debug(f"[UDP] rx {n}B from {addr}")
                threading.Thread(
                    target=self._handle_udp,
                    args=(pkt, addr),
                    daemon=True,
                ).start()
            except Exception as e:
                if self._running:
                    if self.verbose:
                        log.exception(f"[UDP] receive loop: {e}")

    def _handle_udp(self, pkt: bytes, addr):
        # ── HTTP/3 masquerade unwrap ──────────────────────────────────────────
        if self.masquerade and HTTP3Masq.is_masqueraded(pkt):
            if self.verbose:
                log.debug(f"[UDP] masquerade candidate {len(pkt)}B from {addr}")
            unwrapped = HTTP3Masq.unwrap(pkt, self.seed)
            if unwrapped:
                pkt = unwrapped
                if self.verbose:
                    log.debug(f"[UDP] masquerade unwrap ok -> {len(pkt)}B")
            elif self.verbose:
                log.debug("[UDP] masquerade unwrap failed; treating as plain packet")
            # If unwrap failed, fall through — may be a plain packet

        if self.obfs:
            pkt = common.salamander(pkt, self.seed)

        hdr, payload = common.unpack_header(pkt)
        if hdr is None:
            if self.verbose:
                log.debug(f"[UDP] dropped undecodable packet {len(pkt)}B from {addr}")
            return

        t = hdr["type"]
        if self.verbose:
            log.debug(
                f"[UDP] type={t} seq={hdr['seq']} sess={hdr['session_id']} "
                f"shard={hdr['shard_idx']}/{hdr['total_shards']} transport={hdr['transport']}"
            )
        if t == common.TYPE_PROBE:
            self._handle_probe(hdr, addr, common.TRANSPORT_RAW)
        elif t == common.TYPE_DATA:
            self._handle_data(hdr, payload, addr, common.TRANSPORT_RAW)
        elif t == common.TYPE_MTU_PROBE:
            # MTU probe: echo back with the size we actually received
            self._handle_mtu_probe(hdr, payload, addr, len(pkt))

    # ── QUIC receive ──────────────────────────────────────────────────────────

    def _on_quic_data(self, session_id, data: bytes):
        """Called by QUICServer for each received TLS record."""
        if self.obfs:
            data = common.salamander(data, self.seed)
        if self.verbose:
            log.debug(f"[QUIC] rx session={session_id} {len(data)}B")

        hdr, payload = common.unpack_header(data)
        if hdr is None:
            if self.verbose:
                log.debug(f"[QUIC] undecodable session={session_id} {len(data)}B")
            return

        hdr["transport"] = common.TRANSPORT_QUIC
        t = hdr["type"]
        if t == common.TYPE_DATA:
            self._handle_data(hdr, payload, None, common.TRANSPORT_QUIC)

    # ── Probe handler ─────────────────────────────────────────────────────────

    def _handle_probe(self, hdr: dict, addr, transport: int):
        reply = common.pack_header(
            pkt_type   = common.TYPE_PROBE_REPLY,
            seq        = hdr["seq"],
            session_id = hdr["session_id"],
            transport  = transport,
        )
        # Issue a 0-RTT session token alongside first probe reply
        token = self._token_mgr.issue(hdr["session_id"])
        reply = reply + token   # append token so client can cache it
        if self.verbose:
            log.debug(
                f"[probe] reply seq={hdr['seq']} sess={hdr['session_id']} "
                f"addr={addr} token={len(token)}B transport={transport}"
            )

        if self.obfs:
            reply = common.salamander(reply, self.seed)
        try:
            self.udp_sock.sendto(reply, addr)
        except Exception:
            pass
        if self.verbose:
            log.debug(f"Probe reply (with 0-RTT token) → {addr} seq={hdr['seq']}")

    def _handle_mtu_probe(self, hdr: dict, payload: bytes, addr, recv_size: int):
        """Echo back an MTU_REPLY carrying the received size."""
        reply_hdr = common.pack_header(
            pkt_type   = common.TYPE_MTU_REPLY,
            seq        = hdr["seq"],
            session_id = hdr.get("session_id", 0),
        )
        # Carry received size in first 2 bytes of reply payload
        import struct as _struct
        reply = reply_hdr + _struct.pack("!H", recv_size)
        if self.verbose:
            log.debug(f"[MTU] reply seq={hdr['seq']} size={recv_size} addr={addr}")
        if self.obfs:
            reply = common.salamander(reply, self.seed)
        try:
            self.udp_sock.sendto(reply, addr)
        except Exception:
            pass
        if self.verbose:
            log.debug(f"MTU reply → {addr} size={recv_size}")

    # ── Data handler ──────────────────────────────────────────────────────────

    def _handle_data(self, hdr: dict, payload: bytes, addr, transport: int):
        if len(payload) < 4:
            if self.verbose:
                log.debug(f"[DATA] short payload seq={hdr['seq']} len={len(payload)}")
            return

        orig_len   = struct.unpack_from("!I", payload)[0]
        shard_data = common.strip_jitter_padding(payload[4:], max_jitter=self.jitter)
        seq        = hdr["seq"]
        shard_idx  = hdr["shard_idx"]
        total      = hdr["total_shards"]
        sid        = hdr["session_id"]

        # Brutal CC measurement
        sess = self._get_session(sid, addr)
        sess.last_seen = time.monotonic()
        sess.receiver.on_packet(seq, len(payload))

        if self.verbose:
            log.debug(
                f"[DATA] seq={seq} sess={sid} shard={shard_idx}/{total} "
                f"orig_len={orig_len} payload_len={len(payload)} transport={transport}"
            )

        with sess.lock:
            grp = sess.groups.get(seq)
            if grp is None:
                grp = ShardGroup(total, orig_len)
                sess.groups[seq] = grp

            if grp.delivered:
                if self.verbose:
                    log.debug(f"[DATA] duplicate after delivery seq={seq}")
                return  # duplicate after delivery — discard

            if grp.shards[shard_idx] is not None:
                if self.verbose:
                    log.debug(f"[DATA] duplicate shard seq={seq} shard={shard_idx}")
                return  # duplicate shard — discard

            grp.shards[shard_idx] = shard_data
            grp.received += 1

            if self.verbose:
                stack = "QUIC" if transport == common.TRANSPORT_QUIC else "UDP"
                log.debug(
                    f"[{stack}] shard {shard_idx+1}/{total} "
                    f"seq={seq} sess={sid} ({grp.received} present)"
                )

            # Try reconstruct as soon as we have k shards
            if grp.received >= self.fec_k:
                try:
                    recovered = fecmod.reconstruct_data(
                        grp.shards, self.fec_k, self.fec_m, grp.orig_len
                    )
                    grp.delivered = True
                    stack = "QUIC" if transport == common.TRANSPORT_QUIC else "UDP"
                    log.info(
                        f"✓ [{stack}] delivered {len(recovered)} bytes "
                        f"seq={seq} shards={grp.received}/{total}"
                    )
                    self._on_payload(sid, recovered, addr, transport, sess)
                except Exception as e:
                    if self.verbose:
                        log.exception(f"[DATA] FEC reconstruct seq={seq}: {e}")

    def _on_payload(self, sid, data: bytes, addr, transport, sess: Session):
        """Application delivery point — prints received payload."""
        print(f"\n[DELIVERED] {len(data)} bytes: {data!r}\n")
        if self.verbose:
            log.debug(f"[PAYLOAD] sess={sid} transport={transport} bytes={len(data)}")

        # Send Brutal CC feedback back to client
        fb = sess.receiver.feedback()
        if fb and addr:
            recv_kbps, rtt_ms, loss_pct = fb
            bw_payload = common.pack_bw_feedback(recv_kbps, rtt_ms, loss_pct)
            reply_hdr  = common.pack_header(
                pkt_type   = common.TYPE_BW_FEEDBACK,
                seq        = 0,
                session_id = sid,
                transport  = transport,
            )
            pkt = reply_hdr + bw_payload
            if self.obfs:
                pkt = common.salamander(pkt, self.seed)
            try:
                self.udp_sock.sendto(pkt, addr)
            except Exception:
                pass
            log.info(
                f"[BrutalCC] feedback → sess={sid} "
                f"recv={recv_kbps}kbps rtt={rtt_ms}ms loss={loss_pct}%"
            )
        elif self.verbose:
            log.debug(f"[BrutalCC] no feedback sent sess={sid} addr={addr} fb={fb}")

    # ── Brutal CC feedback loop (background, every 200ms) ────────────────────

    def _feedback_loop(self):
        while self._running:
            time.sleep(brutal.FEEDBACK_INTERVAL)
            with self.sess_lock:
                sessions = list(self.sessions.values())
            for sess in sessions:
                fb = sess.receiver.feedback()
                if fb is None or sess.addr is None:
                    if self.verbose and fb is None:
                        log.debug(f"[BrutalCC] skip sess={sess.session_id} no feedback yet")
                    continue
                recv_kbps, rtt_ms, loss_pct = fb
                if recv_kbps == 0:
                    if self.verbose:
                        log.debug(f"[BrutalCC] skip sess={sess.session_id} zero rate")
                    continue
                bw_payload = common.pack_bw_feedback(recv_kbps, rtt_ms, loss_pct)
                reply_hdr  = common.pack_header(
                    pkt_type   = common.TYPE_BW_FEEDBACK,
                    seq        = 0,
                    session_id = sess.session_id,
                )
                pkt = reply_hdr + bw_payload
                if self.obfs:
                    pkt = common.salamander(pkt, self.seed)
                try:
                    self.udp_sock.sendto(pkt, sess.addr)
                except Exception:
                    if self.verbose:
                        log.exception(f"[BrutalCC] feedback send failed sess={sess.session_id}")

    # ── Session management ────────────────────────────────────────────────────

    def _get_session(self, sid: int, addr) -> Session:
        with self.sess_lock:
            if sid not in self.sessions:
                self.sessions[sid] = Session(
                    sid, addr, self.declared_down_kbps
                )
                if self.verbose:
                    log.debug(f"[session] created sid={sid} addr={addr}")
            elif addr and self.sessions[sid].addr is None:
                self.sessions[sid].addr = addr
                if self.verbose:
                    log.debug(f"[session] bound sid={sid} addr={addr}")
            return self.sessions[sid]

    def _cleanup_loop(self):
        while self._running:
            time.sleep(10)
            now = time.monotonic()
            with self.sess_lock:
                dead = [
                    sid for sid, s in self.sessions.items()
                    if now - s.last_seen > 60
                ]
                for sid in dead:
                    del self.sessions[sid]
                    if self.verbose:
                        log.debug(f"[cleanup] removed idle session sid={sid}")
            # Trim old shard groups inside sessions
            with self.sess_lock:
                sessions = list(self.sessions.values())
            for sess in sessions:
                with sess.lock:
                    old = [
                        seq for seq, grp in sess.groups.items()
                        if now - grp.ts > 10
                    ]
                    for seq in old:
                        del sess.groups[seq]
                        if self.verbose:
                            log.debug(f"[cleanup] removed shard group sid={sess.session_id} seq={seq}")

    # ── iptables ──────────────────────────────────────────────────────────────

    def _setup_iptables(self):
        rule = [
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "udp",
            "--dport", f"{self.port_min}:{self.port_max}",
            "-j", "REDIRECT", "--to-port", str(self.listen_port),
        ]
        try:
            subprocess.run(rule, check=True, capture_output=True)
            log.info(
                f"iptables: UDP {self.port_min}-{self.port_max} → {self.listen_port}"
            )
        except Exception as e:
            log.warning(f"iptables failed (need root?): {e}")

    def _remove_iptables(self):
        rule = [
            "iptables", "-t", "nat", "-D", "PREROUTING",
            "-p", "udp",
            "--dport", f"{self.port_min}:{self.port_max}",
            "-j", "REDIRECT", "--to-port", str(self.listen_port),
        ]
        try:
            subprocess.run(rule, check=True, capture_output=True)
            log.info("iptables rules removed")
        except Exception:
            pass

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def stop(self):
        self._running = False
        try:
            self.udp_sock.close()
        except Exception:
            pass
        if self.quic_srv:
            self.quic_srv.stop()
        if self.cfg.get("setup_iptables", False):
            self._remove_iptables()
        if self.verbose:
            log.debug("[server] shutdown complete")
        log.info("Server stopped.")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HopShot Server")
    parser.add_argument("--config",       default=None,    help="JSON config file")
    parser.add_argument("--port",         type=int, default=10000, help="Raw UDP listen port")
    parser.add_argument("--quic-port",    type=int, default=10001, help="QUIC/TLS listen port")
    parser.add_argument("--port-min",     type=int, default=10000, help="Hop range min")
    parser.add_argument("--port-max",     type=int, default=65000, help="Hop range max")
    parser.add_argument("--seed",         default="hopshot-default-seed", help="Shared secret seed")
    parser.add_argument("--obfs",         action="store_true", help="Salamander obfuscation")
    parser.add_argument("--masquerade",   action="store_true", help="HTTP/3 masquerading (DPI evasion)")
    parser.add_argument("--iptables",     action="store_true", help="Auto-setup iptables redirect")
    parser.add_argument("--certfile",     default="/tmp/hopshot.crt")
    parser.add_argument("--keyfile",      default="/tmp/hopshot.key")
    parser.add_argument("--declared-down", type=int, default=0,
                        help="User-declared downlink bandwidth in kbps (0=auto)")
    parser.add_argument("--jitter",       type=int, default=64,
                        help="Jitter strip bytes (must match client --jitter, 0=off)")
    parser.add_argument("--log-file",     default=None,
                        help="Write logs to a file in addition to the terminal")
    parser.add_argument("--json-logs",    action="store_true",
                        help="Write file logs as JSON lines")
    parser.add_argument("--diagnose",     action="store_true",
                        help="Print the resolved config and exit")
    parser.add_argument("-v", "--verbose",action="store_true")
    args = parser.parse_args()

    cfg = {
        "listen_port":    args.port,
        "quic_port":      args.quic_port,
        "port_min":       args.port_min,
        "port_max":       args.port_max,
        "shared_seed":    args.seed,
        "obfs":           args.obfs,
        "masquerade":     args.masquerade,
        "fec_k":          4,
        "fec_m":          4,
        "setup_iptables": args.iptables,
        "certfile":       args.certfile,
        "keyfile":        args.keyfile,
        "declared_down_kbps": args.declared_down,
        "verbose":        args.verbose,
        "jitter_bytes":   args.jitter,
        "log_file":       args.log_file,
        "json_logs":      args.json_logs,
    }

    if args.config:
        with open(args.config) as f:
            cfg.update(json.load(f))

    configure_logging(args.verbose, log_file=cfg.get("log_file"), json_logs=cfg.get("json_logs", False))

    print(title("HopShot Server", "cyan"))
    print(colorize(f"listen: {cfg['listen_port']}  quic: {cfg['quic_port']}", "green", bold=True))
    print(colorize(f"mode: obfs={cfg['obfs']} masq={cfg['masquerade']} jitter={cfg['jitter_bytes']}", "blue"))

    if args.diagnose:
        print(json.dumps(cfg, indent=2, sort_keys=True))
        return

    if args.verbose:
        log.debug(
            "[server] cli config: "
            f"listen={cfg['listen_port']} quic={cfg['quic_port']} "
            f"port_range={cfg['port_min']}-{cfg['port_max']} obfs={cfg['obfs']} "
            f"masq={cfg['masquerade']} declared_down={cfg['declared_down_kbps']} "
            f"jitter={cfg['jitter_bytes']} fec={cfg['fec_k']}x{cfg['fec_m']}"
        )

    srv = HopShotServer(cfg)
    srv.start()

    # Also start the Brutal CC background feedback loop
    threading.Thread(target=srv._feedback_loop, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        srv.stop()


if __name__ == "__main__":
    main()
