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
from session_resume import SessionTokenManager, TOKEN_SIZE
from tunnel_codec import encode_datagrams
from tun_transport import TunTapConfig, TunTapDevice, TunTapError
from terminal_ui import configure_logging, key_value, section_header, supports_color, title
from version import __version__

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hopshot.server")


def _parse_udp_endpoint(value: str | None, default_host: str, default_port: int) -> tuple[str, int]:
    text = str(value or "").strip()
    if not text:
        return default_host, default_port
    if ":" not in text:
        raise ValueError(f"Invalid endpoint '{text}', expected host:port")
    host, port_text = text.rsplit(":", 1)
    host = host.strip() or default_host
    try:
        port = int(port_text)
    except ValueError as e:
        raise ValueError(f"Invalid endpoint '{text}', bad port") from e
    if port < 1 or port > 65535:
        raise ValueError(f"Invalid endpoint '{text}', port out of range")
    return host, port


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
        self.reply_addr = addr
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
        self.max_ping_ms = int(cfg.get("max_ping_ms", 15000) or 15000)
        self.session_timeout_sec = max(60, int((self.max_ping_ms * 3) / 1000))
        self.tunnel_mode = cfg.get("tunnel_mode", "off")
        self.tunnel_iface = cfg.get("tunnel_iface", "hopshot0")
        self.tunnel_mtu   = cfg.get("tunnel_mtu", 1400)
        self.tunnel_addr  = cfg.get("tunnel_address")
        self.tunnel_peer  = cfg.get("tunnel_peer")
        self.tunnel_route_default = cfg.get("tunnel_route_default", False)
        self.tunnel_udp_bind = cfg.get("tunnel_udp_bind", "127.0.0.1:19091")
        self.tunnel_udp_target = cfg.get("tunnel_udp_target")
        self._tunnel_udp_target_addr = None
        self._tunnel_udp_last_peer = None

        self.sessions    = {}         # session_id → Session
        self.sess_lock   = threading.Lock()
        self.delivered   = set()      # (session_id, seq) already delivered
        self.del_lock    = threading.Lock()
        self._running    = False
        self.masquerade  = cfg.get("masquerade", False)
        self._tun_seq    = 0
        self._tun_seq_lock = threading.Lock()
        self._tunnel_session_id = None

        # 0-RTT session resumption (TUIC-style)
        self._token_mgr  = SessionTokenManager(self.seed)

        # Raw UDP socket
        self.udp_sock = None
        self.extra_udp_socks = []

        # QUIC server
        self.quic_srv = None
        self._tunnel = None
        self._tunnel_udp_sock = None

        if self.tunnel_mode in {"tun", "tap"}:
            try:
                self._tunnel = TunTapDevice.open(TunTapConfig(
                    name=self.tunnel_iface,
                    mode=self.tunnel_mode,
                    mtu=self.tunnel_mtu,
                    address=self.tunnel_addr,
                    peer=self.tunnel_peer,
                    up=True,
                    route_default=self.tunnel_route_default,
                ))
            except TunTapError as e:
                raise RuntimeError(f"Failed to initialize tunnel device: {e}") from e
        elif self.tunnel_mode == "udp":
            bind_addr = _parse_udp_endpoint(self.tunnel_udp_bind, "127.0.0.1", 19091)
            self._tunnel_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._tunnel_udp_sock.bind(bind_addr)
            self._tunnel_udp_sock.settimeout(1.0)
            self._tunnel_udp_target_addr = _parse_udp_endpoint(self.tunnel_udp_target, "127.0.0.1", 19090) if self.tunnel_udp_target else None
            log.info(f"[tunnel-udp] local relay bind={bind_addr[0]}:{bind_addr[1]} target={self._tunnel_udp_target_addr}")
        elif self.tunnel_mode != "off":
            raise RuntimeError(f"Unsupported tunnel_mode: {self.tunnel_mode}")

        if self.verbose:
            log.debug(
                "[server] config: "
                f"listen={self.listen_port} quic={self.quic_port} "
                f"port_range={self.port_min}-{self.port_max} obfs={self.obfs} "
                f"masq={self.masquerade} jitter={self.jitter} "
                f"declared_down={self.declared_down_kbps} fec={self.fec_k}x{self.fec_m} "
                f"tunnel={self.tunnel_mode} iface={self.tunnel_iface} "
                f"tunnel_udp_bind={self.tunnel_udp_bind} tunnel_udp_target={self.tunnel_udp_target} "
                f"max_ping_ms={self.max_ping_ms} session_timeout={self.session_timeout_sec}s"
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

        iptables_ok = False
        if self.cfg.get("setup_iptables", False):
            iptables_ok = self._setup_iptables()
            if not iptables_ok:
                log.warning(
                    "[compat] iptables redirect unavailable; falling back to direct UDP binds"
                )
                self._bind_additional_udp_ports_if_needed(force=True)
        else:
            self._bind_additional_udp_ports_if_needed()

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

        # Threads
        threading.Thread(target=self._udp_loop,     daemon=True).start()
        for idx, extra_sock in enumerate(self.extra_udp_socks):
            threading.Thread(
                target=self._udp_loop_on_socket,
                args=(extra_sock, f"extra-{idx}"),
                daemon=True,
            ).start()
        threading.Thread(target=self._feedback_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop,  daemon=True).start()
        if self.tunnel_mode != "off":
            threading.Thread(target=self._tunnel_tx_loop, daemon=True).start()

        log.info("Server ready.")

    # ── UDP receive loop ──────────────────────────────────────────────────────

    def _bind_additional_udp_ports_if_needed(self, force: bool = False):
        if self.cfg.get("setup_iptables", False) and not force:
            return

        auto_bind = self.cfg.get("auto_bind_port_range", True)
        if not auto_bind:
            if self.port_min != self.listen_port or self.port_max != self.listen_port:
                log.warning(
                    "[compat] auto_bind_port_range disabled and no iptables redirect; "
                    "hopping/range probes may fail unless upstream NAT forwards the full port range"
                )
            return

        span = self.port_max - self.port_min + 1
        max_bind_raw = self.cfg.get("auto_bind_port_range_max", 0)
        try:
            max_bind = int(max_bind_raw)
        except Exception:
            max_bind = 0
        if span <= 1:
            return
        if max_bind > 0 and span > max_bind:
            log.warning(
                f"[compat] port range span={span} too large for direct bind limit={max_bind}; "
                "configure setup_iptables=true or narrow the port range"
            )
            return

        for port in range(self.port_min, self.port_max + 1):
            if port == self.listen_port:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                self.extra_udp_socks.append(s)
            except Exception as e:
                log.warning(f"[compat] unable to bind extra UDP port {port}: {e}")

        if self.extra_udp_socks:
            log.info(
                f"[compat] bound {len(self.extra_udp_socks)} extra UDP ports "
                f"for direct range handling ({self.port_min}-{self.port_max})"
            )

    def _udp_loop(self):
        self._udp_loop_on_socket(self.udp_sock, "primary")

    def _udp_loop_on_socket(self, recv_sock: socket.socket, label: str):
        buf = bytearray(common.MAX_PACKET + 64)
        while self._running:
            try:
                n, addr = recv_sock.recvfrom_into(buf)
                pkt = bytes(buf[:n])
                if self.verbose:
                    log.debug(f"[UDP:{label}] rx {n}B from {addr}")
                threading.Thread(
                    target=self._handle_udp,
                    args=(pkt, addr, recv_sock),
                    daemon=True,
                ).start()
            except Exception as e:
                if self._running:
                    if self.verbose:
                        log.exception(f"[UDP:{label}] receive loop: {e}")

    def _handle_udp(self, pkt: bytes, addr, recv_sock: socket.socket):
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
            self._handle_probe(hdr, addr, common.TRANSPORT_RAW, tx_sock=recv_sock)
        elif t == common.TYPE_RESUME:
            self._handle_resume(hdr, payload, addr, common.TRANSPORT_RAW, tx_sock=recv_sock)
        elif t == common.TYPE_DATA:
            self._handle_data(hdr, payload, addr, common.TRANSPORT_RAW, tx_sock=recv_sock)
        elif t == common.TYPE_MTU_PROBE:
            # MTU probe: echo back with the size we actually received
            self._handle_mtu_probe(hdr, payload, addr, len(pkt), tx_sock=recv_sock)
        elif t == common.TYPE_KEEPALIVE:
            self._handle_keepalive(hdr, addr)

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
        elif t == common.TYPE_KEEPALIVE:
            self._handle_keepalive(hdr, None)

    # ── Probe handler ─────────────────────────────────────────────────────────

    def _handle_probe(self, hdr: dict, addr, transport: int, tx_sock: socket.socket | None = None):
        tx_sock = tx_sock or self.udp_sock
        reply = common.pack_header(
            pkt_type   = common.TYPE_PROBE_REPLY,
            seq        = hdr["seq"],
            session_id = hdr["session_id"],
            transport  = transport,
        )
        # Issue a 0-RTT session token alongside first probe reply
        token = self._token_mgr.issue(hdr["session_id"])
        server_ts = struct.pack("!Q", int(time.time() * 1000))
        reply = reply + token + server_ts   # append token and server clock sample
        if self.verbose:
            log.debug(
                f"[probe] reply seq={hdr['seq']} sess={hdr['session_id']} "
                f"addr={addr} token={len(token)}B transport={transport} ts={int(time.time() * 1000)}"
            )

        if self.obfs:
            reply = common.salamander(reply, self.seed)
        try:
            tx_sock.sendto(reply, addr)
        except Exception:
            pass
        if self.verbose:
            log.debug(f"Probe reply (with 0-RTT token + clock sample) → {addr} seq={hdr['seq']}")

    def _handle_keepalive(self, hdr: dict, addr):
        sess = self._get_session(hdr.get("session_id", 0), addr)
        sess.last_seen = time.monotonic()
        if self.verbose:
            log.debug(f"[keepalive] sid={hdr.get('session_id', 0)} addr={addr}")

    def _handle_resume(self, hdr: dict, payload: bytes, addr, transport: int, tx_sock: socket.socket | None = None):
        tx_sock = tx_sock or self.udp_sock
        sid = hdr.get("session_id", 0)
        if len(payload) < TOKEN_SIZE:
            if self.verbose:
                log.debug(f"[resume] short token sid={sid} len={len(payload)}")
            return

        token = payload[:TOKEN_SIZE]
        if not self._token_mgr.verify(token, sid):
            if self.verbose:
                log.debug(f"[resume] token verify failed sid={sid} addr={addr}")
            return

        sess = self._get_session(sid, addr)
        sess.last_seen = time.monotonic()

        # Rotate token on successful resume.
        new_token = self._token_mgr.issue(sid)
        server_ts = struct.pack("!Q", int(time.time() * 1000))
        ack = common.pack_header(
            pkt_type=common.TYPE_RESUME_ACK,
            seq=hdr.get("seq", 0),
            session_id=sid,
            transport=transport,
        ) + new_token + server_ts

        if self.obfs:
            ack = common.salamander(ack, self.seed)
        try:
            tx_sock.sendto(ack, addr)
            log.info(f"[resume] accepted sid={sid} addr={addr}")
        except Exception:
            pass

    def _send_tunnel_payload(self, payload: bytes, sess: Session):
        target_addr = sess.reply_addr or sess.addr
        if target_addr is None:
            return

        with self._tun_seq_lock:
            self._tun_seq = (self._tun_seq + 1) & 0xFFFFFFFF
            seq = self._tun_seq

        encoded = encode_datagrams(
            payload=payload,
            seq=seq,
            session_id=sess.session_id,
            seed=self.seed,
            fec_k=self.fec_k,
            fec_m=self.fec_m,
            jitter=self.jitter,
            obfs=self.obfs,
            masquerade=self.masquerade,
            transport=common.TRANSPORT_RAW,
        )

        for pkt in encoded.datagrams:
            try:
                self.udp_sock.sendto(pkt, target_addr)
            except Exception:
                if self.verbose:
                    log.exception(f"[tunnel] send failed sess={sess.session_id} addr={target_addr}")

    def _tunnel_tx_loop(self):
        """Read IP packets from server TUN device and send them to connected clients."""
        if self._tunnel is None and self._tunnel_udp_sock is None:
            return

        while self._running:
            try:
                if self._tunnel is not None:
                    pkt = self._tunnel.read(65535)
                else:
                    pkt, peer = self._tunnel_udp_sock.recvfrom(65535)
                    self._tunnel_udp_last_peer = peer
                if not pkt:
                    continue
                # Forward TUN packets to all active tunnel sessions via the send pipeline
                with self.sess_lock:
                    sessions = list(self.sessions.values())
                    if self._tunnel_session_id is not None and self._tunnel_session_id in self.sessions:
                        sessions = [self.sessions[self._tunnel_session_id]]
                # Send to each session's client using the full FEC pipeline
                for sess in sessions:
                    if sess.addr is not None:
                        self._send_tunnel_payload(pkt, sess)
            except socket.timeout:
                pass
            except Exception as e:
                if self._running and self.verbose:
                    log.exception(f"[tunnel] tx loop: {e}")

    def _handle_mtu_probe(self, hdr: dict, payload: bytes, addr, recv_size: int, tx_sock: socket.socket | None = None):
        tx_sock = tx_sock or self.udp_sock
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
            tx_sock.sendto(reply, addr)
        except Exception:
            pass
        if self.verbose:
            log.debug(f"MTU reply → {addr} size={recv_size}")

    # ── Data handler ──────────────────────────────────────────────────────────

    def _handle_data(self, hdr: dict, payload: bytes, addr, transport: int, tx_sock: socket.socket | None = None):
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
        if addr is not None:
            # Keep tunnel return path pinned to the latest data socket, not
            # transient probe/keepalive source ports.
            sess.reply_addr = addr

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
                    self._on_payload(sid, recovered, addr, transport, sess, tx_sock=tx_sock)
                except Exception as e:
                    if self.verbose:
                        log.exception(f"[DATA] FEC reconstruct seq={seq}: {e}")

    def _on_payload(self, sid, data: bytes, addr, transport, sess: Session, tx_sock: socket.socket | None = None):
        """Application delivery point — reconstruct complete IP packets from FEC shards.
        
        If TUN mode is active, write reconstructed IP packets back to the server's TUN device
        so they can be processed by local applications. Otherwise, print for testing.
        """
        tx_sock = tx_sock or self.udp_sock
        
        # Write reconstructed payload to tunnel backend
        if self._tunnel is not None:
            try:
                self._tunnel.write(data)
                if self.verbose:
                    log.debug(f"[tunnel] delivered {len(data)}B from session={sid} to TUN device")
            except Exception as e:
                if self.verbose:
                    log.exception(f"[tunnel] write failed sid={sid}: {e}")
        elif self._tunnel_udp_sock is not None:
            target = self._tunnel_udp_target_addr or self._tunnel_udp_last_peer
            if target:
                try:
                    self._tunnel_udp_sock.sendto(data, target)
                    if self.verbose:
                        log.debug(f"[tunnel-udp] delivered {len(data)}B sid={sid} -> {target}")
                except Exception as e:
                    if self.verbose:
                        log.exception(f"[tunnel-udp] delivery failed sid={sid}: {e}")
        else:
            # Non-TUN mode: print reconstructed payload for testing
            print(f"\n[DELIVERED] {len(data)} bytes: {data!r}\n")
        
        if self.verbose:
            log.debug(f"[PAYLOAD] sess={sid} transport={transport} bytes={len(data)}")

        # Send Brutal CC feedback back to client
        fb = sess.receiver.feedback()
        feedback_addr = sess.reply_addr or addr or sess.addr
        if fb and feedback_addr:
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
                tx_sock.sendto(pkt, feedback_addr)
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
                target_addr = sess.reply_addr or sess.addr
                if fb is None or target_addr is None:
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
                    self.udp_sock.sendto(pkt, target_addr)
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
                if self.tunnel_mode != "off" and self._tunnel_session_id is None:
                    self._tunnel_session_id = sid
            elif addr and self.sessions[sid].addr != addr:
                self.sessions[sid].addr = addr
                if self.verbose:
                    log.debug(f"[session] updated sid={sid} new_addr={addr}")
                if self.tunnel_mode != "off" and self._tunnel_session_id is None:
                    self._tunnel_session_id = sid
            return self.sessions[sid]

    def _cleanup_loop(self):
        while self._running:
            time.sleep(10)
            now = time.monotonic()
            with self.sess_lock:
                dead = [
                    sid for sid, s in self.sessions.items()
                    if now - s.last_seen > self.session_timeout_sec
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

    def _setup_iptables(self) -> bool:
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
            return True
        except Exception as e:
            log.warning(f"iptables failed (need root?): {e}")
            return False

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
        for s in self.extra_udp_socks:
            try:
                s.close()
            except Exception:
                pass
        self.extra_udp_socks = []
        if self.quic_srv:
            self.quic_srv.stop()
        if self._tunnel:
            try:
                self._tunnel.close()
            except Exception:
                pass
        if self._tunnel_udp_sock:
            try:
                self._tunnel_udp_sock.close()
            except Exception:
                pass
        if self.cfg.get("setup_iptables", False):
            self._remove_iptables()
        if self.verbose:
            log.debug("[server] shutdown complete")
        log.info("Server stopped.")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HopShot Server")
    parser.add_argument("--config",       default=None,    help="JSON config file")
    parser.add_argument("--version", action="version", version=f"HopShot Server {__version__}")
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
    parser.add_argument("--max-ping-ms", type=int, default=15000,
                        help="Maximum tolerated RTT/latency in ms for session paths")
    parser.add_argument("--jitter",       type=int, default=64,
                        help="Jitter strip bytes (must match client --jitter, 0=off)")
    parser.add_argument("--tunnel-mode",  choices=("off", "tun", "tap", "udp"), default="off",
                        help="Enable a TUN/TAP bridge or userspace UDP relay")
    parser.add_argument("--tunnel-iface", default="hopshot0",
                        help="Tunnel interface name")
    parser.add_argument("--tunnel-mtu",   type=int, default=1400,
                        help="Tunnel interface MTU")
    parser.add_argument("--tunnel-address", default=None,
                        help="Tunnel interface address (e.g. 10.7.0.1/30)")
    parser.add_argument("--tunnel-peer", default=None,
                        help="Peer address for point-to-point tunnel mode")
    parser.add_argument("--tunnel-default-route", action="store_true",
                        help="Replace the default route with the tunnel interface")
    parser.add_argument("--tunnel-udp-bind", default="127.0.0.1:19091",
                        help="Userspace UDP relay bind endpoint host:port")
    parser.add_argument("--tunnel-udp-target", default=None,
                        help="Userspace UDP relay egress target host:port")
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
        "max_ping_ms":    args.max_ping_ms,
        "verbose":        args.verbose,
        "jitter_bytes":   args.jitter,
        "tunnel_mode":    args.tunnel_mode,
        "tunnel_iface":   args.tunnel_iface,
        "tunnel_mtu":     args.tunnel_mtu,
        "tunnel_address": args.tunnel_address,
        "tunnel_peer":    args.tunnel_peer,
        "tunnel_route_default": args.tunnel_default_route,
        "tunnel_udp_bind": args.tunnel_udp_bind,
        "tunnel_udp_target": args.tunnel_udp_target,
        "log_file":       args.log_file,
        "json_logs":      args.json_logs,
    }

    if args.config:
        with open(args.config) as f:
            cfg.update(json.load(f))

    mode = cfg.get("tunnel_mode", "off")
    if mode == "off":
        cfg["tunnel_backend"] = "off"
    elif mode == "udp":
        cfg["tunnel_backend"] = "userspace-udp"
    elif os.name == "nt":
        cfg["tunnel_backend"] = "wintun"
    else:
        cfg["tunnel_backend"] = "kernel"

    configure_logging(args.verbose, log_file=cfg.get("log_file"), json_logs=cfg.get("json_logs", False))

    use_color = supports_color()
    print("\n".join([
        title(f"HopShot Server v{__version__}", "cyan", use_color=use_color),
        section_header("Listener", "cyan", use_color=use_color),
        key_value("listen", f"{cfg['listen_port']}", value_color="green", use_color=use_color),
        key_value("quic", f"{cfg['quic_port']}", value_color="blue", use_color=use_color),
        key_value("port-range", f"{cfg['port_min']}-{cfg['port_max']}", value_color="cyan", use_color=use_color),
        "",
        section_header("Transport", "blue", use_color=use_color),
        key_value("obfs", "on" if cfg["obfs"] else "off", value_color="green" if cfg["obfs"] else "yellow", use_color=use_color),
        key_value("masquerade", "on" if cfg["masquerade"] else "off", value_color="green" if cfg["masquerade"] else "yellow", use_color=use_color),
        key_value("jitter", f"{cfg['jitter_bytes']}B", value_color="magenta", use_color=use_color),
        key_value("max-ping", f"{cfg.get('max_ping_ms', 15000)}ms", value_color="cyan", use_color=use_color),
        key_value("tunnel", f"{cfg.get('tunnel_mode', 'off')} / {cfg.get('tunnel_backend', 'off')}", value_color="cyan", use_color=use_color),
    ]))

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
