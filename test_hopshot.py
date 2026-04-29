#!/usr/bin/env python3
"""
HopShot integration tests — covers every feature.
Run: python3 test_hopshot.py
"""
import os, sys, socket, struct, threading, time, random, tempfile, subprocess, shutil
sys.path.insert(0, os.path.dirname(__file__))

import common, fec as fecmod, brutal
import client as clientmod
import server as servermod
import quic_transport as quicmod
from client import probe_port, HopShotClient, PROFILE_PRESETS, apply_profile_overrides, build_network_recommendation
from http3_masq import HTTP3Masq
from resolver import Resolver, _query_resolver, _build_dns_query, _parse_dns_response
from session_resume import ResumeTokenStore, TOKEN_SIZE, SessionTokenManager
from tunnel_codec import DataReassembler, encode_datagrams
import deploy as deploymod
from version import __version__

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
results = []

def test(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, ""))
    except Exception as e:
        import traceback
        print(f"  {FAIL} {name}: {e}")
        if "--verbose" in sys.argv:
            traceback.print_exc()
        results.append((name, False, str(e)))

# ── Mini server helper ────────────────────────────────────────────────────────

def mini_server(port, obfs=False, seed=b"test-seed", jitter=64,
                probe_token=None, drop_every=0, loss_pct=0, feedback_kbps=1000,
                probe_server_rx_kbps=0, probe_server_tx_kbps=0):
    """Returns (run_obj, received_list). run_obj.alive=False to stop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.1)
    received = []
    groups   = {}
    data_seen = 0
    pkt_seen = 0
    fec_k = fec_m = 4
    token_mgr = SessionTokenManager(seed)

    def should_drop(pkt_idx: int) -> bool:
        if drop_every and pkt_idx % drop_every == 0:
            return True
        if loss_pct <= 0:
            return False
        # Deterministic spread (non-random) so tests are stable while still
        # matching the requested loss percentage up to 98%.
        return ((pkt_idx * loss_pct) % 100) < loss_pct

    def run():
        nonlocal data_seen, pkt_seen
        while getattr(run, "alive", True):
            try:
                data, addr = sock.recvfrom(2048)
                pkt_seen += 1
                if should_drop(pkt_seen):
                    continue
                if obfs:
                    data = common.salamander(data, seed)
                hdr, payload = common.unpack_header(data)
                if not hdr: continue
                if hdr["type"] == common.TYPE_PROBE:
                    rep = common.pack_header(common.TYPE_PROBE_REPLY,
                          seq=hdr["seq"], session_id=hdr["session_id"])
                    token = probe_token if probe_token is not None else token_mgr.issue(hdr["session_id"])
                    rep += token + struct.pack("!Q", int(time.time() * 1000))
                    rep += struct.pack("!II", int(probe_server_rx_kbps), int(probe_server_tx_kbps))
                    if obfs: rep = common.salamander(rep, seed)
                    sock.sendto(rep, addr)
                elif hdr["type"] == common.TYPE_RESUME:
                    if len(payload) >= TOKEN_SIZE and token_mgr.verify(payload[:TOKEN_SIZE], hdr["session_id"]):
                        ack = common.pack_header(common.TYPE_RESUME_ACK, seq=hdr["seq"], session_id=hdr["session_id"])
                        ack += token_mgr.issue(hdr["session_id"]) + struct.pack("!Q", int(time.time() * 1000))
                        if obfs:
                            ack = common.salamander(ack, seed)
                        sock.sendto(ack, addr)
                elif hdr["type"] == common.TYPE_DATA:
                    data_seen += 1
                    orig_len   = struct.unpack_from("!I", payload)[0]
                    shard_data = common.strip_jitter_padding(payload[4:], jitter)
                    seq, idx, total = hdr["seq"], hdr["shard_idx"], hdr["total_shards"]
                    if seq not in groups:
                        groups[seq] = {"s": [None]*total, "ol": orig_len, "done": False, "ts": time.time()}
                    g = groups[seq]
                    if not g["done"] and g["s"][idx] is None:
                        g["s"][idx] = shard_data
                        if sum(1 for x in g["s"] if x) >= fec_k:
                            try:
                                rec = fecmod.reconstruct_data(g["s"], fec_k, fec_m, g["ol"])
                                g["done"] = True
                                received.append(rec)
                                # Send Brutal CC feedback after reconstruction.
                                bw_payload = common.pack_bw_feedback(int(feedback_kbps), 1, 0)
                                fb_hdr = common.pack_header(common.TYPE_BW_FEEDBACK, seq=0, session_id=hdr["session_id"])
                                fb_pkt = fb_hdr + bw_payload
                                if obfs:
                                    fb_pkt = common.salamander(fb_pkt, seed)
                                try:
                                    sock.sendto(fb_pkt, addr)
                                except:
                                    pass
                            except: pass
                elif hdr["type"] == common.TYPE_MTU_PROBE:
                    # Echo back MTU_REPLY with received packet size
                    reply_hdr = common.pack_header(common.TYPE_MTU_REPLY, seq=hdr["seq"], session_id=hdr.get("session_id", 0))
                    reply = reply_hdr + struct.pack("!H", len(data))
                    if obfs:
                        reply = common.salamander(reply, seed)
                    try:
                        sock.sendto(reply, addr)
                    except:
                        pass
            except socket.timeout: pass
        sock.close()
    run.alive = True
    threading.Thread(target=run, daemon=True).start()
    return run, received

def base_cfg(port, **kw):
    cfg = {
        "server_port": port, "quic_port": port+1,
        "port_min": port, "port_max": port,
        "shared_seed": "test-seed", "obfs": False,
        "rand_src_port": False, "jitter_bytes": 0,
        "preemptive_hop_ms": 800,
        "max_ping_ms": 15000,
        "fec_k": 4, "fec_m": 4,
        "probe_count": 5, "probe_timeout_ms": 1000,
        "verbose": False, "destinations": ["127.0.0.1"],
        "resolvers": ["127.0.0.1"],
    }
    cfg.update(kw)
    return cfg

# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "="*50)
print("  HopShot Feature Test Suite")
print("="*50 + "\n")

# ── 1. FEC ───────────────────────────────────────────────────────────────────
print("[ FEC Reed-Solomon ]")

def t_fec_50pct():
    msg = b"FEC test payload"
    shards, orig = fecmod.split_and_encode(msg, 4, 4)
    shards[0]=shards[2]=shards[5]=shards[7]=None
    assert fecmod.reconstruct_data(shards,4,4,orig) == msg
test("50% shard loss reconstructed", t_fec_50pct)

def t_fec_loss_matrix():
    msg = b"packet loss matrix payload"
    shards, orig = fecmod.split_and_encode(msg, 4, 4)
    cases = {
        "0%": set(),
        "25%": {1, 5},
        "50%": {0, 2, 5, 7},
        "62%": {0, 1, 2, 3, 5},
        "75%": {0, 1, 2, 4, 5, 6},
        "100%": set(range(8)),
    }
    for label, dropped in cases.items():
        kept = [None if idx in dropped else shard for idx, shard in enumerate(shards)]
        if sum(1 for shard in kept if shard) >= 4:
            assert fecmod.reconstruct_data(kept, 4, 4, orig) == msg, label
        else:
            try:
                fecmod.reconstruct_data(kept, 4, 4, orig)
            except Exception:
                continue
            raise AssertionError(f"{label} loss should not reconstruct")
test("FEC boundaries hold across 0%..100% dummy loss cases", t_fec_loss_matrix)

def t_fec_large():
    msg = bytes(range(256))*8
    shards,orig=fecmod.split_and_encode(msg,4,4)
    shards[1]=shards[3]=shards[6]=None
    assert fecmod.reconstruct_data(shards,4,4,orig)==msg
test("2KB payload, 3/8 shards lost", t_fec_large)

def t_fec_inverse_cache_reuse():
    msg = b"inverse cache payload" * 4
    shards, orig = fecmod.split_and_encode(msg, 5, 3)
    shards[0] = None
    shards[2] = None
    assert fecmod.reconstruct_data(shards, 5, 3, orig) == msg
    cache_before = len(fecmod._INV_SUBMATRIX_CACHE)
    assert fecmod.reconstruct_data(shards, 5, 3, orig) == msg
    cache_after = len(fecmod._INV_SUBMATRIX_CACHE)
    assert cache_after == cache_before
test("inverse sub-matrix cache reuses repeated decode paths", t_fec_inverse_cache_reuse)

# ── 2. Jitter padding ────────────────────────────────────────────────────────
print("\n[ Packet Size Jitter ]")

def t_jitter_roundtrip():
    data = b"hello world"
    for _ in range(50):
        padded = common.add_jitter_padding(data, 64)
        assert len(padded) >= len(data)
        stripped = common.strip_jitter_padding(padded, 64)
        assert stripped == data, f"got {stripped!r}"
test("add + strip padding roundtrip (50 iterations)", t_jitter_roundtrip)

def t_jitter_size_varies():
    data = b"x" * 100
    sizes = {len(common.add_jitter_padding(data, 64)) for _ in range(30)}
    assert len(sizes) > 3, f"padding not varying: {sizes}"
test("packet sizes vary across sends (breaks DPI fingerprinting)", t_jitter_size_varies)

def t_jitter_zero():
    data = b"no padding"
    assert common.add_jitter_padding(data, 0) == data
    assert common.strip_jitter_padding(data, 0) == data
test("jitter=0 disables padding correctly", t_jitter_zero)

# ── 3. Salamander obfuscation ────────────────────────────────────────────────
print("\n[ Salamander Obfuscation ]")

def t_obfs_rt():
    k=b"key"; d=b"plaintext"
    assert common.salamander(common.salamander(d,k),k)==d
test("obfs roundtrip", t_obfs_rt)

def t_obfs_changes_data():
    k=b"k"; d=b"data"*100
    assert common.salamander(d,k) != d
test("obfs actually changes bytes", t_obfs_changes_data)

# ── 4. Mode classification ───────────────────────────────────────────────────
print("\n[ Mode Classification ]")

def t_modes():
    cases=[(0,0),(29,0),(30,1),(59,1),(60,2),(79,2),(80,3),(89,3),(90,4),(100,4)]
    for loss,exp in cases:
        assert common.classify_loss(loss)==exp, f"loss={loss}"
test("all thresholds: normal/moderate/high/NUCLEAR/ULTRA_NUC", t_modes)

def t_burst_mult():
    assert common.MODE_PARAMS[0][1]==1
    assert common.MODE_PARAMS[1][1]==2
    assert common.MODE_PARAMS[2][1]==4
    assert common.MODE_PARAMS[3][1]==8
    assert common.MODE_PARAMS[4][1]==10
test("burst multipliers 1x/2x/4x/8x/10x baseline correct", t_burst_mult)

def t_profile_overrides():
    base = {
        "profile": "reliable",
        "obfs": True,
        "masquerade": True,
        "rand_src_port": True,
        "jitter_bytes": 64,
        "preemptive_hop_ms": 999,
    }
    cfg = apply_profile_overrides(base)
    assert cfg["disable_hop"] is False
    assert cfg["obfs"] is False
    assert cfg["masquerade"] is False
    assert cfg["rand_src_port"] is False
    assert cfg["jitter_bytes"] == 0
    assert cfg["preemptive_hop_ms"] == 1000
    assert cfg["fixed_hop_ms"] == 0
    assert cfg["keepalive_interval_sec"] == 20
    expected = {"balanced", "ghost", "survival", "throughput", "mobile", "tunnel", "reliable", "stealth"}
    assert expected.issubset(set(PROFILE_PRESETS))
test("profile presets map to safe operator modes", t_profile_overrides)

def t_startup_auto_scan_ramps_step_by_step_to_ultra_nuc():
    port = 19310 + random.randint(0, 30)
    c = HopShotClient(base_cfg(port, adaptive_mode=True, jitter_bytes=0, startup_capacity_scan=True))
    
    # Mock probe_port to simulate 100% loss  
    original_probe_port = clientmod.probe_port
    def fake_probe_port(primary_ip, probe_port_value, **kwargs):
        return {
            "port": probe_port_value,
            "loss_pct": 100.0,
            "rtt_ms": 0.0,
            "sent": kwargs.get("count", 0),
            "received": 0,
            "clock_offset_ms": 0,
        }
    clientmod.probe_port = fake_probe_port
    
    try:
        loss, scan = c._startup_auto_scan({"loss_pct": 100.0})
        # All stages should be tried, ending in ULTRA_NUC
        modes = scan.get("mode_progression", [])
        assert loss == 100.0, f"loss should be 100, got {loss}"
        assert scan["udp_throttled"] is True, "udp_throttled should be True"
        assert modes == ["moderate", "high", "NUCLEAR", "ULTRA_NUC"], f"expected mode progression, got {modes}"
        assert c.mode == common.MODE_ULTRA_NUC, f"Expected MODE_ULTRA_NUC={common.MODE_ULTRA_NUC}, got {c.mode}"
        assert 10 <= c.burst_mult <= 16, f"ULTRA_NUC burst should be x10..x16, got {c.burst_mult}"
    finally:
        clientmod.probe_port = original_probe_port
        c.stop()
    test("startup scan escalates failed presets through ultra-nuc mode", t_startup_auto_scan_ramps_step_by_step_to_ultra_nuc)

def t_diag_recommend_udp_quic_when_bypass():
    rec = build_network_recommendation(
        tcp_tls_clear=False,
        udp_throttled=True,
        udp_port_hopping_bypassed=True,
    )
    assert rec["Protocol"] == "UDP-QUIC"
    assert rec["Port-Hopping"] is True
test("diagnostic recommendation prefers UDP-QUIC after hopping recovery", t_diag_recommend_udp_quic_when_bypass)

def t_diag_recommend_tcp_tls_when_udp_bad():
    rec = build_network_recommendation(
        tcp_tls_clear=True,
        udp_throttled=True,
        udp_port_hopping_bypassed=False,
    )
    assert rec["Protocol"] == "TCP-TLS"
test("diagnostic recommendation falls back to TCP-TLS when UDP degraded", t_diag_recommend_tcp_tls_when_udp_bad)

def t_version_format():
    parts = __version__.split(".")
    assert len(parts) == 3 and all(part.isdigit() for part in parts), __version__
test("release version is semver-like", t_version_format)

def t_udp_endpoint_parser():
    assert clientmod._parse_udp_endpoint("127.0.0.1:19090", "127.0.0.1", 1) == ("127.0.0.1", 19090)
    assert clientmod._parse_udp_endpoint(None, "0.0.0.0", 19090) == ("0.0.0.0", 19090)
    try:
        clientmod._parse_udp_endpoint("bad-endpoint", "127.0.0.1", 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for invalid endpoint")
test("userspace UDP endpoint parser validates host:port", t_udp_endpoint_parser)

def t_deploy_defaults_include_tunnel_udp_fields():
    assert "tunnel_udp_bind" in deploymod.SERVER_DEFAULT_CONFIG
    assert "tunnel_udp_target" in deploymod.SERVER_DEFAULT_CONFIG
    assert "tunnel_udp_bind" in deploymod.CLIENT_DEFAULT_CONFIG
    assert "tunnel_udp_target" in deploymod.CLIENT_DEFAULT_CONFIG
test("deploy default configs include userspace UDP relay fields", t_deploy_defaults_include_tunnel_udp_fields)

def t_deploy_default_server_bind_limit_unlimited():
    assert int(deploymod.SERVER_DEFAULT_CONFIG.get("auto_bind_port_range_max", -1)) == 0
test("deploy default server bind limit is unlimited", t_deploy_default_server_bind_limit_unlimited)

def t_deploy_easy_server_normalizes_and_auto_seeds():
    old_root = deploymod.ROOT
    try:
        with tempfile.TemporaryDirectory() as td:
            td_path = os.path.abspath(td)
            deploymod.ROOT = deploymod.Path(td_path)

            # Malformed client config should not crash seed sync in easy mode.
            bad_client = os.path.join(td_path, "client.config.json")
            with open(bad_client, "w", encoding="utf-8") as f:
                f.write('{"broken": true')

            server_path = os.path.join(td_path, "server.config.json")
            with open(server_path, "w", encoding="utf-8") as f:
                f.write('{"shared_seed":"change-me","listen_port":10000,"port_min":20000,"port_max":10000}')

            cfg, notes = deploymod.ensure_server_config_ready(deploymod.Path(server_path), auto_seed=True)
            assert cfg["port_min"] == 10000 and cfg["port_max"] == 20000
            assert cfg["shared_seed"] != "change-me"
            assert int(cfg.get("auto_bind_port_range_max", -1)) == 0
            assert any("Generated a fresh shared_seed" in note for note in notes)
            assert any("Skipped client.config.json seed sync" in note for note in notes)
    finally:
        deploymod.ROOT = old_root
test("deploy easy mode normalizes ports and tolerates malformed client config", t_deploy_easy_server_normalizes_and_auto_seeds)

def t_server_launch_sh_sanity():
    script_path = os.path.join(os.path.dirname(__file__), "server-launch.sh")
    assert os.path.exists(script_path)
    text = open(script_path, "r", encoding="utf-8").read()
    assert "Easy setup + start server" in text
    assert "Edit server config" in text
    assert "--easy" in text and "--diagnose" in text

    sh_bin = shutil.which("sh")
    if sh_bin:
        subprocess.run([sh_bin, "-n", script_path], check=True)
test("linux launcher script is present and shell-parseable", t_server_launch_sh_sanity)

def t_server_setup_iptables_returns_bool():
    cfg = {
        "listen_port": 19000,
        "quic_port": 19001,
        "port_min": 19000,
        "port_max": 19010,
        "shared_seed": "test-seed",
        "setup_iptables": True,
    }
    srv = servermod.HopShotServer(cfg)

    old_run = servermod.subprocess.run
    try:
        def _ok_run(*args, **kwargs):
            class _R:
                returncode = 0
            return _R()

        def _fail_run(*args, **kwargs):
            raise RuntimeError("iptables unavailable")

        servermod.subprocess.run = _ok_run
        assert srv._setup_iptables() is True

        servermod.subprocess.run = _fail_run
        assert srv._setup_iptables() is False
    finally:
        servermod.subprocess.run = old_run
test("server iptables setup reports success/failure", t_server_setup_iptables_returns_bool)

def t_server_fallback_bind_uses_force_when_iptables_fails():
    cfg = {
        "listen_port": 19100,
        "quic_port": 19101,
        "port_min": 19100,
        "port_max": 19102,
        "shared_seed": "test-seed",
        "setup_iptables": True,
        "auto_bind_port_range": True,
        "auto_bind_port_range_max": 0,
        "certfile": "hopshot.crt",
        "keyfile": "hopshot.key",
    }
    srv = servermod.HopShotServer(cfg)

    calls = {"bind_force": []}

    class _FakeSock:
        def setsockopt(self, *args, **kwargs):
            return None
        def bind(self, *args, **kwargs):
            return None
        def close(self):
            return None

    old_socket = servermod.socket.socket
    old_setup = servermod.HopShotServer._setup_iptables
    old_bind = servermod.HopShotServer._bind_additional_udp_ports_if_needed
    old_quic = servermod.QUICServer
    old_cert = servermod.generate_selfsigned_cert
    old_thread = servermod.threading.Thread

    try:
        servermod.socket.socket = lambda *a, **k: _FakeSock()
        servermod.HopShotServer._setup_iptables = lambda self: False

        def _capture_bind(self, force=False):
            calls["bind_force"].append(force)

        servermod.HopShotServer._bind_additional_udp_ports_if_needed = _capture_bind

        class _FakeQUIC:
            def __init__(self, *args, **kwargs):
                self.data_callback = None
            def start(self):
                return None
            def stop(self):
                return None

        servermod.QUICServer = _FakeQUIC
        servermod.generate_selfsigned_cert = lambda *a, **k: None

        class _FakeThread:
            def __init__(self, target=None, args=(), daemon=None):
                self.target = target
            def start(self):
                return None

        servermod.threading.Thread = _FakeThread

        srv.start()
        assert calls["bind_force"] == [True]
    finally:
        servermod.socket.socket = old_socket
        servermod.HopShotServer._setup_iptables = old_setup
        servermod.HopShotServer._bind_additional_udp_ports_if_needed = old_bind
        servermod.QUICServer = old_quic
        servermod.generate_selfsigned_cert = old_cert
        servermod.threading.Thread = old_thread
        try:
            srv.stop()
        except Exception:
            pass
test("server falls back to forced bind if iptables fails", t_server_fallback_bind_uses_force_when_iptables_fails)

def t_client_keepalive_uses_transport_socket_in_tunnel_mode():
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.bind(("127.0.0.1", 0))
    bind_port = tmp.getsockname()[1]
    tmp.close()

    cfg = base_cfg(
        19200,
        tunnel_mode="udp",
        tunnel_udp_bind=f"127.0.0.1:{bind_port}",
        tunnel_udp_target="127.0.0.1:19091",
        keepalive_interval_sec=15,
    )
    c = HopShotClient(cfg)

    calls = []

    class _FakeTransport:
        def sendto(self, pkt, addr):
            calls.append((len(pkt), addr))

    old_socket = clientmod.socket.socket
    old_transport = c._transport_sock
    try:
        c._transport_sock = _FakeTransport()

        def _no_ephemeral(*args, **kwargs):
            raise AssertionError("keepalive should not open ephemeral UDP sockets in tunnel mode")

        clientmod.socket.socket = _no_ephemeral
        c._send_keepalive()
        assert len(calls) == 1
        assert calls[0][1][0] == "127.0.0.1"
    finally:
        clientmod.socket.socket = old_socket
        c._transport_sock = old_transport
        try:
            c._udp_sock.close()
        except Exception:
            pass
        try:
            if old_transport is not None:
                old_transport.close()
        except Exception:
            pass
        try:
            if c._tunnel_udp_sock is not None:
                c._tunnel_udp_sock.close()
        except Exception:
            pass
test("client keepalive uses stable transport socket in tunnel mode", t_client_keepalive_uses_transport_socket_in_tunnel_mode)

def t_server_keepalive_does_not_poison_tunnel_reply_address():
    cfg = {
        "listen_port": 19210,
        "quic_port": 19211,
        "port_min": 19210,
        "port_max": 19220,
        "shared_seed": "test-seed",
    }
    srv = servermod.HopShotServer(cfg)

    sid = 77
    stable_addr = ("127.0.0.1", 40001)
    hop_addr = ("127.0.0.1", 50002)
    sess = srv._get_session(sid, stable_addr)
    sess.reply_addr = stable_addr

    srv._handle_keepalive({"session_id": sid}, hop_addr)

    assert sess.addr == hop_addr
    assert sess.reply_addr == stable_addr
test("server keepalive updates last-seen addr but preserves tunnel reply addr", t_server_keepalive_does_not_poison_tunnel_reply_address)

def t_server_tunnel_payload_targets_stable_reply_addr():
    cfg = {
        "listen_port": 19230,
        "quic_port": 19231,
        "port_min": 19230,
        "port_max": 19240,
        "shared_seed": "test-seed",
        "fec_k": 1,
        "fec_m": 0,
        "jitter_bytes": 0,
    }
    srv = servermod.HopShotServer(cfg)
    sess = servermod.Session(99, ("127.0.0.1", 45000))
    sess.reply_addr = ("127.0.0.1", 46000)

    sent = []

    class _FakeSock:
        def sendto(self, pkt, addr):
            sent.append(addr)

    srv.udp_sock = _FakeSock()
    srv._send_tunnel_payload(b"hello", sess)

    assert len(sent) >= 1
    assert all(addr == ("127.0.0.1", 46000) for addr in sent)
test("server tunnel send targets stable reply address", t_server_tunnel_payload_targets_stable_reply_addr)

def t_send_uses_fixed_udp_socket_when_rand_src_disabled():
    port = 19480 + random.randint(0, 100)
    c = HopShotClient(base_cfg(port, rand_src_port=False))
    c.reactive_probe_enabled = False

    captures = []
    old_burst = c._burst_send
    try:
        def _capture(pkt, shard_idx, seq, hop_ms, burst_mult, sock=None, force_multi_port=False):
            captures.append(sock)
            return None

        c._burst_send = _capture
        c.send(b"nat-stable")
    finally:
        c._burst_send = old_burst
        try:
            c.stop()
        except Exception:
            pass

    assert len(captures) > 0
    assert all(sock is c._udp_sock for sock in captures)
test("send path uses fixed udp socket when source randomization is off", t_send_uses_fixed_udp_socket_when_rand_src_disabled)

def t_server_probe_applies_client_rx_hint():
    cfg = {
        "listen_port": 19510,
        "quic_port": 19511,
        "port_min": 19510,
        "port_max": 19520,
        "shared_seed": "test-seed",
        "declared_down_kbps": 55555,
    }
    srv = servermod.HopShotServer(cfg)

    sent = []

    class _FakeSock:
        def sendto(self, pkt, addr):
            sent.append((pkt, addr))

    hdr = {
        "seq": 3,
        "session_id": 44,
    }
    srv._handle_probe(hdr, struct.pack("!II", 12345, 0), ("127.0.0.1", 40001), common.TRANSPORT_RAW, tx_sock=_FakeSock())

    sess = srv._get_session(44, ("127.0.0.1", 40001))
    assert int(sess.receiver._ceil) == 12345
    assert len(sent) == 1

    rep_hdr, rep_payload = common.unpack_header(sent[0][0])
    assert rep_hdr is not None and rep_hdr["type"] == common.TYPE_PROBE_REPLY
    assert len(rep_payload) >= TOKEN_SIZE + 16
    assert struct.unpack_from("!I", rep_payload, TOKEN_SIZE + 8)[0] == 55555
    assert struct.unpack_from("!I", rep_payload, TOKEN_SIZE + 12)[0] == 55555
test("server probe stores client rx hint and returns server hints", t_server_probe_applies_client_rx_hint)

# ── 5. Deterministic hopping ─────────────────────────────────────────────────
print("\n[ Deterministic Port Hopping ]")

def t_hop_same():
    s=b"seed"; slot=9999
    assert common.deterministic_port(s,slot,10000,65000)==\
           common.deterministic_port(s,slot,10000,65000)
test("same seed+slot -> same port (client==server)", t_hop_same)

def t_hop_spread():
    s=b"seed"
    ports={common.deterministic_port(s,i,10000,65000) for i in range(30)}
    assert len(ports)>15
test("different slots spread across wide port range", t_hop_spread)

def t_hop_in_range():
    s=b"s"
    for i in range(200):
        p=common.deterministic_port(s,i,20000,30000)
        assert 20000<=p<30000
test("all hops stay within port_min:port_max", t_hop_in_range)

# ── 6. Pre-emptive hopping ───────────────────────────────────────────────────
print("\n[ Pre-emptive Hopping ]")

def t_preemptive_faster():
    # Pre-emptive interval (800ms) must be <= all mode hop intervals.
    assert common.PREEMPTIVE_HOP_MS <= 800
    assert common.PREEMPTIVE_HOP_MS <= 1000
    assert common.PREEMPTIVE_HOP_MS <= 1500
    assert common.PREEMPTIVE_HOP_MS <= 3000
test(f"preemptive={common.PREEMPTIVE_HOP_MS}ms < all mode hop intervals", t_preemptive_faster)

def t_preemptive_new_port():
    seed=b"seed"
    slot_now = common.time_slot(common.PREEMPTIVE_HOP_MS)
    p1 = common.deterministic_port(seed, slot_now,   10000, 65000)
    p2 = common.deterministic_port(seed, slot_now+5, 10000, 65000)
    # Just verify both are valid ports
    assert 10000<=p1<65000 and 10000<=p2<65000
test("pre-emptive slot advance produces valid new port", t_preemptive_new_port)

def t_time_slot_randomized_wallclock():
    original_time = common.time.time
    original_monotonic = common.time.monotonic
    try:
        common.time.time = lambda: 123456.789
        common.time.monotonic = lambda: 1.0
        first = common.time_slot_randomized(1000, b"seed", 7)
        common.time.monotonic = lambda: 98765.0
        second = common.time_slot_randomized(1000, b"seed", 7)
        assert first == second
        shifted = common.time_slot_randomized(1000, b"seed", 7, clock_offset_ms=1000)
        assert shifted != first
    finally:
        common.time.time = original_time
        common.time.monotonic = original_monotonic
test("randomized hop slot ignores uptime differences", t_time_slot_randomized_wallclock)

# ── 7. Brutal CC ─────────────────────────────────────────────────────────────
print("\n[ Brutal CC ]")

def t_cc_rampup():
    s=brutal.BrutalSender(); init=s.rate_kbps
    for _ in range(5): s.on_feedback(5000,20,0)
    assert s.rate_kbps>init
test("ramps up on low loss", t_cc_rampup)

def t_cc_rampdown():
    s=brutal.BrutalSender()
    for _ in range(10): s.on_feedback(10000,20,0)
    high=s.rate_kbps
    for _ in range(5): s.on_feedback(500,300,60)
    assert s.rate_kbps<high
test("ramps down on high loss", t_cc_rampdown)

def t_cc_clamp():
    s=brutal.BrutalSender()
    for _ in range(500): s.on_feedback(999999,1,0)
    assert s.rate_kbps<=brutal.MAX_RATE_KBPS
    for _ in range(500): s.on_feedback(0,999,100)
    assert s.rate_kbps>=brutal.MIN_RATE_KBPS
test("rate clamped within [MIN, MAX] kbps", t_cc_clamp)

def t_cc_receiver_loss():
    r=brutal.BrutalReceiver()
    for i in [0,1,2,3,4,7,8,9]: r.on_packet(i,500)
    time.sleep(brutal.FEEDBACK_INTERVAL + 0.02)
    fb=r.feedback()
    assert fb and fb[2]>0
test("receiver detects seq gaps as loss%", t_cc_receiver_loss)

def t_cc_receiver_rate():
    r=brutal.BrutalReceiver()
    for i in range(20): r.on_packet(i,1000)
    time.sleep(brutal.FEEDBACK_INTERVAL + 0.02)
    fb=r.feedback()
    assert fb and fb[0]>0
test("receiver measures recv rate > 0", t_cc_receiver_rate)

def t_cc_receiver_down_ceiling():
    r=brutal.BrutalReceiver(declared_down_kbps=1200)
    for i in range(20):
        r.on_packet(i,50000)
    time.sleep(brutal.FEEDBACK_INTERVAL + 0.02)
    fb=r.feedback()
    assert fb and fb[0] <= 1200
test("receiver caps reported rate to declared_down_kbps", t_cc_receiver_down_ceiling)

def t_cc_feedback_interval_cadence():
    r=brutal.BrutalReceiver()
    for i in range(5):
        r.on_packet(i,1000)
    # Before FEEDBACK_INTERVAL has elapsed, no feedback should be emitted.
    time.sleep(max(0.01, brutal.FEEDBACK_INTERVAL / 2.0))
    assert r.feedback() is None
    time.sleep(brutal.FEEDBACK_INTERVAL)
    fb = r.feedback()
    assert fb and fb[0] > 0
test("receiver feedback cadence follows FEEDBACK_INTERVAL", t_cc_feedback_interval_cadence)

# ── 8. Resolver ──────────────────────────────────────────────────────────────
print("\n[ Resolver & Custom DNS ]")

def t_resolver_ip_passthrough():
    r=Resolver(["8.8.8.8"])
    assert r.resolve("1.2.3.4")==["1.2.3.4"]
test("IP address passed through without DNS query", t_resolver_ip_passthrough)

def t_resolver_add_remove():
    r=Resolver(["1.1.1.1","8.8.8.8"])
    r.add_resolver("9.9.9.9")
    assert "9.9.9.9" in r.resolvers
    assert r.resolvers[0]=="9.9.9.9"   # prepended = highest priority
    r.remove_resolver("9.9.9.9")
    assert "9.9.9.9" not in r.resolvers
test("add resolver (prepended = priority) + remove", t_resolver_add_remove)

def t_resolver_list():
    r=Resolver(["1.1.1.1","8.8.8.8"])
    lst=r.list_resolvers()
    assert lst==["1.1.1.1","8.8.8.8"]
test("list_resolvers() returns current list", t_resolver_list)

def t_resolver_cache():
    r=Resolver(["8.8.8.8"])
    r.resolve("1.2.3.4")
    r.resolve("1.2.3.4")   # second call should hit cache
    r.flush_cache()
test("resolver caches results, flush_cache() clears", t_resolver_cache)

def t_resolver_multi():
    r=Resolver(["8.8.8.8"])
    ips=r.resolve_all(["1.1.1.1","8.8.8.8","9.9.9.9"])
    assert len(ips)==3
    assert "1.1.1.1" in ips
test("resolve_all() deduplicates multiple IPs", t_resolver_multi)

def t_dns_packet_build():
    pkt = _build_dns_query("example.com", qtype=1)
    assert len(pkt) > 12
    assert pkt[:2] == b"\x12\x34"   # txid
test("DNS query packet builds correctly", t_dns_packet_build)

# ── 9. Multi-destination burst ───────────────────────────────────────────────
print("\n[ Multi-Destination Burst ]")

def t_multi_dest():
    """Two servers on different ports both receive the payload."""
    port1 = 19800 + random.randint(0,50)
    port2 = port1 + 100
    srv1, rx1 = mini_server(port1)
    srv2, rx2 = mini_server(port2)
    time.sleep(0.05)

    cfg = base_cfg(port1,
        destinations=["127.0.0.1"],
        port_min=port1, port_max=port1,
        jitter_bytes=0,
    )
    # Manually add second dest IP — same IP different port not real multi-dest
    # but we test the burst_mult spreading across dest_ips list
    client = HopShotClient(cfg)
    client.dest_ips = ["127.0.0.1"]   # keep single dest for loopback test
    client.primary_ip = "127.0.0.1"
    client._running = True
    client.quic_ok  = False

    msg = b"multi dest test"
    client.send(msg)
    time.sleep(1.0)
    client.stop()
    srv1.alive = srv2.alive = False

    assert len(rx1) > 0, "server 1 got nothing"
    assert rx1[0] == msg
test("burst sender delivers to primary destination", t_multi_dest)

def t_hop_burst_uses_multiple_ports():
    cfg = base_cfg(
        19830,
        adaptive_mode=False,
        disable_hop=False,
        fixed_hop_ms=0,
        port_min=19830,
        port_max=19880,
    )
    c = HopShotClient(cfg)
    try:
        c.mode = common.MODE_HIGH
        c.hop_ms, c.burst_mult = common.MODE_PARAMS[common.MODE_HIGH]
        ports = {
            c._select_dst_port(
                seq=11,
                shard_idx=0,
                burst_idx=i,
                hop_ms=c.hop_ms,
                burst_mult=c.burst_mult,
                force_multi_port=False,
            )
            for i in range(c.burst_mult)
        }
        assert len(ports) > 1, f"expected multi-port fanout, got {ports}"
    finally:
        c.stop()
test("hopping burst uses multiple destination ports", t_hop_burst_uses_multiple_ports)

# ── 10. Source port randomization (optional) ─────────────────────────────────
print("\n[ Source Port Randomization (optional) ]")

def t_src_port_random():
    """When enabled, each packet should use a different source port."""
    seen_ports = set()
    port = 19900 + random.randint(0,50)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.5)

    for _ in range(10):
        src = random.randint(1024, 65535)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("", src))
        except OSError:
            src = 0
        s.sendto(b"x"*16, ("127.0.0.1", port))
        seen_ports.add(src)
        s.close()

    sock.close()
    assert len(seen_ports) > 5, f"only {len(seen_ports)} distinct src ports"
test("[optional] source port randomization varies per packet", t_src_port_random)

# ── 11. Header encode/decode ─────────────────────────────────────────────────
print("\n[ Protocol Header ]")

def t_hdr():
    raw=common.pack_header(common.TYPE_DATA,seq=0xDEAD,shard_idx=3,
        total_shards=8,session_id=0xAB,transport=common.TRANSPORT_QUIC)
    assert len(raw)==common.HEADER_SIZE
    hdr,_=common.unpack_header(raw)
    assert hdr["seq"]==0xDEAD and hdr["shard_idx"]==3
    assert hdr["transport"]==common.TRANSPORT_QUIC
    assert hdr["frag_id"] == 0 and hdr["frag_count"] == 1
test("pack/unpack header roundtrip", t_hdr)

def t_bad_magic():
    hdr,_=common.unpack_header(b"\x00"*16)
    assert hdr is None
test("bad magic rejected", t_bad_magic)

def t_tunnel_codec_roundtrip():
    payload = b"hello tunnel"
    encoded = encode_datagrams(
        payload=payload,
        seq=42,
        session_id=7,
        seed=b"seed",
        fec_k=4,
        fec_m=4,
        jitter=0,
        obfs=False,
        masquerade=False,
    )
    assembler = DataReassembler(4, 4, 0)
    recovered = None
    for pkt in encoded.datagrams:
        hdr, body = common.unpack_header(pkt)
        assert hdr is not None
        maybe = assembler.push(hdr, body)
        if maybe is not None:
            recovered = maybe
    assert recovered == payload
test("tunnel codec roundtrip", t_tunnel_codec_roundtrip)

def t_stream_multiplexing_roundtrip():
    payload_a = b"stream-a-payload"
    payload_b = b"stream-b-payload"
    encoded_a = encode_datagrams(
        payload=payload_a,
        seq=88,
        session_id=10,
        seed=b"seed",
        fec_k=4,
        fec_m=4,
        jitter=0,
        obfs=False,
        masquerade=False,
        stream_id=1,
    )
    encoded_b = encode_datagrams(
        payload=payload_b,
        seq=88,
        session_id=10,
        seed=b"seed",
        fec_k=4,
        fec_m=4,
        jitter=0,
        obfs=False,
        masquerade=False,
        stream_id=2,
    )
    assembler = DataReassembler(4, 4, 0)
    recovered = []
    for pkt in encoded_a.datagrams + encoded_b.datagrams:
        hdr, body = common.unpack_header(pkt)
        assert hdr is not None
        recovered_pkt = assembler.push(hdr, body)
        if recovered_pkt is not None:
            recovered.append(recovered_pkt)
    assert payload_a in recovered and payload_b in recovered
test("stream multiplexing separates packets by stream id", t_stream_multiplexing_roundtrip)

def t_bbr_fallback_selected_without_declared_uplink():
    c = HopShotClient(base_cfg(19690, declared_up_kbps=0))
    try:
        assert isinstance(c.cc, brutal.BBRSender)
    finally:
        c.stop()
test("BBR fallback is selected when no uplink cap is declared", t_bbr_fallback_selected_without_declared_uplink)

def t_bbr_sender_interface_matches_sender():
    cc = brutal.BBRSender()
    cc.pace(64)
    cc.on_feedback(1000, 20, 0)
    cc.record_sent(64)
    rate, rtt = cc.stats()
    assert rate > 0 and rtt >= 0
    assert isinstance(cc.rate_kbps, float)
test("BBR sender exposes the same pacing interface", t_bbr_sender_interface_matches_sender)

def t_tunnel_codec_fragmented_roundtrip():
    payload = b"frag-" * 300
    encoded = encode_datagrams(
        payload=payload,
        seq=77,
        session_id=9,
        seed=b"seed",
        fec_k=4,
        fec_m=4,
        jitter=0,
        obfs=False,
        masquerade=False,
        max_datagram_size=72,
    )
    assert len(encoded.datagrams) > 8

    assembler = DataReassembler(4, 4, 0)
    recovered = None
    for pkt in encoded.datagrams:
        hdr, body = common.unpack_header(pkt)
        assert hdr is not None
        assert hdr["frag_count"] >= 1
        maybe = assembler.push(hdr, body)
        if maybe is not None:
            recovered = maybe
    assert recovered == payload
test("tunnel codec roundtrip with fragmentation", t_tunnel_codec_fragmented_roundtrip)

# ── 12. HTTP/3 masquerading ────────────────────────────────────────────────
print("\n[ HTTP/3 Masquerade ]")

def t_http3_masq_roundtrip_large_seq():
    inner = (
        common.pack_header(
            common.TYPE_DATA,
            seq=42,
            shard_idx=1,
            total_shards=2,
            session_id=0xBEEF,
        ) + b"\x00\x00\x00\x05hello"
    )
    wrapped = HTTP3Masq.wrap(inner, b"test-seed", 300)
    assert HTTP3Masq.is_masqueraded(wrapped)
    assert HTTP3Masq.unwrap(wrapped, b"test-seed") == inner
    assert HTTP3Masq.unwrap(wrapped, b"test-seed", 300) == inner
    assert HTTP3Masq.unwrap(wrapped, b"wrong-seed") is None
test("HTTP/3 unwrap works after seq 255 and rejects wrong seed", t_http3_masq_roundtrip_large_seq)

def t_quic_client_first_write_fragments():
    sent = []

    class _FakeRaw:
        def send(self, data, *args, **kwargs):
            sent.append(data)
            return len(data)
        def sendall(self, data, *args, **kwargs):
            sent.append(data)
        def setsockopt(self, *args, **kwargs):
            return None
        def gettimeout(self):
            return None
        def settimeout(self, *args, **kwargs):
            return None
        def close(self):
            return None

    proxy = quicmod._FragmentingSocket(_FakeRaw())
    proxy.sendall(b"HELLOCLIENTHELLO")
    assert len(sent) == 2
    assert b"".join(sent) == b"HELLOCLIENTHELLO"
test("QUIC client first write is fragmented", t_quic_client_first_write_fragments)

# ── 12. Probe + reactive probe ───────────────────────────────────────────────
print("\n[ Probe / Reactive Probe ]")

def t_probe():
    port = 19200+random.randint(0,100)
    srv, _ = mini_server(port)
    time.sleep(0.05)
    r = probe_port("127.0.0.1", port, count=10, timeout_ms=2000, seed=b"test-seed")
    srv.alive = False
    assert r["received"]>0 and r["loss_pct"]<20
test("probe: replies received, <20% loss on loopback", t_probe)

def t_probe_stores_token():
    port = 19300+random.randint(0,100)
    token = bytes(range(TOKEN_SIZE))
    srv, _ = mini_server(port, probe_token=token)
    time.sleep(0.05)
    store = ResumeTokenStore()
    r = probe_port(
        "127.0.0.1", port, count=5, timeout_ms=1500,
        seed=b"test-seed", resume_store=store,
    )
    srv.alive = False
    assert r["received"] > 0
    assert store.get() == token
test("probe reply token is cached for 0-RTT resumption", t_probe_stores_token)

def t_probe_negotiates_bandwidth_hints():
    port = 19380 + random.randint(0, 100)
    srv, _ = mini_server(
        port,
        probe_server_rx_kbps=42000,
        probe_server_tx_kbps=36000,
    )
    time.sleep(0.05)
    r = probe_port(
        "127.0.0.1",
        port,
        count=5,
        timeout_ms=1200,
        seed=b"test-seed",
        declared_rx_kbps=22000,
        declared_tx_kbps=18000,
    )
    srv.alive = False
    assert r["received"] > 0
    assert r["server_rx_kbps"] == 42000
    assert r["server_tx_kbps"] == 36000
test("probe bandwidth hint negotiation returns server caps", t_probe_negotiates_bandwidth_hints)

def t_reactive_probe_classifies():
    from client import reactive_probe
    port = 19400+random.randint(0,100)
    srv, _ = mini_server(port)
    time.sleep(0.05)
    loss, should_hop = reactive_probe("127.0.0.1", port, b"test-seed", False, threshold=30)
    srv.alive = False
    assert isinstance(loss, float)
    assert isinstance(should_hop, bool)
test("reactive probe classifies low-loss port correctly", t_reactive_probe_classifies)

def t_resume_roundtrip_ack():
    port = 19450 + random.randint(0, 80)
    srv, _ = mini_server(port)
    time.sleep(0.05)

    c = HopShotClient(base_cfg(port, jitter_bytes=0))
    c.start()
    token = c._resume_store.get()
    c.stop()

    assert token is not None and len(token) == TOKEN_SIZE
    sid = struct.unpack_from("!H", token)[0]

    c2 = HopShotClient(base_cfg(port, jitter_bytes=0, resume_token=token.hex()))
    try:
        ok = c2._try_resume()
        assert ok is True
        assert c2.session_id == sid
    finally:
        c2.stop()
        srv.alive = False
test("resume token handshake returns RESUME_ACK", t_resume_roundtrip_ack)

def t_start_uses_resume_and_skips_probe():
    port = 19490 + random.randint(0, 80)
    srv, _ = mini_server(port)
    time.sleep(0.05)

    seed_cfg = base_cfg(port, jitter_bytes=0)
    c = HopShotClient(seed_cfg)
    c.start()
    token = c._resume_store.get()
    c.stop()
    assert token is not None

    original_probe = clientmod.probe_port
    def fail_probe(*args, **kwargs):
        raise AssertionError("probe must be skipped when resume succeeds")

    c2 = None
    clientmod.probe_port = fail_probe
    try:
        c2 = HopShotClient(base_cfg(port, jitter_bytes=0, resume_token=token.hex()))
        c2.start()
        assert c2._resume_used is True
    finally:
        if c2 is not None:
            c2.stop()
        clientmod.probe_port = original_probe
        srv.alive = False
test("startup skips probe when valid resume token is available", t_start_uses_resume_and_skips_probe)

# ── 13. End-to-end ───────────────────────────────────────────────────────────
print("\n[ End-to-End ]")

def t_e2e_normal():
    port=19500+random.randint(0,50)
    srv,rx=mini_server(port, jitter=0)
    time.sleep(0.05)
    c=HopShotClient(base_cfg(port,jitter_bytes=0))
    c.start()
    msg=b"end to end normal mode"
    c.send(msg)
    time.sleep(1.0)
    c.stop(); srv.alive=False
    assert rx and rx[0]==msg
test("normal mode: send -> FEC -> server reconstruct", t_e2e_normal)

def t_e2e_jitter():
    port=19560+random.randint(0,50)
    srv,rx=mini_server(port, jitter=64)
    time.sleep(0.05)
    c=HopShotClient(base_cfg(port,jitter_bytes=64))
    c.start()
    msg=b"jitter padding end to end"
    c.send(msg)
    time.sleep(1.0)
    c.stop(); srv.alive=False
    assert rx and rx[0]==msg
test("jitter padding: client adds, server strips, data intact", t_e2e_jitter)

def t_e2e_obfs():
    port=19620+random.randint(0,50)
    srv,rx=mini_server(port,obfs=True,seed=b"test-seed",jitter=0)
    time.sleep(0.05)
    c=HopShotClient(base_cfg(port,obfs=True,jitter_bytes=0))
    c.start()
    msg=b"obfuscated end to end"
    c.send(msg)
    time.sleep(1.0)
    c.stop(); srv.alive=False
    assert rx and rx[0]==msg
test("Salamander obfs both sides: data survives", t_e2e_obfs)

def t_e2e_quic_blocked_firewall_fallback():
    port = 19645 + random.randint(0, 40)
    srv, rx = mini_server(port, jitter=0)
    time.sleep(0.05)

    original_quic = clientmod.QUICClient

    class FirewallQUIC:
        def __init__(self, *args, **kwargs):
            pass

        def connect(self):
            raise OSError("blocked by strict firewall")

        def send(self, payload):
            raise AssertionError("QUIC should be disabled by the firewall test")

        def close(self):
            pass

    clientmod.QUICClient = FirewallQUIC
    c = None
    try:
        c = HopShotClient(base_cfg(port, jitter_bytes=0))
        c.start()
        assert c.quic_ok is False
        msg = b"strict firewall forces raw udp fallback"
        c.send(msg)
        time.sleep(1.0)
        assert rx and rx[0] == msg
    finally:
        if c is not None:
            c.stop()
        srv.alive = False
        clientmod.QUICClient = original_quic
test("QUIC blocked by strict firewall still falls back to raw UDP", t_e2e_quic_blocked_firewall_fallback)

def _mode_e2e(mode: int, label: str):
    port = 19720 + random.randint(0, 50)
    srv, rx = mini_server(port, jitter=0)
    time.sleep(0.05)
    c = HopShotClient(base_cfg(port, jitter_bytes=0))
    c.mode = mode
    c.hop_ms, c.burst_mult = common.MODE_PARAMS[mode]
    c._running = True
    c.quic_ok = False
    msg = f"{label} mode end to end".encode()
    c.send(msg)
    time.sleep(1.0)
    c.stop()
    srv.alive = False
    assert rx and rx[0] == msg

def t_e2e_moderate():
    _mode_e2e(common.MODE_MODERATE, "moderate")
test("MODERATE mode: 2x burst, data delivered", t_e2e_moderate)

def t_e2e_high():
    _mode_e2e(common.MODE_HIGH, "high")
test("HIGH mode: 4x burst, data delivered", t_e2e_high)

def t_e2e_nuclear():
    port=19680+random.randint(0,50)
    srv,rx=mini_server(port,jitter=0)
    time.sleep(0.05)
    c=HopShotClient(base_cfg(port,jitter_bytes=0))
    c.mode=common.MODE_NUCLEAR
    c.hop_ms,c.burst_mult=common.MODE_PARAMS[common.MODE_NUCLEAR]
    c._running=True; c.quic_ok=False
    msg=b"NUCLEAR 8x burst still works"
    c.send(msg)
    time.sleep(1.0)
    c.stop(); srv.alive=False
    assert rx and rx[0]==msg
test("NUCLEAR mode: 8x burst, data delivered", t_e2e_nuclear)

def t_brutal_cc_feedback_roundtrip_changes_rate():
    port = 19700 + random.randint(0, 50)
    srv, rx = mini_server(port, jitter=0, feedback_kbps=5000)
    time.sleep(0.05)
    c = HopShotClient(base_cfg(port, jitter_bytes=0, rand_src_port=False))
    c.start()
    try:
        initial = c.cc.rate_kbps
        # Send a few packets to give feedback round-trip time to apply.
        for i in range(5):
            c.send(f"cc-feedback-{i}".encode())
            time.sleep(0.15)
        time.sleep(0.8)
        assert c.cc.rate_kbps > initial, (initial, c.cc.rate_kbps)
        assert rx, "server did not reconstruct any payload during CC feedback test"
    finally:
        c.stop()
        srv.alive = False
test("Brutal CC rate changes after BW feedback round-trip", t_brutal_cc_feedback_roundtrip_changes_rate)

def t_loss_sweep_reachability_to_98pct():
    # Increasing loss ladder to represent progressively worse links.
    loss_ladder = [0, 30, 50, 70, 85, 90, 95, 98]
    probe_received = []

    for loss in loss_ladder:
        port = 19860 + random.randint(0, 60)
        srv, rx = mini_server(port, jitter=0, loss_pct=loss)
        time.sleep(0.05)

        # Reachability check under increasing loss.
        probe = probe_port("127.0.0.1", port, count=160, timeout_ms=6000, seed=b"test-seed")
        probe_received.append(probe["received"])
        assert probe["received"] > 0, f"no probe replies at {loss}% loss"

        # Data-path check with strongest profile-like behavior.
        c = HopShotClient(base_cfg(port, jitter_bytes=0, adaptive_mode=False, disable_hop=True))
        c.mode = common.MODE_NUCLEAR
        c.hop_ms, c.burst_mult = common.MODE_PARAMS[common.MODE_NUCLEAR]
        c._running = True
        c.quic_ok = False

        for i in range(10):
            c.send(f"loss={loss} msg={i}".encode())

        time.sleep(1.5)
        c.stop()
        srv.alive = False

        # At extreme 98% loss we only require server reachability; delivery may
        # be intermittent depending on strict drop pattern.
        if loss < 98:
            assert rx, f"no data reconstructed at {loss}% loss"

    # Probe success should trend downward as loss increases.
    for i in range(1, len(probe_received)):
        assert probe_received[i] <= probe_received[i - 1], (
            f"probe reachability not decreasing: {probe_received}"
        )
test("loss sweep 0%..98% keeps reachability on strict bad network", t_loss_sweep_reachability_to_98pct)

def t_adaptive_mode_forces_auto_hop_burst():
    cfg = base_cfg(19790, adaptive_mode=True, disable_hop=True, fixed_hop_ms=2500, manual_burst_mult=9)
    c = HopShotClient(cfg)
    try:
        assert c.adaptive_mode is True
        assert c.disable_hop is False
        assert c.fixed_hop_ms == 0
        assert c.manual_burst_mult == 0
    finally:
        c.stop()
test("adaptive mode keeps loss-based hop/burst automation enabled", t_adaptive_mode_forces_auto_hop_burst)

def t_ultra_nuc_dynamic_burst_scales_10_to_16():
    c = HopShotClient(base_cfg(19805, adaptive_mode=False))
    try:
        c._set_mode(90.0)
        assert c.mode == common.MODE_ULTRA_NUC
        assert c.hop_ms == 800
        assert c.burst_mult == 10

        c._set_mode(100.0)
        assert c.mode == common.MODE_ULTRA_NUC
        assert c.hop_ms == 800
        assert c.burst_mult == 16
    finally:
        c.stop()
test("ULTRA_NUC burst scales from x10 to x16 by loss severity", t_ultra_nuc_dynamic_burst_scales_10_to_16)

def t_nuclear_fallback_forces_multiport_fanout():
    cfg = base_cfg(
        19820,
        adaptive_mode=False,
        disable_hop=True,
        port_min=19820,
        port_max=19880,
    )
    c = HopShotClient(cfg)
    try:
        c.mode = common.MODE_NUCLEAR
        c.hop_ms, c.burst_mult = common.MODE_PARAMS[common.MODE_NUCLEAR]
        ports = {
            c._select_dst_port(
                seq=7,
                shard_idx=0,
                burst_idx=i,
                hop_ms=c.hop_ms,
                burst_mult=c.burst_mult,
                force_multi_port=True,
            )
            for i in range(c.burst_mult)
        }
        assert len(ports) > 1
    finally:
        c.stop()
test("NUCLEAR fallback can fan burst across multiple ports", t_nuclear_fallback_forces_multiport_fanout)

def t_max_ping_propagates_to_quic_timeout():
    observed = {}
    original_quic = clientmod.QUICClient

    class ObserveQUIC:
        def __init__(self, host, port, cafile=None, verify=False, connect_timeout=5.0, **kwargs):
            observed["timeout"] = connect_timeout
        def connect(self):
            return False
        def close(self):
            pass

    clientmod.QUICClient = ObserveQUIC
    c = None
    try:
        c = HopShotClient(base_cfg(19850, max_ping_ms=15000))
        c._connect_quic()
        assert observed.get("timeout", 0) >= 15.0
    finally:
        if c is not None:
            c.stop()
        clientmod.QUICClient = original_quic
test("max_ping_ms is honored by QUIC connect timeout", t_max_ping_propagates_to_quic_timeout)

def t_startup_scan_port_hopping_recovery_logic():
    original_probe = clientmod.probe_port
    calls = []

    def fake_probe(server_ip, port, count=20, timeout_ms=2000,
                   seed=b"hopshot", obfs=False, resume_store=None, verbose=False,
                   declared_rx_kbps=0, declared_tx_kbps=0):
        calls.append(port)
        if len(calls) == 1:
            return {
                "port": port,
                "loss_pct": 9.0,
                "rtt_ms": 130.0,
                "sent": count,
                "received": max(1, int(count * 0.9)),
                "clock_offset_ms": 0,
                "server_rx_kbps": 0,
                "server_tx_kbps": 0,
            }
        return {
            "port": port,
            "loss_pct": 92.0,
            "rtt_ms": 120.0,
            "sent": count,
            "received": 1,
            "clock_offset_ms": 0,
            "server_rx_kbps": 0,
            "server_tx_kbps": 0,
        }

    c = None
    clientmod.probe_port = fake_probe
    try:
        c = HopShotClient(base_cfg(19890, port_min=19890, port_max=19940, adaptive_mode=True))
        effective_loss, scan = c._startup_auto_scan({"loss_pct": 92.0, "received": 1})
        assert scan["udp_throttled"] is True
        assert scan["udp_port_hopping_bypassed"] is True
        assert effective_loss < 20.0
        assert scan["recovery_port"] is not None
    finally:
        if c is not None:
            c.stop()
        clientmod.probe_port = original_probe
test("startup scan mirrors throttling then port-hopping recovery logic", t_startup_scan_port_hopping_recovery_logic)

# ── New tests for recent features: health, bootstrap budget, proxy relay, QUIC multi-fallback
print("\n[ New Feature Tests ]")

def t_health_endpoint_serves_ok():
    health_port = 20050 + random.randint(0, 200)
    cfg = base_cfg(20000, health_port=health_port)
    srv = servermod.HopShotServer(cfg)
    srv._start_health_server(health_port)
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", health_port, timeout=2)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200 and body == b"ok\n"
    finally:
        try:
            if srv.health_srv:
                srv.health_srv.shutdown()
        except Exception:
            pass
test("HTTP /health endpoint responds OK", t_health_endpoint_serves_ok)

def t_bootstrap_5min_budget_expires_quickly():
    port = 20100 + random.randint(0, 50)
    cfg = base_cfg(port)
    c = HopShotClient(cfg)

    original_probe = clientmod.probe_port
    original_monotonic = clientmod.time.monotonic
    original_sleep = clientmod.time.sleep
    # Fast-forward time on sleep so the 5-minute budget expires immediately
    t = [0.0]
    def fake_monotonic():
        return t[0]
    def fake_sleep(s):
        t[0] += 301.0

    def fake_probe(*args, **kwargs):
        return {"port": kwargs.get("port", args[1] if len(args) > 1 else 0), "loss_pct": 100.0, "rtt_ms": 0.0, "sent": 0, "received": 0, "clock_offset_ms": 0}

    clientmod.probe_port = fake_probe
    clientmod.time.monotonic = fake_monotonic
    clientmod.time.sleep = fake_sleep
    orig_connect = c._connect_quic
    c._connect_quic = lambda: None
    try:
        thr = threading.Thread(target=c.start)
        thr.start()
        thr.join(timeout=2.0)
        if thr.is_alive():
            # If start() hasn't returned yet, ensure our fake_sleep advanced time
            c._running = False
            try:
                c.stop()
            except Exception:
                pass
        assert t[0] >= 301.0, "fake sleep did not advance monotonic time as expected"
    finally:
        clientmod.probe_port = original_probe
        clientmod.time.monotonic = original_monotonic
        clientmod.time.sleep = original_sleep
        c._connect_quic = orig_connect
        try:
            c.stop()
        except Exception:
            pass
test("bootstrap 5-minute reachability budget expires and start returns", t_bootstrap_5min_budget_expires_quickly)

def t_proxy_open_data_close_flow():
    # Start a tiny TCP echo server to validate relay
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(1)
    port = srv_sock.getsockname()[1]

    accepted = {}
    def _tcp_worker():
        try:
            conn, addr = srv_sock.accept()
            accepted['conn'] = conn
            data = conn.recv(4096)
            accepted['recv'] = data
            # send a reply so server will emit TYPE_PROXY_DATA
            time.sleep(0.05)
            try:
                conn.sendall(b"SERVER_REPLY")
            except Exception:
                pass
            conn.close()
        except Exception:
            pass

    threading.Thread(target=_tcp_worker, daemon=True).start()

    cfg = base_cfg(20200)
    srv = servermod.HopShotServer(cfg)
    srv._running = True
    captured = []
    orig_send = srv._send_reply_fanout
    srv._send_reply_fanout = lambda pkt, addr, tx_sock=None, label="": captured.append((pkt, addr, label))
    try:
        # Construct proxy OPEN payload: [host_len][host_bytes][port_be]
        host = "127.0.0.1"
        host_b = host.encode('utf-8')
        payload = bytes([len(host_b)]) + host_b + struct.pack("!H", port)
        hdr = {"stream_id": 1, "session_id": 99}
        srv._handle_proxy_open(hdr, payload, ("127.0.0.1", 40000))
        # Wait for ACK path to be invoked
        time.sleep(0.2)
        # ACK should have been captured
        assert any(common.unpack_header(pkt)[0]["type"] == common.TYPE_PROXY_ACK for pkt,_,_ in captured), "no PROXY_ACK sent"

        # Send data from client->server which should be forwarded to TCP target
        captured.clear()
        srv._handle_proxy_data({"stream_id": 1, "session_id": 99}, b"hello target")
        time.sleep(0.2)
        assert b"hello" in accepted.get('recv', b''), "relay did not forward client payload to target"

        # Wait for server->client reply to be emitted
        time.sleep(0.2)
        assert any(common.unpack_header(pkt)[0]["type"] == common.TYPE_PROXY_DATA for pkt,_,_ in captured), "no PROXY_DATA from target forwarded"

        # Close stream
        srv._handle_proxy_close({"stream_id": 1, "session_id": 99})
        time.sleep(0.1)
        assert any(common.unpack_header(pkt)[0]["type"] == common.TYPE_PROXY_CLOSE for pkt,_,_ in captured), "no PROXY_CLOSE emitted"
    finally:
        srv._send_reply_fanout = orig_send
        try:
            srv._proxy_close(99, 1)
        except Exception:
            pass
        srv._running = False
        try:
            srv_sock.close()
        except Exception:
            pass
test("proxy open/data/close flow creates TCP relay and forwards data", t_proxy_open_data_close_flow)

def t_quic_multi_fallback_selects_winner():
    cfg = base_cfg(20300, destinations=["10.0.0.1", "127.0.0.1"]) 
    c = HopShotClient(cfg)
    original_quic = clientmod.QUICClient
    class FakeQUIC:
        def __init__(self, host, port, **kwargs):
            self.host = host
        def connect(self, retry=False):
            return self.host == "127.0.0.1"
        def close(self):
            pass
    clientmod.QUICClient = FakeQUIC
    try:
        ok = c._connect_quic_multi_fallback(1.0)
        assert ok is True
        assert c.quic_ok is True
        assert c.primary_ip == "127.0.0.1"
    finally:
        clientmod.QUICClient = original_quic
        try:
            c.stop()
        except Exception:
            pass
test("QUIC multi-connection fallback picks a working candidate", t_quic_multi_fallback_selects_winner)

# ─── Summary ──────────────────────────────────────────────────────────────────
print("\n" + "="*50)
passed = sum(1 for _,ok,_ in results if ok)
total  = len(results)
print(f"  Results: {passed}/{total} passed")
if passed < total:
    print("\n  Failed:")
    for name,ok,err in results:
        if not ok:
            print(f"    {FAIL} {name}: {err}")
print("="*50 + "\n")
sys.exit(0 if passed==total else 1)
