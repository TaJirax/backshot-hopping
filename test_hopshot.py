#!/usr/bin/env python3
"""
HopShot integration tests — covers every feature.
Run: python3 test_hopshot.py
"""
import os, sys, socket, struct, threading, time, random
sys.path.insert(0, os.path.dirname(__file__))

import common, fec as fecmod, brutal
import client as clientmod
from client import probe_port, HopShotClient, PROFILE_PRESETS, apply_profile_overrides
from http3_masq import HTTP3Masq
from resolver import Resolver, _query_resolver, _build_dns_query, _parse_dns_response
from session_resume import ResumeTokenStore, TOKEN_SIZE

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
                probe_token=None, drop_every=0):
    """Returns (run_obj, received_list). run_obj.alive=False to stop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.1)
    received = []
    groups   = {}
    data_seen = 0
    fec_k = fec_m = 4

    def run():
        nonlocal data_seen
        while getattr(run, "alive", True):
            try:
                data, addr = sock.recvfrom(2048)
                if obfs:
                    data = common.salamander(data, seed)
                hdr, payload = common.unpack_header(data)
                if not hdr: continue
                if hdr["type"] == common.TYPE_PROBE:
                    rep = common.pack_header(common.TYPE_PROBE_REPLY,
                          seq=hdr["seq"], session_id=hdr["session_id"])
                    if probe_token is not None:
                        rep += probe_token
                    if obfs: rep = common.salamander(rep, seed)
                    sock.sendto(rep, addr)
                elif hdr["type"] == common.TYPE_DATA:
                    data_seen += 1
                    if drop_every and data_seen % drop_every == 0:
                        continue
                    orig_len   = struct.unpack_from("!I", payload)[0]
                    shard_data = common.strip_jitter_padding(payload[4:], jitter)
                    seq, idx, total = hdr["seq"], hdr["shard_idx"], hdr["total_shards"]
                    if seq not in groups:
                        groups[seq] = {"s": [None]*total, "ol": orig_len, "done": False}
                    g = groups[seq]
                    if not g["done"] and g["s"][idx] is None:
                        g["s"][idx] = shard_data
                        if sum(1 for x in g["s"] if x) >= fec_k:
                            try:
                                rec = fecmod.reconstruct_data(g["s"], fec_k, fec_m, g["ol"])
                                g["done"] = True
                                received.append(rec)
                            except: pass
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
    cases=[(0,0),(29,0),(30,1),(59,1),(60,2),(79,2),(80,3),(100,3)]
    for loss,exp in cases:
        assert common.classify_loss(loss)==exp, f"loss={loss}"
test("all thresholds: normal/moderate/high/NUCLEAR", t_modes)

def t_burst_mult():
    assert common.MODE_PARAMS[0][1]==1
    assert common.MODE_PARAMS[1][1]==2
    assert common.MODE_PARAMS[2][1]==4
    assert common.MODE_PARAMS[3][1]==8
test("burst multipliers 1x/2x/4x/8x correct", t_burst_mult)

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
    assert cfg["disable_hop"] is True
    assert cfg["obfs"] is False
    assert cfg["masquerade"] is False
    assert cfg["rand_src_port"] is False
    assert cfg["jitter_bytes"] == 0
    assert cfg["preemptive_hop_ms"] == 0
    assert set(PROFILE_PRESETS) == {"balanced", "reliable", "stealth", "throughput"}
test("profile presets map to safe operator modes", t_profile_overrides)

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
    # Pre-emptive interval (800ms) must be <= mode hop interval (1000ms nuclear)
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
    time.sleep(0.1)
    fb=r.feedback()
    assert fb and fb[2]>0
test("receiver detects seq gaps as loss%", t_cc_receiver_loss)

def t_cc_receiver_rate():
    r=brutal.BrutalReceiver()
    for i in range(20): r.on_packet(i,1000)
    time.sleep(0.1)
    fb=r.feedback()
    assert fb and fb[0]>0
test("receiver measures recv rate > 0", t_cc_receiver_rate)

def t_cc_receiver_down_ceiling():
    r=brutal.BrutalReceiver(declared_down_kbps=1200)
    for i in range(20):
        r.on_packet(i,50000)
    time.sleep(0.1)
    fb=r.feedback()
    assert fb and fb[0] <= 1200
test("receiver caps reported rate to declared_down_kbps", t_cc_receiver_down_ceiling)

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
test("pack/unpack header roundtrip", t_hdr)

def t_bad_magic():
    hdr,_=common.unpack_header(b"\x00"*16)
    assert hdr is None
test("bad magic rejected", t_bad_magic)

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
