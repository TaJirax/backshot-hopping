# HopShot v2 — Adaptive UDP Port Hopping Tunnel (Python)

Zero external dependencies. Pure Python 3. Runs on Linux, macOS, Termux/Android.

## New in v2 — Features inspired by established projects

| Feature | Inspired by | Module |
|---|---|---|
| **Randomized hop interval** | Hysteria2 changelog | `common.py` |
| **KCP-style Selective ARQ** | KCP protocol | `fec.py` → `SelectiveARQ` |
| **HTTP/3 masquerading** | Hysteria2 | `http3_masq.py` |
| **User-declared bandwidth** | Hysteria2 Brutal CC | `brutal.py` |
| **0-RTT session resumption** | TUIC | `session_resume.py` |
| **MTU probing** | KCP | `mtu_probe.py` |

---

## Full pipeline (v2)

```
[CLIENT]
  MTU Probe — discover safe path MTU (KCP-style)
  Port Probe — measure loss %
  0-RTT Check — use session token if available (TUIC-style)
  Pick mode (normal / moderate / high / NUCLEAR)
  Dual stack: raw UDP + QUIC (TLS 1.3) simultaneously
  Brutal CC — user-declared bandwidth ceiling (Hysteria2-style)
  FEC encode — Reed-Solomon (4 data + 4 parity shards)
  Selective ARQ — NACK only missing shards (KCP-style)
  Burst sender — each shard sent x N times across different ports
  Randomized hop — shared_seed + jittered_time_slot -> port (Hysteria2-style)
  HTTP/3 masquerade — wrap in QUIC Initial + H3 DATA frame (optional)
  Salamander obfs — optional XOR-stream scrambling
  ════════ NETWORK ════════
[SERVER]
  HTTP/3 de-masquerade (optional)
  MTU reply — echo probe size back to client
  0-RTT token issuance — include in first probe reply
  iptables redirect — full port range -> listener
  Burst receiver — deduplicates redundant copies
  FEC decode — reconstructs from any 4 of 8 shards
  Brutal CC feedback — measures recv rate + loss, replies to client
  QUIC or raw UDP stream delivered
```

---

## Feature Details

### 1. Randomized Hop Interval (Hysteria2-style)
Instead of a fixed interval (e.g. always hop every 1000ms), each hop uses a
±30% randomized interval derived from the shared seed. Both client and server
agree on the same jitter without signaling. The flow signature keeps changing
unpredictably, defeating interval-based DPI fingerprinting.

### 2. KCP-style Selective ARQ on top of FEC
FEC handles random loss. If more than `m` shards are lost in a burst (FEC
failure), the Selective ARQ tracker sends NACKs for only the missing shards —
not the entire window. Far more efficient than Go-Back-N under burst loss.

### 3. HTTP/3 Masquerading (Hysteria2-style)
Wraps HopShot UDP packets inside a byte-accurate QUIC Initial + HTTP/3 DATA
frame. Shallow DPI sees QUIC web traffic. The wrapping is deterministic from
the shared seed so the server strips it without extra signaling.

### 4. User-declared Bandwidth (Hysteria2 Brutal CC)
Pass `--declared-up <kbps>` to set the Brutal CC ceiling. The CC never
exceeds this, preventing the spray-and-pray pattern that triggers ISP QoS.

### 5. 0-RTT Session Resumption (TUIC-style)
Server embeds a 32-byte HMAC token in the first probe reply. On reconnect,
the client presents the token and data flows in the very first packet.
Tokens rotate every 5 minutes to bound replay risk.

### 6. MTU Probing (KCP-style)
Client sends probes of increasing size; server echoes back received size.
FEC shards are sized to fit within the discovered MTU, eliminating IP
fragmentation that destroys port-hop stealth.

---

## Usage

### Server
```bash
python3 server.py --port 10000 --seed "my-secret"
sudo python3 server.py --port 10000 --seed "my-secret" \
    --masquerade --obfs --iptables --port-min 10000 --port-max 65000
```

### Client
```bash
# Basic
python3 client.py --server 1.2.3.4 --port 10000 --seed "my-secret"

# Declare uplink bandwidth (prevents ISP QoS)
python3 client.py --server 1.2.3.4 --port 10000 --seed "my-secret" \
    --declared-up 50000

# Full stealth
python3 client.py --server 1.2.3.4 --port 10000 --seed "my-secret" \
    --port-min 10000 --port-max 65000 \
    --masquerade --obfs --rand-src-port --declared-up 50000
```

### JSON config
```json
{
  "server_port":      10000,
  "shared_seed":      "my-secret",
  "masquerade":       true,
  "declared_up_kbps": 50000,
  "mtu":              0,
  "fec_k":            4,
  "fec_m":            4
}
```
known bug to be fixed :  prot probe token  is broken i know why im working on it  0-RTT is  not working in this version 