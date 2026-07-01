# HopShot Testing Guide

Use this file for quick resilience checks. For normal setup, use `README.md`.

## Fast checks

### Reliable profile

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "your-secret" --profile reliable
```

### Unstable network simulation

```bash
sudo tc qdisc add dev eth0 root netem delay 200ms loss 10%
python client.py --server 1.2.3.4 --port 10000 --seed "test" --profile mobile
```

### Firewall fallback test

```bash
sudo iptables -A INPUT -p tcp --dport 10001 -j DROP
python client.py --server 1.2.3.4 --port 10000 --seed "test" --profile reliable
```

### Server outage recovery

```bash
systemctl stop hopshot-server
python client.py --server 1.2.3.4 --port 10000 --seed "test" --profile reliable
systemctl start hopshot-server
```

## Good settings for tests

### High packet loss

```json
{
  "profile": "survival",
  "max_ping_ms": 10000,
  "probe_timeout_ms": 15000,
  "fec_k": 4,
  "fec_m": 6,
  "keepalive_interval_sec": 10
}
```

### High latency

```json
{
  "profile": "reliable",
  "max_ping_ms": 15000,
  "probe_timeout_ms": 20000,
  "adaptive_mode": true,
  "preemptive_hop_ms": 1000
}
```

### Strict firewall

```json
{
  "profile": "stealth",
  "port_min": 1024,
  "port_max": 65535,
  "disable_hop": false,
  "masquerade": true,
  "obfs": true
}
```

## Log checks

```bash
tail -f client.log | grep -E "QUIC|recovery|fallback"
```

Look for:
- `quic_connect`
- `quic_recovery`
- `monitor_probe`

## Fix common issues

- If the client will not connect, increase `max_ping_ms` and `probe_timeout_ms`.
- If disconnections happen often, increase `keepalive_interval_sec` and use `survival` or `reliable`.
- If CPU usage is high, reduce `probe_count` and use `balanced` or `throughput`.

## Notes

- `README.md` now has the main deployment steps.
- `RESILIENCE_IMPROVEMENTS.md` keeps the engineering details.
- testit
