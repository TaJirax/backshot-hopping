# HopShot v2 — Advanced Notes

This file keeps the longer technical notes for contributors. For normal use, prefer `README.md`.

## Current advanced features

- Randomized hop interval derived from the shared seed
- Selective ARQ on top of FEC
- HTTP/3 masquerading and Salamander obfuscation
- Declared bandwidth hints for Brutal CC
- 0-RTT session resumption
- MTU probing and adaptive shard sizing

## Minimal usage

```bash
python deploy.py server --easy
python deploy.py client
python deploy.py genkey
```

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret" --profile balanced
python server.py --port 10000 --seed "my-secret"
```

## Notes

- Proxy mode is app/browser proxy only.
- `tun` / `tap` with `--tunnel-default-route` is the whole-PC VPN path.
- `udp` tunnel mode is relay-only.
test
