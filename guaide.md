Here's the complete server deployment guide:

---

## HopShot Server Deployment Guide

### What you need
- A Linux VPS (Ubuntu 20.04+ recommended)
- Root or sudo access
- Python 3.10 or newer
- Your `shared_seed` (generate one with `python3 deploy.py genkey`)

---

### Step 1 — Get the code on the server

```bash
# Install git if not already there
sudo apt update && sudo apt install -y git python3 python3-venv

# Clone the repo
git clone https://github.com/Ashentajir/backshot-hopping.git
cd backshot-hopping
```

---

### Step 2 — Generate a secret seed

Run this locally on your PC first and note the seed output:
```bash
python3 deploy.py genkey
```
It will print something like:
```
Generated new shared seed.
Seed: a3f9c1d2e4b5...
Updated: server.config.json
Updated: client.config.json
```
Copy that seed — you need the exact same value on both server and client.

---

### Step 3 — Bootstrap the server

```bash
python3 deploy.py server
```

This automatically creates the virtual environment, installs dependencies, and generates `server.config.json`. It will then launch the server. Stop it with `Ctrl+C` — we'll configure it properly first.

---

### Step 4 — Edit the server config

```bash
nano server.config.json
```

Minimum settings to change:

```json
{
  "listen_port": 10000,
  "quic_port": 10001,
  "port_min": 10000,
  "port_max": 65000,
  "shared_seed": "PASTE_YOUR_SEED_HERE",
  "setup_iptables": true,
  "keepalive_interval_sec": 15,
  "verbose": false,
  "log_file": "server.log",
  "json_logs": false
}
```

For stealth/masquerade mode add:
```json
  "masquerade": true,
  "obfs": true
```

---

### Step 5 — Open the firewall ports

```bash
# Allow the base UDP port and QUIC/TLS port
sudo ufw allow 10000/udp
sudo ufw allow 10001/tcp

# If you want the full hop range open (recommended)
sudo ufw allow 10000:65000/udp
```

If you're using a cloud provider (AWS, Hetzner, etc.) also open these ports in the provider's security group / firewall panel — UFW alone isn't enough on most cloud VPS.

---

### Step 6 — Set up iptables redirect for port hopping

This is what makes port hopping actually work — all UDP on the range funnels to your listener:

```bash
sudo iptables -t nat -A PREROUTING -p udp \
  --dport 10000:65000 -j REDIRECT --to-port 10000
```

To make this survive reboots:
```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

Or set `"setup_iptables": true` in `server.config.json` and run the server as root — it does this automatically.

---

### Step 7 — Run as a background service (systemd)

Create the service file:
```bash
sudo nano /etc/systemd/system/hopshot.service
```

Paste this (adjust the path to where you cloned the repo):
```ini
[Unit]
Description=HopShot UDP Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/backshot-hopping
ExecStart=/root/backshot-hopping/.venv/bin/python server.py --config server.config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable hopshot
sudo systemctl start hopshot

# Check it's running
sudo systemctl status hopshot

# Watch live logs
sudo journalctl -u hopshot -f
```

---

### Step 8 — Verify it's working

On the server:
```bash
# Should show the listener on port 10000
ss -ulnp | grep 10000

# Tail the log file
tail -f server.log
```

On your client machine:
```bash
python3 client.py --server YOUR_SERVER_IP --port 10000 \
  --seed "YOUR_SEED_HERE" --msg "hello"
```

You should see `✓ delivered` in the server log.

---

### Quick reference — useful commands

```bash
# Restart server after config change
sudo systemctl restart hopshot

# Check if iptables redirect is active
sudo iptables -t nat -L PREROUTING -n

# Remove iptables rule if needed
sudo iptables -t nat -D PREROUTING -p udp \
  --dport 10000:65000 -j REDIRECT --to-port 10000

# Re-run bootstrapper after a git pull
git pull && python3 deploy.py server --prepare-only
```

---

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Client probes show 100% loss | Firewall blocking UDP | Open ports in cloud panel, not just UFW |
| Port hopping not working | iptables rule missing | Re-run Step 6 |
| Client connects but rate stays 1000kbps | Brutal CC feedback not reaching client | Check seed matches on both sides |
| `[QUIC] failed` on client | Port 10001/tcp not open | `sudo ufw allow 10001/tcp` |
| Server crashes on start | Python version too old | `python3 --version` — needs 3.10+ |
