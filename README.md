# HopShot

HopShot is a Python UDP tunnel with adaptive port hopping, FEC, Brutal CC pacing, QUIC fallback, proxy mode, and full tunnel mode.

Version: `1.0.0`

## What to use

- Use `proxy` mode when you want to point a browser or app at a proxy host and port.
- Use `tun` or `tap` with `--tunnel-default-route` when you want the whole PC to route through HopShot like a VPN.
- Use `udp` tunnel mode when you want a local relay path without full-device routing.

## Quick start

1. Create or update configs:

```bash
python deploy.py server --prepare-only
python deploy.py client
python deploy.py genkey
```

2. Start the server:

```bash
python deploy.py server --easy
```

3. Start the client:

```bash
python deploy.py client
```

## Windows launchers

- `client-launch.bat` gives a menu for client deploy, proxy, and tunnel setup.
- `server-launch.bat` gives a menu for server deploy, diagnose, seed generation, and config editing.

## Client modes

### Proxy mode

Set your browser or app proxy to the value shown in the client startup screen, usually:

```text
127.0.0.1:1080
```

That is an app-level proxy, not a full system VPN.

### Full VPN / tunnel mode

To route the whole PC through HopShot, use `tun` or `tap` and enable `--tunnel-default-route`:

```bash
python client.py --server 1.2.3.4 --seed "my-secret" \
  --tunnel-mode tun --tunnel-iface hopshot0 \
  --tunnel-address 10.7.0.2/30 --tunnel-peer 10.7.0.1 \
  --tunnel-default-route
```

When that is active, external sites should see the server exit IP, assuming the server has outbound internet access.

### Userspace UDP relay mode

`udp` tunnel mode is a local relay path only. It is useful when TUN/TAP is not available, but it does not redirect the whole PC.

## Server deployment guide

### Recommended quick deploy

```bash
python deploy.py server --easy --prepare-only
python deploy.py server --easy
```

`--easy` normalizes the server config, enables adaptive defaults, and keeps the server ready for tunnel or proxy requests.

### Manual server setup

1. Edit `server.config.json`.
2. Make sure these are set:

```json
{
  "listen_port": 10000,
  "quic_port": 10001,
  "port_min": 10000,
  "port_max": 65000,
  "shared_seed": "PASTE_THE_SAME_SEED_AS_CLIENT",
  "service_mode": "tunnel",
  "tunnel_mode": "udp",
  "adaptive_tunnel_on_demand": true,
  "adaptive_proxy_on_demand": true,
  "max_rx_datagram": 65535,
  "keepalive_interval_sec": 15,
  "log_file": "server.log"
}
```

3. Open firewall ports:

```bash
sudo ufw allow 10000/udp
sudo ufw allow 10001/tcp
sudo ufw allow 10000:65000/udp
```

4. If you want port hopping to work reliably on Linux, enable iptables redirect:

```bash
sudo iptables -t nat -A PREROUTING -p udp \
  --dport 10000:65000 -j REDIRECT --to-port 10000
```

### Run as a service

```ini
[Unit]
Description=HopShot Server
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/hopshot
ExecStart=/usr/bin/python3 /opt/hopshot/deploy.py server --config /opt/hopshot/server.config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hopshot
sudo systemctl status hopshot
```

## Config files

- `client.config.json` and `server.config.json` are the local runtime configs.
- `client.config.example.json` and `server.config.example.json` are the safe templates.
- Run `python deploy.py genkey` to write the same fresh `shared_seed` into both local configs.

## Troubleshooting

- If proxy mode works but full VPN does not, make sure you used `tun` or `tap` and enabled `--tunnel-default-route`.
- If tunnel mode says relay only, that is expected for `udp` tunnel mode.
- If the server does not start, check Python 3.10+, firewall rules, and `server.log`.

## فارسی

### این پروژه چیست؟

HopShot یک تونل UDP با پرش پورت تطبیقی، FEC، Brutal CC، حالت پروکسی، و حالت تونل کامل است.

### کدام حالت را استفاده کنم؟

- اگر می‌خواهید فقط مرورگر یا یک برنامه را وصل کنید، از `proxy` استفاده کنید.
- اگر می‌خواهید کل سیستم از طریق HopShot برود، از `tun` یا `tap` همراه با `--tunnel-default-route` استفاده کنید.
- اگر TUN/TAP ندارید، `udp` فقط یک relay محلی است و VPN کامل نیست.

### راه‌اندازی سریع

```bash
python deploy.py server --prepare-only
python deploy.py client
python deploy.py genkey
python deploy.py server --easy
```

### راه‌اندازی سرور

1. فایل `server.config.json` را ویرایش کنید.
2. مطمئن شوید `shared_seed` در کلاینت و سرور یکی است.
3. پورت‌های `10000/udp` و `10001/tcp` را باز کنید.
4. اگر پرش پورت می‌خواهید، رنج UDP را هم باز کنید.

### حالت VPN کامل

اگر می‌خواهید IP عمومی سیستم عوض شود، این شرط‌ها لازم است:

- `tunnel_mode` برابر `tun` یا `tap` باشد.
- `tunnel_route_default` در کلاینت `true` باشد.
- سرور خروجی اینترنت داشته باشد.

### حالت پروکسی

آدرس پروکسی را از خروجی کلاینت بردارید. معمولاً این است:

```text
127.0.0.1:1080
```
test
### نکته مهم

اگر `tunnel_mode=udp` باشد، فقط relay محلی فعال است و کل سیستم را تونل نمی‌کند.
