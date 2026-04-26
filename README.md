# HopShot

HopShot is a Python UDP tunneling prototype with adaptive port hopping, FEC, packet jitter, optional HTTP/3 masquerading, Brutal CC pacing, and a release-style client/server CLI.

Version: `1.0.0`

## English

### What it does

HopShot runs a client and a server that exchange UDP traffic through a configurable port range. The client can probe loss, choose a profile, hop ports deterministically, and optionally use QUIC/TLS or HTTP/3 masquerading. The server receives traffic, reconstructs FEC shards, and returns feedback.

### Main features

- Adaptive port hopping
- FEC recovery for burst loss
- Packet jitter to vary packet sizes
- Optional HTTP/3 masquerading
- Optional random source ports
- Brutal CC pacing with declared bandwidth hints
- Diagnostic CLI output
- JSON log file support
- Release version flag on both client and server

### Requirements

- Python 3.12 or newer
- Windows, Linux, or macOS
- A local or remote UDP-capable server
- Optional admin/root privileges for firewall or port redirection setup
- No domain is required. You can use a raw IP address or a hostname. A domain is only useful if you want a stable name that points to the server IP.

### Termux / Android

HopShot also runs in Termux with the standard Python package.

```bash
pkg update
pkg install python git
python deploy.py client
```

If you are connecting to a remote server, create both configs and then set the destination IP or hostname in `client.config.json`.

### Quick start

**IMPORTANT: Always generate a new shared seed using `python deploy.py genkey` before production deployment.**

### One-command deployment

Use the deployment bootstrapper to install everything and create local config files:

```bash
python deploy.py server
python deploy.py client
python deploy.py genkey    # <- Generate a random shared_seed
```

The first run creates the virtual environment, installs the available packages, and generates `server.config.json` or `client.config.json` from the example files if they do not already exist. Edit `server.config.json` if you want to change server settings, then rerun the same command.

`python deploy.py genkey` writes a fresh cryptographically random `shared_seed` into both local config files. This replaces the example placeholder seed and ensures both client and server use the same secret key for encryption. **Without this step, both sides will use the default example seed and may conflict with other HopShot deployments.**

For Windows users, there is also a simple menu launcher: `client-launch.bat`. It gives you a tiny text UI, writes `client.config.json`, and then starts the client through the bootstrapper.

#### 1. Server (Manual)

```bash
python server.py --port 10000 --seed "my-secret"
```

For a more complete deployment:

```bash
python server.py --port 10000 --quic-port 10001 --seed "my-secret" \
  --port-min 10000 --port-max 65000 --json-logs --log-file server.log
```

#### 2. Client (Manual)

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret"
```

For an operator-style setup:

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret" \
  --profile balanced --json-logs --log-file client.log
```

If you prefer a domain name instead of an IP, set `--server` to the domain or put the domain in `client.config.json`. It is optional; the client works fine with a direct IP address.

### Client profiles

- `balanced`: general-purpose default
- `reliable`: uses a slow fixed hop plus keepalive packets for lossy single-port environments
- `stealth`: enables stronger camouflage options
- `throughput`: keeps the path simpler for maximum delivery

### Tunnel mode

HopShot can also bridge a local TUN or TAP device for real packet forwarding. On Windows, the tunnel backend uses Wintun, so TAP requests are mapped to TUN because Windows does not expose a native TAP backend here.

```bash
# Client side
python client.py --server 1.2.3.4 --seed "my-secret" \
  --tunnel-mode tun --tunnel-iface hopshot0 \
  --tunnel-address 10.7.0.2/30 --tunnel-peer 10.7.0.1 \
  --tunnel-default-route

# Server side
python server.py --seed "my-secret" \
  --tunnel-mode tun --tunnel-iface hopshot0 \
  --tunnel-address 10.7.0.1/30
```

Tunnel mode requires Linux, root privileges, and `iproute2`. On Windows, install Wintun or Cloudflare WARP and run the CLI with administrator rights. TAP mode is still exposed in the CLI, but on Windows it falls back to Wintun-backed TUN.

### Security note

Do not keep the example `shared_seed` value in production configs. Use `python deploy.py genkey` to generate a fresh seed before deployment.

### Release CLI

python server.py --version
python client.py --diagnose --server 127.0.0.1 --dest 127.0.0.1
python server.py --diagnose
```

### Deployment on server

This is the recommended server flow (validated with `deploy.py server --prepare-only` and `deploy.py server --diagnose`).

1. Copy the repository to the server host and enter the folder.
2. Run a safe bootstrap first:

```bash
python deploy.py server --prepare-only
```

3. Generate a fresh shared seed and apply it to both local configs:

```bash
python deploy.py genkey
```

4. Edit `server.config.json` for your environment.
: Minimum fields to check: `listen_port`, `quic_port`, `port_min`, `port_max`, `shared_seed`, `max_ping_ms`, `log_file`.

5. Validate resolved server config before launching:

```bash
python deploy.py server --diagnose
```

6. Open firewall/NAT for UDP listener ports.
: At minimum open `listen_port` and your hop range (`port_min`..`port_max`).
: If QUIC is enabled in your deployment, open `quic_port` too.

7. Start the server:

```bash
python deploy.py server
```

8. Verify runtime:
: Confirm startup logs show listener ports and transport options.
: Check `server.log` (or your configured log file) for incoming probes/data.

Note: if startup logs show a QUIC init warning and continue in raw UDP mode, ensure OpenSSL is installed and available in PATH so certificate generation can succeed.

If the server is behind NAT or cloud security groups, make sure those rules forward/allow the same UDP ports to the host running `server.py`.

#### Linux service example (systemd)

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

Then enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hopshot
sudo systemctl status hopshot
```

#### Manual run example

```bash
python server.py --port 10000 --quic-port 10001 --seed "my-secret" \
  --port-min 10000 --port-max 65000 --max-ping-ms 15000 --masquerade
```

### Deployment on client

1. Copy the repository to the client machine.
2. Run `python deploy.py client`.
3. Edit `client.config.json` to set the destination server and any preferred client options.
4. Match the shared seed and port range.
5. Rerun the same command to start the client with the saved settings.

Example:

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret" \
  --port-min 10000 --port-max 65000 --profile balanced
```

### TUN/TAP IP Tunneling

HopShot includes bidirectional TUN/TAP support for tunneling arbitrary IP traffic:

**Client side:**
- Applications write IP packets to the TUN device (e.g., `ping`, traffic to a tunnel endpoint)
- `_tunnel_tx_loop()` reads these packets → feeds them through the full send pipeline (reactive probe → FEC encoding → burst → port hopping → obfuscation → send)
- Server receives, reconstructs via FEC, and writes to its TUN device
- Server applications read the reconstructed packets and send responses back

**Server side:**
- Applications or local traffic write responses to the server's TUN device
- `_tunnel_tx_loop()` reads these packets → encodes with FEC → sends back to client through hopping ports
- Client receives on hopping ports → reconstructs via FEC → writes to client TUN device
- Client applications read the reconstructed IP packets

**Enable TUN mode:**

```json
{
  "tunnel_mode": "tun",
  "tunnel_iface": "hopshot0",
  "tunnel_address": "10.0.0.1",
  "tunnel_peer": "10.0.0.2",
  "tunnel_mtu": 1400
}
```

The tunnel integrates with the full adaptive pipeline: packets automatically hop ports, apply FEC for burst loss recovery, obfuscate if enabled, and adapt burst multipliers based on detected loss.

### Logging and diagnostics

- `--log-file` writes logs to a file.
- `--json-logs` writes file logs as JSON lines.
- `--diagnose` prints the resolved configuration and exits.
- `--msg` sends one message and exits.

### Roadmap / remaining gaps

None identified. Full feature set complete:
- ✅ Adaptive port hopping with loss-based mode classification
- ✅ FEC Reed-Solomon error correction (4k+4m shards)
- ✅ Brutal CC bandwidth feedback and pacing
- ✅ TUN/TAP IP tunneling with bidirectional pipeline
- ✅ HTTP/3 masquerading and packet obfuscation
- ✅ Multi-destination failover and QUIC fallback
- ✅ Clock skew compensation
- ✅ Session resumption and 0-RTT probe tokens

### Project layout

- `client.py` - client CLI and transport pipeline
- `server.py` - server CLI and receive pipeline
- `common.py` - packet headers, hopping, and shared helpers
- `tun_transport.py` - cross-platform TUN/TAP device helpers
- `tunnel_codec.py` - shared packet encode/decode helpers for tunnel mode
## فارسی

### این پروژه چه کاری انجام می‌دهد
### ویژگی‌ها

- پرش تطبیقی پورت
- بازیابی خطا با FEC
- تغییر اندازهٔ بسته‌ها برای سخت‌تر شدن fingerprint
- ماسک‌کردن اختیاری HTTP/3
- تصادفی‌سازی اختیاری پورت مبدأ
- کنترل نرخ با Brutal CC
- خروجی تشخیصی برای CLI
- پشتیبانی از لاگ JSON
- نمایش نسخه در کلاینت و سرور

### پیش‌نیازها

- Python 3.14 یا جدیدتر
- ویندوز، لینوکس یا macOS
- یک سرور UDP در دسترس
- در صورت نیاز، دسترسی admin/root برای باز کردن یا redirect کردن پورت‌ها
- دامنه لازم نیست. می‌توانید از IP مستقیم یا hostname استفاده کنید. دامنه فقط وقتی مفید است که بخواهید یک نام ثابت به IP سرور وصل باشد.

### راه‌اندازی سریع

### استقرار یک‌مرحله‌ای

برای نصب خودکار و ساخت فایل تنظیمات، این دستورها را اجرا کنید:

```bash
python deploy.py server
python deploy.py client
```

اجرای اول، virtual environment را می‌سازد، بسته‌های موجود را نصب می‌کند، و در صورت نبودن فایل‌ها، `server.config.json` یا `client.config.json` را از نمونه‌ها ایجاد می‌کند. اگر خواستید تنظیمات سرور را تغییر دهید، فقط `server.config.json` را ویرایش کنید و همان دستور را دوباره اجرا کنید.

برای کاربران ویندوز، یک لانچر ساده هم اضافه شده است: `client-launch.bat`. این فایل یک منوی متنی خیلی ساده نشان می‌دهد، `client.config.json` را می‌سازد، و بعد کلاینت را از طریق bootstrapper اجرا می‌کند.

#### 1) سرور

اول سرور را اجرا کنید:

```bash
python server.py --port 10000 --seed "my-secret"
```

برای حالت کامل‌تر:

```bash
python server.py --port 10000 --quic-port 10001 --seed "my-secret" \
  --port-min 10000 --port-max 65000 --json-logs --log-file server.log
```

#### 2) کلاینت

سپس کلاینت را اجرا کنید:

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret"
```

برای استفادهٔ عملیاتی‌تر:

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret" \
  --profile balanced --json-logs --log-file client.log
```

اگر به‌جای IP بخواهید از دامنه استفاده کنید، کافی است `--server` را روی دامنه بگذارید یا همان را داخل `client.config.json` قرار دهید. این اختیاری است و کلاینت با IP مستقیم هم کاملاً کار می‌کند.

### پروفایل‌های کلاینت

- `balanced`: حالت پیش‌فرض عمومی
- `reliable`: ساده‌تر و پایدارتر، بدون hopping
- `stealth`: با تنظیمات مخفی‌سازی قوی‌تر
- `throughput`: مسیر ساده‌تر برای تحویل بهتر

### حالت Tunnel

HopShot می‌تواند یک دستگاه Linux TUN یا TAP را برای عبور واقعی packetها bridge کند.

```bash
# سمت کلاینت
python client.py --server 1.2.3.4 --seed "my-secret" \
  --tunnel-mode tun --tunnel-iface hopshot0 \
  --tunnel-address 10.7.0.2/30 --tunnel-peer 10.7.0.1 \
  --tunnel-default-route

# سمت سرور
python server.py --seed "my-secret" \
  --tunnel-mode tun --tunnel-iface hopshot0 \
  --tunnel-address 10.7.0.1/30
```

این حالت به Linux، دسترسی root و `iproute2` نیاز دارد. TAP هم در کد expose شده است، ولی برای استفادهٔ درست معمولاً باید bridge یا routing خارجی هم تنظیم کنید.

### دستورهای نسخه و تشخیص

```bash
python client.py --version
python server.py --version
python client.py --diagnose --server 127.0.0.1 --dest 127.0.0.1
python server.py --diagnose
```

### استقرار روی سرور

1. مخزن را روی ماشین سرور کپی کنید.
2. دستور `python deploy.py server` را اجرا کنید.
3. اگر خواستید پورت‌ها، seed یا لاگ را تغییر دهید، `server.config.json` را ویرایش کنید.
4. پورت‌های UDP و در صورت نیاز QUIC/TLS را باز کنید.
5. همان دستور را دوباره اجرا کنید تا سرور با تنظیمات ذخیره‌شده بالا بیاید.

نمونه:

```bash
python server.py --port 10000 --quic-port 10001 --seed "my-secret" \
  --port-min 10000 --port-max 65000 --iptables --masquerade
```

اگر سرور پشت firewall یا NAT است، باید پورت‌ها به همان ماشین forward شوند.

### استقرار روی کلاینت

1. مخزن را روی ماشین کلاینت کپی کنید.
2. دستور `python deploy.py client` را اجرا کنید.
3. `client.config.json` را ویرایش کنید تا IP یا hostname سرور و گزینه‌های دلخواه کلاینت تنظیم شوند.
4. seed و بازهٔ پورت را با سرور هماهنگ کنید.
5. همان دستور را دوباره اجرا کنید تا کلاینت با تنظیمات ذخیره‌شده بالا بیاید.

نمونه:

```bash
python client.py --server 1.2.3.4 --port 10000 --seed "my-secret" \
  --port-min 10000 --port-max 65000 --profile balanced
```

### لاگ و عیب‌یابی

- `--log-file` لاگ را در فایل ذخیره می‌کند.
- `--json-logs` لاگ فایل را به صورت JSON line می‌نویسد.
- `--diagnose` تنظیمات نهایی را چاپ می‌کند و خارج می‌شود.
- `--msg` یک پیام می‌فرستد و تمام می‌شود.

### یادداشت امنیتی

از مقدار نمونهٔ `shared_seed` در محیط واقعی استفاده نکنید. با `python deploy.py genkey` یک seed جدید و تصادفی بسازید.

### ساختار پروژه

- `deploy.py` - bootstrapper خودکار برای سرور و کلاینت
- `server.config.example.json` - تنظیمات نمونهٔ سرور
- `client.config.example.json` - تنظیمات نمونهٔ کلاینت
- `requirements.txt` - فهرست نصب برای bootstrapper
- `client.py` - CLI و مسیر ارسال کلاینت
- `server.py` - CLI و مسیر دریافت سرور
- `common.py` - هدر بسته‌ها و helperهای مشترک
- `fec.py` - منطق FEC و بازیابی
- `brutal.py` - pacing و feedback
- `http3_masq.py` - ماسک‌کردن HTTP/3
- `mtu_probe.py` - تشخیص MTU
- `resolver.py` - DNS و probing مقصد
- `session_resume.py` - کش tokenهای probe
- `terminal_ui.py` - لاگ رنگی و formatting ترمینال
- `tun_transport.py` - helperهای دستگاه Linux TUN/TAP
- `tunnel_codec.py` - helperهای encode/decode برای tunnel mode
- `test_hopshot.py` - تست‌های یکپارچه

### نکته

- این پروژه برای آزمایش و استقرار کنترل‌شده طراحی شده است.
- کلاینت و سرور باید یک seed مشترک داشته باشند.
- اگر masquerade یا iptables redirect را فعال می‌کنید، تنظیمات سمت سرور را هم انجام دهید.
