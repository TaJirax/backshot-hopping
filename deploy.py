#!/usr/bin/env python3
"""Self-installing bootstrapper for HopShot server/client deployments."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"


SERVER_DEFAULT_CONFIG = {
    "listen_port": 10000,
    "quic_port": 10001,
    "port_min": 10000,
    "port_max": 65000,
    "shared_seed": "change-me",
    "max_ping_ms": 15000,
    "obfs": False,
    "masquerade": False,
    "setup_iptables": False,
    "auto_bind_port_range": True,
    "auto_bind_port_range_max": 0,
    "certfile": "hopshot.crt",
    "keyfile": "hopshot.key",
    "declared_down_kbps": 0,
    "verbose": False,
    "jitter_bytes": 64,
    "tunnel_mode": "off",
    "tunnel_iface": "hopshot0",
    "tunnel_mtu": 1400,
    "tunnel_address": "10.7.0.1/30",
    "tunnel_peer": "10.7.0.2",
    "tunnel_route_default": False,
    "tunnel_udp_bind": "127.0.0.1:19091",
    "tunnel_udp_target": None,
    "keepalive_interval_sec": 15,
    "log_file": "server.log",
    "json_logs": False,
}


CLIENT_DEFAULT_CONFIG = {
    "server_port": 10000,
    "quic_port": 10001,
    "port_min": 10000,
    "port_max": 65000,
    "shared_seed": "change-me",
    "profile": "balanced",
    "startup_capacity_scan": True,
    "scan_throttle_threshold_pct": 80.0,
    "scan_recovery_threshold_pct": 20.0,
    "obfs": False,
    "rand_src_port": False,
    "jitter_bytes": 64,
    "preemptive_hop_ms": 800,
    "fixed_hop_ms": 0,
    "keepalive_interval_sec": 15,
    "tunnel_mode": "off",
    "tunnel_iface": "hopshot0",
    "tunnel_mtu": 1400,
    "tunnel_address": "10.7.0.2/30",
    "tunnel_peer": "10.7.0.1",
    "tunnel_route_default": True,
    "tunnel_udp_bind": "127.0.0.1:19090",
    "tunnel_udp_target": None,
    "declared_up_kbps": 0,
    "declared_down_kbps": 0,
    "masquerade": False,
    "mtu": 0,
    "fec_k": 4,
    "fec_m": 4,
    "probe_count": 20,
    "probe_timeout_ms": 2000,
    "destinations": ["127.0.0.1"],
    "resolvers": ["1.1.1.1"],
    "verbose": False,
    "log_file": "client.log",
    "json_logs": False,
    "metrics_file": "client.metrics.jsonl",
}


def venv_python_path() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def requirements_present() -> bool:
    req = ROOT / "requirements.txt"
    if not req.exists():
        return False
    for line in req.read_text(encoding="utf-8").splitlines():
        if not is_comment_or_blank(line):
            return True
    return False


def ensure_venv() -> Path:
    py = venv_python_path()
    if py.exists():
        return py
    subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
    return venv_python_path()


def install_dependencies(py: Path) -> None:
    subprocess.check_call([str(py), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    if requirements_present():
        subprocess.check_call([str(py), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])


def default_config(role: str) -> dict:
    if role == "server":
        return dict(SERVER_DEFAULT_CONFIG)
    return dict(CLIENT_DEFAULT_CONFIG)


def ensure_config(role: str, config_path: Path) -> None:
    if config_path.exists():
        return
    example = ROOT / f"{role}.config.example.json"
    payload = default_config(role)
    if example.exists():
        shutil.copyfile(example, config_path)
        return
    config_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_config(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def update_shared_seed(seed: str) -> tuple[Path, Path]:
    server_path = ROOT / "server.config.json"
    client_path = ROOT / "client.config.json"
    ensure_config("server", server_path)
    ensure_config("client", client_path)

    server_cfg = load_config(server_path)
    client_cfg = load_config(client_path)
    server_cfg["shared_seed"] = seed
    client_cfg["shared_seed"] = seed
    write_config(server_path, server_cfg)
    write_config(client_path, client_cfg)
    return server_path, client_path


def _is_placeholder_seed(seed: str) -> bool:
    value = str(seed or "").strip().lower()
    return value in {"", "change-me", "changeme", "default", "hopshot-default-seed"}


def ensure_server_config_ready(config_path: Path, auto_seed: bool = False) -> tuple[dict, list[str]]:
    cfg = default_config("server")
    cfg.update(load_config(config_path))
    notes: list[str] = []

    listen_port = int(cfg.get("listen_port", SERVER_DEFAULT_CONFIG["listen_port"]) or SERVER_DEFAULT_CONFIG["listen_port"])
    cfg["listen_port"] = listen_port
    cfg["quic_port"] = int(cfg.get("quic_port", listen_port + 1) or (listen_port + 1))

    if "port_min" not in cfg or cfg.get("port_min") is None:
        cfg["port_min"] = listen_port
    if "port_max" not in cfg or cfg.get("port_max") is None:
        cfg["port_max"] = int(cfg["port_min"])

    port_min = int(cfg["port_min"])
    port_max = int(cfg["port_max"])
    if port_max < port_min:
        port_min, port_max = port_max, port_min
        notes.append("Swapped port_min/port_max because they were reversed.")
    cfg["port_min"] = port_min
    cfg["port_max"] = port_max

    if auto_seed and _is_placeholder_seed(str(cfg.get("shared_seed", ""))):
        seed = secrets.token_hex(32)
        cfg["shared_seed"] = seed
        notes.append("Generated a fresh shared_seed for server config.")

        client_path = ROOT / "client.config.json"
        if client_path.exists():
            try:
                client_cfg = load_config(client_path)
                client_cfg["shared_seed"] = seed
                write_config(client_path, client_cfg)
                notes.append("Updated client.config.json to the same shared_seed.")
            except json.JSONDecodeError:
                notes.append("Skipped client.config.json seed sync because that file is not valid JSON.")

    write_config(config_path, cfg)
    return cfg, notes


def main() -> int:
    parser = argparse.ArgumentParser(description="HopShot deployment bootstrapper")
    parser.add_argument("role", choices=("server", "client", "genkey"), help="Which app to prepare and run")
    parser.add_argument("--config", default=None, help="Config file to create/use for the selected role")
    parser.add_argument("--prepare-only", action="store_true", help="Install and create config, but do not launch")
    parser.add_argument("--easy", action="store_true", help="Server-only: normalize config and auto-generate shared_seed if still placeholder")
    parser.add_argument("--diagnose", action="store_true", help="Run target script with --diagnose after prepare steps")
    args, extra = parser.parse_known_args()

    py = ensure_venv()
    install_dependencies(py)

    if args.role == "genkey":
        seed = secrets.token_hex(32)
        server_path, client_path = update_shared_seed(seed)
        print("Generated new shared seed.")
        print(f"Seed: {seed}")
        print(f"Updated: {server_path}")
        print(f"Updated: {client_path}")
        return 0

    config_path = Path(args.config) if args.config else ROOT / f"{args.role}.config.json"
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    ensure_config(args.role, config_path)

    if args.easy and args.role != "server":
        print("--easy is supported only with role=server")
        return 2

    if args.easy and args.role == "server":
        cfg, notes = ensure_server_config_ready(config_path, auto_seed=True)
        print("Server easy-setup ready.")
        print(f"Config: {config_path}")
        print(f"Ports: {cfg['listen_port']} (QUIC {cfg['quic_port']}), hop range {cfg['port_min']}-{cfg['port_max']}")
        if notes:
            for note in notes:
                print(f"- {note}")
        if args.prepare_only:
            print("Next step: python deploy.py server --config server.config.json")

    if args.prepare_only:
        print(f"Prepared {args.role} environment.")
        print(f"Config: {config_path}")
        print(f"Venv: {VENV_DIR}")
        if args.role == "server":
            print("Tip: python deploy.py server --easy --prepare-only for quick production-safe defaults.")
        if args.diagnose:
            script_path = ROOT / f"{args.role}.py"
            diagnose_cmd = [str(py), str(script_path), "--config", str(config_path), "--diagnose"]
            return subprocess.call(diagnose_cmd)
        return 0

    script_path = ROOT / f"{args.role}.py"
    if args.diagnose:
        diagnose_cmd = [str(py), str(script_path), "--config", str(config_path), "--diagnose"]
        rc = subprocess.call(diagnose_cmd)
        if rc != 0:
            return rc

    command = [str(py), str(script_path), "--config", str(config_path), *extra]
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
