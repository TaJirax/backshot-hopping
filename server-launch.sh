#!/usr/bin/env sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR" || exit 1

resolve_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN=python
    return 0
  fi
  echo "Python not found. Install Python 3.10+ and try again."
  return 1
}

pause_wait() {
  printf "Press Enter to continue..."
  read -r _
}

run_deploy() {
  "$PYTHON_BIN" deploy.py "$@"
}

edit_config() {
  if [ ! -f "server.config.json" ]; then
    echo "Preparing server.config.json first..."
    run_deploy server --easy --prepare-only --config server.config.json || return 1
  fi

  EDITOR_CMD=${EDITOR:-}
  if [ -n "$EDITOR_CMD" ] && command -v "$EDITOR_CMD" >/dev/null 2>&1; then
    "$EDITOR_CMD" server.config.json
  elif command -v nano >/dev/null 2>&1; then
    nano server.config.json
  elif command -v vi >/dev/null 2>&1; then
    vi server.config.json
  else
    echo "No editor found. Set EDITOR or install nano/vi."
    return 1
  fi

  "$PYTHON_BIN" -c "import json; json.load(open('server.config.json','r',encoding='utf-8')); print('server.config.json OK')" || {
    echo "Config is invalid JSON. Fix and retry."
    return 1
  }
  return 0
}

if ! resolve_python; then
  exit 1
fi

while true; do
  clear 2>/dev/null || true
  echo "=================================================="
  echo "  HopShot Server Launcher (Linux)"
  echo "=================================================="
  echo
  echo "1) Easy setup + start server (recommended)"
  echo "2) Easy setup only (no start)"
  echo "3) Diagnose server config"
  echo "4) Generate shared seed (server/client)"
  echo "5) Start server (normal)"
  echo "6) Edit server config"
  echo "x) Exit"
  echo
  printf "Select an option: "
  read -r choice

  case "$choice" in
    1)
      run_deploy server --easy --config server.config.json
      pause_wait
      ;;
    2)
      run_deploy server --easy --prepare-only --config server.config.json
      pause_wait
      ;;
    3)
      run_deploy server --easy --diagnose --prepare-only --config server.config.json
      pause_wait
      ;;
    4)
      run_deploy genkey
      pause_wait
      ;;
    5)
      run_deploy server --config server.config.json
      pause_wait
      ;;
    6)
      edit_config
      pause_wait
      ;;
    x|X)
      exit 0
      ;;
    *)
      echo "Invalid option"
      pause_wait
      ;;
  esac
done
