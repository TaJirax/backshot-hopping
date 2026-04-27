@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"
title HopShot Client Launcher

for /f %%E in ('echo prompt $E^| cmd') do set "ESC=%%E"
set "C_RESET=%ESC%[0m"
set "C_DIM=%ESC%[2m"
set "C_BOLD=%ESC%[1m"
set "C_GREEN=%ESC%[32m"
set "C_YELLOW=%ESC%[33m"
set "C_CYAN=%ESC%[36m"
set "C_WHITE=%ESC%[37m"

set "SERVER=127.0.0.1"
set "DESTINATIONS=127.0.0.1"
set "PORT=10000"
set "QUIC_PORT=10001"
set "SEED=change-me"
set "PROFILE=balanced"
set "JITTER=64"
set "PORT_MIN=10000"
set "PORT_MAX=65000"
set "PREEMPTIVE=800"
set "FIXED_HOP_MS=0"
set "DISABLE_HOP=false"
set "MANUAL_BURST=0"
set "KEEPALIVE_SEC=15"
set "ADAPTIVE_MODE=true"
set "MAX_PING_MS=15000"
set "TUNNEL_MODE=off"
set "TUNNEL_IFACE=hopshot0"
set "TUNNEL_MTU=1400"
set "TUNNEL_ADDRESS="
set "TUNNEL_PEER="
set "TUNNEL_DEFAULT_ROUTE=false"
set "TUNNEL_UDP_BIND=127.0.0.1:19090"
set "TUNNEL_UDP_TARGET="
set "DECLARED_UP=0"
set "MTU=0"
set "FEC_K=4"
set "FEC_M=4"
set "PROBE_COUNT=20"
set "PROBE_TIMEOUT=15000"
set "OBFS=false"
set "MASQ=false"
set "RAND_SRC=false"
set "VERBOSE=false"
set "JSON_LOGS=false"

:main_menu
cls
echo %C_CYAN%%C_BOLD%==================================================%C_RESET%
echo %C_CYAN%%C_BOLD%  HopShot Client Launcher%C_RESET%
echo %C_CYAN%%C_BOLD%==================================================%C_RESET%
echo.
echo %C_BOLD%Quick status:%C_RESET%
echo   %C_WHITE%Server:%C_RESET% %SERVER%   %C_WHITE%Port:%C_RESET% %PORT%   %C_WHITE%QUIC:%C_RESET% %QUIC_PORT%
echo   %C_WHITE%Profile:%C_RESET% %PROFILE%   %C_WHITE%Adaptive mode:%C_RESET% %ADAPTIVE_MODE%
echo   %C_WHITE%Max ping:%C_RESET% %MAX_PING_MS%ms
echo   %C_WHITE%Tunnel:%C_RESET% %TUNNEL_MODE%   %C_WHITE%Relay:%C_RESET% %TUNNEL_UDP_BIND% -^> %TUNNEL_UDP_TARGET%
echo   %C_WHITE%Hop disabled:%C_RESET% %DISABLE_HOP%   %C_WHITE%Fixed hop:%C_RESET% %FIXED_HOP_MS%   %C_WHITE%Burst:%C_RESET% %MANUAL_BURST%
echo   %C_WHITE%Obfs/Masq/Rand:%C_RESET% %OBFS%/%MASQ%/%RAND_SRC%   %C_WHITE%Verbose/JSON:%C_RESET% %VERBOSE%/%JSON_LOGS%
echo.
echo %C_GREEN%1.%C_RESET% Start client
echo %C_GREEN%2.%C_RESET% Network menu
echo %C_GREEN%3.%C_RESET% Mode menu (auto/loss-based)
echo %C_GREEN%4.%C_RESET% Transport menu
echo %C_GREEN%5.%C_RESET% Advanced core menu
echo %C_GREEN%6.%C_RESET% Logging menu
echo %C_GREEN%7.%C_RESET% Tunnel menu
echo %C_GREEN%S.%C_RESET% Save config only
echo %C_GREEN%X.%C_RESET% Exit
echo.
choice /c 1234567SX /n /m "Select an option:"
if errorlevel 9 goto :end
if errorlevel 8 goto :save_only
if errorlevel 7 goto :tunnel_menu
if errorlevel 6 goto :logs_menu
if errorlevel 5 goto :advanced_menu
if errorlevel 4 goto :transport_menu
if errorlevel 3 goto :mode_menu
if errorlevel 2 goto :network_menu
if errorlevel 1 goto :start_client
goto :main_menu

:tunnel_menu
cls
echo %C_CYAN%%C_BOLD%[ Tunnel Menu ]%C_RESET%
echo.
echo   Tunnel mode: %TUNNEL_MODE%
echo   Interface: %TUNNEL_IFACE%   MTU: %TUNNEL_MTU%
echo   Address: %TUNNEL_ADDRESS%
echo   Peer: %TUNNEL_PEER%
echo   Default route: %TUNNEL_DEFAULT_ROUTE%
echo   UDP relay bind: %TUNNEL_UDP_BIND%
echo   UDP relay target: %TUNNEL_UDP_TARGET%
echo.
echo %C_GREEN%1.%C_RESET% Change tunnel mode (off/tun/tap/udp)
echo %C_GREEN%2.%C_RESET% Set tunnel interface name
echo %C_GREEN%3.%C_RESET% Set tunnel MTU
echo %C_GREEN%4.%C_RESET% Set tunnel address
echo %C_GREEN%5.%C_RESET% Set tunnel peer
echo %C_GREEN%6.%C_RESET% Toggle tunnel default route
echo %C_GREEN%7.%C_RESET% Set UDP relay bind endpoint
echo %C_GREEN%8.%C_RESET% Set UDP relay target endpoint
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 12345678B /n /m "Select an option:"
if errorlevel 9 goto :main_menu
if errorlevel 8 goto :change_tunnel_udp_target
if errorlevel 7 goto :change_tunnel_udp_bind
if errorlevel 6 goto :toggle_tunnel_default_route
if errorlevel 5 goto :change_tunnel_peer
if errorlevel 4 goto :change_tunnel_address
if errorlevel 3 goto :change_tunnel_mtu
if errorlevel 2 goto :change_tunnel_iface
if errorlevel 1 goto :change_tunnel_mode
goto :tunnel_menu

:network_menu
cls
echo %C_CYAN%%C_BOLD%[ Network Menu ]%C_RESET%
echo.
echo   Server: %SERVER%
echo   Destinations: %DESTINATIONS%
echo   Port range: %PORT_MIN%-%PORT_MAX%
echo.
echo %C_GREEN%1.%C_RESET% Set server address (primary)
echo %C_GREEN%2.%C_RESET% Set destination list (comma separated)
echo %C_GREEN%3.%C_RESET% Set UDP/QUIC ports
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 123B /n /m "Select an option:"
if errorlevel 4 goto :main_menu
if errorlevel 3 goto :change_ports
if errorlevel 2 goto :change_destinations
if errorlevel 1 goto :change_server
goto :network_menu

:mode_menu
cls
echo %C_CYAN%%C_BOLD%[ Mode Menu ]%C_RESET%
echo.
echo   Adaptive mode (loss-based): %ADAPTIVE_MODE%
echo   Profile: %PROFILE%
echo   Hop disabled: %DISABLE_HOP%
echo   Fixed hop ms: %FIXED_HOP_MS%
echo   Manual raw burst: %MANUAL_BURST% (0=auto)
echo   Preemptive hop ms: %PREEMPTIVE%
echo   Keepalive sec: %KEEPALIVE_SEC%
echo   Max ping ms: %MAX_PING_MS%
echo.
echo %C_GREEN%1.%C_RESET% Toggle adaptive mode (recommended ON)
echo %C_GREEN%2.%C_RESET% Change profile
echo %C_GREEN%3.%C_RESET% Change preemptive hop ms
echo %C_GREEN%4.%C_RESET% Toggle hopping on/off
echo %C_GREEN%5.%C_RESET% Set fixed hop ms
echo %C_GREEN%6.%C_RESET% Set manual raw burst multiplier
echo %C_GREEN%7.%C_RESET% Set keepalive seconds
echo %C_GREEN%8.%C_RESET% Set max ping ms
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 12345678B /n /m "Select an option:"
if errorlevel 9 goto :main_menu
if errorlevel 8 goto :change_max_ping
if errorlevel 7 goto :change_keepalive
if errorlevel 6 goto :change_manual_burst
if errorlevel 5 goto :change_fixed_hop
if errorlevel 4 goto :toggle_hop
if errorlevel 3 goto :change_preemptive
if errorlevel 2 goto :pick_profile
if errorlevel 1 goto :toggle_adaptive
goto :mode_menu

:transport_menu
cls
echo %C_CYAN%%C_BOLD%[ Transport Menu ]%C_RESET%
echo.
echo   Obfs: %OBFS%
echo   Masquerade: %MASQ%
echo   Random source port: %RAND_SRC%
echo   Jitter bytes: %JITTER%
echo.
echo %C_GREEN%1.%C_RESET% Toggle obfs
echo %C_GREEN%2.%C_RESET% Toggle masquerade
echo %C_GREEN%3.%C_RESET% Toggle random source port
echo %C_GREEN%4.%C_RESET% Change jitter bytes
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 1234B /n /m "Select an option:"
if errorlevel 5 goto :main_menu
if errorlevel 4 goto :change_jitter
if errorlevel 3 goto :toggle_rand
if errorlevel 2 goto :toggle_masq
if errorlevel 1 goto :toggle_obfs
goto :transport_menu

:advanced_menu
cls
echo %C_CYAN%%C_BOLD%[ Advanced Core Menu ]%C_RESET%
echo.
echo   Seed: %SEED%
echo   Declared uplink kbps: %DECLARED_UP%
echo   MTU override: %MTU%
echo   FEC: k=%FEC_K% m=%FEC_M%
echo   Probe count/timeout: %PROBE_COUNT% / %PROBE_TIMEOUT%
echo.
echo %C_GREEN%1.%C_RESET% Change seed
echo %C_GREEN%2.%C_RESET% Change declared uplink kbps
echo %C_GREEN%3.%C_RESET% Change MTU override
echo %C_GREEN%4.%C_RESET% Change FEC k
echo %C_GREEN%5.%C_RESET% Change FEC m
echo %C_GREEN%6.%C_RESET% Change probe count
echo %C_GREEN%7.%C_RESET% Change probe timeout ms
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 1234567B /n /m "Select an option:"
if errorlevel 8 goto :main_menu
if errorlevel 7 goto :change_probe_timeout
if errorlevel 6 goto :change_probe_count
if errorlevel 5 goto :change_fec_m
if errorlevel 4 goto :change_fec_k
if errorlevel 3 goto :change_mtu
if errorlevel 2 goto :change_declared_up
if errorlevel 1 goto :change_seed
goto :advanced_menu

:logs_menu
cls
echo %C_CYAN%%C_BOLD%[ Logging Menu ]%C_RESET%
echo.
echo   Verbose: %VERBOSE%
echo   JSON logs: %JSON_LOGS%
echo.
echo %C_GREEN%1.%C_RESET% Toggle verbose
echo %C_GREEN%2.%C_RESET% Toggle JSON logs
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 12B /n /m "Select an option:"
if errorlevel 3 goto :main_menu
if errorlevel 2 goto :toggle_json
if errorlevel 1 goto :toggle_verbose
goto :logs_menu

:change_server
set "OLD_SERVER=%SERVER%"
set /p "SERVER=Server address/IP (B=back) [%SERVER%]: "
if /i "%SERVER%"=="b" set "SERVER=%OLD_SERVER%" & goto :network_menu
if not defined SERVER set "SERVER=%OLD_SERVER%"
choice /c YNB /n /m "Use this as only destination now? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :network_menu
if errorlevel 2 goto :network_menu
set "DESTINATIONS=%SERVER%"
goto :network_menu

:change_destinations
set "OLD_DESTINATIONS=%DESTINATIONS%"
set /p "DESTINATIONS=Destinations comma list (B=back) [%DESTINATIONS%]: "
if /i "%DESTINATIONS%"=="b" set "DESTINATIONS=%OLD_DESTINATIONS%" & goto :network_menu
if not defined DESTINATIONS set "DESTINATIONS=%OLD_DESTINATIONS%"
for /f "tokens=1 delims=, " %%A in ("%DESTINATIONS%") do set "SERVER=%%~A"
goto :network_menu

:change_ports
echo.
echo Current UDP port: %PORT%
echo Current QUIC port: %QUIC_PORT%
set "OLD_PORT=%PORT%"
set "OLD_QUIC_PORT=%QUIC_PORT%"
set /p "PORT=UDP port (B=back) [%PORT%]: "
if /i "%PORT%"=="b" set "PORT=%OLD_PORT%" & set "QUIC_PORT=%OLD_QUIC_PORT%" & goto :network_menu
if not defined PORT set "PORT=%OLD_PORT%"
set /p "QUIC_PORT=QUIC port (B=back) [%QUIC_PORT%]: "
if /i "%QUIC_PORT%"=="b" set "PORT=%OLD_PORT%" & set "QUIC_PORT=%OLD_QUIC_PORT%" & goto :network_menu
if not defined QUIC_PORT set "QUIC_PORT=%OLD_QUIC_PORT%"
goto :network_menu

:toggle_adaptive
choice /c YNB /n /m "Toggle adaptive auto-mode? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :mode_menu
if errorlevel 2 goto :mode_menu
if /i "%ADAPTIVE_MODE%"=="true" (
  set "ADAPTIVE_MODE=false"
) else (
  set "ADAPTIVE_MODE=true"
  set "DISABLE_HOP=false"
  set "FIXED_HOP_MS=0"
  set "MANUAL_BURST=0"
)
goto :mode_menu

:pick_profile
echo.
echo Choose profile:
echo   1. balanced
echo   2. reliable
echo   3. stealth
echo   4. throughput
echo   B. back
choice /c 1234B /n /m "Profile:"
if errorlevel 5 goto :mode_menu
if errorlevel 4 set "PROFILE=throughput"
if errorlevel 3 set "PROFILE=stealth"
if errorlevel 2 set "PROFILE=reliable"
if errorlevel 1 set "PROFILE=balanced"
goto :mode_menu

:toggle_hop
choice /c YNB /n /m "Toggle hopping on/off? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :mode_menu
if errorlevel 2 goto :mode_menu
if /i "%DISABLE_HOP%"=="true" (
  set "DISABLE_HOP=false"
) else (
  set "DISABLE_HOP=true"
)
goto :mode_menu

:change_fixed_hop
set "OLD_FIXED_HOP_MS=%FIXED_HOP_MS%"
set /p "FIXED_HOP_MS=Fixed hop ms (0=mode-based, B=back) [%FIXED_HOP_MS%]: "
if /i "%FIXED_HOP_MS%"=="b" set "FIXED_HOP_MS=%OLD_FIXED_HOP_MS%" & goto :mode_menu
if not defined FIXED_HOP_MS set "FIXED_HOP_MS=%OLD_FIXED_HOP_MS%"
goto :mode_menu

:change_manual_burst
set "OLD_MANUAL_BURST=%MANUAL_BURST%"
set /p "MANUAL_BURST=Manual raw burst (0=auto, B=back) [%MANUAL_BURST%]: "
if /i "%MANUAL_BURST%"=="b" set "MANUAL_BURST=%OLD_MANUAL_BURST%" & goto :mode_menu
if not defined MANUAL_BURST set "MANUAL_BURST=%OLD_MANUAL_BURST%"
goto :mode_menu

:change_preemptive
set "OLD_PREEMPTIVE=%PREEMPTIVE%"
set /p "PREEMPTIVE=Preemptive hop ms (B=back) [%PREEMPTIVE%]: "
if /i "%PREEMPTIVE%"=="b" set "PREEMPTIVE=%OLD_PREEMPTIVE%" & goto :mode_menu
if not defined PREEMPTIVE set "PREEMPTIVE=%OLD_PREEMPTIVE%"
goto :mode_menu

:change_keepalive
set "OLD_KEEPALIVE_SEC=%KEEPALIVE_SEC%"
set /p "KEEPALIVE_SEC=Keepalive sec (0=off, B=back) [%KEEPALIVE_SEC%]: "
if /i "%KEEPALIVE_SEC%"=="b" set "KEEPALIVE_SEC=%OLD_KEEPALIVE_SEC%" & goto :mode_menu
if not defined KEEPALIVE_SEC set "KEEPALIVE_SEC=%OLD_KEEPALIVE_SEC%"
goto :mode_menu

:change_max_ping
set "OLD_MAX_PING_MS=%MAX_PING_MS%"
set /p "MAX_PING_MS=Max ping ms (B=back) [%MAX_PING_MS%]: "
if /i "%MAX_PING_MS%"=="b" set "MAX_PING_MS=%OLD_MAX_PING_MS%" & goto :mode_menu
if not defined MAX_PING_MS set "MAX_PING_MS=%OLD_MAX_PING_MS%"
goto :mode_menu

:change_tunnel_mode
set "OLD_TUNNEL_MODE=%TUNNEL_MODE%"
echo.
echo Choose tunnel mode:
echo   1. off
echo   2. tun
echo   3. tap
echo   4. udp (userspace relay)
echo   B. back
choice /c 1234B /n /m "Tunnel mode:"
if errorlevel 5 goto :tunnel_menu
if errorlevel 4 set "TUNNEL_MODE=udp"
if errorlevel 3 set "TUNNEL_MODE=tap"
if errorlevel 2 set "TUNNEL_MODE=tun"
if errorlevel 1 set "TUNNEL_MODE=off"
if not defined TUNNEL_MODE set "TUNNEL_MODE=%OLD_TUNNEL_MODE%"
goto :tunnel_menu

:change_tunnel_iface
set "OLD_TUNNEL_IFACE=%TUNNEL_IFACE%"
set /p "TUNNEL_IFACE=Tunnel interface name (B=back) [%TUNNEL_IFACE%]: "
if /i "%TUNNEL_IFACE%"=="b" set "TUNNEL_IFACE=%OLD_TUNNEL_IFACE%" & goto :tunnel_menu
if not defined TUNNEL_IFACE set "TUNNEL_IFACE=%OLD_TUNNEL_IFACE%"
goto :tunnel_menu

:change_tunnel_mtu
set "OLD_TUNNEL_MTU=%TUNNEL_MTU%"
set /p "TUNNEL_MTU=Tunnel MTU (B=back) [%TUNNEL_MTU%]: "
if /i "%TUNNEL_MTU%"=="b" set "TUNNEL_MTU=%OLD_TUNNEL_MTU%" & goto :tunnel_menu
if not defined TUNNEL_MTU set "TUNNEL_MTU=%OLD_TUNNEL_MTU%"
goto :tunnel_menu

:change_tunnel_address
set "OLD_TUNNEL_ADDRESS=%TUNNEL_ADDRESS%"
set /p "TUNNEL_ADDRESS=Tunnel address CIDR (blank=none, B=back) [%TUNNEL_ADDRESS%]: "
if /i "%TUNNEL_ADDRESS%"=="b" set "TUNNEL_ADDRESS=%OLD_TUNNEL_ADDRESS%" & goto :tunnel_menu
goto :tunnel_menu

:change_tunnel_peer
set "OLD_TUNNEL_PEER=%TUNNEL_PEER%"
set /p "TUNNEL_PEER=Tunnel peer address (blank=none, B=back) [%TUNNEL_PEER%]: "
if /i "%TUNNEL_PEER%"=="b" set "TUNNEL_PEER=%OLD_TUNNEL_PEER%" & goto :tunnel_menu
goto :tunnel_menu

:toggle_tunnel_default_route
choice /c YNB /n /m "Toggle tunnel default route? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :tunnel_menu
if errorlevel 2 goto :tunnel_menu
if /i "%TUNNEL_DEFAULT_ROUTE%"=="true" (
  set "TUNNEL_DEFAULT_ROUTE=false"
) else (
  set "TUNNEL_DEFAULT_ROUTE=true"
)
goto :tunnel_menu

:change_tunnel_udp_bind
set "OLD_TUNNEL_UDP_BIND=%TUNNEL_UDP_BIND%"
set /p "TUNNEL_UDP_BIND=UDP relay bind host:port (B=back) [%TUNNEL_UDP_BIND%]: "
if /i "%TUNNEL_UDP_BIND%"=="b" set "TUNNEL_UDP_BIND=%OLD_TUNNEL_UDP_BIND%" & goto :tunnel_menu
if not defined TUNNEL_UDP_BIND set "TUNNEL_UDP_BIND=%OLD_TUNNEL_UDP_BIND%"
goto :tunnel_menu

:change_tunnel_udp_target
set "OLD_TUNNEL_UDP_TARGET=%TUNNEL_UDP_TARGET%"
set /p "TUNNEL_UDP_TARGET=UDP relay target host:port (blank=auto peer, B=back) [%TUNNEL_UDP_TARGET%]: "
if /i "%TUNNEL_UDP_TARGET%"=="b" set "TUNNEL_UDP_TARGET=%OLD_TUNNEL_UDP_TARGET%" & goto :tunnel_menu
goto :tunnel_menu

:toggle_obfs
choice /c YNB /n /m "Toggle obfs? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :transport_menu
if errorlevel 2 goto :transport_menu
if /i "%OBFS%"=="true" (
  set "OBFS=false"
) else (
  set "OBFS=true"
)
goto :transport_menu

:toggle_masq
choice /c YNB /n /m "Toggle masquerade? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :transport_menu
if errorlevel 2 goto :transport_menu
if /i "%MASQ%"=="true" (
  set "MASQ=false"
) else (
  set "MASQ=true"
)
goto :transport_menu

:toggle_rand
choice /c YNB /n /m "Toggle random source port? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :transport_menu
if errorlevel 2 goto :transport_menu
if /i "%RAND_SRC%"=="true" (
  set "RAND_SRC=false"
) else (
  set "RAND_SRC=true"
)
goto :transport_menu

:change_jitter
set "OLD_JITTER=%JITTER%"
set /p "JITTER=Packet jitter bytes (B=back) [%JITTER%]: "
if /i "%JITTER%"=="b" set "JITTER=%OLD_JITTER%" & goto :transport_menu
if not defined JITTER set "JITTER=%OLD_JITTER%"
goto :transport_menu

:change_seed
set "OLD_SEED=%SEED%"
set /p "SEED=Shared seed (B=back) [%SEED%]: "
if /i "%SEED%"=="b" set "SEED=%OLD_SEED%" & goto :advanced_menu
if not defined SEED set "SEED=%OLD_SEED%"
goto :advanced_menu

:change_declared_up
set "OLD_DECLARED_UP=%DECLARED_UP%"
set /p "DECLARED_UP=Declared uplink kbps (B=back) [%DECLARED_UP%]: "
if /i "%DECLARED_UP%"=="b" set "DECLARED_UP=%OLD_DECLARED_UP%" & goto :advanced_menu
if not defined DECLARED_UP set "DECLARED_UP=%OLD_DECLARED_UP%"
goto :advanced_menu

:change_mtu
set "OLD_MTU=%MTU%"
set /p "MTU=MTU payload override (0=auto, B=back) [%MTU%]: "
if /i "%MTU%"=="b" set "MTU=%OLD_MTU%" & goto :advanced_menu
if not defined MTU set "MTU=%OLD_MTU%"
goto :advanced_menu

:change_fec_k
set "OLD_FEC_K=%FEC_K%"
set /p "FEC_K=FEC data shards k (B=back) [%FEC_K%]: "
if /i "%FEC_K%"=="b" set "FEC_K=%OLD_FEC_K%" & goto :advanced_menu
if not defined FEC_K set "FEC_K=%OLD_FEC_K%"
goto :advanced_menu

:change_fec_m
set "OLD_FEC_M=%FEC_M%"
set /p "FEC_M=FEC parity shards m (B=back) [%FEC_M%]: "
if /i "%FEC_M%"=="b" set "FEC_M=%OLD_FEC_M%" & goto :advanced_menu
if not defined FEC_M set "FEC_M=%OLD_FEC_M%"
goto :advanced_menu

:change_probe_count
set "OLD_PROBE_COUNT=%PROBE_COUNT%"
set /p "PROBE_COUNT=Probe count (B=back) [%PROBE_COUNT%]: "
if /i "%PROBE_COUNT%"=="b" set "PROBE_COUNT=%OLD_PROBE_COUNT%" & goto :advanced_menu
if not defined PROBE_COUNT set "PROBE_COUNT=%OLD_PROBE_COUNT%"
goto :advanced_menu

:change_probe_timeout
set "OLD_PROBE_TIMEOUT=%PROBE_TIMEOUT%"
set /p "PROBE_TIMEOUT=Probe timeout ms (B=back) [%PROBE_TIMEOUT%]: "
if /i "%PROBE_TIMEOUT%"=="b" set "PROBE_TIMEOUT=%OLD_PROBE_TIMEOUT%" & goto :advanced_menu
if not defined PROBE_TIMEOUT set "PROBE_TIMEOUT=%OLD_PROBE_TIMEOUT%"
goto :advanced_menu

:toggle_verbose
choice /c YNB /n /m "Toggle verbose logs? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :logs_menu
if errorlevel 2 goto :logs_menu
if /i "%VERBOSE%"=="true" (
  set "VERBOSE=false"
) else (
  set "VERBOSE=true"
)
goto :logs_menu

:toggle_json
choice /c YNB /n /m "Toggle JSON logs? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :logs_menu
if errorlevel 2 goto :logs_menu
if /i "%JSON_LOGS%"=="true" (
  set "JSON_LOGS=false"
) else (
  set "JSON_LOGS=true"
)
goto :logs_menu

:save_only
choice /c YNB /n /m "Save config now? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :main_menu
if errorlevel 2 goto :main_menu
call :write_config
echo.
echo %C_GREEN%Saved client.config.json.%C_RESET%
pause
goto :main_menu

:start_client
choice /c YNB /n /m "Save and start client now? (Y=yes, N=no, B=back): "
if errorlevel 3 goto :main_menu
if errorlevel 2 goto :main_menu
call :write_config
echo.
echo %C_CYAN%Connecting HopShot client with current settings...%C_RESET%
call :resolve_python
if not defined PYTHON_LAUNCHER goto :main_menu
call %PYTHON_LAUNCHER% deploy.py client --config client.config.json
if errorlevel 1 pause
goto :main_menu

:write_config
setlocal EnableDelayedExpansion
set "DEST_CLEAN=!DESTINATIONS: =!"
if not defined DEST_CLEAN set "DEST_CLEAN=127.0.0.1"
set "DEST_JSON=!DEST_CLEAN:,=\",\"!"
(
  echo {
  echo   "server_port": %PORT%,
  echo   "quic_port": %QUIC_PORT%,
  echo   "port_min": %PORT_MIN%,
  echo   "port_max": %PORT_MAX%,
  echo   "shared_seed": "%SEED%",
  echo   "profile": "%PROFILE%",
  echo   "adaptive_mode": %ADAPTIVE_MODE%,
  echo   "max_ping_ms": %MAX_PING_MS%,
  echo   "disable_hop": %DISABLE_HOP%,
  echo   "obfs": %OBFS%,
  echo   "rand_src_port": %RAND_SRC%,
  echo   "jitter_bytes": %JITTER%,
  echo   "preemptive_hop_ms": %PREEMPTIVE%,
  echo   "fixed_hop_ms": %FIXED_HOP_MS%,
  echo   "manual_burst_mult": %MANUAL_BURST%,
  echo   "keepalive_interval_sec": %KEEPALIVE_SEC%,
  echo   "tunnel_mode": "%TUNNEL_MODE%",
  echo   "tunnel_iface": "%TUNNEL_IFACE%",
  echo   "tunnel_mtu": %TUNNEL_MTU%,
  if defined TUNNEL_ADDRESS (
    echo   "tunnel_address": "%TUNNEL_ADDRESS%",
  ) else (
    echo   "tunnel_address": null,
  )
  if defined TUNNEL_PEER (
    echo   "tunnel_peer": "%TUNNEL_PEER%",
  ) else (
    echo   "tunnel_peer": null,
  )
  echo   "tunnel_route_default": %TUNNEL_DEFAULT_ROUTE%,
  echo   "tunnel_udp_bind": "%TUNNEL_UDP_BIND%",
  if defined TUNNEL_UDP_TARGET (
    echo   "tunnel_udp_target": "%TUNNEL_UDP_TARGET%",
  ) else (
    echo   "tunnel_udp_target": null,
  )
  echo   "declared_up_kbps": %DECLARED_UP%,
  echo   "masquerade": %MASQ%,
  echo   "mtu": %MTU%,
  echo   "fec_k": %FEC_K%,
  echo   "fec_m": %FEC_M%,
  echo   "probe_count": %PROBE_COUNT%,
  echo   "probe_timeout_ms": %PROBE_TIMEOUT%,
  echo   "destinations": ["!DEST_JSON!"],
  echo   "resolvers": ["1.1.1.1"],
  echo   "verbose": %VERBOSE%,
  echo   "log_file": "client.log",
  echo   "json_logs": %JSON_LOGS%,
  echo   "metrics_file": "client.metrics.jsonl"
  echo }
) > client.config.json
endlocal
exit /b 0

:end
endlocal
exit /b 0

:resolve_python
set "PYTHON_LAUNCHER="
where py >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_LAUNCHER=py -3"
  exit /b 0
)
where python >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_LAUNCHER=python"
  exit /b 0
)
echo Python launcher not found. Install Python 3.14 or newer, then run this again.
pause
exit /b 1
