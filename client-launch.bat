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

rem ── Default settings ──────────────────────────────────────────────────────
set "SERVER=195.88.208.120"
set "DESTINATIONS=195.88.208.120"
set "PORT=10000"
set "QUIC_PORT=10001"
set "HEALTH_PORT=10002"
set "SEED=a23bc179a1e96c993fcd5c5f828f8777e47b9bd6cb9e01cc733e1578d7b4628e"
set "PROFILE=balanced"
set "SERVICE_MODE=tunnel"
set "PROXY_LISTEN=127.0.0.1:1080"
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
set "TUNNEL_MODE=udp"
set "TUNNEL_IFACE=hopshot0"
set "TUNNEL_MTU=1400"
set "TUNNEL_ADDRESS="
set "TUNNEL_PEER="
set "TUNNEL_DEFAULT_ROUTE=false"
set "TUNNEL_UDP_BIND=127.0.0.1:19090"
set "TUNNEL_UDP_TARGET="
set "STARTUP_CAPACITY_SCAN=true"
set "SCAN_THROTTLE_THRESHOLD_PCT=80.0"
set "SCAN_RECOVERY_THRESHOLD_PCT=20.0"
set "DECLARED_UP=0"
set "DECLARED_DOWN=0"
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

if exist client.config.json call :load_existing_config

:main_menu
cls
echo %C_CYAN%%C_BOLD%==================================================%C_RESET%
echo %C_CYAN%%C_BOLD%  HopShot Client Launcher%C_RESET%
echo %C_CYAN%%C_BOLD%==================================================%C_RESET%
echo.
echo %C_BOLD%Quick status:%C_RESET%
echo   %C_WHITE%Server:%C_RESET% %SERVER%   %C_WHITE%Port:%C_RESET% %PORT%   %C_WHITE%QUIC:%C_RESET% %QUIC_PORT%
echo   %C_WHITE%Profile:%C_RESET% %PROFILE%   %C_WHITE%Adaptive mode:%C_RESET% %ADAPTIVE_MODE%
echo   %C_WHITE%Max ping:%C_RESET% %MAX_PING_MS%ms   %C_WHITE%Health:%C_RESET% %HEALTH_PORT%
echo   %C_WHITE%Service:%C_RESET% %SERVICE_MODE%   %C_WHITE%Proxy listen:%C_RESET% %PROXY_LISTEN%
echo   %C_WHITE%Tunnel:%C_RESET% %TUNNEL_MODE%   %C_WHITE%Relay:%C_RESET% %TUNNEL_UDP_BIND% -^> %TUNNEL_UDP_TARGET%
echo   %C_WHITE%Hop disabled:%C_RESET% %DISABLE_HOP%   %C_WHITE%Fixed hop:%C_RESET% %FIXED_HOP_MS%ms   %C_WHITE%Burst:%C_RESET% %MANUAL_BURST%
echo   %C_WHITE%Obfs/Masq/Rand:%C_RESET% %OBFS%/%MASQ%/%RAND_SRC%   %C_WHITE%Verbose/JSON:%C_RESET% %VERBOSE%/%JSON_LOGS%
echo   %C_WHITE%FEC:%C_RESET% k=%FEC_K% m=%FEC_M%   %C_WHITE%MTU:%C_RESET% %MTU%   %C_WHITE%Jitter:%C_RESET% %JITTER%B
echo.
echo %C_GREEN%1.%C_RESET% Start client
echo %C_GREEN%2.%C_RESET% Network menu
echo %C_GREEN%3.%C_RESET% Mode menu (auto/loss-based)
echo %C_GREEN%4.%C_RESET% Transport menu
echo %C_GREEN%5.%C_RESET% Advanced core menu
echo %C_GREEN%6.%C_RESET% Logging menu
echo %C_GREEN%7.%C_RESET% Tunnel menu
echo %C_GREEN%8.%C_RESET% Service menu (tunnel/proxy)
echo %C_GREEN%S.%C_RESET% Save config only
echo %C_GREEN%X.%C_RESET% Exit
echo.
choice /c 12345678SX /n /m "Select an option: "
if errorlevel 10 goto :end
if errorlevel 9 goto :save_only
if errorlevel 8 goto :service_menu
if errorlevel 7 goto :tunnel_menu
if errorlevel 6 goto :logs_menu
if errorlevel 5 goto :advanced_menu
if errorlevel 4 goto :transport_menu
if errorlevel 3 goto :mode_menu
if errorlevel 2 goto :network_menu
if errorlevel 1 goto :start_client
goto :main_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  SERVICE MENU
rem ══════════════════════════════════════════════════════════════════════════

:service_menu
cls
echo %C_CYAN%%C_BOLD%[ Service Menu ]%C_RESET%
echo.
echo   Service mode  : %SERVICE_MODE%
echo   Proxy listen  : %PROXY_LISTEN%
echo   Health port   : %HEALTH_PORT%
echo.
echo %C_GREEN%1.%C_RESET% Change service mode (tunnel / proxy)
echo %C_GREEN%2.%C_RESET% Set proxy listen endpoint
echo %C_GREEN%3.%C_RESET% Set health port
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 123B /n /m "Select an option: "
if errorlevel 4 goto :main_menu
if errorlevel 3 goto :change_health_port
if errorlevel 2 goto :change_proxy_listen
if errorlevel 1 goto :change_service_mode
goto :service_menu

:change_service_mode
echo.
echo Choose service mode:
echo   1. tunnel
echo   2. proxy
echo   B. back
choice /c 12B /n /m "Service mode: "
if errorlevel 3 goto :service_menu
if errorlevel 2 set "SERVICE_MODE=proxy" & goto :service_menu
if errorlevel 1 set "SERVICE_MODE=tunnel" & goto :service_menu
goto :service_menu

:change_proxy_listen
set "OLD_PROXY_LISTEN=%PROXY_LISTEN%"
set /p "PROXY_LISTEN=Proxy listen host:port (B=back) [%PROXY_LISTEN%]: "
if /i "%PROXY_LISTEN%"=="b" set "PROXY_LISTEN=%OLD_PROXY_LISTEN%" & goto :service_menu
if not defined PROXY_LISTEN set "PROXY_LISTEN=%OLD_PROXY_LISTEN%"
goto :service_menu

:change_health_port
set "OLD_HEALTH_PORT=%HEALTH_PORT%"
set /p "HEALTH_PORT=Health HTTP port (B=back) [%HEALTH_PORT%]: "
if /i "%HEALTH_PORT%"=="b" set "HEALTH_PORT=%OLD_HEALTH_PORT%" & goto :service_menu
if not defined HEALTH_PORT set "HEALTH_PORT=%OLD_HEALTH_PORT%"
goto :service_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  TUNNEL MENU
rem ══════════════════════════════════════════════════════════════════════════

:tunnel_menu
cls
echo %C_CYAN%%C_BOLD%[ Tunnel Menu ]%C_RESET%
echo.
echo   Tunnel mode     : %TUNNEL_MODE%
echo   Interface       : %TUNNEL_IFACE%   MTU: %TUNNEL_MTU%
echo   Address         : %TUNNEL_ADDRESS%
echo   Peer            : %TUNNEL_PEER%
echo   Default route   : %TUNNEL_DEFAULT_ROUTE%
echo   UDP relay bind  : %TUNNEL_UDP_BIND%
echo   UDP relay target: %TUNNEL_UDP_TARGET%
echo.
echo %C_GREEN%1.%C_RESET% Change tunnel mode (off / tun / tap / udp)
echo %C_GREEN%2.%C_RESET% Set tunnel interface name
echo %C_GREEN%3.%C_RESET% Set tunnel MTU
echo %C_GREEN%4.%C_RESET% Set tunnel address (CIDR e.g. 10.0.0.1/24)
echo %C_GREEN%5.%C_RESET% Set tunnel peer address
echo %C_GREEN%6.%C_RESET% Toggle tunnel default route
echo %C_GREEN%7.%C_RESET% Set UDP relay bind endpoint
echo %C_GREEN%8.%C_RESET% Set UDP relay target endpoint
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 12345678B /n /m "Select an option: "
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

:change_tunnel_mode
echo.
echo Choose tunnel mode:
echo   1. off  (no tunnel — message/proxy only)
echo   2. tun  (kernel TUN device — requires root/admin)
echo   3. tap  (kernel TAP device — requires root/admin)
echo   4. udp  (userspace UDP relay — no root needed)
echo   B. back
choice /c 1234B /n /m "Tunnel mode: "
if errorlevel 5 goto :tunnel_menu
if errorlevel 4 set "TUNNEL_MODE=udp" & goto :tunnel_menu
if errorlevel 3 set "TUNNEL_MODE=tap" & goto :tunnel_menu
if errorlevel 2 set "TUNNEL_MODE=tun" & goto :tunnel_menu
if errorlevel 1 set "TUNNEL_MODE=off" & goto :tunnel_menu
goto :tunnel_menu

:change_tunnel_iface
set "OLD_TUNNEL_IFACE=%TUNNEL_IFACE%"
set /p "TUNNEL_IFACE=Tunnel interface name (B=back) [%TUNNEL_IFACE%]: "
if /i "%TUNNEL_IFACE%"=="b" set "TUNNEL_IFACE=%OLD_TUNNEL_IFACE%" & goto :tunnel_menu
if not defined TUNNEL_IFACE set "TUNNEL_IFACE=%OLD_TUNNEL_IFACE%"
goto :tunnel_menu

:change_tunnel_mtu
set "OLD_TUNNEL_MTU=%TUNNEL_MTU%"
set /p "TUNNEL_MTU=Tunnel MTU bytes (B=back) [%TUNNEL_MTU%]: "
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
set /p "TUNNEL_UDP_TARGET=UDP relay target host:port (blank=auto, B=back) [%TUNNEL_UDP_TARGET%]: "
if /i "%TUNNEL_UDP_TARGET%"=="b" set "TUNNEL_UDP_TARGET=%OLD_TUNNEL_UDP_TARGET%" & goto :tunnel_menu
goto :tunnel_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  NETWORK MENU
rem ══════════════════════════════════════════════════════════════════════════

:network_menu
cls
echo %C_CYAN%%C_BOLD%[ Network Menu ]%C_RESET%
echo.
echo   Server      : %SERVER%
echo   Destinations: %DESTINATIONS%
echo   Port range  : %PORT_MIN% - %PORT_MAX%
echo   UDP port    : %PORT%
echo   QUIC port   : %QUIC_PORT%
echo.
echo %C_GREEN%1.%C_RESET% Set server address (primary)
echo %C_GREEN%2.%C_RESET% Set destination list (comma separated IPs)
echo %C_GREEN%3.%C_RESET% Set UDP / QUIC ports
echo %C_GREEN%4.%C_RESET% Set hop port range
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 1234B /n /m "Select an option: "
if errorlevel 5 goto :main_menu
if errorlevel 4 goto :change_port_range
if errorlevel 3 goto :change_ports
if errorlevel 2 goto :change_destinations
if errorlevel 1 goto :change_server
goto :network_menu

:change_server
set "OLD_SERVER=%SERVER%"
set /p "SERVER=Server IP / hostname (B=back) [%SERVER%]: "
if /i "%SERVER%"=="b" set "SERVER=%OLD_SERVER%" & goto :network_menu
if not defined SERVER set "SERVER=%OLD_SERVER%"
set "DESTINATIONS=%SERVER%"
goto :network_menu

:change_destinations
set "OLD_DESTINATIONS=%DESTINATIONS%"
set /p "DESTINATIONS=Comma-separated destinations (B=back) [%DESTINATIONS%]: "
if /i "%DESTINATIONS%"=="b" set "DESTINATIONS=%OLD_DESTINATIONS%" & goto :network_menu
if not defined DESTINATIONS set "DESTINATIONS=%OLD_DESTINATIONS%"
for /f "tokens=1 delims=, " %%A in ("%DESTINATIONS%") do set "SERVER=%%~A"
goto :network_menu

:change_ports
echo.
set "OLD_PORT=%PORT%"
set "OLD_QUIC_PORT=%QUIC_PORT%"
set /p "PORT=UDP port (B=back) [%PORT%]: "
if /i "%PORT%"=="b" set "PORT=%OLD_PORT%" & goto :network_menu
if not defined PORT set "PORT=%OLD_PORT%"
set /p "QUIC_PORT=QUIC/TLS port (B=back) [%QUIC_PORT%]: "
if /i "%QUIC_PORT%"=="b" set "QUIC_PORT=%OLD_QUIC_PORT%" & goto :network_menu
if not defined QUIC_PORT set "QUIC_PORT=%OLD_QUIC_PORT%"
goto :network_menu

:change_port_range
echo.
set "OLD_PORT_MIN=%PORT_MIN%"
set "OLD_PORT_MAX=%PORT_MAX%"
set /p "PORT_MIN=Hop range min (B=back) [%PORT_MIN%]: "
if /i "%PORT_MIN%"=="b" set "PORT_MIN=%OLD_PORT_MIN%" & goto :network_menu
if not defined PORT_MIN set "PORT_MIN=%OLD_PORT_MIN%"
set /p "PORT_MAX=Hop range max (B=back) [%PORT_MAX%]: "
if /i "%PORT_MAX%"=="b" set "PORT_MAX=%OLD_PORT_MAX%" & goto :network_menu
if not defined PORT_MAX set "PORT_MAX=%OLD_PORT_MAX%"
goto :network_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  MODE MENU
rem ══════════════════════════════════════════════════════════════════════════

:mode_menu
cls
echo %C_CYAN%%C_BOLD%[ Mode Menu ]%C_RESET%
echo.
echo   Adaptive mode (loss-based): %ADAPTIVE_MODE%
echo   Profile         : %PROFILE%
echo   Hop disabled    : %DISABLE_HOP%
echo   Fixed hop ms    : %FIXED_HOP_MS%  (0 = use mode)
echo   Manual burst    : %MANUAL_BURST%  (0 = auto)
echo   Preemptive hop  : %PREEMPTIVE%ms
echo   Keepalive       : %KEEPALIVE_SEC%s
echo   Max ping        : %MAX_PING_MS%ms
echo.
echo %C_GREEN%1.%C_RESET% Toggle adaptive mode (recommended ON)
echo %C_GREEN%2.%C_RESET% Change profile
echo %C_GREEN%3.%C_RESET% Change preemptive hop ms
echo %C_GREEN%4.%C_RESET% Toggle hopping on / off
echo %C_GREEN%5.%C_RESET% Set fixed hop ms
echo %C_GREEN%6.%C_RESET% Set manual burst multiplier
echo %C_GREEN%7.%C_RESET% Set keepalive seconds
echo %C_GREEN%8.%C_RESET% Set max ping ms
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 12345678B /n /m "Select an option: "
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

:toggle_adaptive
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
cls
echo %C_CYAN%%C_BOLD%[ Choose Profile ]%C_RESET%
echo.
echo   %C_GREEN%1.%C_RESET% balanced   - Default. Adaptive, moderate overhead. Good for unknown networks.
echo   %C_GREEN%2.%C_RESET% ghost      - Max DPI evasion. Obfs+masq+rand+jitter all on. Looks like browser.
echo   %C_GREEN%3.%C_RESET% survival   - Max delivery. FEC 4+6, burst x8 always. For 80%%+ loss links.
echo   %C_GREEN%4.%C_RESET% throughput - Max speed. Minimal overhead. For stable low-loss links.
echo   %C_GREEN%5.%C_RESET% mobile     - Cellular optimised. FEC 4+5, short keepalive, handles handoffs.
echo   %C_GREEN%6.%C_RESET% tunnel     - TUN/TAP IP tunnel mode. No reactive probe, very short keepalive.
echo   %C_GREEN%B.%C_RESET% Back
echo.
choice /c 123456B /n /m "Profile: "
if errorlevel 7 goto :mode_menu
if errorlevel 6 set "PROFILE=tunnel" & goto :apply_profile
if errorlevel 5 set "PROFILE=mobile" & goto :apply_profile
if errorlevel 4 set "PROFILE=throughput" & goto :apply_profile
if errorlevel 3 set "PROFILE=survival" & goto :apply_profile
if errorlevel 2 set "PROFILE=ghost" & goto :apply_profile
if errorlevel 1 set "PROFILE=balanced" & goto :apply_profile
goto :mode_menu

:apply_profile
rem Apply sensible defaults per profile so status display is accurate
if /i "%PROFILE%"=="ghost" (
  set "OBFS=true"
  set "MASQ=true"
  set "RAND_SRC=true"
  set "JITTER=64"
  set "PREEMPTIVE=600"
  set "KEEPALIVE_SEC=12"
  set "FEC_K=4"
  set "FEC_M=4"
  set "MANUAL_BURST=0"
)
if /i "%PROFILE%"=="survival" (
  set "OBFS=false"
  set "MASQ=false"
  set "JITTER=0"
  set "PREEMPTIVE=700"
  set "KEEPALIVE_SEC=10"
  set "FEC_K=4"
  set "FEC_M=6"
  set "MANUAL_BURST=8"
)
if /i "%PROFILE%"=="balanced" (
  set "OBFS=false"
  set "MASQ=false"
  set "JITTER=32"
  set "PREEMPTIVE=800"
  set "KEEPALIVE_SEC=15"
  set "FEC_K=4"
  set "FEC_M=4"
  set "MANUAL_BURST=0"
)
if /i "%PROFILE%"=="throughput" (
  set "OBFS=false"
  set "MASQ=false"
  set "JITTER=0"
  set "PREEMPTIVE=0"
  set "KEEPALIVE_SEC=20"
  set "FEC_K=6"
  set "FEC_M=2"
  set "MANUAL_BURST=0"
)
if /i "%PROFILE%"=="mobile" (
  set "OBFS=false"
  set "MASQ=false"
  set "JITTER=16"
  set "PREEMPTIVE=900"
  set "KEEPALIVE_SEC=8"
  set "FEC_K=4"
  set "FEC_M=5"
  set "MANUAL_BURST=0"
)
if /i "%PROFILE%"=="tunnel" (
  set "OBFS=false"
  set "MASQ=false"
  set "JITTER=0"
  set "PREEMPTIVE=800"
  set "KEEPALIVE_SEC=5"
  set "FEC_K=4"
  set "FEC_M=4"
  set "MANUAL_BURST=0"
)
goto :mode_menu

:toggle_hop
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
set /p "MANUAL_BURST=Manual burst multiplier (0=auto, B=back) [%MANUAL_BURST%]: "
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
set /p "KEEPALIVE_SEC=Keepalive seconds (0=off, B=back) [%KEEPALIVE_SEC%]: "
if /i "%KEEPALIVE_SEC%"=="b" set "KEEPALIVE_SEC=%OLD_KEEPALIVE_SEC%" & goto :mode_menu
if not defined KEEPALIVE_SEC set "KEEPALIVE_SEC=%OLD_KEEPALIVE_SEC%"
goto :mode_menu

:change_max_ping
set "OLD_MAX_PING_MS=%MAX_PING_MS%"
set /p "MAX_PING_MS=Max ping ms (B=back) [%MAX_PING_MS%]: "
if /i "%MAX_PING_MS%"=="b" set "MAX_PING_MS=%OLD_MAX_PING_MS%" & goto :mode_menu
if not defined MAX_PING_MS set "MAX_PING_MS=%OLD_MAX_PING_MS%"
goto :mode_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  TRANSPORT MENU
rem ══════════════════════════════════════════════════════════════════════════

:transport_menu
cls
echo %C_CYAN%%C_BOLD%[ Transport Menu ]%C_RESET%
echo.
echo   Obfs              : %OBFS%
echo   Masquerade (H3)   : %MASQ%
echo   Random source port: %RAND_SRC%
echo   Jitter bytes      : %JITTER%
echo.
echo %C_GREEN%1.%C_RESET% Toggle obfuscation (Salamander XOR stream)
echo %C_GREEN%2.%C_RESET% Toggle HTTP/3 masquerade
echo %C_GREEN%3.%C_RESET% Toggle random source port [optional]
echo %C_GREEN%4.%C_RESET% Change jitter bytes (0=off)
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 1234B /n /m "Select an option: "
if errorlevel 5 goto :main_menu
if errorlevel 4 goto :change_jitter
if errorlevel 3 goto :toggle_rand
if errorlevel 2 goto :toggle_masq
if errorlevel 1 goto :toggle_obfs
goto :transport_menu

:toggle_obfs
if /i "%OBFS%"=="true" (set "OBFS=false") else (set "OBFS=true")
goto :transport_menu

:toggle_masq
if /i "%MASQ%"=="true" (set "MASQ=false") else (set "MASQ=true")
goto :transport_menu

:toggle_rand
if /i "%RAND_SRC%"=="true" (set "RAND_SRC=false") else (set "RAND_SRC=true")
goto :transport_menu

:change_jitter
set "OLD_JITTER=%JITTER%"
set /p "JITTER=Packet jitter bytes (0=off, B=back) [%JITTER%]: "
if /i "%JITTER%"=="b" set "JITTER=%OLD_JITTER%" & goto :transport_menu
if not defined JITTER set "JITTER=%OLD_JITTER%"
goto :transport_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  ADVANCED CORE MENU
rem ══════════════════════════════════════════════════════════════════════════

:advanced_menu
cls
echo %C_CYAN%%C_BOLD%[ Advanced Core Menu ]%C_RESET%
echo.
echo   Seed                  : %SEED%
echo   Declared uplink kbps  : %DECLARED_UP%   (0=auto Brutal CC)
echo   Declared downlink kbps: %DECLARED_DOWN%  (0=auto)
echo   MTU override          : %MTU%   (0=auto probe)
echo   FEC                   : k=%FEC_K%  m=%FEC_M%
echo   Probe count/timeout   : %PROBE_COUNT% / %PROBE_TIMEOUT%ms
echo   Startup capacity scan : %STARTUP_CAPACITY_SCAN%
echo   Scan throttle thresh  : %SCAN_THROTTLE_THRESHOLD_PCT%%%
echo   Scan recovery thresh  : %SCAN_RECOVERY_THRESHOLD_PCT%%%
echo.
echo %C_GREEN%1.%C_RESET% Change seed
echo %C_GREEN%2.%C_RESET% Change declared uplink kbps
echo %C_GREEN%3.%C_RESET% Change declared downlink kbps
echo %C_GREEN%4.%C_RESET% Change MTU override (0=auto)
echo %C_GREEN%5.%C_RESET% Change FEC k (data shards)
echo %C_GREEN%6.%C_RESET% Change FEC m (parity shards)
echo %C_GREEN%7.%C_RESET% Change probe count
echo %C_GREEN%8.%C_RESET% Change probe timeout ms
echo %C_GREEN%9.%C_RESET% Toggle startup capacity scan
echo %C_GREEN%A.%C_RESET% Change scan throttle threshold %%
echo %C_GREEN%B.%C_RESET% Change scan recovery threshold %%
echo %C_GREEN%C.%C_RESET% Back
echo.
choice /c 123456789ABC /n /m "Select an option: "
if errorlevel 12 goto :main_menu
if errorlevel 11 goto :change_scan_recovery_threshold
if errorlevel 10 goto :change_scan_throttle_threshold
if errorlevel 9  goto :toggle_startup_capacity_scan
if errorlevel 8  goto :change_probe_timeout
if errorlevel 7  goto :change_probe_count
if errorlevel 6  goto :change_fec_m
if errorlevel 5  goto :change_fec_k
if errorlevel 4  goto :change_mtu
if errorlevel 3  goto :change_declared_down
if errorlevel 2  goto :change_declared_up
if errorlevel 1  goto :change_seed
goto :advanced_menu

:change_seed
set "OLD_SEED=%SEED%"
set /p "SEED=Shared seed (must match server, B=back) [%SEED%]: "
if /i "%SEED%"=="b" set "SEED=%OLD_SEED%" & goto :advanced_menu
if not defined SEED set "SEED=%OLD_SEED%"
goto :advanced_menu

:change_declared_up
set "OLD_DECLARED_UP=%DECLARED_UP%"
set /p "DECLARED_UP=Declared uplink kbps (0=auto, B=back) [%DECLARED_UP%]: "
if /i "%DECLARED_UP%"=="b" set "DECLARED_UP=%OLD_DECLARED_UP%" & goto :advanced_menu
if not defined DECLARED_UP set "DECLARED_UP=%OLD_DECLARED_UP%"
goto :advanced_menu

:change_declared_down
set "OLD_DECLARED_DOWN=%DECLARED_DOWN%"
set /p "DECLARED_DOWN=Declared downlink kbps (0=auto, B=back) [%DECLARED_DOWN%]: "
if /i "%DECLARED_DOWN%"=="b" set "DECLARED_DOWN=%OLD_DECLARED_DOWN%" & goto :advanced_menu
if not defined DECLARED_DOWN set "DECLARED_DOWN=%OLD_DECLARED_DOWN%"
goto :advanced_menu

:change_mtu
set "OLD_MTU=%MTU%"
set /p "MTU=MTU payload override bytes (0=auto probe, B=back) [%MTU%]: "
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
set /p "PROBE_COUNT=Probe packet count (B=back) [%PROBE_COUNT%]: "
if /i "%PROBE_COUNT%"=="b" set "PROBE_COUNT=%OLD_PROBE_COUNT%" & goto :advanced_menu
if not defined PROBE_COUNT set "PROBE_COUNT=%OLD_PROBE_COUNT%"
goto :advanced_menu

:change_probe_timeout
set "OLD_PROBE_TIMEOUT=%PROBE_TIMEOUT%"
set /p "PROBE_TIMEOUT=Probe timeout ms (B=back) [%PROBE_TIMEOUT%]: "
if /i "%PROBE_TIMEOUT%"=="b" set "PROBE_TIMEOUT=%OLD_PROBE_TIMEOUT%" & goto :advanced_menu
if not defined PROBE_TIMEOUT set "PROBE_TIMEOUT=%OLD_PROBE_TIMEOUT%"
goto :advanced_menu

:toggle_startup_capacity_scan
if /i "%STARTUP_CAPACITY_SCAN%"=="true" (
  set "STARTUP_CAPACITY_SCAN=false"
) else (
  set "STARTUP_CAPACITY_SCAN=true"
)
goto :advanced_menu

:change_scan_throttle_threshold
set "OLD_SCAN_THROTTLE_THRESHOLD_PCT=%SCAN_THROTTLE_THRESHOLD_PCT%"
set /p "SCAN_THROTTLE_THRESHOLD_PCT=Throttle threshold %% (B=back) [%SCAN_THROTTLE_THRESHOLD_PCT%]: "
if /i "%SCAN_THROTTLE_THRESHOLD_PCT%"=="b" set "SCAN_THROTTLE_THRESHOLD_PCT=%OLD_SCAN_THROTTLE_THRESHOLD_PCT%" & goto :advanced_menu
if not defined SCAN_THROTTLE_THRESHOLD_PCT set "SCAN_THROTTLE_THRESHOLD_PCT=%OLD_SCAN_THROTTLE_THRESHOLD_PCT%"
goto :advanced_menu

:change_scan_recovery_threshold
set "OLD_SCAN_RECOVERY_THRESHOLD_PCT=%SCAN_RECOVERY_THRESHOLD_PCT%"
set /p "SCAN_RECOVERY_THRESHOLD_PCT=Recovery threshold %% (B=back) [%SCAN_RECOVERY_THRESHOLD_PCT%]: "
if /i "%SCAN_RECOVERY_THRESHOLD_PCT%"=="b" set "SCAN_RECOVERY_THRESHOLD_PCT=%OLD_SCAN_RECOVERY_THRESHOLD_PCT%" & goto :advanced_menu
if not defined SCAN_RECOVERY_THRESHOLD_PCT set "SCAN_RECOVERY_THRESHOLD_PCT=%OLD_SCAN_RECOVERY_THRESHOLD_PCT%"
goto :advanced_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  LOGGING MENU
rem ══════════════════════════════════════════════════════════════════════════

:logs_menu
cls
echo %C_CYAN%%C_BOLD%[ Logging Menu ]%C_RESET%
echo.
echo   Verbose  : %VERBOSE%
echo   JSON logs: %JSON_LOGS%
echo.
echo %C_GREEN%1.%C_RESET% Toggle verbose logging
echo %C_GREEN%2.%C_RESET% Toggle JSON structured logs
echo %C_GREEN%B.%C_RESET% Back
echo.
choice /c 12B /n /m "Select an option: "
if errorlevel 3 goto :main_menu
if errorlevel 2 goto :toggle_json
if errorlevel 1 goto :toggle_verbose
goto :logs_menu

:toggle_verbose
if /i "%VERBOSE%"=="true" (set "VERBOSE=false") else (set "VERBOSE=true")
goto :logs_menu

:toggle_json
if /i "%JSON_LOGS%"=="true" (set "JSON_LOGS=false") else (set "JSON_LOGS=true")
goto :logs_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  SAVE / START
rem ══════════════════════════════════════════════════════════════════════════

:save_only
call :write_config
echo.
echo %C_GREEN%Saved client.config.json%C_RESET%
pause
goto :main_menu

:start_client
call :write_config
echo.
echo %C_CYAN%Starting HopShot client...%C_RESET%
echo   Server  : %SERVER%:%PORT%
echo   Profile : %PROFILE%
echo   Seed    : %SEED%
echo.
call :resolve_python
if not defined PYTHON_LAUNCHER goto :main_menu
%PYTHON_LAUNCHER% client.py --config client.config.json
if errorlevel 1 (
  echo.
  echo %C_YELLOW%Client exited with an error. Check client.log for details.%C_RESET%
  pause
)
goto :main_menu

rem ══════════════════════════════════════════════════════════════════════════
rem  WRITE CONFIG
rem ══════════════════════════════════════════════════════════════════════════

:write_config
setlocal EnableDelayedExpansion
set "DEST_CLEAN=!DESTINATIONS: =!"
if not defined DEST_CLEAN set "DEST_CLEAN=195.88.208.120"
set "DEST_JSON=!DEST_CLEAN:,=","!"
(
  echo {
  echo   "server_port": %PORT%,
  echo   "quic_port": %QUIC_PORT%,
  echo   "health_port": %HEALTH_PORT%,
  echo   "port_min": %PORT_MIN%,
  echo   "port_max": %PORT_MAX%,
  echo   "shared_seed": "%SEED%",
  echo   "profile": "%PROFILE%",
  echo   "service_mode": "%SERVICE_MODE%",
  echo   "adaptive_mode": %ADAPTIVE_MODE%,
  echo   "max_ping_ms": %MAX_PING_MS%,
  echo   "disable_hop": %DISABLE_HOP%,
  echo   "obfs": %OBFS%,
  echo   "masquerade": %MASQ%,
  echo   "rand_src_port": %RAND_SRC%,
  echo   "jitter_bytes": %JITTER%,
  echo   "preemptive_hop_ms": %PREEMPTIVE%,
  echo   "fixed_hop_ms": %FIXED_HOP_MS%,
  echo   "manual_burst_mult": %MANUAL_BURST%,
  echo   "keepalive_interval_sec": %KEEPALIVE_SEC%,
  echo   "proxy_listen": "%PROXY_LISTEN%",
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
  echo   "declared_down_kbps": %DECLARED_DOWN%,
  echo   "mtu": %MTU%,
  echo   "fec_k": %FEC_K%,
  echo   "fec_m": %FEC_M%,
  echo   "probe_count": %PROBE_COUNT%,
  echo   "probe_timeout_ms": %PROBE_TIMEOUT%,
  echo   "startup_capacity_scan": %STARTUP_CAPACITY_SCAN%,
  echo   "scan_throttle_threshold_pct": %SCAN_THROTTLE_THRESHOLD_PCT%,
  echo   "scan_recovery_threshold_pct": %SCAN_RECOVERY_THRESHOLD_PCT%,
  echo   "destinations": ["!DEST_JSON!"],
  echo   "resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
  echo   "verbose": %VERBOSE%,
  echo   "log_file": "client.log",
  echo   "json_logs": %JSON_LOGS%,
  echo   "metrics_file": "client.metrics.jsonl"
  echo }
) > client.config.json
endlocal
exit /b 0

rem ══════════════════════════════════════════════════════════════════════════
rem  LOAD EXISTING CONFIG
rem ══════════════════════════════════════════════════════════════════════════

:load_existing_config
for /f "usebackq delims=" %%L in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $cfg = Get-Content -Raw -Path 'client.config.json' ^| ConvertFrom-Json; " ^
  "if($cfg.destinations){'SERVER=' + $cfg.destinations[0]; 'DESTINATIONS=' + (($cfg.destinations) -join ',')}; " ^
  "'PORT=' + $cfg.server_port; 'QUIC_PORT=' + $cfg.quic_port; " ^
  "if($null -ne $cfg.health_port){'HEALTH_PORT=' + $cfg.health_port}; " ^
  "if($null -ne $cfg.shared_seed){'SEED=' + $cfg.shared_seed}; " ^
  "if($null -ne $cfg.profile){'PROFILE=' + $cfg.profile}; " ^
  "if($null -ne $cfg.service_mode){'SERVICE_MODE=' + $cfg.service_mode}; " ^
  "if($null -ne $cfg.proxy_listen){'PROXY_LISTEN=' + $cfg.proxy_listen}; " ^
  "'PORT_MIN=' + $cfg.port_min; 'PORT_MAX=' + $cfg.port_max; " ^
  "'ADAPTIVE_MODE=' + ($cfg.adaptive_mode.ToString().ToLower()); " ^
  "'MAX_PING_MS=' + $cfg.max_ping_ms; " ^
  "'DISABLE_HOP=' + ($cfg.disable_hop.ToString().ToLower()); " ^
  "'OBFS=' + ($cfg.obfs.ToString().ToLower()); " ^
  "'MASQ=' + ($cfg.masquerade.ToString().ToLower()); " ^
  "'RAND_SRC=' + ($cfg.rand_src_port.ToString().ToLower()); " ^
  "'JITTER=' + $cfg.jitter_bytes; 'PREEMPTIVE=' + $cfg.preemptive_hop_ms; " ^
  "'FIXED_HOP_MS=' + $cfg.fixed_hop_ms; 'MANUAL_BURST=' + $cfg.manual_burst_mult; " ^
  "'KEEPALIVE_SEC=' + $cfg.keepalive_interval_sec; " ^
  "if($null -ne $cfg.tunnel_mode){'TUNNEL_MODE=' + $cfg.tunnel_mode}; " ^
  "if($null -ne $cfg.tunnel_iface){'TUNNEL_IFACE=' + $cfg.tunnel_iface}; " ^
  "if($null -ne $cfg.tunnel_mtu){'TUNNEL_MTU=' + $cfg.tunnel_mtu}; " ^
  "if($null -ne $cfg.tunnel_address){'TUNNEL_ADDRESS=' + $cfg.tunnel_address}; " ^
  "if($null -ne $cfg.tunnel_peer){'TUNNEL_PEER=' + $cfg.tunnel_peer}; " ^
  "if($null -ne $cfg.tunnel_route_default){'TUNNEL_DEFAULT_ROUTE=' + ($cfg.tunnel_route_default.ToString().ToLower())}; " ^
  "if($null -ne $cfg.tunnel_udp_bind){'TUNNEL_UDP_BIND=' + $cfg.tunnel_udp_bind}; " ^
  "if($null -ne $cfg.tunnel_udp_target){'TUNNEL_UDP_TARGET=' + $cfg.tunnel_udp_target}; " ^
  "if($null -ne $cfg.startup_capacity_scan){'STARTUP_CAPACITY_SCAN=' + ($cfg.startup_capacity_scan.ToString().ToLower())}; " ^
  "if($null -ne $cfg.scan_throttle_threshold_pct){'SCAN_THROTTLE_THRESHOLD_PCT=' + $cfg.scan_throttle_threshold_pct}; " ^
  "if($null -ne $cfg.scan_recovery_threshold_pct){'SCAN_RECOVERY_THRESHOLD_PCT=' + $cfg.scan_recovery_threshold_pct}; " ^
  "if($null -ne $cfg.declared_up_kbps){'DECLARED_UP=' + $cfg.declared_up_kbps}; " ^
  "if($null -ne $cfg.declared_down_kbps){'DECLARED_DOWN=' + $cfg.declared_down_kbps}; " ^
  "if($null -ne $cfg.mtu){'MTU=' + $cfg.mtu}; if($null -ne $cfg.fec_k){'FEC_K=' + $cfg.fec_k}; if($null -ne $cfg.fec_m){'FEC_M=' + $cfg.fec_m}; " ^
  "if($null -ne $cfg.probe_count){'PROBE_COUNT=' + $cfg.probe_count}; if($null -ne $cfg.probe_timeout_ms){'PROBE_TIMEOUT=' + $cfg.probe_timeout_ms}; " ^
  "if($null -ne $cfg.verbose){'VERBOSE=' + ($cfg.verbose.ToString().ToLower())}; if($null -ne $cfg.json_logs){'JSON_LOGS=' + ($cfg.json_logs.ToString().ToLower())}"`) do (
  for /f "tokens=1,* delims==" %%K in ("%%L") do set "%%K=%%M"
)
exit /b 0

rem ══════════════════════════════════════════════════════════════════════════
rem  PYTHON RESOLVER
rem ══════════════════════════════════════════════════════════════════════════

:resolve_python
set "PYTHON_LAUNCHER="
where py >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_LAUNCHER=py -3"
  exit /b 0
)
where python3 >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_LAUNCHER=python3"
  exit /b 0
)
where python >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_LAUNCHER=python"
  exit /b 0
)
echo.
echo %C_YELLOW%Python not found. Install Python 3.10 or newer from python.org%C_RESET%
pause
exit /b 1

:end
endlocal
exit /b 0