@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"
title HopShot Client Launcher

set "SERVER=127.0.0.1"
set "PORT=10000"
set "QUIC_PORT=10001"
set "SEED=change-me"
set "PROFILE=balanced"
set "JITTER=64"
set "PORT_MIN=10000"
set "PORT_MAX=65000"
set "PREEMPTIVE=800"
set "DECLARED_UP=0"
set "MTU=0"
set "FEC_K=4"
set "FEC_M=4"
set "PROBE_COUNT=20"
set "PROBE_TIMEOUT=2000"
set "OBFS=false"
set "MASQ=false"
set "RAND_SRC=false"
set "VERBOSE=false"
set "JSON_LOGS=false"

:menu
cls
echo ==================================================
echo   HopShot Client Launcher
echo ==================================================
echo.
echo Current settings:
echo   Server        : %SERVER%
echo   Port          : %PORT%
echo   QUIC port     : %QUIC_PORT%
echo   Seed          : %SEED%
echo   Profile       : %PROFILE%
echo   Destinations   : %SERVER%
echo   Jitter        : %JITTER%
echo   Preemptive hop: %PREEMPTIVE%
echo   Obfs          : %OBFS%
echo   Masquerade    : %MASQ%
echo   Rand src port : %RAND_SRC%
echo   JSON logs     : %JSON_LOGS%
echo.
echo 1. Start client with these settings
echo 2. Change server / domain
echo 3. Change seed
echo 4. Change profile
echo 5. Toggle obfs
echo 6. Toggle masquerade
echo 7. Toggle random source port
echo 8. Save config only
echo 9. Exit
echo.
choice /c 123456789 /n /m "Select an option:"

if errorlevel 9 goto :end
if errorlevel 8 goto :save_only
if errorlevel 7 goto :toggle_rand
if errorlevel 6 goto :toggle_masq
if errorlevel 5 goto :toggle_obfs
if errorlevel 4 goto :pick_profile
if errorlevel 3 goto :change_seed
if errorlevel 2 goto :change_server
if errorlevel 1 goto :start_client
goto :menu

:change_server
set /p "SERVER=Server IP or domain [%SERVER%]: "
if not defined SERVER set "SERVER=127.0.0.1"
goto :menu

:change_seed
set /p "SEED=Shared seed [%SEED%]: "
if not defined SEED set "SEED=change-me"
goto :menu

:pick_profile
echo.
echo Choose profile:
echo   1. balanced
echo   2. reliable
echo   3. stealth
echo   4. throughput
choice /c 1234 /n /m "Profile:"
if errorlevel 4 set "PROFILE=throughput"
if errorlevel 3 set "PROFILE=stealth"
if errorlevel 2 set "PROFILE=reliable"
if errorlevel 1 set "PROFILE=balanced"
goto :menu

:toggle_obfs
if /i "%OBFS%"=="true" (
  set "OBFS=false"
) else (
  set "OBFS=true"
)
goto :menu

:toggle_masq
if /i "%MASQ%"=="true" (
  set "MASQ=false"
) else (
  set "MASQ=true"
)
goto :menu

:toggle_rand
if /i "%RAND_SRC%"=="true" (
  set "RAND_SRC=false"
) else (
  set "RAND_SRC=true"
)
goto :menu

:save_only
call :write_config
echo.
echo Saved client.config.json.
pause
goto :menu

:start_client
call :write_config
echo.
echo Starting HopShot client...
call :resolve_python
if not defined PYTHON_LAUNCHER goto :menu
call %PYTHON_LAUNCHER% deploy.py client
echo.
pause
goto :menu

:write_config
(
  echo {
  echo   "server_port": %PORT%,
  echo   "quic_port": %QUIC_PORT%,
  echo   "port_min": %PORT_MIN%,
  echo   "port_max": %PORT_MAX%,
  echo   "shared_seed": "%SEED%",
  echo   "profile": "%PROFILE%",
  echo   "obfs": %OBFS%,
  echo   "rand_src_port": %RAND_SRC%,
  echo   "jitter_bytes": %JITTER%,
  echo   "preemptive_hop_ms": %PREEMPTIVE%,
  echo   "declared_up_kbps": %DECLARED_UP%,
  echo   "masquerade": %MASQ%,
  echo   "mtu": %MTU%,
  echo   "fec_k": %FEC_K%,
  echo   "fec_m": %FEC_M%,
  echo   "probe_count": %PROBE_COUNT%,
  echo   "probe_timeout_ms": %PROBE_TIMEOUT%,
  echo   "destinations": ["%SERVER%"],
  echo   "resolvers": ["1.1.1.1"],
  echo   "verbose": %VERBOSE%,
  echo   "log_file": "client.log",
  echo   "json_logs": %JSON_LOGS%,
  echo   "metrics_file": "client.metrics.jsonl"
  echo }
) > client.config.json
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
