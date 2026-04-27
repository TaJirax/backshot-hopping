@echo off
setlocal EnableExtensions

cd /d "%~dp0"
title HopShot Server Launcher

:main
cls
echo ==================================================
echo   HopShot Server Launcher
echo ==================================================
echo.
echo 1. Easy setup ^+ start server (recommended)
echo 2. Easy setup only (no start)
echo 3. Diagnose server config
echo 4. Generate shared seed for server/client configs
echo 5. Start server (normal)
echo X. Exit
echo.
choice /c 12345X /n /m "Select an option: "
if errorlevel 6 goto :end
if errorlevel 5 goto :start_normal
if errorlevel 4 goto :genkey
if errorlevel 3 goto :diagnose
if errorlevel 2 goto :easy_prepare
if errorlevel 1 goto :easy_start
goto :main

:easy_start
call :resolve_python
if errorlevel 1 goto :main
call %PYTHON_LAUNCHER% deploy.py server --easy --config server.config.json
if errorlevel 1 pause
goto :main

:easy_prepare
call :resolve_python
if errorlevel 1 goto :main
call %PYTHON_LAUNCHER% deploy.py server --easy --prepare-only --config server.config.json
if errorlevel 1 pause
pause
goto :main

:diagnose
call :resolve_python
if errorlevel 1 goto :main
call %PYTHON_LAUNCHER% deploy.py server --easy --diagnose --prepare-only --config server.config.json
if errorlevel 1 pause
pause
goto :main

:genkey
call :resolve_python
if errorlevel 1 goto :main
call %PYTHON_LAUNCHER% deploy.py genkey
if errorlevel 1 pause
pause
goto :main

:start_normal
call :resolve_python
if errorlevel 1 goto :main
call %PYTHON_LAUNCHER% deploy.py server --config server.config.json
if errorlevel 1 pause
goto :main

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
echo Python launcher not found. Install Python 3.10 or newer, then run this again.
pause
exit /b 1

:end
endlocal
exit /b 0
