@echo off
setlocal
chcp 65001 >nul
title XSIAM

set "OUT=%~dp0"
set "OUT=%OUT:~0,-1%"
set "ROOT=%OUT%\.."
set "BIN=%OUT%\bin\xsiam.exe"
set "LOGDIR=%OUT%\logs"

echo ============================================================
echo  XSIAM  ^(auto-restart loop^)
echo  Web     : http://localhost:18080
echo  Internal: http://localhost:18090
echo  Login   : admin / admin123
echo  Logs    : output\logs\
echo  Press Ctrl+C to stop.
echo ============================================================

if not exist "%BIN%" (
    echo [!!] bin\xsiam.exe not found — run ..\rebuild.bat first
    pause
    exit /b 1
)
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

:: Start Redis if not already on port 6379
netstat -ano | findstr ":6379" | findstr "LISTENING" >nul 2>&1
if errorlevel 1 (
    set "REDIS=%ROOT%\third_party\tools\redis-8.6.3-windows-x64-msys2-with-service\Redis-8.6.3-Windows-x64-msys2-with-Service\redis-server.exe"
    if exist "%REDIS%" (
        start /min "redis" "%REDIS%" --dir "%OUT%\data\redis" --save 300 1
        timeout /t 2 /nobreak >nul
        echo [OK] Redis started
    )
)

:: Start ArangoDB
docker start xsiam-arangodb >nul 2>&1

set "STDOUT=%LOGDIR%\xsiam_out.log"
set "STDERR=%LOGDIR%\xsiam_err.log"

:: Auto-restart loop — run from output/ so config.yaml is picked up
:LOOP
taskkill /f /im xsiam.exe >nul 2>&1
timeout /t 1 /nobreak >nul
cd /d "%OUT%"
"%BIN%" 1>>"%STDOUT%" 2>>"%STDERR%"
echo [WARN] xsiam exited (code %errorlevel%), restarting in 3s...
timeout /t 3 /nobreak >nul
docker start xsiam-arangodb >nul 2>&1
goto LOOP
