@echo off
setlocal
set ROOT=%~dp0
set XSIAM=%ROOT%xsiam
set PATH=%APPDATA%\npm;%PATH%

echo ============================================================
echo  XSIAM start script
echo ============================================================

:: 1. Wake WSL + start ArangoDB + keepalive
echo [1/3] Starting ArangoDB (WSL)...
wsl -d Ubuntu-24.04 -- sudo service arangodb3 start >nul 2>&1
:: Start a keepalive loop in WSL background to prevent VM suspension
start /min "" wsl -d Ubuntu-24.04 -- bash -c "while true; do curl -s http://127.0.0.1:8529/_api/version > /dev/null 2>&1; sleep 15; done"
timeout /t 3 /nobreak >nul

:: Wait up to 30s for 8529 to be reachable
set ARANGO_UP=0
for /L %%i in (1,1,30) do (
    powershell -NoProfile -Command "try { $t=New-Object Net.Sockets.TcpClient; $t.Connect('127.0.0.1',8529); $t.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
    if not errorlevel 1 (
        set ARANGO_UP=1
        goto :ARANGO_READY
    )
    timeout /t 1 /nobreak >nul
)
:ARANGO_READY
if "%ARANGO_UP%"=="0" (
    echo [WARN] ArangoDB port 8529 not reachable after 30s, continuing anyway...
) else (
    echo [OK] ArangoDB
)

:: 2. Start Redis (if not already running)
echo [2/3] Starting Redis...
netstat -ano | findstr ":6379" | findstr "LISTENING" >nul 2>&1
if errorlevel 1 (
    start /min "" "%ROOT%third_party\tools\redis-8.6.3-windows-x64-msys2-with-service\Redis-8.6.3-Windows-x64-msys2-with-Service\redis-server.exe"
    timeout /t 2 /nobreak >nul
)
echo [OK] Redis

:: 3. Keep xsiam running — restart on crash
echo [3/3] Starting xsiam (auto-restart loop)...
echo  Web  : http://localhost:8080
echo  Login: admin / admin
echo  Press Ctrl+C to stop.
echo ============================================================

:LOOP
taskkill /f /im xsiam.exe >nul 2>&1
timeout /t 1 /nobreak >nul
cd /d "%XSIAM%"
xsiam.exe
echo [WARN] xsiam exited (code %errorlevel%), restarting in 3s...
timeout /t 3 /nobreak >nul
:: Re-wake WSL and ensure keepalive is running
wsl -d Ubuntu-24.04 -- sudo service arangodb3 start >nul 2>&1
start /min "" wsl -d Ubuntu-24.04 -- bash -c "while true; do curl -s http://127.0.0.1:8529/_api/version > /dev/null 2>&1; sleep 15; done"
timeout /t 5 /nobreak >nul
goto LOOP
