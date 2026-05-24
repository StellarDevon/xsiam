@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
title XSIAM — Restart All Services

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║        XSIAM — Restart All Services                 ║
echo ╚══════════════════════════════════════════════════════╝
echo.

:: ─────────────────────────────────────────────
:: 1. Stop existing processes
:: ─────────────────────────────────────────────
echo [1/5] Stopping existing processes...

taskkill /F /IM xsiam.exe      >nul 2>&1 && echo   [OK] Stopped xsiam.exe      || echo   [--] xsiam.exe not running
taskkill /F /IM ngx_console.exe >nul 2>&1 && echo   [OK] Stopped ngx_console   || echo   [--] ngx_console not running
taskkill /F /IM ngx_svc.exe    >nul 2>&1 && echo   [OK] Stopped ngx_svc       || echo   [--] ngx_svc not running
taskkill /F /IM ngx_cron.exe   >nul 2>&1 && echo   [OK] Stopped ngx_cron      || echo   [--] ngx_cron not running
taskkill /F /IM redis-server.exe >nul 2>&1 && echo   [OK] Stopped Redis         || echo   [--] Redis not running
taskkill /F /IM etcd.exe        >nul 2>&1 && echo   [OK] Stopped etcd          || echo   [--] etcd not running

timeout /t 1 /nobreak >nul
echo.

:: ─────────────────────────────────────────────
:: 2. Start etcd
:: ─────────────────────────────────────────────
echo [2/5] Starting etcd...
set "ETCD=%ROOT%\third_party\tools\etcd-v3.6.11-windows-amd64\etcd-v3.6.11-windows-amd64\etcd.exe"
if exist "%ETCD%" (
    start "etcd" /MIN "%ETCD%"
    timeout /t 2 /nobreak >nul
    echo   [OK] etcd started
) else (
    echo   [!!] etcd not found: %ETCD%
)

:: ─────────────────────────────────────────────
:: 3. Start Redis
:: ─────────────────────────────────────────────
echo [3/5] Starting Redis...
set "REDIS=%ROOT%\third_party\tools\redis-8.6.3-windows-x64-msys2-with-service\Redis-8.6.3-Windows-x64-msys2-with-Service\redis-server.exe"
if exist "%REDIS%" (
    start "redis" /MIN "%REDIS%"
    timeout /t 2 /nobreak >nul
    echo   [OK] Redis started
) else (
    echo   [!!] Redis not found: %REDIS%
)

:: ─────────────────────────────────────────────
:: 4. Start ArangoDB (Docker)
:: ─────────────────────────────────────────────
echo [4/5] Starting ArangoDB (Docker)...
where docker >nul 2>&1
if %ERRORLEVEL% == 0 (
    docker start xsiam-arangodb >nul 2>&1
    if %ERRORLEVEL% == 0 (
        echo   [OK] ArangoDB container started
    ) else (
        docker run -d --name xsiam-arangodb ^
            -e ARANGO_ROOT_PASSWORD=changeme ^
            -p 8529:8529 ^
            arangodb:3.12.9.1 >nul 2>&1
        if %ERRORLEVEL% == 0 (
            echo   [OK] ArangoDB container created and started
        ) else (
            echo   [!!] Failed to start ArangoDB — check Docker Desktop
        )
    )
) else (
    echo   [~~] Docker not in PATH — skipping ArangoDB
    echo        Start Docker Desktop manually if needed
)
timeout /t 3 /nobreak >nul

:: ─────────────────────────────────────────────
:: 5. Build frontend (optional — skip if dist exists and is fresh)
:: ─────────────────────────────────────────────
echo [5/5] Checking frontend build...
set "DIST=%ROOT%\xsiam\dist\index.html"
set "REBUILD=0"

if not exist "%DIST%" (
    set "REBUILD=1"
    echo   [..] dist/index.html not found — rebuilding frontend
)

if "%REBUILD%"=="1" (
    echo   [..] Running pnpm build in web\...
    pushd "%ROOT%\web"
    call pnpm build
    if %ERRORLEVEL% neq 0 (
        echo   [!!] pnpm build failed — aborting
        popd
        goto :error
    )
    popd
    echo   [OK] Frontend built successfully
) else (
    echo   [OK] dist exists — skipping rebuild ^(run build.bat to force^)
)

:: ─────────────────────────────────────────────
:: 6. Build Go binary if needed
:: ─────────────────────────────────────────────
set "BIN=%ROOT%\xsiam\xsiam.exe"
if not exist "%BIN%" (
    echo   [..] xsiam.exe not found — building...
    pushd "%ROOT%\xsiam"
    set CGO_ENABLED=0
    go build -ldflags="-s -w" -o xsiam.exe ./cmd/xsiam
    if %ERRORLEVEL% neq 0 (
        echo   [!!] go build failed
        popd
        goto :error
    )
    popd
    echo   [OK] xsiam.exe built
)

:: ─────────────────────────────────────────────
:: 7. Start xsiam (all-in-one)
:: ─────────────────────────────────────────────
echo.
echo [*] Starting xsiam (console + svc + cron)...
pushd "%ROOT%\xsiam"
start "xsiam" /MIN "%BIN%"
popd
timeout /t 3 /nobreak >nul

:: ─────────────────────────────────────────────
:: Health check
:: ─────────────────────────────────────────────
echo.
echo [*] Health check — http://localhost:18080/api/health
curl -sf http://localhost:18080/api/health >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo   [OK] xsiam is UP
) else (
    :: Try default port 8080
    curl -sf http://localhost:8080/api/health >nul 2>&1
    if %ERRORLEVEL% == 0 (
        echo   [OK] xsiam is UP at :8080
    ) else (
        echo   [~~] Health check pending — server may still be starting
    )
)

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║  All services started.                               ║
echo ║  Console : http://localhost:18080                    ║
echo ║  ArangoDB: http://localhost:8529  (root/changeme)    ║
echo ╚══════════════════════════════════════════════════════╝
echo.
goto :end

:error
echo.
echo [!!] Restart aborted due to errors above.
pause
exit /b 1

:end
echo Press any key to close this window...
pause >nul
exit /b 0
