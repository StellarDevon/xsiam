@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
title XSIAM — Restart All Services

:: All paths are relative to this file (output/)
set "OUT=%~dp0"
set "OUT=%OUT:~0,-1%"
set "ROOT=%OUT%\.."
set "BIN=%OUT%\bin\xsiam.exe"
set "LOGDIR=%OUT%\logs"
set "STDOUT=%LOGDIR%\xsiam_out.log"
set "STDERR=%LOGDIR%\xsiam_err.log"

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║        XSIAM — Restart All Services                 ║
echo ╚══════════════════════════════════════════════════════╝
echo.

if not exist "%LOGDIR%" mkdir "%LOGDIR%"

:: ── 1. Stop existing processes ────────────────────────────────────────────
echo [1/5] Stopping existing processes...
taskkill /F /IM xsiam.exe        >nul 2>&1 && echo   [OK] xsiam.exe      || echo   [--] not running
taskkill /F /IM ngx_console.exe  >nul 2>&1 && echo   [OK] ngx_console    || echo   [--] not running
taskkill /F /IM redis-server.exe >nul 2>&1 && echo   [OK] Redis          || echo   [--] not running
taskkill /F /IM etcd.exe         >nul 2>&1 && echo   [OK] etcd           || echo   [--] not running
timeout /t 1 /nobreak >nul
echo.

:: ── 2. Start etcd ─────────────────────────────────────────────────────────
echo [2/5] Starting etcd...
set "ETCD=%ROOT%\third_party\tools\etcd-v3.6.11-windows-amd64\etcd-v3.6.11-windows-amd64\etcd.exe"
if exist "%ETCD%" (
    start "etcd" /MIN "%ETCD%" --data-dir "%OUT%\data\etcd"
    timeout /t 2 /nobreak >nul
    echo   [OK] etcd  ^(data: output\data\etcd^)
) else (
    echo   [!!] etcd not found: %ETCD%
)

:: ── 3. Start Redis ────────────────────────────────────────────────────────
echo [3/5] Starting Redis...
set "REDIS=%ROOT%\third_party\tools\redis-8.6.3-windows-x64-msys2-with-service\Redis-8.6.3-Windows-x64-msys2-with-Service\redis-server.exe"
if exist "%REDIS%" (
    start "redis" /MIN "%REDIS%" --dir "%OUT%\data\redis" --save 300 1
    timeout /t 2 /nobreak >nul
    echo   [OK] Redis  ^(data: output\data\redis^)
) else (
    echo   [!!] Redis not found: %REDIS%
)

:: ── 4. Start ArangoDB (Docker) ────────────────────────────────────────────
echo [4/5] Starting ArangoDB...
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
    echo   [~~] Docker not in PATH — start ArangoDB manually
)
timeout /t 3 /nobreak >nul

:: ── 5. Build if binary missing ────────────────────────────────────────────
echo [5/5] Checking binary...
if not exist "%BIN%" (
    echo   [..] bin\xsiam.exe not found — run ..\rebuild.bat first
    goto :error
)
echo   [OK] %BIN%

:: ── Launch xsiam ─────────────────────────────────────────────────────────
echo.
echo [*] Starting xsiam...
:: Run from output/ so config.yaml is found in the working directory
start "xsiam" /MIN cmd /c ^""%BIN%" 1>"%STDOUT%" 2>"%STDERR%"^"
timeout /t 3 /nobreak >nul

:: ── Health check ──────────────────────────────────────────────────────────
echo.
echo [*] Health check...
curl -sf http://localhost:18080/api/health >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo   [OK] xsiam UP at http://localhost:18080
) else (
    echo   [~~] Not responding yet — may still be starting
    echo        stdout: %STDOUT%
    echo        stderr: %STDERR%
)

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║  Console : http://localhost:18080                    ║
echo ║  Internal: http://localhost:18090  ^(loopback only^)  ║
echo ║  ArangoDB: http://localhost:8529   ^(root/changeme^)  ║
echo ║  Logs    : output\logs\                              ║
echo ╚══════════════════════════════════════════════════════╝
echo.
goto :end

:error
echo.
echo [!!] Aborted.
pause
exit /b 1

:end
pause >nul
exit /b 0
