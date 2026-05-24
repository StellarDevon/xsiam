@echo off
setlocal enabledelayedexpansion
set ROOT=%~dp0
set ROOT=%ROOT:~0,-1%

set PATH=%APPDATA%\npm;%PATH%
set WEB=%ROOT%\web
set XSIAM=%ROOT%\xsiam
set OUTDIR=%ROOT%\output\bin
set LOGDIR=%ROOT%\output\logs
set OUT=%OUTDIR%\xsiam.exe

echo ============================================================
echo  XSIAM rebuild  %date% %time%
echo ============================================================

if not exist "%OUTDIR%" mkdir "%OUTDIR%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

:: ── 1. Frontend clean ─────────────────────────────────────────────────────
echo.
echo [1/4] Frontend: clean
cd /d "%WEB%"
if exist "dist" (
    rmdir /s /q dist
    echo   [OK] web\dist\ removed
) else (
    echo   [--] web\dist\ not present
)
:: Also clean xsiam/dist (the embedded copy)
if exist "%XSIAM%\dist" (
    rmdir /s /q "%XSIAM%\dist"
    echo   [OK] xsiam\dist\ removed
)
:: TypeScript incremental build cache
if exist "tsconfig.tsbuildinfo" del /f /q tsconfig.tsbuildinfo
if exist "tsconfig.app.tsbuildinfo" del /f /q tsconfig.app.tsbuildinfo

:: ── 2. Frontend build ─────────────────────────────────────────────────────
echo.
echo [2/4] Frontend: pnpm build
call pnpm build
if errorlevel 1 (
    echo [FAIL] pnpm build failed
    exit /b 1
)
echo   [OK] frontend built  →  xsiam\dist\

:: ── 3. Go binary ──────────────────────────────────────────────────────────
echo.
echo [3/4] Go: build xsiam.exe
cd /d "%XSIAM%"
set CGO_ENABLED=0
go build -ldflags="-s -w" -o "%OUT%" ./cmd/xsiam
if errorlevel 1 (
    echo [FAIL] go build failed
    exit /b 1
)
echo   [OK] %OUT%

:: ── 4. Go: seed tool ──────────────────────────────────────────────────────
echo.
echo [4/4] Go: build seed.exe
go build -ldflags="-s -w" -o "%OUTDIR%\seed.exe" ./cmd/seed
if errorlevel 1 (
    echo   [WARN] seed build failed ^(non-fatal^)
) else (
    echo   [OK] %OUTDIR%\seed.exe
)

:: ── Summary ───────────────────────────────────────────────────────────────
echo.
for %%F in ("%OUT%") do echo  xsiam.exe  %%~zF bytes  %%~tF
echo.
echo ============================================================
echo  Done. Use output\restart.bat or output\start.bat to run.
echo ============================================================
endlocal
