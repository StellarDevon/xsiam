@echo off
setlocal enabledelayedexpansion
set ROOT=%~dp0

:: ensure npm global bin (pnpm) is on PATH
set PATH=%APPDATA%\npm;%PATH%
set WEB=%ROOT%web
set XSIAM=%ROOT%xsiam
set OUT=%XSIAM%\xsiam.exe

echo ============================================================
echo  XSIAM rebuild  %date% %time%
echo ============================================================

:: ---------- 1. frontend ----------
echo.
echo [1/3] Frontend: pnpm build
cd /d "%WEB%"
call pnpm build
if errorlevel 1 (
    echo [FAIL] pnpm build failed
    exit /b 1
)
echo [OK] frontend built

:: ---------- 2. Go compile ----------
echo.
echo [2/3] Go: building xsiam.exe
cd /d "%XSIAM%"
set CGO_ENABLED=0
go build -ldflags="-s -w" -o "%OUT%" ./cmd/xsiam
if errorlevel 1 (
    echo [FAIL] go build failed
    exit /b 1
)
echo [OK] %OUT%

:: ---------- 3. show binary info ----------
echo.
echo [3/3] Binary info
for %%F in ("%OUT%") do echo  Size : %%~zF bytes  /  %%~tF
echo.
echo ============================================================
echo  Done. Run:  xxsiam\xsiam.exe
echo ============================================================
endlocal
