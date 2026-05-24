@echo off
:: Delegate to output\start.bat — the canonical auto-restart launcher.
:: Run rebuild.bat first if output\bin\xsiam.exe is missing.
call "%~dp0output\start.bat"
