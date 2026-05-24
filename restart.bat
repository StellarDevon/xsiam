@echo off
:: Delegate to output\restart.bat — the canonical launcher.
:: Run rebuild.bat first if output\bin\xsiam.exe is missing.
call "%~dp0output\restart.bat"
