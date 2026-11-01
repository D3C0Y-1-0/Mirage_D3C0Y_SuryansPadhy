@echo off
REM Runs the live attack against the emulated controller. Start Cascade first (run_master.bat).
cd /d "%~dp0"
python tools\live\attack.py %*
if errorlevel 9009 py tools\live\attack.py %*
pause
