@echo off
REM Like run_master.bat, but the emulated controller also listens on the network (port 5020),
REM so a second laptop on the same Wi-Fi can run the attack script against it.
REM Windows will ask once whether to allow Python on private networks: allow it.
cd /d "%~dp0"
set CASCADE_DATA=data_master
set CASCADE_LIVE_HOST=0.0.0.0
set CASCADE_LIVE_ALLOW_LAN=1
echo.
echo Attack from the other laptop with:  python attack.py --host YOUR_IP
echo Your IP address (use the one under your Wi-Fi adapter):
ipconfig | findstr /i "IPv4"
echo.
call run.bat
