@echo off
REM Starts Cascade on the 28-system demo district (fallback dataset and performance test).
cd /d "%~dp0"
if not exist "data_district28\assets.csv" python tools\make_demo_district.py
set CASCADE_DATA=data_district28
call run.bat
