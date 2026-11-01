@echo off
REM Starts Cascade on the SENTINEL master city (33 systems, six sectors, real CVEs).
cd /d "%~dp0"
set CASCADE_DATA=data_master
call run.bat
