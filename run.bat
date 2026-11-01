@echo off
REM Starts Cascade on the default dataset (data folder) and opens the browser.
cd /d "%~dp0"
if exist "venv\Scripts\activate.bat" call "venv\Scripts\activate.bat"
if exist "..\venv\Scripts\activate.bat" call "..\venv\Scripts\activate.bat"
if "%CASCADE_DATA%"=="" set CASCADE_DATA=data
echo Starting Cascade on %CASCADE_DATA% ...  Close this window to stop.
start "" cmd /c "timeout /t 3 >nul & start http://localhost:8000"
python -m uvicorn api:app --app-dir backend --port 8000
pause
