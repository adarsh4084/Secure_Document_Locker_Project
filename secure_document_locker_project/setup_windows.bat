@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
  echo Python Launcher not found. Install Python from https://www.python.org/downloads/ and enable Add Python to PATH.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" py -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo.
echo Setup finished. Double-click run_windows.bat to start Vaultly.
pause
exit /b 0
:fail
echo.
echo Setup failed. Check your internet connection and Python installation.
pause
exit /b 1
