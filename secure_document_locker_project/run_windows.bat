@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo First run setup_windows.bat to create the Python environment.
  pause
  exit /b 1
)
.venv\Scripts\python.exe -c "import flask, cryptography" >nul 2>&1
if errorlevel 1 (
  echo Installing required packages...
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 goto fail
)
echo Starting Vaultly at http://127.0.0.1:5000
.venv\Scripts\python.exe app.py
pause
exit /b 0
:fail
echo Dependency installation failed. Check your internet connection.
pause
exit /b 1
