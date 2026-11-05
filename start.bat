@echo off
REM ==========================================================================
REM  SOC Alert Triage Dashboard - one-click launcher (Windows)
REM  First run: creates the Python venv and installs npm packages.
REM  Then starts the Flask backend and the React frontend in their own
REM  windows and opens the dashboard in your browser.
REM  Close the two server windows to stop the app.
REM ==========================================================================
setlocal
cd /d "%~dp0"

where python >nul 2>&1 || (echo [ERROR] Python not found on PATH. Install Python 3.10+ & pause & exit /b 1)
where npm >nul 2>&1 || (echo [ERROR] Node.js/npm not found on PATH. Install Node 18+ & pause & exit /b 1)

REM --- Backend setup (first run only) ---------------------------------------
if not exist "backend\.venv\Scripts\python.exe" (
    echo [setup] Creating Python virtual environment...
    python -m venv "backend\.venv" || (echo [ERROR] venv creation failed & pause & exit /b 1)
    echo [setup] Installing backend requirements...
    "backend\.venv\Scripts\python.exe" -m pip install -q -r "backend\requirements.txt" || (echo [ERROR] pip install failed & pause & exit /b 1)
)

REM --- Frontend setup (first run only) --------------------------------------
if not exist "frontend\node_modules" (
    echo [setup] Installing frontend packages...
    pushd frontend
    call npm install --no-fund --no-audit || (popd & echo [ERROR] npm install failed & pause & exit /b 1)
    popd
)

REM --- Start servers ----------------------------------------------------------
echo Starting backend on http://127.0.0.1:5000 ...
start "SOC Triage - Backend" /D "%~dp0backend" cmd /k ".venv\Scripts\python.exe app.py"

echo Starting frontend on http://localhost:5173 ...
start "SOC Triage - Frontend" /D "%~dp0frontend" cmd /k "npm run dev"

REM Give Vite a few seconds to come up, then open the dashboard.
ping -n 6 127.0.0.1 >nul
start "" http://localhost:5173

echo.
echo Dashboard opened. Close the "SOC Triage - Backend" and "SOC Triage - Frontend"
echo windows to stop the app.
ping -n 6 127.0.0.1 >nul
endlocal
