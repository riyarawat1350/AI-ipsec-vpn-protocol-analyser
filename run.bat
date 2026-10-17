@echo off
REM ============================================================
REM  IPsecScope — One-Click Run Script
REM  Starts Backend (FastAPI) + Frontend (Vite) together
REM ============================================================

title IPsecScope Launcher
color 0A

echo.
echo  ==========================================
echo   AI-Powered IPsec VPN Analyser
echo   IPsecScope — Local Development Server
echo  ==========================================
echo.

REM ── Check if .env exists ──────────────────────────────────
if not exist ".env" (
    echo [WARN] .env not found. Copying from .env.example...
    copy ".env.example" ".env" >nul
    echo [INFO] Please edit .env and set your MONGODB_URL before running again.
    pause
    exit /b 1
)

REM ── Check Python venv ─────────────────────────────────────
if not exist "venv\Scripts\activate.bat" (
    echo [INFO] Creating Python virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Make sure Python 3.11+ is installed.
        pause
        exit /b 1
    )
)

REM ── Install backend dependencies if needed ────────────────
echo [1/4] Installing backend dependencies...
call venv\Scripts\pip install -q -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed. Check requirements.txt.
    pause
    exit /b 1
)
echo       Done.

REM ── Install frontend dependencies if needed ───────────────
echo [2/4] Installing frontend dependencies...
if not exist "frontend\node_modules" (
    cd frontend
    call npm install --silent
    cd ..
)
echo       Done.

REM ── Start Backend in a new window ────────────────────────
echo [3/4] Starting FastAPI backend on http://localhost:8000 ...
start "IPsecScope Backend" cmd /k "call venv\Scripts\activate.bat && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload"

REM ── Wait a moment for backend to initialise ───────────────
timeout /t 3 /nobreak >nul

REM ── Start Frontend in a new window ───────────────────────
echo [4/4] Starting Vite frontend on http://localhost:5173 ...
start "IPsecScope Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo  ==========================================
echo   Both servers are starting in new windows.
echo.
echo   Backend  : http://localhost:8000
echo   API Docs : http://localhost:8000/docs
echo   Frontend : http://localhost:5173
echo.
echo   Press any key to open the app in browser.
echo  ==========================================
echo.
pause >nul

start http://localhost:5173

exit /b 0
