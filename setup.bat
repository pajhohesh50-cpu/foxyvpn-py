@echo off
chcp 65001 >nul
echo ============================================
echo   FoxyVPN-py Setup (First Time Only)
echo ============================================

echo.
echo [1/3] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo [2/3] Installing Playwright Chromium browser...
playwright install chromium
if errorlevel 1 (
    echo Failed to install Chromium. Try running as Administrator.
    pause
    exit /b 1
)

echo.
echo [3/3] Verifying h2 version...
python -c "import h2; print('h2 version:', h2.__version__)" 2>nul

echo.
echo ============================================
echo   Setup complete!
echo   Now run: login.bat (once)
echo ============================================
pause