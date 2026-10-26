@echo off
chcp 65001 >nul
cd /d D:\test\foxyvpn-py
echo ============================================
echo   FoxyVPN-py Login (First Time Only)
echo ============================================

echo.
echo This will open a browser to solve the Fastly challenge.
echo If a CAPTCHA appears, enter it in the terminal when prompted.
echo.

python -m foxyvpn_py login
if errorlevel 1 (
    echo.
    echo Login failed. Please check the error above.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Login successful! Tokens saved.
echo   You can now run: run.bat
echo ============================================
pause