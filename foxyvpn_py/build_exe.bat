@echo off
chcp 65001 >nul
cd /d %~dp0
echo ============================================
echo   FoxyVPN-py EXE Builder
echo ============================================

echo.
echo [1/5] Installing PyInstaller...
pip install pyinstaller
if errorlevel 1 (
    echo Failed to install PyInstaller.
    pause
    exit /b 1
)

echo.
echo [2/5] Installing Playwright Chromium into package (for bundling)...
set PLAYWRIGHT_BROWSERS_PATH=0
playwright install chromium
if errorlevel 1 (
    echo Failed to install Chromium.
    pause
    exit /b 1
)

echo.
echo [3/5] Creating launcher.py...
(
echo import sys
echo from foxyvpn_py.cli import main
echo.
echo if __name__ == "__main__":
echo     sys.exit^(main^(^)^)
) > launcher.py

echo.
echo [4/5] Building EXE with PyInstaller...
pyinstaller -F --name FoxyVPN ^
  --collect-all curl_cffi ^
  --hidden-import=_cffi_backend ^
  --collect-all playwright ^
  launcher.py
if errorlevel 1 (
    echo PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo [5/5] Build complete!
echo.
echo ============================================
echo   EXE created in: dist\FoxyVPN.exe
echo.
echo   IMPORTANT:
echo   1. Copy your tokens.json next to the EXE
echo      (default: C:\Users\%USERNAME%\.foxyvpn-py\tokens.json)
echo   2. The EXE is large (Chromium included)
echo   3. First run may take longer to extract
echo ============================================
pause