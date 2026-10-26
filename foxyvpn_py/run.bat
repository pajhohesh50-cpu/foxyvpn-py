@echo off
chcp 65001 >nul
cd /d D:\test\foxyvpn-py
echo ============================================
echo   FoxyVPN-py Run
echo ============================================

echo.
echo Select a country:
echo   [1] Germany (DE) - default
echo   [2] United States (US)
echo   [3] United Kingdom (GB)
echo   [4] Japan (JP)
echo   [5] France (FR)
echo   [6] Netherlands (NL)
echo   [7] Canada (CA)
echo   [8] Singapore (SG)
echo.
set /p CHOICE=Enter number [1]: 

if "%CHOICE%"=="" set COUNTRY=DE
if "%CHOICE%"=="1" set COUNTRY=DE
if "%CHOICE%"=="2" set COUNTRY=US
if "%CHOICE%"=="3" set COUNTRY=GB
if "%CHOICE%"=="4" set COUNTRY=JP
if "%CHOICE%"=="5" set COUNTRY=FR
if "%CHOICE%"=="6" set COUNTRY=NL
if "%CHOICE%"=="7" set COUNTRY=CA
if "%CHOICE%"=="8" set COUNTRY=SG

echo.
echo Starting SOCKS5 proxy on 127.0.0.1:1088 for country %COUNTRY%...
echo Press Ctrl+C to stop.
echo.

python -m foxyvpn_py -v run --country %COUNTRY% --listen 127.0.0.1:1088
pause