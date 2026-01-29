@echo off
echo ========================================
echo   The Ghost-Sniffer Launcher
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python found
echo [*] Launching Ghost-Sniffer...
echo.

python ghost_sniffer.py

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to launch Ghost-Sniffer
    echo.
    echo If you see import errors, try installing dependencies:
    echo   pip install scapy
    echo.
    echo Note: netifaces is optional and may require C++ build tools on Windows.
    echo The tool works in demo mode without it.
    pause
    exit /b 1
)

pause
