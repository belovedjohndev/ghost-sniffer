@echo off
echo ========================================
echo   Ghost-Sniffer Windows Build
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    exit /b 1
)

echo [*] Installing build dependencies...
pip install -r requirements.txt
pip install -r requirements-dev.txt

echo [*] Building executable...
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Select-String -Path 'ghost_sniffer.py' -Pattern 'TOOL_VERSION\s*=\s*\"(.*)\"').Matches.Groups[1].Value"`) do set GS_VERSION=%%v
if "%GS_VERSION%"=="" (
    echo [ERROR] Unable to determine TOOL_VERSION from ghost_sniffer.py
    exit /b 1
)
set EXE_NAME=Ghost-Sniffer-%GS_VERSION%
pyinstaller --onefile --name "%EXE_NAME%" --distpath dist --noconfirm ghost_sniffer.py

if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)

echo [OK] Build completed. Output: dist\%EXE_NAME%.exe
