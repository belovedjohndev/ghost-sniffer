Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  The Ghost-Sniffer Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    $pythonVersion = python --version 2>&1
    Write-Host "[*] Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.7 or higher from https://www.python.org/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[*] Launching Ghost-Sniffer..." -ForegroundColor Green
Write-Host ""

try {
    python ghost_sniffer.py
} catch {
    Write-Host ""
    Write-Host "[ERROR] Failed to launch Ghost-Sniffer" -ForegroundColor Red
    Write-Host ""
    Write-Host "If you see import errors, try installing dependencies:" -ForegroundColor Yellow
    Write-Host "  pip install scapy" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Note: netifaces is optional and may require C++ build tools on Windows." -ForegroundColor Yellow
    Write-Host "The tool works in demo mode without it." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Read-Host "Press Enter to exit"
