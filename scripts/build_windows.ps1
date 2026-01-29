param(
    [string]$OutputDir = "dist"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ghost-Sniffer Windows Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

python --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Installing build dependencies..." -ForegroundColor Green
pip install -r requirements.txt
pip install -r requirements-dev.txt

Write-Host "[*] Building executable..." -ForegroundColor Green
$version = (Select-String -Path "ghost_sniffer.py" -Pattern 'TOOL_VERSION\s*=\s*"(.*)"').Matches.Groups[1].Value
if (-not $version) {
    Write-Host "[ERROR] Unable to determine TOOL_VERSION from ghost_sniffer.py" -ForegroundColor Red
    exit 1
}
$exeName = "Ghost-Sniffer-$version"
pyinstaller `
    --onefile `
    --name $exeName `
    --distpath $OutputDir `
    --noconfirm `
    ghost_sniffer.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Build completed. Output: $OutputDir\$exeName.exe" -ForegroundColor Green
