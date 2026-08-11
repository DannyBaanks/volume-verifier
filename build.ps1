# build.ps1 - Reproducible build of volume-verifier.exe
#
# Usage:  ./build.ps1
# Output: dist/volume-verifier.exe  (+ prints its SHA-256)
#
# Requires: Python 3.8+, PyInstaller (pip install -r requirements.txt)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path "source/volume_verifier.py")) {
    Write-Error "source/volume_verifier.py not found - run from the repository root."
}

Write-Host "[build] Running PyInstaller..." -ForegroundColor Cyan
$ErrorActionPreference = "Continue"
python -m PyInstaller --onefile --clean --noconfirm `
    --name volume-verifier `
    --distpath dist `
    --workpath build `
    --specpath build `
    source/volume_verifier.py
$ErrorActionPreference = "Stop"

$exe = Join-Path $root "dist/volume-verifier.exe"
if (-not (Test-Path $exe)) {
    Write-Error "Build failed: $exe not produced."
}

$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLower()
Write-Host "[build] OK: $exe" -ForegroundColor Green
Write-Host "[build] SHA256: $hash" -ForegroundColor Green
Write-Host "[build] Verify against the published binary with:"
Write-Host "        Get-FileHash .\volume-verifier.exe -Algorithm SHA256"
