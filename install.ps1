# USARE v2.1.0 — Windows Installer
# Sets up the virtual environment and all dependencies via pip.
# Usage: .\install.ps1

$ErrorActionPreference = "Stop"

Write-Host "[*] USARE v2.1.0 — Windows Installer" -ForegroundColor Cyan
Write-Host ""

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Warning: You are not running this script as Administrator." -ForegroundColor Yellow
    Write-Host "    Raw sockets and stealth features require Administrator privileges." -ForegroundColor Yellow
    Write-Host "    You can still install, but scans may fail." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "[1/3] Creating virtual environment (.venv)..." -ForegroundColor Cyan
if (-not (Test-Path ".venv")) {
    python -m venv .venv
} else {
    Write-Host "      .venv already exists, proceeding." -ForegroundColor DarkGray
}

Write-Host "[2/3] Upgrading pip..." -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pip install --upgrade pip -q

Write-Host "[3/3] Installing USARE package and dependencies..." -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pip install . -q

Write-Host ""
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "You can now run USARE using the wrapper scripts in this directory:" -ForegroundColor Cyan
Write-Host "  .\usare.ps1 -t 127.0.0.1 -p 80 --ghost" -ForegroundColor Green
Write-Host "  .\usare.bat -t 127.0.0.1 -p 80 --ghost" -ForegroundColor Green
Write-Host ""
Write-Host "To install USARE globally to your system PATH (so you can run 'usare' from anywhere):" -ForegroundColor Cyan
Write-Host "  pip install ." -ForegroundColor Green
Write-Host ""
