@echo off
setlocal
:: USARE Professional Suite - Maximum Stealth Research Script

:: 1. Check for Admin Privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [PRO] Administrator Privileges Confirmed.
) else (
    echo [ERROR] This script MUST be run in a terminal opened as Administrator.
    echo Right-click PowerShell/CMD -> Run as Administrator.
    pause
    exit /b 1
)

:: 2. Target Configuration
set /p TARGET="Enter Target IP (or hostname): "
if "%TARGET%"=="" set TARGET=scanme.nmap.org

echo.
echo [!] Launching USARE Ghost-Chain...
echo [!] Mode: Maximum Stealth (Morphing + eBPF + LTE + Decoys + Fragments)
echo.

:: 3. The Sneakiest Command Possible:
:: --ebpf       : Dropping RSTs and Randomizing ISNs in the kernel
:: --cold-start : 120s passive sniff to clone your OS fingerprint
:: --lte        : Mimic 4G/LTE mobile latency (stochastic timing)
:: --decoys 10  : High-entropy noise (10 fake IPs for every 1 real packet)
:: --fragment overlap : Confusion-based IP reassembly evasion
:: --jarm       : TLS infrastructure fingerprinting
:: --full       : Full NVD Vulnerability mapping and WAF detection

.\usare -t %TARGET% -p 21,22,25,53,80,110,139,443,445,3306,3389,8080,8443 --full --ebpf --cold-start --lte --decoys 10 --fragment overlap --jarm

pause
endlocal
