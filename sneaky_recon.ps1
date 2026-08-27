# USARE Professional Suite - Maximum Stealth Research Script (PowerShell)

# 1. Check for Admin Privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script MUST be run in a terminal opened as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator."
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "[PRO] Administrator Privileges Confirmed." -ForegroundColor Green

# 2. Target Configuration
$Target = Read-Host "Enter Target IP (or hostname) [Default: scanme.nmap.org]"
if ([string]::IsNullOrWhiteSpace($Target)) { $Target = "scanme.nmap.org" }

Write-Host "`n[!] Launching USARE Ghost-Chain..." -ForegroundColor Cyan
Write-Host "[!] Mode: Maximum Stealth (Morphing + eBPF + LTE + Decoys + Fragments)"

# 3. Execution
# Parameters Explained:
# -full       : All recon modules (DNS, OS, Services, WAF, CVE mapping)
# -ebpf       : Kernel filter to drop RSTs and randomize ISNs
# -cold-start : 120s passive sniff to clone organic host profiles
# -lte        : Mimic 4G/LTE mobile network timing jitter
# -decoys 10  : High-entropy spoofing (10 false IPs per 1 real packet)
# -fragment overlap : Evasion via malformed/overlapping IP fragments
# -jarm       : TLS fingerprinting

.\usare -t $Target -p 21,22,25,53,80,110,139,443,445,3306,3389,8080,8443 --full --ebpf --cold-start --lte --decoys 10 --fragment overlap --jarm

Read-Host "`nScan Finished. Press Enter to close."
