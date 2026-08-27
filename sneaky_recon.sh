#!/usr/bin/env bash
# USARE Professional Suite — Maximum Stealth Research Script (Kali Linux)
# This is the sneakiest configuration possible.

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script MUST be run as root.${NC}"
    echo -e "${CYAN}Usage: sudo $0${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Root privileges confirmed.${NC}"

read -rp "Enter Target IP (or hostname) [Default: scanme.nmap.org]: " TARGET
TARGET="${TARGET:-scanme.nmap.org}"

echo ""
echo -e "${YELLOW}[!] Launching USARE Ghost-Chain...${NC}"
echo -e "${YELLOW}[!] Mode: Maximum Stealth (eBPF + Cold-Start + LTE + Decoys + Overlap Fragments + JARM)${NC}"
echo ""

# The Sneakiest Command:
# --ebpf       : Kernel filter to silently drop RSTs and scramble TCP ISNs
# --cold-start : 120s passive sniff to clone your real OS fingerprint
# --lte        : Mimic 4G/LTE mobile network timing jitter
# --decoys 10  : 10 fake IPs for every 1 real probe
# --fragment overlap : Confusion-based IP fragment reassembly evasion
# --jarm       : TLS infrastructure fingerprinting
# --full       : All recon modules (DNS, OS, Services, WAF, CVE mapping)

"$BASE_DIR/usare.sh" -t "$TARGET" -p 21,22,25,53,80,110,139,443,445,3306,3389,8080,8443 \
    --full \
    --ebpf \
    --cold-start \
    --lte \
    --decoys 10 \
    --fragment overlap \
    --jarm

echo ""
echo -e "${GREEN}[+] Scan finished.${NC}"
