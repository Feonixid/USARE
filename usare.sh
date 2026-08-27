#!/usr/bin/env bash
# USARE v2.0 — Ultra-Stealth Adaptive Reconnaissance Engine
# Native Kali Linux Wrapper
# Usage: sudo ./usare.sh -t <TARGET> -p <PORTS> --full

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_PYTHON="$BASE_DIR/.venv/bin/python3"
SCRIPT="$BASE_DIR/usare.py"

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] USARE requires root privileges for raw sockets, eBPF, and promiscuous mode.${NC}"
    echo -e "${CYAN}[*] Re-run with: sudo $0 $*${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Root privileges confirmed.${NC}"

if command -v usare >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Using system-wide USARE package...${NC}"
    usare "$@"
elif [ -f "$VENV_PYTHON" ]; then
    echo -e "${CYAN}[*] Using local virtual environment Python...${NC}"
    "$VENV_PYTHON" "$SCRIPT" "$@"
else
    echo -e "${CYAN}[*] Using system Python3...${NC}"
    python3 "$SCRIPT" "$@"
fi
