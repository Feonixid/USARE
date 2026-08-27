#!/usr/bin/env bash
# USARE v2.1.0 — Kali Linux Installer
# Sets up the virtual environment and all dependencies via pip.
# Usage: sudo ./install.sh

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo -e "${CYAN}[*] USARE v2.1.0 — Kali Linux Installer${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root: sudo $0${NC}"
    exit 1
fi

echo -e "${CYAN}[1/5] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv libpcap-dev clang llvm libbpf-dev \
    libnetfilter-queue-dev python3-bpfcc bpfcc-tools linux-headers-$(uname -r) 2>/dev/null || true
# Note: linux-headers may fail on some Kali builds; install manually if needed

echo -e "${CYAN}[2/5] Creating virtual environment...${NC}"
if [ ! -d "$BASE_DIR/.venv" ]; then
    python3 -m venv "$BASE_DIR/.venv"
fi

echo -e "${CYAN}[3/5] Upgrading pip...${NC}"
"$BASE_DIR/.venv/bin/pip3" install --upgrade pip -q

echo -e "${CYAN}[4/5] Installing USARE package and dependencies...${NC}"
"$BASE_DIR/.venv/bin/pip3" install "$BASE_DIR" -q

echo -e "${CYAN}[5/5] Setting executable permissions on wrapper scripts...${NC}"
chmod +x "$BASE_DIR/usare.sh"
chmod +x "$BASE_DIR/sneaky_recon.sh"
chmod +x "$BASE_DIR/quickstart.sh"

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo -e "${CYAN}You can now run USARE using the wrapper script:${NC}"
echo -e "  ${GREEN}sudo ./usare.sh -t <TARGET> -p 1-1000 --full${NC}"
echo ""
echo -e "${CYAN}To install USARE globally to your system PATH (so you can run 'usare' from anywhere):${NC}"
echo -e "  ${GREEN}sudo pip3 install .${NC}"
echo ""
echo -e "${CYAN}Or use the maximum stealth script:${NC}"
echo -e "  ${GREEN}sudo ./sneaky_recon.sh${NC}"
