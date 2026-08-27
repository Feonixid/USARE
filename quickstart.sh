#!/bin/bash
# =============================================================================
# USARE Professional Suite - Quickstart Verification Script
# =============================================================================
#
# Builds the isolated Docker environment and launches a "Ghost Scan"
# using all advanced evasion modules against a test target.
#
# USAGE: ./quickstart.sh [TEST_IP]
# =============================================================================

set -e

# Target IP (default to localhost loopback for testing if none provided)
TARGET=${1:-127.0.0.1}

echo -e "\e[1;36m[USARE] Building Docker Environment...\e[0m"
docker build -t usare .

echo -e "\e[1;36m[USARE] Launching Ghost Scan against ${TARGET}...\e[0m"
echo -e "\e[1;33m⚠️  NOTE: Requires root/sudo for NET_RAW and NET_ADMIN capabilities.\e[0m"

# Wait for Docker to generate interface, then optionally cycle MAC (if we had host access, 
# Docker entrypoint usually handles this from inside, but for external script illustration:)
echo -e "\e[1;36m[USARE] Hardware MAC addresses will be randomized by the container's entrypoint.\e[0m"

# Run the container with all advanced flags and Host Network Mode to allow MAC spoofing on real interfaces
docker run --rm -it \
    --network host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --privileged \
    -v $(pwd)/output:/app/output \
    usare \
    --target ${TARGET} \
    -p 22,80,443 \
    --ghost \
    --ebpf \
    --jarm \
    --vuln-map \
    --decoys 5 \
    --json \
    --password "usare_test_123"

echo -e "\e[1;32m[USARE] Scan complete! Check the ./output directory for results.\e[0m"
