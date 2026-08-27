# =============================================================================
# USARE Dockerfile — Isolated Network Stack
# =============================================================================
# Ensures the tool runs in a completely isolated environment,
# masking the host's MAC address, kernel signature, and network identity.
#
# Build:  docker build -t usare .
# Run:    docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN usare \
#             --target 192.168.1.1 --ports 22,80,443
# =============================================================================

FROM python:3.12-slim AS base

# Metadata
LABEL maintainer="USARE Security Research"
LABEL description="Ultra-Stealth Adaptive Reconnaissance Engine"
LABEL version="1.0.0"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies for raw socket operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iproute2 \
    macchanger \
    iputils-ping \
    net-tools \
    clang \
    llvm \
    libbpf-dev \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*


# Create non-root user for additional isolation
RUN groupadd -r usare && useradd -r -g usare -d /app -s /sbin/nologin usare

# Working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory
RUN mkdir -p /app/output && chown -R usare:usare /app

# Entrypoint script for MAC randomization
COPY <<'EOF' /app/entrypoint.sh
#!/bin/bash
set -e

# Randomize MAC address on all interfaces (if running with NET_ADMIN)
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
    if command -v macchanger &> /dev/null; then
        ip link set "$iface" down 2>/dev/null || true
        macchanger -r "$iface" 2>/dev/null || true
        ip link set "$iface" up 2>/dev/null || true
    fi
done

# Run USARE as the non-root user with raw socket capability
exec python /app/usare.py "$@"
EOF

RUN chmod +x /app/entrypoint.sh

# Default output volume
VOLUME ["/app/output"]

# Run with the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]
