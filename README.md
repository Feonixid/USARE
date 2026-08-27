# USARE (Ultimate Stealth And Reconnaissance Engine)

USARE is a specialized network reconnaissance and diagnostics engine engineered for high-fidelity scanning with minimal detection footprint. Unlike legacy port scanners that prioritize raw packet throughput, USARE prioritizes temporal decorrelation, protocol camouflage, adaptive heat management, and kernel-level socket isolation.

---

## 🏛️ Architecture & Component Overview

USARE is organized into four modular layers:

```
┌────────────────────────────────────────────────────────┐
│                        core/                           │
│  CLI, Main Engine Orchestrator, Packet Engine, eBPF    │
└──────────────────────────┬─────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
┌─────────────────┐┌─────────────────┐┌─────────────────┐
│     recon/      ││    evasion/     ││      ops/       │
│ Probes, Banners,││ Timing, Desync, ││ Heat Meter,     │
│ OS Discovery,   ││ Flow Morphing,  ││ Strategy Control│
│ Interference    ││ Multi-Path, JA3 ││ Crypto, Reports │
└─────────────────┘└─────────────────┘└─────────────────┘
```

### 1. `core/` (Orchestration & Low-Level Control)
- **`engine.py`**: Main scan orchestrator managing phases, targets, and result aggregation.
- **`cli.py`**: Rich console interface, argument parser, configuration summaries.
- **`packet_engine.py`**: Raw packet crafting, Windows 10/Linux TCP options emulation, IPID generators.
- **`ebpf_loader.py`**: eBPF TC egress filters to silently drop kernel RST packets.

### 2. `evasion/` (Stealth & Traffic Camouflage)
- **`timing.py`**: Ghost timing profiles (Ghost, Phantom, Shadow, Glacier, Poisson) with micro-jitter and slow corridors.
- **`multi_path_dispersion.py`**: Proxy/VPN/Tor node pool manager with health checks and heat-based balancing.
- **`flow_morph.py`**: Browser flow shaping matching TLS/HTTP traffic distributions.
- **`proto_tunnel.py`**: Encapsulate probes inside genuine HTTPS, DNS, DoH, QUIC, or ICMP traffic.
- **`tcp_desync_split.py` / `tcp_window_probe.py`**: Stateful firewall desynchronization (checksum corruption, TTL expiry).
- **`ttl_masquerading.py`**: Dual-packet and adaptive TTL modulation.

### 3. `recon/` (Active & Contextual Discovery)
- **`syn_scanner.py`**: Core stealth SYN scanner with priority shuffling and adaptive timeout.
- **`contextual_probe.py`**: OS-aware contextual discovery (LLMNR, mDNS, UPnP) preceding SYN probes.
- **`interference_detector.py`**: Sliding-window detector for RST injection, rate limiting, and honeypots.
- **`service_detect.py` / `nmap_service_probes.py`**: Comprehensive service banner extraction and fingerprinting.
- **`os_fingerprint.py`**: Multi-response OS fingerprinting.

### 4. `ops/` (Feedback Control & Reporting)
- **`heat_meter.py`**: Real-time logistic detection probability and burst tracking.
- **`strategy_controller.py`**: Real-time adaptive controller that automatically scales timing and triggers cooldowns on elevated heat.
- **`encryption.py`**: AES-256-GCM / ChaCha20-Poly1305 encrypted scan result storage.
- **`reporting.py`**: Multi-format report generation (HTML, JSON, Markdown).

---

## 🚀 Quick Start

### Installation

```bash
# Clone and enter directory
git clone https://github.com/Feonixid/USARE.git
cd USARE

# Install dependencies
pip install -r requirements.txt
```

### Basic Scan

```bash
# Basic low-and-slow scan against a single target
python usare.py -t 192.168.1.100 -p 80,443,8080
```

### Full Reconnaissance Suite

```bash
# Full discovery with service detection, OS fingerprinting, and DNS analysis
python usare.py -t 192.168.1.100 --full
```

### Advanced Stealth & Evasion Modes

```bash
# Ghost mode with adaptive timing, micro-jitter, and slow corridor
python usare.py -t 192.168.1.100 \
  --ghost \
  --profile adaptive \
  --slow-corridor 2.5 \
  --micro-jitter-ms 50

# Contextual probing with OS hints
python usare.py -t 192.168.1.100 \
  --contextual-probe \
  --contextual-os-hint windows

# Multi-path proxy dispersion
python usare.py -t 192.168.1.100 \
# Protocol tunneling (HTTPS cover traffic with JA3 rotation)
python usare.py -t 192.168.1.100 \
  --tunnel https \
  --ja3-rotation chrome \
  --entropy-balance chrome_tls

# Covert DNS-over-HTTPS resolution with DNSSEC validation
python usare.py -t 192.168.1.100 --dns --doh

# Encrypted session checkpoint & resume
python usare.py -t 192.168.1.100 --resume .usare_session

# Compliance, SIEM, and SBOM reporting
python usare.py -t 192.168.1.100 --full \
  --sarif-export \
  --stix-export \
  --cyclonedx-export
```

---

## 📊 Standards & Export Formats

USARE natively exports structured diagnostic and audit intelligence into industry-standard formats:

| Format | Standard | CLI Flag | Target Consumers |
| :--- | :--- | :--- | :--- |
| **SARIF 2.1.0** | OASIS Static Analysis Results | `--sarif-export` | GitHub Code Scanning, Azure DevOps, CI/CD |
| **STIX 2.1** | OASIS Structured Threat Information | `--stix-export` | OpenCTI, MISP, AlienVault OTX, Enterprise SIEM |
| **CycloneDX 1.5** | OWASP Software Bill of Materials | `--cyclonedx-export` | Dependency-Track, DefectDojo, Snyk, DevSecOps |
| **Nessus XML** | Tenable Nessus v2 XML | `--nessus-export` | Tenable.io, Nessus Professional |
| **Metasploit XML** | Metasploit db_import XML | `--msf-export` | Metasploit Pro / Community Framework |

---

## 🧪 Testing

USARE includes a comprehensive pytest suite with 109 automated tests covering raw packet crafting, timing jitter, strategy control, eBPF/firewall RST suppression, EPSS scoring, DNSSEC audits, and SBOM validation:

```bash
# Run full unit test suite
pytest
```

---

## ⚖️ Legal Disclaimer

USARE is designed exclusively for authorized security diagnostics, auditing, and defensive verification. Users are solely responsible for ensuring compliance with applicable laws and obtaining explicit written permission before scanning any target network or infrastructure.
