import os
import sys
import json
import time
import signal
import logging
import argparse
import random
from getpass import getpass
from rich.console import Console # type: ignore
from rich.panel import Panel # type: ignore
from rich.table import Table # type: ignore
from rich.text import Text # type: ignore
from rich.progress import Progress, SpinnerColumn, TextColumn # type: ignore
from rich import box 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.packet_engine import PacketEngine # type: ignore
from evasion.timing import GhostTimer, TimingConfig, TimingProfile # type: ignore
from evasion.fragmentation import FragmentationEngine # type: ignore
from evasion.decoys import DecoyEngine # type: ignore
from evasion.port_shuffle import shuffle_ports, shuffle_ports_prioritized # type: ignore
from evasion.session import SessionTracker # type: ignore
from recon.syn_scanner import StealthScanner, ScanConfig, PortState # type: ignore
from recon.banner_grab import BannerGrabber # type: ignore
from recon.waf_bypass import WAFBypass # type: ignore
from recon.os_fingerprint import OSFingerprintEngine # type: ignore
from recon.service_detect import ServiceDetector # type: ignore
from recon.dns_recon import DNSReconEngine # type: ignore
from recon.host_discovery import HostDiscovery # type: ignore
from recon.cold_start import ColdStartSniffer # type: ignore
from recon.traceroute import StealthTraceroute # type: ignore
from recon.vuln_mapping import VulnerabilityMapper # type: ignore
from recon.jarm_fingerprint import JARMFingerprinter # type: ignore
from core.ebpf_loader import EBPFLoader # type: ignore
from ops.encryption import Encryptor, load_encrypted # type: ignore
from ops.heat_meter import HeatMeter # type: ignore
from ops.reporting import ReportEngine # type: ignore
from evasion.proxy_layer import ProxyManager # type: ignore
from recon.http_title import HTTPTitleGrabber # type: ignore
from recon.whois_lookup import WHOISLookup # type: ignore
from evasion.source_port_masq import SourcePortMasquerader # type: ignore
from evasion.flow_morph import FlowShaper, BrowserFlowMorpher, FlowType # type: ignore
from evasion.proto_tunnel import HTTPSTunnel, DNSTunnel # type: ignore
from evasion.distributed import DistributedCoordinator # type: ignore
from evasion.baseline_poison import BaselinePoisoner, PoisonConfig # type: ignore

from rich.progress import BarColumn, TaskProgressColumn, TimeRemainingColumn # type: ignore
if sys.platform.startswith("win"):
    getattr(sys.stdout, "reconfigure")(encoding="utf-8")
    getattr(sys.stderr, "reconfigure")(encoding="utf-8")

console = Console(force_terminal=True)

def _make_banner():
    from core.entry import __version__
    return f"""
[bold cyan]
██╗   ██╗███████╗ █████╗ ██████╗ ███████╗
██║   ██║██╔════╝██╔══██╗██╔══██╗██╔════╝
██║   ██║███████╗███████║██████╔╝█████╗  
██║   ██║╚════██║██╔══██║██╔══██╗██╔══╝  
╚██████╔╝███████║██║  ██║██║  ██║███████╗
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
[/bold cyan]
[bold white]Ultra-Stealth Adaptive Reconnaissance Engine v{__version__}[/bold white]
[dim]Zero-Footprint · Next-Gen Intelligence · Enterprise Evasion[/dim]
"""

BANNER = _make_banner()

def parse_args():
    from core.entry import __version__
    parser = argparse.ArgumentParser(
        description=f"USARE v{__version__} — Ultra-Stealth Adaptive Reconnaissance Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="LEGAL: Authorized security testing ONLY.",
    )
    parser.add_argument("--version", "-V", action="version",
                        version=f"USARE v{__version__}")
    tgt = parser.add_argument_group("Target")
    tgt.add_argument("--target", "-t", help="Target IP address")
    tgt.add_argument("--ports", "-p", default="1-1024",
                     help="Port spec (default: 1-1024)")
    st = parser.add_argument_group("Stealth & Evasion")
    st.add_argument("--ghost", "-g", action="store_true", default=True,
                    help="Enable Ghost Mode (default: on)")
    st.add_argument("--no-ghost", action="store_true",
                    help="Disable Ghost Mode (fast but noisy)")
    st.add_argument("--profile", choices=["ghost","phantom","shadow","glacier","adaptive","poisson"],
                    default="ghost",
                    help="Timing: ghost, phantom, shadow, glacier, adaptive, poisson (exponential inter-arrival)")
    st.add_argument("--slow-corridor", type=float, default=0.0, metavar="SEC",
                    help="Extra uniform 0..SEC seconds after each ghost delay (low-and-slow)")
    st.add_argument("--micro-jitter-ms", type=float, default=0.0, metavar="MS",
                    help="Extra uniform 0..MS milliseconds after ghost delay (breaks fixed cadence)")
    st.add_argument("--fragment", "-f",
                    choices=["none","standard","ttl","overlap","reverse"],
                    default="standard", help="Fragmentation strategy")
    st.add_argument("--decoys", "-d", type=int, default=5,
                    help="Decoy count per probe (default: 5)")
    st.add_argument("--no-decoys", action="store_true")
    rc = parser.add_argument_group("Reconnaissance")
    rc.add_argument("--full", action="store_true",
                    help="Full recon: OS, service, scripts, banner, DNS, traceroute, vuln, JARM, cert-intel")
    rc.add_argument("--discovery", action="store_true",
                    help="Host discovery before scanning")
    rc.add_argument("--os-detect", action="store_true", default=True,
                    help="Passive OS fingerprinting (default: on)")
    rc.add_argument("--service-detect", "-sV", action="store_true",
                    help="Service/version detection on open ports")
    rc.add_argument("--banner", "-b", action="store_true",
                    help="Adaptive banner grabbing")
    rc.add_argument("--banner-delay", type=float, default=600.0,
                    help="Banner grab delay (default: 600s)")
    rc.add_argument("--dns", action="store_true",
                    help="DNS reconnaissance")
    rc.add_argument("--traceroute", action="store_true",
                    help="TCP SYN stealth traceroute")
    rc.add_argument("--ack", action="store_true",
                    help="ACK scan for firewall mapping")
    rc.add_argument("--xmas", action="store_true",
                    help="XMAS/NULL confirmation scan")
    rc.add_argument("--udp", "-sU", action="store_true",
                    help="UDP stealth scan utilizing ICMP unreachables")
    rc.add_argument("--sctp", "-sY", action="store_true",
                    help="SCTP INIT scan to bypass TCP/UDP IDS signatures")
    rc.add_argument("--waf-detect", action="store_true",
                    help="WAF/বেদন detection")
    rc.add_argument("--vuln", action="store_true",
                    help="Map discovered services to CVEs and CISA KEV")
    rc.add_argument("--script", "-sC", action="store_true",
                    help="Run default USARE (NSE equivalent) scripts against targets")
    rc.add_argument("--reason", action="store_true",
                    help="Show reason why each port has its state (syn-ack, rst, no-response)")
    rc.add_argument("--cheatsheet", action="store_true",
                    help="Print quick reference and exit")
    rc.add_argument("--greppable", action="store_true",
                    help="Print machine-readable summary line at end")
    rc.add_argument("--ebgp", action="store_true",
                    help="Real eBGP peering with public route collectors for topology intelligence")
    rc.add_argument("--ebgp-collector", metavar="IP",
                    help="Custom BGP route collector IP (default: RIPE RIS/RouteViews)")
    rc.add_argument("--ebgp-asn", type=int, default=65000,
                    help="Local ASN for eBGP peering (default: 65000)")
    rc.add_argument("--ai-analyst", action="store_true",
                    help="Run AI post-scan analyst via local Ollama LLM")

    advanced_group = parser.add_argument_group("Engine")
    advanced_group.add_argument("--ebpf", action="store_true", help="Load eBPF/XDP filter to drop outgoing TCP RSTs (requires root)")
    advanced_group.add_argument("--ipv6", action="store_true", help="Use IPv6 (and extension headers for fragmentation) instead of IPv4")
    advanced_group.add_argument("--proxy", metavar="PROXY", help="Route traffic through SOCKS5 proxy (e.g., socks5://127.0.0.1:9050)")
    advanced_group.add_argument("--jarm", action="store_true", help="Perform JARM fingerprinting to identify backend infra")
    advanced_group.add_argument("--lte", action="store_true", help="Use the 4G/LTE mobile high-latency profile")
    advanced_group.add_argument("--cold-start", action="store_true", help="Passively sniff background traffic to perfectly clone OS TTL and Window sizes")
    advanced_group.add_argument("--desync", action="store_true", help="Inject 3-packet TCP bursts with corrupted checksums to blind Stateful Firewalls")
    advanced_group.add_argument("--overlap", action="store", choices=["windows", "linux"], help="Execute TCP Fragmentation overlaps targeting specific OS reassembly biases to evade deep packet inspection")
    advanced_group.add_argument("--sni-smuggle", action="store_true", help="Attempt TLS SNI Smuggling/Domain Fronting to bypass DPI")
    advanced_group.add_argument("--icmp-quote", action="store_true", help="Hunt for internal NAT/Firewall routing leakage via ICMP Error Quoting")
    advanced_group.add_argument("--clock-skew", action="store_true", help="Analyze TCP timestamp clock skew to fingerprint OS, estimate uptime, and detect VMs")
    advanced_group.add_argument("--oob", action="store_true", help="Reverse/OOB channel emulation to map egress filtering posture")
    advanced_group.add_argument("--idle", "-sI", action="store_true", help="Zero-attribution idle scan via zombie host (no packets from your IP reach the target)")
    advanced_group.add_argument("--zombie-ip", metavar="IP", help="Manual zombie IP for idle scan (skip auto-discovery)")
    advanced_group.add_argument("--zombie-subnet", metavar="SUBNET", help="Subnet to discover zombies from (e.g., 192.168.1.0)")
    advanced_group.add_argument("--acl-map", action="store_true", help="Infer firewall ACL rules via differential TCP flag probing (SYN/ACK/FIN/XMAS/NULL)")
    advanced_group.add_argument("--crypto-fp", action="store_true", help="Deep SSH/TLS negotiation fingerprinting beyond JA3/JARM")
    advanced_group.add_argument("--app-probe", action="store_true", help="Application protocol deep probes (Redis, MongoDB, Elasticsearch, Docker, K8s)")
    advanced_group.add_argument("--correlate", action="store_true", help="Cross-reference all signals for unified OS/infrastructure intelligence")
    advanced_group.add_argument("--anti-forensics", action="store_true", help="Enable anti-forensics mode (sanitize logs, randomize timestamps, secure delete)")
    advanced_group.add_argument("--ai-learn", action="store_true", help="Enable AI active learning (response patterns, IDS evasion, timing optimization)")
    advanced_group.add_argument("--ollama", action="store_true", help="Use local Ollama LLM for AI-driven evasion strategy selection")
    advanced_group.add_argument("--ollama-model", metavar="MODEL", help="Specific Ollama model to use (auto-selects if omitted)")
    advanced_group.add_argument("--temporal", action="store_true", help="Enable temporal timing (find peak-noise windows, circadian profiling)")
    advanced_group.add_argument("--intel-graph", action="store_true", help="Build unified intelligence graph (pivot-chain discovery)")
    advanced_group.add_argument("--passive", type=float, metavar="SECONDS", nargs="?", const=120.0, help="Zero-packet passive recon via ARP/mDNS/NetBIOS/LLMNR/SSDP (default: 120s)")
    advanced_group.add_argument("--split-handshake", action="store_true", help="TCP split handshake scan (bypasses Cisco ASA / Palo Alto stateful FW)")
    advanced_group.add_argument("--ipv6-ext", type=int, metavar="DEPTH", nargs="?", const=4, help="IPv6 extension header chain stuffing (default depth: 4)")
    advanced_group.add_argument("--tls-0rtt", action="store_true", help="TLS 1.3 0-RTT early data probing")
    advanced_group.add_argument("--ct-scan", action="store_true", help="Certificate Transparency log scraping (passive subdomain discovery)")
    advanced_group.add_argument("--modern-detect", action="store_true", help="Detect gRPC, GraphQL, K8s API, WebSocket services")
    advanced_group.add_argument("--h2-multiplex", action="store_true", help="HTTP/2 multiplexed stream probing (50+ probes per connection)")
    out = parser.add_argument_group("Output & Encryption")
    out.add_argument("--output", "-o", default="usare_results.enc",
                     help="Encrypted output file")
    out.add_argument("--password", help="Encryption password")
    out.add_argument("--json", dest="json_output", action="store_true",
                     help="Also output plaintext JSON (debug)")
    out.add_argument("--format", choices=["json", "csv", "html", "xml"],
                     help="Export results to logs/ directory in specified format")
    dec = parser.add_argument_group("Decrypt")
    dec.add_argument("--decrypt", metavar="FILE",
                     help="Decrypt a results file")
    adv = parser.add_argument_group("Advanced")
    adv.add_argument("--timeout", type=float, default=3.0)
    adv.add_argument("--retries", type=int, default=3,
                     help="Max retransmissions per port (default: 3)")
    adv.add_argument("--interface", "-i", help="Network interface")
    adv.add_argument("--chunk-size", type=int, default=50)
    adv.add_argument("--verbose", "-v", action="store_true", default=False,
                     help="Maximum verbosity (default: OFF, use -v to enable)")
    adv.add_argument("--top-ports", type=int, metavar="N",
                     help="Scan the top N most common ports")
    adv.add_argument("--quiet", "-q", action="store_true",
                     help="Suppress Rich UI, output machine-readable JSON")
    adv.add_argument("--diff", metavar="FILE",
                     help="Compare results against a previous encrypted scan")
    adv.add_argument("--diff-only", metavar="FILE", nargs=2,
                     help="Compare two encrypted scan files without scanning (FILE_A FILE_B)")
    adv.add_argument("--resume", action="store_true",
                     help="Resume an interrupted scan from .usare_session")
    adv.add_argument("--source-masq", action="store_true",
                     help="Use source port mimicry (53/443/123) to bypass firewalls")
    adv.add_argument("--tunnel", choices=["https", "dns", "doh", "quic", "icmp"],
                     help="Encapsulate probes: https, dns, doh, quic, icmp")
    adv.add_argument("--distributed", metavar="NODES_JSON",
                     help="Distribute scan across multiple nodes (JSON config)")
    adv.add_argument("--baseline", type=float, metavar="MINUTES",
                     help="Generate baseline traffic for N minutes before scanning")
    adv.add_argument("--flow-morph", choices=["chrome", "firefox", "curl", "winupdate"],
                     help="Wrap probes in browser-like flow patterns")
    # Advanced reconnaissance features
    adv.add_argument("--timestamp-analysis", action="store_true",
                     help="Analyze TCP timestamp clock skew for precise OS fingerprinting")
    adv.add_argument("--cert-intel", action="store_true",
                     help="Extract intelligence from TLS certificates and CT logs")
    adv.add_argument("--ipid-analysis", action="store_true",
                     help="Analyze IP ID sequences to find idle scan zombies")
    adv.add_argument("--banner-mutation", action="store_true",
                     help="Detect banner mutations for load balancer/WAF analysis")
    adv.add_argument("--mutation-delay", type=int, default=30,
                     help="Delay between banner grabs for mutation analysis (default: 30s)")
    adv.add_argument("--hpack-analysis", action="store_true",
                     help="HTTP/2 HPACK fingerprinting for backend detection")
    adv.add_argument("--consistency-analysis", action="store_true",
                     help="TTL/IPID consistency analysis for infrastructure topology")
    # Advanced Evasion Techniques
    adv.add_argument("--urgent-pointer", action="store_true",
                     help="TCP urgent pointer steganography for covert channel analysis")
    adv.add_argument("--ip-options", action="store_true",
                     help="IP options fingerprinting for firewall and infrastructure analysis")
    adv.add_argument("--window-probe", action="store_true",
                     help="TCP window size probing for OS fingerprinting")
    adv.add_argument("--protocol-confusion", action="store_true",
                     help="Protocol confusion techniques for service fingerprinting")
    adv.add_argument("--ipv6-tunnel", action="store_true",
                     help="IPv4-in-IPv6 tunneling for bypass detection")
    # Advanced Intelligence Gathering
    adv.add_argument("--bgp-intel", action="store_true",
                     help="BGP community intelligence for passive network topology mapping")
    adv.add_argument("--pdns-timeline", action="store_true",
                     help="Passive DNS timeline analysis for infrastructure change reconstruction")
    adv.add_argument("--tls-mapper", action="store_true",
                     help="TLS session ticket analysis for load balancer pool mapping")
    adv.add_argument("--ipmi-probe", action="store_true",
                     help="IPMI out-of-band management discovery")
    adv.add_argument("--ntp-intel", action="store_true",
                     help="NTP intelligence fingerprinting for network topology analysis")
    adv.add_argument("--snmp-infer", action="store_true",
                     help="SNMP community string inference and network device discovery")
    adv.add_argument("--cloud-intel", action="store_true",
                     help="Cloud provider metadata API fingerprinting")
    adv.add_argument("--protocol-downgrade", action="store_true",
                     help="Protocol downgrade and weak configuration enumeration")
    adv.add_argument("--rfc-compliance", action="store_true",
                     help="RFC compliance protocol fingerprinting for exact version detection")
    # New Advanced Intelligence Techniques
    adv.add_argument("--http2-push", action="store_true",
                     help="HTTP/2 push promise abuse for server implementation fingerprinting")
    adv.add_argument("--cert-pinning", action="store_true",
                     help="TLS certificate pinning detection for security maturity assessment")
    adv.add_argument("--quic-version", action="store_true",
                     help="QUIC version negotiation probing for server library fingerprinting")
    adv.add_argument("--tcp-desync", action="store_true",
                     help="TCP desync via split-handshake for stateful firewall bypass")
    adv.add_argument("--http-timing", action="store_true",
                     help="HTTP timing side channel for server processing path analysis")
                     
    # Phase 30: Advanced Protocol Evasion
    adv.add_argument("--quic-churn", action="store_true",
                     help="QUIC Connection ID (CID) churning to exhaust UDP flow trackers")
    adv.add_argument("--ipv6-scramble", action="store_true",
                     help="Randomize IPv6 Flow Labels to bust hardware firewalls")
    adv.add_argument("--tcp-dup-ack", action="store_true",
                     help="TCP Duplicate ACK injection (Fast-Retransmit Spoofing) evasion")
    adv.add_argument("--pmtu-blackhole", action="store_true",
                     help="Path MTU Discovery Blackholing to map invisible middleboxes")
                     
    # Phase 32: Application Layer (L7) Evasion
    adv.add_argument("--rst-block", action="store_true", help="Use iptables to drop outgoing TCP RSTs (Linux only, blocks local snitching)")
    adv.add_argument("--alpn-smuggle", action="store_true", help="ALPN Protocol Smuggling (negotiate h2, send http/1.1)")
    adv.add_argument("--h2-smuggle", action="store_true", help="HTTP/2 Request Smuggling (H2.TE desync)")
    adv.add_argument("--wss-tunnel", action="store_true", help="Encapsulate probes in a persistent WebSocket tunnel")

    # Phase 34: ZTNA Evasion Capstone
    adv.add_argument("--ztna-evasion", action="store_true", help="Detect and attempt to bypass Zero-Trust Network Access (Cloudflare Access, Google IAP)")
    adv.add_argument("--ebpf-stealth", action="store_true", help="[ULTIMATE STEALTH] eBPF XDP Rootkit to silently swallow outgoing RSTs at Driver Level")

    # Newly Integrated Advanced Run-Time Techniques (Recon & Evasion)
    adv.add_argument("--contextual-probe", action="store_true",
                     help="Use OS-specific contextual probes (LLMNR, mDNS, UPnP) before SYN scanning")
    adv.add_argument("--entropy-balance", choices=["chrome_tls", "firefox_tls", "http_traffic", "dns_query"],
                     help="Balance payload entropy; with --flow-morph, shapes cover-traffic payloads; still runs post-scan analysis")
    adv.add_argument("--ja3-rotation", choices=["chrome", "firefox", "safari", "edge"],
                     help="Rotate JA3 TLS ClientHello fingerprint; with --tunnel https, applies to tunnel TLS handshakes")
    adv.add_argument("--ttl-masquerade", choices=["ids_only", "target_only", "dual_packet", "adaptive"],
                     help="Masquerade TTL distances to evade or confuse IDS/IPS systems")
    adv.add_argument("--multi-path", metavar="CONFIG_JSON",
                     help="Distribute traffic across multiple VPN/Proxy/Tor nodes for heat dispersion")
    adv.add_argument("--desync-mode",
                     choices=["checksum", "ttl-expiry", "state-exhaust", "data-inject", "adaptive"],
                     default="adaptive",
                     help="TCP desync variant (default: adaptive)")
    adv.add_argument("--zombie-port", type=int, default=80, metavar="PORT",
                     help="Port to probe zombie host on for idle scan (default: 80)")
    adv.add_argument("--data-length", type=int, default=0, metavar="BYTES",
                     help="Append N random bytes to every probe packet (defeats packet-size IDS signatures)")
    adv.add_argument("--packet-size-profile",
                     choices=["chrome_tls", "firefox_http", "enterprise_mix", "minimal", "uniform"],
                     help="Stochastic payload sizes from traffic profile (overrides fixed --data-length)")
    adv.add_argument("--spoof-mac",
                     metavar="MODE_OR_MAC",
                     help="Spoof Ethernet source MAC. Values: 'random', 'vendor:dell', 'vendor:cisco', "
                          "or an explicit MAC like 'de:ad:be:ef:ca:fe'. "
                          "Only affects local L2 segment (irrelevant once traffic crosses a router).")
    adv.add_argument("--mac-persist", action="store_true",
                     help="Apply --spoof-mac at OS interface level (all traffic spoofed, reverts on exit)")
    adv.add_argument("--ip-proto-scan", action="store_true",
                     help="IP Protocol scan: iterate all 256 IP protocol numbers to find non-TCP/UDP services (GRE, OSPF, ESP...)")
    adv.add_argument("--osscan-guess", action="store_true",
                     help="Fuzzy OS matching: return top-3 closest guesses even when confidence is low")
    adv.add_argument("--version-intensity", type=int, default=5, choices=range(0, 10), metavar="0-9",
                     help="Service version probe intensity (0=fastest/fewest probes, 9=exhaustive, default: 5)")
    adv.add_argument("--script-args", metavar="KEY=VAL,...",
                     help="Arguments to pass to NSE-like script plugins (e.g. http.ua=Firefox,brute.first=true)")
    adv.add_argument("--nvd-api-key", metavar="KEY",
                     help="NVD API key for higher rate limits on vuln mapping (50 req/30s vs 5)")
    adv.add_argument("--output-dir", default="logs", metavar="DIR",
                     help="Directory for all exported reports (JSON/CSV/HTML/XML, default: logs/)")
    adv.add_argument("--module-timeout", type=float, default=0.0, metavar="SECONDS",
                     help="Timeout for post-scan modules (banner grab, cert intel, etc). Defaults to 3x --timeout")

    # New capability flags
    adv.add_argument("--ipv6-discover", action="store_true",
                     help="IPv6 host discovery via ICMPv6, multicast ping, and NDP (complements IPv4 discovery)")
    adv.add_argument("--ipv6-transition", action="store_true",
                     help="Probe for 6to4, Teredo, ISATAP transition mechanisms")
    adv.add_argument("--banner-timing", action="store_true",
                     help="Per-chunk timing fingerprint during banner grab (side-channel)")
    adv.add_argument("--icmp-param-problem", action="store_true",
                     help="ICMP Parameter Problem mapping for firewall behavior")
    adv.add_argument("--mptcp-probe", action="store_true",
                     help="MPTCP MP_CAPABLE SYN probe vs baseline (middlebox / path intel)")
    adv.add_argument("--stun-nat", action="store_true",
                     help="STUN binding — discover public egress IP:port (NAT awareness)")
    adv.add_argument("--tcp-exotic-probe", action="store_true",
                     help="Exotic TCP options (MD5, User-Timeout, NOP flood) response map")
    adv.add_argument("--dtls-probe", action="store_true",
                     help="UDP DTLS ClientHello on common ports (VPN / IoT / RTC surface)")
    adv.add_argument("--ssh-intel", action="store_true",
                     help="SSH banner + partial KEX stream read (port 22 or first open SSH)")
    adv.add_argument("--tls-alpn-probe", action="store_true",
                     help="TLS handshakes with varied ALPN lists (HTTP/2 vs h1 fingerprint)")
    adv.add_argument("--http-security-intel", action="store_true",
                     help="GET / and collect HSTS, CSP, X-Frame-Options, Server, etc.")
    adv.add_argument("--ipv6-prefix", metavar="PREFIX",
                     help="IPv6 prefix to scan during --ipv6-discover (e.g. 2001:db8::/64)")
    adv.add_argument("--smb-null", action="store_true",
                     help="Attempt SMB null/anonymous session to enumerate shares without credentials")
    adv.add_argument("--honeypot-detect", action="store_true",
                     help="Analyse scan results for honeypot/deception indicators (run after scan)")

    # Phase 37: Standalone scan modes (firewall bypass)
    adv.add_argument("--fin", action="store_true",
                     help="FIN scan (-sF): bypasses stateful firewalls that only inspect SYN packets")
    adv.add_argument("--maimon", action="store_true",
                     help="Maimon scan (-sM): FIN+ACK probe, open ports on BSD stacks drop instead of RST")
    adv.add_argument("--custom-flags", type=lambda x: int(x, 0), metavar="FLAGS_HEX",
                     help="Custom TCP flag bitmask scan (e.g. 0x29 = FIN+PSH+URG)")
    adv.add_argument("--custom-flags-name", default="custom", metavar="NAME",
                     help="Label for --custom-flags results (default: custom)")

    # Phase 38: Network-level evasion (new modules)
    adv.add_argument("--gre-tunnel", action="store_true",
                     help="Wrap probes in GRE (Generic Routing Encapsulation) to bypass L4 stateful inspection")
    adv.add_argument("--gre-relay", metavar="IP",
                     help="GRE relay/exit node IP (required for --gre-tunnel)")
    adv.add_argument("--igmp-enum", action="store_true",
                     help="IGMP multicast enumeration — discover hosts silently via mandatory multicast responses")
    adv.add_argument("--syn-cookie-probe", action="store_true",
                     help="Detect SYN cookie usage and infer server load/mitigation posture")
    adv.add_argument("--vlan-hop", action="store_true",
                     help="802.1Q VLAN double-tagging to reach adjacent VLANs on local switched networks")
    adv.add_argument("--vlan-id", type=int, default=1, metavar="VLAN",
                     help="Outer VLAN tag for double-tagging (default: 1, the native VLAN)")
    adv.add_argument("--vlan-target", type=int, default=100, metavar="VLAN",
                     help="Inner/target VLAN to hop into (default: 100)")

    # Phase 36: Next-Gen Packet Forgery & Covert Channels
    adv.add_argument("--ts-forge",
                     choices=["linux_modern", "linux_legacy", "windows10", "macos", "freebsd", "solaris", "cisco_ios"],
                     metavar="OS_PROFILE",
                     help="Forge TCP timestamps to impersonate a specific OS clock (defeats p0f/Zeek passive fingerprinting)")
    adv.add_argument("--ts-forge-per-target", action="store_true", default=True,
                     help="Use independent forged clock per target (defeats cross-target timestamp correlation, default: on)")
    adv.add_argument("--icmp-covert", action="store_true",
                     help="ICMP LSB steganography covert channel — embed probe data inside ping payloads")
    adv.add_argument("--icmp-egress-map", action="store_true",
                     help="Map egress firewall policy via ICMP Unreachable responses (zero TCP/UDP connections made)")
    adv.add_argument("--icmp-covert-bits", type=int, default=2, choices=[1, 2, 4],
                     help="LSBs per byte for ICMP covert channel (1=lowest entropy deviation, 4=max capacity, default: 2)")
    adv.add_argument("--state-actor", action="store_true",
                     help="Bundle: poisson timing, micro-jitter, slow-corridor, header rotation (max stealth)")

    # ── Multi-target ──────────────────────────────────────────────────────────
    tgt.add_argument("--target-file", metavar="FILE",
                     help="File with one target IP/hostname per line (overrides --target)")

    # ── OSINT ─────────────────────────────────────────────────────────────────
    adv.add_argument("--osint", action="store_true",
                     help="Query Shodan and/or Censys for known ports, CVEs, and banners (passive)")
    adv.add_argument("--shodan-key", metavar="KEY",
                     help="Shodan API key (account.shodan.io)")
    adv.add_argument("--censys-id", metavar="ID",
                     help="Censys API ID (censys.io → Account → API)")
    adv.add_argument("--censys-secret", metavar="SECRET",
                     help="Censys API secret")

    # ── ASN / IP ownership ───────────────────────────────────────────────────
    adv.add_argument("--asn-intel", action="store_true",
                     help="Enrich target IP with ASN, org, CDN/cloud edge classification (passive)")

    # ── HTTP path discovery ──────────────────────────────────────────────────
    adv.add_argument("--path-scan", action="store_true",
                     help="Probe high-value HTTP paths (/.env, /.git, /actuator, /swagger, etc.)")
    adv.add_argument("--path-delay", type=float, default=0.2, metavar="SEC",
                     help="Delay between path probes (default: 0.2s, 0=fast/noisy)")

    # ── Service data harvesting ───────────────────────────────────────────────
    adv.add_argument("--service-harvest", action="store_true",
                     help="Extract data from unauthenticated services (Redis, ES, Docker, K8s, etc.)")

    # ── Export formats ────────────────────────────────────────────────────────
    adv.add_argument("--nessus-export", action="store_true",
                     help="Export results as Nessus .nessus XML (importable into Tenable/Nessus)")
    adv.add_argument("--msf-export", action="store_true",
                     help="Export results as Metasploit db_import XML")

    # ── OPEN_FILTERED second-pass ─────────────────────────────────────────────
    adv.add_argument("--verify-filtered", action="store_true",
                     help="Second-pass TCP connect on OPEN_FILTERED ports to push to OPEN or FILTERED")

    # ── Behavioral camouflage ──────────────────────────────────────────────
    adv.add_argument("--behavioral-camouflage",
                     choices=["browser", "office_worker", "devops", "iot_device", "silent"],
                     help="Behavioral camouflage: DNS-before-connect, realistic source ports, decoy traffic")
    adv.add_argument("--camouflage-os", choices=["linux", "windows", "macos"], default="linux",
                     help="OS source-port profile for behavioral camouflage (default: linux)")
    adv.add_argument("--no-decoy-traffic", action="store_true",
                     help="Disable decoy HTTP requests generated by --behavioral-camouflage")

    # ── Interference detection ─────────────────────────────────────────────
    adv.add_argument("--interference-detect", action="store_true",
                     help="Monitor for RST injection, rate limiting, transparent proxy, honeypot indicators")
    adv.add_argument("--interference-auto-escalate", action="store_true",
                     help="Automatically escalate timing profile when interference is detected")

    # ── Advanced OS fingerprint (nmap-parity) ─────────────────────────
    adv.add_argument("--os-probes", action="store_true",
                     help="Full nmap-parity OS fingerprint: T1-T7 + U1 + IE1/IE2 probe suite (requires open port)")

    # ── Mesh / subnet scanning ─────────────────────────────────────────
    adv.add_argument("--mesh", action="store_true",
                     help="Mesh/subnet mode: discover and scan all hosts in a CIDR range")
    adv.add_argument("--mesh-parallel", type=int, default=5, metavar="N",
                     help="Max parallel host scans in mesh mode (default: 5)")
    adv.add_argument("--mesh-no-liveness", action="store_true",
                     help="Skip liveness check in mesh mode (scan all addresses)")

    # ── BloodHound export ───────────────────────────────────────────────
    adv.add_argument("--bloodhound", action="store_true",
                     help="Export results as BloodHound v4/v5 ingest JSON (computers + domain)")
    adv.add_argument("--bh-domain", default="corp.local", metavar="DOMAIN",
                     help="AD domain name for BloodHound export (default: corp.local)")

    args = parser.parse_args()

    # ── --full enables the full recon suite ────────────────────────
    if args.full:
        for flag in [
            "os_detect", "service_detect", "banner", "dns", "traceroute",
            "waf_detect", "vuln", "script", "jarm", "cert_intel",
            "bgp_intel", "quic_version", "reason", "correlate",
            "timestamp_analysis", "consistency_analysis",
            "honeypot_detect", "discovery",
        ]:
            if hasattr(args, flag):
                setattr(args, flag, True)

    return args
def run_decrypt(filepath, password, con):
    try:
        data = load_encrypted(filepath, password)
        con.print(Panel(
            json.dumps(data, indent=2),
            title=f"[bold]🔓 Decrypted: {filepath}[/bold]",
            border_style="green",
        ))
    except Exception as e:
        con.print(f"[bold red]❌ Decryption failed: {e}[/bold red]")
        sys.exit(1)

def run_diff_only(files, password, con):
    try:
        from ops.scan_diff import ScanDiffEngine # type: ignore
        from ops.encryption import load_encrypted # type: ignore
        scan_a = load_encrypted(files[0], password)
        scan_b = load_encrypted(files[1], password)
        diff_engine = ScanDiffEngine()
        diff_result = diff_engine.diff(scan_a, scan_b)

        con.print(f"  [bold]{diff_result.summary}[/bold]")
        for change in diff_result.port_changes:
            icon = "🟢" if change.change_type == "opened" else "🔴" if change.change_type == "closed" else "🟡"
            sev_color = "red" if change.severity == "critical" else "yellow" if change.severity == "warning" else "dim"
            con.print(f"  {icon} [{sev_color}]Port {change.port}/{change.protocol}: {change.change_type} ({change.old_value} → {change.new_value})[/{sev_color}]")
        for cert_chg in diff_result.cert_changes:
            con.print(f"  🔒 [yellow]Port {cert_chg.port}: {cert_chg.change_type} ({cert_chg.old_value} → {cert_chg.new_value})[/yellow]")
        if diff_result.os_change:
            con.print(f"  🖥️  [yellow]OS changed: {diff_result.os_change[0]} → {diff_result.os_change[1]}[/yellow]")
        if diff_result.firewall_change:
            con.print(f"  🛡️  [yellow]Firewall changed[/yellow]")
        con.print(f"  [dim]{diff_result.total_changes} total changes[/dim]")
    except Exception as e:
        con.print(f"[bold red]❌ Diff failed: {e}[/bold red]")
        sys.exit(1)
def display_config(args, con):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Setting", style="bold cyan", width=22)
    table.add_column("Value", style="white")
    ghost = not args.no_ghost
    table.add_row("Target", args.target)
    table.add_row("Ports", args.ports)
    table.add_row("Ghost Mode", "✅" if ghost else "❌")
    table.add_row("Timing Profile", args.profile.upper())
    if getattr(args, "state_actor", False):
        table.add_row("State-Actor Mode", "[bold yellow]ON[/bold yellow] (poisson+jitter+corridor)")
    if getattr(args, "slow_corridor", 0) and args.slow_corridor > 0:
        table.add_row("Slow Corridor", f"+0..{args.slow_corridor}s / probe")
    if getattr(args, "micro_jitter_ms", 0) and args.micro_jitter_ms > 0:
        table.add_row("Micro Jitter", f"+0..{args.micro_jitter_ms} ms / probe")
    table.add_row("Fragmentation", args.fragment)
    table.add_row("Decoys/Probe", str(args.decoys) if not args.no_decoys else "Off")
    table.add_row("Retransmissions", str(args.retries))
    table.add_row("Host Discovery", "✅" if args.discovery else "❌")
    table.add_row("OS Detection", "✅" if args.os_detect else "❌")
    table.add_row("Service Detect", "✅" if args.service_detect else "❌")
    table.add_row("Banner Grab", "✅" if args.banner else "❌")
    table.add_row("DNS Recon", "✅" if args.dns else "❌")
    table.add_row("ACK Scan", "✅" if args.ack else "❌")
    table.add_row("WAF Detect", "✅" if args.waf_detect else "❌")
    table.add_row("Vuln Map", "✅" if getattr(args, 'vuln', False) else "❌")
    table.add_row("Passive OSINT", "[green]Enabled" if getattr(args, "passive", False) else "[red]Disabled")
    
    table.add_row("--- ADVANCED EVASION ---", "")
    table.add_row("eBPF TCP Filter", "[green]Enabled" if args.ebpf else "[red]Disabled")
    table.add_row("IPv6 Engine", "[green]Enabled" if args.ipv6 else "[red]Disabled")
    
    proxy_val = f"[yellow]{args.proxy}" if getattr(args, "proxy", None) else "[red]Disabled"
    table.add_row("Proxy Chain", proxy_val)
    
    decoy_val = f"[yellow]{args.decoys} per real pkt" if getattr(args, "decoys", 0) else "[red]Disabled"
    table.add_row("Decoy Interleave", decoy_val)
    
    desync_val = f"[yellow]{getattr(args, 'desync_mode', 'adaptive')}" if args.desync else "[red]Disabled"
    table.add_row("TCP Desync", desync_val)
    
    tunnel_val = f"[yellow]{args.tunnel}" if getattr(args, "tunnel", None) else "[red]Disabled"
    table.add_row("Protocol Tunnel", tunnel_val)
    
    morph_val = f"[yellow]{args.flow_morph}" if getattr(args, "flow_morph", None) else "[red]Disabled"
    table.add_row("Flow Morphing", morph_val)
    
    dist_val = f"[yellow]{args.distributed}" if getattr(args, "distributed", None) else "[red]Disabled"
    table.add_row("Distributed", dist_val)
    
    base_val = f"[yellow]{args.baseline}m" if getattr(args, "baseline", None) else "[red]Disabled"
    table.add_row("Baseline Poison", base_val)

    adv_phase_30 = any([getattr(args, 'quic_churn', False), getattr(args, 'ipv6_scramble', False), getattr(args, 'tcp_dup_ack', False), getattr(args, 'pmtu_blackhole', False)])
    table.add_row("Phase 30 Evasion", "[green]Enabled" if adv_phase_30 else "[red]Disabled")

    adv_phase_32 = any([getattr(args, 'rst_block', False), getattr(args, 'alpn_smuggle', False), getattr(args, 'h2_smuggle', False), getattr(args, 'wss_tunnel', False)])
    table.add_row("Phase 32 L7 Evasion", "[green]Enabled" if adv_phase_32 else "[red]Disabled")

    table.add_row("Phase 34 ZTNA Evader", "[green]Enabled" if getattr(args, 'ztna_evasion', False) else "[red]Disabled")

    ts_forge_val = f"[green]{getattr(args, 'ts_forge', None)}" if getattr(args, 'ts_forge', None) else "[red]Disabled"
    table.add_row("TS Timestamp Forge", ts_forge_val)
    icmp_covert_val = "[green]Enabled" if getattr(args, 'icmp_covert', False) else "[red]Disabled"
    table.add_row("ICMP Covert Channel", icmp_covert_val)
    icmp_egress_val = "[green]Enabled" if getattr(args, 'icmp_egress_map', False) else "[red]Disabled"
    table.add_row("ICMP Egress Map", icmp_egress_val)
    smb_val = "[green]Enabled" if getattr(args, 'smb_null', False) else "[red]Disabled"
    table.add_row("SMB Null Session", smb_val)
    hp_val = "[green]Enabled" if getattr(args, 'honeypot_detect', False) else "[red]Disabled"
    table.add_row("Honeypot Detect", hp_val)

    con.print(Panel(table, title="[bold]⚙️  Configuration[/bold]", border_style="cyan"))
