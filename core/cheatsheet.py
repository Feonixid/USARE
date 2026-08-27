"""
USARE Cheatsheet — Quick reference printed by --cheatsheet.
"""

CHEATSHEET = r"""
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
[bold]  USARE v2.0 — Quick Reference Cheatsheet[/bold]
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]

[bold yellow]BASIC SCANNING[/bold yellow]
  usare -t 10.10.10.1 -p 80,443           Single target, specific ports
  usare -t 10.10.10.0/24 -p 1-1024        CIDR subnet scan
  usare -t 10.10.10.1 -p-                 All 65535 ports
  usare -t 10.10.10.1 --top-ports 100     Top 100 common ports
  usare --target-file hosts.txt -p 22     Multi-target from file

[bold yellow]SCAN TYPES[/bold yellow]
  usare -t IP -p 80                        SYN scan (default, stealthiest)
  usare -t IP -p 80 --fin                  FIN scan (bypasses stateful FW)
  usare -t IP -p 80 --maimon               Maimon FIN+ACK (BSD detection)
  usare -t IP -p 80 -sU                    UDP scan
  usare -t IP -p 80 -sY                    SCTP INIT scan
  usare -t IP -p 80 -sI                    Idle/zombie scan (zero attribution)
  usare -t IP --ip-proto-scan              All 256 IP protocol numbers

[bold yellow]FULL RECON (like nmap -A)[/bold yellow]
  usare -t IP --full                       Everything: OS, service, scripts,
                                           banner, DNS, traceroute, vuln, JARM

[bold yellow]STEALTH PROFILES[/bold yellow]
  --profile ghost       Default. Random delays 0.5-3s
  --profile phantom     Slower, more random (1-8s)
  --profile shadow      Very slow (5-30s per probe)
  --profile glacier     Extreme (30-120s per probe)
  --profile adaptive    Auto-adjusts based on detection risk
  --profile poisson     Exponential inter-arrival (mimics natural traffic)
  --state-actor         Max stealth bundle (poisson + jitter + corridor)

[bold yellow]EVASION TECHNIQUES[/bold yellow]
  --fragment standard   Fragment probes (default)
  --decoys 10           10 decoy IPs per probe
  --flow-morph chrome   Wrap traffic in browser-like patterns
  --tunnel https        Encapsulate probes in HTTPS
  --tunnel quic         Bypass TCP DPI via QUIC/UDP
  --tunnel dns          DNS tunneling
  --desync              TCP desync to blind stateful FW
  --source-masq         Source port mimicry (53/443/123)
  --ts-forge linux_modern  Forge TCP timestamps to match OS
  --behavioral-camouflage browser  Full browser behavior emulation
  --spoof-mac random    Randomize source MAC address

[bold yellow]INTELLIGENCE MODULES[/bold yellow]
  --bgp-intel           BGP community topology mapping
  --quic-version        QUIC version negotiation fingerprint
  --cert-intel          TLS certificate chain intelligence
  --pdns-timeline       Passive DNS infrastructure history
  --osint               Shodan/Censys passive lookup
  --asn-intel           ASN/IP ownership enrichment
  --cloud-intel         Cloud provider metadata detection

[bold yellow]SCRIPT ENGINE (NSE equivalent)[/bold yellow]
  usare -t IP -p 80 --script               Run all matching scripts
  usare -t IP --script --script-args http.timeout=10
  Scripts: http_title, ftp_anon, ssl_cert, ssh_hostkey,
           smtp_enum, redis_unauth, mongodb_unauth,
           default_creds, dns_zone_transfer, http_methods

[bold yellow]OUTPUT[/bold yellow]
  -o results.enc        Encrypted output (default)
  --json                Also write plaintext JSON
  --format json|csv|html|xml   Export to logs/ directory
  --nessus-export       Nessus-compatible .nessus XML
  --msf-export          Metasploit db_import XML
  --bloodhound          BloodHound v4/v5 JSON ingest
  --reason              Show why each port has its state

[bold yellow]AI FEATURES[/bold yellow]
  --ai-learn            AI response pattern learning
  --ollama              Local LLM for strategy selection
  --ollama-model llama3 Specific Ollama model

[bold yellow]EXAMPLES[/bold yellow]
  [dim]# Quick stealth scan of a web server[/dim]
  sudo usare -t 10.10.10.1 -p 80,443,8080,8443 --script

  [dim]# Full recon with max stealth[/dim]
  sudo usare -t target.com --full --state-actor --tunnel https

  [dim]# Subnet discovery + scan[/dim]
  sudo usare -t 192.168.1.0/24 --top-ports 20 --discovery

  [dim]# Zero-attribution idle scan[/dim]
  sudo usare -t 10.10.10.1 -p 1-1024 -sI --zombie-subnet 192.168.1.0

  [dim]# Bug bounty: passive first, then targeted[/dim]
  sudo usare -t target.com --osint --asn-intel --cert-intel --bgp-intel
  sudo usare -t target.com --full --script --path-scan

[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
"""


def print_cheatsheet(console):
    """Print the USARE cheatsheet."""
    console.print(CHEATSHEET)
