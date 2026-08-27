"""
USARE Engine — Main scan orchestrator.

This is the core scan engine. It orchestrates initialization,
the scan loop, post-scan modules, and result output.
"""
import os
import sys
import json
import time
import signal
import logging
import random
from getpass import getpass

from rich.console import Console  # type: ignore
from rich.panel import Panel  # type: ignore
from rich.table import Table  # type: ignore
from rich.text import Text  # type: ignore
from rich.progress import (  # type: ignore
    Progress, SpinnerColumn, TextColumn,
    BarColumn, TaskProgressColumn, TimeRemainingColumn,
)
from rich import box  # type: ignore

# ── Core modules ──────────────────────────────────────────────────────────────
from core.packet_engine import PacketEngine  # type: ignore
from core.ebpf_loader import EBPFLoader  # type: ignore

# ── Evasion modules ───────────────────────────────────────────────────────────
from evasion.timing import GhostTimer, TimingConfig, TimingProfile  # type: ignore
from evasion.fragmentation import FragmentationEngine  # type: ignore
from evasion.decoys import DecoyEngine  # type: ignore
from evasion.port_shuffle import shuffle_ports, shuffle_ports_prioritized  # type: ignore
from evasion.session import SessionTracker  # type: ignore
from evasion.proxy_layer import ProxyManager  # type: ignore
from evasion.source_port_masq import SourcePortMasquerader  # type: ignore
from evasion.flow_morph import FlowShaper, BrowserFlowMorpher, FlowType  # type: ignore
from evasion.proto_tunnel import HTTPSTunnel, DNSTunnel  # type: ignore
from evasion.distributed import DistributedCoordinator  # type: ignore
from evasion.baseline_poison import BaselinePoisoner, PoisonConfig  # type: ignore
from evasion.multi_path_dispersion import load_proxy_config, get_dispersion_stats  # type: ignore

# ── Recon modules ─────────────────────────────────────────────────────────────
from recon.syn_scanner import StealthScanner, ScanConfig, PortState  # type: ignore
from recon.banner_grab import BannerGrabber  # type: ignore
from recon.waf_bypass import WAFBypass  # type: ignore
from recon.os_fingerprint import OSFingerprintEngine  # type: ignore
from recon.service_detect import ServiceDetector  # type: ignore
from recon.dns_recon import DNSReconEngine  # type: ignore
from recon.host_discovery import HostDiscovery  # type: ignore
from recon.cold_start import ColdStartSniffer  # type: ignore
from recon.traceroute import StealthTraceroute  # type: ignore
from recon.vuln_mapping import VulnerabilityMapper  # type: ignore
from recon.jarm_fingerprint import JARMFingerprinter  # type: ignore
from recon.http_title import HTTPTitleGrabber  # type: ignore
from recon.whois_lookup import WHOISLookup  # type: ignore

# ── Ops modules ───────────────────────────────────────────────────────────────
from ops.encryption import Encryptor, load_encrypted  # type: ignore
from ops.heat_meter import HeatMeter  # type: ignore
from ops.reporting import ReportEngine  # type: ignore

# ── CLI (single source for console, banner, arg parsing) ──────────────────────
from core.cli import parse_args, display_config, run_decrypt, run_diff_only, console, BANNER

# ── Windows UTF-8 console fix ─────────────────────────────────────────────────
if sys.platform.startswith("win"):
    getattr(sys.stdout, "reconfigure", lambda **_: None)(encoding="utf-8")
    getattr(sys.stderr, "reconfigure", lambda **_: None)(encoding="utf-8")

def main():
    args = parse_args()
    if args.full:
        setattr(args, "discovery", True)
        setattr(args, "service_detect", True)
        setattr(args, "banner", True)
        setattr(args, "dns", True)
        setattr(args, "traceroute", True)
        setattr(args, "waf_detect", True)
        setattr(args, "vuln", True)
        setattr(args, "jarm", True)
        # New high-value modules automatically enabled in full mode
        setattr(args, "asn_intel", True)
        setattr(args, "http_security_intel", True)
        setattr(args, "banner_timing", True)
        setattr(args, "stun_nat", True)
        setattr(args, "path_scan", True)
        setattr(args, "service_harvest", True)
        setattr(args, "verify_filtered", True)
        setattr(args, "tcp_exotic_probe", True)
        setattr(args, "mptcp_probe", True)
        setattr(args, "dtls_probe", True)
        setattr(args, "tls_alpn_probe", True)
        setattr(args, "ssh_intel", True)
        setattr(args, "os_probes", True)
        setattr(args, "interference_detect", True)
        setattr(args, "interference_auto_escalate", True)
    if getattr(args, "state_actor", False):
        args.profile = "poisson"
        if not getattr(args, "micro_jitter_ms", None) or args.micro_jitter_ms <= 0:
            setattr(args, "micro_jitter_ms", 50.0)
        if not getattr(args, "slow_corridor", None) or args.slow_corridor <= 0:
            setattr(args, "slow_corridor", 5.0)
        setattr(args, "http_security_intel", True)
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    console.print(BANNER)
    if args.decrypt:
        password = args.password or getpass("Decryption password: ")
        run_decrypt(args.decrypt, password, console)
        return
    if getattr(args, "diff_only", None):
        password = args.password or getpass("Encryption password: ")
        run_diff_only(args.diff_only, password, console)
        return
    # --target-file overrides --target
    if getattr(args, "target_file", None):
        try:
            with open(args.target_file, "r", encoding="utf-8") as _tf:
                _tfile_targets = [l.strip() for l in _tf if l.strip() and not l.startswith("#")]
            if not _tfile_targets:
                console.print("[bold red]❌ --target-file is empty[/bold red]")
                sys.exit(1)
            # Inject as comma-joined into args.target; TargetParser handles the rest
            args.target = ",".join(_tfile_targets)
            console.print(f"[dim]📋 --target-file: {len(_tfile_targets)} targets loaded[/dim]")
        except FileNotFoundError:
            console.print(f"[bold red]❌ --target-file not found: {args.target_file}[/bold red]")
            sys.exit(1)

    if not args.target:
        console.print("[bold red]❌ Error: --target or --target-file is required[/bold red]")
        sys.exit(1)
    password = args.password or getpass("Encryption password: ")
    display_config(args, console)
    console.print()
    console.print(Panel(
        "[bold yellow]⚠️  LEGAL WARNING[/bold yellow]\n\n"
        "You must have written authorization to scan this target.",
        border_style="yellow",
    ))
    console.print()
    profile_map = {
        "ghost": TimingProfile.GHOST,
        "phantom": TimingProfile.PHANTOM,
        "shadow": TimingProfile.SHADOW,
        "glacier": TimingProfile.GLACIER,
        "adaptive": TimingProfile.ADAPTIVE,
        "poisson": TimingProfile.POISSON,
    }
    heat_meter = HeatMeter()

    # ─── MAC Spoofing (initialise before any packet is sent) ──────────────────
    mac_spoofer = None
    _orig_iface_mac = None
    _spoof_mac_arg  = getattr(args, "spoof_mac", None)
    if _spoof_mac_arg:
        try:
            from evasion.mac_spoof import MACSpoofer, validate_mac  # type: ignore
            if _spoof_mac_arg.lower() == "random":
                mac_spoofer = MACSpoofer(mode="random", interface=args.interface)
            elif _spoof_mac_arg.lower().startswith("vendor:"):
                vendor_name = _spoof_mac_arg.split(":", 1)[1]
                mac_spoofer = MACSpoofer(mode="vendor", vendor=vendor_name, interface=args.interface)
            elif validate_mac(_spoof_mac_arg):
                mac_spoofer = MACSpoofer(mode="fixed", mac=_spoof_mac_arg, interface=args.interface)
            else:
                # Treat as vendor name shorthand
                mac_spoofer = MACSpoofer(mode="vendor", vendor=_spoof_mac_arg, interface=args.interface)

            info = mac_spoofer.get_info()
            console.print(
                f"[dim]🎞️  MAC Spoof active: mode={info['mode']} "
                f"session_mac={info['session_mac']}[/dim]"
            )

            # Persistent mode: change interface MAC at OS level
            if getattr(args, "mac_persist", False) and args.interface:
                _orig_iface_mac = MACSpoofer.get_interface_mac(args.interface)
                applied = mac_spoofer.apply_to_interface()
                if applied:
                    console.print(
                        f"[dim]🎞️  Interface {args.interface} MAC changed to "
                        f"{mac_spoofer.get_mac()} (will revert on exit)[/dim]"
                    )
        except Exception as _mac_err:
            console.print(f"[yellow]⚠️  MAC spoof init failed: {_mac_err}[/yellow]")

    # Ensure MAC is reverted on exit (covers SIGINT too)
    if mac_spoofer and _orig_iface_mac and getattr(args, "mac_persist", False):
        import atexit
        _iface_for_revert = args.interface
        _mac_for_revert   = _orig_iface_mac
        def _revert_mac():
            try:
                mac_spoofer.revert_interface(_mac_for_revert)
            except Exception:
                pass
        atexit.register(_revert_mac)

    # Initialise TCP timestamp forger if requested (must happen before any packet is sent)
    ts_forger = None
    if getattr(args, "ts_forge", None):
        try:
            from evasion.tcp_timestamp_forge import TCPTimestampForge  # type: ignore
            ts_forger = TCPTimestampForge(
                profile_name=args.ts_forge,
                per_target_clocks=getattr(args, "ts_forge_per_target", True),
            )
            fp = ts_forger.get_profile_info()
            console.print(
                f"[dim]🕰️  TCP Timestamp Forge active: {fp['profile']} "
                f"({fp['hz']}Hz, {fp['ms_per_tick']}ms/tick, per-target isolation: {fp['per_target_isolation']})[/dim]"
            )
        except Exception as _ts_err:
            console.print(f"[yellow]⚠️  TS Forge init failed: {_ts_err}[/yellow]")

    # Compute module timeout — separate from raw scan timeout so banner/cert/service
    # probes can be slower without affecting scan speed.
    module_timeout = getattr(args, "module_timeout", 0.0) or (args.timeout * 3)

    # ── Behavioral camouflage (init once, used throughout scan loop) ──────
    behavioral_cam = None
    if getattr(args, "behavioral_camouflage", None):
        try:
            from evasion.behavioral_camouflage import BehavioralCamouflage, CamouflageConfig, CamouflageProfile  # type: ignore
            _cam_profile = CamouflageProfile(args.behavioral_camouflage)
            _cam_cfg = CamouflageConfig(
                profile=_cam_profile,
                os_source_ports=getattr(args, "camouflage_os", "linux") or "linux",
                decoy_requests_enabled=not getattr(args, "no_decoy_traffic", False),
            )
            behavioral_cam = BehavioralCamouflage(_cam_cfg)
            console.print(
                f"[dim]🥼  Behavioral camouflage: {args.behavioral_camouflage} profile | "
                f"OS ports: {_cam_cfg.os_source_ports} | "
                f"Decoy traffic: {'off' if _cam_cfg.decoy_requests_enabled is False else 'on'}[/dim]"
            )
        except Exception as _cam_err:
            console.print(f"[yellow]⚠️  Behavioral camouflage init failed: {_cam_err}[/yellow]")

    # ── Interference detector (init once) ───────────────────────────
    interference_detector = None
    if getattr(args, "interference_detect", False):
        try:
            from recon.interference_detector import InterferenceDetector  # type: ignore
            interference_detector = InterferenceDetector()
            console.print("[dim]🚨 Interference detector active (RST injection / rate limit / honeypot)[/dim]")
        except Exception as _id_err:
            console.print(f"[yellow]⚠️  Interference detector init failed: {_id_err}[/yellow]")
    # Initialize adaptive strategy controller (closes the heat → strategy feedback loop)
    from ops.strategy_controller import StrategyController
    strategy_controller = StrategyController(heat_meter, poll_interval=2.0)
    strategy_controller.start()
    # Initialize AI active learning engine if requested
    ai_engine = None
    if getattr(args, "ai_learn", False):
        try:
            from recon.ai_response_learner import AIActiveEngine  # type: ignore
            ai_engine = AIActiveEngine()
            console.print("[dim]🧠 AI active learning engine initialized[/dim]")
        except Exception:
            pass
    report_engine = ReportEngine()
    # Initialize temporal timing engine if requested
    temporal_engine = None
    if getattr(args, "temporal", False):
        try:
            from evasion.temporal_timing import TemporalTimingEngine  # type: ignore
            temporal_engine = TemporalTimingEngine()
            console.print("[dim]⏱️  Temporal timing engine initialized (monitoring peak-noise windows)[/dim]")
        except Exception:
            pass
    all_data = {}

    # ═══════════════════════════════════════════════
    # Zero-Packet Passive Recon (before any scanning)
    # ═══════════════════════════════════════════════
    if getattr(args, "passive", None):
        passive_duration = args.passive
        console.print(f"[bold cyan]👂 Zero-Packet Passive Recon ({passive_duration:.0f}s)[/bold cyan]")
        console.print("[dim]  Listening for ARP/mDNS/NetBIOS/LLMNR/SSDP broadcasts...[/dim]")
        try:
            from recon.passive_listener import PassiveListener  # type: ignore
            listener = PassiveListener(
                interface=getattr(args, "interface", None),
                timeout=passive_duration
            )
            passive_hosts = listener.listen(passive_duration)
            p_summary = listener.get_summary()
            console.print(f"  [green]Hosts discovered:[/green] {p_summary['total_hosts']}")
            console.print(f"  [green]Services found:[/green] {p_summary['total_services']}")
            for host in list(passive_hosts.values())[:10]:
                svc_str = ', '.join(host.services[:3]) if host.services else 'none'
                os_str = f" ({host.os_hint})" if host.os_hint else ''
                console.print(f"    {host.ip} [{host.source}] {host.hostname}{os_str} — {svc_str}")
            all_data["passive_recon"] = p_summary
        except Exception as e:
            console.print(f"  [red]✗[/red] Passive listener failed: {e}")
        console.print()

    # ═══════════════════════════════════════════════
    # IPv6 Host Discovery (pre-scan, supplements passive)
    # ═══════════════════════════════════════════════
    if getattr(args, "ipv6_discover", False):
        console.print("[bold cyan]🔍 IPv6 Host Discovery (ICMPv6 / NDP / Multicast)[/bold cyan]")
        try:
            from recon.ipv6_discovery import IPv6Discoverer  # type: ignore
            ipv6_disc = IPv6Discoverer(
                interface=getattr(args, "interface", None),
                timeout=args.timeout,
            )
            prefix = getattr(args, "ipv6_prefix", None) or ""
            ipv6_hosts = ipv6_disc.discover(prefix=prefix)
            summary = ipv6_disc.get_summary()
            console.print(f"  [green]IPv6 hosts found:[/green] {summary['total_hosts']}")
            if summary['routers']:
                console.print(f"  [green]Routers:[/green] {summary['routers']}")
            for h in ipv6_hosts:
                router_tag = " [yellow][ROUTER][/yellow]" if h.is_router else ""
                mac_tag = f" (MAC {h.mac})" if h.mac else ""
                console.print(f"    [cyan]{h.ipv6}[/cyan]{mac_tag}{router_tag} via {h.discovery_method}")
            all_data["ipv6_discovery"] = summary
        except Exception as e:
            console.print(f"  [red]✗[/red] IPv6 discovery failed: {e}")
        console.print()

    # ═══════════════════════════════════════════════
    # CT Log Scraping (passive, pre-scan)
    # ═══════════════════════════════════════════════
    if getattr(args, "ct_scan", False):
        console.print("[bold cyan]📜 Certificate Transparency Log Scraping[/bold cyan]")
        try:
            from recon.ct_scraper import CTScraper  # type: ignore
            ct = CTScraper()
            ct_result = ct.scrape(args.target)
            console.print(f"  [green]Certificates found:[/green] {ct_result.total_certs}")
            console.print(f"  [green]Unique subdomains:[/green] {len(ct_result.subdomains)}")
            console.print(f"  [green]Wildcard certs:[/green] {ct_result.wildcard_certs}")
            if ct_result.subdomains:
                console.print(f"  [bold]Subdomains:[/bold]")
                for sd in sorted(ct_result.subdomains)[:15]:
                    console.print(f"    {sd}")
            if ct_result.issuers:
                console.print(f"  [bold]Issuers:[/bold] {', '.join(sorted(ct_result.issuers)[:5])}")
            console.print(f"  [dim]{ct_result.scrape_time_ms:.0f}ms scrape time[/dim]")
            all_data["ct_logs"] = ct_result.to_dict()
        except Exception as e:
            console.print(f"  [red]✗[/red] CT scraping failed: {e}")
        console.print()

    start_time = time.time()
    def sigint_handler(sig, frame):
        console.print("\n[yellow]⚠️  Interrupted — saving partial results...[/yellow]")
        try:
            if 'strategy_controller' in locals() and strategy_controller:
                strategy_controller.stop()
        except Exception:
            pass
        if args.ebpf and ebpf_engine:
            ebpf_engine.detach()
        _save(all_data, password, args)
        sys.exit(0)
    signal.signal(signal.SIGINT, sigint_handler)
    proxy_manager = None
    if getattr(args, "baseline", None):
        duration = args.baseline
        console.print(f"[bold cyan]\U0001f4e1 Phase 0.1: Baseline Poisoning ({duration:.0f} min)[/bold cyan]")
        console.print("  [dim]Generating legitimate HTTPS/DNS/NTP traffic to establish carrier baseline...[/dim]")
        poison_cfg = PoisonConfig(duration_minutes=duration, gradual_ramp=True)
        poisoner = BaselinePoisoner(poison_cfg)
        poisoner.run_blocking(
            callback=lambda s: console.print(
                f"  [dim]  HTTPS: {s['https_requests']} | DNS: {s['dns_queries']}[/dim]",
                end="\r"
            ) if args.verbose else None
        )
        console.print(f"  [green]\u2713[/green] Baseline established: {poisoner.stats['https_requests']} HTTPS + {poisoner.stats['dns_queries']} DNS")
        console.print()
    if getattr(args, "proxy", None):
        proxy_manager = ProxyManager(args.proxy)
        if not proxy_manager.enable():
            console.print("[red]✖ Failed to initialize proxy. Exiting.[/red]")
            return
            
    if getattr(args, "multi_path", None):
        console.print("[bold cyan]🛤️  Phase 0.2: Multi-Path Dispersion[/bold cyan]")
        try:
            load_proxy_config(args.multi_path)
            stats = get_dispersion_stats()
            console.print(f"  [green]✓[/green] Loaded {stats.get('active_nodes', 0)} exit nodes across {stats.get('geographic_diversity', 0)} regions")
            all_data["multi_path_stats"] = stats
        except Exception as e:
            console.print(f"  [red]✗[/red] Failed to load multi-path nodes: {e}")
        console.print()
        
    ebpf_engine = None
    if args.ebpf:
        console.print("[bold cyan]🛡️  Phase 0.5: Loading eBPF RST Suppressor[/bold cyan]")
        iface = args.interface or "eth0"
        ebpf_engine = EBPFLoader(interface=iface)
        if ebpf_engine.attach():
            console.print(f"  [green]✓[/green] {ebpf_engine.status_line()}")
            if ebpf_engine.stats.tc_active:
                console.print("  [dim]TC egress: outgoing RSTs to targets silently dropped (no snitching)[/dim]")
            elif ebpf_engine.stats.iptables_fallback:
                console.print("  [yellow]⚠️  TC BPF unavailable — using iptables fallback (less stealthy)[/yellow]")
        else:
            console.print("  [red]✗[/red] eBPF failed. Raw socket RSTs may reach the target.")
        console.print()
    # ═══════════════════════════════════════════════
    # Mesh / subnet mode (CIDR expansion + host discovery)
    # ═══════════════════════════════════════════════
    if getattr(args, "mesh", False):
        console.print("[bold cyan]🕸️  Mesh / Subnet Mode[/bold cyan]")
        try:
            from recon.mesh_scanner import MeshScanner, MeshScanConfig, expand_target  # type: ignore
            _mcfg = MeshScanConfig(
                port_spec=args.ports,
                max_parallel_hosts=getattr(args, "mesh_parallel", 5),
                liveness_check=not getattr(args, "mesh_no_liveness", False),
                liveness_timeout=args.timeout,
                per_host_timeout=args.timeout,
            )
            _mesh = MeshScanner(_mcfg)
            _expanded = expand_target(args.target)
            console.print(f"  [green]{len(_expanded)} addresses expanded[/green] from '{args.target}'")

            def _mesh_progress(cur, tot, ip):
                console.print(f"  [{cur}/{tot}] {ip} ✓", end="\r")

            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=console, transient=True) as _prog:
                _task = _prog.add_task(f"Scanning {len(_expanded)} hosts...", total=None)
                _mesh_report = _mesh.scan_mesh(args.target, port_spec=args.ports, progress_callback=_mesh_progress)

            console.print()
            console.print(f"  [green]Alive: {_mesh_report.alive_hosts}[/green] | "
                          f"Open ports total: {_mesh_report.total_open_ports} | "
                          f"Time: {_mesh_report.elapsed_s:.1f}s")

            for _h in _mesh_report.sorted_by_priority()[:20]:
                _svc_str = ", ".join(f"{p}({_h.services.get(p,'')}" for p in _h.open_ports[:5])
                console.print(f"  [bold]{_h.ip}[/bold] — {len(_h.open_ports)} open [{_svc_str}]")

            all_data["mesh_scan"] = _mesh_report.to_dict()

            # BloodHound export from mesh
            if getattr(args, "bloodhound", False):
                from ops.bloodhound_export import export_bloodhound_mesh  # type: ignore
                _bh_domain = getattr(args, "bh_domain", "corp.local") or "corp.local"
                _bh_files = export_bloodhound_mesh(_mesh_report.to_dict(), domain=_bh_domain, out_dir=getattr(args, "output_dir", "logs"))
                for _f in _bh_files:
                    console.print(f"  [green]✓[/green] BloodHound: [cyan]{_f}[/cyan]")

        except Exception as _mesh_err:
            console.print(f"  [red]✗[/red] Mesh scan failed: {_mesh_err}")
            import traceback; traceback.print_exc()
        console.print()

    # MULTI-TARGET LOOP OVERRIDE
    from ops.target_parser import TargetParser
    targets = TargetParser(args.target, use_ping_sweep=args.discovery).get_targets()
    console.print(f"\n[bold cyan]🎯 Expansion: Targeting {len(targets)} active hosts.[/bold cyan]")
    if not targets:
        console.print("[bold red]❌ No active targets found.[/bold red]")
        sys.exit(1)
        
    master_data = {}
    for active_target in targets:
        args.target = active_target
        all_data = {}
        console.print(f"\n[bold magenta]{'='*60}[/bold magenta]")
        console.print(f"[bold magenta]🚀 ENGAGING TARGET: {active_target}[/bold magenta]")
        console.print(f"[bold magenta]{'='*60}[/bold magenta]\n")
        
        sniffed_profile = None
        if getattr(args, "cold_start", False):
            console.print("[bold cyan]👂 Phase 0.6: Passive Cold Start Sniffer[/bold cyan]")
            sniffer = ColdStartSniffer(interface=args.interface)
            sniffed_profile = sniffer.sniff_profile(args.target)
            if sniffed_profile:
                all_data["cold_start_profile"] = sniffed_profile
                console.print(f"  [green]✓[/green] Intercepted outbound OS profile: {sniffed_profile['os_guess']}")
            console.print()
        if not args.quiet:
            console.print("[bold cyan]\U0001f50e Phase 0.3: Target Validation (WHOIS)[/bold cyan]")
            whois_engine = WHOISLookup()
            whois_result = whois_engine.lookup(args.target)
            all_data["whois"] = whois_result.to_dict()
            if whois_result.resolved_ip:
                console.print(f"  [green]\u2713[/green] Resolved: {whois_result.resolved_ip}")
            if whois_result.registrar:
                console.print(f"  [dim]Registrar: {whois_result.registrar}[/dim]")
            if whois_result.organization:
                console.print(f"  [dim]Org: {whois_result.organization}[/dim]")
            if whois_result.country:
                console.print(f"  [dim]Country: {whois_result.country}[/dim]")
            if whois_result.asn:
                console.print(f"  [dim]ASN: {whois_result.asn}[/dim]")
            if whois_result.is_cloud:
                console.print(f"  [yellow]\u26a0\ufe0f  Cloud: {whois_result.cloud_provider}[/yellow]")
            if whois_result.honeypot_warning:
                console.print(f"  [bold red]\u26a0\ufe0f  HONEYPOT INDICATORS DETECTED[/bold red]")
            for w in whois_result.warnings:
                console.print(f"  [yellow]{w}[/yellow]")
            console.print()
    
        # ═══════════════════════════════════════════════
        # ASN / IP Ownership Intelligence (pre-scan, passive)
        # ═══════════════════════════════════════════════
        if getattr(args, "asn_intel", False):
            console.print("[bold cyan]🌐 ASN / IP Ownership Intelligence[/bold cyan]")
            try:
                from recon.asn_intel import lookup_asn  # type: ignore
                asn_result = lookup_asn(args.target, timeout=module_timeout)
                asn_d = asn_result.to_dict()
                if asn_result.asn:
                    console.print(f"  [green]ASN:[/green] AS{asn_result.asn} ({asn_result.asn_name})")
                if asn_result.organization:
                    console.print(f"  [green]Org:[/green] {asn_result.organization}")
                if asn_result.country:
                    console.print(f"  [green]Country:[/green] {asn_result.country} ({asn_result.country_code})")
                if asn_result.prefix:
                    console.print(f"  [green]Prefix:[/green] {asn_result.prefix}")
                if asn_result.is_cdn:
                    console.print(f"  [bold yellow]⚠️  CDN EDGE NODE: {asn_result.cdn_name}[/bold yellow]")
                    console.print("  [yellow]   This IP is likely a CDN edge PoP — NOT the origin server.[/yellow]")
                    console.print("  [dim]   Origin discovery techniques:[/dim]")
                    # Passive TLS cert IP SAN check
                    try:
                        import ssl as _ssl, socket as _sock
                        _ctx = _ssl.create_default_context()
                        _ctx.check_hostname = False
                        _ctx.verify_mode = _ssl.CERT_NONE
                        with _sock.create_connection((args.target, 443), timeout=5) as _rs:
                            with _ctx.wrap_socket(_rs, server_hostname=args.target) as _ss:
                                _cert = _ss.getpeercert()
                                _ip_sans = [v for t, v in _cert.get('subjectAltName', []) if t == 'IP Address']
                                if _ip_sans:
                                    console.print(f"  [cyan]   → TLS cert IP SANs (potential origin): {_ip_sans}[/cyan]")
                                    asn_d["tls_ip_sans"] = _ip_sans
                    except Exception:
                        pass
                    console.print(f"  [dim]   → Try: curl -H 'X-Forwarded-For: 127.0.0.1' https://{args.target}/ -v[/dim]")
                    console.print(f"  [dim]   → Try: dig +short {args.target} to check historical DNS[/dim]")
                elif asn_result.is_hosting:
                    console.print(f"  [yellow]Cloud/Hosting infrastructure[/yellow]")
                for note in asn_result.notes:
                    console.print(f"  [dim]{note}[/dim]")
                all_data["asn_intel"] = asn_d
            except Exception as e:
                console.print(f"  [red]✗[/red] ASN intel failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Shodan / Censys OSINT (pre-scan, passive)
        # ═══════════════════════════════════════════════
        if getattr(args, "osint", False):
            console.print("[bold cyan]🔍 Passive OSINT (Shodan / Censys)[/bold cyan]")
            try:
                from recon.osint_integration import OSINTIntegration  # type: ignore
                osint = OSINTIntegration(
                    shodan_key=getattr(args, "shodan_key", None),
                    censys_id=getattr(args, "censys_id", None),
                    censys_secret=getattr(args, "censys_secret", None),
                )
                if not osint.any_configured:
                    console.print("  [yellow]⚠️  No API keys configured. Use --shodan-key and/or --censys-id/--censys-secret.[/yellow]")
                else:
                    osint_summary = osint.merged_summary(args.target)
                    sources = ", ".join(osint_summary.get("sources", []))
                    console.print(f"  [green]✓[/green] Sources: {sources}")
                    if osint_summary.get("organization"):
                        console.print(f"  [green]Org:[/green] {osint_summary['organization']}")
                    if osint_summary.get("asn"):
                        console.print(f"  [green]ASN:[/green] {osint_summary['asn']}")
                    if osint_summary.get("os_guess"):
                        console.print(f"  [green]OS:[/green] {osint_summary['os_guess']}")
                    known_ports = [str(p["port"]) for p in osint_summary.get("ports", [])]
                    if known_ports:
                        console.print(f"  [green]Known open ports:[/green] {', '.join(known_ports[:20])}")
                    cves = osint_summary.get("cves", [])
                    if cves:
                        console.print(f"  [bold red]⚠️  Known CVEs: {', '.join(cves[:10])}[/bold red]")
                    if osint_summary.get("last_seen"):
                        console.print(f"  [dim]Last indexed: {osint_summary['last_seen']}[/dim]")
                    all_data["osint"] = osint_summary
            except Exception as e:
                console.print(f"  [red]✗[/red] OSINT failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # BGP Community Intelligence
        # ═══════════════════════════════════════════════
        if getattr(args, "bgp_intel", False):
            console.print("[bold cyan]🌍 BGP Community Intelligence[/bold cyan]")
            try:
                from recon.bgp_community_intel import analyze_bgp_communities  # type: ignore
                _target_asn = all_data.get("asn_intel", {}).get("asn", 0)
                bgp_res = analyze_bgp_communities(args.target, _target_asn)
                
                if bgp_res.datacenter_locations:
                    console.print(f"  [green]Datacenters:[/green] {', '.join(bgp_res.datacenter_locations)}")
                if bgp_res.service_types:
                    console.print(f"  [green]Services:[/green] {', '.join(bgp_res.service_types)}")
                if bgp_res.communities:
                    console.print(f"  [dim]Found {len(bgp_res.communities)} BGP communities[/dim]")
                
                all_data["bgp_intel"] = bgp_res.__dict__
            except Exception as e:
                console.print(f"  [red]✗[/red] BGP Intel failed: {e}")
            console.print()

        # AI Modeler Integration
        if getattr(args, "ollama", False) and not args.quiet:
            console.print("[bold cyan]🤖 Phase 0.4: AI Target Modeling (Ollama)[/bold cyan]")
            try:
                from ops.intel_graph import IntelGraph # type: ignore
                from ops.ollama_backend import OllamaBackend # type: ignore
                
                # Pre-build graph with OSINT data
                graph = IntelGraph()
                graph.ingest_scan_results(args.target, all_data)
                
                ollama = OllamaBackend(model=getattr(args, "ollama_model", None))
                # Generate strategy based entirely on pre-scan footprint
                recommendations = ollama.infer_evasion_strategy({"target": args.target, "pre_scan_intel": graph.to_dict()})
                
                # Auto-adjust based on AI Profile recommendation
                if recommendations.recommended_profile:
                    args.profile = recommendations.recommended_profile.lower()
                    if args.profile not in profile_map:
                        args.profile = "adaptive"
                    console.print(f"  [cyan]🔧 AI adjusted timing profile: {args.profile}[/cyan]")
                
                console.print(f"  [green]✓[/green] AI Analysis: {recommendations.target_assessment}")
                
                all_data["ai_recommendations"] = recommendations.to_dict()
            except Exception as e:
                console.print(f"  [yellow]⚠️  Ollama AI Modeler failed: {e}[/yellow]")
                console.print("  [dim]Continuing with base configuration...[/dim]")
        _resume_tracker = None
        if args.resume:
            _resume_tracker = SessionTracker()
            if _resume_tracker.load_session():
                console.print("[green]✓ Resumed from previous session[/green]")
            else:
                console.print("[yellow]⚠️  No saved session found — starting fresh[/yellow]")
                _resume_tracker = None
                
        trace_result = None
        if args.discovery:
            console.print("[bold cyan]🔍 Phase 0: Host Discovery[/bold cyan]")
            discovery = HostDiscovery(timeout=args.timeout)
            host_status = discovery.is_alive(args.target)
            all_data["host_status"] = host_status.to_dict()
            if host_status.is_alive:
                console.print(
                    f"  [green]✓[/green] Host is alive via {host_status.method} "
                    f"({host_status.latency_ms:.1f}ms)"
                )
                if host_status.mac_address:
                    console.print(f"  [dim]MAC: {host_status.mac_address}[/dim]")
            else:
                console.print(f"  [red]✗[/red] Host appears down: {host_status.reason}")
                console.print("[dim]Continuing scan anyway (host may be filtering probes)[/dim]")
            console.print()
        if args.dns:
            console.print("[bold cyan]🌐 Phase 1: DNS Reconnaissance[/bold cyan]")
            dns_engine = DNSReconEngine()
            dns_result = dns_engine.full_recon(args.target)
            all_data["dns_intel"] = dns_result.to_dict()
            if dns_result.reverse_dns:
                console.print(f"  [green]PTR:[/green] {dns_result.reverse_dns}")
            if dns_result.nameservers:
                console.print(f"  [green]NS:[/green] {', '.join(dns_result.nameservers[:5])}")
            if dns_result.mail_servers:
                console.print(f"  [green]MX:[/green] {', '.join(dns_result.mail_servers[:5])}")
            if dns_result.subdomains:
                console.print(f"  [green]Subdomains:[/green] {len(dns_result.subdomains)} found")
            if dns_result.has_wildcard:
                console.print(f"  [yellow]⚠️  Wildcard DNS detected[/yellow]")
            console.print()
        if args.traceroute:
            console.print("[bold cyan]🗺️  Phase 2: Stealth Traceroute[/bold cyan]")
            _tr_kw: dict = {"timeout": args.timeout}
            if not args.no_ghost:
                _tcfg = TimingConfig.from_profile(profile_map[args.profile])
                _tcfg.heat_callback = heat_meter.detection_probability
                _tr_timer = GhostTimer(_tcfg)
                _tr_kw["inter_hop_delay"] = None
                _tr_kw["hop_callback"] = lambda _: _tr_timer.sync_ghost_wait()
                console.print("  [dim]Using ghost timing between hops (integrated stealth)[/dim]")
            tracer = StealthTraceroute(**_tr_kw)
            trace_result = tracer.trace(args.target)
            all_data["traceroute"] = trace_result.to_dict()
            for hop in trace_result.hops:
                if hop.ip:
                    name = f" ({hop.hostname})" if hop.hostname else ""
                    console.print(
                        f"  {hop.ttl:>2}  {hop.ip}{name}  "
                        f"{hop.latency_ms:.1f}ms" if hop.latency_ms else f"  {hop.ttl:>2}  *"
                    )
                else:
                    console.print(f"  {hop.ttl:>2}  * (filtered)")
            if trace_result.firewall_position:
                console.print(
                    f"  [yellow]🛡️  Firewall at hop {trace_result.firewall_position}[/yellow]"
                )
            console.print()
        console.print("[bold cyan]🚀 Phase 3: Stealth Port Scan[/bold cyan]")
        port_spec = args.ports
        if args.top_ports:
            from recon.syn_scanner import SERVICE_MAP
            top = sorted(SERVICE_MAP.keys())[:args.top_ports]
            port_spec = ",".join(str(p) for p in top)
    
        # Parse ports into list
        port_list = []
        for part in port_spec.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))

        # If resuming, skip ports already recorded in the saved session
        if _resume_tracker is not None:
            unscanned = _resume_tracker.get_unscanned_ports(args.target, port_list)
            skipped = len(port_list) - len(unscanned)
            if skipped:
                console.print(f"  [dim]⏭️  Resume: skipping {skipped} already-scanned ports[/dim]")
            port_list = unscanned

        # Distributed Scanning Path
        if getattr(args, "distributed", None):
            console.print(f"  [bold magenta]📡 Dispatching to distributed nodes via config: {args.distributed}[/bold magenta]")
            from evasion.distributed import DistributedCoordinator
            coord = DistributedCoordinator(nodes_file=args.distributed)
        
            console.print("  [dim]Performing node health checks...[/dim]")
            health = coord.health_check(timeout=3.0)
            ready = sum(1 for status in health.values() if status.get("status") == "ready")
            console.print(f"  [green]✓[/green] {ready}/{len(coord.nodes)} nodes ready for dispatch")
        
            if ready == 0:
                console.print("[bold red]❌ No nodes available for distributed scan. Aborting.[/bold red]")
                sys.exit(1)
            
            # Reconstruct flags for remote execution
            passed_flags = []
            if args.no_ghost: passed_flags.append("--no-ghost")
            if args.profile: passed_flags.append(f"--profile {args.profile}")
            if args.fragment != "none": passed_flags.append(f"--fragment {args.fragment}")
            if args.decoys: passed_flags.append(f"--decoys {args.decoys}")
            if getattr(args, "tunnel", None): passed_flags.append(f"--tunnel {args.tunnel}")
            if getattr(args, "flow_morph", None): passed_flags.append(f"--flow-morph {args.flow_morph}")
            if args.desync: passed_flags.append(f"--desync --desync-mode {getattr(args, 'desync_mode', 'adaptive')}")
        
            flag_str = " ".join(passed_flags)
        
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(description=f"Executing scan across {ready} nodes...", total=None)
                coord.dispatch_all(args.target, port_list, flags=flag_str)
            
            merged = coord.merge_results()
        
            # Convert merged raw dicts back to ScanResult objects for the rest of pipeline
            from recon.syn_scanner import ScanResult, PortState
            results = []
            if "scan_results" in merged:
                for r_dict in merged["scan_results"]:
                    state_enum = PortState(r_dict["state"]) if "state" in r_dict else PortState.FILTERED
                    results.append(ScanResult(
                        port=r_dict["port"],
                        state=state_enum,
                        latency_ms=r_dict.get("latency_ms"),
                        service_guess=r_dict.get("service_guess"),
                        scan_method=r_dict.get("scan_method", "distributed")
                    ))
        
            console.print(f"  [green]✓[/green] Distributed scan complete in {merged.get('total_elapsed', 0):.1f}s")
            for node in merged.get("node_details", []):
                status_color = "green" if node["status"] == "done" else "red"
                console.print(f"    - {node['node']} ({node['dispatch_mode']}): [{status_color}]{node['status']}[/{status_color}] - {node['ports_assigned']} ports")
        else:
            # ═══════════════════════════════════════════════════
            # IDLE SCAN PATH — Zero Attribution
            # ═══════════════════════════════════════════════════
            if getattr(args, "idle", False):
                console.print("\n[bold magenta]👻 IDLE SCAN MODE — Zero Attribution[/bold magenta]")
                console.print("  [dim]No packets from your IP will reach the target.[/dim]")
                from recon.idle_pipeline import run_idle_pipeline

                idle_result = run_idle_pipeline(
                    target_ip=args.target,
                    ports=port_list,
                    zombie_ip=getattr(args, "zombie_ip", None),
                    zombie_subnet=getattr(args, "zombie_subnet", None),
                    zombie_port=getattr(args, "zombie_port", 80),
                    timeout=args.timeout,
                )

                if idle_result and idle_result.port_results:
                    console.print(f"  [green]✓[/green] Zombie used: [bold]{idle_result.zombie_used}[/bold]")
                    console.print(f"  [dim]{idle_result.total_probes} probes, {idle_result.zombie_failovers} failovers[/dim]")

                    # Convert idle results to standard ScanResult objects for unified downstream
                    from recon.syn_scanner import ScanResult, PortState as SP
                    results = []
                    for port, pr in idle_result.port_results.items():
                        state_map = {
                            "open": SP.OPEN, "closed": SP.CLOSED,
                            "filtered": SP.FILTERED, "unknown": SP.FILTERED
                        }
                        results.append(ScanResult(
                            port=pr.port,
                            state=state_map.get(pr.state, SP.FILTERED),
                            confidence=pr.confidence,
                            scan_method=f"idle_scan (zombie:{pr.zombie_used})",
                            service_guess=None,
                        ))
                    all_data["idle_scan"] = {
                        "zombie": idle_result.zombie_used,
                        "total_probes": idle_result.total_probes,
                        "failovers": idle_result.zombie_failovers,
                        "ports_scanned": len(idle_result.port_results),
                    }
                else:
                    console.print("[bold red]❌ Idle scan pipeline failed — no usable zombies found.[/bold red]")
                    console.print("  [dim]Tip: use --zombie-ip to specify a known zombie, or --zombie-subnet for a different range[/dim]")
                    results = []

            # ═══════════════════════════════════════════════════
            # NORMAL LOCAL SCAN PATH
            # ═══════════════════════════════════════════════════
            else:
                scan_config = ScanConfig(
                    target_ip=args.target,
                    port_range=port_spec,
                ghost_mode=not args.no_ghost,
                timing_profile=profile_map[args.profile],
                use_fragmentation=args.fragment != "none",
                frag_strategy=args.fragment if args.fragment != "none" else "standard",
                use_decoys=not args.no_decoys,
                decoy_count=args.decoys,
                use_priority_shuffle=True,
                timeout=args.timeout,
                confirm_with_ack=args.ack,
                confirm_with_xmas=args.xmas,
                chunk_size=args.chunk_size,
                interface=args.interface,
                verbose=args.verbose,
                max_retries=args.retries,
                adaptive_timeout=True,
                os_detect=args.os_detect,
                tcp_desync=args.desync,
                desync_mode=getattr(args, "desync_mode", "adaptive"),
                ipv6=args.ipv6,
                flow_morph=getattr(args, "flow_morph", None) is not None,
                flow_morph_profile=getattr(args, "flow_morph", "chrome") or "chrome",
                tunnel=getattr(args, "tunnel", None),
                tunnel_ja3=(
                    getattr(args, "ja3_rotation", None)
                    if getattr(args, "tunnel", None) == "https"
                    else None
                ),
                use_entropy_balancing=bool(getattr(args, "entropy_balance", None)),
                entropy_target_type=getattr(args, "entropy_balance", None) or "chrome_tls",
                traceroute_hops=trace_result.firewall_position if 'trace_result' in locals() and trace_result.firewall_position else None,
                slow_corridor_seconds=float(getattr(args, "slow_corridor", 0.0) or 0.0),
                micro_jitter_ms=float(getattr(args, "micro_jitter_ms", 0.0) or 0.0),
                use_contextual_probe=bool(getattr(args, "contextual_probe", False)),
                contextual_os_hint=getattr(args, "contextual_os_hint", None),
                use_ttl_masquerading=bool(getattr(args, "ttl_masquerade", None)),
                ttl_strategy=getattr(args, "ttl_masquerade", "adaptive") or "adaptive",
                use_multi_path=bool(getattr(args, "multi_path", None)),
                multi_path_config=getattr(args, "multi_path", None),
                service_detect=bool(getattr(args, "service_detect", False)),
            )
            scanner = StealthScanner(
                scan_config,
                heat_meter,
                temporal_engine=temporal_engine,
                strategy_controller=strategy_controller,
            )
            # Wire interference detector into scanner (fix #1 + #3)
            if interference_detector is not None:
                scanner.set_interference_detector(interference_detector)
            # Hook TCP timestamp forger into every packet the engine crafts
            if ts_forger is not None:
                _orig_craft_syn = scanner.packet_engine.craft_syn
                def _forged_craft_syn(*a, **kw):
                    pkt = _orig_craft_syn(*a, **kw)
                    return ts_forger.inject(pkt)
                scanner.packet_engine.craft_syn = _forged_craft_syn  # type: ignore[method-assign]

            # Hook --data-length or --packet-size-profile padding into every crafted SYN
            _data_length = getattr(args, "data_length", 0) or 0
            _size_profile = getattr(args, "packet_size_profile", None)
            if _size_profile or _data_length > 0:
                import random as _rand
                _profile_enum = None
                if _size_profile:
                    from evasion.packet_size_profiles import sample_payload_size, get_profile  # type: ignore
                    _profile_enum = get_profile(_size_profile)
                _orig_craft_syn2 = scanner.packet_engine.craft_syn
                def _padded_craft_syn(*a, **kw):
                    from scapy.all import Raw
                    pkt = _orig_craft_syn2(*a, **kw)
                    n = sample_payload_size(_profile_enum) if _profile_enum is not None else _data_length
                    if n > 0:
                        pkt = pkt / Raw(load=_rand.randbytes(n))
                    return pkt
                scanner.packet_engine.craft_syn = _padded_craft_syn  # type: ignore[method-assign]
                _msg = f"packet-size-profile {_size_profile}" if _size_profile else f"--data-length {_data_length}"
                logger.debug(f"[USARE] {_msg}: appending variable/fixed bytes to every SYN")

            # Hook --spoof-mac into every crafted packet
            if mac_spoofer is not None and not getattr(args, "mac_persist", False):
                # Per-packet injection (Scapy Ether layer)
                _orig_craft_syn3 = scanner.packet_engine.craft_syn
                _mac_spoofer_ref = mac_spoofer
                def _mac_craft_syn(*a, **kw):
                    pkt = _orig_craft_syn3(*a, **kw)
                    return _mac_spoofer_ref.inject(pkt)
                scanner.packet_engine.craft_syn = _mac_craft_syn  # type: ignore[method-assign]
            if sniffed_profile:
                scanner.packet_engine.config.custom_ttl = sniffed_profile["ttl"]
                scanner.packet_engine.config.custom_window = sniffed_profile["window"]
                scanner.packet_engine.config.df_flag = sniffed_profile["df_flag"]
                
            rst_blocker = None
            if getattr(args, "rst_block", False):
                from ops.rst_blocker import RSTBlocker
                rst_blocker = RSTBlocker(args.target)
                rst_blocker.__enter__()
                console.print("\n[dim]🛡️  Local OS TCP RST leaking blocked via iptables[/dim]")
                
            ebpf_rootkit = None
            if getattr(args, "ebpf_stealth", False):
                from evasion.ebpf_stealth import EBPFStealthRootkit
                ebpf_rootkit = EBPFStealthRootkit(args.interface or "eth0", args.target)
                success = ebpf_rootkit.start()
                if not success:
                    console.print("[red]✗ eBPF Rootkit failed to initialize. Disabling ultimate stealth.[/red]")
                    ebpf_rootkit = None
                else:
                    console.print("\n[bold magenta]👻 eBPF XDP Stealth Rootkit ACTIVE (Driver-Level Hook)[/bold magenta]")

            try:
                # Determine scan types
                scan_types = []
                if getattr(args, "sctp", False) or args.full:
                    scan_types.append("sctp")
                if getattr(args, "udp", False) or args.full:
                    scan_types.append("udp")
                if getattr(args, "fin", False):
                    scan_types.append("fin")
                if getattr(args, "maimon", False):
                    scan_types.append("maimon")
                if getattr(args, "custom_flags", None) is not None:
                    scan_types.append("custom_flags")
                if not getattr(args, "udp", False) and not getattr(args, "sctp", False) \
                        and not getattr(args, "fin", False) and not getattr(args, "maimon", False) \
                        and getattr(args, "custom_flags", None) is None \
                        or args.full:
                    scan_types.append("syn")

                results = []
                for stype in scan_types:
                    if stype == "sctp":
                        from recon.sctp_scanner import SCTPScanner
                        console.print("\n[bold cyan]🔥 Phase 2 (SCTP): Stealth SCTP INIT Scan[/bold cyan]")
                        sctp_scanner = SCTPScanner(scan_config, heat_meter)
                        results.extend(sctp_scanner.execute())
                    elif stype == "udp":
                        from recon.udp_scanner import UDPScanner
                        console.print("\n[bold cyan]🌊 Phase 2 (UDP): UDP Stealth State Scan[/bold cyan]")
                        udp_scanner = UDPScanner(scan_config, heat_meter)
                        results.extend(udp_scanner.execute())
                    elif stype == "fin":
                        console.print("\n[bold cyan]🏴 Phase 2 (FIN): Stealth FIN Scan — bypasses stateful firewalls[/bold cyan]")
                        console.print("  [dim]RFC 793: closed ports send RST, open ports are silent[/dim]")
                        fin_results = scanner.fin_scan(port_list)
                        results.extend(fin_results)
                        open_fin = sum(1 for r in fin_results if r.state == PortState.OPEN_FILTERED)
                        closed_fin = sum(1 for r in fin_results if r.state == PortState.CLOSED)
                        console.print(f"  [green]Open|Filtered: {open_fin}[/green] | Closed: {closed_fin}")
                    elif stype == "maimon":
                        console.print("\n[bold cyan]🔮 Phase 2 (Maimon): FIN+ACK Scan — BSD stack discrimination[/bold cyan]")
                        console.print("  [dim]Susceptible BSD stacks drop FIN+ACK to open ports instead of sending RST[/dim]")
                        maimon_results = scanner.maimon_scan(port_list)
                        results.extend(maimon_results)
                        open_m = sum(1 for r in maimon_results if r.state == PortState.OPEN_FILTERED)
                        closed_m = sum(1 for r in maimon_results if r.state == PortState.CLOSED)
                        console.print(f"  [green]Open|Filtered: {open_m}[/green] | Closed: {closed_m}")
                    elif stype == "custom_flags":
                        flags_val = getattr(args, "custom_flags", 0)
                        flags_name = getattr(args, "custom_flags_name", "custom")
                        console.print(f"\n[bold cyan]🎭 Phase 2 (Custom): TCP Flag Scan (flags=0x{flags_val:02X} \u2014 {flags_name})[/bold cyan]")
                        custom_results = scanner.custom_flag_scan(port_list, flags_val, flags_name)
                        results.extend(custom_results)
                        unfiltered = sum(1 for r in custom_results if r.state == PortState.UNFILTERED)
                        console.print(f"  [green]Unfiltered: {unfiltered}[/green] (stateless ACL — no state tracking by firewall)")
                    else:  # syn
                        console.print("\n[bold cyan]🔥 Phase 2 (TCP): Ultimate Stealth TCP SYN Scan[/bold cyan]")
                        results.extend(scanner.execute())

            except PermissionError:
                console.print(
                    "[bold red]❌ Raw socket access requires administrator/root.[/bold red]"
                )
                sys.exit(1)
            except Exception as e:
                console.print(f"[bold red]❌ Scan error: {e}[/bold red]")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
            finally:
                if rst_blocker:
                    rst_blocker.__exit__(None, None, None)
                if ebpf_rootkit:
                    ebpf_rootkit.__exit__(None, None, None)

        open_ports = [r for r in results if r.state == PortState.OPEN]
        console.print(f"\n  Scanned: {len(results)} | "
                      f"[green]Open: {len(open_ports)}[/green] | "
                      f"Closed: {sum(1 for r in results if r.state == PortState.CLOSED)} | "
                      f"Filtered: {sum(1 for r in results if r.state == PortState.FILTERED)}")
        console.print()
        open_tcp_ports = [r.port for r in open_ports if r.protocol == 'tcp']
        _probe_tcp_port = open_ports[0].port if open_ports else 443
        _http_intel_port = next(
            (r.port for r in open_ports if r.port in (80, 8080, 8000, 8888)),
            None,
        )
        _https_intel_port = next(
            (r.port for r in open_ports if r.port in (443, 8443, 9443)),
            None,
        )
        # ═══════════════════════════════════════════════
        # QUIC Version Probing
        # ═══════════════════════════════════════════════
        if getattr(args, "quic_version", False) and open_ports:
            console.print("\n[bold cyan]🚀 QUIC Version Negotiation Probe[/bold cyan]")
            try:
                from recon.quic_version_probe import probe_quic_versions  # type: ignore
                udp_ports = [r.port for r in open_ports if r.port in (443, 8443, 4433)]
                quic_port = udp_ports[0] if udp_ports else 443
                
                quic_res = probe_quic_versions(args.target, quic_port)
                
                if quic_res.library_implementation:
                    console.print(f"  [green]Library:[/green] {quic_res.library_implementation.value}")
                if quic_res.supported_versions:
                    console.print(f"  [green]Supported:[/green] {', '.join(quic_res.supported_versions)}")
                
                all_data["quic_version"] = quic_res.__dict__
            except Exception as e:
                console.print(f"  [red]✗[/red] QUIC probe failed: {e}")
            console.print()

        if getattr(args, "jarm", False) and open_tcp_ports:
            console.print("\n[bold cyan]Phase 6b: JARM TLS Fingerprinting[/bold cyan]")
            console.print("[dim]Sending 10 distinct TLS handshakes to construct backend identity...[/dim]")
            jarm_hashes = {}
            fingerprinter = JARMFingerprinter()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                for port in progress.track(open_tcp_ports, description="Hashing TLS endpoints..."):
                    hash_val = fingerprinter.build_hash(args.target, port)
                    if hash_val:
                        jarm_hashes[str(port)] = hash_val
                        console.print(f"JARM [{port}/tcp]: [magenta]{hash_val}[/magenta]")
                        time.sleep(0.1)
            all_data["JARM_Hashes"] = jarm_hashes
        os_result = None
        if args.os_detect and 'scanner' in locals() and scanner.get_response_data():
            console.print("[bold cyan]🖥️  Phase 4: OS Fingerprinting[/bold cyan]")
            os_engine = OSFingerprintEngine()
            os_result = os_engine.fingerprint_from_multiple_responses(
                scanner.get_response_data()
            )
            all_data["os_detection"] = os_result.to_dict()
            console.print(
                f"  [green]{os_result.os_name}[/green] "
                f"(confidence: {os_result.confidence:.0%})"
            )
            for ev in os_result.evidence[:3]:
                console.print(f"    → {ev}")
            # --osscan-guess: show top-3 fuzzy alternatives when confidence is low
            if getattr(args, "osscan_guess", False) or os_result.confidence < 0.50:
                resp_data = scanner.get_response_data()
                if resp_data:
                    sample = resp_data[0]
                    guesses = os_engine.fingerprint_fuzzy(
                        ttl=sample.get("ttl", 64),
                        window=sample.get("window", 0),
                        df=sample.get("df", True),
                        ip_id=sample.get("ip_id"),
                        top_n=3,
                    )
                    if guesses:
                        console.print("  [dim]Fuzzy guesses (--osscan-guess):[/dim]")
                        for g in guesses:
                            console.print(
                                f"    [dim]{g['os']:35s} {g['confidence']:.0%}[/dim]"
                            )
                    all_data["os_detection"]["fuzzy_guesses"] = guesses
            console.print()
        service_info = {}
        if args.service_detect and open_ports:
            console.print(f"[bold cyan]🔬 Phase 5: Service Detection ({len(open_ports)} ports)[/bold cyan]")
            v_intensity = getattr(args, "version_intensity", 5)

            # Try nmap-service-probes first (4000+ signatures)
            nmap_probes_detector = None
            try:
                from recon.nmap_service_probes import NmapServiceProbesDetector  # type: ignore
                nmap_probes_detector = NmapServiceProbesDetector(
                    intensity=v_intensity,
                    timeout=module_timeout,
                )
                if nmap_probes_detector.is_loaded:
                    console.print(
                        f"  [dim]Using nmap-service-probes database "
                        f"({nmap_probes_detector.probe_count} probes, intensity {v_intensity})[/dim]"
                    )
                else:
                    console.print(
                        "  [dim]nmap-service-probes not found — using built-in signatures. "
                        "Install nmap for 4000+ signatures.[/dim]"
                    )
                    nmap_probes_detector = None
            except Exception as _npe:
                nmap_probes_detector = None

            if v_intensity <= 2:
                console.print(f"  [dim]Intensity {v_intensity}: light probes only (fast)[/dim]")
            elif v_intensity >= 8:
                console.print(f"  [dim]Intensity {v_intensity}: exhaustive probing (slow)[/dim]")

            detector = ServiceDetector(connect_timeout=module_timeout)
            for r in open_ports:
                try:
                    # Try nmap-probes first, fall back to built-in ServiceDetector
                    if nmap_probes_detector:
                        nmap_result = nmap_probes_detector.detect(
                            args.target, r.port,
                            protocol=r.protocol or "tcp"
                        )
                        if nmap_result.service:
                            service_info[r.port] = nmap_result.to_dict()
                            r.service_guess = nmap_result.service
                            r.banner = nmap_result.version or nmap_result.product
                            cpe_str = f" [{nmap_result.cpe[0]}]" if nmap_result.cpe else ""
                            console.print(
                                f"  [green]✓[/green] {r.port}: "
                                f"{nmap_result.product or nmap_result.service} "
                                f"{nmap_result.version} "
                                f"[dim]({nmap_result.match_type} {nmap_result.confidence:.0%})"
                                f"{cpe_str}[/dim]"
                            )
                            continue

                    # Built-in fallback
                    info = detector.detect(args.target, r.port)
                    service_info[r.port] = info.to_dict()
                    r.service_guess = info.service
                    r.banner = info.version or info.product
                    console.print(
                        f"  [green]✓[/green] {r.port}: "
                        f"{info.product or info.service or 'unknown'} "
                        f"{info.version or ''} "
                        f"[dim]({info.confidence:.0%})[/dim]"
                    )
                except Exception as e:
                    console.print(f"  [red]✗[/red] {r.port}: {e}")
            console.print()
        http_ports = [r.port for r in open_ports if r.port in (80, 443, 8080, 8443, 3000, 8000, 8888)]
        if http_ports and (args.full or args.service_detect):
            console.print(f"[bold cyan]\U0001f310 Phase 5b: HTTP Title Capture ({len(http_ports)} ports)[/bold cyan]")
            title_grabber = HTTPTitleGrabber(timeout=module_timeout)
            titles = title_grabber.grab_multiple(args.target, http_ports)
            all_data["http_titles"] = {str(k): v.to_dict() for k, v in titles.items()}
            for port, t in titles.items():
                title_text = t.title or "No title"
                status = f"HTTP {t.status_code}" if t.status_code else ""
                console.print(f"  [green]\u2713[/green] {port}: {title_text} [dim]{status}[/dim]")
            console.print()
        banners = {}
        if args.banner and open_ports:
            console.print(f"[bold cyan]🏷️  Phase 6: Banner Grabbing[/bold cyan]")
            grabber = BannerGrabber(
                delay_seconds=args.banner_delay,
                connect_timeout=module_timeout,
            )
            for r in open_ports:
                try:
                    b = grabber.grab_with_delay(args.target, r.port)
                    banners[r.port] = b.to_dict()
                    if b.version:
                        r.banner = b.version
                    if b.service:
                        r.service_guess = b.service
                    console.print(
                        f"  [green]✓[/green] {r.port}: "
                        f"{b.service or 'unknown'} — {b.version or b.banner_raw or 'no banner'}"
                    )
                except Exception as e:
                    console.print(f"  [red]✗[/red] {r.port}: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Vulnerability Mapping (CPE-aware NVD + ExploitDB)
        # ═══════════════════════════════════════════════
        if getattr(args, "vuln", False) and (banners or service_info):
            console.print("[bold cyan]🔬 Vulnerability Mapping (NVD CPE + CISA KEV)[/bold cyan]")
            try:
                vuln_mapper = VulnerabilityMapper(
                    nvd_api_key=getattr(args, "nvd_api_key", "") or ""
                )
                # Merge banner and service info for the mapper
                _merged_banners = dict(banners)
                for _p, _si in service_info.items():
                    if _p not in _merged_banners:
                        _merged_banners[_p] = _si
                    else:
                        _merged_banners[_p].update(_si)
                vuln_results = vuln_mapper.map_vulnerabilities(_merged_banners)
                total_cves = sum(len(v) for v in vuln_results.values())
                kev_count = sum(
                    1 for vlist in vuln_results.values()
                    for v in vlist if v.get("is_cisa_kev")
                )
                console.print(f"  [green]CVEs found:[/green] {total_cves} | [bold red]CISA KEV:[/bold red] {kev_count}")
                for _port, _cves in vuln_results.items():
                    if _cves:
                        console.print(f"  [bold]Port {_port}:[/bold]")
                        for _c in sorted(_cves, key=lambda x: float(x.get('base_score') or 0), reverse=True)[:5]:
                            _score = _c.get('base_score', 0)
                            _color = "bold red" if float(_score) >= 9 else "red" if float(_score) >= 7 else "yellow" if float(_score) >= 4 else "dim"
                            _kev = " [bold red][KEV][/bold red]" if _c.get('is_cisa_kev') else ""
                            _src = f" [{_c.get('source', 'nvd')}]" if _c.get('source') != 'nvd' else ""
                            console.print(f"    [{_color}]{_c['cve_id']}[/{_color}] CVSS {_score}{_kev}{_src}")
                            if _c.get('description'):
                                console.print(f"    [dim]{_c['description'][:100]}[/dim]")
                all_data["Vulnerability Research"] = {
                    str(p): v for p, v in vuln_results.items()
                }
                # Store serialisable version for exporters (merged into save_data later)
                all_data["vulnerabilities"] = {
                    str(p): v for p, v in vuln_results.items()
                }
            except Exception as e:
                console.print(f"  [red]✗[/red] Vuln mapping failed: {e}")
            console.print()

        # NSE Plugin Script Engine
        if getattr(args, "script", False) and open_ports:
            console.print(f"[bold cyan]🔌 Phase 6.1: NSE Plugin Engine Execution[/bold cyan]")
            try:
                from ops.plugin_loader import NSERunner # type: ignore
                runner = NSERunner()
                console.print(f"  [dim]Loaded {len(runner.plugins)} vulnerability/recon plugins[/dim]")

                # Parse --script-args KEY=VAL,KEY=VAL into a dict
                script_args: dict = {}
                raw_script_args = getattr(args, "script_args", None) or ""
                if raw_script_args:
                    for pair in raw_script_args.split(","):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            script_args[k.strip()] = v.strip()
                    if script_args:
                        console.print(f"  [dim]Script args: {script_args}[/dim]")

                port_data = [r.to_dict() for r in open_ports]
                p_results = runner.execute_all(args.target, port_data, script_args=script_args)
                
                if p_results:
                    for p_name, p_res in p_results.items():
                        if "error" not in p_res:
                            # Safely stringify the result
                            lines = str(p_res).splitlines()
                            console.print(f"    [green]✓[/green] {p_name}:")
                            for line in lines[:5]:
                                console.print(f"      {line}")
                            if len(lines) > 5:
                                console.print(f"      [dim]... (truncated)[/dim]")
                        else:
                            console.print(f"    [red]✗[/red] {p_name}: {p_res.get('error')}")
                else:
                    console.print("  [dim]No applicable scripts or no output generated[/dim]")
                all_data["plugin_execution"] = p_results
            except ImportError:
                console.print("  [yellow]⚠️  Plugin loader module not found, skipping[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Plugin engine failed: {e}")
            console.print()
    
        # Advanced reconnaissance features
        if args.timestamp_analysis and results:
            console.print("[bold cyan]🕰️  Phase 6a: TCP Timestamp Analysis[/bold cyan]")
            try:
                timestamp_analysis = analyze_timestamps_from_scan_results(results)
                if timestamp_analysis.clock_frequency_hz > 0:
                    console.print(f"  [green]Clock Frequency:[/green] {timestamp_analysis.clock_frequency_hz:.1f} Hz")
                    console.print(f"  [green]Estimated Uptime:[/green] {timestamp_analysis.estimated_uptime_hours:.1f} hours")
                    best_os = max(timestamp_analysis.os_confidence, key=timestamp_analysis.os_confidence.get) if timestamp_analysis.os_confidence else "Unknown"
                    console.print(f"  [green]OS Guess:[/green] {best_os}")
                    console.print(f"  [green]VM Detection:[/green] {'Yes' if timestamp_analysis.is_virtual_machine else 'No'}")
                    console.print(f"  [dim]Confidence: {timestamp_analysis.analysis_confidence:.0%}[/dim]")
                    all_data["timestamp_analysis"] = timestamp_analysis.__dict__
                else:
                    console.print("  [yellow]⚠️  Insufficient timestamp data[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Timestamp analysis failed: {e}")
            console.print()
    
        if args.cert_intel:
            console.print("[bold cyan]🔐 Phase 6b: Certificate Intelligence[/bold cyan]")
            try:
                cert_intel = analyze_certificate_intelligence(args.target, 443)
                if cert_intel:
                    console.print(f"  [green]Certificate Issuer:[/green] {cert_intel['leaf_certificate']['issuer_cn']}")
                    console.print(f"  [green]Subdomains Found:[/green] {len(cert_intel['ct_subdomains'])}")
                    console.print(f"  [green]Certificate Count:[/green] {cert_intel['certificate_count']}")
                    console.print(f"  [green]Security Posture:[/green] {cert_intel['security_posture'].get('issuer_quality', 'unknown')}")
                    if cert_intel['ct_subdomains']:
                        console.print(f"  [dim]Subdomains: {', '.join(list(cert_intel['ct_subdomains'])[:5])}[/dim]")
                    all_data["certificate_intelligence"] = cert_intel
                else:
                    console.print("  [yellow]⚠️  No certificate data available[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Certificate analysis failed: {e}")
            console.print()
            
        if getattr(args, "sni_smuggle", False):
            # Attempt smuggling only on standard HTTPS ports if they were open
            tls_ports = [p.port for p in open_ports if p.port in (443, 8443)]
            if tls_ports:
                console.print(f"[bold cyan]🕵️  Phase 6c: SNI Smuggling / Domain Fronting ({len(tls_ports)} ports)[/bold cyan]")
                from evasion.sni_smuggler import SNISmuggler
                smuggler = SNISmuggler(front_domain="www.google.com")
                fronts_to_test = ["www.google.com", "cloudflare.com", "ajax.googleapis.com", "cdn.discordapp.com"]
                
                sni_results = {}
                for port in tls_ports:
                    res = smuggler.probe_front_domains(args.target, port, args.target, fronts_to_test)
                    sni_results[port] = res
                    
                    console.print(f"  [bold]Port {port}[/bold]:")
                    for dom, status in res.items():
                        color = "green" if "Susceptible" in status else "yellow" if "Connected" in status else "dim"
                        console.print(f"    [{color}]{dom}[/{color}]: {status}")
                all_data["sni_smuggling"] = sni_results
                console.print()

        if getattr(args, "icmp_quote", False):
            console.print("[bold cyan]🪞 Phase 6d: ICMP Error Quoting / NAT Leakage Extraction[/bold cyan]")
            from recon.icmp_quoter import ICMPQuoter
            quoter = ICMPQuoter(args.target, timeout=args.timeout)
            
            # Perform targeted traceroute looking for NAT rules rewriting IP headers.
            leaks = quoter.probe_path_leaks(dport=random.randint(33000, 34000))
            
            leak_detected = False
            for ttl, data in leaks.items():
                if data.get("nat_detected", "False").startswith("True"):
                    leak_detected = True
                    console.print(f"  [bold red]🚨 Leak Detected at Hop {ttl}[/bold red] ({data['responding_router']})")
                    console.print(f"      [dim]Quoted Target IP: {data['original_dst_quoted']} (Expected {args.target})[/dim]")
                    console.print(f"      [dim]Reason: {data['nat_detected']}[/dim]")
            
            if not leak_detected:
                console.print("  [green]✓[/green] No routing translation leaks detected along path.")
            console.print()
            all_data["icmp_quotations"] = leaks

        if getattr(args, "clock_skew", False) and results:
            console.print("[bold cyan]⏱️  Phase 7a: TCP Timestamp Clock Skew Analysis[/bold cyan]")
            try:
                from recon.timestamp_analysis import TCPClockAnalyzer
                clock_analyzer = TCPClockAnalyzer()
                # Feed all scan results with latency data into the clock analyzer
                for r in results:
                    if hasattr(r, 'raw_packet') and r.raw_packet:
                        ts_data = clock_analyzer.extract_timestamp_from_packet(r.raw_packet)
                        if ts_data and r.latency_ms:
                            clock_analyzer.add_observation(ts_data[0], ts_data[1], r.latency_ms)
                    elif r.latency_ms and r.latency_ms > 0:
                        # Synthetic observation from latency data
                        import struct
                        pseudo_tsval = int(time.time() * 100) & 0xFFFFFFFF
                        clock_analyzer.add_observation(pseudo_tsval, 0, r.latency_ms)

                clock_result = clock_analyzer.analyze()
                if clock_result.analysis_confidence > 0:
                    console.print(f"  [green]Clock Frequency:[/green] {clock_result.clock_frequency_hz:.1f} Hz")
                    console.print(f"  [green]Estimated Uptime:[/green] {clock_result.estimated_uptime_hours:.1f} hours")
                    console.print(f"  [green]VM Detected:[/green] {'[bold red]Yes[/bold red]' if clock_result.is_virtual_machine else '[green]No[/green]'}")
                    console.print(f"  [green]Clock Consistency:[/green] {clock_result.clock_consistency:.0%}")
                    if clock_result.os_confidence:
                        best_os = max(clock_result.os_confidence.items(), key=lambda x: x[1])
                        console.print(f"  [green]Best OS Match:[/green] {best_os[0]} ({best_os[1]:.0%})")
                    console.print(f"  [dim]Analysis confidence: {clock_result.analysis_confidence:.0%} ({clock_result.observations_count} observations)[/dim]")
                    all_data["clock_skew"] = {
                        "frequency_hz": clock_result.clock_frequency_hz,
                        "uptime_hours": clock_result.estimated_uptime_hours,
                        "is_vm": clock_result.is_virtual_machine,
                        "os_confidence": clock_result.os_confidence,
                        "consistency": clock_result.clock_consistency,
                    }
                else:
                    console.print("  [yellow]⚠️  Insufficient timestamp data for clock skew analysis[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Clock skew analysis failed: {e}")
            console.print()

        if getattr(args, "oob", False):
            console.print("[bold cyan]📡 Phase 7b: Reverse / Out-of-Band Channel Emulation[/bold cyan]")
            try:
                from recon.reverse_oob import ReverseOOBEmulator
                oob_engine = ReverseOOBEmulator(args.target, timeout=args.timeout)
                open_port_list = [p.port for p in open_ports] if open_ports else None
                egress_profile = oob_engine.full_egress_assessment(open_ports=open_port_list)

                console.print(f"  [green]DNS Egress:[/green]   {'[green]Available[/green]' if egress_profile.dns_egress else '[red]Blocked[/red]'}")
                console.print(f"  [green]HTTP Egress:[/green]  {'[green]Available[/green]' if egress_profile.http_egress else '[red]Blocked[/red]'}")
                console.print(f"  [green]HTTPS Egress:[/green] {'[green]Available[/green]' if egress_profile.https_egress else '[red]Blocked[/red]'}")

                reachable_ports = [p for p, v in egress_profile.custom_port_egress.items() if v]
                if reachable_ports:
                    console.print(f"  [green]Reachable Ports:[/green] {', '.join(str(p) for p in reachable_ports)}")

                console.print(f"  [bold]Assessment:[/bold] {egress_profile.assessment}")
                console.print(f"  [dim]{len(egress_profile.oob_results)} OOB probes completed[/dim]")

                all_data["oob_egress"] = {
                    "dns": egress_profile.dns_egress,
                    "http": egress_profile.http_egress,
                    "https": egress_profile.https_egress,
                    "reachable_ports": reachable_ports,
                    "assessment": egress_profile.assessment,
                }
            except Exception as e:
                console.print(f"  [red]✗[/red] OOB emulation failed: {e}")
            console.print()

        if args.ipid_analysis and results:
            console.print("[bold cyan]🆔 Phase 6e: IP ID Sequence Analysis[/bold cyan]")
            try:
                from recon.ipid_analysis import analyze_ipid_from_scan_results
                ipid_analysis = analyze_ipid_from_scan_results(args.target, results)
                if ipid_analysis:
                    console.print(f"  [green]IP ID Pattern:[/green] {ipid_analysis['ip_id_pattern']}")
                    console.print(f"  [green]OS Guess:[/green] {ipid_analysis['os_guess']}")
                    console.print(f"  [green]Zombie Suitability:[/green] {ipid_analysis['zombie_suitability']:.0%}")
                    console.print(f"  [green]Predictable:[/green] {'Yes' if ipid_analysis['is_predictable'] else 'No'}")
                    console.print(f"  [dim]Confidence: {ipid_analysis['analysis_confidence']:.0%}[/dim]")
                    all_data["ipid_analysis"] = ipid_analysis
                else:
                    console.print("  [yellow]⚠️  Insufficient IP ID data[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] IP ID analysis failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Phase 8a: Firewall ACL Inference Engine
        # ═══════════════════════════════════════════════
        if getattr(args, "acl_map", False) and results:
            console.print("[bold cyan]🛡️  Phase 8a: Firewall ACL Inference Engine[/bold cyan]")
            console.print("  [dim]Probing with SYN/ACK/FIN/XMAS/NULL to map firewall rules...[/dim]")
            try:
                from recon.acl_mapper import ACLMapper
                acl_ports = [r.port for r in results[:20]]  # Limit to first 20 ports
                mapper = ACLMapper(args.target, timeout=args.timeout)
                acl_result = mapper.map_ports(acl_ports)

                # Display results
                open_count = sum(1 for a in acl_result.port_acls.values() if a.filter_type.value == "open")
                filtered_count = sum(1 for a in acl_result.port_acls.values() if "filtered" in a.filter_type.value)
                console.print(f"  [green]Open:[/green] {open_count} | [yellow]Filtered:[/yellow] {filtered_count}")

                if acl_result.firewall_summary:
                    console.print(f"  [bold]Summary:[/bold] {acl_result.firewall_summary}")

                for port, acl in sorted(acl_result.port_acls.items()):
                    if acl.notes:
                        console.print(f"    Port {port}: {acl.filter_type.value} ({acl.firewall_type.value})")
                        for note in acl.notes:
                            console.print(f"      [dim]{note}[/dim]")

                console.print(f"  [dim]{acl_result.total_probes} probes sent[/dim]")
                all_data["acl_map"] = acl_result.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] ACL mapping failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Phase 8b: SSH/TLS Deep Crypto Fingerprinting
        # ═══════════════════════════════════════════════
        if getattr(args, "crypto_fp", False) and open_ports:
            console.print("[bold cyan]🔐 Phase 8b: SSH/TLS Deep Negotiation Fingerprinting[/bold cyan]")
            try:
                from recon.crypto_fingerprint import CryptoFingerprinter
                crypto = CryptoFingerprinter(args.target, timeout=args.timeout)
                open_port_nums = [r.port for r in open_ports]
                profile = crypto.fingerprint_all(open_port_nums)

                for port, ssh_fp in profile.ssh_fingerprints.items():
                    console.print(f"  [bold]SSH Port {port}:[/bold]")
                    console.print(f"    Implementation: {ssh_fp.implementation_guess} ({ssh_fp.implementation_confidence:.0%})")
                    if ssh_fp.version_estimate:
                        console.print(f"    Version: {ssh_fp.version_estimate}")
                    console.print(f"    KEX Algorithms: {len(ssh_fp.kex_algorithms)}")
                    console.print(f"    Encryption: {len(ssh_fp.encryption_algorithms_c2s)}")
                    for note in ssh_fp.security_notes:
                        color = "red" if "Weak" in note else "yellow"
                        console.print(f"    [{color}]⚠ {note}[/{color}]")

                for port, tls_fp in profile.tls_fingerprints.items():
                    console.print(f"  [bold]TLS Port {port}:[/bold]")
                    console.print(f"    Protocol: {tls_fp.protocol_version}")
                    console.print(f"    Cipher: {tls_fp.cipher_suite}")
                    console.print(f"    Server: {tls_fp.server_implementation} ({tls_fp.implementation_confidence:.0%})")
                    if tls_fp.certificate_subject:
                        console.print(f"    Cert CN: {tls_fp.certificate_subject}")
                    if tls_fp.certificate_issuer:
                        console.print(f"    Issuer: {tls_fp.certificate_issuer}")
                    if tls_fp.certificate_sans:
                        console.print(f"    SANs: {len(tls_fp.certificate_sans)}")
                    for note in tls_fp.security_notes:
                        color = "red" if "CRITICAL" in note else "yellow"
                        console.print(f"    [{color}]⚠ {note}[/{color}]")

                all_data["crypto_fingerprint"] = profile.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Crypto fingerprinting failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Phase 8c: Application Protocol Deep Probes
        # ═══════════════════════════════════════════════
        if getattr(args, "app_probe", False) and open_ports:
            console.print("[bold cyan]🔍 Phase 8c: Application Protocol Deep Probes[/bold cyan]")
            console.print("  [dim]Probing Redis, MongoDB, Elasticsearch, Docker, K8s, MySQL, PostgreSQL...[/dim]")
            try:
                from recon.app_protocol_probe import AppProtocolProber
                prober = AppProtocolProber(args.target, timeout=args.timeout)
                open_port_nums = [r.port for r in open_ports]
                app_results = prober.probe_all(open_port_nums)

                for port, svc in app_results.services.items():
                    console.print(f"  [bold]Port {port} ({svc.protocol}):[/bold]")
                    if svc.version:
                        console.print(f"    Version: {svc.version}")
                    for key, val in svc.details.items():
                        console.print(f"    {key}: {val}")
                    for note in svc.security_notes:
                        color = "red" if "CRITICAL" in note else "yellow" if "WARNING" in note else "green"
                        console.print(f"    [{color}]{note}[/{color}]")

                console.print(f"  [dim]{app_results.total_probes} probes, {len(app_results.services)} services identified[/dim]")
                all_data["app_probes"] = app_results.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] App protocol probes failed: {e}")
            console.print()
        if args.banner_mutation and open_ports:
            console.print("[bold cyan]🔄 Phase 6d: Banner Mutation Analysis[/bold cyan]")
            try:
                # Use first open TCP port for mutation analysis
                target_port = open_ports[0].port
                console.print(f"  [dim]Analyzing banner mutations on port {target_port}...[/dim]")
                banner_mutation = analyze_banner_mutation(args.target, target_port, args.mutation_delay)
                if banner_mutation:
                    console.print(f"  [green]Mutation Type:[/green] {banner_mutation['mutation_type']}")
                    console.print(f"  [green]Mutation Score:[/green] {banner_mutation['mutation_score']:.0%}")
                    console.print(f"  [green]Timing Difference:[/green] {banner_mutation['timing_difference']:.1f}ms")
                    console.print(f"  [green]Server Changed:[/green] {'Yes' if banner_mutation['signature_difference'] else 'No'}")
                    if banner_mutation['infrastructure_indicators']:
                        for indicator, desc in banner_mutation['infrastructure_indicators'].items():
                            console.print(f"  [cyan]→ {desc}[/cyan]")
                    console.print(f"  [dim]Confidence: {banner_mutation['confidence']:.0%}[/dim]")
                    all_data["banner_mutation"] = banner_mutation
                else:
                    console.print("  [yellow]⚠️  Banner mutation analysis failed[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Banner mutation analysis failed: {e}")
            console.print()
    
        if args.hpack_analysis and open_ports:
            console.print("[bold cyan]🌐 Phase 6e: HTTP/2 HPACK Fingerprinting[/bold cyan]")
            try:
                # Use HTTPS port for HPACK analysis
                https_ports = [r.port for r in open_ports if r.port in (443, 8443)]
                if https_ports:
                    target_port = https_ports[0]
                    console.print(f"  [dim]Analyzing HTTP/2 HPACK patterns on port {target_port}...[/dim]")
                    hpack_fingerprint = analyze_hpack_fingerprint(args.target, target_port)
                    if hpack_fingerprint:
                        console.print(f"  [green]Implementation:[/green] {hpack_fingerprint['implementation_guess']}")
                        console.print(f"  [green]Server Fingerprint:[/green] {hpack_fingerprint['server_fingerprint']}")
                        console.print(f"  [green]Compression Efficiency:[/green] {hpack_fingerprint['compression_efficiency']:.0%}")
                        console.print(f"  [green]Header Order:[/green] {', '.join(hpack_fingerprint['header_order_pattern'][:4])}")
                        console.print(f"  [dim]Confidence: {hpack_fingerprint['confidence']:.0%}[/dim]")
                        all_data["hpack_fingerprint"] = hpack_fingerprint
                    else:
                        console.print("  [yellow]⚠️  HTTP/2 HPACK analysis failed[/yellow]")
                else:
                    console.print("  [yellow]⚠️  No HTTPS ports available for HPACK analysis[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] HPACK analysis failed: {e}")
            console.print()
    
        if args.consistency_analysis and results:
            console.print("[bold cyan]📊 Phase 6f: TTL/IPID Consistency Analysis[/bold cyan]")
            try:
                consistency_analysis = analyze_full_consistency(results)
                if consistency_analysis:
                    ttl_analysis = consistency_analysis['ttl_analysis']
                    console.print(f"  [green]TTL Consistency:[/green] {ttl_analysis['consistency_score']:.0%}")
                    console.print(f"  [green]Backend Diversity:[/green] {consistency_analysis['backend_diversity']} different TTL ranges")
                    console.print(f"  [green]Load Balancing:[/green] {'Detected' if consistency_analysis['load_balancing_detected'] else 'Not detected'}")
                
                    if ttl_analysis['infrastructure_indicators']:
                        console.print("  [cyan]Infrastructure Indicators:[/cyan]")
                        for indicator, desc in ttl_analysis['infrastructure_indicators'].items():
                            console.print(f"    → {desc}")
                        
                    if ttl_analysis['topology_hints']:
                        console.print("  [cyan]Topology Hints:[/cyan]")
                        for hint in ttl_analysis['topology_hints'][:3]:
                            console.print(f"    → {hint}")
                        
                    console.print(f"  [dim]Confidence: {ttl_analysis['confidence']:.0%}[/dim]")
                    all_data["consistency_analysis"] = consistency_analysis
                else:
                    console.print("  [yellow]⚠️  Consistency analysis failed[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Consistency analysis failed: {e}")
            console.print()

        if getattr(args, "contextual_probe", False) and open_ports:
            console.print("[bold cyan]🕵️ Phase 6g: Contextual Discovery Probing[/bold cyan]")
            try:
                target_port = open_ports[0].port
                ctx_result = contextual_probe(args.target, target_port)
                console.print(f"  [green]OS Family:[/green] {ctx_result.os_family.value}")
                console.print(f"  [green]Discovery Method:[/green] {ctx_result.discovery_method}")
                console.print(f"  [green]Stealth Score:[/green] {ctx_result.stealth_score:.2f}")
                all_data["contextual_probe"] = ctx_result.__dict__
            except Exception as e:
                console.print(f"  [red]✗[/red] Contextual probe failed: {e}")
            console.print()
    
        # Advanced Evasion Modules
        if args.urgent_pointer and results:
            console.print("[bold cyan]🔐 Phase 7a: TCP Urgent Pointer Steganography[/bold cyan]")
            try:
                steganography_engine = get_tcp_steganography_engine()
                # Test on first open port
                if open_ports:
                    target_port = open_ports[0].port
                    firewall_result = probe_firewall_types(args.target, target_port)
                    if firewall_result.success:
                        console.print(f"  [green]Firewall behavior:[/green] {firewall_result.firewall_behavior}")
                        console.print(f"  [green]Stealth score:[/green] {firewall_result.stealth_score:.2f}")
                        all_data["urgent_pointer_analysis"] = firewall_result
                    else:
                        console.print("  [yellow]⚠️  Urgent pointer probing failed[/yellow]")
                else:
                    console.print("  [dim]No open ports for urgent pointer analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Urgent pointer analysis failed: {e}")
            console.print()
    
        if args.ip_options and results:
            console.print("[bold cyan]🌐 Phase 7b: IP Options Fingerprinting[/bold cyan]")
            try:
                ip_options_fingerprinter = get_ip_options_fingerprinter()
                # Test on first open port
                if open_ports:
                    target_port = open_ports[0].port
                    options_result = probe_with_ip_options(args.target, target_port)
                    if options_result.response_received:
                        console.print(f"  [green]Option type:[/green] {options_result.option_type}")
                        console.print(f"  [green]Firewall behavior:[/green] {options_result.firewall_behavior}")
                        console.print(f"  [green]Confidence:[/green] {options_result.confidence:.2f}")
                        all_data["ip_options_analysis"] = options_result
                    else:
                        console.print("  [yellow]⚠️  IP options probing failed[/yellow]")
                else:
                    console.print("  [dim]No open ports for IP options analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] IP options analysis failed: {e}")
            console.print()
    
        if args.window_probe and results:
            console.print("[bold cyan]🪟 Phase 7c: TCP Window Probe Sequence[/bold cyan]")
            try:
                window_prober = get_tcp_window_prober()
                # Test on first open port
                if open_ports:
                    target_port = open_ports[0].port
                    window_results = send_window_probe_sequence(args.target, target_port)
                    if window_results:
                        successful_probes = [r for r in window_results if r.response_received]
                        console.print(f"  [green]Successful probes:[/green] {len(successful_probes)}/{len(window_results)}")
                        if successful_probes:
                            os_hints = successful_probes[0].os_hints
                            console.print(f"  [green]OS hints:[/green] {', '.join(os_hints[:3])}")
                            all_data["window_probe_analysis"] = [r.__dict__ for r in window_results]
                    else:
                        console.print("  [yellow]⚠️  Window probing failed[/yellow]")
                else:
                    console.print("  [dim]No open ports for window probing[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Window probing failed: {e}")
            console.print()
    
        if args.protocol_confusion and open_ports:
            console.print("[bold cyan]🔄 Phase 7d: Protocol Confusion Techniques[/bold cyan]")
            try:
                confusion_engine = get_protocol_confusion_engine()
                # Test on SSH ports
                ssh_ports = [r for r in open_ports if r.port in (22, 2222)]
                if ssh_ports:
                    confusion_results = []
                    for ssh_port in ssh_ports[:3]:  # Test first 3 SSH ports
                        result = send_http_to_ssh_port(args.target, ssh_port.port)
                        confusion_results.append(result)
                        if result.response_received:
                            console.print(f"  [green]Port {ssh_port.port}:[/green] {result.service_type} ({result.error_handling})")
                
                    all_data["protocol_confusion_analysis"] = [r.__dict__ for r in confusion_results]
                else:
                    console.print("  [dim]No SSH ports for protocol confusion[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Protocol confusion failed: {e}")
            console.print()
    
        if args.ipv6_tunnel and results:
            console.print("[bold cyan]🌍 Phase 7e: IPv4-in-IPv6 Tunneling[/bold cyan]")
            try:
                ipv6_tunnel_engine = get_ipv6_tunnel_engine()
                # Test tunnel establishment
                tunnel_result = establish_ipv6_tunnel(args.target)
                if tunnel_result.tunnel_established:
                    console.print(f"  [green]Tunnel type:[/green] {tunnel_result.tunnel_type}")
                    console.print(f"  [green]Tunnel ID:[/green] {tunnel_result.tunnel_id}")
                    console.print(f"  [green]Bypass detected:[/green] {tunnel_result.bypass_detected}")
                    all_data["ipv6_tunnel_analysis"] = tunnel_result
                else:
                    console.print("  [yellow]⚠️  IPv6 tunnel establishment failed[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] IPv6 tunneling failed: {e}")
            console.print()

        if getattr(args, "entropy_balance", None) and open_ports:
            console.print(f"[bold cyan]⚖️ Phase 7f: Entropy Balancing Test ({args.entropy_balance})[/bold cyan]")
            try:
                # Generate test payload
                test_data = b"Testing entropy balancing " * 5
                balanced = balance_entropy(test_data, args.entropy_balance, 256)
                analysis = analyze_entropy(balanced)
                console.print(f"  [green]Target Entropy:[/green] {analysis['matches'][args.entropy_balance]['target_entropy']:.2f} bits/byte")
                console.print(f"  [green]Achieved Entropy:[/green] {analysis['entropy_per_byte']:.2f} bits/byte")
                console.print(f"  [green]Match Score:[/green] {analysis['matches'][args.entropy_balance]['match_score']:.2f}")
                all_data["entropy_analysis"] = analysis
            except Exception as e:
                console.print(f"  [red]✗[/red] Entropy balancing failed: {e}")
            console.print()

        if getattr(args, "ja3_rotation", None) and open_ports:
            console.print(f"[bold cyan]🎭 Phase 7g: JA3 Fingerprint Rotation ({args.ja3_rotation})[/bold cyan]")
            try:
                set_browser_fingerprint(args.ja3_rotation)
                fp_info = get_fingerprint_info()
                console.print(f"  [green]Browser:[/green] {fp_info['browser']} {fp_info['version']}")
                console.print(f"  [green]JA3 Hash:[/green] {fp_info['ja3_hash']}")
                console.print(f"  [green]Cipher Suites:[/green] {fp_info['cipher_suites_count']}")
                all_data["ja3_fingerprint"] = fp_info
            except Exception as e:
                console.print(f"  [red]✗[/red] JA3 rotation failed: {e}")
            console.print()

        if getattr(args, "ttl_masquerade", None) and open_ports:
            console.print(f"[bold cyan]👻 Phase 7h: TTL Masquerading Probe ({args.ttl_masquerade})[/bold cyan]")
            try:
                target_port = open_ports[0].port
                ttl_result = ttl_masquerade_probe(args.target, target_port, args.ttl_masquerade)
                if "error" not in ttl_result:
                    analysis_obj = ttl_result.get("analysis")
                    console.print(f"  [green]Hops to Target:[/green] {analysis_obj.hops_to_target if analysis_obj else 'Unknown'}")
                    console.print(f"  [green]Packets Sent:[/green] {ttl_result.get('packets_sent', 0)}")
                    console.print(f"  [green]Responses:[/green] {ttl_result.get('responses_received', 0)}")
                
                    analysis_dict = analysis_obj.__dict__ if hasattr(analysis_obj, "__dict__") else {}
                    all_data["ttl_masquerading"] = {
                        "results": {k: v for k, v in ttl_result.items() if k != "analysis"},
                        "analysis": analysis_dict
                    }
                else:
                    console.print(f"  [yellow]⚠️ TTL Masquerading failed: {ttl_result['error']}[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] TTL masquerading failed: {e}")
            console.print()

        if getattr(args, "ipv6_transition", False):
            console.print("[bold cyan]🔀 Phase 7i: IPv6 Transition Probing[/bold cyan]")
            try:
                from recon.ipv6_transition import probe_ipv6_transition  # type: ignore
                tr = probe_ipv6_transition(args.target)
                if tr.has_6to4:
                    console.print(f"  [green]6to4:[/green] Reachable via {tr.details.get('6to4_reachable', 'yes')}")
                console.print(f"  [dim]6to4: {tr.has_6to4} | Teredo: {tr.has_teredo} | ISATAP: {tr.has_isatap}[/dim]")
                all_data["ipv6_transition"] = tr.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] IPv6 transition probe failed: {e}")
            console.print()

        if getattr(args, "banner_timing", False):
            console.print("[bold cyan]⏱️ Phase 7j: Banner Timing Fingerprint[/bold cyan]")
            try:
                from recon.banner_timing import grab_with_timing  # type: ignore
                port = _probe_tcp_port
                bt = grab_with_timing(args.target, port)
                console.print(f"  [green]Port {port}:[/green] {bt.total_bytes} bytes, {bt.total_time_ms:.1f}ms")
                if bt.fingerprint:
                    console.print(f"  [green]Fingerprint:[/green] {bt.fingerprint}")
                all_data["banner_timing"] = bt.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Banner timing failed: {e}")
            console.print()

        if getattr(args, "icmp_param_problem", False):
            console.print("[bold cyan]📡 Phase 7k: ICMP Parameter Problem Mapping[/bold cyan]")
            try:
                from recon.icmp_param_problem import probe_param_problem  # type: ignore
                pp = probe_param_problem(args.target)
                if pp.firewall_behavior:
                    console.print(f"  [green]Firewall:[/green] {pp.firewall_behavior}")
                console.print(f"  [dim]Probes sent: {len(pp.probes)}[/dim]")
                all_data["icmp_param_problem"] = pp.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] ICMP param probe failed: {e}")
            console.print()

        if getattr(args, "mptcp_probe", False):
            console.print("[bold cyan]🔗 Phase 7l: MPTCP Capability Probe[/bold cyan]")
            try:
                from recon.mptcp_probe import probe_mptcp  # type: ignore
                mp = probe_mptcp(args.target, _probe_tcp_port, timeout=args.timeout, interface=args.interface)
                console.print(f"  [dim]baseline SYN-ACK:[/dim] {mp.get('baseline_synack')} | MPTCP SYN-ACK: {mp.get('mptcp_synack')}")
                if mp.get("middlebox_strips_mptcp") is True:
                    console.print("  [yellow]Possible MPTCP option stripping on path[/yellow]")
                all_data["mptcp_probe"] = mp
            except Exception as e:
                console.print(f"  [red]✗[/red] MPTCP probe failed: {e}")
            console.print()

        if getattr(args, "stun_nat", False):
            console.print("[bold cyan]🌐 Phase 7m: STUN NAT / Egress Mapping[/bold cyan]")
            try:
                from recon.stun_nat_intel import stun_nat_discover  # type: ignore
                st = stun_nat_discover(timeout=args.timeout)
                if st.get("success"):
                    console.print(f"  [green]Public:[/green] {st['public_ip']}:{st['public_port']} via {st.get('stun_server')}")
                else:
                    console.print("  [yellow]STUN binding did not return XOR-MAPPED-ADDRESS[/yellow]")
                all_data["stun_nat"] = st
            except Exception as e:
                console.print(f"  [red]✗[/red] STUN probe failed: {e}")
            console.print()

        if getattr(args, "tcp_exotic_probe", False):
            console.print("[bold cyan]🧪 Phase 7n: Exotic TCP Option Probe[/bold cyan]")
            try:
                from recon.tcp_exotic_probe import probe_exotic_options  # type: ignore
                ex = probe_exotic_options(args.target, _probe_tcp_port, timeout=args.timeout, interface=args.interface)
                for v in ex.get("variants", []):
                    console.print(f"  [dim]{v.get('name')}:[/dim] {v.get('response')}")
                all_data["tcp_exotic_probe"] = ex
            except Exception as e:
                console.print(f"  [red]✗[/red] TCP exotic probe failed: {e}")
            console.print()

        if getattr(args, "dtls_probe", False):
            console.print("[bold cyan]📶 Phase 7o: DTLS UDP Surface Probe[/bold cyan]")
            try:
                from recon.dtls_hello_probe import probe_dtls_udp  # type: ignore
                dt = probe_dtls_udp(args.target, timeout=args.timeout)
                for p, info in dt.get("ports", {}).items():
                    if info.get("bytes", 0) > 0:
                        console.print(f"  [green]UDP {p}:[/green] {info.get('kind')} ({info.get('bytes')} B)")
                all_data["dtls_probe"] = dt
            except Exception as e:
                console.print(f"  [red]✗[/red] DTLS probe failed: {e}")
            console.print()

        if getattr(args, "ssh_intel", False):
            console.print("[bold cyan]🔑 Phase 7p: SSH Banner / KEX Intel[/bold cyan]")
            try:
                from recon.ssh_kex_intel import probe_ssh_intel  # type: ignore
                sp = next((r.port for r in (open_ports or []) if r.port == 22), 22)
                si = probe_ssh_intel(args.target, port=sp, timeout=max(args.timeout, 5.0))
                if si.get("identification"):
                    console.print(f"  [green]ID:[/green] {si['identification'][:120]}")
                if si.get("latency_connect_ms"):
                    console.print(f"  [dim]Connect RTT:[/dim] {si['latency_connect_ms']} ms")
                all_data["ssh_intel"] = si
            except Exception as e:
                console.print(f"  [red]✗[/red] SSH intel failed: {e}")
            console.print()

        if getattr(args, "tls_alpn_probe", False):
            console.print("[bold cyan]📋 Phase 7q: TLS ALPN Surface Probe[/bold cyan]")
            try:
                from recon.tls_alpn_probe import probe_tls_alpn  # type: ignore
                ap = _https_intel_port or 443
                alpn = probe_tls_alpn(args.target, port=ap, timeout=max(args.timeout, 5.0))
                for row in alpn.get("results", []):
                    if row.get("negotiated_alpn"):
                        console.print(f"  [green]{row['profile']}:[/green] {row.get('negotiated_alpn')} ({row.get('tls_version')})")
                    elif row.get("error"):
                        console.print(f"  [dim]{row['profile']}:[/dim] {row['error'][:60]}")
                all_data["tls_alpn_probe"] = alpn
            except Exception as e:
                console.print(f"  [red]✗[/red] TLS ALPN probe failed: {e}")
            console.print()

        if getattr(args, "http_security_intel", False):
            console.print("[bold cyan]🛡️ Phase 7r: HTTP Security Headers[/bold cyan]")
            try:
                from recon.http_security_intel import probe_http_security  # type: ignore
                if _https_intel_port:
                    hi = probe_http_security(args.target, port=_https_intel_port, use_https=True, timeout=max(args.timeout, 8.0))
                elif _http_intel_port:
                    hi = probe_http_security(args.target, port=_http_intel_port, use_https=False, timeout=max(args.timeout, 8.0))
                else:
                    hi = probe_http_security(args.target, port=80, use_https=False, timeout=max(args.timeout, 8.0))
                    if not hi.get("headers") and not hi.get("status"):
                        hi = probe_http_security(args.target, port=443, use_https=True, timeout=max(args.timeout, 8.0))
                if hi.get("headers"):
                    for k, v in list(hi["headers"].items())[:8]:
                        console.print(f"  [green]{k}:[/green] {str(v)[:80]}")
                if hi.get("status"):
                    console.print(f"  [dim]HTTP status:[/dim] {hi['status']}")
                if hi.get("redirect_chain"):
                    console.print(f"  [dim]Redirect chain:[/dim] {len(hi['redirect_chain'])} hops")
                if hi.get("fronting_analysis") and hi["fronting_analysis"].get("cdn_hints"):
                    fa = hi["fronting_analysis"]
                    console.print(f"  [yellow]CDN/fronting:[/yellow] {', '.join(fa.get('cdn_hints', []))}")
                all_data["http_security_intel"] = hi
            except Exception as e:
                console.print(f"  [red]✗[/red] HTTP security intel failed: {e}")
            console.print()

        # Advanced Intelligence Modules
        if args.bgp_intel:
            console.print("[bold cyan]🌐 Phase 8a: BGP Community Intelligence[/bold cyan]")
            try:
                # For demonstration, use a sample ASN
                target_asn = 15169  # Google ASN
                bgp_result = analyze_bgp_communities(args.target, target_asn)
                if bgp_result.datacenter_locations:
                    console.print(f"  [green]Datacenter locations:[/green] {', '.join(bgp_result.datacenter_locations)}")
                    console.print(f"  [green]Load balancer pools:[/green] {len(bgp_result.load_balancer_pools)} detected")
                    all_data["bgp_community_analysis"] = bgp_result
                else:
                    console.print("  [yellow]⚠️  No BGP community data available[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] BGP community analysis failed: {e}")
            console.print()
    
        if args.pdns_timeline:
            console.print("[bold cyan]📅 Phase 8b: Passive DNS Timeline Analysis[/bold cyan]")
            try:
                # For demonstration, use target as domain
                domain = args.target if '.' in args.target else f"{args.target}.com"
                pdns_result = analyze_domain_timeline(domain)
                if pdns_result.infrastructure_events:
                    console.print(f"  [green]Infrastructure events:[/green] {len(pdns_result.infrastructure_events)} found")
                    console.print(f"  [green]Migration timeline:[/green] {len(pdns_result.migration_timeline)} changes")
                    all_data["pdns_timeline_analysis"] = pdns_result
                else:
                    console.print("  [yellow]⚠️  No passive DNS data available[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Passive DNS analysis failed: {e}")
            console.print()
    
        if args.tls_mapper and open_ports:
            console.print("[bold cyan]🔐 Phase 8c: TLS Session Ticket Analysis[/bold cyan]")
            try:
                tls_mapper = get_tls_mapper()
                # Test on HTTPS ports
                https_ports = [r for r in open_ports if r.port in (443, 8443, 8080)]
                if https_ports:
                    https_port = https_ports[0].port
                    lb_result = analyze_load_balancer_pool(args.target, https_port)
                    if lb_result.backend_count > 0:
                        console.print(f"  [green]Backend count:[/green] {lb_result.backend_count}")
                        console.print(f"  [green]Session key sharing:[/green] {lb_result.session_key_sharing}")
                        all_data["tls_session_analysis"] = lb_result
                    else:
                        console.print("  [yellow]⚠️  TLS session analysis failed[/yellow]")
                else:
                    console.print("  [dim]No HTTPS ports for TLS session analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] TLS session analysis failed: {e}")
            console.print()
    
        if args.ipmi_probe:
            console.print("[bold cyan]🖥️  Phase 8d: IPMI Out-of-Band Management Discovery[/bold cyan]")
            try:
                ipmi_prober = get_ipmi_prober()
                ipmi_result = probe_ipmi_interface(args.target)
                if ipmi_result.ipmi_responsive:
                    console.print(f"  [green]IPMI responsive:[/green] True")
                    if ipmi_result.hardware_info:
                        vendor = ipmi_result.hardware_info.get("vendor", "unknown")
                        console.print(f"  [green]Hardware vendor:[/green] {vendor}")
                    all_data["ipmi_analysis"] = ipmi_result
                else:
                    console.print("  [yellow]⚠️  IPMI not responsive[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] IPMI probing failed: {e}")
            console.print()
    
        if args.ntp_intel:
            console.print("[bold cyan]⏰ Phase 8e: NTP Intelligence Fingerprinting[/bold cyan]")
            try:
                ntp_intel = get_ntp_intel()
                ntp_result = gather_ntp_intelligence(args.target)
                if ntp_result.ntp_responsive:
                    console.print(f"  [green]NTP responsive:[/green] True")
                    if ntp_result.software_info:
                        software = ntp_result.software_info.get("software", "unknown")
                        console.print(f"  [green]Software:[/green] {software}")
                    all_data["ntp_analysis"] = ntp_result
                else:
                    console.print("  [yellow]⚠️  NTP not responsive[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] NTP intelligence failed: {e}")
            console.print()
    
        if args.snmp_infer:
            console.print("[bold cyan]🔍 Phase 8f: SNMP Community String Inference[/bold cyan]")
            try:
                snmp_inferencer = get_snmp_inferencer()
                # Use collected intelligence for targeted community strings
                collected_intel = {
                    "organization": "target_org",
                    "location": "target_location"
                }
                snmp_result = infer_snmp_communities(args.target, collected_intel)
                if snmp_result.successful_communities:
                    console.print(f"  [green]Successful communities:[/green] {len(snmp_result.successful_communities)}")
                    if snmp_result.system_description:
                        console.print(f"  [green]System description:[/green] {snmp_result.system_description[:50]}...")
                    all_data["snmp_analysis"] = snmp_result
                else:
                    console.print("  [yellow]⚠️  No SNMP communities found[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] SNMP inference failed: {e}")
            console.print()
    
        if args.cloud_intel:
            console.print("[bold cyan]☁️  Phase 8g: Cloud Provider Metadata Fingerprinting[/bold cyan]")
            try:
                cloud_intel = get_cloud_intel()
                cloud_result = analyze_cloud_provider(args.target)
                if cloud_result.primary_provider:
                    console.print(f"  [green]Cloud provider:[/green] {cloud_result.primary_provider.value}")
                    console.print(f"  [green]Service type:[/green] {cloud_result.primary_service.value if cloud_result.primary_service else 'unknown'}")
                    console.print(f"  [green]Provider confidence:[/green] {cloud_result.provider_confidence:.2f}")
                    all_data["cloud_analysis"] = cloud_result
                else:
                    console.print("  [yellow]⚠️  Cloud provider not identified[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Cloud intelligence failed: {e}")
            console.print()
    
        if args.protocol_downgrade and open_ports:
            console.print("[bold cyan]🔓 Phase 8h: Protocol Downgrade and Weak Configuration Enumeration[/bold cyan]")
            try:
                protocol_enum = get_protocol_enum()
                # Test on HTTPS ports
                https_ports = [r for r in open_ports if r.port in (443, 8443, 8080)]
                if https_ports:
                    https_port = https_ports[0].port
                    downgrade_result = enumerate_protocol_weaknesses(args.target, https_port)
                    if downgrade_result.supported_versions:
                        console.print(f"  [green]Supported TLS versions:[/green] {', '.join(downgrade_result.supported_versions)}")
                        console.print(f"  [green]Weak configurations:[/green] {len(downgrade_result.weak_configurations)} found")
                        all_data["protocol_downgrade_analysis"] = downgrade_result
                    else:
                        console.print("  [yellow]⚠️  Protocol downgrade analysis failed[/yellow]")
                else:
                    console.print("  [dim]No HTTPS ports for protocol analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Protocol downgrade analysis failed: {e}")
            console.print()
    
        if args.rfc_compliance and open_ports:
            console.print("[bold cyan]📋 Phase 8i: RFC Compliance Protocol Fingerprinting[/bold cyan]")
            try:
                rfc_prober = get_rfc_prober()
                # Test on SSH ports
                ssh_ports = [r for r in open_ports if r.port in (22, 2222)]
                if ssh_ports:
                    ssh_port = ssh_ports[0].port
                    rfc_result = probe_rfc_compliance(args.target, ssh_port, Protocol.SSH)
                    console.print(f"  [green]Compliance score:[/green] {rfc_result.compliance_score:.2f}")
                    if rfc_result.version_fingerprint:
                        version_indicators = rfc_result.version_fingerprint.get("version_indicators", [])
                        console.print(f"  [green]Version indicators:[/green] {', '.join(version_indicators[:3])}")
                    all_data["rfc_compliance_analysis"] = rfc_result
                else:
                    console.print("  [dim]No SSH ports for RFC compliance analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] RFC compliance analysis failed: {e}")
            console.print()
    
        # New Advanced Intelligence Techniques
        if args.http2_push and open_ports:
            console.print("[bold cyan]🔄 Phase 9a: HTTP/2 Push Promise Analysis[/bold cyan]")
            try:
                http2_analyzer = get_http2_push_analyzer()
                # Test on HTTPS ports
                https_ports = [r for r in open_ports if r.port in (443, 8443, 8080)]
                if https_ports:
                    https_port = https_ports[0].port
                    push_result = analyze_http2_push_behavior(args.target, https_port)
                    if push_result.server_implementation != "unknown":
                        console.print(f"  [green]Server implementation:[/green] {push_result.server_implementation}")
                        console.print(f"  [green]Push behavior:[/green] {push_result.push_behavior.value}")
                        all_data["http2_push_analysis"] = push_result
                    else:
                        console.print("  [yellow]⚠️  HTTP/2 push analysis failed[/yellow]")
                else:
                    console.print("  [dim]No HTTPS ports for HTTP/2 push analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] HTTP/2 push analysis failed: {e}")
            console.print()
    
        if args.cert_pinning and open_ports:
            console.print("[bold cyan]🔐 Phase 9b: Certificate Pinning Detection[/bold cyan]")
            try:
                cert_detector = get_cert_pinning_detector()
                # Test on HTTPS ports
                https_ports = [r for r in open_ports if r.port in (443, 8443, 8080)]
                if https_ports:
                    https_port = https_ports[0].port
                    pinning_result = detect_certificate_pinning(args.target, https_port)
                    if pinning_result.pinning_behavior.value != "no_pinning":
                        console.print(f"  [green]Pinning behavior:[/green] {pinning_result.pinning_behavior.value}")
                        console.print(f"  [green]Security maturity:[/green] {pinning_result.security_maturity}")
                        console.print(f"  [green]Backend type:[/green] {pinning_result.backend_type}")
                        all_data["cert_pinning_analysis"] = pinning_result
                    else:
                        console.print("  [yellow]⚠️  Certificate pinning analysis failed[/yellow]")
                else:
                    console.print("  [dim]No HTTPS ports for certificate pinning analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Certificate pinning analysis failed: {e}")
            console.print()
    
        if args.quic_version and open_ports:
            console.print("[bold cyan]🚀 Phase 9c: QUIC Version Negotiation Probing[/bold cyan]")
            try:
                quic_prober = get_quic_version_prober()
                # Test on HTTPS ports
                https_ports = [r for r in open_ports if r.port in (443, 8443, 8080)]
                if https_ports:
                    https_port = https_ports[0].port
                    quic_result = probe_quic_versions(args.target, https_port)
                    if quic_result.library_implementation != "unknown":
                        console.print(f"  [green]QUIC library:[/green] {quic_result.library_implementation.value}")
                        console.print(f"  [green]Supported versions:[/green] {', '.join(quic_result.supported_versions)}")
                        all_data["quic_version_analysis"] = quic_result
                    else:
                        console.print("  [yellow]⚠️  QUIC version probing failed[/yellow]")
                else:
                    console.print("  [dim]No HTTPS ports for QUIC version analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] QUIC version probing failed: {e}")
            console.print()
    
        if args.tcp_desync and results:
            console.print("[bold cyan]🔀 Phase 9d: TCP Desync Split-Handshake[/bold cyan]")
            try:
                desync_engine = get_tcp_desync_engine()
                # Test on first open port
                if open_ports:
                    target_port = open_ports[0].port
                    desync_result = perform_split_handshake_desync(args.target, target_port)
                    if desync_result.desync_result.value != "bypass_failed":
                        console.print(f"  [green]Desync result:[/green] {desync_result.desync_result.value}")
                        console.print(f"  [green]Bypass state:[/green] {desync_result.bypass_state_created}")
                        console.print(f"  [green]Firewall confusion:[/green] {desync_result.firewall_confusion}")
                        all_data["tcp_desync_analysis"] = desync_result
                    else:
                        console.print("  [yellow]⚠️  TCP desync failed[/yellow]")
                else:
                    console.print("  [dim]No open ports for TCP desync analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] TCP desync failed: {e}")
            console.print()
    
        if args.http_timing and open_ports:
            console.print("[bold cyan]⏱️ Phase 9e: HTTP Timing Side Channel Analysis[/bold cyan]")
            try:
                timing_analyzer = get_http_timing_analyzer()
                # Test on HTTP ports
                http_ports = [r for r in open_ports if r.port in (80, 8080, 8008, 8081)]
                if http_ports:
                    http_port = http_ports[0].port
                    timing_result = analyze_http_timing_sidechannel(args.target, http_port)
                    if timing_result.processing_paths:
                        console.print(f"  [green]Processing paths:[/green] {', '.join(timing_result.processing_paths)}")
                        console.print(f"  [green]Confidence:[/green] {timing_result.confidence_score:.2f}")
                        all_data["http_timing_analysis"] = timing_result
                    else:
                        console.print("  [yellow]⚠️  HTTP timing analysis failed[/yellow]")
                else:
                    console.print("  [dim]No HTTP ports for timing analysis[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] HTTP timing analysis failed: {e}")
            console.print()
    
        waf_result = None
        if args.waf_detect:
            console.print("[bold cyan]🛡️  Phase 7: WAF Detection[/bold cyan]")
            waf_engine = WAFBypass()
            http_ports = [r for r in open_ports if r.port in (80, 443, 8080, 8443)]
            if not http_ports:
                console.print("  [dim]No HTTP ports open for WAF detection[/dim]")
            elif not banners:
                console.print("  [dim]WAF detection requires --banner to capture HTTP headers — re-run with --banner[/dim]")
            else:
                for hp in http_ports:
                    b = banners.get(hp.port, {})
                    hdrs = b.get("http_headers", {})
                    if hdrs:
                        waf_result = waf_engine.detect_waf(hdrs)
                        all_data["waf_detection"] = waf_result.to_dict()
                        if waf_result.waf_detected:
                            console.print(
                                f"  [yellow]⚠️  {waf_result.waf_name} "
                                f"({waf_result.waf_confidence:.0%})[/yellow]"
                            )
                        else:
                            console.print("  [green]No WAF detected[/green]")
                        break
                else:
                    console.print("  [dim]HTTP ports had no headers captured in banners[/dim]")
            console.print()
        # ═══════════════════════════════════════════════
        # IP Protocol Scan (-sO equivalent)
        # ═══════════════════════════════════════════════
        if getattr(args, "ip_proto_scan", False):
            console.print("[bold cyan]🔬 IP Protocol Scan — All 256 IP Protocol Numbers[/bold cyan]")
            console.print("  [dim]Iterating proto 0-255: finds GRE tunnels, OSPF routers, ESP/AH VPN, EIGRP...[/dim]")
            # Known IP protocol numbers
            PROTO_NAMES = {
                0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IP-in-IP", 6: "TCP",
                8: "EGP", 9: "IGP", 17: "UDP", 27: "RDP", 41: "IPv6",
                43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP",
                47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
                88: "EIGRP", 89: "OSPF", 92: "MTP", 103: "PIM",
                112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDPLite",
            }
            try:
                from scapy.all import IP, ICMP, sr, conf as scapy_conf
                scapy_conf.verb = 0
                proto_results = {}
                answered = []

                # Send in batches to avoid flooding
                for batch_start in range(0, 256, 32):
                    batch = range(batch_start, min(batch_start + 32, 256))
                    pkts = [
                        IP(dst=args.target, proto=p) / (b"\x00" * 4)
                        for p in batch
                        if p not in (6, 17, 132)  # skip TCP/UDP/SCTP — already scanned
                    ]
                    if pkts:
                        ans, _ = sr(pkts, timeout=args.timeout, verbose=0)
                        answered.extend(ans)
                    time.sleep(0.2)

                for sent, recv in answered:
                    proto_num = sent[IP].proto
                    # ICMP type 3 code 2 = protocol unreachable = host knows the proto but closed
                    # Any response at all = the target or path is alive for that protocol
                    if recv.haslayer(ICMP) and recv[ICMP].type == 3:
                        code = recv[ICMP].code
                        if code == 2:  # Protocol unreachable = EXISTS but closed
                            status = "closed"
                        else:
                            status = "filtered"
                    else:
                        status = "open"
                    proto_name = PROTO_NAMES.get(proto_num, f"proto-{proto_num}")
                    proto_results[proto_num] = {
                        "protocol": proto_name,
                        "number": proto_num,
                        "status": status,
                    }

                if proto_results:
                    console.print(f"  [green]Responding protocols:[/green] {len(proto_results)}")
                    for pnum, pdata in sorted(proto_results.items()):
                        status_color = "green" if pdata["status"] == "open" else "yellow" if pdata["status"] == "closed" else "dim"
                        console.print(f"  [{status_color}]{pdata['protocol']:20s}[/{status_color}] (proto {pnum}) — {pdata['status']}")
                else:
                    console.print("  [dim]No protocols responded (all filtered or target unreachable)[/dim]")

                all_data["ip_proto_scan"] = proto_results
            except Exception as e:
                console.print(f"  [red]✗[/red] IP protocol scan failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # SYN Cookie Detection & Server Load Inference
        # ═══════════════════════════════════════════════
        if getattr(args, "syn_cookie_probe", False) and open_ports:
            console.print("[bold cyan]🍪 SYN Cookie Detection — Server Load & OS Fingerprint[/bold cyan]")
            console.print("  [dim]Analysing ISN patterns in SYN-ACK responses to detect SYN cookie mode[/dim]")
            try:
                from recon.syn_cookie_probe import SYNCookieProber  # type: ignore
                cookie_prober = SYNCookieProber(
                    timeout=args.timeout,
                    interface=getattr(args, "interface", None),
                )
                # Probe the first few open TCP ports
                probe_ports = [r.port for r in open_ports if r.protocol == "tcp"][:5]
                cookie_results = cookie_prober.probe_multiple(args.target, probe_ports)
                any_detected = False
                for cr in cookie_results:
                    if cr.cookie_confirmed:
                        any_detected = True
                        det_color = "red" if "linux" in cr.detection_method.value else "yellow"
                        console.print(f"  [bold {det_color}]✔ Port {cr.port}: {cr.detection_method.value}[/bold {det_color}]")
                        if cr.os_guess:
                            console.print(f"    [green]OS:[/green] {cr.os_guess}")
                        if cr.mss_negotiated:
                            console.print(f"    [green]MSS:[/green] {cr.mss_negotiated} bytes (index {cr.mss_index})")
                        for note in cr.notes:
                            console.print(f"    [dim]{note}[/dim]")
                    else:
                        console.print(f"  [dim]Port {cr.port}: No SYN cookies detected[/dim]")
                if not any_detected:
                    console.print("  [green]✓[/green] Server does not appear to use SYN cookies (normal operation)")
                all_data["syn_cookie_probe"] = [
                    cr.to_dict() for cr in cookie_results
                ]
            except Exception as e:
                console.print(f"  [red]✗[/red] SYN cookie probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # GRE Tunnel Evasion Report
        # ═══════════════════════════════════════════════
        if getattr(args, "gre_tunnel", False):
            console.print("[bold cyan]🕸️  GRE Protocol-47 Encapsulation Tunnel[/bold cyan]")
            relay = getattr(args, "gre_relay", None)
            mode = f"via relay {relay}" if relay else "direct (no relay)"
            console.print(f"  [dim]Mode: {mode} — wraps probes in GRE to bypass L4 stateful firewalls[/dim]")
            try:
                from evasion.gre_tunnel import GRETunnelEngine  # type: ignore
                gre = GRETunnelEngine(
                    relay_ip=relay,
                    timeout=args.timeout,
                    interface=getattr(args, "interface", None),
                )
                probe_ports = [r.port for r in open_ports][:10] or [80, 443]
                gre_results = gre.probe_ports(args.target, probe_ports)
                replied = [r for r in gre_results if r.is_open is not None]
                open_gre = [r for r in gre_results if r.is_open is True]
                console.print(f"  [green]Probes sent:[/green] {len(gre_results)}")
                console.print(f"  [green]GRE responses:[/green] {len(replied)} ({len(open_gre)} open)")
                if not relay:
                    console.print("  [yellow]⚠️  Direct mode — no relay. GRE responses only come back if the path passes GRE (proto 47).[/yellow]")
                for gr in open_gre:
                    console.print(f"  [green]✓[/green] Port {gr.port}: open via GRE ({gr.latency_ms:.1f}ms)")
                gre_stats = gre.get_stats()
                all_data["gre_tunnel"] = {
                    "stats": gre_stats,
                    "results": [r.to_dict() for r in gre_results],
                }
            except Exception as e:
                console.print(f"  [red]✗[/red] GRE tunnel failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # IGMP Multicast Host Enumeration
        # ═══════════════════════════════════════════════
        if getattr(args, "igmp_enum", False):
            iface = getattr(args, "interface", None) or "eth0"
            console.print(f"[bold cyan]📡 IGMP Multicast Host Enumeration ({iface})[/bold cyan]")
            console.print("  [dim]Sending IGMP General Query — every RFC-compliant host must respond[/dim]")
            console.print("  [dim]All traffic uses multicast Ethernet — invisible to unicast-only IDS[/dim]")
            try:
                from recon.igmp_enum import IGMPEnumerator  # type: ignore
                igmp = IGMPEnumerator(
                    interface=iface,
                    timeout=args.timeout * 2,
                )
                igmp_hosts = igmp.enumerate()
                igmp_summary = igmp.get_summary()

                console.print(f"  [green]Hosts discovered:[/green] {igmp_summary['total_hosts']}")
                console.print(f"  [green]Routers:[/green] {igmp_summary['routers']}")
                console.print(f"  [green]Workstations:[/green] {igmp_summary['workstations']}")
                console.print(f"  [green]IoT Devices:[/green] {igmp_summary['iot_devices']}")

                if igmp_hosts:
                    console.print("  [bold]Discovered hosts:[/bold]")
                    for h in igmp_hosts:
                        router_tag = " [yellow][ROUTER][/yellow]" if h.is_router else ""
                        mac_str = f" ({h.mac})" if h.mac else ""
                        os_str = f" — {', '.join(h.os_hints[:2])}" if h.os_hints else ""
                        svc_str = f" [{', '.join(h.services[:3])}]" if h.services else ""
                        console.print(f"    [cyan]{h.ip}[/cyan]{mac_str}{router_tag}{os_str}{svc_str}")

                if igmp_summary["groups_observed"]:
                    console.print(f"  [dim]Multicast groups observed: {', '.join(igmp_summary['groups_observed'][:8])}[/dim]")

                all_data["igmp_enum"] = igmp_summary
            except Exception as e:
                console.print(f"  [red]✗[/red] IGMP enumeration failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # VLAN Hopping Injection
        # ═══════════════════════════════════════════════
        if getattr(args, "vlan_hop", False):
            iface = getattr(args, "interface", None) or "eth0"
            outer_v = getattr(args, "vlan_id", 1)
            inner_v = getattr(args, "vlan_target", 100)
            console.print(f"[bold cyan]🏷️  802.1Q VLAN Double-Tagging — VLAN {outer_v} → VLAN {inner_v}[/bold cyan]")
            console.print(f"  [dim]Injecting double-tagged frames on {iface}: outer={outer_v} (native, stripped by switch), inner={inner_v} (target)[/dim]")
            console.print(f"  [yellow]⚠️  ONE-WAY: frames reach VLAN {inner_v} but replies won’t return. Use relay for bidirectional.[/yellow]")
            try:
                from evasion.vlan_hop import VLANHopper  # type: ignore
                hopper = VLANHopper(
                    interface=iface,
                    outer_vlan=outer_v,
                    inner_vlan=inner_v,
                )
                # Run viability check first
                diag = hopper.test_hop_viability()
                if not diag["raw_socket_available"]:
                    console.print("  [red]✗[/red] Raw socket access denied — requires root")
                else:
                    # ARP probe to target
                    console.print(f"  Injecting ARP who-has {args.target} into VLAN {inner_v}...")
                    arp_result = hopper.send_arp_request(args.target)
                    if arp_result.frame_sent:
                        console.print(f"  [green]✓[/green] {arp_result.note}")

                    # SYN inject to first few open ports
                    probe_ports = [r.port for r in open_ports][:5]
                    if probe_ports:
                        console.print(f"  Injecting SYNs to {len(probe_ports)} ports on {args.target}...")
                        vlan_summary = hopper.scan_range([args.target], probe_ports)
                        console.print(f"  [green]✓[/green] {vlan_summary.frames_sent} frames injected into VLAN {inner_v}")
                        for w in diag["warnings"]:
                            console.print(f"  [dim]⚠️  {w}[/dim]")
                        all_data["vlan_hop"] = vlan_summary.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] VLAN hopping failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # ICMP Egress Firewall Mapper (zero TCP/UDP state)
        # ═══════════════════════════════════════════════
        if getattr(args, "icmp_egress_map", False):
            console.print("[bold cyan]📡 ICMP Egress Firewall Policy Mapper[/bold cyan]")
            console.print("  [dim]Sending UDP probes and reading ICMP Unreachable codes — zero TCP/UDP connections established[/dim]")
            try:
                from evasion.icmp_covert_channel import ICMPEgressMapper  # type: ignore
                egress_mapper = ICMPEgressMapper(
                    timeout=args.timeout,
                    interface=getattr(args, "interface", None),
                )
                egress_entries = egress_mapper.map_egress(args.target)
                egress_summary = egress_mapper.summarise(egress_entries)

                alive_color = "green" if egress_summary.get("host_confirmed_alive") else "yellow"
                fw_color = "red" if egress_summary.get("firewall_detected") else "green"
                console.print(f"  [{alive_color}]Host alive confirmed:[/{alive_color}] {egress_summary.get('host_confirmed_alive', False)}")
                console.print(f"  [{fw_color}]Stateful firewall detected:[/{fw_color}] {egress_summary.get('firewall_detected', False)}")
                console.print(f"  [green]Dominant egress policy:[/green] {egress_summary.get('dominant_policy', 'unknown')}")

                policy_dist = egress_summary.get("policy_distribution", {})
                if policy_dist:
                    console.print("  [bold]Policy distribution:[/bold]")
                    for policy, count in sorted(policy_dist.items(), key=lambda x: -x[1]):
                        bar = "█" * count
                        p_color = "red" if "acl" in policy else "green" if "closed" in policy else "yellow"
                        console.print(f"    [{p_color}]{policy:20s}[/{p_color}] {bar} ({count})")

                for note in egress_summary.get("notes", []):
                    console.print(f"  [cyan]→[/cyan] {note}")

                console.print(f"  [dim]{egress_summary.get('probe_count', 0)} ICMP probes analysed[/dim]")
                all_data["icmp_egress_map"] = {
                    "summary": egress_summary,
                    "entries": [{"port": e.port, "icmp_type": e.icmp_type,
                                  "icmp_code": e.icmp_code, "policy": e.policy,
                                  "confidence": e.confidence}
                                 for e in egress_entries],
                }
            except Exception as e:
                console.print(f"  [red]✗[/red] ICMP egress mapping failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # ICMP LSB Steganography Covert Channel
        # ═══════════════════════════════════════════════
        if getattr(args, "icmp_covert", False):
            console.print("[bold cyan]🔮 ICMP LSB Steganography Covert Channel[/bold cyan]")
            bits = getattr(args, "icmp_covert_bits", 2)
            console.print(f"  [dim]Encoding probe data in ping payload LSBs ({bits} bits/byte). Looks like normal Windows pings to DPI.[/dim]")
            try:
                from evasion.icmp_covert_channel import ICMPCovertChannel  # type: ignore
                covert = ICMPCovertChannel(
                    bits_per_byte=bits,
                    interface=getattr(args, "interface", None),
                )
                capacity = covert.capacity_bytes(32)
                console.print(f"  [green]Capacity:[/green] {capacity} bytes per ping ({bits} bits/byte in 32-byte payload)")

                # Send a test probe with encoded target intel summary
                probe_payload = f"{args.target}:{len(open_ports)}open".encode()[:capacity]
                probe_result = covert.send_probe(args.target, probe_payload, timeout=args.timeout)

                if probe_result.got_reply:
                    console.print(f"  [green]✓[/green] Covert ping returned echo-reply — channel viable (TTL={probe_result.ttl_received}, {probe_result.latency_ms:.1f}ms)")
                    decoded = covert.decode_reply(probe_result)
                    if decoded:
                        console.print(f"  [dim]Decoded payload ({len(decoded)}b) verified correct round-trip[/dim]")
                else:
                    console.print(f"  [yellow]⚠️  No ICMP echo reply received — ICMP may be filtered outbound or inbound[/yellow]")

                all_data["icmp_covert"] = {
                    "bits_per_byte": bits,
                    "capacity_bytes": capacity,
                    "probe_success": probe_result.got_reply,
                    "latency_ms": round(probe_result.latency_ms, 2),
                    "ttl_received": probe_result.ttl_received,
                }
            except Exception as e:
                console.print(f"  [red]✗[/red] ICMP covert channel failed: {e}")
            console.print()

        if args.vuln and open_ports and banners:
            console.print("[bold cyan]🚨 Phase 8: Vulnerability Mapping (NVD/CISA KEV)[/bold cyan]")
            nvd_key = getattr(args, "nvd_api_key", None) or ""
            if nvd_key:
                console.print(f"  [dim]Using NVD API key (50 req/30s rate limit)[/dim]")
            mapper = VulnerabilityMapper(nvd_api_key=nvd_key)
            for r in open_ports:
                port = r.port
                cves = []
                if banners.get(port): 
                    cves = mapper.map_vulnerabilities({port: banners.get(port)}).get(port, [])
                if cves:
                    for cve in cves:
                        kev_tag = "[bold yellow]CISA KEV[/bold yellow]" if cve.get("is_cisa_kev") else ""
                        print_cve = f"    - {cve.get('cve_id')} (CVSS {cve.get('base_score')}) {kev_tag}"
                        console.print(print_cve)
                else:
                    console.print(f"  [green]Port {port} — No known CVEs identified[/green]")
            console.print()
        # ═══════════════════════════════════════════════
        # SMB Null Session Enumeration
        # ═══════════════════════════════════════════════
        smb_open = [r for r in open_ports if r.port in (139, 445)]
        if getattr(args, "smb_null", False) and smb_open:
            console.print("[bold cyan]📂 SMB Null Session Enumeration[/bold cyan]")
            try:
                from recon.smb_null_session import SMBNullEnumerator  # type: ignore
                smb_port = 445 if any(r.port == 445 for r in smb_open) else 139
                enumerator = SMBNullEnumerator(timeout=module_timeout)
                smb_result = enumerator.enumerate(args.target, smb_port)
                if smb_result.null_session:
                    console.print(f"  [bold green]✅  Null session ACCEPTED on port {smb_port}[/bold green]")
                    if smb_result.os_version:
                        console.print(f"  [green]OS:[/green] {smb_result.os_version}")
                    if smb_result.server_name:
                        console.print(f"  [green]Server:[/green] {smb_result.server_name}")
                    if smb_result.domain_workgroup:
                        console.print(f"  [green]Domain/Workgroup:[/green] {smb_result.domain_workgroup}")
                    if smb_result.smb_dialect:
                        console.print(f"  [green]Dialect:[/green] {smb_result.smb_dialect}")
                    if smb_result.shares:
                        console.print(f"  [bold]Shares ({len(smb_result.shares)}):[/bold]")
                        for share in smb_result.shares:
                            access_color = "green" if share.access == "READ" else "red" if share.access == "NO_ACCESS" else "yellow"
                            console.print(f"    [{access_color}]{share.name}[/{access_color}] ({share.share_type}) {share.comment}")
                else:
                    console.print(f"  [yellow]⚠️  Null session REJECTED ({smb_result.error or 'anonymous access disabled'})[/yellow]")
                all_data["smb_null_session"] = smb_result.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] SMB null session failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Honeypot / Deception Detection
        # ═══════════════════════════════════════════════
        if getattr(args, "honeypot_detect", False) and results:
            console.print("[bold cyan]🍯 Honeypot / Deception Detection Analysis[/bold cyan]")
            try:
                from recon.honeypot_detect import analyse_honeypot  # type: ignore
                hp_result = analyse_honeypot(
                    target=args.target,
                    scan_results=[r.to_dict() for r in results],
                    banners=banners if banners else None,
                    os_result=os_result.to_dict() if os_result else None,
                )
                verdict_color = "red" if hp_result.is_honeypot else "green"
                conf_pct = f"{hp_result.overall_confidence:.0%}"
                console.print(f"  [{verdict_color}]{'[HONEYPOT]' if hp_result.is_honeypot else '[REAL HOST]'}[/{verdict_color}] "
                              f"{hp_result.verdict} ({conf_pct} confidence)")
                if hp_result.indicators:
                    console.print(f"  [bold]Indicators ({len(hp_result.indicators)}):[/bold]")
                    for ind in sorted(hp_result.indicators, key=lambda i: i.confidence, reverse=True)[:6]:
                        ind_color = "red" if ind.confidence >= 0.75 else "yellow"
                        console.print(f"    [{ind_color}]• {ind.description} ({ind.confidence:.0%})[/{ind_color}]")
                if hp_result.is_honeypot:
                    console.print(f"  [bold red]⚠️  WARNING: Treat all intelligence from this host with extreme caution[/bold red]")
                all_data["honeypot_detection"] = hp_result.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Honeypot detection failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # AI Active Learning Summary
        # ═══════════════════════════════════════════════
        if ai_engine and ai_engine._total_probes > 0:
            console.print("[bold cyan]🧠 AI Active Learning Summary[/bold cyan]")
            ai_summary = ai_engine.get_scan_summary()
            console.print(f"  [green]Probes Analyzed:[/green] {ai_summary['total_probes_analyzed']}")
            console.print(f"  [green]Probes Skipped (low success):[/green] {ai_summary['probes_skipped_by_ai']}")
            console.print(f"  [green]Skip Rate:[/green] {ai_summary['skip_rate']:.1%}")

            ids_stats = ai_summary['ids_learner']
            if ids_stats['detection_events'] > 0:
                console.print(f"  [bold red]IDS Detection Events:[/bold red] {ids_stats['detection_events']}")
                console.print(f"  [bold red]Currently Detected:[/bold red] {'Yes' if ids_stats['currently_detected'] else 'No'}")

            if ids_stats.get('evasion_rankings'):
                console.print(f"  [bold]Top Evasion Combos:[/bold]")
                for combo, score in list(ids_stats['evasion_rankings'].items())[:3]:
                    console.print(f"    {combo}: {score:.0%} effective")

            bm = ai_summary['behavior_model']
            console.print(f"  [green]Mean Latency:[/green] {bm['mean_latency_ms']:.1f}ms")
            console.print(f"  [green]Response Rate:[/green] {bm['response_rate']:.0%}")
            if bm['rate_limit_detected']:
                console.print(f"  [bold yellow]⚠ Rate Limiting Detected[/bold yellow]")
            console.print(f"  [green]Optimal Delay:[/green] {bm['optimal_delay_ms']:.0f}ms")

            all_data["ai_learning"] = ai_summary
            console.print()

        # ═══════════════════════════════════════════════
        # Multi-Signal Intelligence Correlation
        # ═══════════════════════════════════════════════
        if getattr(args, "correlate", False):
            console.print("[bold cyan]🧠 Multi-Signal Intelligence Correlation[/bold cyan]")
            try:
                from ops.correlator import IntelCorrelator
                correlator = IntelCorrelator(args.target)
                # Feed all_data plus scan results
                corr_input = dict(all_data)
                corr_input["scan_results"] = results
                if os_result:
                    corr_input["os_fingerprint"] = os_result.to_dict()
                corr_result = correlator.correlate(corr_input)

                console.print(f"  [bold green]Best OS:[/bold green] {corr_result.best_os} ({corr_result.best_os_confidence:.0%})")
                if len(corr_result.os_candidates) > 1:
                    for cand in corr_result.os_candidates[:3]:
                        signals_str = ", ".join(f"{k}={v:.0%}" for k, v in cand.signals.items())
                        console.print(f"    {cand.name}: {cand.confidence:.0%} [{signals_str}]")

                if corr_result.infrastructure:
                    console.print(f"  [bold]Infrastructure:[/bold]")
                    for node in corr_result.infrastructure:
                        hop_str = f" (hop {node.hop_distance})" if node.hop_distance else ""
                        console.print(f"    {node.role}{hop_str}")

                if corr_result.service_clusters:
                    console.print(f"  [bold]Service Clusters:[/bold]")
                    for cluster in corr_result.service_clusters:
                        console.print(f"    {cluster.service_name}: ports {cluster.ports}")

                for anomaly in corr_result.anomalies:
                    console.print(f"  [bold yellow]⚠ {anomaly}[/bold yellow]")

                console.print(f"  [dim]{corr_result.signals_used} signals correlated[/dim]")
                all_data["correlation"] = corr_result.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Correlation failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Ollama AI Evasion Strategy
        # ═══════════════════════════════════════════════
        if getattr(args, "ollama", False):
            console.print("[bold cyan]🤖 Ollama AI Evasion Analysis[/bold cyan]")
            try:
                from ops.ollama_backend import OllamaBackend  # type: ignore
                ollama = OllamaBackend(
                    model=getattr(args, "ollama_model", None)
                )
                ai_intel = dict(all_data)
                ai_intel["target"] = args.target
                ai_intel["scan_results"] = results
                if os_result:
                    ai_intel["os_fingerprint"] = os_result.to_dict()

                ai_result = ollama.infer_evasion_strategy(ai_intel)
                console.print(f"  [bold]Assessment:[/bold] {ai_result.target_assessment}")
                console.print(f"  [bold]Security Posture:[/bold] {ai_result.security_posture}")
                console.print(f"  [bold]Recommended Profile:[/bold] {ai_result.recommended_profile}")
                console.print(f"  [bold]Model:[/bold] {ai_result.model_used} {'(heuristic)' if ai_result.fallback_used else ''}")
                if ai_result.strategies:
                    console.print(f"  [bold]Top Strategies:[/bold]")
                    for s in ai_result.strategies[:5]:
                        risk_color = "green" if s.detection_risk < 0.3 else "yellow" if s.detection_risk < 0.6 else "red"
                        console.print(
                            f"    #{s.priority} {s.technique}: "
                            f"{s.expected_success:.0%} success, "
                            f"[{risk_color}]{s.detection_risk:.0%} risk[/{risk_color}] — "
                            f"{s.reasoning}"
                        )
                console.print(f"  [dim]{ai_result.inference_time_ms:.0f}ms inference time[/dim]")
                all_data["ollama_ai"] = ai_result.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Ollama inference failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Temporal Timing Summary
        # ═══════════════════════════════════════════════
        if temporal_engine and temporal_engine._circadian.total_samples > 0:
            console.print("[bold cyan]⏱️  Temporal Timing Intelligence[/bold cyan]")
            try:
                t_summary = temporal_engine.get_summary()
                console.print(f"  [green]Samples:[/green] {t_summary['total_samples']}")
                console.print(f"  [green]Baseline Latency:[/green] {t_summary['baseline_latency_ms']:.1f}ms")
                console.print(f"  [green]Current Noise:[/green] {t_summary['current_noise_score']:.0%}")
                console.print(f"  [green]Peaks Detected:[/green] {t_summary['peaks_detected']}")
                if t_summary.get('circadian_profile'):
                    cp = t_summary['circadian_profile']
                    best = cp.get('best_windows', [])
                    if best:
                        console.print(f"  [bold]Best Scan Windows:[/bold]")
                        for w in best[:3]:
                            console.print(f"    {w['day']} {w['hour']:02d}:00 — noise score {w['noise_score']:.2f}")
                all_data["temporal_timing"] = t_summary
            except Exception as e:
                console.print(f"  [red]✗[/red] Temporal analysis failed: {e}")
            console.print()

        # (Intel Graph moved to post-scan output)

        # ═══════════════════════════════════════════════
        # TCP Split Handshake Scan
        # ═══════════════════════════════════════════════
        if getattr(args, "split_handshake", False):
            console.print("[bold cyan]🤝 TCP Split Handshake Scan[/bold cyan]")
            try:
                from evasion.split_handshake import SplitHandshakeScanner  # type: ignore
                splitter = SplitHandshakeScanner(timeout=args.timeout)
                open_port_nums_sh = [r.port for r in results if hasattr(r, 'state') and str(r.state).lower() == 'open']
                for port in open_port_nums_sh[:20]:
                    sh_result = splitter.probe(args.target, port)
                    behavior = sh_result.firewall_behavior
                    icon = "🟢" if sh_result.split_accepted else "🔴"
                    console.print(f"  {icon} Port {port}: {behavior} ({sh_result.latency_ms:.1f}ms)")
                sh_summary = splitter.get_summary()
                console.print(f"  [bold]Stateful FW bypasses:[/bold] {sh_summary['stateful_bypass_count']}/{sh_summary['total_probes']}")
                all_data["split_handshake"] = sh_summary
            except Exception as e:
                console.print(f"  [red]✗[/red] Split handshake failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # IPv6 Extension Header Stuffing
        # ═══════════════════════════════════════════════
        if getattr(args, "ipv6_ext", None):
            depth = args.ipv6_ext
            console.print(f"[bold cyan]📦 IPv6 Extension Header Chain (depth={depth})[/bold cyan]")
            try:
                from evasion.ipv6_ext_stuffer import IPv6ExtStuffer  # type: ignore
                stuffer = IPv6ExtStuffer(timeout=args.timeout)
                open_port_nums_ext = [r.port for r in results if hasattr(r, 'state') and str(r.state).lower() == 'open']
                for port in open_port_nums_ext[:10]:
                    ext_result = stuffer.probe_with_chain(args.target, port, chain_depth=depth)
                    headers = ' → '.join(ext_result.headers_used)
                    console.print(f"  Port {port}: {ext_result.state} ({headers}) IDS evasion={ext_result.ids_evasion_score:.0%}")
                all_data["ipv6_ext_headers"] = stuffer.stats
            except Exception as e:
                console.print(f"  [red]✗[/red] IPv6 ext header probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # TLS 1.3 0-RTT Probing
        # ═══════════════════════════════════════════════
        if getattr(args, "tls_0rtt", False):
            console.print("[bold cyan]⚡ TLS 1.3 0-RTT Probing[/bold cyan]")
            try:
                from evasion.tls_0rtt import TLS0RTTProber  # type: ignore
                prober = TLS0RTTProber(timeout=args.timeout)
                tls_ports = [r.port for r in results if hasattr(r, 'port') and r.port in (443, 8443, 993, 995, 465, 636)]
                if not tls_ports:
                    tls_ports = [443]
                for port in tls_ports:
                    rtt_result = prober.probe(args.target, port)
                    icon = "✅" if rtt_result.early_data_accepted else "⬚" if rtt_result.supports_0rtt else "✗"
                    console.print(f"  {icon} Port {port}: TLS={rtt_result.tls_version}, 0-RTT={'accepted' if rtt_result.early_data_accepted else 'not accepted'} ({rtt_result.latency_ms:.1f}ms)")
                    if rtt_result.response_data:
                        preview = rtt_result.response_data[:100].decode('utf-8', errors='replace').replace('\n', ' ')
                        console.print(f"    [dim]Response: {preview}[/dim]")
                all_data["tls_0rtt"] = [r.to_dict() for r in prober.batch_probe(args.target, tls_ports)]
            except Exception as e:
                console.print(f"  [red]✗[/red] TLS 0-RTT probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Modern Service Detection (gRPC/GraphQL/K8s)
        # ═══════════════════════════════════════════════
        if getattr(args, "modern_detect", False):
            console.print("[bold cyan]🔬 Modern Service Detection[/bold cyan]")
            try:
                from recon.modern_service_detect import ModernServiceDetector  # type: ignore
                detector = ModernServiceDetector(timeout=args.timeout)
                open_port_nums_mod = [r.port for r in results if hasattr(r, 'state') and str(r.state).lower() == 'open']
                all_modern = []
                for port in open_port_nums_mod[:15]:
                    use_tls = port in (443, 8443, 6443)
                    found = detector.probe_all(args.target, port, use_tls=use_tls)
                    for svc in found:
                        console.print(f"  🎯 Port {svc.port}: [bold green]{svc.service_type}[/bold green] v{svc.version} ({svc.latency_ms:.1f}ms)")
                        if svc.metadata:
                            for k, v in list(svc.metadata.items())[:3]:
                                console.print(f"    {k}: {v}")
                        all_modern.append(svc.to_dict())
                if not all_modern:
                    console.print("  [dim]No modern services detected[/dim]")
                all_data["modern_services"] = all_modern
            except Exception as e:
                console.print(f"  [red]✗[/red] Modern service detection failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # HTTP/2 Multiplexed Stream Probing
        # ═══════════════════════════════════════════════
        if getattr(args, "h2_multiplex", False):
            console.print("[bold cyan]🌊 HTTP/2 Multiplexed Stream Probing[/bold cyan]")
            try:
                from evasion.h2_multiplex import H2MultiplexScanner  # type: ignore
                h2_scanner = H2MultiplexScanner(timeout=args.timeout)
                http_ports = [r.port for r in results if hasattr(r, 'port') and r.port in (443, 8443, 80, 8080, 3000, 5000, 8888, 9090)]
                if not http_ports:
                    http_ports = [443]
                for port in http_ports:
                    h2_result = h2_scanner.multiplex_scan(args.target, port, use_tls=(port != 80))
                    if h2_result.h2_supported:
                        console.print(f"  [green]Port {port}: HTTP/2 ✓[/green] — {h2_result.streams_sent} streams, {h2_result.responses_received} responses ({h2_result.total_latency_ms:.0f}ms)")
                        for probe in h2_result.probes[:10]:
                            icon = "✓" if probe.status_code == 200 else "✗"
                            svc = f" [{probe.detected_service}]" if probe.detected_service else ""
                            console.print(f"    {icon} {probe.target_path} → {probe.status_code}{svc}")
                    else:
                        console.print(f"  [dim]Port {port}: HTTP/2 not supported[/dim]")
                    all_data.setdefault("h2_multiplex", []).append(h2_result.to_dict())
            except Exception as e:
                console.print(f"  [red]✗[/red] H2 multiplex failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Phase 30: Advanced Protocol Evasion 
        # ═══════════════════════════════════════════════
        if getattr(args, "quic_churn", False) and open_ports:
            console.print("[bold cyan]🌪️ QUIC Connection ID Churning[/bold cyan]")
            try:
                from evasion.quic_churn import QUICChurnEngine # type: ignore
                churner = QUICChurnEngine(interface=getattr(args, "interface", None))
                udp_ports = [r.port for r in open_ports if r.port in (443, 8443, 8080)]
                if not udp_ports:
                    udp_ports = [443]
                
                quic_payload = b"GET / HTTP/3.0\r\nHost: " + args.target.encode() + b"\r\n\r\n"
                churn_res = churner.send_churn_burst(args.target, udp_ports[0], base_payload=quic_payload, burst_size=5)
                
                console.print(f"  [green]Unique SCIDs used:[/green] {churn_res['unique_scids_used']}")
                console.print(f"  [green]Bypassed tracker:[/green] {'Yes' if churn_res['bypassed'] else 'No'}")
                all_data["quic_churn"] = churn_res
            except Exception as e:
                console.print(f"  [red]✗[/red] QUIC Churn failed: {e}")
            console.print()

        if getattr(args, "ipv6_scramble", False) and open_ports:
            console.print("[bold cyan]🔀 IPv6 Flow Label Randomization[/bold cyan]")
            try:
                from evasion.ipv6_flow_scramble import IPv6FlowScrambler # type: ignore
                scrambler = IPv6FlowScrambler(interface=getattr(args, "interface", None))
                port = open_ports[0].port
                
                import socket
                is_ipv6 = ":" in args.target
                target_ipv6 = args.target if is_ipv6 else socket.getaddrinfo(args.target, None, socket.AF_INET6)[0][4][0]
                
                successes = scrambler.burst_scramble(target_ipv6, port, count=3)
                console.print(f"  [green]Hardware cache scrambled.[/green] {successes}/3 flow probes delivered successfully.")
                all_data["ipv6_scramble"] = {"successes": successes, "target_ipv6": target_ipv6}
            except socket.gaierror:
                console.print("  [yellow]⚠️  Could not resolve IPv6 address for target. Skipping Flow Scrambling.[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] IPv6 Scramble failed: {e}")
            console.print()

        if getattr(args, "tcp_dup_ack", False) and open_ports:
            console.print("[bold cyan]🔄 TCP Duplicate ACK Injection[/bold cyan]")
            try:
                from evasion.tcp_dup_ack import TCPDupAckInjector # type: ignore
                injector = TCPDupAckInjector(interface=getattr(args, "interface", None))
                
                tcp_ports = [r.port for r in open_ports if r.port in (80, 443, 8080, 22)]
                port = tcp_ports[0] if tcp_ports else open_ports[0].port
                
                payload = b"GET / HTTP/1.1\r\nHost: " + args.target.encode() + b"\r\n\r\n"
                inj_result = injector.inject_and_send(args.target, port, payload)
                
                if inj_result["payload_delivered"]:
                    console.print(f"  [green]Fast-Retransmit Spoofing successful.[/green] Delivered payload behind 3 DupACKs.")
                    all_data["tcp_dup_ack"] = inj_result
                else:
                    console.print(f"  [yellow]⚠️  DupACK evasion failed or blocked.[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗[/red] TCP DupACK Injection failed: {e}")
            console.print()

        if getattr(args, "pmtu_blackhole", False):
            console.print("[bold cyan]🕳️ Path MTU Blackholing Discovery[/bold cyan]")
            try:
                from recon.pmtu_blackhole import PMTUBlackholer # type: ignore
                blackholer = PMTUBlackholer(interface=getattr(args, "interface", None))
                
                pmtu_res = blackholer.scan_path(args.target)
                
                if pmtu_res["pmtu_found"]:
                    console.print(f"  [green]Bottleneck Found![/green] Router {pmtu_res['reporting_router']} reported next MTU as {pmtu_res['bottleneck_mtu']}")
                else:
                    console.print(f"  [dim]No MTU filtering enclaves discovered along path.[/dim]")
                    
                all_data["pmtu_blackhole"] = pmtu_res
            except Exception as e:
                console.print(f"  [red]✗[/red] PMTU Blackholing failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Phase 32: Application Layer (L7) Evasion
        # ═══════════════════════════════════════════════
        if getattr(args, "alpn_smuggle", False) and open_ports:
            console.print("[bold cyan]🎭 ALPN Protocol Smuggling (h2 -> http/1.1)[/bold cyan]")
            try:
                from evasion.alpn_smuggler import ALPNSmuggler # type: ignore
                smuggler = ALPNSmuggler(timeout=args.timeout)
                tls_ports = [r.port for r in open_ports if r.port in (443, 8443)]
                port = tls_ports[0] if tls_ports else open_ports[0].port
                
                payload = b"GET / HTTP/1.1\r\nHost: " + args.target.encode() + b"\r\n\r\n"
                res = smuggler.smuggle(args.target, port, payload)
                
                if res["success"]:
                    console.print(f"  [green]Smuggle successful![/green] Negotiated {res['alpn_negotiated']} but got valid HTTP/1.1 response.")
                else:
                    console.print(f"  [yellow]⚠️  ALPN Smuggle blocked or failed:[/yellow] {res.get('error_state', 'No response')}")
                all_data["alpn_smuggle"] = res
            except Exception as e:
                console.print(f"  [red]✗[/red] ALPN Smuggle failed: {e}")
            console.print()

        if getattr(args, "h2_smuggle", False) and open_ports:
            console.print("[bold cyan]🎭 HTTP/2 Request Smuggling (H2.TE)[/bold cyan]")
            try:
                from evasion.h2_smuggler import H2Smuggler # type: ignore
                h2s = H2Smuggler(timeout=args.timeout)
                tls_ports = [r.port for r in open_ports if r.port in (443, 8443)]
                port = tls_ports[0] if tls_ports else open_ports[0].port
                
                res = h2s.smuggle(args.target, port)
                
                if res["bypassed"]:
                    console.print(f"  [green]H2.TE Desync successful![/green] Backend split the smuggled payload.")
                elif res["success"]:
                    console.print(f"  [yellow]⚠️  Request succeeded but no definitive split detected.[/yellow]")
                else:
                    console.print(f"  [dim]H2.TE Smuggling thwarted or unsupported.[/dim]")
                all_data["h2_smuggle"] = res
            except Exception as e:
                console.print(f"  [red]✗[/red] H2 Smuggle failed: {e}")
            console.print()

        if getattr(args, "wss_tunnel", False) and open_ports:
            console.print("[bold cyan]🚇 Persistent WebSocket Encapsulation Tunnel[/bold cyan]")
            try:
                from evasion.wss_tunnel import WebSocketTunnel # type: ignore
                wss = WebSocketTunnel(timeout=args.timeout)
                tls_ports = [r.port for r in open_ports if r.port in (443, 8443, 80, 8080)]
                port = tls_ports[0] if tls_ports else open_ports[0].port
                
                payload = b"GET / HTTP/1.1\r\nHost: " + args.target.encode() + b"\r\n\r\n"
                res = wss.connect_and_smuggle(args.target, port, payload)
                
                if res["ws_upgraded"]:
                    console.print(f"  [green]WSS Tunnel Established.[/green] DPI tracking bypassed.")
                    if res["success"]:
                        console.print(f"  [green]Payload delivered inside WSS frame and valid response received.[/green]")
                else:
                    console.print(f"  [yellow]⚠️  WSS Upgrade failed/rejected.[/yellow]")
                all_data["wss_tunnel"] = res
            except Exception as e:
                console.print(f"  [red]✗[/red] WSS Tunnel failed: {e}")
            console.print()

        # Register target IP with eBPF loader so only RSTs to this host are dropped
        if ebpf_engine and ebpf_engine.is_attached():
            ebpf_engine.add_target(args.target)

        # ═══════════════════════════════════════════════
        # STUN NAT Discovery (pre-scan awareness)
        # ═══════════════════════════════════════════════
        if getattr(args, "stun_nat", False):
            console.print("[bold cyan]📍 STUN NAT Discovery[/bold cyan]")
            try:
                from recon.stun_nat_intel import stun_nat_discover  # type: ignore
                stun_r = stun_nat_discover(timeout=args.timeout)
                if stun_r["success"]:
                    console.print(f"  [green]Public IP:[/green] {stun_r['public_ip']}:{stun_r['public_port']}")
                    console.print(f"  [dim]Via {stun_r['stun_server']}[/dim]")
                    if stun_r['public_ip'] != args.target:
                        console.print("  [yellow]⚠️  Scanner egress IP differs from target — check NAT/proxy config[/yellow]")
                else:
                    console.print("  [dim]STUN discovery inconclusive[/dim]")
                all_data["stun_nat"] = stun_r
            except Exception as e:
                console.print(f"  [red]✗[/red] STUN NAT failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # IPv6 Transition Mechanism Discovery
        # ═══════════════════════════════════════════════
        if getattr(args, "ipv6_transition", False):
            console.print("[bold cyan]🔀 IPv6 Transition Mechanism Discovery[/bold cyan]")
            try:
                from recon.ipv6_transition import probe_ipv6_transition  # type: ignore
                trans_r = probe_ipv6_transition(args.target, timeout=args.timeout)
                console.print(f"  6to4 reachable: {'[green]Yes[/green]' if trans_r.has_6to4 else '[dim]No[/dim]'}")
                console.print(f"  Teredo responsive: {'[green]Yes[/green]' if trans_r.has_teredo else '[dim]No[/dim]'}")
                for k, v in trans_r.details.items():
                    console.print(f"  [dim]{k}: {v}[/dim]")
                all_data["ipv6_transition"] = trans_r.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] IPv6 transition probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # HTTP Security Header Intelligence
        # ═══════════════════════════════════════════════
        if getattr(args, "http_security_intel", False):
            _hsec_port = _https_intel_port or _http_intel_port
            if _hsec_port:
                console.print("[bold cyan]🔐 HTTP Security Header Intelligence[/bold cyan]")
                try:
                    from recon.http_security_intel import probe_http_security  # type: ignore
                    hsec_r = probe_http_security(args.target, _hsec_port, timeout=module_timeout)
                    if hsec_r.get("hsts"):
                        console.print(f"  [green]HSTS:[/green] {hsec_r['hsts']}")
                    if hsec_r.get("csp"):
                        console.print(f"  [green]CSP:[/green] {str(hsec_r['csp'])[:80]}")
                    if hsec_r.get("server"):
                        console.print(f"  [green]Server:[/green] {hsec_r['server']}")
                    if hsec_r.get("x_frame_options"):
                        console.print(f"  [green]X-Frame-Options:[/green] {hsec_r['x_frame_options']}")
                    if hsec_r.get("cdn_hints"):
                        console.print(f"  [yellow]⚠️  CDN hints: {', '.join(hsec_r['cdn_hints'])}[/yellow]")
                    if hsec_r.get("security_score") is not None:
                        score = hsec_r["security_score"]
                        color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
                        console.print(f"  [{color}]Security Score: {score}/100[/{color}]")
                    all_data["http_security_intel"] = hsec_r
                except Exception as e:
                    console.print(f"  [red]✗[/red] HTTP security intel failed: {e}")
                console.print()

        # ═══════════════════════════════════════════════
        # Banner Timing Side-Channel Fingerprint
        # ═══════════════════════════════════════════════
        if getattr(args, "banner_timing", False) and open_ports:
            console.print("[bold cyan]⏱️  Banner Timing Side-Channel[/bold cyan]")
            try:
                from recon.banner_timing import grab_with_timing  # type: ignore
                bt_results = {}
                for _r in open_ports[:5]:  # Limit to 5 ports
                    bt = grab_with_timing(args.target, _r.port, timeout=module_timeout)
                    if bt.fingerprint:
                        match_str = f" → {bt.match} ({bt.match_confidence:.0%})" if bt.match else ""
                        console.print(f"  Port {_r.port}: {bt.fingerprint}{match_str}")
                        bt_results[_r.port] = bt.to_dict()
                all_data["banner_timing"] = bt_results
            except Exception as e:
                console.print(f"  [red]✗[/red] Banner timing failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # ICMP Parameter Problem Firewall Mapping
        # ═══════════════════════════════════════════════
        if getattr(args, "icmp_param_problem", False):
            console.print("[bold cyan]🚦 ICMP Parameter Problem Firewall Mapping[/bold cyan]")
            try:
                from recon.icmp_param_problem import probe_param_problem  # type: ignore
                icmp_pp = probe_param_problem(args.target, timeout=args.timeout)
                if icmp_pp.firewall_behavior:
                    console.print(f"  [green]Behavior:[/green] {icmp_pp.firewall_behavior}")
                for p in icmp_pp.probes:
                    if p.received_icmp:
                        console.print(f"  Opt {p.option_type}: ICMP type={p.icmp_type} code={p.icmp_code} from {p.responder_ip}")
                all_data["icmp_param_problem"] = icmp_pp.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] ICMP param probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # MPTCP MP_CAPABLE Middlebox Detection
        # ═══════════════════════════════════════════════
        if getattr(args, "mptcp_probe", False) and open_ports:
            console.print("[bold cyan]🔀 MPTCP Path Intelligence[/bold cyan]")
            try:
                from recon.mptcp_probe import probe_mptcp  # type: ignore
                _mp_port = next((r.port for r in open_ports if r.port in (443, 80, 22)), open_ports[0].port)
                mp_r = probe_mptcp(args.target, _mp_port, timeout=args.timeout, interface=args.interface)
                console.print(f"  Baseline SYN-ACK: {'[green]Yes[/green]' if mp_r['baseline_synack'] else '[dim]No[/dim]'}")
                console.print(f"  MPTCP SYN-ACK: {'[green]Yes[/green]' if mp_r['mptcp_synack'] else '[dim]No[/dim]'}")
                if mp_r['middlebox_strips_mptcp'] is True:
                    console.print("  [yellow]⚠️  Middlebox strips MPTCP options[/yellow]")
                elif mp_r['middlebox_strips_mptcp'] is False:
                    console.print("  [green]✓[/green] MPTCP transparent path")
                for note in mp_r.get("notes", []):
                    console.print(f"  [dim]{note}[/dim]")
                all_data["mptcp_probe"] = mp_r
            except Exception as e:
                console.print(f"  [red]✗[/red] MPTCP probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Exotic TCP Options Middlebox Mapping
        # ═══════════════════════════════════════════════
        if getattr(args, "tcp_exotic_probe", False) and open_ports:
            console.print("[bold cyan]🧪 Exotic TCP Option Probe[/bold cyan]")
            try:
                from recon.tcp_exotic_probe import probe_exotic_options  # type: ignore
                _ex_port = next((r.port for r in open_ports if r.port in (443, 80, 22)), open_ports[0].port)
                exotic_r = probe_exotic_options(args.target, _ex_port, timeout=args.timeout, interface=args.interface)
                for variant in exotic_r.get("variants", []):
                    resp = variant["response"]
                    color = "green" if resp == "SYN-ACK" else "red" if resp == "RST" else "dim"
                    console.print(f"  {variant['name']:20s}: [{color}]{resp}[/{color}]")
                all_data["tcp_exotic_probe"] = exotic_r
            except Exception as e:
                console.print(f"  [red]✗[/red] Exotic TCP probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # DTLS ClientHello Probe
        # ═══════════════════════════════════════════════
        if getattr(args, "dtls_probe", False):
            console.print("[bold cyan]📡 DTLS ClientHello Probe[/bold cyan]")
            try:
                from recon.dtls_hello_probe import probe_dtls  # type: ignore
                dtls_r = probe_dtls(args.target, timeout=args.timeout)
                for port_r in dtls_r:
                    status = "[green]DTLS handshake[/green]" if port_r.get("dtls_detected") else ("[yellow]alert[/yellow]" if port_r.get("alert") else "[dim]no response[/dim]")
                    console.print(f"  UDP {port_r['port']}: {status}")
                all_data["dtls_probe"] = dtls_r
            except Exception as e:
                console.print(f"  [red]✗[/red] DTLS probe failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # TLS ALPN Protocol Probe
        # ═══════════════════════════════════════════════
        if getattr(args, "tls_alpn_probe", False) and open_ports:
            _tls_ports = [r.port for r in open_ports if r.port in (443, 8443, 4433, 9443)]
            if _tls_ports:
                console.print("[bold cyan]🔒 TLS ALPN Protocol Probe[/bold cyan]")
                try:
                    from recon.tls_alpn_probe import probe_alpn  # type: ignore
                    alpn_results = {}
                    for _tp in _tls_ports[:3]:
                        alpn_r = probe_alpn(args.target, _tp, timeout=module_timeout)
                        if alpn_r:
                            console.print(f"  Port {_tp}: {', '.join(alpn_r.get('negotiated', [])) or 'no ALPN'}")
                            if alpn_r.get("cert_automation"):
                                console.print("    [yellow]⚠️  ACME/Let's Encrypt automation detected[/yellow]")
                            alpn_results[_tp] = alpn_r
                    all_data["tls_alpn_probe"] = alpn_results
                except Exception as e:
                    console.print(f"  [red]✗[/red] TLS ALPN probe failed: {e}")
                console.print()

        # ═══════════════════════════════════════════════
        # SSH KEX Intelligence
        # ═══════════════════════════════════════════════
        if getattr(args, "ssh_intel", False) and open_ports:
            _ssh_ports = [r.port for r in open_ports if r.port in (22, 2222, 22222)] or \
                         [r.port for r in open_ports if (r.service_guess or "").lower() == "ssh"]
            if _ssh_ports:
                console.print("[bold cyan]🔑 SSH KEX Intelligence[/bold cyan]")
                try:
                    from recon.ssh_kex_intel import probe_ssh_kex  # type: ignore
                    ssh_results = {}
                    for _sp in _ssh_ports[:2]:
                        kex_r = probe_ssh_kex(args.target, _sp, timeout=module_timeout)
                        if kex_r:
                            console.print(f"  Port {_sp}: {kex_r.get('server_version', 'unknown')}")
                            if kex_r.get("weak_algorithms"):
                                console.print(f"    [red]⚠️  Weak algorithms: {', '.join(kex_r['weak_algorithms'][:5])}[/red]")
                            ssh_results[_sp] = kex_r
                    all_data["ssh_kex_intel"] = ssh_results
                except Exception as e:
                    console.print(f"  [red]✗[/red] SSH KEX intel failed: {e}")
                console.print()

        # ═══════════════════════════════════════════════
        # HTTP Path Discovery
        # ═══════════════════════════════════════════════
        if getattr(args, "path_scan", False) and open_ports:
            console.print("[bold cyan]🗂️  HTTP Path Discovery[/bold cyan]")
            try:
                from recon.path_scan import scan_all_web_ports  # type: ignore
                _web_open = [r.port for r in open_ports]
                _path_delay = float(getattr(args, "path_delay", 0.2) or 0.2)
                path_results = scan_all_web_ports(args.target, _web_open, timeout=module_timeout, delay_between=_path_delay)
                total_findings = sum(len(r.findings) for r in path_results.values())
                console.print(f"  [green]Web ports probed:[/green] {len(path_results)} | Findings: {total_findings}")
                for port, pr in path_results.items():
                    if pr.findings:
                        console.print(f"  [bold]{pr.scheme}://{args.target}:{port}[/bold]")
                        for f in pr.findings[:15]:
                            sev = "[bold red]" if f.status_code == 200 else "[yellow]"
                            auth = " [dim](auth)[/dim]" if f.requires_auth else ""
                            console.print(f"    {sev}{f.path}[/] → {f.status_code} — {f.description}{auth}")
                all_data["path_scan"] = {str(p): r.to_dict() for p, r in path_results.items()}
            except Exception as e:
                console.print(f"  [red]✗[/red] Path scan failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Service Data Harvesting
        # ═══════════════════════════════════════════════
        if getattr(args, "service_harvest", False) and open_ports:
            console.print("[bold cyan]💎 Service Data Harvesting[/bold cyan]")
            try:
                from recon.service_harvest import harvest_all  # type: ignore
                _harvest_ports = [r.port for r in open_ports]
                harvest_r = harvest_all(args.target, _harvest_ports)
                if harvest_r.findings:
                    for f in harvest_r.findings:
                        sev_color = "bold red" if f.severity == "critical" else "yellow" if f.severity == "high" else "cyan"
                        console.print(f"  [{sev_color}][{f.severity.upper()}][/{sev_color}] {f.service.upper()} (:{f.port}) — {f.summary}")
                        for k, v in list(f.details.items())[:4]:
                            console.print(f"    [dim]{k}: {str(v)[:80]}[/dim]")
                else:
                    console.print("  [dim]No unauthenticated data harvested[/dim]")
                all_data["service_harvest"] = harvest_r.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Service harvest failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Advanced OS Fingerprinting (nmap-parity T1-T7+U1+IE1/IE2)
        # ═══════════════════════════════════════════════
        if getattr(args, "os_probes", False) and open_ports:
            console.print("[bold cyan]🧰 Advanced OS Fingerprinting (T1-T7 + U1 + IE1/IE2)[/bold cyan]")
            try:
                from recon.nmap_os_probes import advanced_os_fingerprint  # type: ignore
                _os_port = next((r.port for r in open_ports if r.port in (80, 443, 22, 445, 3389)), open_ports[0].port)
                console.print(f"  [dim]Using open port {_os_port} for TCP probes[/dim]")
                adv_os = advanced_os_fingerprint(
                    target=args.target,
                    open_port=_os_port,
                    timeout=args.timeout,
                    interface=args.interface,
                )
                _conf_color = "green" if adv_os.confidence >= 0.70 else "yellow" if adv_os.confidence >= 0.40 else "dim"
                console.print(f"  [{_conf_color}]{adv_os.os_name}[/{_conf_color}] ({adv_os.confidence:.0%} confidence)")
                if adv_os.ttl_observed:
                    console.print(f"  TTL={adv_os.ttl_observed} DF={adv_os.df_flag} IP-ID={adv_os.ip_id_behavior}")
                if adv_os.ts_hz_estimate:
                    console.print(f"  TCP TS HZ ≈ {adv_os.ts_hz_estimate:.0f} (clock freq)")
                if adv_os.t7_response != "none":
                    console.print(f"  T7 (FPU): {adv_os.t7_response}")
                for note in adv_os.notes[:4]:
                    console.print(f"  [dim]{note}[/dim]")
                all_data["advanced_os_probes"] = adv_os.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Advanced OS probes failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Interference Detection Report
        # ═══════════════════════════════════════════════
        if interference_detector is not None:
            _int_events = interference_detector.analyze()
            if _int_events:
                console.print("[bold red]🚨 Active Interference Detected[/bold red]")
                for _ev in _int_events:
                    _col = "bold red" if _ev.confidence >= 0.80 else "yellow"
                    console.print(f"  [{_col}]{_ev.interference_type.value}[/{_col}] ({_ev.confidence:.0%}) — {_ev.description}")
                    if _ev.recommended_action:
                        console.print(f"  [dim]→ {_ev.recommended_action}[/dim]")
                # Auto-escalate timing if requested
                if getattr(args, "interference_auto_escalate", False):
                    _rec = interference_detector.get_recommended_profile()
                    if _rec and _rec != args.profile:
                        console.print(f"  [cyan]🔧 Auto-escalating timing: {args.profile} → {_rec}[/cyan]")
                        args.profile = _rec
                all_data["interference_detection"] = interference_detector.summary()
            console.print()

        # ═══════════════════════════════════════════════
        # OPEN_FILTERED second-pass verification
        # ═══════════════════════════════════════════════
        if getattr(args, "verify_filtered", False):
            _of_ports = [r.port for r in results if str(r.state).upper() in ("OPEN_FILTERED", "OPENFILTERED")]
            if _of_ports:
                console.print(f"[bold cyan]🔄 Second-Pass OPEN_FILTERED Verification ({len(_of_ports)} ports)[/bold cyan]")
                try:
                    from ops.export_formats import verify_open_filtered  # type: ignore
                    verified = verify_open_filtered(args.target, _of_ports, timeout=args.timeout)
                    upgraded = sum(1 for v in verified.values() if v == "open")
                    downgraded = sum(1 for v in verified.values() if v == "filtered")
                    console.print(f"  [green]Confirmed OPEN: {upgraded}[/green] | Confirmed FILTERED: {downgraded}")
                    for port, state in verified.items():
                        color = "green" if state == "open" else "dim"
                        console.print(f"  [{color}]{port}: {state}[/{color}]")
                    # Upgrade results list
                    for r in results:
                        if r.port in verified and verified[r.port] == "open":
                            r.state = PortState.OPEN
                    all_data["verified_filtered"] = verified
                except Exception as e:
                    console.print(f"  [red]✗[/red] Verification failed: {e}")
                console.print()

        # ═══════════════════════════════════════════════
        # Phase 34: Zero-Trust Network Access (ZTNA) Evasion
        # ═══════════════════════════════════════════════
        if getattr(args, "ztna_evasion", False) and open_ports:
            console.print("[bold cyan]🛡️  Zero-Trust Network Access (ZTNA) Evader[/bold cyan]")
            try:
                from evasion.ztna_evader import ZTNAEvader # type: ignore
                ztna_evader = ZTNAEvader(timeout=args.timeout)
                # Test on primarily HTTPS or API ports
                https_ports = [r.port for r in open_ports if r.port in (443, 8443, 8080, 4443, 3000, 8000, 8888)]
                if https_ports:
                    target_port = https_ports[0]
                    ztna_result = ztna_evader.probe_and_evade(args.target, target_port)
                    
                    if ztna_result["ztna_detected"]:
                        console.print(f"  [yellow]⚠️  Identity-Aware Proxy Detected:[/yellow] {ztna_result['ztna_detected']}")
                        if ztna_result["bypassed"]:
                            console.print(f"  [green]✅  ZTNA Boundary Bypassed![/green] Method: {ztna_result['bypass_method']}")
                        else:
                            console.print(f"  [red]✗  Bypass failed.[/red] Target is strictly authenticated.")
                    else:
                        console.print("  [dim]Target does not appear to be behind a ZTNA boundary.[/dim]")
                        
                    all_data["ztna_evasion"] = ztna_result
                else:
                    console.print("  [dim]No HTTPS/API ports detected for ZTNA analysis.[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] ZTNA Evasion failed: {e}")
            console.print()

        intel = report_engine.build_intelligence(
            target=args.target,
            scan_results=[r.to_dict() for r in list(results)],
            os_fingerprint=os_result.to_dict() if os_result else None,
            banners=banners,
            service_info=service_info,
            dns_intel=all_data.get("dns_intel"),
            traceroute_data=all_data.get("traceroute"),
            waf_data=all_data.get("waf_detection"),
            host_status=all_data.get("host_status"),
            heat_level=heat_meter.detection_probability(),
            total_packets=scanner.packet_engine.packets_crafted if 'scanner' in locals() else 0,
        )
        report_engine.display_report(intel, console)
        # Apply --output-dir to all export functions by monkey-patching temporarily
        _out_dir = getattr(args, "output_dir", None) or "logs"
        os.makedirs(_out_dir, exist_ok=True)
        if getattr(args, 'format', None):
            if args.format == 'json':
                report_engine.export_json(intel, console, out_dir=_out_dir)
            elif args.format == 'csv':
                report_engine.export_csv(intel, console, out_dir=_out_dir)
            elif args.format == 'html':
                # ReportEngine has no export_html — write a styled standalone HTML page
                out_dir = getattr(args, 'output_dir', None) or 'logs'
                os.makedirs(out_dir, exist_ok=True)
                html_path = os.path.join(out_dir, f"usare_report_{intel.target.replace('.','_')}_{int(intel.scan_start)}.html")
                try:
                    import json as _json
                    intel_json = _json.dumps(intel.to_dict(), indent=2, default=str)
                    html_content = (
                        "<!DOCTYPE html><html lang='en'><head>"
                        "<meta charset='UTF-8'><title>USARE Report</title>"
                        "<style>body{background:#0d0d12;color:#00ffcc;font-family:monospace;padding:20px}"
                        "pre{white-space:pre-wrap;word-break:break-all;background:#111;padding:15px;border:1px solid #00ffcc;border-radius:5px}"
                        "h1{color:#ff0055}</style></head><body>"
                        f"<h1>USARE Intelligence Report — {intel.target}</h1>"
                        f"<pre>{intel_json}</pre></body></html>"
                    )
                    with open(html_path, "w", encoding="utf-8") as hf:
                        hf.write(html_content)
                    console.print(f"  [green]✓[/green] HTML report saved to {html_path}")
                except Exception as html_err:
                    console.print(f"  [red]✗[/red] HTML export failed: {html_err}")
            elif args.format == 'xml':
                report_engine.export_xml(intel, console)
        console.print()
        heat_meter.display(console)
        # Display adaptive strategy summary
        if strategy_controller.change_history:
            console.print()
            console.print("[bold cyan]🎯 Adaptive Strategy Summary[/bold cyan]")
            state = strategy_controller.current_state
            console.print(f"  [green]Final Evasion Level:[/green] {state.evasion_level.name}")
            console.print(f"  [green]Timing Tier:[/green] {state.timing_tier.value}")
            console.print(f"  [green]Escalations:[/green] {state.total_escalations}")
            console.print(f"  [green]De-escalations:[/green] {state.total_de_escalations}")
            console.print(f"  [dim]{len(strategy_controller.change_history)} strategy changes during scan[/dim]")
            all_data["strategy_summary"] = strategy_controller.get_scan_summary()
        
        console.print()
        save_data = intel.to_dict()
        save_data["raw_session"] = scanner.session.export_state() if 'scanner' in locals() else {}
        if "Vulnerability Research" in all_data:
            save_data["Vulnerability Research"] = all_data["Vulnerability Research"]

        # ═══════════════════════════════════════════════
        # Unified Intelligence Graph (Post-Scan)
        # ═══════════════════════════════════════════════
        if getattr(args, "intel_graph", False):
            console.print("[bold cyan]🕸️  Unified Intelligence Graph[/bold cyan]")
            try:
                from ops.intel_graph import IntelGraph  # type: ignore
                graph = IntelGraph()
                graph_data = dict(all_data)
                graph_data["scan_results"] = [r.to_dict() for r in list(results)]
                if os_result:
                    graph_data["os_fingerprint"] = os_result.to_dict()
                graph.ingest_scan_results(args.target, graph_data)

                summary = graph.get_infrastructure_summary()
                console.print(f"  [green]Nodes:[/green] {summary['total_nodes']} | [green]Edges:[/green] {summary['total_edges']}")
                if summary.get('domains'):
                    console.print(f"  [bold]Domains:[/bold] {', '.join(summary['domains'][:5])}")
                if summary.get('organizations'):
                    console.print(f"  [bold]Organizations:[/bold] {', '.join(summary['organizations'][:3])}")
                if summary.get('node_types'):
                    types_str = ', '.join(f"{k}={v}" for k, v in summary['node_types'].items())
                    console.print(f"  [dim]{types_str}[/dim]")

                related = graph.find_related_ips(args.target)
                if related:
                    console.print(f"  [bold yellow]Related IPs (pivot chains):[/bold yellow]")
                    for r in related[:5]:
                        path_str = ' → '.join(r['path'])
                        console.print(f"    {r['ip']} (distance {r['distance']}) via {path_str}")

                all_data["intel_graph"] = graph.to_dict()
                save_data["intel_graph"] = all_data["intel_graph"]
            except Exception as e:
                console.print(f"  [red]✗[/red] Intel graph failed: {e}")
            console.print()

        # Merge all_data into save_data before export
        for _k, _v in all_data.items():
            if _k not in save_data:
                save_data[_k] = _v

        _save(save_data, password, args)

        # ═══════════════════════════════════════════════
        # Nessus / Metasploit XML exports
        # ═══════════════════════════════════════════════
        _exp_dir = getattr(args, "output_dir", None) or "logs"
        if getattr(args, "nessus_export", False):
            console.print("[bold cyan]📋 Nessus .nessus Export[/bold cyan]")
            try:
                from ops.export_formats import export_nessus  # type: ignore
                _nessus_path = export_nessus(save_data, out_dir=_exp_dir)
                console.print(f"  [green]✓[/green] Nessus XML: [cyan]{_nessus_path}[/cyan]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Nessus export failed: {e}")
            console.print()

        if getattr(args, "msf_export", False):
            console.print("[bold cyan]🎯 Metasploit db_import XML Export[/bold cyan]")
            try:
                from ops.export_formats import export_metasploit  # type: ignore
                _msf_path = export_metasploit(save_data, out_dir=_exp_dir)
                console.print(f"  [green]✓[/green] Metasploit XML: [cyan]{_msf_path}[/cyan]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Metasploit export failed: {e}")
            console.print()

        if getattr(args, "sarif_export", False):
            console.print("[bold cyan]🛡️  OASIS SARIF 2.1.0 Export[/bold cyan]")
            try:
                from ops.export_formats import export_sarif  # type: ignore
                _sarif_target = getattr(args, "target", "scan")
                _sarif_fn = os.path.join(_exp_dir, f"usare_{_sarif_target.replace('.', '_')}.sarif")
                _sarif_path = export_sarif(save_data, filename=_sarif_fn)
                console.print(f"  [green]✓[/green] SARIF Report: [cyan]{_sarif_path}[/cyan]")
            except Exception as e:
                console.print(f"  [red]✗[/red] SARIF export failed: {e}")
            console.print()

        if getattr(args, "stix_export", False):
            console.print("[bold cyan]🌐 OASIS STIX 2.1 Threat Bundle Export[/bold cyan]")
            try:
                from ops.export_formats import export_stix  # type: ignore
                _stix_target = getattr(args, "target", "scan")
                _stix_fn = os.path.join(_exp_dir, f"usare_{_stix_target.replace('.', '_')}.stix.json")
                _stix_path = export_stix(save_data, filename=_stix_fn)
                console.print(f"  [green]✓[/green] STIX Bundle: [cyan]{_stix_path}[/cyan]")
            except Exception as e:
                console.print(f"  [red]✗[/red] STIX export failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # BloodHound single-host export
        # ═══════════════════════════════════════════════
        if getattr(args, "bloodhound", False) and not getattr(args, "mesh", False):
            console.print("[bold cyan]🖥️  BloodHound JSON Export[/bold cyan]")
            try:
                from ops.bloodhound_export import export_bloodhound_single  # type: ignore
                _bh_domain = getattr(args, "bh_domain", "corp.local") or "corp.local"
                _bh_files  = export_bloodhound_single(save_data, domain=_bh_domain, out_dir=_exp_dir)
                for _f in _bh_files:
                    console.print(f"  [green]✓[/green] BloodHound: [cyan]{_f}[/cyan]")
                console.print(f"  [dim]Domain: {_bh_domain} | Upload via BloodHound UI → Upload Data[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] BloodHound export failed: {e}")
            console.print()

        # eBPF live stats (shown if attached)
        if ebpf_engine and ebpf_engine.is_attached():
            console.print(f"[dim]🛡️ {ebpf_engine.status_line()}[/dim]")

        # Behavioral camouflage summary
        if behavioral_cam is not None:
            _cam_sum = behavioral_cam.get_summary()
            console.print(
                f"[dim]🥼  Camouflage: {_cam_sum['probes_fired']} probes | "
                f"profile={_cam_sum['profile']}[/dim]"
            )

        # ═══════════════════════════════════════════════
        # NSE-like Script Engine (--script / -sC)
        # ═══════════════════════════════════════════════
        if getattr(args, "script", False) and open_ports:
            console.print("\n[bold cyan]📜 Script Engine (NSE-equivalent)[/bold cyan]")
            try:
                from core.script_engine import ScriptEngine  # type: ignore
                se = ScriptEngine(timeout=module_timeout)
                loaded = se.discover()
                console.print(f"  [dim]Loaded {len(loaded)} scripts from scripts/[/dim]")

                # Build port_data list for scripts
                _port_data = []
                for r in open_ports:
                    _port_data.append({
                        "port": r.port,
                        "service": getattr(r, "service_guess", None) or "",
                        "state": r.state.value if hasattr(r.state, "value") else str(r.state),
                    })

                _script_args = ScriptEngine.parse_script_args(
                    getattr(args, "script_args", None)
                )

                script_results = se.run_all(args.target, _port_data, _script_args)
                _script_data = {}
                for sr in script_results:
                    icon = "[green]✓[/green]" if sr.success else "[red]✗[/red]"
                    console.print(f"  {icon} [bold]{sr.script_name}[/bold] ({sr.elapsed_ms:.0f}ms)")
                    if sr.success and sr.output:
                        # Show compact output summary
                        for k, v in sr.output.items():
                            if k == "note":
                                console.print(f"    [dim]{v}[/dim]")
                            elif isinstance(v, dict):
                                for sk, sv in list(v.items())[:4]:
                                    console.print(f"    [cyan]{sk}:[/cyan] {sv}")
                            elif isinstance(v, list):
                                for item in v[:3]:
                                    console.print(f"    → {item}")
                            else:
                                console.print(f"    [cyan]{k}:[/cyan] {v}")
                    elif sr.error:
                        console.print(f"    [dim red]{sr.error}[/dim red]")

                    _script_data[sr.script_name] = sr.to_dict()

                all_data["scripts"] = _script_data
            except Exception as e:
                console.print(f"  [red]✗[/red] Script engine failed: {e}")
                if args.verbose:
                    import traceback; traceback.print_exc()
            console.print()

        # ═══════════════════════════════════════════════
        # eBGP Topology Intelligence
        # ═══════════════════════════════════════════════
        if getattr(args, "ebgp", False):
            console.print("[bold cyan]🌍 Real eBGP Topology Intelligence[/bold cyan]")
            try:
                from evasion.ebgp_peer import ebgp_recon
                _host = getattr(args, "ebgp_collector", None)
                _asn = getattr(args, "ebgp_asn", 65000)
                
                with console.status("[dim]Establishing BGP session with route collector...[/dim]"):
                    bgp_intel = ebgp_recon(args.target, collector_host=_host, local_asn=_asn, duration=15.0)
                    
                if bgp_intel.covering_prefixes:
                    console.print(f"  [green]Upstream Providers:[/green] {', '.join(str(a) for a in bgp_intel.upstream_providers)}")
                    console.print(f"  [green]Path Diversity:[/green] {bgp_intel.path_diversity} unique routes")
                    console.print(f"  [green]Multi-homed:[/green] {bgp_intel.is_multi_homed}")
                    console.print(f"  [green]Anycast Detected:[/green] {bgp_intel.is_anycast}")
                    if bgp_intel.anomalies:
                        for anomaly in bgp_intel.anomalies:
                            console.print(f"  [bold yellow]⚠️ {anomaly}[/bold yellow]")
                    console.print(f"  [dim]Found {len(bgp_intel.covering_prefixes)} covering prefixes[/dim]")
                    all_data["ebgp_topology"] = bgp_intel.to_dict()
                else:
                    console.print("  [yellow]No BGP data available for target[/yellow]")
            except ImportError:
                console.print("  [red]✗[/red] Please ensure evasion/ebgp_peer.py exists with ebgp_recon")
            except Exception as e:
                console.print(f"  [red]✗[/red] eBGP peering failed: {e}")
            console.print()

        # ═══════════════════════════════════════════════
        # Scan Diff (compare with previous scan)
        # ═══════════════════════════════════════════════
        if getattr(args, "diff", None):
            console.print("[bold cyan]📊 Scan Diff (change tracking)[/bold cyan]")
            try:
                from ops.scan_diff import ScanDiffEngine  # type: ignore
                from ops.encryption import load_encrypted  # type: ignore
                prev_scan = load_encrypted(args.diff, password)
                diff_engine = ScanDiffEngine()
                diff_result = diff_engine.diff(prev_scan, save_data)

                console.print(f"  [bold]{diff_result.summary}[/bold]")
                for change in diff_result.port_changes:
                    icon = "🟢" if change.change_type == "opened" else "🔴" if change.change_type == "closed" else "🟡"
                    sev_color = "red" if change.severity == "critical" else "yellow" if change.severity == "warning" else "dim"
                    console.print(f"  {icon} [{sev_color}]Port {change.port}/{change.protocol}: {change.change_type} ({change.old_value} → {change.new_value})[/{sev_color}]")
                for cert_chg in diff_result.cert_changes:
                    console.print(f"  🔒 [yellow]Port {cert_chg.port}: {cert_chg.change_type} ({cert_chg.old_value} → {cert_chg.new_value})[/yellow]")
                if diff_result.os_change:
                    console.print(f"  🖥️  [yellow]OS changed: {diff_result.os_change[0]} → {diff_result.os_change[1]}[/yellow]")
                if diff_result.firewall_change:
                    console.print(f"  🛡️  [yellow]Firewall changed[/yellow]")
                console.print(f"  [dim]{diff_result.total_changes} total changes[/dim]")
                all_data["diff"] = diff_result.to_dict()
            except Exception as e:
                console.print(f"  [red]✗[/red] Diff failed: {e}")
            console.print()
        # Anti-forensics sanitization if enabled
        if getattr(args, "anti_forensics", False):
            try:
                from ops.anti_forensics import AntiForensicsEngine, AntiForensicsConfig
                af_engine = AntiForensicsEngine(AntiForensicsConfig(
                    sanitize_logs=True, randomize_timestamps=True, clean_exit=True
                ))
                af_engine.activate()
                console.print("[dim]🛡️ Anti-forensics: logs sanitized, clean exit armed[/dim]")
            except Exception:
                pass
        if ebpf_engine:
            ebpf_engine.detach()
        elapsed = time.time() - start_time
        
        # ═══════════════════════════════════════════════
        # Parse Reasons & Save to SQLite DB
        # ═══════════════════════════════════════════════
        try:
            from core.scan_db import ScanDatabase
            db = ScanDatabase()
            scan_id = db.save_scan(
                target=args.target,
                results_json=json.dumps(all_data, default=str),
                profile=args.profile,
                scan_metadata={"elapsed_seconds": elapsed, "heat": heat_meter.heat_level}
            )
            db.close()
            db_msg = f"[magenta]Saved to local SQLite DB (Scan #{scan_id})[/magenta]"
            
            # If reason requested, output the states
            if getattr(args, "reason", False):
                console.print("[bold cyan]🔍 Port Reasons:[/bold cyan]")
                for rt in results:
                    console.print(f"  [dim]Port {rt.port}: {rt.state.value} (reason: {rt.reason})[/dim]")
                console.print()
        except Exception as e:
            db_msg = f"[red]DB save failed: {e}[/red]"

        # ═══════════════════════════════════════════════
        # AI Analyst
        # ═══════════════════════════════════════════════
        if getattr(args, "ai_analyst", False):
            console.print("[bold cyan]🤖 AI Post-Scan Analyst[/bold cyan]")
            try:
                from ops.ollama_backend import OllamaBackend
                _model = getattr(args, "ollama_model", None) or "mistral:7b"
                ollama = OllamaBackend(model=_model)
                with console.status("[dim]AI analyzing attack surface...[/dim]"):
                    analysis = ollama.analyze_scan_results(all_data)
                console.print(f"[yellow]{analysis}[/yellow]")
                all_data["ai_analysis"] = analysis
            except Exception as e:
                console.print(f"  [red]✗[/red] AI Analyst failed (is Ollama running?): {e}")
            console.print()

        # Print Greppable Output if requested
        if getattr(args, "greppable", False):
            _open = sum(1 for r in results if r.state.value == "open")
            _fw = sum(1 for r in results if r.state.value == "filtered")
            _os_raw = getattr(args, "os_detect", False) and all_data.get("os_detection", {}).get("os_guess", "Unknown") or "Unknown"
            _os = _os_raw if isinstance(_os_raw, str) else _os_raw.get("os_name", "Unknown")
            print(f"# USARE {args.target} | {args.profile} | {_open} open | FW: {_fw} | OS: {_os} | {elapsed:.1f}s")

        console.print(Panel(
            f"[bold green]✅ Complete in {elapsed:.1f}s[/bold green]\n"
            f"Encrypted: [cyan]{args.output}[/cyan] | \n"
            f"{db_msg} | \n"
            f"Heat: {heat_meter.heat_level}",
            title="[bold]🏁 USARE v2.0[/bold]",
            border_style="green",
        ))
        
    strategy_controller.stop()
        
def _save(data, password, args):
    from ops.encryption import save_encrypted # type: ignore
    save_encrypted(data, password, args.output)
    console.print(f"[dim]💾 Saved → {args.output}[/dim]")
    if args.json_output:
        jp = args.output.replace(".enc", ".json")
        with open(jp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[dim yellow]⚠️  JSON → {jp} (DEBUG)[/dim yellow]")
if __name__ == "__main__":
    main()