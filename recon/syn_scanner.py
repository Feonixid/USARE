import time
import random
import logging
import threading
import asyncio
try:
    import msvcrt
except ImportError:
    msvcrt = None
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from scapy.all import IP, TCP, ICMP, sr1, send, conf
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
from rich.console import Console as RichConsole
from core.packet_engine import PacketEngine, PacketConfig
from evasion.timing import GhostTimer, TimingConfig, TimingProfile
from evasion.fragmentation import FragmentationEngine
from evasion.decoys import DecoyEngine
from evasion.port_shuffle import (
    shuffle_ports,
    shuffle_ports_prioritized,
    generate_port_ranges,
    chunk_ports,
)
from evasion.session import SessionTracker
from ops.heat_meter import HeatMeter
# New contextual probing imports
try:
    from recon.contextual_probe import get_contextual_prober, contextual_probe
    from evasion.ttl_masquerading import get_ttl_engine, ttl_masquerade_probe
    from evasion.multi_path_dispersion import get_proxy_manager, send_with_dispersion
    from evasion.entropy_balancer import get_entropy_balancer, balance_entropy
    HAS_CONTEXTUAL = True
except ImportError:
    HAS_CONTEXTUAL = False
logger = logging.getLogger("usare.scanner")
class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
@dataclass
class ScanResult:
    port: int
    state: PortState
    protocol: str = "tcp"
    ttl_received: Optional[int] = None
    window_received: Optional[int] = None
    latency_ms: Optional[float] = None
    banner: Optional[str] = None
    service_guess: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    scan_method: str = "syn"
    raw_flags: Optional[str] = None
    confidence: float = 0.0
    retries: int = 0
    ip_id_received: Optional[int] = None
    df_flag: Optional[bool] = None
    reason: str = "no-response"
    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state.value,
            "protocol": self.protocol,
            "ttl": self.ttl_received,
            "window": self.window_received,
            "latency_ms": self.latency_ms,
            "banner": self.banner,
            "service": self.service_guess,
            "timestamp": self.timestamp,
            "method": self.scan_method,
            "flags": self.raw_flags,
            "confidence": round(self.confidence, 3),
            "retries": self.retries,
            "ip_id": self.ip_id_received,
            "df": self.df_flag,
        }
SERVICE_MAP: Dict[int, str] = {
    1: "tcpmux", 5: "rje", 7: "echo", 9: "discard",
    11: "systat", 13: "daytime", 17: "qotd", 18: "msp",
    19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 42: "nameserver",
    43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp-server",
    68: "dhcp-client", 69: "tftp", 70: "gopher", 79: "finger",
    80: "http", 81: "http-alt", 88: "kerberos",
    102: "iso-tsap", 104: "dicom", 106: "poppassd",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmp-trap", 163: "cmip-man",
    164: "cmip-agent", 179: "bgp", 194: "irc",
    199: "smux", 201: "at-rtmp", 209: "qmtp",
    210: "z39.50", 220: "imap3", 264: "bgmp",
    389: "ldap", 443: "https", 445: "microsoft-ds",
    464: "kpasswd", 465: "smtps", 497: "retrospect",
    500: "isakmp", 502: "modbus", 512: "exec", 513: "login",
    514: "syslog", 515: "printer", 520: "rip",
    521: "ripng", 540: "uucp", 548: "afp",
    554: "rtsp", 563: "nntps", 587: "submission",
    591: "filemaker", 593: "http-rpc-epmap",
    623: "ipmi", 631: "ipp", 636: "ldaps",
    646: "ldp", 691: "exchange-resync", 860: "iscsi",
    873: "rsync", 902: "vmware-auth", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s",
    1025: "nfs-or-iis", 1080: "socks", 1099: "rmi-registry",
    1194: "openvpn", 1214: "kazaa", 1241: "nessus",
    1311: "rxmon", 1337: "waste", 1433: "ms-sql",
    1434: "ms-sql-m", 1521: "oracle", 1588: "ptp",
    1701: "l2tp", 1723: "pptp", 1741: "cisco-bcast",
    1812: "radius", 1813: "radius-acct",
    1883: "mqtt", 1900: "ssdp", 2000: "cisco-sccp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2100: "amiganetfs", 2181: "zookeeper",
    2222: "directadmin", 2375: "docker",
    2376: "docker-ssl", 2379: "etcd-client",
    2380: "etcd-server", 2483: "oracle-db", 2484: "oracle-dbs",
    2638: "sybase", 3000: "ppp", 3001: "nessus",
    3128: "squid-proxy", 3268: "globalcatLDAP",
    3269: "globalcatLDAPs", 3306: "mysql",
    3389: "ms-wbt-server", 3443: "ov-nnm-websrv",
    3478: "stun", 3544: "teredo", 3689: "daap",
    3690: "svn", 4000: "remoteanything",
    4040: "yo-main", 4100: "netscript",
    4369: "epmd", 4443: "pharos", 4505: "salt-master",
    4506: "salt-minion", 4567: "tram",
    4662: "edonkey", 4848: "glassfish-admin",
    4899: "radmin", 5000: "upnp",
    5001: "commplex-link", 5003: "filemaker",
    5004: "avt-profile-1", 5005: "avt-profile-2",
    5050: "yahoo-im", 5060: "sip", 5061: "sip-tls",
    5190: "aim", 5222: "xmpp-client",
    5223: "xmpp-client-ssl", 5269: "xmpp-server",
    5353: "mdns", 5432: "postgresql", 5500: "vnc-http",
    5631: "pcanywhere-data", 5632: "pcanywhere",
    5672: "amqp", 5683: "coap", 5800: "vnc-http-alt",
    5900: "vnc", 5901: "vnc-1", 5938: "teamviewer",
    5984: "couchdb", 5985: "wsman", 5986: "wsmans",
    6000: "x11", 6001: "x11-1", 6379: "redis",
    6443: "kubernetes-api", 6514: "syslog-tls",
    6660: "irc-alt", 6661: "irc-alt", 6662: "irc-alt",
    6663: "irc-alt", 6664: "irc-alt", 6665: "irc-alt",
    6666: "irc-alt", 6667: "irc", 6668: "irc-alt",
    6669: "irc-alt", 6697: "irc-ssl",
    7000: "afs3-fileserver", 7001: "afs3-callback",
    7070: "realserver", 7443: "oracleas-https",
    7474: "neo4j", 7547: "cwmp", 7680: "pando-pub",
    8000: "http-alt", 8008: "http-alt",
    8009: "ajp13", 8010: "xmpp",
    8042: "yarn-nodemanager", 8080: "http-proxy",
    8081: "http-proxy", 8088: "radan-http",
    8090: "opsmessaging", 8140: "puppet",
    8181: "http-alt", 8200: "vault-api",
    8222: "vmware", 8333: "bitcoin",
    8443: "https-alt", 8500: "consul",
    8834: "nessus-xmlrpc", 8880: "cddbp-alt",
    8888: "http-alt", 8983: "solr",
    9000: "cslistener", 9001: "tor-dir",
    9042: "cassandra", 9043: "websphere",
    9060: "websphere", 9080: "glassfish",
    9090: "zeus-admin", 9091: "xmltec-xmlmail",
    9100: "jetdirect", 9160: "cassandra-thrift",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    9418: "git", 9443: "tungsten-https",
    9500: "ismserver", 9600: "logstash",
    9800: "webdav", 9999: "abyss",
    10000: "webmin", 10001: "scp-config",
    10050: "zabbix-agent", 10051: "zabbix-server",
    10443: "cirrossp", 11211: "memcached",
    11214: "memcached", 11215: "memcached",
    12345: "netbus", 13579: "media-agent",
    14265: "iota", 15672: "rabbitmq-mgmt",
    16993: "amt-soap-https", 17000: "cluster",
    20000: "dnp", 20547: "bacnet",
    25565: "minecraft", 25575: "mcquery",
    27017: "mongodb", 27018: "mongodb-shard",
    27019: "mongodb-config", 28015: "rethinkdb",
    28017: "mongodb-web", 31337: "elite",
    32400: "plex", 33060: "mysqlx",
    44818: "ethernet-ip", 47808: "bacnet",
    49152: "dynamic", 50000: "sap",
    50070: "hdfs-namenode", 50075: "hdfs-datanode",
    54321: "bo2k", 61613: "stomp",
    61616: "activemq",
}
@dataclass
class ScanConfig:
    target_ip: str
    ports: Optional[List[int]] = None
    port_range: str = "1-1024"
    ghost_mode: bool = True
    timing_profile: TimingProfile = TimingProfile.GHOST
    use_fragmentation: bool = True
    frag_strategy: str = "standard"
    use_decoys: bool = True
    decoy_count: int = 5
    use_priority_shuffle: bool = True
    timeout: float = 3.0
    confirm_with_ack: bool = False
    confirm_with_xmas: bool = False
    chunk_size: int = 50
    interface: Optional[str] = None
    verbose: bool = False
    adaptive_timeout: bool = True
    service_detect: bool = False
    os_detect: bool = True
    tcp_desync: bool = False
    desync_mode: str = "adaptive"
    max_retries: int = 3
    ipv6: bool = False
    flow_morph: bool = False
    # New contextual probing options
    use_contextual_probe: bool = False
    contextual_os_hint: Optional[str] = None  # windows, apple, linux, iot, enterprise
    use_ttl_masquerading: bool = False
    ttl_strategy: str = "adaptive"  # ids_only, target_only, dual_packet, adaptive
    use_multi_path: bool = False
    multi_path_config: Optional[str] = None  # Path to proxy config file
    use_entropy_balancing: bool = False
    entropy_target_type: str = "chrome_tls"  # Target traffic type
    flow_morph_profile: str = "chrome"
    overlap: Optional[str] = None
    tunnel: Optional[str] = None
    # When tunnel=https, use JA3 browser stack (same names as --ja3-rotation)
    tunnel_ja3: Optional[str] = None
    traceroute_hops: Optional[int] = None
    wait_for_peak: bool = False
    # Extra delay on top of ghost timer (uniform 0..N seconds) — low-and-slow corridor
    slow_corridor_seconds: float = 0.0
    micro_jitter_ms: float = 0.0

class StealthScanner:
    def __init__(self, config: ScanConfig, heat_meter: Optional[HeatMeter] = None, temporal_engine=None, strategy_controller=None, show_progress: bool = True):
        self.config = config
        self.heat_meter = heat_meter or HeatMeter()
        pkt_config = PacketConfig(
            interface=config.interface,
            verbose=config.verbose,
        )
        self.packet_engine = PacketEngine(pkt_config)
        timing_config = TimingConfig.from_profile(config.timing_profile)
        if config.timing_profile == TimingProfile.ADAPTIVE:
            timing_config.heat_callback = self.heat_meter.detection_probability
        self.timer = GhostTimer(timing_config)
        self.frag_engine = FragmentationEngine(frag_size=8)
        self.decoy_engine = DecoyEngine(self.packet_engine) if config.use_decoys else None
        self.use_ipv6 = getattr(config, 'ipv6', False)
        self.session = SessionTracker(max_retries=config.max_retries)
        self.results: List[ScanResult] = []
        self._start_time: Optional[float] = None
        self._response_data: List[Dict[str, Any]] = []
        self._running: bool = False
        self._show_progress = show_progress
        
        self.temporal_engine = temporal_engine
        if not self.temporal_engine and self.config.wait_for_peak:
            from evasion.temporal_timing import TemporalTimingEngine
            self.temporal_engine = TemporalTimingEngine()
            
        self.strategy_controller = strategy_controller

        self._shaper = None
        if self.config.flow_morph:
            from evasion.flow_morph import FlowShaper, FLOW_TYPE_MAP, FlowType
            profile_enum = FLOW_TYPE_MAP.get(self.config.flow_morph_profile, FlowType.CHROME_HTTPS)
            _ent = (
                self.config.entropy_target_type
                if getattr(self.config, "use_entropy_balancing", False)
                else None
            )
            self._shaper = FlowShaper(profile=profile_enum, entropy_profile=_ent)

        self._tunnel_engine = None
        if self.config.tunnel:
            from evasion.proto_tunnel import create_tunnel
            _t_kw: Dict[str, Any] = {"timeout": self.config.timeout}
            if self.config.tunnel == "https" and getattr(self.config, "tunnel_ja3", None):
                _t_kw["ja3_browser"] = self.config.tunnel_ja3
            self._tunnel_engine = create_tunnel(self.config.tunnel, **_t_kw)

        if not config.verbose:
            conf.verb = 0
            logging.getLogger("scapy").setLevel(logging.ERROR)

    def execute(self) -> List[ScanResult]:
        self._start_time = time.time()
        logger.info(f"[USARE] Starting v2.0 stealth scan against {self.config.target_ip}")
        ports = self._resolve_ports()
        logger.info(f"[USARE] Target ports: {len(ports)} ports to scan")
        self._running = True
        total_ports = len(ports)
        def progress_listener():
            while getattr(self, '_running', False):
                if msvcrt and hasattr(msvcrt, 'kbhit') and getattr(msvcrt, 'kbhit')():
                    key = getattr(msvcrt, 'getch')()
                    if key in (b'\r', b'\n'):
                        start_time = self._start_time or time.time()
                        elapsed = time.time() - start_time
                        done = len(self.results)
                        percent = (done / total_ports) * 100 if total_ports else 100
                        rem = ((total_ports - done) * (elapsed / done)) if done else 0.0
                        print(f"\n[Status] About {percent:.2f}% done; {elapsed:.1f}s elapsed, {rem:.1f}s remaining.")
                time.sleep(0.1)
        if msvcrt:
            pt = threading.Thread(target=progress_listener, daemon=True)
            pt.start()
        if self.config.use_priority_shuffle:
            ports = shuffle_ports_prioritized(ports)
        else:
            ports = shuffle_ports(ports)
        ports = self.session.get_unscanned_ports(self.config.target_ip, ports)
        self._syn_scan_phase(ports)
        if self.config.confirm_with_ack and not self.config.tunnel:
            filtered = [r.port for r in self.results if r.state == PortState.FILTERED]
            if filtered:
                self._ack_scan_phase(filtered)
        if self.config.confirm_with_xmas and not self.config.tunnel:
            targets = [
                r.port for r in self.results
                if r.state in (PortState.OPEN, PortState.FILTERED)
            ]
            if targets:
                self._xmas_null_phase(targets)
        start_time_final = self._start_time or time.time()
        elapsed = time.time() - start_time_final
        decoys = self.decoy_engine.total_decoys_generated if self.decoy_engine else 0
        logger.info(f"[USARE] Scan complete. {len(self.results)} results in {elapsed:.1f}s. Sent {decoys} decoy packets.")
        self._running = False
        return self.results
    def _syn_scan_phase(self, ports: List[int]):
        if self.temporal_engine:
            logger.info("[USARE] Temporal Peak Detection Active: Waiting for noise spike to mask scan...")
            peak_found = self.temporal_engine.wait_for_peak(timeout=300)
            if peak_found:
                logger.warning("[USARE] Peak Noise Detected! Unleashing scan burst while IDS is loaded.")
            else:
                logger.info("[USARE] Peak timeout reached. Proceeding with scan anyway.")

        if not self.config.ghost_mode:
            logger.info("[USARE] Ghost Mode disabled: Engaging Asyncio High-Throughput Engine (Nmap Parity)")
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            loop.run_until_complete(self._syn_scan_phase_async(ports))
            return
            
        chunks = chunk_ports(ports, self.config.chunk_size)
        total_ports = len(ports)
        scanned_count = 0

        # Rich progress bar — only shown in ghost mode (async path has its own concurrency)
        _progress_ctx = None
        _task_id = None
        if self._show_progress and self.config.ghost_mode:
            _console = RichConsole()
            _progress_ctx = Progress(
                TextColumn("  [bold cyan]Scanning[/bold cyan]"),
                BarColumn(bar_width=40, style="cyan", complete_style="green"),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[heat]}"),
                TimeRemainingColumn(),
                console=_console,
                transient=True,
            )
            _progress_ctx.start()
            _task_id = _progress_ctx.add_task(
                "scan", total=total_ports, heat=""
            )

        try:
            for chunk_idx, port_chunk in enumerate(chunks):
                logger.info(
                    f"[USARE] SYN Phase (Ghost) — chunk {chunk_idx + 1}/{len(chunks)} "
                    f"({len(port_chunk)} ports)"
                )
                for port in port_chunk:
                    if self.session.is_scanned(self.config.target_ip, port):
                        scanned_count += 1
                        if _progress_ctx and _task_id is not None:
                            _progress_ctx.update(_task_id, advance=1)
                        continue
                    if not self.session.check_rate_limit():
                        wait_time = self.session.time_until_next_allowed()
                        time.sleep(wait_time)
                    result = self._probe_port_syn_with_retries(port)
                    self.results.append(result)
                    self.session.set_state(
                        self.config.target_ip, port, result.state.value
                    )
                    scanned_count += 1
                    if _progress_ctx and _task_id is not None:
                        heat_str = self.heat_meter.heat_level
                        _progress_ctx.update(_task_id, advance=1, heat=heat_str)
                    if self.config.ghost_mode:
                        base_delay = self.timer.sync_ghost_wait()
                        multiplier = self.strategy_controller.get_timing_multiplier() if self.strategy_controller else 1.0
                        extra_delay = base_delay * (multiplier - 1.0)
                        if extra_delay > 0:
                            time.sleep(extra_delay)
                        sc = float(getattr(self.config, "slow_corridor_seconds", 0.0) or 0.0)
                        if sc > 0:
                            corridor = random.uniform(0.0, sc)
                            time.sleep(corridor)
                            extra_delay += corridor
                        mj = float(getattr(self.config, "micro_jitter_ms", 0.0) or 0.0)
                        if mj > 0:
                            micro = random.uniform(0.0, mj / 1000.0)
                            time.sleep(micro)
                            extra_delay += micro
                        logger.debug(f"[USARE] Ghost delay: {base_delay + extra_delay:.1f}s")
        finally:
            if _progress_ctx:
                _progress_ctx.stop()
                    
    async def _syn_scan_phase_async(self, ports: List[int]):
        chunks = chunk_ports(ports, self.config.chunk_size)
        for chunk_idx, port_chunk in enumerate(chunks):
            logger.info(
                f"[USARE] Async SYN Phase — chunk {chunk_idx + 1}/{len(chunks)} "
                f"({len(port_chunk)} ports concurrently)"
            )
            tasks = []
            for port in port_chunk:
                if self.session.is_scanned(self.config.target_ip, port):
                    continue
                tasks.append(asyncio.to_thread(self._probe_port_syn_with_retries, port))
            
            if tasks:
                chunk_results = await asyncio.gather(*tasks)
                for result in chunk_results:
                    self.results.append(result)
                    self.session.set_state(
                        self.config.target_ip, result.port, result.state.value
                    )
    def set_interference_detector(self, detector) -> None:
        """Attach a live interference detector. Called from usare.py after init."""
        self._interference_detector = detector

    def _feed_interference(self, result: 'ScanResult') -> None:
        """Feed a probe result into the interference detector (if attached)."""
        det = getattr(self, '_interference_detector', None)
        if det is None:
            return
        try:
            from recon.interference_detector import ProbeObservation  # type: ignore
            flags = str(result.raw_flags or "")
            if result.state == PortState.OPEN:
                rtype = "synack"
            elif result.state == PortState.CLOSED:
                rtype = "rst"
            else:
                rtype = "timeout"
            obs = ProbeObservation(
                port=result.port,
                response_type=rtype,
                latency_ms=result.latency_ms or 0.0,
                raw_flags=result.raw_flags,
            )
            det.record_observation(obs)
        except Exception as _e:
            logger.debug("[scanner] interference feed error: %s", _e)

    def _apply_strategy_controller_timing(self) -> None:
        """Read current strategy and apply timing multiplier to the ghost timer."""
        if not self.strategy_controller:
            return
        try:
            mult = self.strategy_controller.get_timing_multiplier()
            if mult == 0.0:
                # Paused — block until unpaused
                logger.info("[USARE] Strategy: paused by controller, waiting...")
                while self.strategy_controller.get_timing_multiplier() == 0.0:
                    time.sleep(2.0)
                logger.info("[USARE] Strategy: resuming")
                return
            # Adjust ghost timer ceiling dynamically
            if mult > 1.0:
                self.timer.config.ceiling = min(
                    self.timer.config.ceiling * mult,
                    900.0,
                )
        except Exception as _e:
            logger.debug("[scanner] strategy timing error: %s", _e)

    def _probe_port_syn_with_retries(self, port: int) -> ScanResult:
        if self.strategy_controller and getattr(self.strategy_controller, "is_paused", False):
            logger.info("[USARE] StrategyController paused scan due to heat. Waiting...")
            while getattr(self.strategy_controller, "is_paused", False):
                time.sleep(1)
                
        src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
        timeout = self.config.timeout
        if self.config.adaptive_timeout:
            timeout = self.session.get_adaptive_timeout(self.config.target_ip)
        last_result = None
        for attempt in range(self.config.max_retries):
            result = self._probe_port_syn(port, src_port, timeout)
            result.retries = attempt
            method_str = "tunnel" if self.config.tunnel else "syn"
            self.session.record_probe(
                target=self.config.target_ip,
                port=port,
                method=method_str,
                src_port=src_port,
                response=result.state.value,
                latency_ms=result.latency_ms,
                is_retry=(attempt > 0),
            )
            if result.latency_ms:
                self.session.record_rtt(self.config.target_ip, result.latency_ms)
                if self.temporal_engine:
                    self.temporal_engine.observe(result.latency_ms, 0, result.state != PortState.FILTERED)
            # Feed interference detector with every probe result
            self._feed_interference(result)
            # Apply live strategy controller timing changes
            self._apply_strategy_controller_timing()
            if result.state != PortState.FILTERED:
                return result
            last_result = result
            backoff = (1.5 ** attempt) * 0.5
            time.sleep(backoff)
            timeout *= 1.5
        if last_result:
            last_result.confidence = 0.3  
        return last_result or ScanResult(port=port, state=PortState.FILTERED)
    def _probe_port_syn(
        self, port: int, src_port: int, timeout: float
    ) -> ScanResult:
        # Try contextual probing first if enabled
        if self.config.use_contextual_probe and HAS_CONTEXTUAL:
            return self._probe_port_contextual(port, src_port, timeout)
        
        # Fall back to original method
        if self.config.tunnel and self._tunnel_engine:
            if self.config.tunnel == "https":
                tres = self._tunnel_engine.probe_through_https(self.config.target_ip, port)
            elif self.config.tunnel == "dns":
                tres = self._tunnel_engine.probe_via_dns(self.config.target_ip, port)
            elif self.config.tunnel == "doh":
                tres = self._tunnel_engine.probe_via_doh(self.config.target_ip, port)
            elif self.config.tunnel == "quic":
                tres = self._tunnel_engine.probe_through_quic(self.config.target_ip, port)
            elif self.config.tunnel == "icmp":
                tres = self._tunnel_engine.probe_via_icmp(self.config.target_ip, port)
            else:
                tres = None
            
            if tres:
                return ScanResult(
                    port=port, state=PortState.OPEN if tres.is_open else PortState.FILTERED,
                    latency_ms=tres.latency_ms, service_guess=SERVICE_MAP.get(port),
                    scan_method=f"tunnel_{self.config.tunnel}", confidence=0.85 if tres.is_open else 0.4
                )

        resp = None
        latency = timeout * 1000
        syn_pkt = self.packet_engine.craft_syn(
            target_ip=self.config.target_ip,
            target_port=port,
            src_port=src_port,
            use_ipv6=self.use_ipv6,
        )

        packet_queue: List[IP] = []
        if self.config.tcp_desync:
            burst_pkts = self.packet_engine.craft_desync_adaptive(
                target_ip=self.config.target_ip,
                target_port=port,
                src_port=src_port,
                mode=self.config.desync_mode,
                firewall_hops=self.config.traceroute_hops,
            )
            syn_pkt = burst_pkts[-1]  # type: ignore[index]
            packet_queue = burst_pkts
        elif self.config.flow_morph and self._shaper:
            # Generate cover packets + probe + teardown
            shaped_flow = self._shaper.wrap_probe(syn_pkt, self.config.target_ip, port, src_port)
            # Send the shaped flow inline
            # We must break out the actual probe to receive the response
            for pkt_tuple in shaped_flow:
                p, d = pkt_tuple
                time.sleep(d)
                if p is syn_pkt:
                    t0 = time.time()
                    resp = sr1(p, timeout=timeout, verbose=0)
                    latency = (time.time() - t0) * 1000
                else:
                    send(p, verbose=0)
            packet_queue = [] # Already sent
        elif self.config.overlap:
            from evasion.overlap_fragment import OverlapFragmenter
            overlapper = OverlapFragmenter(
                target_ip=self.config.target_ip, 
                target_port=port, 
                os_target=self.config.overlap
            )
            dummy_payload = b"A" * 32  # Ensure payload is large enough to fragment (> 16 bytes for padding constraints)
            overlapper.inject_tcp_overlap(sport=src_port, flags="S", payload=dummy_payload)
            # Simulate a timeout response as overlapping completely mangles packet tracking for synchronous SCAPY sniffer
            t0 = time.time()
            resp = sr1(IP(dst=self.config.target_ip)/TCP(sport=src_port, dport=port, flags="A"), timeout=timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            packet_queue = [] # Already dispatched asynchronously
        else:
            packet_queue = [syn_pkt]

        if self.config.use_decoys and self.decoy_engine and packet_queue:
            packet_queue = self.decoy_engine.interleave_decoys(syn_pkt, self.config.target_ip)
            
        for p in packet_queue:
            if self.config.use_fragmentation and getattr(self, "frag_engine", None):
                fragments = self._apply_fragmentation(p)  # type: ignore[attr-defined]
                for frag in fragments[:-1]:
                    send(frag, verbose=0)
                    self.heat_meter.record_packet()
                    self.session.record_send()
                if p is syn_pkt: 
                    t0 = time.time()
                    resp = sr1(fragments[-1], timeout=timeout, verbose=0)  # type: ignore[index]
                    latency = (time.time() - t0) * 1000
                else:
                    send(fragments[-1], verbose=0)  # type: ignore[index]
            else:
                if p is syn_pkt:
                    t0 = time.time()
                    resp = sr1(p, timeout=timeout, verbose=0)
                    latency = (time.time() - t0) * 1000
                else:
                    send(p, verbose=0)
            self.heat_meter.record_packet(is_decoy=(p is not syn_pkt))
            self.session.record_send()
        if resp is None:
            return ScanResult(
                port=port, state=PortState.FILTERED, reason="no-response",
                latency_ms=latency,
                service_guess=SERVICE_MAP.get(port),
                scan_method="syn", confidence=0.3,
            )
        if resp.haslayer(TCP):
            tcp_flags = resp[TCP].flags
            self._response_data.append({
                "ttl": resp[IP].ttl,
                "window": resp[TCP].window,
                "df": bool(resp[IP].flags & 0x02),
                "ip_id": resp[IP].id,
            })
            if tcp_flags & 0x12 == 0x12:  
                rst = self.packet_engine.craft_syn_ack_response_rst(resp, src_port=src_port)
                send(rst, verbose=0)
                self.heat_meter.record_packet()
                self.session.record_send()
                return ScanResult(
                    port=port, state=PortState.OPEN, reason="syn-ack",
                    ttl_received=resp[IP].ttl,
                    window_received=resp[TCP].window,
                    latency_ms=latency,
                    service_guess=SERVICE_MAP.get(port),
                    scan_method="syn",
                    raw_flags=str(tcp_flags),
                    confidence=0.95,  
                    ip_id_received=resp[IP].id,
                    df_flag=bool(resp[IP].flags & 0x02),
                )
            elif tcp_flags & 0x04:  
                return ScanResult(
                    port=port, state=PortState.CLOSED, reason="rst",
                    ttl_received=resp[IP].ttl,
                    latency_ms=latency,
                    service_guess=SERVICE_MAP.get(port),
                    scan_method="syn",
                    raw_flags=str(tcp_flags),
                    confidence=0.95,
                    ip_id_received=resp[IP].id,
                    df_flag=bool(resp[IP].flags & 0x02),
                )
        if resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            if icmp_type == 3 and icmp_code in (1, 2, 3, 9, 10, 13):
                return ScanResult(
                    port=port, state=PortState.FILTERED, reason="no-response",
                    latency_ms=latency,
                    service_guess=SERVICE_MAP.get(port),
                    scan_method="syn", confidence=0.85,
                )
        return ScanResult(
            port=port, state=PortState.FILTERED, reason="no-response",
            latency_ms=latency,
            service_guess=SERVICE_MAP.get(port),
            scan_method="syn", confidence=0.4,
        )
    def _ack_scan_phase(self, ports: List[int]):
        logger.info(f"[USARE] ACK Phase — probing {len(ports)} filtered ports")
        for port in ports:
            src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
            ack_pkt = self.packet_engine.craft_ack(
                self.config.target_ip, port, src_port=src_port
            )
            timeout = self.session.get_adaptive_timeout(self.config.target_ip)
            t0 = time.time()
            resp = sr1(ack_pkt, timeout=timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            self.heat_meter.record_packet()
            if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                for r in self.results:
                    if r.port == port:
                        r.state = PortState.CLOSED
                        r.confidence = max(r.confidence, 0.7)
                        break
            if self.config.ghost_mode:
                self.timer.sync_ghost_wait()
    def _xmas_null_phase(self, ports: List[int]):
        logger.info(f"[USARE] XMAS/NULL Phase — confirming {len(ports)} ports")
        for port in ports:
            src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
            xmas_pkt = self.packet_engine.craft_xmas(
                self.config.target_ip, port, src_port=src_port
            )
            timeout = self.session.get_adaptive_timeout(self.config.target_ip)
            t0 = time.time()
            resp = sr1(xmas_pkt, timeout=timeout, verbose=0)
            self.heat_meter.record_packet()
            if resp is None:
                for r in self.results:
                    if r.port == port and r.state == PortState.FILTERED:
                        r.state = PortState.OPEN_FILTERED
                        break
            elif resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                for r in self.results:
                    if r.port == port:
                        r.state = PortState.CLOSED
                        r.confidence = max(r.confidence, 0.8)
                        break
            if self.config.ghost_mode:
                self.timer.sync_ghost_wait()

    def fin_scan(self, ports: List[int]) -> List[ScanResult]:
        """
        FIN scan (Nmap -sF equivalent).

        RFC 793: if a port is CLOSED, it MUST send RST back to a FIN.
        If OPEN, it silently drops the FIN (no response = open|filtered).
        Most stateful firewalls only track SYN-initiated connections, so
        FIN probes bypass them and reach the target OS directly.

        Interpretation:
          - RST received  → CLOSED (high confidence)
          - No response   → OPEN|FILTERED (port is open or packet was dropped)
          - ICMP unreach  → FILTERED (firewall is actively blocking)
        """
        logger.info(f"[USARE] FIN Scan — {len(ports)} ports")
        results = []
        timeout = self.session.get_adaptive_timeout(self.config.target_ip)

        for port in ports:
            src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
            fin_pkt = self.packet_engine.craft_fin(
                self.config.target_ip, port,
                src_port=src_port,
                seq=random.randint(1, 0xFFFFFFFF),
                ack=0,
            )
            t0 = time.time()
            resp = sr1(fin_pkt, timeout=timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            self.heat_meter.record_packet()

            if resp is None:
                state = PortState.OPEN_FILTERED
                confidence = 0.55
            elif resp.haslayer(TCP) and resp[TCP].flags & 0x04:  # RST
                state = PortState.CLOSED
                confidence = 0.95
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3:
                state = PortState.FILTERED
                confidence = 0.85
            else:
                state = PortState.OPEN_FILTERED
                confidence = 0.45

            results.append(ScanResult(
                port=port, state=state,
                ttl_received=resp[IP].ttl if resp and resp.haslayer(IP) else None,
                latency_ms=latency,
                service_guess=SERVICE_MAP.get(port),
                scan_method="fin",
                confidence=confidence,
            ))

            if self.config.ghost_mode:
                self.timer.sync_ghost_wait()

        return results

    def maimon_scan(self, ports: List[int]) -> List[ScanResult]:
        """
        Maimon scan (Nmap -sM equivalent).

        Sends FIN+ACK probes. Named after Uriel Maimon who discovered
        that some BSD-derived stacks erroneously drop FIN|ACK to open ports
        rather than sending RST, making open ports distinguishable.

        Particularly effective against:
          - OpenBSD / FreeBSD targets
          - Older Cisco IOS
          - Some embedded OS TCP stacks

        Interpretation (same as FIN but ACK bit also set):
          - RST       → CLOSED
          - No reply  → OPEN (on susceptible stacks) or FILTERED
          - ICMP      → FILTERED
        """
        logger.info(f"[USARE] Maimon Scan (FIN+ACK) — {len(ports)} ports")
        results = []
        timeout = self.session.get_adaptive_timeout(self.config.target_ip)

        for port in ports:
            src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
            # FIN+ACK = flags 0x11
            pkt = IP(dst=self.config.target_ip) / TCP(
                sport=src_port, dport=port,
                flags="FA",
                seq=random.randint(1, 0xFFFFFFFF),
                ack=random.randint(1, 0xFFFFFFFF),
                window=self.packet_engine.config.custom_window,
            )
            t0 = time.time()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            self.heat_meter.record_packet()

            if resp is None:
                state = PortState.OPEN_FILTERED
                confidence = 0.60
            elif resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                state = PortState.CLOSED
                confidence = 0.95
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3:
                state = PortState.FILTERED
                confidence = 0.80
            else:
                state = PortState.FILTERED
                confidence = 0.40

            results.append(ScanResult(
                port=port, state=state,
                ttl_received=resp[IP].ttl if resp and resp.haslayer(IP) else None,
                latency_ms=latency,
                service_guess=SERVICE_MAP.get(port),
                scan_method="maimon",
                confidence=confidence,
            ))

            if self.config.ghost_mode:
                self.timer.sync_ghost_wait()

        return results

    def custom_flag_scan(self, ports: List[int], flags: int,
                         scan_name: str = "custom") -> List[ScanResult]:
        """
        Arbitrary TCP flag combination scan.

        Send any TCP flag bitmask to probe how the target and intermediate
        devices react to non-standard flag combinations. Useful for:
          - Identifying OS TCP stack quirks (differentiating Linux vs BSD vs Windows)
          - Finding stateless ACL rules (a firewall blocking SYN but passing PSH)
          - ECN probing: flags=0xC2 (SYN+ECE+CWR)
          - URG-only probing to test urgent pointer handling

        Args:
            ports: Ports to probe.
            flags: Integer TCP flags bitmask (e.g. 0x29 = FIN+PSH+URG).
            scan_name: Label for scan_method field in results.
        """
        logger.info(f"[USARE] Custom Flag Scan (flags=0x{flags:02X}) — {len(ports)} ports")
        results = []
        timeout = self.session.get_adaptive_timeout(self.config.target_ip)

        for port in ports:
            src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
            pkt = IP(dst=self.config.target_ip) / TCP(
                sport=src_port, dport=port,
                flags=flags,
                seq=random.randint(1, 0xFFFFFFFF),
                window=self.packet_engine.config.custom_window,
            )
            t0 = time.time()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            self.heat_meter.record_packet()

            if resp is None:
                state = PortState.OPEN_FILTERED
                confidence = 0.50
            elif resp.haslayer(TCP):
                rflags = resp[TCP].flags
                if rflags & 0x04:  # RST
                    state = PortState.CLOSED
                    confidence = 0.90
                elif rflags & 0x12 == 0x12:  # SYN-ACK (unlikely but guard)
                    state = PortState.OPEN
                    confidence = 0.90
                else:
                    state = PortState.UNFILTERED
                    confidence = 0.65
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3:
                state = PortState.FILTERED
                confidence = 0.85
            else:
                state = PortState.FILTERED
                confidence = 0.35

            results.append(ScanResult(
                port=port, state=state,
                ttl_received=resp[IP].ttl if resp and resp.haslayer(IP) else None,
                raw_flags=f"0x{flags:02X}",
                latency_ms=latency,
                service_guess=SERVICE_MAP.get(port),
                scan_method=scan_name,
                confidence=confidence,
            ))

            if self.config.ghost_mode:
                self.timer.sync_ghost_wait()

        return results
    def _apply_fragmentation(self, pkt: IP) -> list:
        strategy = self.config.frag_strategy
        if strategy == "ttl":
            return self.frag_engine.fragment_with_ttl_evasion(pkt)
        elif strategy == "overlap":
            return self.frag_engine.fragment_with_overlap(pkt)
        elif strategy == "reverse":
            return self.frag_engine.fragment_ordered_reverse(pkt)
        else:
            return self.frag_engine.fragment_packet(pkt)
    def _resolve_ports(self) -> List[int]:
        if self.config.ports:
            return [p for p in self.config.ports]  # type: ignore[arg-type, union-attr]
        ports = []
        for part in self.config.port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
    def get_response_data(self) -> List[Dict]:
        return self._response_data
    def get_summary(self) -> Dict[str, Any]:
        open_ports = [r for r in self.results if r.state == PortState.OPEN]
        closed_ports = [r for r in self.results if r.state == PortState.CLOSED]
        filtered_ports = [r for r in self.results if r.state == PortState.FILTERED]
        elapsed = time.time() - (self._start_time or time.time())
        return {
            "target": self.config.target_ip,
            "total_ports_scanned": len(self.results),
            "open": len(open_ports),
            "closed": len(closed_ports),
            "filtered": len(filtered_ports),
            "open_ports": [r.to_dict() for r in open_ports],
            "elapsed_seconds": round(elapsed, 1),
            "packets_sent": self.packet_engine.packets_crafted,
            "decoys_sent": self.decoy_engine.total_decoys_generated if self.decoy_engine else 0,
            "heat_level": self.heat_meter.detection_probability(),
            "timing_stats": self.timer.stats,
            "session_stats": self.session.stats,
            "os_fingerprint": self.packet_engine.get_fingerprint_summary(),
        }

    def _probe_port_contextual(self, port: int, src_port: int, timeout: float) -> ScanResult:
        """Probe port using contextual discovery workflow."""
        if not HAS_CONTEXTUAL:
            return ScanResult(port=port, state=PortState.FILTERED, reason="no-response", scan_method="contextual_unavailable")
        
        try:
            # Use contextual prober
            os_hint = self.config.contextual_os_hint
            contextual_result = contextual_probe(self.config.target_ip, port, os_hint)
            
            # Convert contextual result to ScanResult
            if contextual_result.probe_success:
                state = PortState.OPEN
            else:
                state = PortState.FILTERED if contextual_result.probe_response_time_ms == 0 else PortState.CLOSED
            
            # Apply TTL masquerading if enabled
            if self.config.use_ttl_masquerading:
                ttl_result = ttl_masquerade_probe(self.config.target_ip, port, self.config.ttl_strategy)
                if ttl_result.get("success"):
                    logger.debug(f"[Contextual] TTL masquerading successful for port {port}")
            
            # Apply entropy balancing if enabled
            confidence = contextual_result.stealth_score
            if self.config.use_entropy_balancing:
                confidence *= 0.95  # Slight reduction for entropy balancing overhead
            
            return ScanResult(
                port=port,
                state=state,
                latency_ms=contextual_result.probe_response_time_ms,
                service_guess=SERVICE_MAP.get(port),
                scan_method=f"contextual_{contextual_result.discovery_method}",
                confidence=confidence,
                timestamp=time.time()
            )
            
        except Exception as e:
            logger.debug(f"[Contextual] Contextual probe failed for port {port}: {e}")
            # Fall back to standard SYN scan
            return self._probe_port_syn_standard(port, src_port, timeout)
    
    def _probe_port_syn_standard(self, port: int, src_port: int, timeout: float) -> ScanResult:
        """Standard SYN scan fallback — sends a raw SYN and reads the response."""
        try:
            syn_pkt = self.packet_engine.craft_syn(
                self.config.target_ip, port, src_port=src_port
            )
            if self.config.use_fragmentation:
                frags = self._apply_fragmentation(syn_pkt)
                t0 = time.time()
                # Send all but the last fragment, then sr1 the last one to receive the response
                for frag in frags[:-1]:
                    send(frag, verbose=0)
                resp = sr1(frags[-1], timeout=timeout, verbose=0)
            else:
                t0 = time.time()
                resp = sr1(syn_pkt, timeout=timeout, verbose=0)

            latency = (time.time() - t0) * 1000
            self.heat_meter.record_packet()
            if resp is None:
                return ScanResult(
                    port=port, state=PortState.FILTERED, reason="no-response",
                    latency_ms=timeout * 1000, 
                    protocol='tcp'  # type: ignore[call-arg]
                )

            if resp.haslayer(TCP):
                tcp_layer = resp.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # We got a SYN-ACK, port is Open.
                    # Send a RST to tear down connection (no half-open state leak)
                    if not getattr(self.config, "rst_block", False):
                        rst = self.packet_engine.craft_rst(self.config.target_ip, port, src_port, tcp_layer.ack)
                        send(rst, verbose=0)
                    return ScanResult(
                        port=port, state=PortState.OPEN, reason="syn-ack",
                        latency_ms=latency, protocol='tcp'  # type: ignore[call-arg]
                    )
                elif tcp_layer.flags & 0x04:  # RST
                    return ScanResult(
                        port=port, state=PortState.CLOSED, reason="rst",
                        latency_ms=latency,
                        service_guess=SERVICE_MAP.get(port),
                        scan_method="syn_fallback", confidence=0.85,
                        timestamp=time.time()
                    )

            return ScanResult(
                port=port, state=PortState.FILTERED, reason="no-response",
                latency_ms=latency,
                service_guess=SERVICE_MAP.get(port),
                scan_method="syn_fallback", confidence=0.4,
                timestamp=time.time()
            )
        except Exception as e:
            logger.debug(f"[SYN Fallback] Failed for port {port}: {e}")
            return ScanResult(
                port=port, state=PortState.FILTERED, reason="no-response",
                scan_method="syn_fallback_error",
                timestamp=time.time()
            )