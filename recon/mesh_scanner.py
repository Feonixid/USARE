"""
USARE Mesh / Subnet Scanner

Extends USARE from single-target to proper multi-host scanning:
  - CIDR range expansion (192.168.1.0/24, 10.0.0.0/16, etc.)
  - Per-host result isolation with delta tracking
  - Priority queue: hosts with more open ports / interesting services first
  - AD-aware scope: auto-skip broadcast, network, gateway addresses
  - Concurrency control: N hosts in parallel, each with ghost timing
  - BloodHound-compatible output piping

This module slots in before the main scan loop in usare.py.
"""

import ipaddress
import logging
import socket
import struct
import time
import threading
import queue
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Iterator, Set, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("usare.mesh_scanner")


# ─────────────────────────────────────────────────────────────────────────────
# CIDR / target expansion
# ─────────────────────────────────────────────────────────────────────────────

def expand_ipv6_prefix(prefix_str: str) -> List[str]:
    """
    Expand an IPv6 prefix (e.g. '2001:db8::/120') into individual addresses.
    Limited to /112 or smaller to prevent memory exhaustion.
    """
    import ipaddress as _ip
    try:
        net = _ip.ip_network(prefix_str, strict=False)
        if net.prefixlen < 112:
            logger.warning(
                "[mesh] IPv6 prefix /%d too large to enumerate — minimum /112 required",
                net.prefixlen
            )
            return []
        return [str(h) for h in net.hosts()]
    except ValueError as e:
        logger.warning("[mesh] Invalid IPv6 prefix '%s': %s", prefix_str, e)
        return []


def expand_target(target_str: str) -> List[str]:
    """
    Expand a target string into a list of individual IP addresses.
    Handles:
      - Single IP:       192.168.1.1
      - CIDR range:      192.168.1.0/24
      - Hyphen range:    192.168.1.1-50
      - Comma list:      192.168.1.1,192.168.1.5,10.0.0.1
      - Hostname:        server.corp.local (resolved once)
    """
    targets: List[str] = []
    for part in target_str.replace(" ", "").split(","):
        part = part.strip()
        if not part:
            continue
        # CIDR (IPv4 or IPv6)
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                if net.version == 6:
                    # IPv6 — only enumerate if prefix is /112 or smaller
                    if net.prefixlen >= 112:
                        targets.extend(str(h) for h in net.hosts())
                    else:
                        logger.warning("[mesh] IPv6 /%d prefix skipped — use /112 or smaller", net.prefixlen)
                else:
                    # IPv4 — skip network and broadcast for /31 and larger
                    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
                    targets.extend(str(h) for h in hosts)
                continue
            except ValueError:
                pass
        # Hyphen range: x.x.x.start-end
        if "-" in part:
            segments = part.rsplit(".", 1)
            if len(segments) == 2 and "-" in segments[1]:
                base = segments[0]
                lo_str, hi_str = segments[1].split("-", 1)
                try:
                    lo, hi = int(lo_str), int(hi_str)
                    for octet in range(lo, hi + 1):
                        targets.append(f"{base}.{octet}")
                    continue
                except ValueError:
                    pass
        # Hostname — resolve once
        if not _is_ipv4(part):
            try:
                resolved = socket.gethostbyname(part)
                targets.append(resolved)
                logger.debug("[mesh] %s → %s", part, resolved)
            except socket.gaierror:
                logger.warning("[mesh] Cannot resolve: %s", part)
            continue
        targets.append(part)
    # Deduplicate, preserve order
    seen: Set[str] = set()
    result: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def _is_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False


def _is_ipv6(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except (OSError, AttributeError):
        return False


def is_skip_address(ip: str) -> bool:
    """Return True for addresses that should never be scanned (broadcast, loopback, multicast)."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_loopback
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or str(addr).endswith(".0")
            or str(addr).endswith(".255")
        )
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Host liveness check
# ─────────────────────────────────────────────────────────────────────────────

def quick_alive_check(ip: str, ports: List[int] = None, timeout: float = 1.5) -> bool:
    """
    Fast TCP connect check to determine if a host is alive.
    Supports both IPv4 and IPv6.
    """
    check_ports = ports or [80, 443, 22, 445, 3389, 8080, 53]
    af = socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET
    for port in check_ports[:5]:
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            s.close()
            if rc == 0:
                return True
        except Exception:
            pass
    # ICMP ping fallback (requires raw socket / root)
    try:
        import subprocess
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=2.0
        )
        return result.returncode == 0
    except Exception:
        pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-host result container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HostScanResult:
    ip: str
    is_alive: bool = False
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)   # port → service name
    os_guess: Optional[str] = None
    os_confidence: float = 0.0
    banners: Dict[int, str] = field(default_factory=dict)
    scan_time_s: float = 0.0
    error: Optional[str] = None
    priority_score: float = 0.0      # higher = more interesting
    scan_data: Dict[str, Any] = field(default_factory=dict)  # full module outputs

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "alive": self.is_alive,
            "open_ports": self.open_ports,
            "services": self.services,
            "os_guess": self.os_guess,
            "os_confidence": round(self.os_confidence, 2),
            "banners": self.banners,
            "scan_time_s": round(self.scan_time_s, 2),
            "priority_score": round(self.priority_score, 2),
            "error": self.error,
        }

    def compute_priority(self):
        """
        Score this host by intelligence value.
        Higher score = more interesting / more attack surface.
        """
        score = 0.0
        score += len(self.open_ports) * 2.0
        # High-value services
        hv = {22, 80, 443, 445, 3389, 8080, 8443, 1433, 3306, 5432, 6379, 9200, 2375, 6443}
        score += sum(5.0 for p in self.open_ports if p in hv)
        # OS confidence
        score += self.os_confidence * 10.0
        self.priority_score = score


# ─────────────────────────────────────────────────────────────────────────────
# Mesh scan coordinator
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MeshScanConfig:
    port_spec: str = "1-1024"
    max_parallel_hosts: int = 5       # concurrent host scans
    liveness_check: bool = True
    liveness_timeout: float = 1.5
    per_host_timeout: float = 3.0
    skip_dead_hosts: bool = True
    ad_scope_aware: bool = True       # skip .0 and .255 addresses
    priority_sort: bool = True        # scan interesting hosts first
    inter_host_delay_s: float = 0.5   # ghost delay between starting host scans


@dataclass
class MeshScanReport:
    total_targets: int = 0
    alive_hosts: int = 0
    dead_hosts: int = 0
    skipped_hosts: int = 0
    total_open_ports: int = 0
    hosts: List[HostScanResult] = field(default_factory=list)
    scan_start: float = field(default_factory=time.time)
    scan_end: Optional[float] = None
    notes: List[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        end = self.scan_end or time.time()
        return end - self.scan_start

    def sorted_by_priority(self) -> List[HostScanResult]:
        return sorted(self.hosts, key=lambda h: h.priority_score, reverse=True)

    def to_dict(self) -> dict:
        return {
            "total_targets": self.total_targets,
            "alive_hosts": self.alive_hosts,
            "dead_hosts": self.dead_hosts,
            "skipped": self.skipped_hosts,
            "total_open_ports": self.total_open_ports,
            "elapsed_s": round(self.elapsed_s, 2),
            "hosts": [h.to_dict() for h in self.sorted_by_priority()],
            "notes": self.notes,
        }


class MeshScanner:
    """
    Scans multiple hosts from a CIDR range or target list.

    Intended use in usare.py:
        mesh = MeshScanner(config)
        report = mesh.discover_and_scan(target_string, port_spec)
        for host in report.sorted_by_priority():
            # process per-host results
    """

    def __init__(self, config: Optional[MeshScanConfig] = None):
        self.config = config or MeshScanConfig()

    def discover(self, target_string: str) -> Tuple[List[str], List[str]]:
        """
        Expand targets and run liveness checks.
        Returns (alive_ips, dead_ips).
        """
        all_ips = expand_target(target_string)
        skipped = [ip for ip in all_ips if self.config.ad_scope_aware and is_skip_address(ip)]
        candidates = [ip for ip in all_ips if ip not in skipped]

        logger.info("[mesh] %d candidates from '%s' (%d skipped)", len(candidates), target_string, len(skipped))

        if not self.config.liveness_check:
            return candidates, []

        alive: List[str] = []
        dead: List[str] = []

        def check(ip: str):
            if quick_alive_check(ip, timeout=self.config.liveness_timeout):
                alive.append(ip)
            else:
                dead.append(ip)

        with ThreadPoolExecutor(max_workers=min(50, len(candidates))) as ex:
            list(ex.map(check, candidates))

        logger.info("[mesh] Alive: %d / Dead: %d", len(alive), len(dead))
        return alive, dead

    def scan_host(self, ip: str, port_spec: str) -> HostScanResult:
        """
        Run a lightweight SYN scan against a single host.
        Returns a HostScanResult populated with open ports and basic service info.
        This is intentionally minimal — the caller (usare.py) runs the full
        module pipeline (banner grab, OS fingerprint, vuln map, etc.) per host.
        """
        result = HostScanResult(ip=ip, is_alive=True)
        t0 = time.time()
        try:
            from recon.syn_scanner import StealthScanner, ScanConfig, PortState  # type: ignore
            from ops.heat_meter import HeatMeter  # type: ignore
            sc = ScanConfig(
                target_ip=ip,
                port_range=port_spec,
                ghost_mode=True,
                timeout=self.config.per_host_timeout,
                use_decoys=False,    # minimal footprint for mesh discovery
                use_fragmentation=False,
                chunk_size=50,
            )
            scanner = StealthScanner(sc, HeatMeter())
            scan_results = scanner.execute()
            result.open_ports = [r.port for r in scan_results if r.state == PortState.OPEN]
            result.services = {r.port: (r.service_guess or "") for r in scan_results if r.state == PortState.OPEN}
        except Exception as e:
            result.error = str(e)
            logger.debug("[mesh] Host %s scan failed: %s", ip, e)

        result.scan_time_s = time.time() - t0
        result.compute_priority()
        return result

    def scan_mesh(
        self,
        target_string: str,
        port_spec: str = "1-1024",
        progress_callback=None,
    ) -> MeshScanReport:
        """
        Full mesh scan: discover alive hosts, scan each, return prioritised report.
        progress_callback(current, total, ip) called after each host completes.
        """
        report = MeshScanReport()
        alive, dead = self.discover(target_string)

        all_ips = expand_target(target_string)
        report.total_targets = len(all_ips)
        report.dead_hosts    = len(dead)
        report.skipped_hosts = len([ip for ip in all_ips if is_skip_address(ip)])

        targets = alive
        if self.config.skip_dead_hosts:
            pass
        else:
            targets = [ip for ip in all_ips if not is_skip_address(ip)]

        report.alive_hosts = len(alive)

        if not targets:
            report.notes.append("No alive hosts found")
            report.scan_end = time.time()
            return report

        completed = 0
        total = len(targets)

        def scan_one(ip: str) -> HostScanResult:
            nonlocal completed
            time.sleep(self.config.inter_host_delay_s * completed)  # stagger start
            result = self.scan_host(ip, port_spec)
            completed += 1
            if progress_callback:
                try:
                    progress_callback(completed, total, ip)
                except Exception:
                    pass
            return result

        with ThreadPoolExecutor(max_workers=self.config.max_parallel_hosts) as ex:
            futures = {ex.submit(scan_one, ip): ip for ip in targets}
            for future in as_completed(futures):
                try:
                    host_result = future.result()
                    report.hosts.append(host_result)
                    report.total_open_ports += len(host_result.open_ports)
                except Exception as e:
                    ip = futures[future]
                    logger.warning("[mesh] Host %s future failed: %s", ip, e)
                    report.hosts.append(HostScanResult(ip=ip, error=str(e)))

        report.scan_end = time.time()
        report.notes.append(
            f"Mesh scan complete: {len(report.hosts)} hosts, "
            f"{report.total_open_ports} total open ports, "
            f"{report.elapsed_s:.1f}s"
        )
        return report
