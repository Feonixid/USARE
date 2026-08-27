"""
USARE Idle Scan Pipeline — Zero Attribution Port Scanning

Automates the complete idle scan workflow:
1. Discover zombie candidates (from subnet, discovered hosts, or manual)
2. Validate IPID predictability and rank candidates
3. Execute the port scan through the best zombie
4. Fail over to next-best zombie if reliability degrades mid-scan
5. Merge results into standard ScanResult format for unified reporting

Zero packets from the operator's real IP ever reach the target.
"""

import time
import random
import logging
import threading
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from scapy.all import IP, TCP, ICMP, sr1, send, conf

logger = logging.getLogger("usare.idle_pipeline")


@dataclass
class ZombieCandidate:
    """A potential idle scan zombie host."""
    ip: str
    port: int
    suitability: float      # 0-1 from IPIDAnalyzer
    pattern: str             # 'incrementing', 'random', etc.
    increment: int           # Expected IP ID increment per probe
    os_guess: str
    response_rate: float     # Fraction of probes that got responses
    validated: bool = False
    failed_probes: int = 0   # Track reliability degradation


class ZombieState(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DEAD = "dead"


@dataclass
class IdleScanPortResult:
    """Result for a single port from idle scan."""
    port: int
    state: str               # open, closed, filtered
    confidence: float
    ipid_diff: int
    zombie_used: str
    attempts: int = 1


@dataclass
class IdlePipelineResult:
    """Complete results from the idle scan pipeline."""
    target_ip: str
    zombie_used: str
    zombies_tested: int
    zombies_validated: int
    port_results: Dict[int, IdleScanPortResult] = field(default_factory=dict)
    total_probes: int = 0
    zombie_failovers: int = 0
    scan_method: str = "idle_scan"


class ZombieDiscovery:
    """
    Discovers potential zombie hosts for idle scanning by probing
    hosts on a subnet or from a provided list.
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def discover_from_subnet(self, subnet_base: str, count: int = 20) -> List[str]:
        """
        Probe random IPs from a /24 subnet (or nearby range) to find
        responsive hosts that could serve as zombies.
        """
        # Parse base IP and generate candidates
        parts = subnet_base.split('.')
        if len(parts) != 4:
            logger.error(f"[Zombie] Invalid subnet base: {subnet_base}")
            return []

        candidates = []
        base = '.'.join(parts[:3])

        # Generate random IPs in the /24, excluding .0 and .255
        ips_to_try = random.sample(range(1, 255), min(count * 2, 254))

        for host_part in ips_to_try[:count * 2]:
            ip = f"{base}.{host_part}"
            if ip == subnet_base:
                continue  # Skip the target itself

            try:
                # Quick SYN probe to port 80 (most likely to respond)
                syn = IP(dst=ip) / TCP(sport=random.randint(40000, 60000),
                                       dport=80, flags="S")
                resp = sr1(syn, timeout=self.timeout, verbose=0)

                if resp and resp.haslayer(IP):
                    candidates.append(ip)
                    logger.debug(f"[Zombie] Found responsive host: {ip}")

                    if len(candidates) >= count:
                        break

            except Exception:
                continue

        logger.info(f"[Zombie] Discovered {len(candidates)} responsive hosts")
        return candidates

    def discover_from_list(self, ip_list: List[str]) -> List[str]:
        """
        Filter a list of known IPs to those that are responsive.
        """
        responsive = []
        for ip in ip_list:
            try:
                syn = IP(dst=ip) / TCP(sport=random.randint(40000, 60000),
                                       dport=80, flags="S")
                resp = sr1(syn, timeout=self.timeout, verbose=0)
                if resp and resp.haslayer(IP):
                    responsive.append(ip)
            except Exception:
                continue
        return responsive


class ZombieValidator:
    """
    Validates zombie candidates by analyzing their IP ID predictability.
    Ranks candidates by suitability for idle scanning.
    """

    MIN_SUITABILITY = 0.6   # Minimum score to be usable
    PROBE_COUNT = 10        # Number of IP ID probes per candidate

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def validate_candidate(self, ip: str, port: int = 80) -> Optional[ZombieCandidate]:
        """
        Probe a host's IP ID sequence and assess its suitability as a zombie.
        """
        from recon.ipid_analysis import IPIDAnalyzer

        analyzer = IPIDAnalyzer(timeout=self.timeout)
        analyzer.collect_ip_id_sequence(ip, port, count=self.PROBE_COUNT)

        if len(analyzer.observations) < 6:
            logger.debug(f"[Zombie] {ip} — insufficient responses, skipping")
            return None

        analysis = analyzer.analyze()

        response_rate = len([o for o in analyzer.observations if o.response_received]) / len(analyzer.observations)

        candidate = ZombieCandidate(
            ip=ip,
            port=port,
            suitability=analysis.zombie_suitability,
            pattern=analysis.ip_id_pattern,
            increment=analysis.increment_value,
            os_guess=analysis.os_guess,
            response_rate=response_rate,
            validated=analysis.zombie_suitability >= self.MIN_SUITABILITY
        )

        logger.info(
            f"[Zombie] {ip}: suitability={analysis.zombie_suitability:.2f}, "
            f"pattern={analysis.ip_id_pattern}, OS={analysis.os_guess}, "
            f"validated={candidate.validated}"
        )

        return candidate

    def validate_and_rank(self, ips: List[str], port: int = 80) -> List[ZombieCandidate]:
        """Validate all candidates and return ranked by suitability."""
        candidates = []

        for ip in ips:
            candidate = self.validate_candidate(ip, port)
            if candidate and candidate.validated:
                candidates.append(candidate)

        # Sort by suitability (highest first), then by response rate
        candidates.sort(key=lambda c: (c.suitability, c.response_rate), reverse=True)

        logger.info(
            f"[Zombie] Validated {len(candidates)} usable zombies from {len(ips)} candidates"
        )

        return candidates


class IdleScanOrchestrator:
    """
    Executes the complete idle scan using validated zombies.
    Handles mid-scan zombie failover if reliability degrades.
    """

    # If a zombie's IP ID jumps more than this many increments unexpectedly,
    # it's considered busy/unreliable
    MAX_ACCEPTABLE_DRIFT = 5
    FAILOVER_THRESHOLD = 3  # Number of unreliable probes before switching zombies

    def __init__(self, target_ip: str, zombies: List[ZombieCandidate],
                 timeout: float = 2.0):
        self.target_ip = target_ip
        self.zombies = zombies
        self.active_zombie_idx = 0
        self.timeout = timeout
        self.results = IdlePipelineResult(
            target_ip=target_ip,
            zombie_used=zombies[0].ip if zombies else "",  # type: ignore[index]
            zombies_tested=len(zombies),
            zombies_validated=len(zombies),
        )
        self._lock = threading.Lock()

        if not conf.verb:
            conf.verb = 0

    @property
    def active_zombie(self) -> Optional[ZombieCandidate]:
        if self.active_zombie_idx < len(self.zombies):
            return self.zombies[self.active_zombie_idx]
        return None

    def _get_zombie_ipid(self, zombie: ZombieCandidate) -> Optional[int]:
        """Probe zombie's current IP ID."""
        try:
            syn = IP(dst=zombie.ip) / TCP(
                sport=random.randint(40000, 60000),
                dport=zombie.port,
                flags="S"
            )
            resp = sr1(syn, timeout=self.timeout, verbose=0)

            if resp and resp.haslayer(IP):
                # Send RST to keep zombie clean
                if resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
                    rst = IP(dst=zombie.ip) / TCP(
                        sport=resp[TCP].dport,
                        dport=resp[TCP].sport,
                        flags="R",
                        seq=resp[TCP].ack
                    )
                    send(rst, verbose=0)
                return resp[IP].id
        except Exception as e:
            logger.debug(f"[Idle] Failed to probe zombie {zombie.ip}: {e}")
        return None

    def _probe_port_idle(self, port: int, zombie: ZombieCandidate) -> Optional[IdleScanPortResult]:
        """Execute single idle scan probe for one port."""

        # 1. Get baseline zombie IP ID
        baseline = self._get_zombie_ipid(zombie)
        if baseline is None:
            return None

        # 2. Send spoofed SYN to target from zombie's IP
        try:
            spoofed = IP(dst=self.target_ip, src=zombie.ip) / TCP(
                sport=random.randint(40000, 60000),
                dport=port,
                flags="S",
                seq=random.randint(1000, 4000000000)
            )
            send(spoofed, verbose=0)

            # Wait for target to respond to zombie
            time.sleep(0.15)

        except Exception as e:
            logger.debug(f"[Idle] Spoofed SYN failed for port {port}: {e}")
            return None

        # 3. Get post-probe zombie IP ID
        post = self._get_zombie_ipid(zombie)
        if post is None:
            return None

        # 4. Calculate IP ID difference (16-bit wraparound safe)
        ipid_diff = (post - baseline) & 0xFFFF

        # Adjust for zombie's expected increment per our two probes
        # We probe zombie twice (baseline + post), so expect +2 from our own probes alone
        effective_diff = ipid_diff - 2  # Subtract our own probe increments

        # 5. Determine port state
        if zombie.increment == 256:
            # Windows-style: increments by 256 per connection
            effective_diff = ipid_diff - (2 * 256)
            if effective_diff == 0:
                # No extra increment = target sent RST (closed)
                state, confidence = "closed", 0.85
            elif effective_diff == 256:
                # One extra increment = target sent SYN-ACK, zombie sent RST (open)
                state, confidence = "open", 0.90
            elif effective_diff < 0 or effective_diff > 256 * self.MAX_ACCEPTABLE_DRIFT:
                state, confidence = "unknown", 0.2
                zombie.failed_probes += 1
            else:
                state, confidence = "filtered", 0.6
        else:
            # Linux/Cisco-style: increments by 1
            if effective_diff == 0:
                state, confidence = "closed", 0.85
            elif effective_diff == 1:
                state, confidence = "open", 0.90
            elif effective_diff < 0 or effective_diff > self.MAX_ACCEPTABLE_DRIFT:
                state, confidence = "unknown", 0.2
                zombie.failed_probes += 1
            else:
                state, confidence = "filtered", 0.6

        with self._lock:
            self.results.total_probes += 3  # baseline + spoofed + post

        return IdleScanPortResult(
            port=port,
            state=state,
            confidence=confidence,
            ipid_diff=ipid_diff,
            zombie_used=zombie.ip
        )

    def _check_zombie_health(self, zombie: ZombieCandidate) -> ZombieState:
        """Check if the current zombie is still reliable."""
        if zombie.failed_probes >= self.FAILOVER_THRESHOLD:
            return ZombieState.DEAD
        elif zombie.failed_probes > 0:
            return ZombieState.DEGRADED
        return ZombieState.HEALTHY

    def _failover_zombie(self) -> bool:
        """Switch to the next best zombie. Returns False if no zombies left."""
        self.active_zombie_idx += 1
        if self.active_zombie_idx < len(self.zombies):
            new_zombie = self.zombies[self.active_zombie_idx]
            logger.warning(
                f"[Idle] Zombie failover → {new_zombie.ip} "
                f"(suitability: {new_zombie.suitability:.2f})"
            )
            self.results.zombie_failovers += 1
            self.results.zombie_used = new_zombie.ip
            return True
        else:
            logger.error("[Idle] No more zombies available for failover!")
            return False

    def scan_ports(self, ports: List[int], max_retries: int = 2) -> IdlePipelineResult:
        """
        Execute idle scan across all ports with zombie failover.
        """
        logger.info(
            f"[Idle] Starting idle scan: {len(ports)} ports via "
            f"zombie {self.active_zombie.ip if self.active_zombie is not None else 'N/A'}"
        )

        for port in ports:
            zombie = self.active_zombie
            if zombie is None:
                logger.error("[Idle] No zombie available — aborting")
                break

            # Check zombie health before each probe
            health = self._check_zombie_health(zombie)
            if health == ZombieState.DEAD:
                if not self._failover_zombie():
                    break
                zombie = self.active_zombie
                if zombie is None:
                    break

            best_result = None
            for attempt in range(max_retries):
                result = self._probe_port_idle(port, zombie)
                if result and result.state != "unknown":
                    best_result = result
                    best_result.attempts = attempt + 1
                    break
                elif result:
                    best_result = result  # Keep unknown as fallback

                # Re-check zombie health after each attempt
                health = self._check_zombie_health(zombie)
                if health == ZombieState.DEAD:
                    if self._failover_zombie():
                        zombie = self.active_zombie
                        if zombie is None:
                            break
                    else:
                        break

            if best_result:
                self.results.port_results[port] = best_result

            # Small inter-probe delay for stealth
            time.sleep(random.uniform(0.05, 0.2))

        logger.info(
            f"[Idle] Scan complete: {len(self.results.port_results)} ports scanned, "
            f"{self.results.total_probes} total probes, "
            f"{self.results.zombie_failovers} failovers"
        )

        return self.results


def run_idle_pipeline(
    target_ip: str,
    ports: List[int],
    zombie_ip: Optional[str] = None,
    zombie_subnet: Optional[str] = None,
    zombie_port: int = 80,
    timeout: float = 2.0,
) -> Optional[IdlePipelineResult]:
    """
    Complete idle scan pipeline entry point.

    Args:
        target_ip: The target to scan (zero packets from us reach this)
        ports: Ports to scan on the target
        zombie_ip: Manual zombie IP (skip discovery/validation)
        zombie_subnet: Subnet to discover zombies from (e.g., "192.168.1.0")
        zombie_port: Port to use for zombie probing (default 80)
        timeout: Packet timeout in seconds
    """
    logger.info(f"[Idle Pipeline] Target: {target_ip}, Ports: {len(ports)}")

    # Step 1: Discover zombie candidates
    discovery = ZombieDiscovery(timeout=timeout)

    if zombie_ip:
        # Manual zombie — validate it directly
        candidate_ips = [zombie_ip]
        logger.info(f"[Idle Pipeline] Using manual zombie: {zombie_ip}")
    elif zombie_subnet:
        logger.info(f"[Idle Pipeline] Discovering zombies in {zombie_subnet}/24...")
        candidate_ips = discovery.discover_from_subnet(zombie_subnet, count=15)
    else:
        # Try to use the target's /24 as zombie hunting ground
        parts = target_ip.split('.')
        subnet_base = '.'.join(parts[:3]) + '.0'
        logger.info(f"[Idle Pipeline] Auto-discovering zombies near target in {subnet_base}/24...")
        candidate_ips = discovery.discover_from_subnet(subnet_base, count=15)

    if not candidate_ips:
        logger.error("[Idle Pipeline] No responsive hosts found for zombie selection")
        return None

    # Step 2: Validate and rank zombies
    validator = ZombieValidator(timeout=timeout)
    zombies = validator.validate_and_rank(candidate_ips, port=zombie_port)

    if not zombies:
        logger.error(
            "[Idle Pipeline] No hosts with predictable IP IDs found. "
            "Idle scan requires at least one zombie with incrementing IP IDs."
        )
        return None

    logger.info(
        f"[Idle Pipeline] Best zombie: {zombies[0].ip} "  # type: ignore[index]
        f"(suitability: {zombies[0].suitability:.2f}, "  # type: ignore[index]
        f"pattern: {zombies[0].pattern}, OS: {zombies[0].os_guess})"  # type: ignore[index]
    )

    # Step 3: Execute idle scan
    orchestrator = IdleScanOrchestrator(target_ip, zombies, timeout=timeout)
    result = orchestrator.scan_ports(ports)

    return result
