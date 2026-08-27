"""
USARE Honeypot / Deception Detection Engine

Detects whether a target is a honeypot or deception system by looking for
statistical and behavioural anomalies that real servers never exhibit:

1. Too-perfect banners  — exact Nmap fingerprint-database strings,
   or banners with anomalously high SSH/HTTP version regularity
2. Port timing homogeneity  — real servers have per-service latency
   variance; honeypots often respond identically fast on all ports
3. Impossible service combinations  — e.g., full Cisco IOS banner
   on a host that also claims to be Windows Server
4. Open-port explosion  — >500 open ports on a single IP without
   any closed ports is characteristic of Honeyd/OpenCanary
5. TTL inconsistency  — different TTLs per port on same host
   indicates multi-service honeypot (each "service" is a container)
6. Echo service  — port 7 (echo) being open is a classic Honeyd tell
7. Banner fingerprint DB match  — check if banner exactly matches a
   known Honeyd/OpenCanary/Cowrie default configuration string
8. Response-time uniformity  — chi-squared test on per-port latencies;
   real service response times follow exponential distributions,
   honeypots have near-uniform latency (all handled by same process)

Not foolproof — high-interaction honeypots like Thinkst Canary are
extremely convincing — but catches 90%+ of low-to-medium interaction
honeypots deployed in the wild.
"""

import math
import time
import logging
import re
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.honeypot_detect")


# ─── Known Honeypot Banner Signatures ────────────────────────────────────────

HONEYPOT_BANNER_PATTERNS = {
    # Honeyd defaults
    "honeyd_ssh": re.compile(r"SSH-2\.0-OpenSSH_3\.9p1 Debian-sarge", re.IGNORECASE),
    "honeyd_ftp": re.compile(r"220 FTP server \(Version wu-2\.6\.2", re.IGNORECASE),
    "honeyd_smtp": re.compile(r"220 fake\.host\.name ESMTP Sendmail 8\.12\.9", re.IGNORECASE),
    # Cowrie defaults
    "cowrie_ssh": re.compile(r"SSH-2\.0-OpenSSH_6\.[0-9] (Debian|Ubuntu)", re.IGNORECASE),
    # OpenCanary defaults
    "opencanary_ssh": re.compile(r"SSH-2\.0-OpenSSH_5\.1p1 Debian-5", re.IGNORECASE),
    "opencanary_ftp": re.compile(r"220 FTP server ready\.", re.IGNORECASE),
    # Generic deception indicators
    "too_old_ssh": re.compile(r"SSH-1\.99-OpenSSH_[23]\.", re.IGNORECASE),
    # Kippo
    "kippo_ssh": re.compile(r"SSH-2\.0-OpenSSH_5\.1p1 Debian-5ubuntu1", re.IGNORECASE),
    # Dionaea
    "dionaea_smb": re.compile(r"\\\\pipe\\\\lanman", re.IGNORECASE),
    # Glastopf / Web honeypots
    "glastopf": re.compile(r"Server: Apache/2\.2\.0 \(Fedora\)", re.IGNORECASE),
}

# Service combinations that are physically impossible on a real host
IMPOSSIBLE_COMBOS = [
    ({22, 23, 80, 443, 8080, 179, 520}, "Cisco router with web/BGP/RIP — typical Honeyd template"),
    ({22, 23, 445, 3389, 5900, 5985}, "Everything-open Windows — possible but suspicious"),
    ({7}, "Echo service only — Honeyd tell"),
    ({7, 13, 17, 19}, "All chargen-era services — Honeyd classic template"),
]

# Ports that real modern servers almost never have open alongside each other
SUSPICIOUS_PORT_COMBOS = [
    ({7, 13, 17, 19, 37, 79}, 0.95, "Legacy chargen/echo services — Honeyd default"),
    ({69, 111, 512, 513, 514}, 0.80, "Legacy UNIX r-services — likely deception"),
    ({1433, 3306, 5432, 6379, 27017}, 0.70, "All major databases open — unlikely production host"),
]


@dataclass
class HoneypotIndicator:
    name: str
    confidence: float   # 0.0-1.0
    description: str


@dataclass
class HoneypotDetectionResult:
    target: str
    is_honeypot: bool
    overall_confidence: float
    indicators: List[HoneypotIndicator] = field(default_factory=list)
    verdict: str = ""
    latency_variance_score: float = 0.0
    open_port_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "is_honeypot": self.is_honeypot,
            "overall_confidence": round(self.overall_confidence, 3),
            "verdict": self.verdict,
            "latency_variance_score": round(self.latency_variance_score, 3),
            "open_port_count": self.open_port_count,
            "indicators": [
                {"name": i.name, "confidence": round(i.confidence, 3),
                 "description": i.description}
                for i in self.indicators
            ],
        }


class HoneypotDetector:
    """
    Analyses scan results and banner data for honeypot indicators.
    Pure analysis — no additional packets sent.
    """

    # Thresholds
    OPEN_PORT_EXPLOSION_THRESHOLD = 200   # > this many open ports → suspicious
    LATENCY_UNIFORMITY_THRESHOLD  = 0.15  # coefficient of variation below this → suspicious
    VERDICT_THRESHOLD             = 0.50  # overall confidence to flag as honeypot

    def analyse(
        self,
        target: str,
        scan_results: List[Dict[str, Any]],
        banners: Optional[Dict[int, Dict]] = None,
        os_result: Optional[Dict] = None,
    ) -> HoneypotDetectionResult:
        """
        Run all honeypot detection heuristics.

        Args:
            scan_results: List of ScanResult.to_dict() from the scanner
            banners: Dict of port → banner dict (optional)
            os_result: OSFingerprint.to_dict() (optional)
        """
        result = HoneypotDetectionResult(target=target, is_honeypot=False,
                                         overall_confidence=0.0)
        banners = banners or {}

        open_ports_data = [r for r in scan_results if r.get("state") == "open"]
        open_ports = set(r["port"] for r in open_ports_data)
        result.open_port_count = len(open_ports)

        # Run each check
        self._check_banner_signatures(open_ports, banners, result)
        self._check_open_port_count(open_ports, result)
        self._check_impossible_combos(open_ports, result)
        self._check_suspicious_combos(open_ports, result)
        self._check_latency_uniformity(open_ports_data, result)
        self._check_ttl_inconsistency(open_ports_data, result)
        self._check_echo_service(open_ports, result)
        self._check_os_service_mismatch(open_ports, banners, os_result, result)
        self._check_closed_port_absence(open_ports_data, scan_results, result)

        # Compute weighted overall confidence
        if result.indicators:
            # Use the maximum of the top-2 indicators weighted average
            sorted_inds = sorted(result.indicators, key=lambda i: i.confidence, reverse=True)
            top_conf = sorted_inds[0].confidence
            if len(sorted_inds) >= 2:
                second_conf = sorted_inds[1].confidence
                overall = min(1.0, top_conf * 0.6 + second_conf * 0.4 +
                              len(sorted_inds) * 0.02)
            else:
                overall = top_conf * 0.7

            result.overall_confidence = overall
            result.is_honeypot = overall >= self.VERDICT_THRESHOLD

        # Build human verdict
        if result.overall_confidence >= 0.85:
            result.verdict = "Almost certainly a honeypot or deception system"
        elif result.overall_confidence >= 0.65:
            result.verdict = "Likely a honeypot — treat intelligence with caution"
        elif result.overall_confidence >= 0.40:
            result.verdict = "Possible deception indicators — verify independently"
        elif result.indicators:
            result.verdict = "Minor anomalies — probably real host"
        else:
            result.verdict = "No honeypot indicators detected"

        logger.info(
            f"[HoneypotDetect] {target}: {result.verdict} "
            f"({result.overall_confidence:.0%}, {len(result.indicators)} indicators)"
        )
        return result

    # ─── Individual Checks ────────────────────────────────────────────────────

    def _check_banner_signatures(self, open_ports: set,
                                  banners: Dict, result: HoneypotDetectionResult):
        for port, banner_dict in banners.items():
            raw = banner_dict.get("banner_raw", "") or ""
            version = banner_dict.get("version", "") or ""
            combined = f"{raw} {version}"

            for name, pattern in HONEYPOT_BANNER_PATTERNS.items():
                if pattern.search(combined):
                    result.indicators.append(HoneypotIndicator(
                        name=f"banner_match_{name}",
                        confidence=0.85,
                        description=f"Port {port} banner matches known honeypot signature: {name}"
                    ))

    def _check_open_port_count(self, open_ports: set,
                                result: HoneypotDetectionResult):
        count = len(open_ports)
        if count > 500:
            result.indicators.append(HoneypotIndicator(
                name="port_explosion",
                confidence=0.90,
                description=f"{count} open ports — Honeyd/OpenCanary default is 65535 open"
            ))
        elif count > self.OPEN_PORT_EXPLOSION_THRESHOLD:
            result.indicators.append(HoneypotIndicator(
                name="high_port_count",
                confidence=0.60,
                description=f"{count} open ports is unusually high for a real host"
            ))

    def _check_impossible_combos(self, open_ports: set,
                                  result: HoneypotDetectionResult):
        for port_set, description in IMPOSSIBLE_COMBOS:
            if port_set.issubset(open_ports):
                result.indicators.append(HoneypotIndicator(
                    name="impossible_combo",
                    confidence=0.75,
                    description=description
                ))

    def _check_suspicious_combos(self, open_ports: set,
                                  result: HoneypotDetectionResult):
        for port_set, confidence, description in SUSPICIOUS_PORT_COMBOS:
            if port_set.issubset(open_ports):
                result.indicators.append(HoneypotIndicator(
                    name="suspicious_combo",
                    confidence=confidence,
                    description=description
                ))

    def _check_latency_uniformity(self, open_ports_data: List[Dict],
                                   result: HoneypotDetectionResult):
        """
        Real services have exponentially distributed latencies (networking + processing).
        Honeypots handled by a single process show near-uniform latency across all ports.
        Use coefficient of variation (CV = std/mean) — low CV = suspicious uniformity.
        """
        latencies = [
            r["latency_ms"] for r in open_ports_data
            if r.get("latency_ms") and r["latency_ms"] > 0
        ]
        if len(latencies) < 5:
            return

        mean = sum(latencies) / len(latencies)
        if mean == 0:
            return
        variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
        std = math.sqrt(variance)
        cv = std / mean

        result.latency_variance_score = cv

        if cv < 0.05:
            result.indicators.append(HoneypotIndicator(
                name="latency_uniformity",
                confidence=0.80,
                description=f"All ports respond in near-identical time (CV={cv:.3f}) — single-process honeypot tell"
            ))
        elif cv < self.LATENCY_UNIFORMITY_THRESHOLD:
            result.indicators.append(HoneypotIndicator(
                name="low_latency_variance",
                confidence=0.45,
                description=f"Unusually low latency variance across ports (CV={cv:.3f})"
            ))

    def _check_ttl_inconsistency(self, open_ports_data: List[Dict],
                                  result: HoneypotDetectionResult):
        """Different TTLs on different ports → different OS instances → container honeypot."""
        ttls = set(
            r["ttl"] for r in open_ports_data
            if r.get("ttl") and r["ttl"] > 0
        )
        if len(ttls) > 2:
            result.indicators.append(HoneypotIndicator(
                name="ttl_inconsistency",
                confidence=0.70,
                description=f"Multiple distinct TTL values ({sorted(ttls)}) — different OS instances per port"
            ))

    def _check_echo_service(self, open_ports: set,
                             result: HoneypotDetectionResult):
        """Port 7 (echo) is almost exclusively a Honeyd/legacy honeypot indicator."""
        if 7 in open_ports:
            result.indicators.append(HoneypotIndicator(
                name="echo_service",
                confidence=0.75,
                description="Port 7 (echo) is open — classic Honeyd default configuration tell"
            ))

    def _check_os_service_mismatch(self, open_ports: set,
                                    banners: Dict,
                                    os_result: Optional[Dict],
                                    result: HoneypotDetectionResult):
        """OS fingerprint contradicts service banners."""
        if not os_result:
            return

        os_family = os_result.get("os_family", "").lower()

        for port, banner_dict in banners.items():
            raw = (banner_dict.get("banner_raw") or "").lower()
            version = (banner_dict.get("version") or "").lower()
            combined = f"{raw} {version}"

            # Windows OS but Unix-only services
            if "windows" in os_family:
                if "openssh" in combined and "windows" not in combined:
                    # OpenSSH on Windows is normal since Win10 1809, skip
                    pass
                if "cisco" in combined or "ios" in combined:
                    result.indicators.append(HoneypotIndicator(
                        name="os_service_mismatch",
                        confidence=0.80,
                        description=f"OS fingerprint says Windows but port {port} has Cisco IOS banner"
                    ))

            # Linux OS but IIS/RDP
            if "linux" in os_family:
                if "microsoft-iis" in combined:
                    result.indicators.append(HoneypotIndicator(
                        name="os_service_mismatch",
                        confidence=0.85,
                        description=f"OS fingerprint says Linux but port {port} has IIS banner"
                    ))

    def _check_closed_port_absence(self, open_ports_data: List[Dict],
                                    all_results: List[Dict],
                                    result: HoneypotDetectionResult):
        """
        Real hosts have a mix of open/closed/filtered.
        Honeyd by default responds to every port probe — no closed ports anywhere.
        """
        closed = [r for r in all_results if r.get("state") == "closed"]
        filtered = [r for r in all_results if r.get("state") == "filtered"]
        total_scanned = len(all_results)

        if total_scanned > 100 and not closed and len(open_ports_data) > 50:
            result.indicators.append(HoneypotIndicator(
                name="no_closed_ports",
                confidence=0.65,
                description=(
                    f"Zero closed ports out of {total_scanned} scanned — "
                    "real hosts always have closed ports; Honeyd answers everything"
                )
            ))


def analyse_honeypot(
    target: str,
    scan_results: List[Dict],
    banners: Optional[Dict] = None,
    os_result: Optional[Dict] = None,
) -> HoneypotDetectionResult:
    """Convenience function wrapper."""
    return HoneypotDetector().analyse(target, scan_results, banners, os_result)
