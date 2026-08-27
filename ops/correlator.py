"""
USARE Multi-Signal Intelligence Correlator

Cross-references results from ALL modules to produce unified,
high-confidence intelligence:

1. Multi-signal OS detection (TCP fingerprint + clock skew + IPID + banner + SSH)
2. Infrastructure topology (traceroute + TTL + ICMP quoting + ACL mapping)
3. Service dependency graph (group ports by application)
4. Composite confidence scoring from all contributing signals
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("usare.correlator")


@dataclass
class OSCandidate:
    """OS identification candidate with multi-signal confidence."""
    name: str
    confidence: float
    signals: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "confidence": round(self.confidence, 3),
            "signals": {k: round(v, 3) for k, v in self.signals.items()},
        }


@dataclass
class ServiceCluster:
    """Group of ports belonging to the same application."""
    service_name: str
    ports: List[int] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class InfraNode:
    """A node in the inferred infrastructure topology."""
    role: str            # "edge_firewall", "load_balancer", "host", "cdn"
    hop_distance: Optional[int] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    """Complete correlated intelligence picture."""
    target_ip: str
    os_candidates: List[OSCandidate] = field(default_factory=list)
    best_os: str = "Unknown"
    best_os_confidence: float = 0.0
    infrastructure: List[InfraNode] = field(default_factory=list)
    service_clusters: List[ServiceCluster] = field(default_factory=list)
    signals_used: int = 0
    anomalies: List[str] = field(default_factory=list)
    mitre_attack: List[Dict[str, Any]] = field(default_factory=list)
    remediations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target": self.target_ip,
            "best_os": self.best_os,
            "best_os_confidence": round(self.best_os_confidence, 3),
            "os_candidates": [c.to_dict() for c in self.os_candidates],
            "infrastructure": [{"role": n.role, "hop": n.hop_distance, "evidence": n.evidence}
                               for n in self.infrastructure],
            "service_clusters": [{"name": c.service_name, "ports": c.ports, "evidence": c.evidence}
                                 for c in self.service_clusters],
            "signals_used": self.signals_used,
            "anomalies": self.anomalies,
            "mitre_attack": self.mitre_attack,
            "remediations": self.remediations,
        }


class IntelCorrelator:
    """
    Cross-references all available scan data to produce a unified
    intelligence picture with weighted confidence scoring.
    """

    # OS family signal weights (higher = more reliable signal)
    SIGNAL_WEIGHTS = {
        "tcp_fingerprint": 0.30,
        "clock_skew": 0.20,
        "ipid_pattern": 0.15,
        "ssh_banner": 0.15,
        "banner_grab": 0.10,
        "crypto_fp": 0.10,
    }

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.result = CorrelationResult(target_ip=target_ip)

    def correlate(self, all_data: Dict[str, Any]) -> CorrelationResult:
        """
        Run all correlation analyses on the combined scan data.

        Args:
            all_data: The unified data dict from usare.py containing
                      all module outputs keyed by module name.
        """
        self._correlate_os(all_data)
        self._correlate_infrastructure(all_data)
        self._correlate_services(all_data)
        self._detect_anomalies(all_data)

        # Correlate MITRE ATT&CK Techniques and defensive remediations
        try:
            from recon.vuln_mapping import map_mitre_attack_techniques
            banners = all_data.get("banners") or {}
            vulns = all_data.get("vulnerabilities") or {}
            attack_data = map_mitre_attack_techniques(banners, vulns)
            self.result.mitre_attack = attack_data.get("mitre_techniques", [])
            self.result.remediations = attack_data.get("remediations", [])
        except Exception as _e:
            logger.debug(f"[Correlator] MITRE ATT&CK correlation failed: {_e}")

        logger.info(
            f"[Correlator] Complete: OS={self.result.best_os} "
            f"({self.result.best_os_confidence:.0%}), "
            f"{self.result.signals_used} signals, "
            f"{len(self.result.anomalies)} anomalies, "
            f"{len(self.result.mitre_attack)} MITRE ATT&CK techniques"
        )

        return self.result

    def _correlate_os(self, data: Dict[str, Any]):
        """Multi-signal OS identification."""
        os_scores: Dict[str, Dict[str, float]] = defaultdict(dict)

        # Signal 1: TCP OS fingerprint
        os_fp = data.get("os_fingerprint", {})
        if os_fp:
            os_name = os_fp.get("os_guess", "")
            if os_name and os_name != "Unknown":
                confidence = os_fp.get("confidence", 0.5)
                os_scores[os_name]["tcp_fingerprint"] = confidence
                self.result.signals_used += 1

        # Signal 2: Clock skew
        clock_data = data.get("clock_skew", {})
        if clock_data:
            os_conf = clock_data.get("os_confidence", {})
            for os_name, conf in os_conf.items():
                os_scores[os_name]["clock_skew"] = conf
            if os_conf:
                self.result.signals_used += 1

        # Signal 3: IP ID pattern
        ipid = data.get("ipid_analysis", {})
        if ipid:
            os_guess = ipid.get("os_guess", "")
            if os_guess and os_guess != "Unknown":
                os_scores[os_guess]["ipid_pattern"] = ipid.get("analysis_confidence", 0.5)
                self.result.signals_used += 1

        # Signal 4: SSH banner
        crypto = data.get("crypto_fingerprint", {})
        if crypto and "ssh" in crypto:
            for port_data in crypto["ssh"].values():
                impl = port_data.get("implementation", "")
                if "OpenSSH" in impl:
                    os_scores["Linux"]["ssh_banner"] = 0.7
                    os_scores["FreeBSD"]["ssh_banner"] = 0.3
                elif "Bitvise" in impl or "WinSSHD" in impl:
                    os_scores["Windows"]["ssh_banner"] = 0.8
                self.result.signals_used += 1

        # Signal 5: Service banners
        scan_data = data.get("scan_results", [])
        if isinstance(scan_data, list):
            for result in scan_data:
                if hasattr(result, "service_guess") and result.service_guess:
                    svc = result.service_guess.lower()
                    if "iis" in svc or "microsoft" in svc:
                        os_scores["Windows"]["banner_grab"] = max(
                            os_scores["Windows"].get("banner_grab", 0), 0.7
                        )
                    elif "apache" in svc or "nginx" in svc:
                        os_scores["Linux"]["banner_grab"] = max(
                            os_scores["Linux"].get("banner_grab", 0), 0.5
                        )

        # Compute weighted consensus
        for os_name, signals in os_scores.items():
            weighted_sum = 0.0
            weight_total = 0.0
            for signal_name, confidence in signals.items():
                weight = self.SIGNAL_WEIGHTS.get(signal_name, 0.1)
                weighted_sum += confidence * weight
                weight_total += weight

            final_confidence = weighted_sum / max(weight_total, 0.01)
            self.result.os_candidates.append(
                OSCandidate(name=os_name, confidence=final_confidence, signals=signals)
            )

        # Sort and select best
        self.result.os_candidates.sort(key=lambda c: c.confidence, reverse=True)
        if self.result.os_candidates:
            self.result.best_os = self.result.os_candidates[0].name
            self.result.best_os_confidence = self.result.os_candidates[0].confidence

    def _correlate_infrastructure(self, data: Dict[str, Any]):
        """Build infrastructure topology from multi-source data."""

        # From traceroute
        trace = data.get("traceroute", {})
        if trace:
            fw_hop = trace.get("firewall_position")
            if fw_hop:
                self.result.infrastructure.append(InfraNode(
                    role="edge_firewall", hop_distance=fw_hop,
                    evidence=["traceroute: TTL drop detected"]
                ))

        # From ACL mapping
        acl = data.get("acl_map", {})
        if acl:
            summary = acl.get("firewall_summary", "")
            if "stateful" in summary.lower():
                self.result.infrastructure.append(InfraNode(
                    role="stateful_firewall",
                    evidence=[f"ACL inference: {summary}"]
                ))

            edge_ttl = acl.get("edge_firewall_ttl")
            host_ttl = acl.get("host_ttl")
            if edge_ttl and host_ttl and edge_ttl != host_ttl:
                self.result.infrastructure.append(InfraNode(
                    role="multi_hop_filtering",
                    evidence=[f"Edge TTL={edge_ttl}, Host TTL={host_ttl}"]
                ))

        # From ICMP quoting
        icmp = data.get("icmp_quotations", {})
        if icmp:
            for ttl, leak in icmp.items():
                if isinstance(leak, dict) and leak.get("nat_detected", "").startswith("True"):
                    self.result.infrastructure.append(InfraNode(
                        role="nat_gateway", hop_distance=int(ttl) if str(ttl).isdigit() else None,
                        evidence=[f"ICMP quotation leak at hop {ttl}"]
                    ))

        # Host node
        self.result.infrastructure.append(InfraNode(
            role="target_host",
            evidence=[f"Target: {self.target_ip}"]
        ))

    def _correlate_services(self, data: Dict[str, Any]):
        """Group ports into service clusters."""
        port_services: Dict[str, List[int]] = defaultdict(list)

        # From scan results
        scan_data = data.get("scan_results", [])
        if isinstance(scan_data, list):
            for result in scan_data:
                if hasattr(result, "service_guess") and result.service_guess:
                    port_services[result.service_guess].append(result.port)

        # From app probes
        app = data.get("app_probes", {})
        if app and "services" in app:
            for port_str, svc in app["services"].items():
                proto = svc.get("protocol", "unknown")
                port_services[proto].append(int(port_str) if str(port_str).isdigit() else 0)

        # Web server cluster (merge HTTP/HTTPS variants)
        web_ports = []
        for svc_name in list(port_services.keys()):
            if any(w in svc_name.lower() for w in ["http", "https", "web", "nginx", "apache", "iis"]):
                web_ports.extend(port_services.pop(svc_name))

        if web_ports:
            self.result.service_clusters.append(ServiceCluster(
                service_name="Web Application",
                ports=sorted(set(web_ports)),
                evidence=["HTTP/HTTPS ports grouped"],
                confidence=0.8,
            ))

        for svc_name, ports in port_services.items():
            if len(ports) >= 1:
                self.result.service_clusters.append(ServiceCluster(
                    service_name=svc_name,
                    ports=sorted(set(ports)),
                    evidence=[f"Service detection: {svc_name}"],
                    confidence=0.6,
                ))

    def _detect_anomalies(self, data: Dict[str, Any]):
        """Detect contradictory or unusual signals."""

        # OS contradiction check
        if len(self.result.os_candidates) >= 2:
            top_two = self.result.os_candidates[:2]
            if (top_two[0].confidence > 0.4 and top_two[1].confidence > 0.4
                    and top_two[0].name != top_two[1].name):
                diff = abs(top_two[0].confidence - top_two[1].confidence)
                if diff < 0.15:
                    self.result.anomalies.append(
                        f"OS ambiguity: {top_two[0].name} ({top_two[0].confidence:.0%}) vs "
                        f"{top_two[1].name} ({top_two[1].confidence:.0%}) — "
                        "possible OS spoofing or honeypot"
                    )

        # VM detection
        clock = data.get("clock_skew", {})
        if clock and clock.get("is_vm"):
            self.result.anomalies.append("Virtual machine detected via clock skew inconsistency")

        # Multiple infrastructure layers
        fw_count = sum(1 for n in self.result.infrastructure
                       if "firewall" in n.role or "nat" in n.role)
        if fw_count >= 2:
            self.result.anomalies.append(
                f"{fw_count} filtering/NAT layers detected — hardened perimeter"
            )
