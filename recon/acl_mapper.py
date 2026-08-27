"""
USARE Firewall ACL Inference Engine

Systematically maps the target's firewall ruleset by sending multiple
TCP flag combinations (SYN, ACK, FIN, XMAS, NULL) to each port and
analyzing the differential responses to infer:

1. Stateful vs stateless filtering rules
2. Edge firewall vs host firewall (via TTL hop-count differences)
3. ICMP admin-prohibited vs host-unreachable distinction
4. Complete ACL map: open, closed-by-host, filtered-by-edge, filtered-by-host
"""

import time
import random
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from scapy.all import IP, TCP, ICMP, sr1, conf
import threading

logger = logging.getLogger("usare.acl_mapper")


class FilterType(Enum):
    OPEN = "open"
    CLOSED_BY_HOST = "closed_by_host"
    FILTERED_EDGE = "filtered_edge_firewall"
    FILTERED_HOST = "filtered_host_firewall"
    FILTERED_UNKNOWN = "filtered_unknown"
    ADMIN_PROHIBITED = "admin_prohibited"
    UNFILTERED = "unfiltered"


class FirewallType(Enum):
    STATEFUL = "stateful"
    STATELESS = "stateless"
    UNKNOWN = "unknown"


@dataclass
class ProbeResponse:
    """Response to a single TCP flag probe."""
    flags_sent: str          # SYN, ACK, FIN, XMAS, NULL
    got_response: bool
    response_flags: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None


@dataclass
class PortACL:
    """Inferred ACL entry for a single port."""
    port: int
    filter_type: FilterType
    firewall_type: FirewallType
    responses: Dict[str, ProbeResponse] = field(default_factory=dict)
    ttl_variance: float = 0.0
    hop_distance: Optional[int] = None
    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class ACLMap:
    """Complete ACL map for the target."""
    target_ip: str
    port_acls: Dict[int, PortACL] = field(default_factory=dict)
    edge_firewall_ttl: Optional[int] = None
    host_ttl: Optional[int] = None
    firewall_summary: str = ""
    total_probes: int = 0

    def to_dict(self) -> Dict:
        result = {
            "target": self.target_ip,
            "edge_firewall_ttl": self.edge_firewall_ttl,
            "host_ttl": self.host_ttl,
            "firewall_summary": self.firewall_summary,
            "total_probes": self.total_probes,
            "ports": {},
        }
        for port, acl in self.port_acls.items():
            result["ports"][port] = {
                "filter_type": acl.filter_type.value,
                "firewall_type": acl.firewall_type.value,
                "confidence": acl.confidence,
                "hop_distance": acl.hop_distance,
                "notes": acl.notes,
            }
        return result


# TCP flag combinations for ACL inference
PROBE_FLAGS = {
    "SYN": "S",
    "ACK": "A",
    "FIN": "F",
    "XMAS": "FPU",       # FIN+PSH+URG
    "NULL": "",           # No flags
    "SYN_ACK": "SA",
}


class ACLMapper:
    """
    Maps firewall rules by probing with different TCP flag combinations
    and analyzing differential responses.

    The key insight: stateful firewalls treat SYN differently from ACK/FIN.
    Stateless firewalls apply the same rule regardless of flags.
    """

    # ICMP codes that indicate specific filtering
    ICMP_ADMIN_PROHIBITED = {9, 10, 13}  # type 3, codes 9/10/13
    ICMP_HOST_UNREACHABLE = {1}           # type 3, code 1
    ICMP_PORT_UNREACHABLE = {3}           # type 3, code 3

    def __init__(self, target_ip: str, timeout: float = 2.0,
                 inter_probe_delay: float = 0.1):
        self.target_ip = target_ip
        self.timeout = timeout
        self.inter_probe_delay = inter_probe_delay
        self.acl_map = ACLMap(target_ip=target_ip)
        self._ttl_observations: List[int] = []

    def _send_probe(self, port: int, flags: str, flag_name: str) -> ProbeResponse:
        """Send a single TCP probe and analyze the response."""
        src_port = random.randint(40000, 60000)

        pkt = IP(dst=self.target_ip) / TCP(
            sport=src_port, dport=port,
            flags=flags, seq=random.randint(0, 2**32 - 1)
        )

        t0 = time.time()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        latency = (time.time() - t0) * 1000

        self.acl_map.total_probes += 1

        if resp is None:
            return ProbeResponse(
                flags_sent=flag_name,
                got_response=False,
                latency_ms=latency,
            )

        # TCP response
        if resp.haslayer(TCP):
            tcp_flags = str(resp[TCP].flags)
            ttl = resp[IP].ttl
            self._ttl_observations.append(ttl)
            return ProbeResponse(
                flags_sent=flag_name,
                got_response=True,
                response_flags=tcp_flags,
                ttl=ttl,
                latency_ms=latency,
            )

        # ICMP response (filtering indicator)
        if resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            ttl = resp[IP].ttl
            self._ttl_observations.append(ttl)
            return ProbeResponse(
                flags_sent=flag_name,
                got_response=True,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                ttl=ttl,
                latency_ms=latency,
            )

        return ProbeResponse(
            flags_sent=flag_name,
            got_response=False,
            latency_ms=latency,
        )

    def probe_port(self, port: int) -> PortACL:
        """
        Send all TCP flag combinations to a single port and infer ACL.
        """
        port_acl = PortACL(port=port, filter_type=FilterType.UNFILTERED,
                           firewall_type=FirewallType.UNKNOWN)

        # Send each probe type
        for flag_name, flags in PROBE_FLAGS.items():
            resp = self._send_probe(port, flags, flag_name)
            port_acl.responses[flag_name] = resp
            time.sleep(self.inter_probe_delay)

        # Analyze differential responses
        self._infer_acl(port_acl)

        return port_acl

    def _infer_acl(self, acl: PortACL):
        """
        Infer the ACL entry from differential response analysis.
        """
        syn_resp = acl.responses.get("SYN")
        ack_resp = acl.responses.get("ACK")
        fin_resp = acl.responses.get("FIN")
        xmas_resp = acl.responses.get("XMAS")
        null_resp = acl.responses.get("NULL")

        if not syn_resp:
            return

        # ═══════════════════════════════════════
        # Case 1: SYN got SYN-ACK → Port is OPEN
        # ═══════════════════════════════════════
        if syn_resp.got_response and syn_resp.response_flags and "SA" in syn_resp.response_flags:
            acl.filter_type = FilterType.OPEN
            acl.confidence = 0.95

            # Check if ACK also gets RST (expected for open port + stateful FW)
            if ack_resp and ack_resp.got_response and ack_resp.response_flags and "R" in ack_resp.response_flags:
                acl.firewall_type = FirewallType.STATEFUL
                acl.notes.append("ACK probe returned RST — stateful firewall or host stack")
            elif ack_resp and not ack_resp.got_response:
                acl.firewall_type = FirewallType.STATEFUL
                acl.notes.append("ACK probe silently dropped — stateful firewall (only SYN allowed)")

            acl.hop_distance = syn_resp.ttl
            return

        # ═══════════════════════════════════════
        # Case 2: SYN got RST → Port is CLOSED
        # ═══════════════════════════════════════
        if syn_resp.got_response and syn_resp.response_flags and "R" in syn_resp.response_flags:
            acl.filter_type = FilterType.CLOSED_BY_HOST
            acl.confidence = 0.90

            # If ACK also gets RST, firewall is transparent (stateless or no FW)
            if ack_resp and ack_resp.got_response and ack_resp.response_flags and "R" in ack_resp.response_flags:
                acl.firewall_type = FirewallType.STATELESS
                acl.notes.append("Both SYN and ACK get RST — no stateful filtering")
            elif ack_resp and not ack_resp.got_response:
                acl.firewall_type = FirewallType.STATEFUL
                acl.notes.append("SYN gets RST but ACK dropped — stateful FW passes SYN to host")

            acl.hop_distance = syn_resp.ttl
            return

        # ═══════════════════════════════════════
        # Case 3: SYN got ICMP error → Filtered
        # ═══════════════════════════════════════
        if syn_resp.got_response and syn_resp.icmp_type == 3:
            if syn_resp.icmp_code in self.ICMP_ADMIN_PROHIBITED:
                acl.filter_type = FilterType.ADMIN_PROHIBITED
                acl.notes.append(f"ICMP type 3 code {syn_resp.icmp_code} — admin prohibited")
                acl.confidence = 0.95
            elif syn_resp.icmp_code in self.ICMP_HOST_UNREACHABLE:
                acl.filter_type = FilterType.FILTERED_EDGE
                acl.notes.append("ICMP host unreachable — edge firewall blocking")
                acl.confidence = 0.85
            else:
                acl.filter_type = FilterType.FILTERED_UNKNOWN
                acl.notes.append(f"ICMP type 3 code {syn_resp.icmp_code}")
                acl.confidence = 0.70

            # TTL analysis: if ICMP TTL is much higher than TCP responses,
            # the ICMP came from an intermediate device (edge firewall)
            if syn_resp.ttl and self._ttl_observations:
                avg_ttl = sum(self._ttl_observations) / len(self._ttl_observations)
                if syn_resp.ttl > avg_ttl + 5:
                    acl.filter_type = FilterType.FILTERED_EDGE
                    acl.notes.append(f"TTL {syn_resp.ttl} > avg {avg_ttl:.0f} — ICMP from edge device")
                elif syn_resp.ttl < avg_ttl - 5:
                    acl.filter_type = FilterType.FILTERED_HOST
                    acl.notes.append(f"TTL {syn_resp.ttl} < avg {avg_ttl:.0f} — ICMP from host")

            acl.hop_distance = syn_resp.ttl
            return

        # ═══════════════════════════════════════
        # Case 4: SYN got no response → Filtered (silent drop)
        # ═══════════════════════════════════════
        if not syn_resp.got_response:
            # Check if other flag types get through
            non_syn_responses = [
                (name, resp) for name, resp in acl.responses.items()
                if name != "SYN" and resp.got_response
            ]

            if non_syn_responses:
                # SYN blocked but other flags pass → stateful firewall
                acl.filter_type = FilterType.FILTERED_EDGE
                acl.firewall_type = FirewallType.STATEFUL
                acl.confidence = 0.90
                passed_flags = [name for name, _ in non_syn_responses]
                acl.notes.append(f"SYN silently dropped but {', '.join(passed_flags)} pass — stateful FW")

                # If ACK gets RST, the host is alive behind the firewall
                if ack_resp and ack_resp.got_response and ack_resp.response_flags and "R" in ack_resp.response_flags:
                    acl.notes.append("ACK gets RST — host alive behind stateful firewall")
                    # Infer host TTL from ACK response
                    if ack_resp.ttl:
                        acl.hop_distance = ack_resp.ttl
            else:
                # Everything dropped — could be edge or host
                acl.filter_type = FilterType.FILTERED_UNKNOWN
                acl.firewall_type = FirewallType.UNKNOWN
                acl.confidence = 0.50
                acl.notes.append("All probes silently dropped — heavy filtering")

        # Compute TTL variance for this port
        ttls = [r.ttl for r in acl.responses.values() if r.ttl is not None]
        if len(ttls) >= 2:
            acl.ttl_variance = max(ttls) - min(ttls)
            if acl.ttl_variance > 3:
                acl.notes.append(
                    f"TTL variance across probes: {acl.ttl_variance} — "
                    "responses may come from different devices"
                )

    def map_ports(self, ports: List[int]) -> ACLMap:
        """Map ACL rules for a list of ports."""
        logger.info(f"[ACL] Mapping firewall rules for {len(ports)} ports on {self.target_ip}")

        for port in ports:
            acl = self.probe_port(port)
            self.acl_map.port_acls[port] = acl

        # Infer edge vs host firewall TTLs from all observations
        self._infer_firewall_topology()

        return self.acl_map

    def _infer_firewall_topology(self):
        """
        Analyze TTL patterns across all probed ports to distinguish
        edge firewall responses from host responses.
        """
        if not self._ttl_observations:
            return

        # Group TTLs into clusters (edge FW typically has different TTL than host)
        ttl_set = sorted(set(self._ttl_observations))

        if len(ttl_set) >= 2:
            # Simple two-cluster approach: highest TTL = closest device (edge FW)
            # lowest TTL = furthest device (host or host FW)
            self.acl_map.host_ttl = min(ttl_set)
            self.acl_map.edge_firewall_ttl = max(ttl_set)

        # Count filter types for summary
        filter_counts: Dict[str, int] = {}
        for acl in self.acl_map.port_acls.values():
            ft = acl.filter_type.value
            filter_counts[ft] = filter_counts.get(ft, 0) + 1

        stateful_count = sum(
            1 for acl in self.acl_map.port_acls.values()
            if acl.firewall_type == FirewallType.STATEFUL
        )
        stateless_count = sum(
            1 for acl in self.acl_map.port_acls.values()
            if acl.firewall_type == FirewallType.STATELESS
        )

        parts = []
        if stateful_count > stateless_count:
            parts.append("Primary: stateful firewall detected")
        elif stateless_count > 0:
            parts.append("Primary: stateless/packet-filter firewall")

        for ft, count in sorted(filter_counts.items(), key=lambda x: -x[1]):
            parts.append(f"{ft}: {count} ports")

        self.acl_map.firewall_summary = " | ".join(parts)
        logger.info(f"[ACL] Mapping complete: {self.acl_map.firewall_summary}")
