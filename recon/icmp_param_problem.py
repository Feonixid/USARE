"""
ICMP Parameter Problem (Type 12) Firewall Mapping.

Sends IP packets with malformed or unusual options; observes ICMP
Parameter Problem (type 12) responses to map firewall behavior,
middlebox presence, and ACL policy. State-level technique.
"""

import logging
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.icmp_param_problem")

try:
    from scapy.all import IP, ICMP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class ParamProbeResult:
    option_type: int
    received_icmp: bool
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    responder_ip: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class ParamProblemReport:
    target: str
    probes: List[ParamProbeResult] = field(default_factory=list)
    firewall_behavior: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "probes": [
                {
                    "option": p.option_type,
                    "icmp": p.received_icmp,
                    "type": p.icmp_type,
                    "code": p.icmp_code,
                    "responder": p.responder_ip,
                }
                for p in self.probes
            ],
            "firewall_behavior": self.firewall_behavior,
            "notes": self.notes,
        }


# IP option types used for probing
# Format: (option_type, encoded_bytes, label)
# Option 0  = EOL — sometimes triggers strict parsers
# Option 1  = NOP
# Option 7  = Record Route (variable-length; needs pointer + slots)
# Option 131 = LSRR (Loose Source and Record Route, 0x83) — NOT Router Alert
# Option 148 = Router Alert (0x94, RFC 2113) — correctly labelled
# Option 68  = Timestamp option (kind=0x44), 4-byte minimal encoding
PROBE_OPTIONS: List[tuple] = [
    (0,   bytes([0]),                         "EOL"),
    (1,   bytes([1]),                         "NOP"),
    # Record Route: kind=7, len=7, pointer=4, one empty 4-byte slot
    (7,   bytes([7, 7, 4, 0, 0, 0, 0]),       "RR"),
    # LSRR: kind=131, len=7, pointer=4, one empty 4-byte slot
    (131, bytes([131, 7, 4, 0, 0, 0, 0]),     "LSRR"),
    # Router Alert: kind=148, len=4, value=0 (RFC 2113)
    (148, bytes([148, 4, 0, 0]),              "RouterAlert"),
]


def probe_param_problem(
    target_ip: str,
    timeout: float = 2.0,
) -> ParamProblemReport:
    """
    Send IP packets with various options, collect ICMP type 12 responses.

    Note: the `port` parameter was removed — this probe operates at the IP
    layer and does not use a transport port.
    """
    report = ParamProblemReport(target=target_ip)
    if not HAS_SCAPY:
        report.notes.append("Scapy required")
        return report
    try:
        conf.verb = 0
        for opt_type, opt_bytes, label in PROBE_OPTIONS:
            try:
                pkt = IP(dst=target_ip, options=opt_bytes) / (b"\x00" * 20)
                t0 = time.perf_counter()
                ans = sr1(pkt, timeout=timeout, verbose=0)
                latency = (time.perf_counter() - t0) * 1000 if ans else None
                res = ParamProbeResult(option_type=opt_type, received_icmp=False)
                if ans and ans.haslayer(ICMP):
                    res.received_icmp = True
                    res.icmp_type = int(ans[ICMP].type)
                    res.icmp_code = int(ans[ICMP].code)
                    res.responder_ip = str(ans[IP].src)
                    res.latency_ms = latency
                report.probes.append(res)
                logger.debug("Param probe opt %d (%s): icmp=%s", opt_type, label, res.received_icmp)
            except Exception as e:
                logger.debug("Param probe opt %d (%s): %s", opt_type, label, e)
        if any(p.received_icmp and p.icmp_type == 12 for p in report.probes):
            report.firewall_behavior = "Sends ICMP Param Problem for malformed options"
        elif any(p.received_icmp for p in report.probes):
            report.firewall_behavior = "Responds with ICMP (non-param-problem)"
        else:
            report.firewall_behavior = "No ICMP response to IP options"
    except Exception as e:
        report.notes.append(str(e))
    return report
