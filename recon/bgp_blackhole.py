"""
USARE BGP Blackhole Route Detection Engine

Differentiates between four distinct reasons a probe might get no response:

  1. Host is down / unreachable normally
  2. Stateful firewall silently drops the packet
  3. BGP Remote Triggered Black Hole (RTBH) — the route is announced but
     null-routed in the upstream provider's backbone
  4. Provider-level RTBH — the /32 host route is withdrawn from the DFZ

══════════════════════════════════════════════════════════════════════
WHY THIS MATTERS FOR RED TEAMS
══════════════════════════════════════════════════════════════════════

When a target applies BGP RTBH against a scanner's source IP, all packets
from that IP are silently dropped at the provider's edge — the scanner
effectively "disappears" from the target's perspective.

Detecting this is critical because:
- If RTBH is active against your source IP, continuing the scan is pointless
- You need to rotate source IPs / use a different egress node
- The presence of RTBH reveals the target has an active DDoS/RTBH service

══════════════════════════════════════════════════════════════════════
DETECTION METHODS
══════════════════════════════════════════════════════════════════════

1. TTL-varying ICMP probes — send pings with TTL=1, 2, 3... and observe
   where they stop.  Normal host-down: ICMP Time Exceeded from all hops.
   RTBH: packets disappear silently at a specific hop that corresponds to
   the provider's edge router.

2. UDP-ICMP port unreachable — send UDP to a high port.  Normal drop:
   ICMP port unreachable.  RTBH: no response at all.  Host down: same as
   RTBH.  Discriminated by #3.

3. Alternate-source verification — repeat from a different source IP/exit
   node.  If one source gets responses and another doesn't, RTBH is
   targeting the first source.

4. BGP Looking Glass comparison — compare routing table at multiple
   looking glass vantage points.  RTBH: more-specific /32 route announced
   with community 0:666 or similar RTBH tag.

5. ICMP echo from spoofed source — send ICMP from an obviously-spoofed
   address (e.g., 192.0.2.1) to the target.  If RTBH is source-specific,
   the spoofed probe may get through.  (Requires raw socket + spoofing.)
"""

import time
import socket
import random
import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.bgp_blackhole")

try:
    from scapy.all import IP, ICMP, UDP, TCP, Raw, sr1, send, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class BlackholeHopResult:
    ttl: int
    router_ip: Optional[str]
    icmp_type: Optional[int]
    icmp_code: Optional[int]
    got_response: bool
    latency_ms: float = 0.0


@dataclass
class BGPBlackholeResult:
    target: str
    blackholed: bool = False
    blackhole_type: str = ""   # "source_rtbh", "destination_rtbh", "firewall_drop", "host_down", "reachable"
    confidence: float = 0.0
    silent_drop_hop: Optional[int] = None   # TTL where responses stop
    last_responding_router: Optional[str] = None
    hops: List[BlackholeHopResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "blackholed": self.blackholed,
            "blackhole_type": self.blackhole_type,
            "confidence": round(self.confidence, 3),
            "silent_drop_hop": self.silent_drop_hop,
            "last_responding_router": self.last_responding_router,
            "notes": self.notes,
            "hops": [
                {
                    "ttl": h.ttl, "router": h.router_ip,
                    "icmp_type": h.icmp_type, "got_response": h.got_response,
                    "latency_ms": round(h.latency_ms, 2),
                }
                for h in self.hops
            ],
        }


class BGPBlackholeDetector:
    """
    Detects BGP Remote Triggered Black Hole (RTBH) routing against a target
    or source IP using TTL-varying ICMP probes and differential analysis.
    """

    # TTL range to trace through — typically 30 hops is more than enough
    MAX_HOPS = 30

    # How many consecutive non-responses before we declare a blackhole
    SILENCE_THRESHOLD = 3

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: float = 2.0,
        src_ip: Optional[str] = None,
    ):
        self.interface = interface
        self.timeout   = timeout
        self.src_ip    = src_ip

        if not HAS_SCAPY:
            logger.warning("[BGPBlackhole] Scapy not available")

    # ─── Public API ─────────────────────────────────────────────────────────

    def detect(self, target: str) -> BGPBlackholeResult:
        """
        Full blackhole detection pipeline for a target IP.

        Sends TTL-varying ICMP probes from TTL=1 up to MAX_HOPS and
        characterises the pattern of responses / non-responses.
        """
        result = BGPBlackholeResult(target=target)

        if not HAS_SCAPY:
            result.notes.append("Scapy not available — blackhole detection skipped")
            return result

        conf.verb = 0

        # Phase 1: TTL-varying trace
        hops = self._ttl_trace(target)
        result.hops = hops

        # Phase 2: Classify the response pattern
        self._classify(result)

        # Phase 3: UDP-ICMP port unreachable cross-check
        self._udp_cross_check(target, result)

        logger.info(
            f"[BGPBlackhole] {target}: {result.blackhole_type} "
            f"(confidence={result.confidence:.0%})"
        )
        return result

    def check_source_rtbh(self, target: str,
                           spoofed_src: str = "198.51.100.1") -> Dict[str, Any]:
        """
        Check if RTBH is source-specific by sending probes from both the
        real source and a spoofed RFC-5737 address.

        If spoofed source gets a response but real source doesn't, the
        upstream provider is applying source-based RTBH against our real IP.

        Args:
            target:      Target IP to probe
            spoofed_src: RFC-5737 documentation address to use as spoofed src

        Returns:
            Dict with 'real_responds', 'spoofed_responds', 'source_rtbh'
        """
        if not HAS_SCAPY:
            return {"error": "scapy_unavailable"}

        conf.verb = 0

        # Real source probe
        real_pkt = IP(dst=target, ttl=64) / ICMP(type=8, seq=1)
        real_resp = sr1(real_pkt, timeout=self.timeout, verbose=0,
                        iface=self.interface)
        real_responds = real_resp is not None

        # Spoofed source probe
        spoof_pkt = IP(src=spoofed_src, dst=target, ttl=64) / ICMP(type=8, seq=2)
        spoof_resp = sr1(spoof_pkt, timeout=self.timeout, verbose=0,
                         iface=self.interface)
        spoof_responds = spoof_resp is not None

        source_rtbh = (not real_responds) and spoof_responds

        return {
            "target": target,
            "real_src_responds": real_responds,
            "spoofed_src_responds": spoof_responds,
            "source_rtbh_suspected": source_rtbh,
            "note": (
                "Source-based RTBH detected — your IP is null-routed at provider level"
                if source_rtbh else
                "No source-based RTBH detected"
            ),
        }

    # ─── Internal ────────────────────────────────────────────────────────────

    def _ttl_trace(self, target: str) -> List[BlackholeHopResult]:
        """Send ICMP with TTL=1 through MAX_HOPS, record responses."""
        hops: List[BlackholeHopResult] = []
        consecutive_silence = 0

        for ttl in range(1, self.MAX_HOPS + 1):
            pkt = IP(dst=target, ttl=ttl) / ICMP(
                type=8, code=0,
                id=random.randint(1, 65535),
                seq=ttl,
            ) / Raw(load=b"usare-bhprobe" + ttl.to_bytes(2, "big"))

            if self.src_ip:
                pkt[IP].src = self.src_ip

            t0 = time.time()
            resp = sr1(pkt, timeout=self.timeout, verbose=0,
                       iface=self.interface)
            latency = (time.time() - t0) * 1000

            hop = BlackholeHopResult(ttl=ttl, router_ip=None,
                                     icmp_type=None, icmp_code=None,
                                     got_response=resp is not None,
                                     latency_ms=latency)

            if resp is not None and resp.haslayer(ICMP):
                hop.icmp_type  = resp[ICMP].type
                hop.icmp_code  = resp[ICMP].code
                hop.router_ip  = resp[IP].src
                consecutive_silence = 0
            else:
                consecutive_silence += 1

            hops.append(hop)

            # Target reached (ICMP echo reply)
            if resp is not None and resp.haslayer(ICMP) and resp[ICMP].type == 0:
                break

            # Enough silence to conclude blackhole
            if consecutive_silence >= self.SILENCE_THRESHOLD:
                break

            time.sleep(0.05)

        return hops

    def _classify(self, result: BGPBlackholeResult):
        """Classify the hop pattern into a blackhole type."""
        hops = result.hops
        if not hops:
            result.blackhole_type = "unknown"
            return

        responding = [h for h in hops if h.got_response]
        non_responding = [h for h in hops if not h.got_response]

        # Reached target cleanly
        if responding and responding[-1].icmp_type == 0:
            result.blackhole_type = "reachable"
            result.confidence     = 0.95
            return

        # Nothing responded at all — could be host down or total blackhole
        if not responding:
            result.blackhole_type = "host_down_or_rtbh"
            result.blackholed     = True
            result.confidence     = 0.50
            result.notes.append("No ICMP TTL-exceeded responses — network may be blocking ICMP or host is fully blackholed")
            return

        # Some hops respond then silence — classic RTBH pattern
        if responding and non_responding:
            last_resp = responding[-1]
            first_silent = non_responding[0]
            result.last_responding_router = last_resp.router_ip
            result.silent_drop_hop        = first_silent.ttl

            # Provider RTBH typically happens at hop 2-5 (provider edge)
            if first_silent.ttl <= 6:
                result.blackhole_type = "destination_rtbh"
                result.blackholed     = True
                result.confidence     = 0.75
                result.notes.append(
                    f"Silence begins at TTL={first_silent.ttl} — consistent with "
                    f"provider-edge RTBH null-route"
                )
            elif first_silent.ttl <= 15:
                result.blackhole_type = "firewall_drop_or_rtbh"
                result.blackholed     = True
                result.confidence     = 0.60
                result.notes.append(
                    f"Silence begins at TTL={first_silent.ttl} — could be "
                    f"enterprise perimeter firewall or upstream RTBH"
                )
            else:
                result.blackhole_type = "firewall_drop"
                result.blackholed     = False
                result.confidence     = 0.55
                result.notes.append(
                    f"Silence begins at TTL={first_silent.ttl} — likely "
                    f"host-local firewall rather than RTBH"
                )

    def _udp_cross_check(self, target: str, result: BGPBlackholeResult):
        """
        Cross-check with UDP probe: RTBH drops silently,
        host-down gives ICMP unreachable from nearby hop.
        """
        if not HAS_SCAPY:
            return

        try:
            udp_pkt = IP(dst=target, ttl=64) / UDP(
                sport=random.randint(49152, 65535),
                dport=33435,   # traceroute range
            ) / Raw(load=b"\x00" * 8)

            if self.src_ip:
                udp_pkt[IP].src = self.src_ip

            resp = sr1(udp_pkt, timeout=self.timeout, verbose=0,
                       iface=self.interface)

            if resp is None:
                result.notes.append("UDP probe also silently dropped — consistent with RTBH or strict firewall")
            elif resp.haslayer(ICMP):
                t = resp[ICMP].type
                c = resp[ICMP].code
                if t == 3 and c == 3:
                    result.notes.append("UDP probe got port-unreachable — host is alive, firewall not RTBH")
                    if result.blackholed:
                        result.confidence = max(0.3, result.confidence - 0.2)
                elif t == 3 and c in (9, 10, 13):
                    result.notes.append("UDP probe got admin-prohibited — stateful ACL, not RTBH")
                    result.blackhole_type = "firewall_drop"
                    result.blackholed = False
        except Exception as e:
            logger.debug(f"[BGPBlackhole] UDP cross-check failed: {e}")
