"""
USARE GRE / IP-in-IP Tunnel Evasion Engine

GRE (Generic Routing Encapsulation, RFC 2784) wraps arbitrary IP packets
inside a new outer IP packet. From the perspective of a Layer-4 stateful
firewall or IDS, the inner packet is opaque binary data inside a GRE
protocol-47 datagram — most L4 devices cannot inspect it.

Why this bypasses firewalls:
  - Stateful firewalls track TCP/UDP 5-tuples. GRE packets have no port
    numbers — they appear as raw IP protocol 47 datagrams.
  - Many enterprise firewalls and AWS Security Groups either pass GRE
    outright or fail to parse the inner packet at all.
  - IDS rules written for TCP/UDP signatures never fire on GRE payloads
    because the pattern-matching engine never reaches the encapsulated data.
  - Even when a firewall CAN parse GRE, reassembly of fragmented GRE is
    often incomplete, allowing probe data through in fragments.

Architecture:
  Scanner → GRE encapsulated SYN → Relay node (cooperative host)
  Relay node → decapsulates → forwards raw SYN to target
  Target → SYN-ACK → Relay node
  Relay node → GRE encapsulated SYN-ACK → Scanner

The relay decapsulates and forwards, so the scanner's IP never appears
in the target's connection logs — only the relay's IP is seen.

For solo use (no relay), GRE encapsulation is sent directly. Many
network devices and clouds pass GRE to the inner destination if they
cannot parse it, making direct GRE probes effective even without a relay.

Requirements:
  - Root / administrator privileges (raw socket)
  - Scapy installed
  - Optional: a cooperative relay host running a simple GRE decap daemon
"""

import os
import time
import random
import socket
import struct
import logging
import threading
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.gre_tunnel")

try:
    from scapy.all import (
        IP, TCP, ICMP, GRE, Ether,
        sr1, send, conf, Raw,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─── GRE Header Constants ─────────────────────────────────────────────────────

GRE_PROTO_IP   = 0x0800   # Ethertype for IPv4 inside GRE
GRE_PROTO_IPV6 = 0x86DD   # IPv6 inside GRE
IP_PROTO_GRE   = 47       # Protocol number for GRE in IP header


@dataclass
class GREProbeResult:
    """Result of a single GRE-encapsulated probe."""
    target: str
    port: int
    relay: Optional[str]
    is_open: Optional[bool]        # None = inconclusive (relay not responding)
    latency_ms: float = 0.0
    gre_key: Optional[int] = None  # GRE key field used (for keyed sessions)
    inner_response: bool = False    # Did we receive an inner IP response?
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "port": self.port,
            "relay": self.relay, "is_open": self.is_open,
            "latency_ms": round(self.latency_ms, 2),
            "gre_key": self.gre_key, "error": self.error,
        }


class GRETunnelEngine:
    """
    Encapsulates port probes in GRE packets.

    Two operational modes:
      1. DIRECT  — GRE packet sent directly to target's IP. Works when
                   the target or a hop en-route passes GRE protocol-47.
      2. RELAY   — GRE packet sent to relay node which decapsulates and
                   forwards the inner TCP SYN, then relays the response.
    """

    def __init__(
        self,
        relay_ip: Optional[str] = None,
        use_gre_key: bool = True,
        timeout: float = 5.0,
        interface: Optional[str] = None,
        ttl: int = 64,
    ):
        """
        Args:
            relay_ip: IP of the cooperative relay host. None = direct mode.
            use_gre_key: Include a random GRE key field (per-session isolation).
            timeout: Seconds to wait for response.
            interface: Network interface to use.
            ttl: Outer IP TTL.
        """
        if not HAS_SCAPY:
            raise RuntimeError("Scapy is required for GRE tunnel evasion")

        self.relay_ip = relay_ip
        self.use_gre_key = use_gre_key
        self.timeout = timeout
        self.interface = interface
        self.ttl = ttl
        self._rng = random.SystemRandom()
        self._lock = threading.Lock()
        self._probes_sent = 0
        self._probes_replied = 0

        conf.verb = 0
        if interface:
            conf.iface = interface

    # ─── Public API ──────────────────────────────────────────────────────────

    def probe_port(self, target_ip: str, target_port: int,
                   src_port: Optional[int] = None) -> GREProbeResult:
        """
        Probe a single port via GRE encapsulation.

        In DIRECT mode, sends a GRE-wrapped SYN directly and watches for
        GRE-wrapped SYN-ACK. Useful when the path passes GRE.

        In RELAY mode, sends to the relay and waits for a GRE-wrapped
        response containing the target's reply.
        """
        sp = src_port or self._rng.randint(49152, 65535)
        gre_key = self._rng.randint(1, 0xFFFFFFFF) if self.use_gre_key else None
        outer_dst = self.relay_ip if self.relay_ip else target_ip

        # Build inner TCP SYN packet (exactly what a normal scanner would send)
        inner_pkt = (
            IP(dst=target_ip, ttl=self.ttl) /
            TCP(
                sport=sp,
                dport=target_port,
                flags="S",
                seq=self._rng.randint(0, 0xFFFFFFFF),
                window=65535,
            )
        )

        # Build GRE header
        gre_layer = GRE(proto=GRE_PROTO_IP)
        if gre_key is not None:
            gre_layer.key_present = 1
            gre_layer.key = gre_key

        # Outer IP envelope
        outer_pkt = (
            IP(dst=outer_dst, proto=IP_PROTO_GRE, ttl=self.ttl) /
            gre_layer /
            inner_pkt
        )

        t0 = time.time()
        try:
            resp = sr1(outer_pkt, timeout=self.timeout, verbose=0)
        except Exception as e:
            return GREProbeResult(
                target=target_ip, port=target_port,
                relay=self.relay_ip, is_open=None,
                latency_ms=(time.time() - t0) * 1000,
                gre_key=gre_key, error=str(e),
            )

        latency = (time.time() - t0) * 1000
        with self._lock:
            self._probes_sent += 1

        if resp is None:
            return GREProbeResult(
                target=target_ip, port=target_port,
                relay=self.relay_ip, is_open=None,
                latency_ms=latency, gre_key=gre_key,
                error="timeout_no_gre_response",
            )

        # Parse response: could be GRE-wrapped inner reply or ICMP error
        is_open, inner_resp = self._parse_gre_response(resp, target_ip, target_port, sp)

        with self._lock:
            if is_open is not None:
                self._probes_replied += 1

        return GREProbeResult(
            target=target_ip, port=target_port,
            relay=self.relay_ip, is_open=is_open,
            latency_ms=latency, gre_key=gre_key,
            inner_response=inner_resp,
        )

    def probe_ports(self, target_ip: str, ports: List[int],
                    src_port_base: Optional[int] = None) -> List[GREProbeResult]:
        """Probe multiple ports via GRE."""
        results = []
        for i, port in enumerate(ports):
            sp = (src_port_base or 49152) + i if src_port_base else None
            result = self.probe_port(target_ip, port, src_port=sp)
            results.append(result)
            time.sleep(0.05)  # Brief pacing between probes
        return results

    def craft_gre_fragment_burst(self, target_ip: str, target_port: int,
                                  outer_dst: Optional[str] = None) -> List:
        """
        Craft a GRE packet and then fragment the outer IP packet.

        Fragmenting the outer GRE packet is particularly effective because:
        - Many IDS reassemble only inner TCP, not outer GRE fragments
        - Stateful firewalls may accept fragment 1 and drop fragment 2
          (or vice versa) depending on reassembly implementation
        - Some hardware forwarding engines pass GRE fragments as-is

        Returns a list of fragment packets ready to send.
        """
        dst = outer_dst or self.relay_ip or target_ip
        sp = self._rng.randint(49152, 65535)

        inner = (
            IP(dst=target_ip, ttl=self.ttl) /
            TCP(sport=sp, dport=target_port, flags="S",
                seq=self._rng.randint(0, 0xFFFFFFFF), window=65535)
        )

        gre = GRE(proto=GRE_PROTO_IP)
        outer = IP(dst=dst, proto=IP_PROTO_GRE, ttl=self.ttl, flags=0) / gre / inner

        from scapy.all import fragment
        return fragment(outer, fragsize=280)  # Force fragmentation at GRE boundary

    # ─── Response Parsing ─────────────────────────────────────────────────────

    def _parse_gre_response(self, resp, target_ip: str,
                             target_port: int, src_port: int) -> Tuple[Optional[bool], bool]:
        """
        Parse a received packet to determine port open/closed status.

        Returns:
            (is_open, inner_response_found)
            is_open = True/False/None (None = inconclusive)
        """
        if not resp:
            return None, False

        # Case 1: Direct ICMP from the outer hop (GRE blocked)
        if resp.haslayer(ICMP) and not resp.haslayer(GRE):
            icmp = resp[ICMP]
            if icmp.type == 3:  # Destination unreachable
                logger.debug(f"[GRE] ICMP unreachable code {icmp.code} — GRE may be filtered")
                return None, False
            return None, False

        # Case 2: GRE-encapsulated response (relay or direct pass-through)
        if resp.haslayer(GRE):
            inner = resp[GRE].payload
            if hasattr(inner, 'haslayer'):
                if inner.haslayer(TCP):
                    tcp = inner[TCP]
                    if tcp.flags & 0x12 == 0x12:  # SYN-ACK
                        return True, True
                    elif tcp.flags & 0x04:  # RST
                        return False, True
                elif inner.haslayer(ICMP) and inner[ICMP].type == 3:
                    return False, True
            return None, True

        # Case 3: Raw TCP response (direct mode, some devices strip GRE)
        if resp.haslayer(TCP):
            tcp = resp[TCP]
            if tcp.flags & 0x12 == 0x12:
                return True, False
            elif tcp.flags & 0x04:
                return False, False

        return None, False

    # ─── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "probes_sent": self._probes_sent,
                "probes_replied": self._probes_replied,
                "reply_rate": (
                    round(self._probes_replied / max(self._probes_sent, 1), 3)
                ),
                "relay": self.relay_ip or "direct",
                "gre_key_enabled": self.use_gre_key,
                "timeout": self.timeout,
            }
