"""
USARE IPv6 Extension Header Stuffing

Stacks multiple IPv6 extension headers to create chains that
many IDS/IPS systems can't fully reassemble:

  IPv6 → Hop-by-Hop → Destination → Routing → Fragment → TCP

This exploits the fact that IDS must follow the entire chain
to find the upper-layer protocol. Many systems give up after
2-3 extension headers, especially with padding options.

Combined with the existing fragmentation engine, this creates
packets that are extremely difficult to inspect.
"""

import struct
import socket
import time
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger("usare.ipv6_ext_stuffer")

try:
    from scapy.all import (  # type: ignore
        IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt,
        IPv6ExtHdrRouting, IPv6ExtHdrFragment,
        TCP, Pad1, PadN, send, sr1, Raw
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class ExtHeaderResult:
    """Result of an IPv6 extension header probe."""
    port: int
    state: str
    headers_used: List[str]
    total_chain_length: int
    latency_ms: float = 0.0
    ids_evasion_score: float = 0.0  # 0.0-1.0 estimated IDS confusion

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "state": self.state,
            "headers_used": self.headers_used,
            "chain_length": self.total_chain_length,
            "latency_ms": round(self.latency_ms, 2),
            "ids_evasion_score": round(self.ids_evasion_score, 3),
        }


class IPv6ExtStuffer:
    """
    IPv6 extension header chain constructor for IDS evasion.
    """

    # Extension header types
    HOPBYHOP = 0       # Must be first if present
    ROUTING = 43
    FRAGMENT = 44
    DESTOPT = 60
    # Fictional/experimental next headers for padding
    NO_NEXT_HEADER = 59

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self._probes_sent = 0

    def probe_with_chain(self, target: str, port: int,
                         chain_depth: int = 4,
                         padding_size: int = 8) -> ExtHeaderResult:
        """
        Probe a port with a stacked extension header chain.

        Args:
            target: IPv6 target address
            port: Target port
            chain_depth: Number of extension headers to stack (2-6)
            padding_size: Bytes of padding in each option header
        """
        if not HAS_SCAPY:
            return ExtHeaderResult(
                port=port, state="error",
                headers_used=[], total_chain_length=0,
            )

        chain_depth = max(2, min(chain_depth, 6))
        headers_used = []
        t0 = time.time()

        try:
            # Build the IPv6 base
            pkt = IPv6(dst=target)

            # Layer 1: Hop-by-Hop Options (MUST be first per RFC 8200)
            hbh_padding = PadN(optlen=padding_size, optdata=os.urandom(padding_size))
            pkt = pkt / IPv6ExtHdrHopByHop(options=[hbh_padding])
            headers_used.append("hop-by-hop")

            # Layer 2: Destination Options (first instance)
            if chain_depth >= 2:
                dest_padding = PadN(optlen=padding_size, optdata=os.urandom(padding_size))
                pkt = pkt / IPv6ExtHdrDestOpt(options=[dest_padding])
                headers_used.append("destination-opts-1")

            # Layer 3: Extra Destination Options with large random padding
            # (Type 2 Routing Header is Mobile IPv6-only and gets dropped)
            if chain_depth >= 3:
                dest_padding_lg = PadN(optlen=padding_size * 3, optdata=os.urandom(padding_size * 3))
                pkt = pkt / IPv6ExtHdrDestOpt(options=[dest_padding_lg])
                headers_used.append("destination-opts-extra")

            # Layer 4: Second Destination Options (allowed before upper layer)
            if chain_depth >= 4:
                dest_padding2 = PadN(optlen=padding_size * 2, optdata=os.urandom(padding_size * 2))
                pkt = pkt / IPv6ExtHdrDestOpt(options=[dest_padding2])
                headers_used.append("destination-opts-2")

            # Layer 5: Fragment Header (even for non-fragmented packet)
            if chain_depth >= 5:
                pkt = pkt / IPv6ExtHdrFragment(offset=0, m=0, id=os.urandom(4)[0] << 24)
                headers_used.append("fragment")

            # Layer 6: Additional Destination Options with large padding
            if chain_depth >= 6:
                big_pad = PadN(optlen=padding_size * 4, optdata=os.urandom(padding_size * 4))
                pkt = pkt / IPv6ExtHdrDestOpt(options=[big_pad])
                headers_used.append("destination-opts-3")

            # Final: TCP SYN
            pkt = pkt / TCP(dport=port, flags="S", seq=int.from_bytes(os.urandom(4), "big"))
            headers_used.append("tcp-syn")

            total_len = len(bytes(pkt))
            self._probes_sent += 1

            # Send and wait for response
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000

            if resp is None:
                ids_score = min(0.3 * chain_depth, 1.0)
                return ExtHeaderResult(
                    port=port, state="filtered",
                    headers_used=headers_used,
                    total_chain_length=total_len,
                    latency_ms=latency,
                    ids_evasion_score=ids_score,
                )

            if resp.haslayer(TCP):
                tcp_flags = resp[TCP].flags
                if tcp_flags & 0x12 == 0x12:
                    # SYN-ACK — port open, IDS likely didn't see through chain
                    rst = IPv6(dst=target) / TCP(dport=port, flags="R",
                                                  sport=pkt[TCP].sport,
                                                  seq=resp[TCP].ack)
                    send(rst, verbose=0)

                    ids_score = min(0.25 * chain_depth, 1.0)
                    return ExtHeaderResult(
                        port=port, state="open",
                        headers_used=headers_used,
                        total_chain_length=total_len,
                        latency_ms=latency,
                        ids_evasion_score=ids_score,
                    )
                elif tcp_flags & 0x04:
                    return ExtHeaderResult(
                        port=port, state="closed",
                        headers_used=headers_used,
                        total_chain_length=total_len,
                        latency_ms=latency,
                        ids_evasion_score=0.0,
                    )

            return ExtHeaderResult(
                port=port, state="filtered",
                headers_used=headers_used,
                total_chain_length=total_len,
                latency_ms=latency,
                ids_evasion_score=min(0.3 * chain_depth, 1.0),
            )

        except Exception as e:
            logger.debug(f"[IPv6ExtStuffer] Error on port {port}: {e}")
            return ExtHeaderResult(
                port=port, state="error",
                headers_used=headers_used,
                total_chain_length=0,
            )

    @property
    def stats(self) -> Dict:
        return {"probes_sent": self._probes_sent}
