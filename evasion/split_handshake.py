"""
USARE TCP Split Handshake

Instead of the normal SYN → SYN-ACK → ACK, this sends:
  SYN → receive SYN-ACK → reply with SYN-ACK (instead of ACK)

Some stateful firewalls (Cisco ASA, Palo Alto PAN-OS) mishandle this
simultaneous-open scenario and mark the connection as established,
allowing port state inference without completing a real handshake.

This is different from TCP desync — desync manipulates the data stream
after handshake; split handshake exploits the handshake itself.
"""

import socket
import struct
import time
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger("usare.split_handshake")

try:
    from scapy.all import IP, TCP, sr1, send, RandShort, conf  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class SplitHandshakeResult:
    """Result of a split handshake probe."""
    port: int
    state: str            # "open", "closed", "filtered", "fw_confused"
    latency_ms: float = 0.0
    firewall_behavior: str = ""  # "stateful_bypassed", "rejected", "timeout"
    syn_ack_received: bool = False
    split_accepted: bool = False

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "state": self.state,
            "latency_ms": round(self.latency_ms, 2),
            "firewall_behavior": self.firewall_behavior,
            "syn_ack_received": self.syn_ack_received,
            "split_accepted": self.split_accepted,
        }


class SplitHandshakeScanner:
    """
    TCP split handshake scanner for firewall evasion.

    Technique:
    1. Send SYN to target
    2. Receive SYN-ACK from target (port is open)
    3. Instead of sending ACK, send our own SYN-ACK back
       (simulating simultaneous open per RFC 793)
    4. Some firewalls interpret this as an established connection

    This confuses stateful inspection because:
    - The firewall sees a SYN-ACK from us that it didn't initiate
    - RFC 793 mandates handling simultaneous open, but many
      firewalls don't implement this edge case
    - The firewall may skip deep packet inspection for what it
      considers an already-established connection
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self._results = []

    def probe(self, target: str, port: int, src_port: Optional[int] = None) -> SplitHandshakeResult:
        """Execute split handshake probe on a single port."""
        if not HAS_SCAPY:
            return SplitHandshakeResult(
                port=port, state="error",
                firewall_behavior="scapy_unavailable"
            )

        src_port = src_port or int(RandShort())
        seq_num = int(RandShort()) << 16 | int(RandShort())
        t0 = time.time()

        try:
            # Step 1: Send SYN
            syn = IP(dst=target) / TCP(
                sport=src_port, dport=port,
                flags="S", seq=seq_num,
                options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]
            )
            resp = sr1(syn, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000

            if resp is None:
                return SplitHandshakeResult(
                    port=port, state="filtered",
                    latency_ms=latency,
                    firewall_behavior="timeout",
                )

            if not resp.haslayer(TCP):
                return SplitHandshakeResult(
                    port=port, state="filtered",
                    latency_ms=latency,
                    firewall_behavior="non_tcp_response",
                )

            tcp_resp = resp[TCP]

            # RST received — port is closed
            if tcp_resp.flags & 0x04:
                return SplitHandshakeResult(
                    port=port, state="closed",
                    latency_ms=latency,
                    firewall_behavior="rst_received",
                )

            # SYN-ACK received — port is open, now do the split
            if tcp_resp.flags & 0x12 == 0x12:
                their_seq = tcp_resp.seq
                their_ack = tcp_resp.ack

                # Step 3: Instead of ACK, send our own SYN-ACK
                # This simulates a simultaneous open (RFC 793 Section 3.4)
                our_syn_ack = IP(dst=target) / TCP(
                    sport=src_port, dport=port,
                    flags="SA",  # SYN-ACK
                    seq=seq_num,
                    ack=their_seq + 1,
                    options=[("MSS", 1460)]
                )

                split_resp = sr1(our_syn_ack, timeout=self.timeout, verbose=0)
                split_latency = (time.time() - t0) * 1000

                if split_resp and split_resp.haslayer(TCP):
                    split_flags = split_resp[TCP].flags

                    if split_flags & 0x10:  # ACK
                        # Firewall accepted the split handshake!
                        # Send RST to clean up
                        rst = IP(dst=target) / TCP(
                            sport=src_port, dport=port,
                            flags="R", seq=their_ack
                        )
                        send(rst, verbose=0)

                        result = SplitHandshakeResult(
                            port=port, state="open",
                            latency_ms=split_latency,
                            firewall_behavior="stateful_bypassed",
                            syn_ack_received=True,
                            split_accepted=True,
                        )
                        self._results.append(result)
                        return result

                    elif split_flags & 0x04:  # RST to our SYN-ACK
                        # Firewall or host rejected the split
                        result = SplitHandshakeResult(
                            port=port, state="open",
                            latency_ms=split_latency,
                            firewall_behavior="split_rejected",
                            syn_ack_received=True,
                            split_accepted=False,
                        )
                        self._results.append(result)
                        return result

                # No response to split — firewall may have dropped it
                # But we know port is open from the original SYN-ACK
                # Send RST to clean up original half-open
                rst = IP(dst=target) / TCP(
                    sport=src_port, dport=port,
                    flags="R", seq=their_ack
                )
                send(rst, verbose=0)

                result = SplitHandshakeResult(
                    port=port, state="open",
                    latency_ms=latency,
                    firewall_behavior="split_timeout",
                    syn_ack_received=True,
                    split_accepted=False,
                )
                self._results.append(result)
                return result

        except Exception as e:
            logger.debug(f"[SplitHandshake] Error on port {port}: {e}")
            return SplitHandshakeResult(
                port=port, state="error",
                firewall_behavior=f"exception: {e}",
            )

        return SplitHandshakeResult(port=port, state="filtered", latency_ms=0)

    def get_summary(self) -> Dict[str, Any]:
        """Summarize split handshake scan results."""
        bypassed = sum(1 for r in self._results if r.split_accepted)
        return {
            "total_probes": len(self._results),
            "stateful_bypass_count": bypassed,
            "results": [r.to_dict() for r in self._results],
        }
