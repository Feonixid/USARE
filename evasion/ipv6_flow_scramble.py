"""
USARE IPv6 Flow Label Randomization

Exploits IPv6 "Fast Path" hardware routing and firewall state mechanisms.
The IPv6 header contains a 20-bit Flow Label field. Many high-speed
routers and stateful IDSs cache flow state by hashing the Source IP, 
Dest IP, and the Flow Label to avoid digging into upper-layer (TCP/UDP) 
headers. 

This engine crafts packets where the Flow Label is completely randomized
for every single packet sent to the exact same target and port. This
constantly busts the hardware cache, forcing the IDS into expensive
slow-path processing or causing it to fail-open entirely.
"""

import random
import logging
import time
from typing import Optional, Dict, Any

try:
    from scapy.all import IPv6, TCP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.ipv6_flow")


class IPv6FlowScrambler:
    """Manages randomized IPv6 Flow Label crafting."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._rng = random.SystemRandom()
        if not HAS_SCAPY:
            logger.warning("[IPv6 Flow] Scapy not installed. IPv6 Flow Scrambling disabled.")

    def scramble_probe(self, target_ipv6: str, port: int, timeout: float = 3.0) -> Dict:
        """
        Sends a single TCP SYN over IPv6 with a highly randomized Flow Label.
        """
        result = {
            "target": target_ipv6,
            "port": port,
            "flow_label_used": 0,
            "port_state": "filtered",
            "latency": 0.0
        }

        if not HAS_SCAPY:
            return result

        t0 = time.time()
        try:
            # 20-bit value (0 to 1,048,575)
            # RFC 6437 specifies that a flow label of 0 means "no label".
            # We want to use non-zero randomly to bust hardware caches.
            scrambled_flow = self._rng.randint(1, 0xFFFFF)
            result["flow_label_used"] = scrambled_flow
            
            ipv6_layer = IPv6(dst=target_ipv6, fl=scrambled_flow)
            
            # Use random high source port
            sport = self._rng.randint(49152, 65535)
            tcp_layer = TCP(sport=sport, dport=port, flags="S", seq=self._rng.randint(1000, 4000000000))
            
            packet = ipv6_layer / tcp_layer
            
            kwargs: Dict[str, Any] = {"timeout": timeout, "verbose": 0}
            if self.interface:
                kwargs["iface"] = self.interface
                
            resp = sr1(packet, **kwargs)
            
            if resp and resp.haslayer(TCP):
                flags = resp[TCP].flags
                result["latency"] = (time.time() - t0) * 1000
                
                if flags & 0x12 == 0x12:      # SYN-ACK
                    result["port_state"] = "open"
                elif flags & 0x04 == 0x04:    # RST
                    result["port_state"] = "closed"
                    
        except Exception as e:
            logger.debug(f"[IPv6 Flow] Scrambled probe failed to {target_ipv6}:{port} - {e}")
            
        return result

    def burst_scramble(self, target_ipv6: str, port: int, count: int = 5) -> int:
        """
        Send a rapid burst of packets with rotating flow labels to exhaust cache.
        Returns the number of identical packets successfully delivered over
        different synthetic flows.
        """
        successes = 0
        for _ in range(count):
            res = self.scramble_probe(target_ipv6, port, timeout=1.0)
            if res["port_state"] in ("open", "closed"):
                successes = int(successes + 1)
        return successes
