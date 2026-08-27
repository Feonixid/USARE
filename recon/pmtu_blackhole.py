"""
USARE Path MTU (PMTU) Blackhole Discovery Engine

This module probes for hidden network security appliances (firewalls,
VPN gateways, IPS filters) that invisibly sanitize traffic. By intentionally
sending oversized ICMP/UDP fragments with the `DF` (Don't Fragment) bit
hardcoded to 1, this tool maps out the Maximum Transmission Unit (MTU)
bottlenecks of the network path without ever establishing a full connection 
to the endpoint.

If a router or firewall drops the packet due to MTU constraints, it is 
required to send an ICMP Type 3 Code 4 (Fragmentation Needed) error containing
the next-hop MTU. This allows USARE to silently infer the presence of 
IPsec tunnels (typically MTU 1400-1436), PPPoE (1492), or restrictive 
WAF appliances.
"""

import logging
import random
import time
from typing import Optional, Dict, List

try:
    from scapy.all import IP, UDP, ICMP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.pmtu_blackhole")

class PMTUBlackholer:
    """Discovers intermediary MTU bottlenecks via oversized DF probes."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._rng = random.SystemRandom()
        if not HAS_SCAPY:
            logger.warning("[PMTU] Scapy not installed. PMTU Discovery disabled.")

    def probe_path_mtu(self, target: str, port: int = 33434, max_mtu: int = 1500, min_mtu: int = 1300, timeout: float = 2.0) -> Dict:
        """
        Sends sequentially smaller packets with DF=1 to find the Path MTU and locate bottlenecks.
        Uses UDP by default (traceroute style port) to avoid TCP state tracking.
        """
        result = {
            "target": target,
            "port": port,
            "pmtu_found": False,
            "bottleneck_mtu": 0,
            "reporting_router": None,
            "latency_ms": 0.0,
            "probes_sent": 0
        }

        if not HAS_SCAPY:
            return result

        current_size = max_mtu
        t0 = time.time()

        # We step down in 50-byte increments until we get past or hit min_mtu
        while current_size >= min_mtu:
            # Construct a raw UDP packet exactly matching `current_size` Total Length
            # IP Header = 20 bytes
            # UDP Header = 8 bytes
            # Payload = current_size - 28
            payload_size = current_size - 28
            if payload_size < 0:
                break
                
            payload = b"X" * payload_size
            
            # Flags=2 sets the DF (Don't Fragment) bit
            ip_layer = IP(dst=target, flags=2)
            udp_layer = UDP(sport=self._rng.randint(49152, 65535), dport=port)
            
            packet = ip_layer / udp_layer / payload
            
            kwargs = {"timeout": timeout, "verbose": 0}
            if self.interface:
                kwargs["iface"] = self.interface

            result["probes_sent"] += 1
            
            # Send the probe and wait for ICMP error
            response = sr1(packet, **kwargs)

            if response:
                if response.haslayer(ICMP):
                    icmp_type = response[ICMP].type
                    icmp_code = response[ICMP].code
                    
                    if icmp_type == 3 and icmp_code == 4:
                        # Fragmentation Needed and DF Set
                        next_mtu = getattr(response[ICMP], "nexthopmtu", 0)
                        
                        logger.debug(f"[PMTU] Router {response.src} reported Fragmentation Needed. Next MTU: {next_mtu}")
                        
                        # We found an MTU bottleneck
                        result["pmtu_found"] = True
                        result["bottleneck_mtu"] = next_mtu if next_mtu > 0 else current_size - 1
                        result["reporting_router"] = response.src
                        result["latency_ms"] = (time.time() - t0) * 1000
                        
                        return result
                        
                    elif icmp_type == 3:
                        # Destination Unreachable for another reason (Admin Prohibited, Port Unreachable)
                        # The packet made it through without fragmenting
                        return result

            # If no response or we didn't receive an ICMP Frag Needed, try slightly smaller
            # (or we timed out, meaning it was blackholed). Step down quickly.
            current_size -= 40
            
        return result

    def scan_path(self, target: str) -> Dict:
        """
        Executes a PMTU discovery scan.
        """
        return self.probe_path_mtu(target)
