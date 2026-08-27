"""
USARE TCP Zero-Window Probing

Sends TCP SYN packets with the window size strictly set to 0.
This informs the target (and in-path firewalls) that the client
cannot receive any data.

Because no data can theoretically flow, many IDS/IPS systems
drop the connection from state tracking, classifying it as inert.
However, the target OS will still reply with a SYN-ACK,
revealing the port state silently.
"""

import time
import socket
import logging
from typing import Optional, Dict, Any

try:
    from scapy.all import IP, TCP, sr1, conf, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.zero_window")


class ZeroWindowProber:
    """Manages Zero-Window SYN probing."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        if not HAS_SCAPY:
            logger.warning("[ZeroWindow] Scapy not installed. Zero-Window probing disabled.")

    def probe(self, target: str, port: int, timeout: float = 3.0) -> Dict:
        """
        Send a SYN packet with Window Size = 0.
        """
        result: Dict[str, Any] = {
            "port": port,
            "zero_window_accepted": False,
            "port_state": "filtered",
            "latency": 0.0,
            "response_flags": "",
        }

        if not HAS_SCAPY:
            return result
            
        t0 = time.time()
        try:
            ip_layer = IP(dst=target)
            # Standard SYN but Window = 0
            tcp_layer = TCP(dport=port, flags="S", window=0)
            
            packet = ip_layer / tcp_layer
            
            kwargs = {"timeout": timeout, "verbose": 0}
            if self.interface:
                kwargs["iface"] = self.interface
                
            resp = sr1(packet, **kwargs)
            
            if resp and resp.haslayer(TCP):
                flags = resp[TCP].flags
                result["response_flags"] = str(flags)
                result["latency"] = (time.time() - t0) * 1000
                
                # SYN-ACK confirms port is open despite Window 0
                if flags & 0x12 == 0x12: 
                    result["port_state"] = "open"
                    result["zero_window_accepted"] = True
                    # Target honored the SYN. Note: A real implementation might need to
                    # respond with an RST here to prevent OS retransmissions, depending on setup.
                elif flags & 0x04 == 0x04:  # RST
                    result["port_state"] = "closed"
                    result["zero_window_accepted"] = True
                        
        except Exception as e:
            logger.debug(f"[ZeroWindow] Probe failed to {target}:{port} - {e}")
            
        return result
