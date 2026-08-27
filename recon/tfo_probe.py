"""
USARE TCP Fast Open (TFO) Probing

Exploits RFC 7413 TCP Fast Open by sending application data inside
the initial SYN packet. Many stateful middleboxes forward TFO SYN packets
without Deep Packet Inspection (DPI) because the connection is not yet
fully established in their state tables.

This module tests if target ports accept and process TFO data payloads,
bypassing standard 3-way handshake inspection loops.
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

logger = logging.getLogger("usare.tfo_probe")


class TFOProber:
    """Manages raw TCP Fast Open scanning probes."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        if not HAS_SCAPY:
            logger.warning("[TFO Prober] Scapy not installed. Raw TFO probing disabled.")

    def probe_tfo(self, target: str, port: int, payload: bytes = b"GET / HTTP/1.1\r\n\r\n", 
                  timeout: float = 3.0) -> Dict:
        """
        Send a SYN packet with TCP Option 34 (TFO) and a data payload.
        """
        result: Dict[str, Any] = {
            "port": port,
            "tfo_supported": False,
            "data_processed": False,
            "latency": 0.0,
            "response_flags": "",
        }

        if not HAS_SCAPY:
            return result
            
        t0 = time.time()
        try:
            # Construct TFO Cookie Option: Kind 34, Length 2 for request (empty cookie)
            tfo_option = (34, b"")
            
            # Application data in SYN
            ip_layer = IP(dst=target)
            tcp_layer = TCP(dport=port, flags="S", options=[tfo_option])
            
            packet = ip_layer / tcp_layer / payload
            
            # Send and wait for SYN-ACK or RST
            kwargs = {"timeout": timeout, "verbose": 0}
            if self.interface:
                kwargs["iface"] = self.interface
                
            resp = sr1(packet, **kwargs)
            
            if resp and resp.haslayer(TCP):
                flags = resp[TCP].flags
                result["response_flags"] = str(flags)
                result["latency"] = (time.time() - t0) * 1000
                
                # If we get SYN-ACK (SA), the port is open and accepted the SYN
                if flags & 0x12 == 0x12: 
                    # Did it acknowledge the data?
                    # The ACK number should be ISN + len(payload) + 1 if data was accepted.
                    # Standard SYN-ACK without TFO data accepted is ISN + 1.
                    if resp[TCP].ack > packet[TCP].seq + 1:
                        result["tfo_supported"] = True
                        result["data_processed"] = True
                    else:
                        # Server ignored the TFO data but port is open
                        result["tfo_supported"] = False
                        
        except Exception as e:
            logger.debug(f"[TFO] Probe failed to {target}:{port} - {e}")
            
        return result
