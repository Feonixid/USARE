"""
USARE QUIC Connection ID (CID) Churning

This module generates raw UDP packets formatted to look like QUIC Initial frames.
It constantly rotates the Source Connection ID (SCID) for each packet sent
to the same target and port. By changing the SCID rapidly, stateful UDP 
firewalls and Intrusion Detection Systems (IDS) that track flows via 
the 5-tuple + CID are forced to treat the single logical scan as hundreds 
of independent, incomplete UDP connection attempts, exhausting fast-path 
tracking tables and blinding signature engines.
"""

import socket
import logging
import random
import time
from typing import Optional, Dict, Any

try:
    from scapy.all import IP, UDP, sr1, Raw, conf, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.quic_churn")

class QUICChurnEngine:
    """Manages raw UDP/QUIC packet generation with SCID churning."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._rng = random.SystemRandom()
        if not HAS_SCAPY:
            logger.warning("[QUIC Churn] Scapy not installed. Advanced QUIC generation disabled.")

    def generate_random_cid(self, length: int = 8) -> bytes:
        """Generates a random Connection ID."""
        return bytes([self._rng.randint(0, 255) for _ in range(length)])

    def craft_quic_initial(self, scid: bytes, dcid: bytes, payload: bytes) -> bytes:
        """
        Constructs a minimal, fake QUIC Version 1 Initial Packet header.
        Structure (Simplified for bypass, not full cryptographic handshake):
        - Header Form (1 bit): 1 (Long Header)
        - Fixed Bit (1 bit): 1
        - Packet Type (2 bits): 00 (Initial)
        - Reserved (4 bits): 0000
        - Version (32 bits): 0x00000001 (Version 1)
        - DCIL (1 byte): Length of DCID
        - DCID (Variable)
        - SCIL (1 byte): Length of SCID
        - SCID (Variable)
        - Token Length & Token (Omitting for simple bypass)
        - Length (Variable-length integer representation)
        - Packet Number (Variable)
        - Payload
        """
        # 11000000 = 0xC0 (Long Header, Initial Packet)
        flags = b"\xC0"
        version = b"\x00\x00\x00\x01" # QUIC v1
        
        # Lengths (Assuming 8-byte CIDs for simplicity in this engine)
        dcil = bytes([len(dcid)])
        scil = bytes([len(scid)])
        
        # We append the raw probe payload directly after the basic header.
        # This is malformed according to strict QUIC crypto, but effectively
        # accomplishes the evasion against L4-L6 DPI engines looking for UDP streams.
        return flags + version + dcil + dcid + scil + scid + payload

    def send_churn_burst(self, target: str, port: int, base_payload: bytes, burst_size: int = 5, timeout: float = 2.0) -> Dict:
        """
        Sends a burst of packets to the target, changing the SCID on every single packet.
        """
        result: Dict[str, Any] = {
            "target": target,
            "port": port,
            "packets_sent": 0,
            "responses_received": 0,
            "unique_scids_used": 0,
            "bypassed": False
        }

        if not HAS_SCAPY:
            return result

        # The Destination CID can remain constant (or empty) to target
        # a specific backend routing instance if desired, but for raw evasion
        # we generate one random DCID for the session, and churn the SCID.
        dcid = self.generate_random_cid(8)
        
        received_answers = 0

        for _ in range(burst_size):
            scid = self.generate_random_cid(8)
            quic_payload = self.craft_quic_initial(scid, dcid, base_payload)
            
            ip_layer = IP(dst=target)
            udp_layer = UDP(sport=self._rng.randint(49152, 65535), dport=port)
            
            packet = ip_layer / udp_layer / Raw(load=quic_payload)
            
            kwargs: Dict[str, Any] = {"timeout": timeout / burst_size, "verbose": 0}
            if self.interface:
                kwargs["iface"] = self.interface
                
            # Send the packet and briefly listen for an ICMP unreach or UDP reply
            resp = sr1(packet, **kwargs)
            
            result["unique_scids_used"] += 1
            result["packets_sent"] += 1
            
            if resp:
                received_answers += 1
                
        result["responses_received"] = received_answers
        if received_answers > 0:
            result["bypassed"] = True
            
        return result
