"""
USARE QUIC / Alt-Svc Tunneling

Connects to a target over standard HTTP/1.1 or HTTP/2, extracts
the `Alt-Svc` header, and if HTTP/3 (QUIC) is supported, routes
subsequent probes through UDP 443 bypassing deep packet inspection
focused on TCP.
"""

import socket
import logging
import ssl
import time
from typing import Dict, Optional, List

logger = logging.getLogger("usare.quic_tunnel")


class QUICTunnelEngine:
    """Manages Alt-Svc discovery and HTTP/3 QUIC encapsulation."""

    def __init__(self):
        self.known_quic_endpoints: Dict[str, int] = {}

    def extract_alt_svc(self, target: str, port: int = 443) -> Optional[List[str]]:
        """
        Connect via TLS/HTTP and parse the Alt-Svc header.
        """
        logger.debug(f"[QUICTunnel] Checking Alt-Svc for {target}:{port}")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target, port), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    ssock.sendall(request.encode())
                    
                    response = ssock.recv(4096).decode("utf-8", errors="ignore")
                    
                    # Parse headers case-insensitively
                    for line in response.split("\r\n"):
                        if line.lower().startswith("alt-svc:"):
                            parts = line.split(":", 1)[1].strip()
                            alts = [p.strip() for p in parts.split(",")]
                            logger.info(f"[QUICTunnel] Found Alt-Svc capabilities: {alts}")
                            
                            # Cache if h3 is supported
                            h3_supported = False
                            for alt in alts:
                                if alt.startswith('h3="'):
                                    h3_supported = True
                                    self.known_quic_endpoints[target] = port  # Usually same port (443)
                                    
                            return alts
                            
            return None
            
        except Exception as e:
            logger.debug(f"[QUICTunnel] Failed to extract Alt-Svc from {target}:{port} - {e}")
            return None

    def support_quic(self, target: str) -> bool:
        """Check if target is known to support QUIC."""
        return target in self.known_quic_endpoints

    def wrap_probe_quic(self, target: str, payload: bytes) -> bytes:
        """
        Wraps a generic application probe inside a minimal QUIC packet structure.
        Note: Full QUIC connection establishment requires a cryptographic handshake.
        For scanning enumeration, we send a QUIC Initial packet mimicking 0-RTT
        or a malformed connection attempt that still bypasses TCP DPI.
        """
        if not self.support_quic(target):
            # Attempt discovery
            self.extract_alt_svc(target)
            if not self.support_quic(target):
                logger.warning(f"[QUICTunnel] Target {target} does not advertise HTTP/3.")
                return payload

        logger.info(f"[QUICTunnel] Wrapping probe for {target} via UDP 443 (QUIC)")
        
        # Build a dummy QUIC Initial Packet (Version 1 - 0x00000001)
        # Type: Initial (11), varying flags
        header_form = 0xC0  # Long header
        version = b"\x00\x00\x00\x01"
        dcil_scil = b"\x00" # 0-length connection IDs
        
        # This is a highly abstracted raw representation. True QUIC requires crypto handling
        # via external libraries. This implementation tricks naive L4 DPI that expects TCP.
        quic_packet = bytes([header_form]) + version + dcil_scil + payload
        
        return quic_packet
