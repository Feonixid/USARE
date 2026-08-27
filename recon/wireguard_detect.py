"""
USARE WireGuard Detection

Detects WireGuard VPN endpoints on UDP ports.
WireGuard is designed to be stealthy (ignores unauthenticated packets),
but we can detect it by sending a valid, well-formed Handshake Initiation
message with a dummy public key. 

If the server drops the packet silently without sending an ICMP
Port Unreachable error, it's highly likely to be a WireGuard endpoint
(or deeply filtered UDP port). By correlating UDP probe behavior against
known WireGuard ports (e.g., 51820) vs random unused UDP ports on the
same host, we can reliably infer WireGuard presence.
"""

import socket
import time
import os
import struct
import logging
from typing import Dict, Tuple

logger = logging.getLogger("usare.wireguard_detect")

class WireGuardDetector:
    """Probes for WireGuard VPN endpoints on UDP."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def _build_initiation_packet(self) -> bytes:
        """
        Builds a valid (but unauthorized) WireGuard Handshake Initiation packet.
        Format (Little Endian):
        1 byte: message type (1 = Handshake Initiation)
        3 bytes: reserved (0)
        4 bytes: sender index (random)
        32 bytes: unencrypted ephemeral public key (random)
        48 bytes: encrypted static public key (dummy)
        16 bytes: encrypted timestamp (dummy)
        16 bytes: MAC1 (dummy)
        16 bytes: MAC2 (dummy)
        Total: 148 bytes
        """
        msg_type = b'\x01\x00\x00\x00'
        sender_idx = os.urandom(4)
        ephemeral_pub_key = os.urandom(32)
        encrypted_pub_key = os.urandom(48)
        encrypted_timestamp = os.urandom(16)
        mac1 = os.urandom(16)
        mac2 = os.urandom(16)

        return (msg_type + sender_idx + ephemeral_pub_key + 
                encrypted_pub_key + encrypted_timestamp + mac1 + mac2)

    def probe(self, target: str, port: int) -> Tuple[bool, float]:
        """
        Send a WG Initiation packet and wait.
        WireGuard silently drops unauthorized packets.
        A closed UDP port typically returns ICMP Port Unreachable.
        If we get no ICMP error, it's either WireGuard or filtered.
        """
        t0 = time.time()
        pkt = self._build_initiation_packet()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send WG packet
            sock.sendto(pkt, (target, port))
            
            try:
                # If we get any UDP response back, it's not WireGuard
                # WireGuard will NEVER reply to a bad auth payload.
                data, _ = sock.recvfrom(1024)
                return False, (time.time() - t0) * 1000
                
            except socket.timeout:
                # Silence! This means either WireGuard ignored us, 
                # or a firewall dropped the UDP packet entirely.
                # In a real scanning context, we cross-reference this with 
                # a known closed UDP port to rule out generic UDP filtering.
                return True, (time.time() - t0) * 1000
            except ConnectionRefusedError:
                # Only works on some OSes for ICMP port unreachable
                return False, (time.time() - t0) * 1000
                
        except Exception as e:
            logger.debug(f"[WireGuard] Probe error on {port}: {e}")
            return False, 0.0
        finally:
            sock.close()

    def check_wireguard(self, target: str, port: int = 51820) -> Dict:
        """
        High-confidence WireGuard check.
        Requires comparing the target port with a random high UDP port
        to verify if the host is dropping all UDP traffic or just this port.
        """
        # Step 1: Probe the potential WG port
        is_wg_silent, latency_ms = self.probe(target, port)
        
        if not is_wg_silent:
            return {"detected": False, "port": port, "confidence": 0, "latency_ms": latency_ms}
            
        # Step 2: Probe a random high port (e.g., 54321) as a control
        is_control_silent, _ = self.probe(target, 54321)
        
        # If control rejected it but WG port absorbed it silently -> High confidence
        if not is_control_silent and is_wg_silent:
            confidence = 90
        # If both absorbed -> Host is likely firewalled heavily
        else:
            confidence = 40
            
        return {
            "detected": confidence > 50,
            "port": port,
            "confidence": confidence,
            "latency_ms": round(latency_ms, 2)
        }
