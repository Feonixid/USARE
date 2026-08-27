"""
DTLS ClientHello Probe (UDP).

Many VPNs, IoT stacks, and RTC services speak DTLS on UDP. A minimal
ClientHello can elicit ServerHello / Alert without completing a handshake,
mapping UDP surface and middlebox behavior with low packet count.
"""

import socket
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("usare.dtls_probe")

# DTLS 1.2 record header + minimal ClientHello (single cipher)
# Content type 22 = handshake, version 0xfeff = DTLS 1.0 record layer
# Handshake type 1 = ClientHello


def _minimal_dtls_client_hello() -> bytes:
    """
    Pre-built minimal DTLS 1.2 ClientHello (single fragment).
    Elicits ServerHello, HelloVerifyRequest, or Alert on many DTLS endpoints.
    """
    return bytes.fromhex(
        "16fefd0000000000000000006c01000060000000000060"
        "fefd"
        + "00" * 32
        + "00"
        + "0002c02f"
        + "0100"
    )


def probe_dtls_udp(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    ports = ports or [443, 5349, 1194, 4433, 5684]
    payload = _minimal_dtls_client_hello()
    results: Dict[str, Any] = {"target": target, "ports": {}}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            t0 = time.perf_counter()
            sock.sendto(payload, (target, port))
            try:
                data, _ = sock.recvfrom(4096)
                ms = (time.perf_counter() - t0) * 1000
                kind = "unknown"
                if data and data[0] == 0x16:
                    kind = "handshake_record"
                elif data and data[0] == 0x15:
                    kind = "alert"
                elif data and data[0] == 0x14:
                    kind = "change_cipher_spec"
                results["ports"][str(port)] = {
                    "bytes": len(data),
                    "kind": kind,
                    "latency_ms": round(ms, 2),
                }
            except socket.timeout:
                results["ports"][str(port)] = {"bytes": 0, "kind": "timeout"}
            sock.close()
        except Exception as e:
            results["ports"][str(port)] = {"error": str(e)}
            logger.debug("DTLS probe %s:%s: %s", target, port, e)
    return results
