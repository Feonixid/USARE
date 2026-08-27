"""
TLS ALPN / Extension Surface Probe.

Attempts handshakes with different ALPN lists to detect HTTP/2, HTTP/1.1
only, or exotic ALPN acceptance — maps CDN / reverse-proxy behavior.
"""

import ssl
import socket
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("usare.tls_alpn_probe")

ALPN_SETS: List[tuple] = [
    ("h2_http11", ["h2", "http/1.1"]),
    ("http11_only", ["http/1.1"]),
    ("h2_only", ["h2"]),
    ("acme_tls", ["acme-tls/1"]),
]


def probe_tls_alpn(
    target: str,
    port: int = 443,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"target": target, "port": port, "results": []}
    for name, protos in ALPN_SETS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                ctx.set_alpn_protocols(protos)
            except ssl.SSLError:
                out["results"].append({"profile": name, "error": "ALPN not supported by OpenSSL"})
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            t0 = time.perf_counter()
            tls = ctx.wrap_socket(sock, server_hostname=target)
            ms = (time.perf_counter() - t0) * 1000
            negotiated = tls.selected_alpn_protocol()
            ver = tls.version()
            tls.close()
            out["results"].append({
                "profile": name,
                "negotiated_alpn": negotiated,
                "tls_version": ver,
                "handshake_ms": round(ms, 2),
            })
        except Exception as e:
            out["results"].append({"profile": name, "error": str(e)})
            logger.debug("ALPN probe %s %s: %s", name, target, e)
    return out
