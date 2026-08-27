"""
SSH Key-Exchange / Banner Intelligence.

Reads SSH identification string and optional KEXINIT without completing
authentication — maps algorithms, vendor hints, and timing (useful for
correlation with passive collection).
"""

import socket
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("usare.ssh_kex_intel")


def probe_ssh_intel(
    target: str,
    port: int = 22,
    timeout: float = 5.0,
    read_kexinit: bool = True,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "target": target,
        "port": port,
        "identification": None,
        "kex_algorithms": None,
        "host_key_algorithms": None,
        "encryption_client_to_server": None,
        "latency_connect_ms": None,
        "notes": [],
    }
    try:
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        out["latency_connect_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        buf = b""
        while b"\n" not in buf and len(buf) < 512:
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n")[0].decode("utf-8", errors="replace").strip()
        out["identification"] = line

        if read_kexinit and line.startswith("SSH-"):
            # Client banner (minimal)
            sock.sendall(b"SSH-2.0-USARE_Probe_0.1\r\n")
            # Read packet length + KEXINIT (binary SSH framing)
            sock.settimeout(timeout)
            raw = sock.recv(16384)
            if raw and len(raw) > 10:
                # Best-effort: look for comma-separated algorithm lists in payload
                try:
                    text = raw.decode("latin-1", errors="ignore")
                    if "curve25519" in text or "diffie-hellman" in text:
                        out["notes"].append("KEXINIT-like payload observed")
                    if "ssh-rsa" in text or "rsa-sha2" in text:
                        out["notes"].append("host key algorithms present in stream")
                except Exception:
                    pass
        sock.close()
    except Exception as e:
        out["notes"].append(str(e))
        logger.debug("SSH intel %s:%s: %s", target, port, e)
    return out
