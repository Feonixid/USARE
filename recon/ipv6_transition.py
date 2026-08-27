"""
IPv6 Transition Mechanism Discovery.

Probes for 6to4, Teredo, and ISATAP relay presence.
State-level networks often use transition mechanisms; discovering them
reveals tunnel endpoints and can enable bypass paths.

NOTE: 6to4 probing requires IPv6 connectivity on the scanner.  If the
scanner only has IPv4 the 6to4 block will fail with socket.gaierror and
is caught gracefully.  Teredo probing only needs IPv4 (UDP to port 3544).
ISATAP is link-local and cannot be probed remotely; it is recorded as a
note only.
"""

import socket
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ipv6_transition")

# Known public Teredo relay servers — contacted over IPv4 UDP port 3544
TEREDO_SERVERS_IPV4 = [
    "teredo.remlab.net",   # Jérôme Duval's public relay
    "teredo.ipv6.microsoft.com",
]

# Teredo port (RFC 4380)
TEREDO_PORT = 3544


@dataclass
class TransitionResult:
    target: str
    ipv4: str
    has_6to4: bool = False
    has_teredo: bool = False
    has_isatap: bool = False
    relay_ip: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ipv4": self.ipv4,
            "has_6to4": self.has_6to4,
            "has_teredo": self.has_teredo,
            "has_isatap": self.has_isatap,
            "relay_ip": self.relay_ip,
            "details": self.details,
        }


def ipv4_to_6to4(ipv4: str) -> str:
    """Convert dotted-quad IPv4 to its 6to4 /48 prefix address (2002::/16)."""
    try:
        parts = ipv4.split(".")
        if len(parts) != 4:
            return ""
        a, b, c, d = map(int, parts)
        return f"2002:{a:02x}{b:02x}:{c:02x}{d:02x}::1"
    except (ValueError, IndexError):
        return ""


def ipv4_to_isatap(ipv4: str) -> str:
    """
    Return the link-local ISATAP address for a given IPv4.
    This address is only reachable on the local link and cannot be probed
    remotely — provided here as an informational helper.
    """
    try:
        parts = ipv4.split(".")
        if len(parts) != 4:
            return ""
        a, b, c, d = map(int, parts)
        return f"fe80::5efe:{a}.{b}.{c}.{d}"
    except (ValueError, IndexError):
        return ""


def probe_ipv6_transition(target_ipv4: str, timeout: float = 3.0) -> TransitionResult:
    """
    Probe target for IPv6 transition mechanisms.
    """
    result = TransitionResult(target=target_ipv4, ipv4=target_ipv4)

    # ── 6to4 ──────────────────────────────────────────────────────────────────
    # Requires IPv6 connectivity on the scanner.  Will fail gracefully otherwise.
    addr_6to4 = ipv4_to_6to4(target_ipv4)
    if addr_6to4:
        result.details["6to4_derived_addr"] = addr_6to4
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((addr_6to4, 80))
            sock.close()
            result.has_6to4 = True
            result.details["6to4_reachable"] = True
        except socket.gaierror as e:
            result.details["6to4_error"] = f"gaierror (scanner may lack IPv6): {e}"
        except (socket.timeout, OSError) as e:
            result.details["6to4_error"] = str(e)
        except Exception as e:
            logger.debug("6to4 probe: %s", e)

    # ── Teredo ────────────────────────────────────────────────────────────────
    # RFC 4380: client sends UDP to the Teredo server's *IPv4* address on port
    # 3544.  We probe this with a minimal Router-Solicitation-style packet.
    # If any server responds (even with an error) Teredo traffic is not blocked.
    teredo_probed = False
    for ts_host in TEREDO_SERVERS_IPV4:
        try:
            addr_infos = socket.getaddrinfo(
                ts_host, TEREDO_PORT, socket.AF_INET, socket.SOCK_DGRAM
            )
            if not addr_infos:
                continue
            _, _, _, _, sockaddr = addr_infos[0]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # Minimal RS packet (random bytes — enough to get a Teredo error back)
            sock.sendto(b"\x00" * 4, sockaddr)
            try:
                data, _ = sock.recvfrom(256)
                result.has_teredo = True
                result.details["teredo_server"] = ts_host
                result.details["teredo_response_bytes"] = len(data)
            except socket.timeout:
                result.details[f"teredo_{ts_host}"] = "timeout (server silent or path blocked)"
            sock.close()
            teredo_probed = True
            break
        except Exception as e:
            logger.debug("Teredo probe %s: %s", ts_host, e)
    if not teredo_probed:
        result.details["teredo_note"] = "Could not resolve any Teredo server"

    # ── ISATAP ────────────────────────────────────────────────────────────────
    # ISATAP operates at L2; remote probing is not meaningful.
    result.details["isatap_link_local_addr"] = ipv4_to_isatap(target_ipv4)
    result.details["isatap_note"] = "ISATAP requires L2 adjacency — remote probing not possible"

    return result
