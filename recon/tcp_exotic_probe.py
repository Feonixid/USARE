"""
Exotic / Legacy TCP Option Probing.

Sends SYNs with unusual options (MD5 auth kind 19, Urgent pointer games,
padding) to map middlebox stripping, enterprise firewalls, and legacy
router stacks — patterns relevant to long-haul targeted assessment.
"""

import random
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("usare.tcp_exotic")

try:
    from scapy.all import IP, TCP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def _sport() -> int:
    """Return a random ephemeral source port (IANA dynamic range)."""
    return random.randint(49152, 65535)


def struct_bytes_user_timeout() -> bytes:
    """User Timeout Option (kind 28, RFC 5482) value: granularity=0, timeout=30s."""
    # 2 bytes: G(1bit)|timeout(15bits). 30 seconds, granularity=0 (seconds).
    return bytes([0x00, 30, 0x00, 0x00])


def probe_exotic_options(
    target: str,
    port: int = 443,
    timeout: float = 2.5,
    interface: Optional[str] = None,
) -> Dict[str, Any]:
    """
    For each probe variant, record whether SYN-ACK, RST, or silence.
    Compares baseline option set against exotic / legacy options to detect
    middlebox stripping or RST injection.
    """
    report: Dict[str, Any] = {"target": target, "port": port, "variants": []}
    if not HAS_SCAPY:
        report["error"] = "Scapy required"
        return report

    conf.verb = 0
    # Set iface via conf.iface — sr1 does not accept iface as a kwarg
    if interface:
        old_iface = conf.iface
        conf.iface = interface

    kw: Dict[str, Any] = {"timeout": timeout, "verbose": 0}

    # struct_bytes_user_timeout() is defined above so it's always available here
    variants: List[tuple] = [
        ("baseline", [("MSS", 1460), ("WScale", 8), ("SAckOK", b"")]),
        # Obsolete TCP MD5 option (kind 19) — often stripped or RST
        ("md5_option", [("MSS", 1460), (19, b"\x10" + b"\x00" * 14)]),
        # User Timeout Option kind 28 (RFC 5482)
        ("user_timeout", [("MSS", 1460), (28, struct_bytes_user_timeout())]),
        # Excessive NOP padding — some stacks mis-parse and RST
        ("nop_flood", [("NOP", None)] * 8 + [("MSS", 1460)]),
    ]

    try:
        for name, opts in variants:
            try:
                pkt = IP(dst=target) / TCP(
                    dport=port,
                    sport=_sport(),
                    flags="S",
                    seq=int(time.time() * 1e6) % (2 ** 32),
                    options=opts,
                )
                r = sr1(pkt, **kw)
                flags = ""
                if r and r.haslayer(TCP):
                    f = int(r[TCP].flags)
                    if f & 0x04:
                        flags = "RST"
                    elif (f & 0x12) == 0x12:
                        flags = "SYN-ACK"
                    else:
                        flags = hex(f)
                report["variants"].append(
                    {"name": name, "response": flags or "none"}
                )
            except Exception as e:
                report["variants"].append({"name": name, "response": f"err:{e}"})
                logger.debug("Exotic TCP %s: %s", name, e)
    finally:
        # Restore original iface if we changed it
        if interface:
            conf.iface = old_iface  # type: ignore[possibly-undefined]

    return report
