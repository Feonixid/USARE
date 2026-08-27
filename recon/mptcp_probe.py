"""
MPTCP (Multipath TCP) Capability Probe.

Sends a SYN with MP_CAPABLE (TCP option kind 30). Linux kernels with MPTCP
enabled may respond differently than strict middleboxes that strip unknown
options. Useful for mapping path diversity and bypass surfaces.

RFC 8684 §3.1: MP_CAPABLE on-wire layout (12 bytes total):
  kind(1) + len(1) + [subtype|ver](1) + flags(1) + sender_key(8)
In Scapy's (kind, value) tuple, Scapy prepends kind+len automatically, so
the value bytes must be exactly 10 bytes to produce a 12-byte on-wire option.
"""

import random
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("usare.mptcp_probe")

try:
    from scapy.all import IP, TCP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# MP_CAPABLE option value — 10 bytes so Scapy emits 12 bytes on-wire.
# Layout (RFC 8684 §3.1):
#   byte 0: (subtype=0 << 4) | version=1  → 0x01
#   byte 1: flags (checksum required=0, ...) → 0x00
#   bytes 2-9: sender key (8 bytes, random or zero for probe purposes)
_MPTCP_VALUE = bytes([0x01, 0x00]) + b"\x00" * 8   # 10 bytes total


def probe_mptcp(
    target: str,
    port: int = 443,
    timeout: float = 3.0,
    interface: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compare baseline SYN vs SYN carrying a synthetic MPTCP MP_CAPABLE option.
    If baseline gets SYN-ACK but MPTCP SYN does not, a middlebox is stripping
    the option on the path.
    """
    result: Dict[str, Any] = {
        "target": target,
        "port": port,
        "baseline_synack": False,
        "mptcp_synack": False,
        "middlebox_strips_mptcp": None,
        "notes": [],
    }
    if not HAS_SCAPY:
        result["notes"].append("Scapy required")
        return result

    conf.verb = 0

    # Set interface via conf.iface — sr1 does not accept iface as a kwarg
    old_iface = None
    if interface:
        old_iface = conf.iface
        conf.iface = interface

    kw: Dict[str, Any] = {"timeout": timeout, "verbose": 0}

    def _syn(opts):
        return IP(dst=target) / TCP(
            dport=port,
            sport=random.randint(49152, 65535),
            flags="S",
            seq=int(time.time() * 1e6) % (2 ** 32),
            options=opts,
        )

    try:
        # Baseline SYN
        base = _syn([("MSS", 1460), ("WScale", 7), ("SAckOK", b"")])
        r0 = sr1(base, **kw)
        if r0 and r0.haslayer(TCP) and (r0[TCP].flags & 0x12) == 0x12:
            result["baseline_synack"] = True

        # MPTCP SYN — MP_CAPABLE (kind=30) with correct 10-byte value
        mptcp_syn = _syn([("MSS", 1460), (30, _MPTCP_VALUE)])
        r1 = sr1(mptcp_syn, **kw)
        if r1 and r1.haslayer(TCP) and (r1[TCP].flags & 0x12) == 0x12:
            result["mptcp_synack"] = True

        if result["baseline_synack"] and not result["mptcp_synack"]:
            result["middlebox_strips_mptcp"] = True
            result["notes"].append(
                "SYN-ACK for baseline but not for MPTCP SYN — option stripped on path"
            )
        elif result["mptcp_synack"]:
            result["middlebox_strips_mptcp"] = False
            result["notes"].append("MPTCP MP_CAPABLE option accepted on path")
        elif not result["baseline_synack"]:
            result["notes"].append("No SYN-ACK for baseline — port may be closed/filtered")

    except Exception as e:
        logger.debug("MPTCP probe failed: %s", e)
        result["notes"].append(str(e))
    finally:
        if old_iface is not None:
            conf.iface = old_iface

    return result
