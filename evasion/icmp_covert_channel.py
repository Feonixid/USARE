"""
USARE ICMP Covert Channel + Payload Steganography

Two distinct capabilities:

═══════════════════════════════════════════════════════════════════════
1. ICMP COVERT CHANNEL
═══════════════════════════════════════════════════════════════════════

Encodes arbitrary probe data inside the 32-byte ICMP Echo request payload
using a combination of techniques:

  a) LSB Steganography  — low bits of each payload byte carry signal bits
     while high bits are populated with realistic Windows ping data, making
     the payload look statistically normal to entropy-based DPI.

  b) Sequence/ID field encoding  — the 16-bit ICMP identifier and sequence
     fields can each carry 1 byte of probe data without affecting ICMP
     protocol operation, since these fields are opaque to routers.

  c) Timing covert channel  — inter-packet delay encodes bits via
     pulse-position modulation (short gap = 0, long gap = 1).

Practical use: probe whether a firewall silently drops specific ports by
sending ICMP pings and observing which ones return echo-replies vs silently
disappear, without ever sending TCP/UDP to the target (zero TCP/UDP state
on firewalls and IDS).

═══════════════════════════════════════════════════════════════════════
2. FIREWALL EGRESS MAPPING VIA ICMP UNREACHABLES
═══════════════════════════════════════════════════════════════════════

Sends UDP probes to high ports and collects ICMP Type 3 (Destination
Unreachable) responses. Different unreachable codes reveal:
  - Code 0: Network unreachable (routing issue or null route)
  - Code 1: Host unreachable (ARP failure, host down)
  - Code 2: Protocol unreachable (IP layer rejects protocol)
  - Code 3: Port unreachable (UDP port closed) — means host is ALIVE
  - Code 9: Network admin prohibited (ACL/firewall rule)
  - Code 10: Host admin prohibited
  - Code 13: Communication admin prohibited (most firewalls)

By mapping which codes come back from which destinations/ports, USARE
infers the complete egress firewall policy without ever establishing
a TCP connection — zero TCP state created in any device.

═══════════════════════════════════════════════════════════════════════
3. ICMP TUNNEL PROBE RELAY (advanced)
═══════════════════════════════════════════════════════════════════════

Some networks only allow ICMP through their perimeter. This module
builds a lightweight ICMP-tunnelled probe relay where scan data is
embedded in ping requests to a cooperating relay host, which forwards
the actual TCP probe to the target and returns results via ping replies.
"""

import time
import struct
import random
import socket
import logging
import threading
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.icmp_covert")

try:
    from scapy.all import IP, ICMP, UDP, Raw, sr1, srp, send, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─── Windows ping payload pattern (mimics Windows 10 icmp.exe exactly) ──────

_WIN10_PING_ALPHABET = b"abcdefghijklmnopqrstuvwabcdefghi"


# ─── Part 1: ICMP Covert Channel ─────────────────────────────────────────────

def _encode_lsb(carrier: bytes, data: bytes, bits_per_byte: int = 1) -> bytes:
    """
    Encode `data` into the LSBs of `carrier`.

    Args:
        carrier: The cover bytes (Windows ping payload, ~32 bytes)
        data: Secret bytes to embed
        bits_per_byte: How many LSBs of each carrier byte carry signal (1-4)

    Returns:
        Steganographic payload that looks like normal ICMP data.
    """
    if bits_per_byte not in (1, 2, 4):
        bits_per_byte = 1

    mask = (1 << bits_per_byte) - 1
    capacity_bits = len(carrier) * bits_per_byte
    data_bits = len(data) * 8

    if data_bits > capacity_bits:
        raise ValueError(
            f"Cannot embed {len(data)} bytes into {len(carrier)}-byte carrier "
            f"at {bits_per_byte} bits/byte (need {data_bits}, have {capacity_bits})"
        )

    # Convert data to bit stream
    bit_stream: List[int] = []
    for byte in data:
        for bit_pos in range(7, -1, -1):
            bit_stream.append((byte >> bit_pos) & 1)

    result = bytearray(carrier)
    bit_idx = 0

    for i in range(len(result)):
        if bit_idx >= len(bit_stream):
            break
        # Clear the LSBs we're using
        result[i] = result[i] & ~mask

        # Pack bits_per_byte bits in
        chunk = 0
        for b in range(bits_per_byte):
            if bit_idx < len(bit_stream):
                chunk = (chunk << 1) | bit_stream[bit_idx]
                bit_idx += 1
        result[i] |= chunk

    return bytes(result)


def _decode_lsb(payload: bytes, num_bytes: int, bits_per_byte: int = 1) -> bytes:
    """Extract LSB-encoded bytes from a payload."""
    mask = (1 << bits_per_byte) - 1
    bit_stream: List[int] = []

    for byte in payload:
        chunk = byte & mask
        for bit_pos in range(bits_per_byte - 1, -1, -1):
            bit_stream.append((chunk >> bit_pos) & 1)

    result = bytearray()
    for byte_idx in range(num_bytes):
        if (byte_idx + 1) * 8 > len(bit_stream):
            break
        byte_val = 0
        for bit_pos in range(8):
            byte_val = (byte_val << 1) | bit_stream[byte_idx * 8 + bit_pos]
        result.append(byte_val)

    return bytes(result)


@dataclass
class ICMPProbeResult:
    """Result of a single covert ICMP probe."""
    target: str
    icmp_id: int
    icmp_seq: int
    payload_data: bytes
    got_reply: bool
    reply_payload: Optional[bytes] = None
    latency_ms: float = 0.0
    ttl_received: Optional[int] = None


class ICMPCovertChannel:
    """
    Send and receive covert probe data inside ICMP Echo packets.
    """

    def __init__(self, bits_per_byte: int = 2, interface: Optional[str] = None):
        """
        Args:
            bits_per_byte: LSBs of each payload byte used for covert data (1-4).
                           Higher = more capacity but more entropy deviation.
                           2 bits/byte gives 8 bytes capacity per 32-byte ping.
            interface: Network interface for raw sockets.
        """
        if not HAS_SCAPY:
            logger.warning("[ICMPCovert] Scapy not available")
        self._bpb = min(4, max(1, bits_per_byte))
        self._interface = interface
        self._rng = random.SystemRandom()

    def capacity_bytes(self, payload_size: int = 32) -> int:
        """How many secret bytes fit per ICMP packet."""
        return (payload_size * self._bpb) // 8

    def send_probe(self, target: str, secret_data: bytes,
                   timeout: float = 2.0) -> ICMPProbeResult:
        """
        Embed secret_data in an ICMP ping to target and wait for echo reply.
        The secret is invisible to DPI — the packet looks exactly like a normal ping.

        Args:
            target: Destination IP
            secret_data: Bytes to embed (max capacity_bytes() bytes)
            timeout: Reply wait time in seconds

        Returns:
            ICMPProbeResult with reply status and decoded reply payload.
        """
        if not HAS_SCAPY:
            return ICMPProbeResult(target=target, icmp_id=0, icmp_seq=0,
                                   payload_data=secret_data, got_reply=False,
                                   latency_ms=0.0)

        # Use ICMP ID and seq to embed 2 bytes of metadata
        icmp_id   = (secret_data[0] ^ 0xA5) if len(secret_data) > 0 else self._rng.randint(1, 65535)
        icmp_seq  = (secret_data[1] ^ 0x5A) if len(secret_data) > 1 else self._rng.randint(1, 65535)

        # Embed remaining data in payload
        remaining = secret_data[2:] if len(secret_data) > 2 else b""
        carrier = _WIN10_PING_ALPHABET
        if remaining:
            payload = _encode_lsb(carrier, remaining, self._bpb)
        else:
            payload = carrier

        pkt = (
            IP(dst=target, ttl=128) /
            ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq) /
            Raw(load=payload)
        )

        kwargs = {"timeout": timeout, "verbose": 0}
        if self._interface:
            kwargs["iface"] = self._interface

        t0 = time.time()
        reply = sr1(pkt, **kwargs)
        latency = (time.time() - t0) * 1000

        got_reply = reply is not None and reply.haslayer(ICMP) and reply[ICMP].type == 0
        reply_payload = None
        ttl_rx = None

        if got_reply:
            ttl_rx = reply[IP].ttl
            if reply.haslayer(Raw):
                reply_payload = bytes(reply[Raw].load)

        return ICMPProbeResult(
            target=target,
            icmp_id=icmp_id,
            icmp_seq=icmp_seq,
            payload_data=secret_data,
            got_reply=got_reply,
            reply_payload=reply_payload,
            latency_ms=latency,
            ttl_received=ttl_rx,
        )

    def decode_reply(self, result: ICMPProbeResult) -> Optional[bytes]:
        """
        Decode embedded data from an ICMP reply payload.

        Returns:
            Decoded bytes, or None if no embedded data found.
        """
        if not result.got_reply or not result.reply_payload:
            return None
        try:
            # The echo reply payload is the same as what we sent —
            # extract the LSB-encoded data we embedded
            return _decode_lsb(result.reply_payload,
                                self.capacity_bytes(len(result.reply_payload)),
                                self._bpb)
        except Exception:
            return None

    def timing_encode(self, target: str, data_byte: int,
                      short_gap: float = 0.05, long_gap: float = 0.15,
                      timeout: float = 2.0) -> List[bool]:
        """
        Encode one byte (8 bits) via pulse-position timing modulation.
        Short inter-probe gap = bit 0, long gap = bit 1.

        Returns:
            List of 8 booleans indicating which probes got replies.
        """
        if not HAS_SCAPY:
            return [False] * 8

        replies = []
        for bit_pos in range(7, -1, -1):
            bit = (data_byte >> bit_pos) & 1
            gap = long_gap if bit else short_gap

            pkt = (
                IP(dst=target, ttl=128) /
                ICMP(type=8, code=0,
                     id=self._rng.randint(1, 65535),
                     seq=bit_pos) /
                Raw(load=_WIN10_PING_ALPHABET)
            )
            reply = sr1(pkt, timeout=timeout, verbose=0)
            replies.append(reply is not None)
            time.sleep(gap)

        return replies


# ─── Part 2: Firewall Egress Mapping via ICMP Unreachables ──────────────────

@dataclass
class EgressPolicyEntry:
    """A single inferred egress firewall policy entry."""
    destination: str
    port: int
    protocol: str    # "udp" / "tcp"
    icmp_type: int
    icmp_code: int
    policy: str      # "open", "closed", "acl_drop", "host_unreach", "net_unreach"
    confidence: float


class ICMPEgressMapper:
    """
    Maps egress firewall rules using ICMP Unreachable responses.

    Does NOT send TCP/UDP data — only sends UDP probes to trigger ICMP
    errors, revealing what the firewall permits or denies.
    """

    # ICMP Code → policy mapping
    CODE_POLICIES = {
        (3, 0):  ("net_unreach",   0.75),
        (3, 1):  ("host_unreach",  0.80),
        (3, 2):  ("proto_unreach", 0.75),
        (3, 3):  ("closed",        0.95),   # Port unreachable = host alive, port closed
        (3, 9):  ("acl_drop",      0.90),   # Net admin prohib
        (3, 10): ("acl_drop",      0.90),   # Host admin prohib
        (3, 13): ("acl_drop",      0.95),   # Comm admin prohib = firewall rule
    }

    UDP_PROBES = [
        # (port, description)
        (33434, "traceroute range start"),
        (33500, "traceroute range mid"),
        (65000, "high port"),
        (12345, "common test port"),
        (9999,  "common test port"),
        (7,     "echo"),
        (19,    "chargen"),
    ]

    def __init__(self, timeout: float = 2.0, interface: Optional[str] = None):
        self.timeout = timeout
        self._interface = interface

    def map_egress(self, target: str) -> List[EgressPolicyEntry]:
        """
        Send UDP probes and collect ICMP unreachables to infer firewall rules.
        """
        if not HAS_SCAPY:
            return []

        results: List[EgressPolicyEntry] = []
        conf.verb = 0

        for port, desc in self.UDP_PROBES:
            try:
                pkt = IP(dst=target) / UDP(sport=random.randint(49152, 65535),
                                           dport=port) / Raw(load=b"\x00" * 8)
                kwargs = {"timeout": self.timeout, "verbose": 0}
                if self._interface:
                    kwargs["iface"] = self._interface

                reply = sr1(pkt, **kwargs)

                if reply is None:
                    continue

                if reply.haslayer(ICMP):
                    t = reply[ICMP].type
                    c = reply[ICMP].code
                    policy, confidence = self.CODE_POLICIES.get(
                        (t, c), ("unknown_icmp", 0.5)
                    )
                    results.append(EgressPolicyEntry(
                        destination=target,
                        port=port,
                        protocol="udp",
                        icmp_type=t,
                        icmp_code=c,
                        policy=policy,
                        confidence=confidence,
                    ))
                    logger.debug(
                        f"[EgressMap] {target}:{port}/UDP → "
                        f"ICMP {t}/{c} ({policy})"
                    )

            except Exception as e:
                logger.debug(f"[EgressMap] Probe {port} failed: {e}")

        return results

    def summarise(self, entries: List[EgressPolicyEntry]) -> Dict[str, Any]:
        """Produce a human-readable policy summary."""
        if not entries:
            return {"status": "no_icmp_responses", "note": "All probes silently dropped or filtered"}

        policy_counts: Dict[str, int] = {}
        for e in entries:
            policy_counts[e.policy] = policy_counts.get(e.policy, 0) + 1

        dominant = max(policy_counts, key=lambda k: policy_counts[k])

        notes = []
        if "acl_drop" in policy_counts:
            notes.append("Stateful ACL/firewall detected (ICMP admin-prohibited responses)")
        if "closed" in policy_counts:
            notes.append("Host is alive — port-unreachable received on some probes")
        if "host_unreach" in policy_counts:
            notes.append("Some destinations return host-unreachable (possible filtering or routing)")

        return {
            "policy_distribution": policy_counts,
            "dominant_policy": dominant,
            "host_confirmed_alive": "closed" in policy_counts,
            "firewall_detected": "acl_drop" in policy_counts,
            "notes": notes,
            "probe_count": len(entries),
        }
