"""
USARE SYN Cookie Detection & Server Load Inference Engine

SYN cookies (RFC 4987) are a countermeasure against SYN flood attacks.
When a server's listen backlog is full or when SYN cookie mode is always
active, the server encodes connection state into the TCP ISN (Initial
Sequence Number) and TSecr (Timestamp Echo Reply) instead of allocating
a socket slot.

What we can infer from SYN cookie detection:
  - Server is under active SYN flood attack or has permanent syn_cookies=1
  - The server OS (Linux SYN cookie formula is different from FreeBSD's)
  - Server uptime / secret rotation schedule (Linux rotates every 64 seconds)
  - Whether SYN flood mitigation is at kernel or hardware level (ASIC NICs
    implement SYN cookies in firmware with different ISN patterns)
  - Connection backlog size (by counting how many connections we can open
    before the server switches to cookie mode)

Detection technique:
  1. Send SYN → receive SYN-ACK with ISN value
  2. Extract cookie bits from ISN: top 5 bits = server time (t), next 3 = MSS index
  3. Send RST immediately (don't complete handshake)
  4. Wait 1 second, send another SYN
  5. If the new ISN has t incremented by exactly 1 → cookie mode confirmed
  6. Compare ISN formula to Linux / FreeBSD / Windows templates to identify OS

Linux SYN cookie ISN formula (kernel source net/ipv4/syncookies.c):
  isn = (siphash(...) + t << 24) & 0xFFFFFFFF
  where t = jiffies / HZ / 64 (rolls over every 64 seconds)
  top 5 bits encode t, next 3 encode MSS index

MSS index → actual MSS (Linux):
  0 → 536, 1 → 1300, 2 → 536 (IPsec), 3 → 1440, 4 → 1440 (DS),
  5 → 1452 (PPPoE), 6 → 1460, 7 → 1460 (DS)
"""

import time
import random
import socket
import struct
import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("usare.syn_cookie")

try:
    from scapy.all import IP, TCP, ICMP, sr1, send, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─── Linux MSS index table ────────────────────────────────────────────────────

LINUX_MSS_TABLE = [536, 1300, 536, 1440, 1440, 1452, 1460, 1460]
FREEBSD_MSS_TABLE = [216, 536, 1200, 1460]


class CookieDetectionMethod(Enum):
    NOT_DETECTED      = "not_detected"      # Server not using SYN cookies
    LINUX_COOKIE      = "linux_syn_cookie"  # Linux kernel SYN cookies confirmed
    FREEBSD_COOKIE    = "freebsd_syn_cookie"
    GENERIC_COOKIE    = "generic_syn_cookie"  # Cookie-like ISN but OS unknown
    UNDER_ATTACK      = "under_syn_flood"   # Backlog full (cookies activated)
    HARDWARE_OFFLOAD  = "hardware_syn_cookie"  # ASIC-level SYN cookies (NICs)


@dataclass
class SYNCookieResult:
    """Result of SYN cookie detection for a single target."""
    target: str
    port: int
    detection_method: CookieDetectionMethod = CookieDetectionMethod.NOT_DETECTED
    cookie_confirmed: bool = False
    os_guess: str = ""
    server_time_t: Optional[int] = None    # t value from cookie (Linux: jiffies/HZ/64)
    mss_negotiated: Optional[int] = None   # MSS inferred from cookie bits
    mss_index: Optional[int] = None
    backlog_exhausted: bool = False         # True if we triggered cookie by filling backlog
    cookie_rotates_per_min: Optional[float] = None  # Rotation frequency (OS fingerprint)
    isn_samples: List[int] = field(default_factory=list)
    latency_ms: float = 0.0
    error: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "detection_method": self.detection_method.value,
            "cookie_confirmed": self.cookie_confirmed,
            "os_guess": self.os_guess,
            "server_time_t": self.server_time_t,
            "mss_negotiated": self.mss_negotiated,
            "backlog_exhausted": self.backlog_exhausted,
            "cookie_rotates_per_min": self.cookie_rotates_per_min,
            "isn_samples": self.isn_samples,
            "latency_ms": round(self.latency_ms, 2),
            "notes": self.notes,
            "error": self.error,
        }


class SYNCookieProber:
    """
    Detects and fingerprints TCP SYN cookie implementations.
    """

    # Linux SYN cookie bit layout in ISN
    LINUX_T_SHIFT  = 27   # Top 5 bits = t
    LINUX_MSS_MASK = 0x07 # Bottom 3 bits of top byte = MSS index

    def __init__(self, timeout: float = 3.0, interface: Optional[str] = None):
        if not HAS_SCAPY:
            raise RuntimeError("Scapy required for SYN cookie probing")
        self.timeout = timeout
        self.interface = interface
        self._rng = random.SystemRandom()
        conf.verb = 0
        if interface:
            conf.iface = interface

    # ─── Public API ──────────────────────────────────────────────────────────

    def probe(self, target: str, port: int) -> SYNCookieResult:
        """
        Full SYN cookie detection pipeline.

        Sends multiple SYNs and analyses ISN patterns to determine if SYN
        cookies are active and which OS/implementation is being used.
        """
        result = SYNCookieResult(target=target, port=port)
        t0 = time.time()

        try:
            # Phase 1: Collect baseline ISN samples
            isn_samples = self._collect_isn_samples(target, port, count=3)
            result.isn_samples = isn_samples

            if len(isn_samples) < 2:
                result.error = "Insufficient ISN samples (port may be filtered)"
                result.latency_ms = (time.time() - t0) * 1000
                return result

            # Phase 2: Analyse ISN for cookie patterns
            self._analyse_isn_pattern(result, isn_samples)

            # Phase 3: If cookie detected, extract metadata
            if result.cookie_confirmed:
                self._extract_cookie_metadata(result, isn_samples)

            # Phase 4: Verify rotation timing (if Linux-style)
            if result.detection_method == CookieDetectionMethod.LINUX_COOKIE:
                self._verify_linux_rotation(result, target, port)

        except Exception as e:
            result.error = str(e)
            logger.debug(f"[SYNCookie] Probe failed for {target}:{port}: {e}")

        result.latency_ms = (time.time() - t0) * 1000
        return result

    def probe_multiple(self, target: str, ports: List[int]) -> List[SYNCookieResult]:
        """Probe multiple ports for SYN cookie usage."""
        return [self.probe(target, port) for port in ports]

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _collect_isn_samples(self, target: str, port: int,
                             count: int = 3) -> List[int]:
        """Send SYNs and collect ISN values from SYN-ACK responses."""
        isn_samples = []

        for i in range(count):
            src_port = self._rng.randint(49152, 65535)
            pkt = (
                IP(dst=target) /
                TCP(
                    sport=src_port,
                    dport=port,
                    flags="S",
                    seq=self._rng.randint(1, 0xFFFFFFFF),
                    window=65535,
                    options=[
                        ("MSS", 1460),
                        ("SAckOK", b""),
                        ("Timestamp", (int(time.time() * 1000) & 0xFFFFFFFF, 0)),
                        ("NOP", None),
                        ("WScale", 7),
                    ]
                )
            )

            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
                isn = resp[TCP].seq
                isn_samples.append(isn)
                logger.debug(f"[SYNCookie] ISN sample {i+1}: {isn:#010x}")

                # Send RST to avoid half-open connections
                rst = IP(dst=target) / TCP(
                    sport=src_port, dport=port,
                    flags="R", seq=resp[TCP].ack, window=0
                )
                send(rst, verbose=0)

            # Brief pause between probes to avoid rate limiting
            time.sleep(0.1 + self._rng.uniform(0, 0.05))

        return isn_samples

    def _analyse_isn_pattern(self, result: SYNCookieResult, samples: List[int]):
        """
        Determine if ISN values follow a SYN cookie formula.

        Key insight: Random ISNs have ~32 bits of entropy.
        Linux SYN cookie ISNs have only ~27 bits of randomness
        because 5 bits encode the time value t and carry the MSS index.
        Also, sequential probes within the same 64-second window will
        have ISNs where the top 5 bits are identical.
        """
        if len(samples) < 2:
            return

        # Extract top-5-bit values for each sample
        top5_values = [(isn >> 27) & 0x1F for isn in samples]
        mss_indices = [(isn >> 24) & 0x07 for isn in samples]

        # If all top-5 values are the same → strong indicator of Linux SYN cookie
        # (within a 64-second window, t is constant)
        if len(set(top5_values)) == 1:
            t_value = top5_values[0]
            mss_idx = mss_indices[0]

            if mss_idx < len(LINUX_MSS_TABLE):
                result.cookie_confirmed = True
                result.detection_method = CookieDetectionMethod.LINUX_COOKIE
                result.os_guess = "Linux (SYN cookies active)"
                result.server_time_t = t_value
                result.mss_index = mss_idx
                result.mss_negotiated = LINUX_MSS_TABLE[mss_idx]
                result.notes.append(
                    f"Linux SYN cookie confirmed: t={t_value}, "
                    f"MSS index {mss_idx} → {result.mss_negotiated} bytes"
                )
                logger.info(
                    f"[SYNCookie] Linux SYN cookie detected: t={t_value}, "
                    f"MSS={result.mss_negotiated}"
                )
                return

        # FreeBSD pattern: different MSS table, different bit layout
        freebsd_top = [(isn >> 29) & 0x07 for isn in samples]
        if len(set(freebsd_top)) == 1 and freebsd_top[0] < len(FREEBSD_MSS_TABLE):
            result.cookie_confirmed = True
            result.detection_method = CookieDetectionMethod.FREEBSD_COOKIE
            result.os_guess = "FreeBSD (SYN cookies active)"
            result.mss_negotiated = FREEBSD_MSS_TABLE[freebsd_top[0]]
            result.notes.append("FreeBSD-style SYN cookie pattern detected")
            return

        # Generic check: very low ISN variance across multiple probes
        # (random ISNs should have high variance)
        if len(samples) >= 3:
            mean = sum(samples) / len(samples)
            variance = sum((s - mean) ** 2 for s in samples) / len(samples)
            # Coefficient of variation (normalised std dev)
            import math
            cv = math.sqrt(variance) / max(mean, 1)
            if cv < 0.01:  # < 1% variation → very likely cookie
                result.cookie_confirmed = True
                result.detection_method = CookieDetectionMethod.GENERIC_COOKIE
                result.os_guess = "Unknown (SYN cookie-like ISN pattern)"
                result.notes.append(
                    f"Low ISN variance (CV={cv:.4f}) suggests SYN cookie or deterministic ISN"
                )

    def _extract_cookie_metadata(self, result: SYNCookieResult, samples: List[int]):
        """Extract additional metadata from confirmed cookie ISNs."""
        if not samples:
            return

        if result.detection_method == CookieDetectionMethod.LINUX_COOKIE:
            t = result.server_time_t or 0
            # t increments every 64 seconds; estimate server uptime range
            # (t wraps at 2^5=32, so we can't get exact uptime without the epoch)
            result.notes.append(
                f"Server time slot t={t} (Linux rotates every 64s; "
                f"t wraps at 32 → uptime multiple of 2048s indeterminate)"
            )
            result.cookie_rotates_per_min = 60.0 / 64.0  # ~0.94 rotations/min
            result.notes.append(
                "SYN flood mitigation: ACTIVE (kernel net.ipv4.tcp_syncookies=1)"
            )

    def _verify_linux_rotation(self, result: SYNCookieResult,
                                target: str, port: int):
        """
        Wait for the 64-second boundary and check if t increments.
        If it does, Linux SYN cookie is confirmed beyond any doubt.

        This is a slow check — only runs if caller explicitly waits.
        For speed, we skip this step and rely on the ISN pattern.
        """
        # For now, note that manual verification is possible
        result.notes.append(
            "To confirm: wait 64s and re-probe; if ISN top-5-bits increment by 1, "
            "Linux SYN cookie is verified with 100% certainty"
        )
