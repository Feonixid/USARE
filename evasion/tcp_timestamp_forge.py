"""
USARE TCP Timestamp Forgery Engine

Forges TCP timestamp (TSval/TSecr) values in outgoing packets to:

1. DEFEAT PASSIVE OS FINGERPRINTING — Passive observers like p0f and Zeek
   determine OS by correlating the TCP timestamp clock rate (100Hz, 250Hz,
   1000Hz) against observed system uptime. By injecting a fabricated clock
   that matches a chosen OS target profile, USARE makes its probes look like
   they originate from an entirely different OS than the scanner's host.

2. DEFEAT TIMING CORRELATION — Network forensics tools correlate TCP
   timestamps across multiple connections to prove they came from the same
   host (even behind NAT or VPN). By using different fabricated clock bases
   per target, each connection appears to come from a different machine.

3. FAKE SYSTEM UPTIME — Servers leak uptime via TCP timestamps (TSval
   divided by clock frequency = seconds since boot). By setting a plausible
   but fabricated boot time, analysts examining packet captures will see a
   non-existent uptime history.

4. ANTI-REPLAY DETECTION BYPASS — Some firewalls use TCP timestamps to
   detect replay attacks or duplicate connections. By advancing or retarding
   the clock, replayed probe packets avoid timestamp-based duplicate detection.

Clock frequencies by OS:
  Linux kernel ≥ 2.6   → 250Hz  (4ms/tick)
  Linux kernel ≥ 5.4   → 1000Hz (1ms/tick) on most configs
  Windows 10/11        → 100Hz  (10ms/tick) for legacy compat
  macOS                → 1000Hz
  FreeBSD              → 1000Hz
  Solaris              → 100Hz
  Cisco IOS            → 100Hz
"""

import time
import random
import threading
import logging
from typing import Optional, Dict
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ts_forge")

try:
    from scapy.all import IP, TCP, Raw, send, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─── OS Clock Profiles ──────────────────────────────────────────────────────

@dataclass
class TSClockProfile:
    """Defines the TCP timestamp clock behaviour of a specific OS."""
    name: str
    hz: int                     # Ticks per second
    uptime_days_range: tuple    # (min_days, max_days) for fake uptime
    jitter_ticks: int           # Max random jitter added per tick
    monotonic: bool = True      # If False, clock can occasionally jump

    def ticks_per_ms(self) -> float:
        return self.hz / 1000.0


TS_PROFILES: Dict[str, TSClockProfile] = {
    "linux_modern": TSClockProfile(
        name="Linux 5.x (1000Hz)",
        hz=1000,
        uptime_days_range=(7, 180),
        jitter_ticks=1,
    ),
    "linux_legacy": TSClockProfile(
        name="Linux 2.6/3.x (250Hz)",
        hz=250,
        uptime_days_range=(14, 365),
        jitter_ticks=0,
    ),
    "windows10": TSClockProfile(
        name="Windows 10/11 (100Hz)",
        hz=100,
        uptime_days_range=(1, 30),
        jitter_ticks=0,
    ),
    "macos": TSClockProfile(
        name="macOS 12+ (1000Hz)",
        hz=1000,
        uptime_days_range=(3, 90),
        jitter_ticks=1,
    ),
    "freebsd": TSClockProfile(
        name="FreeBSD 13+ (1000Hz)",
        hz=1000,
        uptime_days_range=(30, 730),
        jitter_ticks=1,
    ),
    "solaris": TSClockProfile(
        name="Solaris 11 (100Hz)",
        hz=100,
        uptime_days_range=(60, 1000),
        jitter_ticks=0,
    ),
    "cisco_ios": TSClockProfile(
        name="Cisco IOS (100Hz)",
        hz=100,
        uptime_days_range=(90, 2000),
        jitter_ticks=0,
        monotonic=False,
    ),
}


class ForgedTSClock:
    """
    A fabricated TCP timestamp clock for a specific target session.

    Each connection to a different target gets its own ForgedTSClock instance
    with an independently randomised epoch offset, defeating cross-session
    timestamp correlation even if multiple concurrent scans are in progress.
    """

    def __init__(self, profile: TSClockProfile, epoch_offset: Optional[int] = None):
        self._profile = profile
        self._start_real = time.time()
        self._lock = threading.Lock()
        self._last_tsval = 0

        # Compute epoch offset to represent a plausible fake boot time
        if epoch_offset is not None:
            self._epoch = epoch_offset
        else:
            min_days, max_days = profile.uptime_days_range
            uptime_secs = random.uniform(min_days * 86400, max_days * 86400)
            # TSval = ticks since boot; fake boot was uptime_secs ago
            self._epoch = int(uptime_secs * profile.hz) & 0xFFFFFFFF

    def current_tsval(self) -> int:
        """Generate the current forged TSval."""
        with self._lock:
            elapsed = time.time() - self._start_real
            ticks = int(elapsed * self._profile.hz)
            if self._profile.jitter_ticks:
                ticks += random.randint(0, self._profile.jitter_ticks)
            tsval = (self._epoch + ticks) & 0xFFFFFFFF

            # Enforce monotonicity
            if self._profile.monotonic and tsval <= self._last_tsval:
                tsval = (self._last_tsval + 1) & 0xFFFFFFFF
            self._last_tsval = tsval
            return tsval

    def reply_tsecr(self, received_tsval: int) -> int:
        """Echo received TSval back as TSecr (per RFC 7323)."""
        return received_tsval & 0xFFFFFFFF


class TCPTimestampForge:
    """
    Injects forged TCP timestamps into raw Scapy packets.

    Usage:
        forge = TCPTimestampForge("linux_modern")
        pkt = forge.inject(original_syn_packet)
        send(pkt)
    """

    def __init__(self, profile_name: str = "linux_modern",
                 per_target_clocks: bool = True):
        """
        Args:
            profile_name: OS profile key from TS_PROFILES
            per_target_clocks: If True, each target IP gets its own epoch offset.
                               Defeats cross-target timestamp correlation.
        """
        if profile_name not in TS_PROFILES:
            raise ValueError(f"Unknown profile '{profile_name}'. "
                             f"Valid: {list(TS_PROFILES.keys())}")
        self._profile = TS_PROFILES[profile_name]
        self._per_target = per_target_clocks
        self._clocks: Dict[str, ForgedTSClock] = {}
        self._lock = threading.Lock()

    def _get_clock(self, target_ip: str) -> ForgedTSClock:
        """Get or create a per-target forged clock."""
        if not self._per_target:
            # Single shared clock — simpler but correlatable
            if "global" not in self._clocks:
                with self._lock:
                    if "global" not in self._clocks:
                        self._clocks["global"] = ForgedTSClock(self._profile)
            return self._clocks["global"]

        if target_ip not in self._clocks:
            with self._lock:
                if target_ip not in self._clocks:
                    self._clocks[target_ip] = ForgedTSClock(self._profile)
        return self._clocks[target_ip]

    def inject(self, pkt, received_tsval: int = 0):
        """
        Inject forged TCP timestamps into a Scapy packet.

        Args:
            pkt: Scapy IP/TCP packet
            received_tsval: TSval from last received packet (for TSecr echo).
                            Use 0 for initial SYNs.

        Returns:
            Modified packet with forged Timestamp option.
        """
        if not HAS_SCAPY:
            return pkt
        if not pkt.haslayer(TCP):
            return pkt

        target_ip = pkt[IP].dst if pkt.haslayer(IP) else "global"
        clock = self._get_clock(target_ip)

        tsval = clock.current_tsval()
        tsecr = clock.reply_tsecr(received_tsval)

        # Rebuild TCP options replacing or inserting Timestamp
        old_opts = pkt[TCP].options or []
        new_opts = []
        ts_inserted = False

        for opt in old_opts:
            if isinstance(opt, tuple) and opt[0] == "Timestamp":
                new_opts.append(("Timestamp", (tsval, tsecr)))
                ts_inserted = True
            else:
                new_opts.append(opt)

        if not ts_inserted:
            # Insert Timestamp in the standard position (after MSS, NOP, WScale, NOP, NOP)
            new_opts.append(("Timestamp", (tsval, tsecr)))

        pkt[TCP].options = new_opts

        # Invalidate cached checksums so Scapy recalculates
        if pkt.haslayer(IP):
            del pkt[IP].chksum
        del pkt[TCP].chksum

        return pkt

    def forge_syn(self, target_ip: str, target_port: int,
                  src_port: int, seq: int, window: int = 65535):
        """
        Craft a complete forged SYN packet with OS-matching TCP timestamps.
        Combines OS-specific window size, TTL, and options ordering.
        """
        if not HAS_SCAPY:
            return None

        clock = self._get_clock(target_ip)
        tsval = clock.current_tsval()

        # OS-specific TCP options in correct ordering
        profile = self._profile
        if "windows" in profile.name.lower():
            # Windows: MSS, NOP, WScale, NOP, NOP, SAckOK
            tcp_opts = [
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 8),
                ("NOP", None),
                ("NOP", None),
                ("SAckOK", b""),
            ]
            ttl = 128
            win = 65535
        elif "macos" in profile.name.lower():
            # macOS: MSS, NOP, WScale, NOP, NOP, Timestamp, SAckOK, EOL
            tcp_opts = [
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 6),
                ("NOP", None),
                ("NOP", None),
                ("Timestamp", (tsval, 0)),
                ("SAckOK", b""),
                ("EOL", None),
            ]
            ttl = 64
            win = 65535
        elif "freebsd" in profile.name.lower():
            # FreeBSD: MSS, NOP, WScale, SAckOK, Timestamp
            tcp_opts = [
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 6),
                ("SAckOK", b""),
                ("Timestamp", (tsval, 0)),
            ]
            ttl = 64
            win = 65535
        else:
            # Linux: MSS, SAckOK, Timestamp, NOP, WScale
            tcp_opts = [
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (tsval, 0)),
                ("NOP", None),
                ("WScale", 7),
            ]
            ttl = 64
            win = 29200

        pkt = (
            IP(dst=target_ip, ttl=ttl) /
            TCP(
                sport=src_port,
                dport=target_port,
                flags="S",
                seq=seq,
                window=win,
                options=tcp_opts,
            )
        )
        return pkt

    def get_profile_info(self) -> dict:
        return {
            "profile": self._profile.name,
            "hz": self._profile.hz,
            "ms_per_tick": round(1000 / self._profile.hz, 2),
            "active_clocks": len(self._clocks),
            "per_target_isolation": self._per_target,
        }


# ─── Convenience functions ──────────────────────────────────────────────────

_default_forger: Optional[TCPTimestampForge] = None

def get_ts_forger(profile: str = "linux_modern") -> TCPTimestampForge:
    """Get or create the module-level default forger."""
    global _default_forger
    if _default_forger is None:
        _default_forger = TCPTimestampForge(profile)
    return _default_forger

def forge_packet_timestamps(pkt, profile: str = "linux_modern",
                             received_tsval: int = 0):
    """One-shot: inject forged timestamps into any TCP packet."""
    return get_ts_forger(profile).inject(pkt, received_tsval)
