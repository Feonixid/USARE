"""
USARE eBPF Loader v3.0

Two-program architecture to cover both directions:

  bpf_filter.c  (XDP ingress) — drop incoming RSTs from the target
                                  that would confuse our scanner state
  bpf_egress.c  (TC egress)   — drop OUTGOING RSTs from our kernel
                                  that snitch on raw-socket scanning

Why two programs:
  XDP is an INGRESS hook — it catches packets arriving at your NIC.
  Outgoing RSTs (the snitching ones) travel on the EGRESS path.
  TC (Traffic Control) BPF with clsact qdisc covers egress.

Fallback chain:
  1. TC egress BPF  (best — kernel-level, invisible to iptables-list)
  2. iptables OUTPUT rule (RSTBlocker) — reliable but visible to iptables -L
  3. Nothing — scan will work but target may see RSTs

Requires: clang, iproute2, tc, Linux kernel >= 4.19.
Root / CAP_NET_ADMIN required.
"""

import os
import re
import json
import struct
import socket
import subprocess
import logging
import signal
import sys
import time
from typing import Optional, Dict, List
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ebpf")

MAX_TARGETS        = 64
DROP_MODE_TARGETED = 0
DROP_MODE_ALL_RST  = 1

STAT_RST_SEEN = 0
STAT_DROPPED  = 1
STAT_PASSED   = 2


@dataclass
class EBPFStats:
    # Ingress (XDP) counters
    xdp_rst_seen: int = 0
    xdp_dropped:  int = 0
    xdp_passed:   int = 0
    # Egress (TC) counters
    tc_rst_seen:  int = 0
    tc_dropped:   int = 0
    tc_passed:    int = 0
    attach_time:  float = 0.0
    last_read:    float = 0.0
    drop_mode:    int = DROP_MODE_TARGETED
    tc_active:    bool = False
    xdp_active:   bool = False
    iptables_fallback: bool = False


class EBPFLoader:
    """
    Dual-hook eBPF loader: XDP ingress + TC egress RST suppression.

    The TC egress program is the one that actually stops your machine
    from snitching — it drops outgoing RSTs before they leave the NIC.

    The XDP ingress program prevents incoming RSTs from confusing the
    scanner's state machine (secondary benefit).

    Falls back to iptables if TC BPF fails to load.
    """

    def __init__(
        self,
        interface: str = "eth0",
        base_dir: Optional[str] = None,
    ):
        self.interface = interface
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._base = base_dir

        # Source / object paths
        self._xdp_src = os.path.join(base_dir, "core", "bpf_filter.c")
        self._xdp_obj = os.path.join(base_dir, "core", "bpf_filter.o")
        self._tc_src  = os.path.join(base_dir, "core", "bpf_egress.c")
        self._tc_obj  = os.path.join(base_dir, "core", "bpf_egress.o")

        self.stats = EBPFStats()
        self._targets:  List[str]       = []
        self._map_ids:  Dict[str, int]  = {}
        self._cleanup_handlers: list    = []
        self._iptables_rules: List[str] = []   # rules we added, for cleanup

    # ── compilation ───────────────────────────────────────────────────────

    def _compile(self, src: str, obj: str) -> bool:
        if not os.path.exists(src):
            logger.error("[eBPF] Source missing: %s", src)
            return False
        common = [
            "clang", "-O2", "-target", "bpf",
            "-c", src, "-o", obj,
            "-I/usr/include",
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include/aarch64-linux-gnu",  # ARM support
        ]
        res = subprocess.run(common, capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(obj):
            logger.info("[eBPF] Compiled %s → %s", os.path.basename(src), os.path.basename(obj))
            return True
        logger.warning("[eBPF] Compile failed: %s", res.stderr[:300])
        return False

    # ── XDP ingress ───────────────────────────────────────────────────────

    def _attach_xdp(self) -> bool:
        if not os.path.exists(self._xdp_obj):
            if not self._compile(self._xdp_src, self._xdp_obj):
                return False
        # Remove existing XDP program (idempotent)
        subprocess.run(
            ["ip", "link", "set", "dev", self.interface, "xdp", "off"],
            stderr=subprocess.DEVNULL,
        )
        res = subprocess.run(
            ["ip", "link", "set", "dev", self.interface,
             "xdp", "obj", self._xdp_obj, "sec", "xdp"],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            logger.warning("[eBPF] XDP attach failed: %s", res.stderr.strip())
            return False
        self.stats.xdp_active = True
        logger.info("[eBPF] XDP ingress filter attached to %s", self.interface)
        return True

    def _detach_xdp(self):
        subprocess.run(
            ["ip", "link", "set", "dev", self.interface, "xdp", "off"],
            stderr=subprocess.DEVNULL,
        )
        self.stats.xdp_active = False

    # ── TC egress ─────────────────────────────────────────────────────────

    def _attach_tc_egress(self) -> bool:
        """
        Attach TC BPF egress program.
        This is the one that actually stops outgoing RSTs from snitching.
        """
        if not os.path.exists(self._tc_obj):
            if not self._compile(self._tc_src, self._tc_obj):
                return False

        # Set up clsact qdisc (safe to run if already exists)
        subprocess.run(
            ["tc", "qdisc", "add", "dev", self.interface, "clsact"],
            capture_output=True,   # ignore "already exists" error
        )

        # Remove existing egress BPF filter
        subprocess.run(
            ["tc", "filter", "del", "dev", self.interface, "egress"],
            stderr=subprocess.DEVNULL,
        )

        # Attach the egress filter
        res = subprocess.run(
            [
                "tc", "filter", "add", "dev", self.interface,
                "egress", "bpf", "da",
                "obj", self._tc_obj, "sec", "tc_egress",
            ],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            logger.warning("[eBPF] TC egress attach failed: %s", res.stderr.strip())
            return False

        self.stats.tc_active = True
        logger.info("[eBPF] TC egress RST filter attached to %s", self.interface)
        logger.info("[eBPF] Outgoing RSTs to scan targets will be silently dropped.")
        return True

    def _detach_tc_egress(self):
        subprocess.run(
            ["tc", "filter", "del", "dev", self.interface, "egress"],
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["tc", "qdisc", "del", "dev", self.interface, "clsact"],
            stderr=subprocess.DEVNULL,
        )
        self.stats.tc_active = False

    # ── iptables fallback ─────────────────────────────────────────────────

    def _add_iptables_rst_block(self, target_ip: str) -> bool:
        """
        Fallback: iptables OUTPUT rule.
        Less elegant than TC BPF but works on any Linux system without
        clang or TC BPF support.
        """
        if not sys.platform.startswith("linux"):
            return False
        rule = [
            "iptables", "-A", "OUTPUT",
            "-p", "tcp",
            "--tcp-flags", "RST", "RST",
            "-d", target_ip,
            "-j", "DROP",
        ]
        try:
            subprocess.run(rule, check=True, capture_output=True)
            self._iptables_rules.append(target_ip)
            self.stats.iptables_fallback = True
            logger.info("[eBPF] iptables fallback: blocking outgoing RST to %s", target_ip)
            return True
        except Exception as e:
            logger.warning("[eBPF] iptables fallback failed: %s", e)
            return False

    def _remove_iptables_rst_block(self, target_ip: str):
        rule = [
            "iptables", "-D", "OUTPUT",
            "-p", "tcp",
            "--tcp-flags", "RST", "RST",
            "-d", target_ip,
            "-j", "DROP",
        ]
        try:
            subprocess.run(rule, capture_output=True)
        except Exception:
            pass

    # ── main attach/detach ────────────────────────────────────────────────

    def attach(self) -> bool:
        """
        Attach both XDP (ingress) and TC BPF (egress).
        Falls back to iptables for egress if TC BPF is unavailable.
        Returns True if at least egress suppression is active.
        """
        self.stats.attach_time = time.time()

        # XDP ingress (nice to have — doesn't stop snitching on its own)
        self._attach_xdp()

        # TC egress — the critical one for RST suppression
        tc_ok = self._attach_tc_egress()

        if not tc_ok:
            logger.warning(
                "[eBPF] TC egress BPF unavailable — falling back to iptables.\n"
                "       Install: apt install clang iproute2 (kernel >= 4.19 required)"
            )
            # iptables fallback will be added per-target when add_target() is called

        self._discover_map_ids()
        self.set_drop_mode(DROP_MODE_TARGETED)
        self._setup_cleanup_handlers()

        active = self.stats.xdp_active or self.stats.tc_active
        return active

    def detach(self) -> bool:
        self._detach_xdp()
        self._detach_tc_egress()
        # Clean up iptables rules
        for ip in list(self._iptables_rules):
            self._remove_iptables_rst_block(ip)
        self._iptables_rules.clear()
        self._targets.clear()
        self._map_ids.clear()
        self.stats.tc_active  = False
        self.stats.xdp_active = False
        logger.info("[eBPF] All filters detached from %s", self.interface)
        return True

    # ── BPF map management ────────────────────────────────────────────────

    def _discover_map_ids(self):
        try:
            res = subprocess.run(
                ["bpftool", "map", "show", "--json"],
                capture_output=True, text=True, timeout=5,
            )
            if res.returncode != 0:
                return
            maps = json.loads(res.stdout)
            wanted = {
                "target_ips", "control_map", "stats_map",     # XDP maps
                "eg_target_ips", "eg_control_map", "eg_stats_map",  # TC maps
            }
            for m in maps:
                name = m.get("name", "")
                if name in wanted:
                    self._map_ids[name] = m.get("id", -1)
                    logger.debug("[eBPF] map '%s' → kernel ID %d", name, self._map_ids[name])
        except Exception as e:
            logger.debug("[eBPF] bpftool map discovery failed: %s", e)

    def _map_update(self, map_name: str, key_bytes: bytes, val_bytes: bytes) -> bool:
        mid = self._map_ids.get(map_name)
        if mid is None:
            return False
        try:
            key_args = [str(b) for b in key_bytes]
            val_args = [str(b) for b in val_bytes]
            res = subprocess.run(
                ["bpftool", "map", "update", "id", str(mid),
                 "key", *key_args, "value", *val_args],
                capture_output=True, text=True, timeout=5,
            )
            return res.returncode == 0
        except Exception as e:
            logger.debug("[eBPF] map update failed: %s", e)
            return False

    def _read_stat(self, map_name: str, idx: int) -> int:
        mid = self._map_ids.get(map_name)
        if mid is None:
            return 0
        try:
            key_args = [str(b) for b in struct.pack("<I", idx)]
            res = subprocess.run(
                ["bpftool", "map", "lookup", "id", str(mid), "key", *key_args],
                capture_output=True, text=True, timeout=5,
            )
            if res.returncode != 0:
                return 0
            m = re.search(r"value:\s*((?:[0-9a-f]{2}\s*)+)", res.stdout, re.IGNORECASE)
            if not m:
                return 0
            raw = bytes(int(x, 16) for x in m.group(1).split())
            return struct.unpack("<Q", raw[:8])[0] if len(raw) >= 8 else 0
        except Exception:
            return 0

    # ── public API ────────────────────────────────────────────────────────

    def add_target(self, ip: str) -> bool:
        """
        Register a target IP.
        RSTs destined for this IP will be suppressed at TC egress.
        If TC BPF is not active, falls back to iptables.
        """
        if ip in self._targets:
            return True
        if len(self._targets) >= MAX_TARGETS:
            logger.warning("[eBPF] Target list full (%d)", MAX_TARGETS)
            return False

        slot = len(self._targets)
        try:
            ip_int = struct.unpack("I", socket.inet_aton(ip))[0]
        except Exception:
            return False

        key = struct.pack("<I", slot)
        val = struct.pack("I", ip_int)

        # Update both XDP and TC maps
        self._map_update("target_ips",    key, val)
        self._map_update("eg_target_ips", key, val)

        self._targets.append(ip)

        # iptables fallback if TC BPF not loaded
        if not self.stats.tc_active:
            self._add_iptables_rst_block(ip)

        logger.info("[eBPF] Target registered: %s (slot %d)", ip, slot)
        return True

    def remove_target(self, ip: str) -> bool:
        if ip not in self._targets:
            return False
        slot = self._targets.index(ip)
        key  = struct.pack("<I", slot)
        zero = struct.pack("I", 0)
        self._map_update("target_ips",    key, zero)
        self._map_update("eg_target_ips", key, zero)
        self._targets.remove(ip)
        self._remove_iptables_rst_block(ip)
        logger.info("[eBPF] Target removed: %s", ip)
        return True

    def set_drop_mode(self, mode: int) -> bool:
        key = struct.pack("<I", 0)
        val = struct.pack("<I", mode)
        self._map_update("control_map",    key, val)
        self._map_update("eg_control_map", key, val)
        self.stats.drop_mode = mode
        logger.info("[eBPF] Drop mode: %s", "targeted" if mode == 0 else "all-RST")
        return True

    def refresh_stats(self) -> EBPFStats:
        self.stats.xdp_rst_seen = self._read_stat("stats_map",    STAT_RST_SEEN)
        self.stats.xdp_dropped  = self._read_stat("stats_map",    STAT_DROPPED)
        self.stats.xdp_passed   = self._read_stat("stats_map",    STAT_PASSED)
        self.stats.tc_rst_seen  = self._read_stat("eg_stats_map", STAT_RST_SEEN)
        self.stats.tc_dropped   = self._read_stat("eg_stats_map", STAT_DROPPED)
        self.stats.tc_passed    = self._read_stat("eg_stats_map", STAT_PASSED)
        self.stats.last_read    = time.time()
        return self.stats

    def get_stats(self) -> EBPFStats:
        if self._map_ids:
            return self.refresh_stats()
        return self.stats

    def is_attached(self) -> bool:
        return self.stats.xdp_active or self.stats.tc_active or self.stats.iptables_fallback

    def status_line(self) -> str:
        s = self.stats
        parts = []
        if s.tc_active:
            parts.append(f"TC-egress(drops={s.tc_dropped})")
        if s.xdp_active:
            parts.append(f"XDP-ingress(drops={s.xdp_dropped})")
        if s.iptables_fallback:
            parts.append("iptables-fallback")
        if not parts:
            parts.append("NOT ACTIVE — outgoing RSTs unblocked")
        targets = ", ".join(self._targets) if self._targets else "none"
        return f"eBPF [{' + '.join(parts)}] | targets=[{targets}]"

    # ── signal handlers ───────────────────────────────────────────────────

    def _setup_cleanup_handlers(self):
        def handler(signum, frame):
            logger.info("[eBPF] Signal %d — detaching", signum)
            self.detach()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                orig = signal.signal(sig, handler)
                self._cleanup_handlers.append((sig, orig))
            except Exception:
                pass

    def __enter__(self):
        self.attach()
        return self

    def __exit__(self, *_):
        self.detach()
