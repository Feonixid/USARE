"""
USARE IGMP Multicast Host Enumeration

IGMP (Internet Group Management Protocol) is mandatory for IPv4 multicast.
Every IPv4 host MUST respond to IGMP Membership Queries sent to multicast
group addresses, because participation in multicast groups is compulsory for
basic network operation (all-hosts group 224.0.0.1).

Why this is a superior discovery technique:
  - ZERO unicast probes sent — all probes go to well-known multicast addresses
  - IDS systems that only monitor unicast traffic are completely blind
  - No TCP connections, no UDP port probes, no ARP entries left behind
  - Every RFC-compliant IPv4 host must respond — IoT, cameras, printers,
    routers, switches, servers all respond identically
  - Works on subnets where ICMP echo is firewalled but multicast is not
    (very common in enterprise networks that block ping but not IGMP)

Discovered hosts are returned with:
  - IP address
  - MAC address (from Ethernet layer)
  - Multicast groups they have joined (leaked via Membership Reports)
  - OS hints from multicast group membership patterns:
      224.0.0.251     → mDNS (Apple/Linux)
      224.0.0.252     → LLMNR (Windows)
      239.255.255.250 → SSDP/UPnP (IoT, Windows, NAS)
      224.0.1.22      → SLP (enterprise service location)
      224.0.0.9       → RIPv2 (router)
      224.0.0.5/6     → OSPF (router)
      224.0.0.13      → PIM (multicast router)

Requires: root privileges (raw Ethernet sockets via Scapy)
"""

import time
import random
import socket
import logging
import threading
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger("usare.igmp_enum")

try:
    from scapy.all import (
        Ether, IP, IGMP, IGMPv3, IGMPv3mr, IGMPv3gr,
        srp, sendp, sniff, conf,
    )
    HAS_SCAPY = True
except ImportError:
    try:
        from scapy.all import Ether, IP, IGMP, srp, sendp, sniff, conf
        IGMPv3 = None
        HAS_SCAPY = True
    except ImportError:
        HAS_SCAPY = False


# ─── Known Multicast Group → OS/Service Fingerprint ─────────────────────────

MULTICAST_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "224.0.0.1":   {"service": "all-hosts",       "os_hint": "any",         "role": "host"},
    "224.0.0.2":   {"service": "all-routers",     "os_hint": "router",      "role": "router"},
    "224.0.0.5":   {"service": "ospf-hello",      "os_hint": "router",      "role": "router"},
    "224.0.0.6":   {"service": "ospf-dr",         "os_hint": "router",      "role": "router"},
    "224.0.0.9":   {"service": "rip-v2",          "os_hint": "router",      "role": "router"},
    "224.0.0.10":  {"service": "eigrp",           "os_hint": "cisco",       "role": "router"},
    "224.0.0.13":  {"service": "pim",             "os_hint": "router",      "role": "mcast-router"},
    "224.0.0.18":  {"service": "vrrp",            "os_hint": "router",      "role": "gateway"},
    "224.0.0.22":  {"service": "igmp-v3-report",  "os_hint": "any",         "role": "host"},
    "224.0.0.102": {"service": "hsrp-v2",         "os_hint": "cisco",       "role": "gateway"},
    "224.0.0.251": {"service": "mdns",            "os_hint": "apple/linux", "role": "workstation"},
    "224.0.0.252": {"service": "llmnr",           "os_hint": "windows",     "role": "workstation"},
    "224.0.1.22":  {"service": "slp",             "os_hint": "enterprise",  "role": "server"},
    "224.0.1.24":  {"service": "ntp-multicast",   "os_hint": "any",         "role": "ntp"},
    "239.255.255.250": {"service": "ssdp-upnp",   "os_hint": "iot/windows", "role": "iot"},
    "239.192.152.143": {"service": "crestron",    "os_hint": "av-device",   "role": "iot"},
}


@dataclass
class IGMPHost:
    """A host discovered via IGMP enumeration."""
    ip: str
    mac: str
    groups_joined: List[str] = field(default_factory=list)
    os_hints: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    roles: Set[str] = field(default_factory=set)
    is_router: bool = False
    first_seen: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "groups_joined": self.groups_joined,
            "os_hints": list(set(self.os_hints)),
            "services": self.services,
            "roles": sorted(self.roles),
            "is_router": self.is_router,
        }


class IGMPEnumerator:
    """
    Discovers live IPv4 hosts using IGMP membership queries.

    Completely passive from an IDS perspective — all frames use
    multicast Ethernet addresses and multicast IP destinations.
    No unicast traffic is generated during the query phase.
    """

    # Multicast groups to query
    ALL_HOSTS_GROUP   = "224.0.0.1"    # All hosts — mandatory reply
    ALL_ROUTERS_GROUP = "224.0.0.2"    # All routers
    ALL_IGMP_GROUP    = "224.0.0.22"   # IGMPv3 reports land here

    # IGMPv1/v2 general query — smallest possible triggering packet
    # Type 0x11 = Membership Query, code 0x64 = max response time 10s
    IGMP_QUERY_TYPE = 0x11

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: float = 5.0,
        igmp_version: int = 2,
    ):
        """
        Args:
            interface: Network interface (e.g. "eth0").
            timeout: Seconds to listen for responses after sending query.
            igmp_version: IGMP version to use for queries (1, 2, or 3).
        """
        if not HAS_SCAPY:
            raise RuntimeError("Scapy is required for IGMP enumeration")
        self.interface = interface or "eth0"
        self.timeout = timeout
        self.igmp_version = igmp_version
        self._hosts: Dict[str, IGMPHost] = {}
        self._lock = threading.Lock()
        conf.verb = 0

    # ─── Public API ──────────────────────────────────────────────────────────

    def enumerate(self) -> List[IGMPHost]:
        """
        Send IGMP membership queries and collect all responding hosts.

        Returns the list of discovered hosts sorted by IP address.
        """
        logger.info(f"[IGMP] Sending IGMPv{self.igmp_version} General Query on {self.interface}")

        # Send the general membership query in a background thread so we
        # can start sniffing before the responses arrive
        send_thread = threading.Thread(
            target=self._send_general_query, daemon=True
        )
        send_thread.start()

        # Sniff responses — capture IGMP Membership Reports from all hosts
        try:
            pkts = sniff(
                iface=self.interface,
                filter="igmp",
                timeout=self.timeout,
                store=True,
            )
            for pkt in pkts:
                self._process_packet(pkt)
        except Exception as e:
            logger.warning(f"[IGMP] Sniff error: {e}")

        send_thread.join(timeout=1.0)

        # Also send targeted queries to known multicast groups
        self._query_specific_groups()

        with self._lock:
            hosts = sorted(self._hosts.values(),
                           key=lambda h: tuple(int(x) for x in h.ip.split('.')))
        return hosts

    def passive_listen(self, duration: float = 30.0) -> List[IGMPHost]:
        """
        Purely passive — listen for spontaneous IGMP reports without sending
        any queries. Completely undetectable. Effective on busy networks
        where hosts regularly send unsolicited reports.

        Args:
            duration: How many seconds to listen.
        """
        logger.info(f"[IGMP] Passive IGMP listener on {self.interface} for {duration:.0f}s")
        try:
            pkts = sniff(
                iface=self.interface,
                filter="igmp",
                timeout=duration,
                store=True,
            )
            for pkt in pkts:
                self._process_packet(pkt)
        except Exception as e:
            logger.warning(f"[IGMP] Passive listen error: {e}")

        with self._lock:
            return list(self._hosts.values())

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            routers = [h for h in self._hosts.values() if h.is_router]
            workstations = [h for h in self._hosts.values()
                            if "workstation" in h.roles]
            iot = [h for h in self._hosts.values() if "iot" in h.roles]
            return {
                "total_hosts": len(self._hosts),
                "routers": len(routers),
                "workstations": len(workstations),
                "iot_devices": len(iot),
                "hosts": [h.to_dict() for h in self._hosts.values()],
                "groups_observed": self._all_groups_seen(),
            }

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _send_general_query(self):
        """Send IGMPv2 General Query to 224.0.0.1."""
        try:
            # IGMP General Query:
            #   dst = 224.0.0.1 (all-hosts multicast)
            #   IGMP type = 0x11 (Query)
            #   gaddr = 0.0.0.0 (general query, not group-specific)
            #   max_resp_time = 100 (10 seconds)
            pkt = (
                Ether(dst="01:00:5e:00:00:01") /          # Multicast MAC for 224.0.0.1
                IP(dst=self.ALL_HOSTS_GROUP, ttl=1,
                   options=b"\x94\x04\x00\x00") /          # Router Alert option
                IGMP(type=0x11, gaddr="0.0.0.0", mrcode=100)
            )
            sendp(pkt, iface=self.interface, verbose=0)
            logger.debug("[IGMP] General query sent")
            time.sleep(0.5)
        except Exception as e:
            logger.debug(f"[IGMP] Query send failed: {e}")

    def _query_specific_groups(self):
        """Send group-specific queries for high-value multicast groups."""
        interesting_groups = [
            "239.255.255.250",  # SSDP/UPnP
            "224.0.0.251",      # mDNS
            "224.0.0.252",      # LLMNR
        ]
        for group in interesting_groups:
            try:
                mac_suffix = ".".join(
                    f"{int(x):02x}" for x in group.split(".")[-3:]
                )
                dst_mac = f"01:00:5e:{mac_suffix}"
                pkt = (
                    Ether(dst=dst_mac) /
                    IP(dst=group, ttl=1) /
                    IGMP(type=0x11, gaddr=group, mrcode=20)
                )
                sendp(pkt, iface=self.interface, verbose=0)
                time.sleep(0.1)
            except Exception as e:
                logger.debug(f"[IGMP] Group query for {group} failed: {e}")

    def _process_packet(self, pkt):
        """Parse an IGMP packet and register the responding host."""
        try:
            if not pkt.haslayer(IP):
                return
            if not pkt.haslayer(IGMP):
                return

            src_ip = pkt[IP].src
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""

            # Skip our own transmissions and multicast sources
            if src_ip.startswith("224.") or src_ip.startswith("239."):
                return

            igmp_type = pkt[IGMP].type

            # Type 0x12 = IGMPv1 Membership Report
            # Type 0x16 = IGMPv2 Membership Report
            # Type 0x22 = IGMPv3 Membership Report
            if igmp_type not in (0x12, 0x16, 0x22):
                return

            # Which group is this host reporting membership in?
            group = pkt[IGMP].gaddr if hasattr(pkt[IGMP], 'gaddr') else "0.0.0.0"

            with self._lock:
                if src_ip not in self._hosts:
                    self._hosts[src_ip] = IGMPHost(ip=src_ip, mac=src_mac)
                    logger.info(f"[IGMP] Discovered: {src_ip} (MAC: {src_mac})")

                host = self._hosts[src_ip]
                if src_mac and not host.mac:
                    host.mac = src_mac

                if group and group != "0.0.0.0" and group not in host.groups_joined:
                    host.groups_joined.append(group)
                    self._apply_fingerprint(host, group)

        except Exception as e:
            logger.debug(f"[IGMP] Packet processing error: {e}")

    def _apply_fingerprint(self, host: IGMPHost, group: str):
        """Apply OS and service fingerprints based on multicast group membership."""
        fp = MULTICAST_FINGERPRINTS.get(group)
        if not fp:
            # Generic 239.x.x.x is organisation-local scope multicast (common for enterprise apps)
            if group.startswith("239."):
                host.services.append(f"enterprise-app ({group})")
            return

        if fp["service"] not in host.services:
            host.services.append(fp["service"])

        os_hint = fp.get("os_hint", "")
        if os_hint and os_hint != "any" and os_hint not in host.os_hints:
            host.os_hints.append(os_hint)

        role = fp.get("role", "")
        if role:
            host.roles.add(role)

        if role == "router" or role == "mcast-router" or role == "gateway":
            host.is_router = True

    def _all_groups_seen(self) -> List[str]:
        """Return all multicast groups seen across all hosts."""
        groups: Set[str] = set()
        for host in self._hosts.values():
            groups.update(host.groups_joined)
        return sorted(groups)
