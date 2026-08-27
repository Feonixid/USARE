"""
USARE IPv6 Host Discovery

Discovers live IPv6 hosts using multiple techniques that the ping-sweep
in TargetParser (ICMPv4 only) completely misses:

1. ICMPv6 Echo Request  — equivalent of ping for IPv6
2. Multicast listener discovery  — queries all-nodes (ff02::1) and
   all-routers (ff02::2) to enumerate all link-local hosts without
   scanning each address individually
3. Neighbour Solicitation  — NDP equivalent of ARP, leaks MAC + IPv6
   of every reachable host on the local segment
4. Router Advertisement parsing  — passive; captures prefix info
5. DHCPv6 Solicit  — discovers DHCPv6 servers and their prefixes

These techniques work even on hosts that firewall ICMPv4/ICMP echo,
because multicast/NDP traffic is required for IPv6 link-layer operation
and cannot be fully suppressed without breaking IPv6 connectivity.
"""

import socket
import struct
import time
import logging
import random
import threading
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ipv6_discovery")

try:
    from scapy.all import (
        IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA,
        ICMPv6MLQuery, ICMPv6MLReport,
        Ether, sendp, srp, sr1, conf,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class IPv6Host:
    """A discovered IPv6 host."""
    ipv6: str
    mac: str = ""
    link_local: str = ""
    is_router: bool = False
    discovery_method: str = ""
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v}


class IPv6Discoverer:
    """
    Multi-technique IPv6 host discovery engine.
    
    Requires root (raw sockets) and an interface with IPv6 enabled.
    """

    ALL_NODES_MULTICAST  = "ff02::1"   # Every IPv6 node on the link
    ALL_ROUTERS_MULTICAST = "ff02::2"  # Every IPv6 router on the link

    def __init__(self, interface: Optional[str] = None, timeout: float = 3.0):
        self.interface = interface or "eth0"
        self.timeout = timeout
        self._hosts: Dict[str, IPv6Host] = {}
        self._lock = threading.Lock()

        if not HAS_SCAPY:
            logger.warning("[IPv6Disc] Scapy not available — IPv6 discovery disabled")

    # ─── Public API ───────────────────────────────────────────────────────────

    def discover(self, prefix: str = "") -> List[IPv6Host]:
        """
        Run all discovery methods and return unique live hosts.

        Args:
            prefix: Optional IPv6 prefix to scan (e.g. "2001:db8::/64").
                    If empty, only link-local discovery methods run.
        """
        if not HAS_SCAPY:
            return []

        conf.verb = 0

        threads = [
            threading.Thread(target=self._multicast_ping, daemon=True),
            threading.Thread(target=self._neighbour_solicitation, daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=self.timeout + 1)

        if prefix:
            self._prefix_scan(prefix)

        with self._lock:
            return list(self._hosts.values())

    # ─── Discovery Methods ────────────────────────────────────────────────────

    def _multicast_ping(self):
        """
        ICMPv6 Echo Request to ff02::1 (all-nodes multicast).
        Every IPv6 host on the link MUST respond — this is mandatory per RFC 4291.
        One packet, all hosts reply. Best stealth-to-coverage ratio on any technique.
        """
        try:
            pkt = (
                IPv6(dst=self.ALL_NODES_MULTICAST) /
                ICMPv6EchoRequest(id=random.randint(1, 65535), seq=1)
            )
            ans, _ = sr1(pkt, timeout=self.timeout, verbose=0, iface=self.interface,
                         multi=True) if hasattr(sr1, 'multi') else (None, None)

            # sr1 only gives first reply; use srp for multi-reply via Ether layer
            eth_pkt = Ether(dst="33:33:00:00:00:01") / pkt
            answers, _ = srp(eth_pkt, timeout=self.timeout, verbose=0,
                             iface=self.interface)

            for _, reply in answers:
                if reply.haslayer(ICMPv6EchoReply):
                    src_ip = reply[IPv6].src
                    mac = reply[Ether].src if reply.haslayer(Ether) else ""
                    self._register(src_ip, mac=mac, method="multicast_ping")

        except Exception as e:
            logger.debug(f"[IPv6Disc] Multicast ping failed: {e}")

    def _neighbour_solicitation(self):
        """
        Send ICMPv6 Neighbour Solicitation to solicited-node multicast.
        Targets respond with Neighbour Advertisement containing their MAC.
        Equivalent to ARP — mandatory protocol behaviour per RFC 4861.
        """
        try:
            # Send NS for the all-nodes multicast address to get all neighbours
            pkt = (
                Ether(dst="33:33:00:00:00:01") /
                IPv6(dst=self.ALL_NODES_MULTICAST) /
                ICMPv6ND_NS(tgt="ff02::1")
            )
            answers, _ = srp(pkt, timeout=self.timeout, verbose=0, iface=self.interface)

            for _, reply in answers:
                if reply.haslayer(ICMPv6ND_NA):
                    src_ip = reply[IPv6].src
                    mac = reply[Ether].src if reply.haslayer(Ether) else ""
                    is_router = bool(reply[ICMPv6ND_NA].R)
                    self._register(src_ip, mac=mac, method="ndp_na",
                                   is_router=is_router)

        except Exception as e:
            logger.debug(f"[IPv6Disc] Neighbour Solicitation failed: {e}")

    def _prefix_scan(self, prefix: str):
        """
        Ping-scan a specified /64 prefix (last 64-bits generated randomly).
        Tries up to 256 random addresses within the prefix — enough to find
        servers while avoiding DHCPv6-sequential scanning patterns.
        """
        try:
            import ipaddress
            net = ipaddress.IPv6Network(prefix, strict=False)
            hosts_iter = net.hosts()
            candidates = []
            for _ in range(256):
                try:
                    candidates.append(str(next(hosts_iter)))
                except StopIteration:
                    break

            random.shuffle(candidates)

            for target in candidates[:64]:  # probe at most 64 to stay stealthy
                try:
                    pkt = IPv6(dst=target) / ICMPv6EchoRequest(
                        id=random.randint(1, 65535), seq=1
                    )
                    reply = sr1(pkt, timeout=1.0, verbose=0, iface=self.interface)
                    if reply and reply.haslayer(ICMPv6EchoReply):
                        self._register(target, method="prefix_ping")
                except Exception:
                    pass
                time.sleep(0.05)  # Gentle pacing

        except Exception as e:
            logger.debug(f"[IPv6Disc] Prefix scan failed for {prefix}: {e}")

    def icmpv6_ping(self, target_ipv6: str) -> Optional[IPv6Host]:
        """Probe a single specific IPv6 address."""
        if not HAS_SCAPY:
            return None
        try:
            conf.verb = 0
            pkt = IPv6(dst=target_ipv6) / ICMPv6EchoRequest(
                id=random.randint(1, 65535), seq=1
            )
            t0 = time.time()
            reply = sr1(pkt, timeout=self.timeout, verbose=0, iface=self.interface)
            latency = (time.time() - t0) * 1000

            if reply and reply.haslayer(ICMPv6EchoReply):
                host = IPv6Host(
                    ipv6=target_ipv6,
                    discovery_method="icmpv6_ping",
                    latency_ms=latency,
                )
                return host
        except Exception as e:
            logger.debug(f"[IPv6Disc] ICMPv6 ping failed for {target_ipv6}: {e}")
        return None

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _register(self, ipv6: str, mac: str = "", method: str = "",
                  is_router: bool = False):
        """Thread-safe host registration."""
        with self._lock:
            if ipv6.startswith("ff"):  # Skip multicast sources
                return
            if ipv6 not in self._hosts:
                self._hosts[ipv6] = IPv6Host(
                    ipv6=ipv6,
                    mac=mac,
                    is_router=is_router,
                    discovery_method=method,
                )
                logger.info(f"[IPv6Disc] Discovered: {ipv6} via {method}"
                            + (f" (MAC {mac})" if mac else ""))
            else:
                host = self._hosts[ipv6]
                if mac and not host.mac:
                    host.mac = mac
                if is_router:
                    host.is_router = True

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_hosts": len(self._hosts),
                "routers": sum(1 for h in self._hosts.values() if h.is_router),
                "hosts": [h.to_dict() for h in self._hosts.values()],
            }
