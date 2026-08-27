"""
USARE Zero-Packet Passive Listener

Fully passive reconnaissance that never sends a single packet.
Listens for broadcast/multicast traffic on the local segment to infer:
- Open services from ARP broadcasts (host discovery)
- mDNS announcements (service discovery, hostnames)
- LLMNR queries (Windows name resolution → hostname + service leaks)
- NetBIOS Name Service announcements (workgroups, shares, hostnames)
- DHCP offers (subnet, gateway, DNS, lease info)
- SSDP/UPnP announcements (device types, services)
- CDP/LLDP frames (network infrastructure mapping)

Zero-footprint recon phase before any active scanning.
"""

import socket
import struct
import time
import threading
import logging
import platform
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("usare.passive_listener")

IS_WINDOWS = platform.system() == "Windows"

try:
    from scapy.all import sniff as scapy_sniff, ARP  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class PassiveHost:
    """A host discovered passively."""
    ip: str
    mac: str = ""
    hostname: str = ""
    os_hint: str = ""
    services: List[str] = field(default_factory=list)
    source: str = ""             # How it was discovered
    first_seen: float = 0.0
    last_seen: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os_hint": self.os_hint,
            "services": self.services,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
        }


class PassiveListener:
    """
    Zero-packet passive reconnaissance via network sniffing.
    Requires root/admin privileges for raw sockets.
    """

    def __init__(self, interface: Optional[str] = None, timeout: float = 120.0):
        self.interface = interface
        self.timeout = timeout
        self._hosts: Dict[str, PassiveHost] = {}
        self._lock = threading.Lock()
        self._running = False
        self._services_found: Dict[str, Set[str]] = defaultdict(set)  # ip → set of services

    def listen(self, duration: Optional[float] = None) -> Dict[str, PassiveHost]:
        """
        Listen passively for the given duration.
        Returns dict of IP → PassiveHost.
        """
        duration = duration or self.timeout
        self._running = True
        start = time.time()

        threads = [
            threading.Thread(target=self._listen_arp, args=(duration,), daemon=True),
            threading.Thread(target=self._listen_mdns, args=(duration,), daemon=True),
            threading.Thread(target=self._listen_netbios, args=(duration,), daemon=True),
            threading.Thread(target=self._listen_llmnr, args=(duration,), daemon=True),
            threading.Thread(target=self._listen_ssdp, args=(duration,), daemon=True),
            threading.Thread(target=self._listen_dhcp, args=(duration,), daemon=True),
        ]

        for t in threads:
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join(timeout=duration + 5)

        self._running = False
        return dict(self._hosts)

    def _register_host(self, ip: str, source: str, mac: str = "",
                       hostname: str = "", os_hint: str = "",
                       services: Optional[List[str]] = None,
                       **metadata: Any):
        """Thread-safe host registration."""
        with self._lock:
            now = time.time()
            if ip in self._hosts:
                host = self._hosts[ip]
                host.last_seen = now
                if mac and not host.mac:
                    host.mac = mac
                if hostname and not host.hostname:
                    host.hostname = hostname
                if os_hint and not host.os_hint:
                    host.os_hint = os_hint
                if services:
                    for svc in services:
                        if svc not in host.services:
                            host.services.append(svc)
                host.metadata.update(metadata)
            else:
                self._hosts[ip] = PassiveHost(
                    ip=ip, mac=mac, hostname=hostname, os_hint=os_hint,
                    services=services or [], source=source,
                    first_seen=now, last_seen=now, metadata=metadata,
                )

    def _listen_arp(self, duration: float):
        """Listen for ARP broadcasts (RFC 826). Platform-aware."""
        if IS_WINDOWS:
            self._listen_arp_scapy(duration)
        else:
            self._listen_arp_raw(duration)

    def _listen_arp_scapy(self, duration: float):
        """ARP listener via Scapy sniff() — works on Windows and Linux."""
        if not HAS_SCAPY:
            logger.debug("[Passive] ARP listener skipped: Scapy not available")
            return

        def arp_handler(pkt):
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if arp.op in (1, 2):  # who-has or is-at
                    self._register_host(
                        ip=arp.psrc, source="arp",
                        mac=arp.hwsrc,
                        arp_opcode="request" if arp.op == 1 else "reply"
                    )

        try:
            iface = self.interface if self.interface else None
            scapy_sniff(
                filter="arp", prn=arp_handler,
                timeout=duration, store=False,
                iface=iface,
            )
        except Exception as e:
            logger.debug(f"[Passive] ARP Scapy listener error: {e}")

    def _listen_arp_raw(self, duration: float):
        """ARP listener via raw socket (Linux only, AF_PACKET)."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0806))
            sock.settimeout(1.0)
            if self.interface:
                sock.bind((self.interface, 0))

            start = time.time()
            while self._running and time.time() - start < duration:
                try:
                    data, _ = sock.recvfrom(65535)
                    if len(data) < 42:
                        continue

                    arp_header = data[14:42]
                    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack(
                        "!HHBBH", arp_header[:8]
                    )

                    if opcode in (1, 2):
                        sender_mac = ":".join(f"{b:02x}" for b in arp_header[8:14])
                        sender_ip = socket.inet_ntoa(arp_header[14:18])

                        self._register_host(
                            ip=sender_ip, source="arp",
                            mac=sender_mac,
                            arp_opcode="request" if opcode == 1 else "reply"
                        )

                except socket.timeout:
                    continue
                except Exception:
                    continue

            sock.close()
        except PermissionError:
            logger.debug("[Passive] ARP listener requires root privileges")
        except Exception as e:
            logger.debug(f"[Passive] ARP listener error: {e}")

    def _listen_mdns(self, duration: float):
        """Listen for mDNS announcements (RFC 6762, port 5353)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            sock.bind(("", 5353))
            sock.settimeout(1.0)

            # Join mDNS multicast group
            mreq = struct.pack("4s4s",
                               socket.inet_aton("224.0.0.251"),
                               socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            start = time.time()
            while self._running and time.time() - start < duration:
                try:
                    data, addr = sock.recvfrom(4096)
                    src_ip = addr[0]

                    # Parse DNS response for service names
                    hostname, services, os_hint = self._parse_mdns(data)

                    self._register_host(
                        ip=src_ip, source="mdns",
                        hostname=hostname, os_hint=os_hint,
                        services=services,
                    )
                except socket.timeout:
                    continue
                except Exception:
                    continue

            sock.close()
        except Exception as e:
            logger.debug(f"[Passive] mDNS listener error: {e}")

    def _parse_mdns(self, data: bytes):
        """Extract hostname, services, and OS hints from mDNS packet."""
        hostname = ""
        services = []
        os_hint = ""

        try:
            if len(data) < 12:
                return hostname, services, os_hint

            # Parse DNS header
            an_count = struct.unpack("!H", data[6:8])[0]
            ar_count = struct.unpack("!H", data[10:12])[0]

            # Simple label extraction from the packet
            text = data[12:].decode("utf-8", errors="replace")

            # Common mDNS service types
            if "_http._tcp" in text:
                services.append("http")
            if "_https._tcp" in text:
                services.append("https")
            if "_ssh._tcp" in text:
                services.append("ssh")
            if "_smb._tcp" in text:
                services.append("smb")
            if "_ftp._tcp" in text:
                services.append("ftp")
            if "_printer._tcp" in text:
                services.append("printer")
            if "_ipp._tcp" in text:
                services.append("ipp")
            if "_airplay._tcp" in text:
                services.append("airplay")
                os_hint = "Apple/macOS"
            if "_raop._tcp" in text:
                services.append("airplay-audio")
                os_hint = "Apple/macOS"
            if "_googlecast._tcp" in text:
                services.append("chromecast")
            if "_companion-link._tcp" in text:
                os_hint = "Apple/macOS"

            # Try to extract hostname from first DNS name
            idx = 12
            labels = []
            while idx < len(data) and data[idx] != 0:
                label_len = data[idx]
                if label_len > 63 or idx + label_len + 1 > len(data):
                    break
                labels.append(data[idx + 1:idx + 1 + label_len].decode("utf-8", errors="replace"))
                idx += label_len + 1

            if labels:
                # Filter out service type labels
                name_parts = [l for l in labels if not l.startswith("_")
                              and l not in ("local", "tcp", "udp")]
                if name_parts:
                    hostname = name_parts[0]

        except Exception:
            pass

        return hostname, services, os_hint

    def _listen_netbios(self, duration: float):
        """Listen for NetBIOS Name Service broadcasts (port 137)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 137))
            sock.settimeout(1.0)

            start = time.time()
            while self._running and time.time() - start < duration:
                try:
                    data, addr = sock.recvfrom(1024)
                    src_ip = addr[0]

                    # Parse NetBIOS name from response
                    if len(data) > 56:
                        # Decode NetBIOS name (half-ASCII encoded)
                        raw_name = data[13:45]
                        try:
                            name = ""
                            for i in range(0, 32, 2):
                                if i + 1 < len(raw_name):
                                    ch = ((raw_name[i] - 0x41) << 4) | (raw_name[i + 1] - 0x41)
                                    if 32 <= ch < 127:
                                        name += chr(ch)
                            name = name.strip()
                            if name:
                                self._register_host(
                                    ip=src_ip, source="netbios",
                                    hostname=name, os_hint="Windows",
                                )
                        except Exception:
                            self._register_host(ip=src_ip, source="netbios", os_hint="Windows")

                except socket.timeout:
                    continue
                except Exception:
                    continue

            sock.close()
        except Exception as e:
            logger.debug(f"[Passive] NetBIOS listener error: {e}")

    def _listen_llmnr(self, duration: float):
        """Listen for LLMNR queries (RFC 4795, port 5355)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 5355))
            sock.settimeout(1.0)

            # Join LLMNR multicast group
            mreq = struct.pack("4s4s",
                               socket.inet_aton("224.0.0.252"),
                               socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            start = time.time()
            while self._running and time.time() - start < duration:
                try:
                    data, addr = sock.recvfrom(1024)
                    src_ip = addr[0]

                    # LLMNR has same format as DNS
                    if len(data) > 12:
                        # Extract queried name
                        idx = 12
                        labels = []
                        while idx < len(data) and data[idx] != 0:
                            label_len = data[idx]
                            if label_len > 63:
                                break
                            labels.append(
                                data[idx + 1:idx + 1 + label_len].decode("utf-8", errors="replace")
                            )
                            idx += label_len + 1
                        queried_name = ".".join(labels)

                        if queried_name:
                            self._register_host(
                                ip=src_ip, source="llmnr",
                                os_hint="Windows",
                                llmnr_query=queried_name,
                            )

                except socket.timeout:
                    continue
                except Exception:
                    continue

            sock.close()
        except Exception as e:
            logger.debug(f"[Passive] LLMNR listener error: {e}")

    def _listen_ssdp(self, duration: float):
        """Listen for SSDP/UPnP announcements (port 1900)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 1900))
            sock.settimeout(1.0)

            # Join SSDP multicast
            mreq = struct.pack("4s4s",
                               socket.inet_aton("239.255.255.250"),
                               socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            start = time.time()
            while self._running and time.time() - start < duration:
                try:
                    data, addr = sock.recvfrom(4096)
                    src_ip = addr[0]
                    text = data.decode("utf-8", errors="replace")

                    services = []
                    os_hint = ""

                    if "SERVER:" in text.upper():
                        for line in text.split("\r\n"):
                            if line.upper().startswith("SERVER:"):
                                server = line.split(":", 1)[1].strip()
                                services.append(f"ssdp:{server}")
                                if "windows" in server.lower():
                                    os_hint = "Windows"
                                elif "linux" in server.lower():
                                    os_hint = "Linux"

                    if "ST:" in text.upper() or "NT:" in text.upper():
                        for line in text.split("\r\n"):
                            upper = line.upper()
                            if upper.startswith("ST:") or upper.startswith("NT:"):
                                svc_type = line.split(":", 1)[1].strip()
                                services.append(svc_type)

                    self._register_host(
                        ip=src_ip, source="ssdp",
                        services=services, os_hint=os_hint,
                    )

                except socket.timeout:
                    continue
                except Exception:
                    continue

            sock.close()
        except Exception as e:
            logger.debug(f"[Passive] SSDP listener error: {e}")

    def _listen_dhcp(self, duration: float):
        """
        Listen for DHCP Discover/Request (UDP 67/68).
        Extracts Option 55 (Parameter Request List) for OS fingerprinting.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 67))  # DHCP server port (clients broadcast here)
            sock.settimeout(1.0)
            
            start = time.time()
            while self._running and time.time() - start < duration:
                try:
                    data, addr = sock.recvfrom(4096)
                    # DHCP packet minimum size is ~240 bytes
                    if len(data) < 240:
                        continue
                        
                    # Check DHCP magic cookie
                    if data[236:240] != b"\x63\x82\x53\x63":
                        continue
                        
                    # Extract client MAC
                    mac_bytes = data[28:34]
                    client_mac = ":".join(f"{b:02x}" for b in mac_bytes)
                    src_ip = addr[0]
                    
                    # If broadcasting from 0.0.0.0, we just register the MAC
                    
                    # Parse DHCP options
                    idx = 240
                    os_hint = ""
                    hostname = ""
                    options = {}
                    
                    while idx < len(data) and data[idx] != 255:  # 255 = End option
                        opt_type = data[idx]
                        if opt_type == 0:  # Pad
                            idx += 1
                            continue
                            
                        opt_len = data[idx+1]
                        opt_val = data[idx+2 : idx+2+opt_len]
                        
                        options[opt_type] = opt_val
                        idx += 2 + opt_len
                        
                    # Option 12: Hostname
                    if 12 in options:
                        hostname = options[12].decode('utf-8', errors='ignore')
                        
                    # Option 55: Parameter Request List (OS Fingerprint signature)
                    if 55 in options:
                        prq_list = list(options[55])
                        
                        # Very heuristic basic fingerprints from p0f/PRL signatures
                        if prq_list == [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]:
                            os_hint = "Windows 10/11"
                        elif prq_list == [1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 252, 43]:
                            os_hint = "Windows 7/8"
                        elif prq_list[:4] == [1, 121, 33, 3] or prq_list[:4] == [1, 3, 6, 12]:
                            os_hint = "Linux"
                        elif 119 in prq_list and 252 in prq_list and 120 not in prq_list:
                            # Apple devices usually request 252 (WPAD) and 119 (Domain Search)
                            if 12 in prq_list: os_hint = "macOS"
                            else: os_hint = "iOS/iPadOS"
                        elif 1 in prq_list and 3 in prq_list and 6 in prq_list and 28 in prq_list:
                            os_hint = "Android"
                            
                    if src_ip != "0.0.0.0":
                        self._register_host(
                            ip=src_ip, source="dhcp",
                            mac=client_mac,
                            hostname=hostname,
                            os_hint=os_hint
                        )
                        
                except socket.timeout:
                    continue
                except Exception:
                    continue
            sock.close()
        except PermissionError:
            logger.debug("[Passive] DHCP listener requires root privileges or port 67 is bound")
        except Exception as e:
            logger.debug(f"[Passive] DHCP listener error: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of passive reconnaissance."""
        with self._lock:
            hosts_by_source: Dict[str, int] = defaultdict(int)
            total_services = 0
            for host in self._hosts.values():
                hosts_by_source[host.source] += 1
                total_services += len(host.services)

            return {
                "total_hosts": len(self._hosts),
                "hosts_by_source": dict(hosts_by_source),
                "total_services": total_services,
                "hosts": [h.to_dict() for h in self._hosts.values()],
            }
