"""
USARE eBGP Peering Engine — Real eBGP session establishment and route intelligence.

This module implements a lightweight eBGP speaker that can:
  1. Establish a real BGP session with a looking-glass or route collector
  2. Receive and parse BGP UPDATE messages
  3. Extract prefix/AS-path/community intelligence for the target IP
  4. Map network topology, upstream providers, and peering relationships
  5. Identify route anomalies (hijacks, leaks, unstable prefixes)

Designed for authorized reconnaissance ONLY. Uses public route collectors
(e.g., RIPE RIS, RouteViews) and looking-glass servers — never announces
routes or modifies the routing table.

Protocol: RFC 4271 (BGP-4)
"""

import socket
import struct
import time
import logging
import threading
import ipaddress
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger("usare.ebgp_peer")

# ═══════════════════════════════════════════════════════════════
# BGP Protocol Constants (RFC 4271)
# ═══════════════════════════════════════════════════════════════

BGP_MARKER = b"\xff" * 16
BGP_VERSION = 4
BGP_HOLD_TIME = 90
BGP_HEADER_LEN = 19

class BGPMessageType(IntEnum):
    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4

class BGPOrigin(IntEnum):
    IGP = 0
    EGP = 1
    INCOMPLETE = 2

# Well-known BGP path attribute type codes
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_MED = 4
ATTR_LOCAL_PREF = 5
ATTR_ATOMIC_AGGREGATE = 6
ATTR_AGGREGATOR = 7
ATTR_COMMUNITIES = 8
ATTR_EXTENDED_COMMUNITIES = 16
ATTR_LARGE_COMMUNITIES = 32

# Well-known community values
COMMUNITY_NO_EXPORT = 0xFFFFFF01
COMMUNITY_NO_ADVERTISE = 0xFFFFFF02
COMMUNITY_NO_EXPORT_SUBCONFED = 0xFFFFFF03

# ═══════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════

@dataclass
class BGPPrefix:
    """A learned BGP prefix with full path attributes."""
    prefix: str
    prefix_len: int
    as_path: List[int] = field(default_factory=list)
    origin: str = "incomplete"
    next_hop: str = ""
    med: int = 0
    local_pref: int = 100
    communities: List[str] = field(default_factory=list)
    peer_asn: int = 0
    timestamp: float = field(default_factory=time.time)
    is_best: bool = False

    @property
    def origin_asn(self) -> Optional[int]:
        """The originating AS (rightmost in AS_PATH)."""
        return self.as_path[-1] if self.as_path else None

    @property
    def path_length(self) -> int:
        return len(self.as_path)

    def covers(self, ip: str) -> bool:
        """Check if this prefix covers the given IP."""
        try:
            net = ipaddress.ip_network(f"{self.prefix}/{self.prefix_len}", strict=False)
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prefix": f"{self.prefix}/{self.prefix_len}",
            "as_path": self.as_path,
            "origin": self.origin,
            "next_hop": self.next_hop,
            "med": self.med,
            "local_pref": self.local_pref,
            "communities": self.communities,
            "origin_asn": self.origin_asn,
            "path_length": self.path_length,
            "is_best": self.is_best,
        }


@dataclass
class BGPSessionState:
    """State of an eBGP session."""
    state: str = "idle"  # idle, connect, opensent, openconfirm, established
    peer_asn: int = 0
    peer_bgp_id: str = ""
    peer_hold_time: int = 0
    local_asn: int = 0
    local_bgp_id: str = ""
    prefixes_received: int = 0
    updates_received: int = 0
    keepalives_sent: int = 0
    established_time: float = 0.0
    last_keepalive: float = 0.0
    error: Optional[str] = None


@dataclass
class TopologyIntel:
    """Intelligence extracted from BGP routing data."""
    target_ip: str
    covering_prefixes: List[BGPPrefix] = field(default_factory=list)
    origin_asns: Set[int] = field(default_factory=set)
    upstream_providers: List[int] = field(default_factory=list)
    peering_asns: Set[int] = field(default_factory=set)
    communities_seen: List[str] = field(default_factory=list)
    path_diversity: int = 0
    shortest_path: int = 0
    longest_path: int = 0
    is_multi_homed: bool = False
    is_anycast: bool = False
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_ip,
            "covering_prefixes": [p.to_dict() for p in self.covering_prefixes],
            "origin_asns": list(self.origin_asns),
            "upstream_providers": self.upstream_providers,
            "peering_asns": list(self.peering_asns),
            "communities": self.communities_seen,
            "path_diversity": self.path_diversity,
            "shortest_path": self.shortest_path,
            "longest_path": self.longest_path,
            "is_multi_homed": self.is_multi_homed,
            "is_anycast": self.is_anycast,
            "anomalies": self.anomalies,
        }


# ═══════════════════════════════════════════════════════════════
# BGP Message Builders / Parsers
# ═══════════════════════════════════════════════════════════════

def _build_bgp_header(length: int, msg_type: BGPMessageType) -> bytes:
    """Build a BGP message header (19 bytes)."""
    return BGP_MARKER + struct.pack("!HB", length, msg_type)


def build_open_message(local_asn: int, hold_time: int, bgp_id: str) -> bytes:
    """Build a BGP OPEN message."""
    bgp_id_bytes = socket.inet_aton(bgp_id)

    # Optional parameters (empty for basic eBGP)
    opt_params = b""

    # OPEN body: version(1) + ASN(2) + hold_time(2) + bgp_id(4) + opt_len(1) + opt_params
    body = struct.pack("!BHH", BGP_VERSION, local_asn & 0xFFFF, hold_time)
    body += bgp_id_bytes
    body += struct.pack("!B", len(opt_params))
    body += opt_params

    total_len = BGP_HEADER_LEN + len(body)
    return _build_bgp_header(total_len, BGPMessageType.OPEN) + body


def build_keepalive_message() -> bytes:
    """Build a BGP KEEPALIVE message (header only, 19 bytes)."""
    return _build_bgp_header(BGP_HEADER_LEN, BGPMessageType.KEEPALIVE)


def parse_bgp_header(data: bytes) -> Tuple[int, BGPMessageType, bytes]:
    """Parse BGP header. Returns (length, type, remaining_payload)."""
    if len(data) < BGP_HEADER_LEN:
        raise ValueError(f"Data too short for BGP header: {len(data)}")

    marker = data[:16]
    if marker != BGP_MARKER:
        raise ValueError("Invalid BGP marker")

    length, msg_type = struct.unpack("!HB", data[16:19])
    payload = data[19:length]
    return length, BGPMessageType(msg_type), payload


def parse_open_message(payload: bytes) -> Dict[str, Any]:
    """Parse BGP OPEN message payload."""
    version = payload[0]
    peer_asn = struct.unpack("!H", payload[1:3])[0]
    hold_time = struct.unpack("!H", payload[3:5])[0]
    bgp_id = socket.inet_ntoa(payload[5:9])
    opt_len = payload[9]

    return {
        "version": version,
        "asn": peer_asn,
        "hold_time": hold_time,
        "bgp_id": bgp_id,
        "opt_params_len": opt_len,
    }


def parse_update_message(payload: bytes) -> Tuple[List[str], List[BGPPrefix]]:
    """Parse BGP UPDATE message. Returns (withdrawn_routes, nlri_with_attrs)."""
    if len(payload) < 4:
        return [], []

    offset = 0

    # Withdrawn routes length
    wr_len = struct.unpack("!H", payload[offset:offset+2])[0]
    offset += 2

    # Parse withdrawn prefixes
    withdrawn = []
    wr_end = offset + wr_len
    while offset < wr_end:
        plen = payload[offset]
        offset += 1
        nbytes = (plen + 7) // 8
        prefix_bytes = payload[offset:offset+nbytes]
        offset += nbytes
        prefix_bytes += b"\x00" * (4 - len(prefix_bytes))
        prefix_str = socket.inet_ntoa(prefix_bytes[:4])
        withdrawn.append(f"{prefix_str}/{plen}")

    # Total path attribute length
    pa_len = struct.unpack("!H", payload[offset:offset+2])[0]
    offset += 2

    # Parse path attributes
    pa_end = offset + pa_len
    attrs = {}
    while offset < pa_end and offset < len(payload):
        if offset + 3 > len(payload):
            break
        attr_flags = payload[offset]
        attr_type = payload[offset + 1]
        offset += 2

        if attr_flags & 0x10:  # Extended length
            if offset + 2 > len(payload):
                break
            attr_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
        else:
            if offset + 1 > len(payload):
                break
            attr_len = payload[offset]
            offset += 1

        attr_data = payload[offset:offset+attr_len]
        offset += attr_len
        attrs[attr_type] = attr_data

    # Parse NLRI (Network Layer Reachability Information)
    nlri = []
    while offset < len(payload):
        plen = payload[offset]
        offset += 1
        nbytes = (plen + 7) // 8
        if offset + nbytes > len(payload):
            break
        prefix_bytes = payload[offset:offset+nbytes]
        offset += nbytes
        prefix_bytes += b"\x00" * (4 - len(prefix_bytes))

        prefix = BGPPrefix(
            prefix=socket.inet_ntoa(prefix_bytes[:4]),
            prefix_len=plen,
        )

        # Populate from path attributes
        if ATTR_ORIGIN in attrs and len(attrs[ATTR_ORIGIN]) >= 1:
            origin_val = attrs[ATTR_ORIGIN][0]
            prefix.origin = {0: "igp", 1: "egp", 2: "incomplete"}.get(origin_val, "incomplete")

        if ATTR_AS_PATH in attrs:
            prefix.as_path = _parse_as_path(attrs[ATTR_AS_PATH])

        if ATTR_NEXT_HOP in attrs and len(attrs[ATTR_NEXT_HOP]) >= 4:
            prefix.next_hop = socket.inet_ntoa(attrs[ATTR_NEXT_HOP][:4])

        if ATTR_MED in attrs and len(attrs[ATTR_MED]) >= 4:
            prefix.med = struct.unpack("!I", attrs[ATTR_MED][:4])[0]

        if ATTR_LOCAL_PREF in attrs and len(attrs[ATTR_LOCAL_PREF]) >= 4:
            prefix.local_pref = struct.unpack("!I", attrs[ATTR_LOCAL_PREF][:4])[0]

        if ATTR_COMMUNITIES in attrs:
            prefix.communities = _parse_communities(attrs[ATTR_COMMUNITIES])

        nlri.append(prefix)

    return withdrawn, nlri


def _parse_as_path(data: bytes) -> List[int]:
    """Parse AS_PATH attribute into list of ASNs."""
    path = []
    offset = 0
    while offset + 2 <= len(data):
        seg_type = data[offset]     # 1=AS_SET, 2=AS_SEQUENCE
        seg_len = data[offset + 1]  # number of ASNs
        offset += 2
        for _ in range(seg_len):
            if offset + 2 > len(data):
                break
            # Try 4-byte ASN first, fall back to 2-byte
            if offset + 4 <= len(data) and seg_len * 4 + 2 <= len(data):
                asn = struct.unpack("!I", data[offset:offset+4])[0]
                offset += 4
            else:
                asn = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
            path.append(asn)
    return path


def _parse_communities(data: bytes) -> List[str]:
    """Parse BGP communities attribute into ASN:value strings."""
    communities = []
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack("!I", data[i:i+4])[0]
        if val == COMMUNITY_NO_EXPORT:
            communities.append("no-export")
        elif val == COMMUNITY_NO_ADVERTISE:
            communities.append("no-advertise")
        elif val == COMMUNITY_NO_EXPORT_SUBCONFED:
            communities.append("no-export-subconfed")
        else:
            high = (val >> 16) & 0xFFFF
            low = val & 0xFFFF
            communities.append(f"{high}:{low}")
    return communities


# ═══════════════════════════════════════════════════════════════
# eBGP Session Manager
# ═══════════════════════════════════════════════════════════════

class EBGPPeer:
    """
    Lightweight eBGP speaker for passive route collection.

    Connects to a public route collector or looking-glass peer,
    establishes a BGP session, and collects routing information
    for intelligence purposes. Never announces any routes.
    """

    # Public BGP route collectors that accept research peering
    ROUTE_COLLECTORS = [
        # RIPE RIS Route Collectors
        {"host": "193.0.0.56", "asn": 12654, "name": "rrc00.ripe.net (Amsterdam)"},
        {"host": "80.249.211.155", "asn": 12654, "name": "rrc01.ripe.net (London)"},
        # RouteViews
        {"host": "128.223.51.15", "asn": 6447, "name": "route-views.routeviews.org"},
        {"host": "198.32.176.177", "asn": 6447, "name": "route-views2.routeviews.org"},
    ]

    def __init__(
        self,
        local_asn: int = 65000,
        local_bgp_id: str = "10.0.0.1",
        hold_time: int = BGP_HOLD_TIME,
        connect_timeout: float = 10.0,
    ):
        self.local_asn = local_asn
        self.local_bgp_id = local_bgp_id
        self.hold_time = hold_time
        self.connect_timeout = connect_timeout

        self._sock: Optional[socket.socket] = None
        self._state = BGPSessionState(local_asn=local_asn, local_bgp_id=local_bgp_id)
        self._prefixes: List[BGPPrefix] = []
        self._keepalive_thread: Optional[threading.Thread] = None
        self._running = False
        self._recv_buffer = b""

    @property
    def session_state(self) -> BGPSessionState:
        return self._state

    @property
    def learned_prefixes(self) -> List[BGPPrefix]:
        return list(self._prefixes)

    def connect(self, peer_host: str, peer_port: int = 179) -> bool:
        """Establish TCP connection and perform BGP OPEN exchange."""
        logger.info(f"[eBGP] Connecting to {peer_host}:{peer_port}")
        self._state.state = "connect"

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.connect_timeout)
            self._sock.connect((peer_host, peer_port))
            logger.info(f"[eBGP] TCP connected to {peer_host}:{peer_port}")

            # Send OPEN
            open_msg = build_open_message(self.local_asn, self.hold_time, self.local_bgp_id)
            self._sock.sendall(open_msg)
            self._state.state = "opensent"
            logger.info(f"[eBGP] Sent OPEN (AS{self.local_asn}, ID={self.local_bgp_id})")

            # Receive peer OPEN
            data = self._recv_message()
            if not data:
                self._state.error = "No response to OPEN"
                return False

            length, msg_type, payload = parse_bgp_header(data)

            if msg_type == BGPMessageType.NOTIFICATION:
                error_code = payload[0] if payload else 0
                error_sub = payload[1] if len(payload) > 1 else 0
                self._state.error = f"NOTIFICATION received: {error_code}/{error_sub}"
                logger.warning(f"[eBGP] Peer sent NOTIFICATION: {error_code}/{error_sub}")
                return False

            if msg_type != BGPMessageType.OPEN:
                self._state.error = f"Expected OPEN, got {msg_type}"
                return False

            peer_open = parse_open_message(payload)
            self._state.peer_asn = peer_open["asn"]
            self._state.peer_bgp_id = peer_open["bgp_id"]
            self._state.peer_hold_time = peer_open["hold_time"]
            self._state.state = "openconfirm"
            logger.info(
                f"[eBGP] Received OPEN from AS{peer_open['asn']} "
                f"(ID={peer_open['bgp_id']}, hold={peer_open['hold_time']}s)"
            )

            # Send KEEPALIVE to confirm
            self._sock.sendall(build_keepalive_message())
            self._state.keepalives_sent += 1

            # Wait for peer KEEPALIVE
            data = self._recv_message()
            if data:
                _, kt, _ = parse_bgp_header(data)
                if kt == BGPMessageType.KEEPALIVE:
                    self._state.state = "established"
                    self._state.established_time = time.time()
                    self._state.last_keepalive = time.time()
                    self._running = True
                    logger.info("[eBGP] Session ESTABLISHED")

                    # Start keepalive thread
                    self._keepalive_thread = threading.Thread(
                        target=self._keepalive_loop, daemon=True
                    )
                    self._keepalive_thread.start()
                    return True

            self._state.error = "Failed to complete OPEN exchange"
            return False

        except socket.timeout:
            self._state.error = f"Connection timed out ({self.connect_timeout}s)"
            logger.warning(f"[eBGP] Connection timed out to {peer_host}")
            return False
        except ConnectionRefusedError:
            self._state.error = "Connection refused (port 179 not open)"
            logger.warning(f"[eBGP] Connection refused by {peer_host}")
            return False
        except Exception as e:
            self._state.error = str(e)
            logger.error(f"[eBGP] Connection failed: {e}")
            return False

    def collect_routes(self, duration: float = 30.0, target_ip: Optional[str] = None) -> List[BGPPrefix]:
        """
        Collect BGP UPDATE messages for a duration.

        If target_ip is specified, only collect prefixes that cover that IP.
        """
        if self._state.state != "established":
            logger.warning("[eBGP] Cannot collect routes — session not established")
            return []

        logger.info(f"[eBGP] Collecting routes for {duration:.0f}s" +
                     (f" (filtering for {target_ip})" if target_ip else ""))

        deadline = time.time() + duration
        self._sock.settimeout(5.0)

        while time.time() < deadline and self._running:
            try:
                data = self._recv_message()
                if not data:
                    continue

                length, msg_type, payload = parse_bgp_header(data)

                if msg_type == BGPMessageType.UPDATE:
                    self._state.updates_received += 1
                    withdrawn, nlri = parse_update_message(payload)

                    for prefix in nlri:
                        prefix.peer_asn = self._state.peer_asn
                        if target_ip and not prefix.covers(target_ip):
                            continue
                        self._prefixes.append(prefix)
                        self._state.prefixes_received += 1

                elif msg_type == BGPMessageType.KEEPALIVE:
                    self._state.last_keepalive = time.time()

                elif msg_type == BGPMessageType.NOTIFICATION:
                    error_code = payload[0] if payload else 0
                    logger.warning(f"[eBGP] Session terminated by peer: NOTIFICATION {error_code}")
                    self._running = False
                    break

            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"[eBGP] Receive error: {e}")
                continue

        return self._prefixes

    def analyze_topology(self, target_ip: str) -> TopologyIntel:
        """Analyze collected prefixes to build topology intelligence."""
        intel = TopologyIntel(target_ip=target_ip)

        # Find covering prefixes
        for prefix in self._prefixes:
            if prefix.covers(target_ip):
                intel.covering_prefixes.append(prefix)
                if prefix.origin_asn:
                    intel.origin_asns.add(prefix.origin_asn)
                if prefix.as_path:
                    # First AS in path (after collector) is typically upstream
                    if len(prefix.as_path) >= 2:
                        intel.upstream_providers.append(prefix.as_path[0])
                    # Collect all transit ASNs
                    for asn in prefix.as_path[:-1]:
                        intel.peering_asns.add(asn)
                intel.communities_seen.extend(prefix.communities)

        # Deduplicate
        intel.upstream_providers = list(set(intel.upstream_providers))
        intel.communities_seen = list(set(intel.communities_seen))

        # Path analysis
        if intel.covering_prefixes:
            path_lengths = [p.path_length for p in intel.covering_prefixes if p.path_length > 0]
            if path_lengths:
                intel.shortest_path = min(path_lengths)
                intel.longest_path = max(path_lengths)
            intel.path_diversity = len(set(
                tuple(p.as_path) for p in intel.covering_prefixes
            ))

        # Multi-homing detection
        intel.is_multi_homed = len(intel.origin_asns) > 1 or len(intel.upstream_providers) > 1

        # Anycast detection (same prefix from multiple origins)
        prefix_origin_map: Dict[str, Set[int]] = {}
        for p in intel.covering_prefixes:
            key = f"{p.prefix}/{p.prefix_len}"
            if key not in prefix_origin_map:
                prefix_origin_map[key] = set()
            if p.origin_asn:
                prefix_origin_map[key].add(p.origin_asn)
        for key, origins in prefix_origin_map.items():
            if len(origins) > 1:
                intel.is_anycast = True
                intel.anomalies.append(
                    f"MOAS conflict: {key} announced by ASNs {origins}"
                )

        # Detect unusually long AS paths (possible route leak)
        for p in intel.covering_prefixes:
            if p.path_length > 6:
                intel.anomalies.append(
                    f"Long AS path ({p.path_length} hops) for {p.prefix}/{p.prefix_len}: "
                    f"{' → '.join(str(a) for a in p.as_path)}"
                )

        return intel

    def disconnect(self):
        """Gracefully close the BGP session."""
        self._running = False
        if self._sock:
            try:
                # Send NOTIFICATION (Cease)
                cease = _build_bgp_header(21, BGPMessageType.NOTIFICATION)
                cease += struct.pack("BB", 6, 0)  # Cease, no subcode
                self._sock.sendall(cease)
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
        self._state.state = "idle"
        logger.info("[eBGP] Session closed")

    def _recv_message(self) -> Optional[bytes]:
        """Receive a single BGP message from the socket."""
        try:
            # Read until we have at least a header
            while len(self._recv_buffer) < BGP_HEADER_LEN:
                chunk = self._sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buffer += chunk

            # Parse header to get total length
            length = struct.unpack("!H", self._recv_buffer[16:18])[0]

            # Read remaining bytes
            while len(self._recv_buffer) < length:
                chunk = self._sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buffer += chunk

            msg = self._recv_buffer[:length]
            self._recv_buffer = self._recv_buffer[length:]
            return msg

        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"[eBGP] recv error: {e}")
            return None

    def _keepalive_loop(self):
        """Send periodic keepalives to maintain the session."""
        interval = min(self.hold_time, self._state.peer_hold_time or self.hold_time) // 3
        if interval < 10:
            interval = 10

        while self._running:
            time.sleep(interval)
            if not self._running:
                break
            try:
                self._sock.sendall(build_keepalive_message())
                self._state.keepalives_sent += 1
            except Exception as e:
                logger.warning(f"[eBGP] Keepalive send failed: {e}")
                self._running = False
                break


# ═══════════════════════════════════════════════════════════════
# Fallback: HTTP-based Route Info (when BGP port 179 is blocked)
# ═══════════════════════════════════════════════════════════════

def query_ris_api(target_ip: str) -> Optional[TopologyIntel]:
    """
    Query RIPE RIS Looking Glass API as fallback when direct
    BGP peering is not possible (port 179 blocked).
    """
    import requests

    intel = TopologyIntel(target_ip=target_ip)

    try:
        # RIPE RIS RIPEstat API
        url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={target_ip}"
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return None

        data = resp.json().get("data", {})
        rrcs = data.get("rrcs", [])

        for rrc in rrcs:
            for peer in rrc.get("peers", []):
                as_path_str = peer.get("as_path", "")
                as_path = [int(a) for a in as_path_str.split() if a.isdigit()]
                prefix_str = peer.get("prefix", "")

                if "/" in prefix_str:
                    parts = prefix_str.split("/")
                    prefix = BGPPrefix(
                        prefix=parts[0],
                        prefix_len=int(parts[1]),
                        as_path=as_path,
                        next_hop=peer.get("next_hop", ""),
                        peer_asn=int(peer.get("asn_origin", 0) or 0),
                        communities=peer.get("community", "").split() if peer.get("community") else [],
                    )
                    intel.covering_prefixes.append(prefix)

                    if as_path:
                        intel.origin_asns.add(as_path[-1])
                        if len(as_path) >= 2:
                            intel.upstream_providers.append(as_path[-2])
                        for asn in as_path[:-1]:
                            intel.peering_asns.add(asn)

        intel.upstream_providers = list(set(intel.upstream_providers))
        intel.path_diversity = len(set(
            tuple(p.as_path) for p in intel.covering_prefixes
        ))

        if intel.covering_prefixes:
            path_lengths = [p.path_length for p in intel.covering_prefixes if p.path_length > 0]
            if path_lengths:
                intel.shortest_path = min(path_lengths)
                intel.longest_path = max(path_lengths)

        intel.is_multi_homed = len(intel.upstream_providers) > 1

        return intel

    except Exception as e:
        logger.warning(f"[eBGP] RIS API query failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════
# High-level convenience functions
# ═══════════════════════════════════════════════════════════════

def ebgp_recon(
    target_ip: str,
    collector_host: Optional[str] = None,
    collector_asn: int = 0,
    local_asn: int = 65000,
    duration: float = 30.0,
) -> TopologyIntel:
    """
    Attempt real eBGP peering with a route collector, fall back to
    RIS HTTP API if port 179 is unreachable.

    Returns TopologyIntel with route data.
    """
    # Try direct eBGP first
    if collector_host:
        collectors = [{"host": collector_host, "asn": collector_asn, "name": "custom"}]
    else:
        collectors = EBGPPeer.ROUTE_COLLECTORS

    for collector in collectors:
        peer = EBGPPeer(local_asn=local_asn)
        logger.info(f"[eBGP] Trying collector: {collector['name']}")

        if peer.connect(collector["host"]):
            peer.collect_routes(duration=duration, target_ip=target_ip)
            intel = peer.analyze_topology(target_ip)
            peer.disconnect()

            if intel.covering_prefixes:
                logger.info(
                    f"[eBGP] Collected {len(intel.covering_prefixes)} covering prefixes "
                    f"from {collector['name']}"
                )
                return intel

        peer.disconnect()

    # Fallback to HTTP API
    logger.info("[eBGP] Direct peering failed — falling back to RIPE RIS API")
    api_intel = query_ris_api(target_ip)
    if api_intel:
        return api_intel

    return TopologyIntel(target_ip=target_ip, anomalies=["No BGP data available"])
