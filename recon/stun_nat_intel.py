"""
STUN Binding — NAT / egress mapping intelligence.

Classic technique: learn the public IPv4:port as seen by a STUN server.
Helps understand NAT type, egress path, and correlation with scan source.
"""

import socket
import struct
import random
import logging
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("usare.stun_nat")

# Google public STUN (RFC 5389)
STUN_HOSTS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
]


def _build_binding_request() -> Tuple[bytes, bytes]:
    tid = random.randbytes(12)
    # Type 0x0001 Binding Request, length 0, magic cookie, transaction id
    msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tid
    return msg, tid


def _parse_xor_mapped(data: bytes, tid: bytes) -> Optional[Tuple[str, int]]:
    """Extract XOR-MAPPED-ADDRESS (0x0020) from STUN response."""
    if len(data) < 20:
        return None
    mtype, mlen = struct.unpack("!HH", data[0:4])
    if mtype & 0x3FFF != 0x0101:  # success response
        return None
    off = 20
    while off + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[off : off + 4])
        pad = (4 - (attr_len % 4)) % 4
        val = data[off + 4 : off + 4 + attr_len]
        if attr_type == 0x0020 and len(val) >= 8:  # XOR-MAPPED-ADDRESS
            fam = val[1]
            xport = struct.unpack("!H", val[2:4])[0] ^ (0x2112A442 >> 16)
            if fam == 0x01 and len(val) >= 8:
                ip_int = struct.unpack("!I", val[4:8])[0] ^ 0x2112A442
                ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                return ip, xport
            if fam == 0x02 and len(val) >= 20:
                # IPv6 — XOR with magic + tid
                x = bytearray(val[4:20])
                cookie = struct.pack("!I", 0x2112A442)
                for i in range(4):
                    x[i] ^= cookie[i]
                for i in range(12):
                    x[4 + i] ^= tid[i]
                ip = socket.inet_ntop(socket.AF_INET6, bytes(x))
                return ip, xport
        off += 4 + attr_len + pad
    return None


def stun_nat_discover(timeout: float = 3.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "success": False,
        "public_ip": None,
        "public_port": None,
        "stun_server": None,
        "notes": [],
    }
    req, tid = _build_binding_request()
    for host, port in STUN_HOSTS:
        try:
            addr_infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
            if not addr_infos:
                continue
            fam, _, _, _, sockaddr = addr_infos[0]
            sock = socket.socket(fam, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(req, sockaddr)
            data, _ = sock.recvfrom(2048)
            sock.close()
            mapped = _parse_xor_mapped(data, tid)
            if mapped:
                out["success"] = True
                out["public_ip"], out["public_port"] = mapped[0], mapped[1]
                out["stun_server"] = f"{host}:{port}"
                out["notes"].append("XOR-MAPPED-ADDRESS parsed")
                return out
        except Exception as e:
            logger.debug("STUN %s:%s failed: %s", host, port, e)
            out["notes"].append(f"{host}: {e}")
    return out
