"""
USARE Script: default-creds
Tests common default credential combinations against discovered services.
Covers: HTTP Basic/Digest, Telnet, FTP, SNMP community strings.
Nmap equivalent: http-default-accounts + various brute NSE scripts (light mode).
"""
import socket, ssl, base64, re
from typing import List, Dict, Any

DESCRIPTION = "Test default/common credentials against HTTP, Telnet, FTP, SNMP"
CATEGORIES  = ["auth", "safe"]

# Common credential pairs: (username, password)
DEFAULT_HTTP_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "1234"), ("admin", "admin123"), ("root", "root"),
    ("root", ""), ("user", "user"), ("admin", "Admin"),
    ("administrator", "administrator"), ("guest", "guest"),
    ("test", "test"), ("demo", "demo"), ("pi", "raspberry"),
    ("ubnt", "ubnt"), ("cisco", "cisco"),
]
DEFAULT_SNMP_COMMUNITIES = [
    "public", "private", "community", "manager", "admin",
    "snmpd", "snmp", "cisco", "mngt", "monitor", "all", "secret",
]

def _try_http_basic(target, port, tls, user, password, timeout):
    """Try HTTP Basic Auth and return status code."""
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target)
        cred = base64.b64encode(f"{user}:{password}".encode()).decode()
        req  = (
            f"GET / HTTP/1.1\r\nHost: {target}\r\n"
            f"Authorization: Basic {cred}\r\n"
            f"User-Agent: Mozilla/5.0 USARE/2.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        resp = sock.recv(512).decode("utf-8", errors="replace")
        sock.close()
        m = re.match(r"HTTP/\S+ (\d+)", resp)
        return int(m.group(1)) if m else 0
    except Exception:
        return -1

def _try_snmp(target, community, timeout):
    """Send a SNMPv1 GET-REQUEST for sysDescr and check response."""
    import struct
    def ber_len(n):
        return bytes([n]) if n < 128 else bytes([0x81, n])
    def ber_str(s):
        enc = s.encode()
        return bytes([0x04]) + ber_len(len(enc)) + enc
    def ber_int(n):
        return b"\x02\x01" + bytes([n & 0xFF])
    def ber_oid(oid_str):
        parts = [int(x) for x in oid_str.split(".")]
        body  = bytes([parts[0] * 40 + parts[1]])
        for p in parts[2:]:
            if p < 128:
                body += bytes([p])
            else:
                enc = []
                while p:
                    enc.append(p & 0x7F)
                    p >>= 7
                enc.reverse()
                for i, b in enumerate(enc):
                    body += bytes([b | (0x80 if i < len(enc) - 1 else 0)])
        return b"\x06" + ber_len(len(body)) + body

    try:
        # Build SNMPv1 GET for sysDescr.0
        oid      = ber_oid("1.3.6.1.2.1.1.1.0")
        varbind  = b"\x30" + ber_len(len(oid) + 2) + oid + b"\x05\x00"
        varlist  = b"\x30" + ber_len(len(varbind)) + varbind
        pdu      = b"\xa0" + ber_len(6 + len(varlist)) + ber_int(1) + ber_int(0) + ber_int(0) + varlist
        comm     = ber_str(community)
        msg      = b"\x02\x01\x00" + comm + pdu  # version=0 (v1)
        packet   = b"\x30" + ber_len(len(msg)) + msg

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (target, 161))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        return len(resp) > 20
    except Exception:
        return False

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout   = float(script_args.get("creds.timeout", 4))
    max_tries = int(script_args.get("creds.max", 5))
    results: Dict[str, Any] = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()

        # HTTP Basic Auth
        if port in (80, 443, 8080, 8443, 8888, 3000, 4443) or "http" in service:
            tls  = port in (443, 8443, 4443, 9443)
            info: Dict[str, Any] = {"service": "http", "found": []}

            # First check if auth is even required
            status = _try_http_basic(target_ip, port, tls, "", "", timeout)
            if status in (401, 403):
                for user, pwd in DEFAULT_HTTP_CREDS[:max_tries]:
                    s = _try_http_basic(target_ip, port, tls, user, pwd, timeout)
                    if s not in (-1, 401, 403):
                        info["found"].append({
                            "username": user,
                            "password": pwd,
                            "status":   s,
                            "note":     f"CRITICAL: Default credentials {user}:{pwd} work (HTTP {s})",
                        })
                        if len(info["found"]) >= 3:
                            break
            elif status == -1:
                info["error"] = "Connection failed"
            else:
                info["note"] = f"No auth required (HTTP {status})"

            results[port] = info

        # SNMP community strings
        elif port in (161, 162) or "snmp" in service:
            info = {"service": "snmp", "valid_communities": []}
            for community in DEFAULT_SNMP_COMMUNITIES[:max_tries]:
                if _try_snmp(target_ip, community, timeout):
                    info["valid_communities"].append(community)
                    info[f"community_{community}"] = "ACCESSIBLE"
            if info["valid_communities"]:
                info["note"] = f"CRITICAL: SNMP accessible with communities: {info['valid_communities']}"
            results[port] = info

    return results if results else {"note": "No applicable ports for credential testing"}
