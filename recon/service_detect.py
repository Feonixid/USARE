import re
import socket
import ssl
import time
import logging
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
logger = logging.getLogger("usare.service_detect")
@dataclass
class ServiceInfo:
    port: int
    service: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    os_hint: Optional[str] = None
    cpe: Optional[str] = None
    hostname: Optional[str] = None
    confidence: float = 0.0
    method: str = "probe"      
    raw_response: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}
SERVICE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "probe": None,  
        "wait_banner": True,
        "patterns": [
            {"regex": r"SSH-(\d+\.\d+)-OpenSSH[_](\S+)\s*(.*)",
             "service": "ssh", "product": "OpenSSH", "ver_group": 2,
             "cpe": "cpe:/a:openbsd:openssh:{ver}", "extra_group": 3},
            {"regex": r"SSH-(\d+\.\d+)-dropbear[_](\S+)",
             "service": "ssh", "product": "Dropbear", "ver_group": 2,
             "cpe": "cpe:/a:dropbear:dropbear:{ver}"},
            {"regex": r"SSH-(\d+\.\d+)-libssh[_-](\S+)",
             "service": "ssh", "product": "libssh", "ver_group": 2},
            {"regex": r"SSH-(\d+\.\d+)-(.+)",
             "service": "ssh", "product": None, "ver_group": 2},
        ],
    },
    {
        "probe": None,
        "wait_banner": True,
        "patterns": [
            {"regex": r"220[- ].*vsftpd (\S+)",
             "service": "ftp", "product": "vsftpd", "ver_group": 1,
             "cpe": "cpe:/a:vsftpd:vsftpd:{ver}"},
            {"regex": r"220[- ].*ProFTPD (\S+)",
             "service": "ftp", "product": "ProFTPD", "ver_group": 1,
             "cpe": "cpe:/a:proftpd:proftpd:{ver}"},
            {"regex": r"220[- ].*Pure-FTPd",
             "service": "ftp", "product": "Pure-FTPd", "ver_group": None},
            {"regex": r"220[- ].*FileZilla Server (\S+)",
             "service": "ftp", "product": "FileZilla Server", "ver_group": 1},
            {"regex": r"220[- ].*Microsoft FTP Service",
             "service": "ftp", "product": "Microsoft FTP", "ver_group": None,
             "os_hint": "Windows"},
            {"regex": r"220[- ](.*)",
             "service": "ftp", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": b"EHLO probe.local\r\n",
        "wait_banner": True,
        "patterns": [
            {"regex": r"220[- ].*Postfix",
             "service": "smtp", "product": "Postfix", "ver_group": None,
             "cpe": "cpe:/a:postfix:postfix"},
            {"regex": r"220[- ].*Sendmail[/ ](\S+)",
             "service": "smtp", "product": "Sendmail", "ver_group": 1},
            {"regex": r"220[- ].*Microsoft ESMTP.*",
             "service": "smtp", "product": "Microsoft Exchange", "ver_group": None,
             "os_hint": "Windows"},
            {"regex": r"220[- ].*Exim[/ ](\S+)",
             "service": "smtp", "product": "Exim", "ver_group": 1,
             "cpe": "cpe:/a:exim:exim:{ver}"},
            {"regex": r"220[- ](.*)",
             "service": "smtp", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": (
            b"GET / HTTP/1.1\r\n"
            b"Host: {target}\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            b"AppleWebKit/537.36 (KHTML, like Gecko) "
            b"Chrome/120.0.0.0 Safari/537.36\r\n"
            b"Accept: */*\r\n"
            b"Connection: close\r\n\r\n"
        ),
        "wait_banner": False,
        "patterns": [
            {"regex": r"Server:\s*nginx/(\S+)",
             "service": "http", "product": "nginx", "ver_group": 1,
             "cpe": "cpe:/a:nginx:nginx:{ver}"},
            {"regex": r"Server:\s*Apache/(\S+)",
             "service": "http", "product": "Apache httpd", "ver_group": 1,
             "cpe": "cpe:/a:apache:http_server:{ver}"},
            {"regex": r"Server:\s*Microsoft-IIS/(\S+)",
             "service": "http", "product": "Microsoft IIS", "ver_group": 1,
             "os_hint": "Windows", "cpe": "cpe:/a:microsoft:iis:{ver}"},
            {"regex": r"Server:\s*LiteSpeed/(\S+)",
             "service": "http", "product": "LiteSpeed", "ver_group": 1},
            {"regex": r"Server:\s*openresty/(\S+)",
             "service": "http", "product": "OpenResty", "ver_group": 1},
            {"regex": r"Server:\s*Caddy",
             "service": "http", "product": "Caddy", "ver_group": None},
            {"regex": r"Server:\s*gunicorn/(\S+)",
             "service": "http", "product": "Gunicorn", "ver_group": 1},
            {"regex": r"Server:\s*uvicorn",
             "service": "http", "product": "Uvicorn", "ver_group": None},
            {"regex": r"X-Powered-By:\s*Express",
             "service": "http", "product": "Express.js", "ver_group": None},
            {"regex": r"X-Powered-By:\s*PHP/(\S+)",
             "service": "http", "product": "PHP", "ver_group": 1,
             "cpe": "cpe:/a:php:php:{ver}"},
            {"regex": r"X-Powered-By:\s*ASP\.NET",
             "service": "http", "product": "ASP.NET", "ver_group": None,
             "os_hint": "Windows"},
            {"regex": r"Server:\s*(\S+)",
             "service": "http", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": None,
        "wait_banner": True,
        "binary_extract": True,
        "patterns": [
            {"regex": r"(\d+\.\d+\.\d+[-\w]*)",
             "service": "mysql", "product": "MySQL/MariaDB", "ver_group": 1,
             "cpe": "cpe:/a:mysql:mysql:{ver}"},
        ],
    },
    {
        "probe": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  
        "wait_banner": False,
        "patterns": [
            {"regex": r"^N",  
             "service": "postgresql", "product": "PostgreSQL", "ver_group": None,
             "cpe": "cpe:/a:postgresql:postgresql"},
            {"regex": r"^S",  
             "service": "postgresql", "product": "PostgreSQL (SSL)", "ver_group": None},
        ],
    },
    {
        "probe": b"PING\r\n",
        "wait_banner": False,
        "patterns": [
            {"regex": r"\+PONG",
             "service": "redis", "product": "Redis", "ver_group": None,
             "cpe": "cpe:/a:redis:redis"},
        ],
    },
    {
        "probe": None,
        "wait_banner": True,
        "patterns": [
            {"regex": r"\+OK.*Dovecot",
             "service": "pop3", "product": "Dovecot", "ver_group": None},
            {"regex": r"\+OK (.*)",
             "service": "pop3", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": None,
        "wait_banner": True,
        "patterns": [
            {"regex": r"\* OK.*Dovecot",
             "service": "imap", "product": "Dovecot", "ver_group": None},
            {"regex": r"\* OK.*Cyrus",
             "service": "imap", "product": "Cyrus IMAP", "ver_group": None},
            {"regex": r"\* OK (.*)",
             "service": "imap", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": bytes.fromhex(  
            "030000130ee00000000000010008000b000000"
        ),
        "wait_banner": False,
        "patterns": [
            {"regex": r"^\x03\x00",
             "service": "ms-wbt-server", "product": "Microsoft RDP",
             "ver_group": None, "os_hint": "Windows"},
        ],
    },
    {
        "probe": None,
        "wait_banner": True,
        "patterns": [
            {"regex": r"(.*login|.*Login|.*Username)",
             "service": "telnet", "product": "Telnet", "ver_group": None},
            {"regex": r"(.*)",
             "service": "telnet", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": bytes.fromhex(  
            "002d" "0000" "0010" "0001" "0000" "0000" "0000"
            "0776657273696f6e" "0462696e64" "0000" "0010" "0003"
        ),
        "wait_banner": False,
        "patterns": [
            {"regex": r"(BIND|dnsmasq|PowerDNS|Unbound|CoreDNS|NSD)",
             "service": "dns", "product": None, "ver_group": 1},
        ],
    },
    {
        "probe": bytes.fromhex(  
            "3a0000000100000000000000dd0700000000000000"
            "1b000000016973"
            "6d617374657200000000000000f03f00"
        ),
        "wait_banner": False,
        "patterns": [
            {"regex": r"version.*?(\d+\.\d+\.\d+)",
             "service": "mongodb", "product": "MongoDB", "ver_group": 1,
             "cpe": "cpe:/a:mongodb:mongodb:{ver}"},
        ],
    },
    {
        "probe": b"version\r\n",
        "wait_banner": False,
        "patterns": [
            {"regex": r"VERSION (\S+)",
             "service": "memcached", "product": "Memcached", "ver_group": 1,
             "cpe": "cpe:/a:memcached:memcached:{ver}"},
        ],
    },
    {
        "probe": (
            b"GET / HTTP/1.0\r\n"
            b"Host: localhost\r\n\r\n"
        ),
        "wait_banner": False,
        "patterns": [
            {"regex": r'"version".*?"number"\s*:\s*"(\S+)"',
             "service": "elasticsearch", "product": "Elasticsearch", "ver_group": 1,
             "cpe": "cpe:/a:elastic:elasticsearch:{ver}"},
        ],
    },
    {
        "probe": (
            b"GET /version HTTP/1.0\r\n"
            b"Host: localhost\r\n\r\n"
        ),
        "wait_banner": False,
        "patterns": [
            {"regex": r'"Version"\s*:\s*"(\S+)".*"Os"\s*:\s*"(\S+)"',
             "service": "docker", "product": "Docker Engine", "ver_group": 1},
        ],
    },
]
class ServiceDetector:
    def __init__(
        self,
        connect_timeout: float = 8.0,
        read_timeout: float = 5.0,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
    def detect(self, target_ip: str, port: int) -> ServiceInfo:
        result = ServiceInfo(port=port)
        for sig in SERVICE_SIGNATURES:
            try:
                response = self._probe(target_ip, port, sig)  # type: ignore[attr-defined]
                if response is None:
                    continue
                match = self._match_response(response, sig, port)  # type: ignore[attr-defined]
                if match and match.confidence > result.confidence:  # type: ignore[attr-defined]
                    result = match
                    if result.confidence >= 0.9:
                        break  
            except Exception as e:
                logger.debug(f"Probe failed for {target_ip}:{port}: {e}")
                continue
        if result.service == "unknown":  # type: ignore[attr-defined]
            tls_result = self._tls_detect(target_ip, port)  # type: ignore[attr-defined]
            if tls_result:
                result = tls_result
        return result
    def _probe(
        self, target_ip: str, port: int, sig: Dict
    ) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect((target_ip, port))
            response = ""
            if sig.get("wait_banner", False):
                sock.settimeout(self.read_timeout)
                data = sock.recv(4096)  # type: ignore[attr-defined]
                response = data.decode("utf-8", errors="replace")
            probe = sig.get("probe")
            if probe:
                if isinstance(probe, bytes) and b"{target}" in probe:
                    probe = probe.replace(b"{target}", target_ip.encode())
                sock.sendall(probe)  # type: ignore[attr-defined]
                sock.settimeout(self.read_timeout)
                data = sock.recv(4096)  # type: ignore[attr-defined]
                response += data.decode("utf-8", errors="replace")
            try:
                sock.shutdown(socket.SHUT_RDWR)  # type: ignore[attr-defined]
            except Exception:
                pass
            sock.close()  # type: ignore[attr-defined]
            return response if response.strip() else None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
    def _match_response(
        self, response: str, sig: Dict, port: int
    ) -> Optional[ServiceInfo]:
        for pattern in sig.get("patterns", []):
            regex = pattern["regex"]
            try:
                match = re.search(regex, response, re.IGNORECASE | re.DOTALL)
            except re.error:
                continue
            if match:
                info = ServiceInfo(port=port)
                info.service = pattern.get("service", "unknown")
                info.product = pattern.get("product")
                info.method = "probe"
                info.raw_response = response[:500]  # type: ignore[index]
                ver_group = pattern.get("ver_group")
                if ver_group and match.lastindex and ver_group <= match.lastindex:
                    info.version = match.group(ver_group).strip()
                extra_group = pattern.get("extra_group")
                if extra_group and match.lastindex and extra_group <= match.lastindex:
                    info.extra_info = match.group(extra_group).strip()
                info.os_hint = pattern.get("os_hint")
                cpe_template = pattern.get("cpe")
                if cpe_template and info.version:
                    info.cpe = cpe_template.replace("{ver}", info.version)
                elif cpe_template:
                    info.cpe = cpe_template.replace(":{ver}", "")
                info.confidence = 0.5  
                if info.version:
                    info.confidence += 0.3  
                if info.product:
                    info.confidence += 0.1  
                if info.cpe:
                    info.confidence += 0.1  
                return info
        return None
    def _tls_detect(self, target_ip: str, port: int) -> Optional[ServiceInfo]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect((target_ip, port))
            ssock = ctx.wrap_socket(sock, server_hostname=target_ip)
            version = ssock.version()  # type: ignore[attr-defined]
            cipher = ssock.cipher()  # type: ignore[attr-defined]
            info = ServiceInfo(
                port=port,
                service="ssl/https" if port in (443, 8443) else f"ssl/{port}",
                product=f"TLS ({version})" if version else "TLS",
                version=cipher[0] if cipher else None,
                confidence=0.6,
                method="tls",
            )
            cert = ssock.getpeercert()  # type: ignore[attr-defined]
            if cert:
                subject = cert.get("subject", ())
                for rdn in subject:
                    for attr_type, attr_value in rdn:
                        if attr_type == "commonName":
                            info.hostname = attr_value
            ssock.close()
            return info
        except Exception:
            return None