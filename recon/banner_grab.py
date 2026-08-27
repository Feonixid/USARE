import ssl
import socket
import time
import logging
import re
from typing import Optional, Dict, Any, List, cast
from dataclasses import dataclass, field
logger = logging.getLogger("usare.banner")
@dataclass
class BannerResult:
    port: int
    service: Optional[str] = None
    version: Optional[str] = None
    banner_raw: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    certificate_cn: Optional[str] = None
    certificate_san: Optional[List[str]] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    http_server: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    h2_discrepancy_result: Optional[str] = None
    os_guess: Optional[str] = None
    cpe: Optional[str] = None           
    timestamp: float = field(default_factory=time.time)
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}
PROTOCOL_PROBES: Dict[int, Dict[str, Any]] = {
    21: {
        "name": "ftp",
        "wait_banner": True,
        "probe": b"HELP\r\n",
        "pattern": r"^(220[ -].*)",
    },
    22: {
        "name": "ssh",
        "wait_banner": True,
        "probe": None,
        "pattern": r"^(SSH-[\d.]+-\S+)",
    },
    23: {
        "name": "telnet",
        "wait_banner": True,
        "probe": None,
        "pattern": r"^(.+)",
    },
    25: {
        "name": "smtp",
        "wait_banner": True,
        "probe": b"EHLO scanner.local\r\n",
        "pattern": r"^(220[ -].*)",
    },
    80: {
        "name": "http",
        "wait_banner": False,
        "probe": (
            b"GET / HTTP/1.1\r\n"
            b"Host: {target}\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            b"AppleWebKit/537.36 (KHTML, like Gecko) "
            b"Chrome/120.0.0.0 Safari/537.36\r\n"
            b"Accept: text/html\r\n"
            b"Connection: close\r\n\r\n"
        ),
        "pattern": r"Server:\s*(.+)",
    },
    110: {
        "name": "pop3",
        "wait_banner": True,
        "probe": None,
        "pattern": r"^(\+OK.*)",
    },
    143: {
        "name": "imap",
        "wait_banner": True,
        "probe": None,
        "pattern": r"^\* OK (.+)",
    },
    445: {
        "name": "microsoft-ds",
        "wait_banner": False,
        "probe": (
            b"\x00\x00\x00\x55\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x28"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x32"
            b"\x00\x00\x00\x00\x00\x00\x00\x2e\x00\x00\x02\x4e\x54\x20\x4c\x4d"
            b"\x20\x30\x2e\x31\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31"
            b"\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x50\x43\x20"
            b"\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20"
            b"\x31\x2e\x30\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e"
            b"\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00\x02\x4d\x49\x43"
            b"\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20"
            b"\x31\x2e\x30\x33\x00"
        ),
        "pattern": r"(\xffSMB)",
    },
    3389: {
        "name": "ms-wbt-server",
        "wait_banner": False,
        "probe": b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        "pattern": r"(\x03\x00\x00\x13\x0e\xd0)",
    },
    3306: {
        "name": "mysql",
        "wait_banner": True,
        "probe": None,
        "pattern": r"([\d\.]+-MariaDB|[\d\.]+-log)",
    },
    5432: {
        "name": "postgresql",
        "wait_banner": False,
        "probe": None,
        "pattern": None,
    },
    6379: {
        "name": "redis",
        "wait_banner": False,
        "probe": b"INFO server\r\n",
        "pattern": r"redis_version:(\S+)",
    },
    27017: {
        "name": "mongodb",
        "wait_banner": False,
        "probe": None,
        "pattern": None,
    },
}
class BannerGrabber:
    def __init__(
        self,
        delay_seconds: float = 600.0,
        connect_timeout: float = 10.0,
        read_timeout: float = 5.0,
    ):
        self.delay_seconds = delay_seconds
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
    def grab(self, target_ip: str, port: int) -> BannerResult:
        result = BannerResult(port=port)
        if port in (443, 8443, 8080, 9443) or port not in PROTOCOL_PROBES:
            tls_result = self._tls_grab(target_ip, port)
            if tls_result:
                return tls_result
            if port in PROTOCOL_PROBES:
                return self._plaintext_grab(target_ip, port)
            return result
        if port in PROTOCOL_PROBES:
            return self._plaintext_grab(target_ip, port)
        return result
    def grab_with_delay(self, target_ip: str, port: int) -> BannerResult:
        logger.info(
            f"[USARE] Banner grab for {target_ip}:{port} — "
            f"waiting {self.delay_seconds}s for temporal decorrelation"
        )
        time.sleep(self.delay_seconds)
        return self.grab(target_ip, port)
    def _tls_grab(self, target_ip: str, port: int, browser: Optional[str] = None) -> Optional[BannerResult]:
        result = BannerResult(port=port)
        try:
            ctx = self._create_rotating_ssl_context(browser)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect((target_ip, port))
            ssock = ctx.wrap_socket(
                sock,
                server_hostname=target_ip,
                do_handshake_on_connect=True,
            )
            result.tls_version = ssock.version()
            cipher = ssock.cipher()
            if cipher:
                result.tls_cipher = cipher[0]
            cert = ssock.getpeercert()
            if cert:
                result = self._parse_certificate(result, cert)
            if port in (443, 8443, 8080, 9443):
                if ssock.selected_alpn_protocol() == "h2":
                    h2_result = self._http2_discrepancy_probe(ssock, target_ip)
                    if h2_result:
                        result.h2_discrepancy_result = h2_result
                http_result = self._http_probe_over_tls(ssock, target_ip)
                if http_result:
                    result.http_server = http_result.get("server")
                    result.http_headers = http_result
                    result.service = "https"
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            ssock.close()
            return result
        except ssl.SSLError as e:
            logger.debug(f"[USARE] TLS failed on {target_ip}:{port}: {e}")
            try:
                if 'sock' in locals():
                    sock.close()
                if 'ssock' in locals():
                    ssock.close()
            except Exception:
                pass
            return None
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"[USARE] Connection failed to {target_ip}:{port}: {e}")
            try:
                if 'sock' in locals():
                    sock.close()
                if 'ssock' in locals():
                    ssock.close()
            except Exception:
                pass
            return None
    def _create_rotating_ssl_context(self, browser: Optional[str] = None) -> ssl.SSLContext:
        """Create SSL context with JA3 fingerprint rotation."""
        try:
            from recon.ja3_rotation import get_ja3_rotator, set_browser_fingerprint
        except ImportError:
            # Fallback to basic Chrome context
            return self._create_chrome_ssl_context()
        
        rotator = get_ja3_rotator()
        
        # Set browser fingerprint if specified
        if browser:
            try:
                set_browser_fingerprint(browser)
            except ValueError:
                # Invalid browser, use random
                rotator.set_random_browser()
        else:
            # Rotate to random browser for each connection
            rotator.set_random_browser()
        
        # Get SSL context with current fingerprint
        context = rotator.create_ssl_context()
        if context:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        else:
            # Fallback to Chrome context
            return self._create_chrome_ssl_context()
    
    def _create_chrome_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        chrome_ciphers = ":".join([
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "AES256-SHA",
        ])
        try:
            ctx.set_ciphers(chrome_ciphers)
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT")
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    def _parse_certificate(self, result: BannerResult, cert: dict) -> BannerResult:
        subject = cert.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    result.certificate_cn = attr_value
                    break
        san = cert.get("subjectAltName", ())
        if san:
            result.certificate_san = [name for _, name in san]
        issuer = cert.get("issuer", ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                if attr_type == "organizationName":
                    result.certificate_issuer = attr_value
                    break
        not_after = cert.get("notAfter")
        if not_after:
            result.certificate_expiry = not_after
        return result
    def _http_probe_over_tls(
        self, ssock: ssl.SSLSocket, target_ip: str
    ) -> Optional[Dict[str, str]]:
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/120.0.0.0 Safari/537.36\r\n"
                f"Accept: text/html,application/xhtml+xml\r\n"
                f"Accept-Language: en-US,en;q=0.9\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            ssock.sendall(request.encode())
            ssock.settimeout(self.read_timeout)
            response = ssock.recv(4096).decode("utf-8", errors="replace")
            return self._parse_http_headers(response)
        except Exception as e:
            logger.debug(f"[USARE] HTTP probe failed: {e}")
            return None
    @staticmethod
    def _parse_http_headers(response: str) -> Dict[str, str]:
        headers = {}
        lines = response.split("\r\n")
        if lines:
            headers["status_line"] = lines[0]
        for i in range(1, len(lines)):
            line = lines[i]
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
            elif line == "":
                break
        return headers
    def _http2_discrepancy_probe(self, ssock: ssl.SSLSocket, target_ip: str) -> Optional[str]:
        try:
            preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            settings_frame = bytes.fromhex("000000040000000000")
            def encode_hpack_literal(name: str, value: str) -> bytes:
                name_bytes = name.encode()
                val_bytes = value.encode()
                res = b"\x00" + bytes([len(name_bytes)]) + name_bytes + bytes([len(val_bytes)]) + val_bytes
                return res
            hpack_data = b"\x82\x84\x87"
            hpack_data += encode_hpack_literal(":authority", target_ip)
            hpack_data += encode_hpack_literal("transfer-encoding", "chunked")
            hpack_data += encode_hpack_literal("content-length", "1")
            headers_length = len(hpack_data)
            headers_frame_header = (
                headers_length.to_bytes(3, byteorder='big') +
                b"\x01\x05\x00\x00\x00\x01"
            )
            headers_frame = headers_frame_header + hpack_data
            payload = preface + settings_frame + headers_frame
            ssock.sendall(payload)
            ssock.settimeout(2.0)
            response = ssock.recv(4096)
            if not response:
                return "Connection Closed"
            idx = 0
            while idx < len(response) - 9:
                if not isinstance(response, bytes):
                    break
                resp_any = cast(Any, response)
                length_bytes = resp_any[idx:idx+3]
                length = int.from_bytes(length_bytes, byteorder='big')
                frame_type = resp_any[idx+3]
                if frame_type == 3:
                    return "Rejected (RST_STREAM)"
                elif frame_type == 7:
                    if idx + 17 <= len(response):
                        error_code_bytes = resp_any[idx+13:idx+17]
                        error_code = int.from_bytes(error_code_bytes, byteorder='big')
                    else:
                        error_code = -1
                    return f"Rejected (GOAWAY error={error_code})"
                elif frame_type == 1:
                    return "Accepted (Headers Returned - Vulnerable to TE.CL Smuggling)"
                idx += 9 + length
            return "Unknown behavior"
        except Exception as e:
            logger.debug(f"[USARE] HTTP/2 Discrepancy probe failed: {e}")
            return None
    def _plaintext_grab(self, target_ip: str, port: int) -> BannerResult:
        result = BannerResult(port=port)
        probe_info = PROTOCOL_PROBES.get(port, {})
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect((target_ip, port))
            if probe_info.get("wait_banner", False):
                sock.settimeout(self.read_timeout)
                banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
                result.banner_raw = banner
                result.service = probe_info.get("name")
                pattern = probe_info.get("pattern")
                if pattern and banner:
                    match = re.search(pattern, banner, re.MULTILINE)
                    if match:
                        result.version = match.group(1)
                if port == 22 and banner:
                    result.os_guess = self._guess_os_from_ssh(banner)
            probe = probe_info.get("probe")
            if probe:
                if b"{target}" in probe:
                    probe = probe.replace(b"{target}", target_ip.encode())
                sock.sendall(probe)
                sock.settimeout(self.read_timeout)
                response = sock.recv(4096).decode("utf-8", errors="replace")
                if not result.banner_raw:
                    result.banner_raw = response.strip()
                pattern = probe_info.get("pattern")
                if pattern and response:
                    match = re.search(pattern, response, re.MULTILINE)
                    if match:
                        if not result.version:
                            result.version = match.group(1)
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"[USARE] Plaintext grab failed for {target_ip}:{port}: {e}")
        return result
    @staticmethod
    def _guess_os_from_ssh(banner: str) -> Optional[str]:
        banner_lower = banner.lower()
        if "ubuntu" in banner_lower:
            return "Ubuntu Linux"
        elif "debian" in banner_lower:
            return "Debian Linux"
        elif "fedora" in banner_lower or "redhat" in banner_lower:
            return "Red Hat / Fedora Linux"
        elif "freebsd" in banner_lower:
            return "FreeBSD"
        elif "openbsd" in banner_lower:
            return "OpenBSD"
        elif "windows" in banner_lower:
            return "Windows"
        elif "openssh" in banner_lower:
            return "Linux/Unix (OpenSSH)"
        return None