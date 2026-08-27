import socket
import ssl
import re
import logging
from typing import Optional, Dict
from dataclasses import dataclass

logger = logging.getLogger("usare.http_title")

@dataclass
class HTTPTitleResult:
    port: int
    title: Optional[str] = None
    status_code: Optional[int] = None
    redirect_url: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}

class HTTPTitleGrabber:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self._user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )

    def grab_title(self, target: str, port: int) -> HTTPTitleResult:
        result = HTTPTitleResult(port=port)
        use_tls = port in (443, 8443, 4443, 9443)
        try:
            response = self._fetch(target, port, use_tls)
            if not response and not use_tls:
                response = self._fetch(target, port, True)
            if response:
                self._parse_response(response, result)
        except Exception as e:
            logger.debug(f"HTTP title grab failed for {target}:{port}: {e}")
        return result

    def _fetch(self, target: str, port: int, use_tls: bool) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=target)
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: {self._user_agent}\r\n"
                f"Accept: text/html\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())  # type: ignore[attr-defined]
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break
            sock.close()  # type: ignore[attr-defined]
            return response.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _parse_response(self, response: str, result: HTTPTitleResult):
        status_match = re.search(r"HTTP/\d\.\d (\d{3})", response)
        if status_match:
            result.status_code = int(status_match.group(1))

        server_match = re.search(r"Server:\s*(.+?)(?:\r\n|\n)", response, re.IGNORECASE)
        if server_match:
            result.server = server_match.group(1).strip()

        location_match = re.search(r"Location:\s*(.+?)(?:\r\n|\n)", response, re.IGNORECASE)
        if location_match:
            result.redirect_url = location_match.group(1).strip()

        title_match = re.search(r"<title[^>]*>(.*?)</title>", response, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            title = re.sub(r"\s+", " ", title)
            result.title = title[:200]  # type: ignore[index]

        cl_match = re.search(r"Content-Length:\s*(\d+)", response, re.IGNORECASE)
        if cl_match:
            result.content_length = int(cl_match.group(1))

    def grab_multiple(self, target: str, ports: list) -> Dict[int, HTTPTitleResult]:
        results = {}
        for port in ports:
            result = self.grab_title(target, port)
            # Include all responses, even 404s with no title, to show responsive ports
            if result.status_code is not None or result.title is not None:
                results[port] = result
        return results
