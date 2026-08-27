"""
USARE FTP Bounce Scanner

Exploits FTP servers with the PORT command enabled to scan third-party hosts
indirectly. The attacker sends a PORT command instructing the FTP server to
open a connection to the target port, then issues a LIST or RETR command.
If the data connection succeeds, the target port is open. If it fails,
the port is closed or filtered.

This is an older technique (Nmap -b) but still works on legacy infrastructure
and provides excellent stealth, as the attacker's IP never touches the
final target.
"""

import socket
import logging
import time
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ftp_bounce")


@dataclass
class FTPBounceResult:
    """Result of an FTP bounce scan against a target."""
    target_host: str
    target_port: int
    proxy_ftp_server: str
    proxy_ftp_port: int
    state: str = "error"  # open, closed, filtered, error
    latency_ms: float = 0.0
    error_msg: str = ""

    def to_dict(self) -> Dict:
        return {
            "target": self.target_host,
            "port": self.target_port,
            "proxy": self.proxy_ftp_server,
            "state": self.state,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error_msg,
        }


class FTPBounceScanner:
    """
    FTP Bounce Scanner.
    Uses a vulnerable FTP server as a proxy to scan other hosts.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._cache_vulnerable: Dict[str, bool] = {}

    def _connect_ftp(self, proxy_ip: str, proxy_port: int = 21,
                     user: str = "anonymous",
                     password: str = "-anonymous@") -> Optional[Tuple[socket.socket, str]]:
        """Connect to FTP proxy and authenticate."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((proxy_ip, proxy_port))

            # Read banner
            banner = sock.recv(1024).decode(errors="ignore")
            if not banner.startswith("220"):
                sock.close()
                return None

            # Login
            sock.sendall(f"USER {user}\r\n".encode())
            resp = sock.recv(1024).decode(errors="ignore")
            if not resp.startswith("331") and not resp.startswith("230"):
                sock.close()
                return None

            if "331" in resp:
                sock.sendall(f"PASS {password}\r\n".encode())
                resp = sock.recv(1024).decode(errors="ignore")
                if not resp.startswith("230"):
                    sock.close()
                    return None

            return sock, banner
        except Exception as e:
            logger.debug(f"[FTPBounce] Connection failed to {proxy_ip}: {e}")
            return None

    def check_vulnerability(self, proxy_ip: str, proxy_port: int = 21) -> bool:
        """Check if the FTP server supports PORT bouncing."""
        if proxy_ip in self._cache_vulnerable:
            return self._cache_vulnerable[proxy_ip]

        conn = self._connect_ftp(proxy_ip, proxy_port)
        if not conn:
            self._cache_vulnerable[proxy_ip] = False
            return False

        sock, _ = conn
        try:
            # Send PORT command pointing to ourselves or a known safe host
            # Format: PORT h1,h2,h3,h4,p1,p2
            # E.g., PORT 8,8,8,8,0,80 (8.8.8.8 port 80)
            port_cmd = "PORT 8,8,8,8,0,80\r\n"
            sock.sendall(port_cmd.encode())
            resp = sock.recv(1024).decode(errors="ignore")

            # 200 PORT command successful implies vulnerability
            is_vuln = resp.startswith("200")
            self._cache_vulnerable[proxy_ip] = is_vuln

        except Exception:
            self._cache_vulnerable[proxy_ip] = False
        finally:
            try:
                sock.sendall(b"QUIT\r\n")
                sock.close()
            except Exception:
                pass

        return self._cache_vulnerable[proxy_ip]

    def bounce_scan(self, proxy_ip: str, proxy_port: int,
                    target_ip: str, target_port: int) -> FTPBounceResult:
        """Scan a single target port via the FTP proxy."""
        t0 = time.time()
        result = FTPBounceResult(
            target_host=target_ip, target_port=target_port,
            proxy_ftp_server=proxy_ip, proxy_ftp_port=proxy_port,
        )

        conn = self._connect_ftp(proxy_ip, proxy_port)
        if not conn:
            result.error_msg = "Proxy connection failed"
            return result

        sock, _ = conn
        try:
            # Format IP and Port for PORT command
            # IP: a.b.c.d -> a,b,c,d
            # Port: p -> p//256, p%256
            ip_parts = target_ip.replace(".", ",")
            p1 = target_port // 256
            p2 = target_port % 256
            port_cmd = f"PORT {ip_parts},{p1},{p2}\r\n"

            sock.sendall(port_cmd.encode())
            resp1 = sock.recv(1024).decode(errors="ignore")

            if not resp1.startswith("200"):
                result.state = "filtered"
                result.error_msg = f"PORT command rejected: {resp1.strip()}"
                return result

            # Trigger connection via LIST command (requires virtually empty dir)
            sock.sendall(b"LIST\r\n")
            
            # Usually the FTP server responds twice: 
            # 1. 150 File status okay; about to open data connection.
            # 2. 226 Transfer complete OR 425 Can't build data connection
            
            sock.settimeout(self.timeout * 2)  # Give time for bounce connection
            resp2 = sock.recv(1024).decode(errors="ignore")
            
            if resp2.startswith("150"):
                # Data connection established initially
                try:
                    resp3 = sock.recv(1024).decode(errors="ignore")
                    if resp3.startswith("226"):
                        result.state = "open"
                    elif resp3.startswith("425") or resp3.startswith("426"):
                        result.state = "closed"
                    else:
                        result.state = "open"  # Ambiguous but likely open
                except socket.timeout:
                    # Timeout after 150 often means data is flowing or stateful firewall dropped it
                    result.state = "open"
            elif resp2.startswith("425"):
                # "Can't build data connection" -> Port closed or filtered
                result.state = "closed"
            else:
                result.state = "filtered"

        except socket.timeout:
            result.state = "filtered"
            result.error_msg = "Timeout waiting for proxy response"
        except Exception as e:
            result.error_msg = str(e)
        finally:
            try:
                sock.sendall(b"QUIT\r\n")
                sock.close()
            except Exception:
                pass

        result.latency_ms = (time.time() - t0) * 1000
        return result
