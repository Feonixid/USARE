"""
Gap 5 — Baseline Poisoning

Generates legitimate-looking background traffic to establish a
behavioral baseline before and during scanning. When the IDS has
already observed probe-like patterns as part of normal traffic,
the real probes blend in.
"""

import random
import socket
import ssl
import struct
import time
import threading
import logging
from typing import Optional, List, Callable
from dataclasses import dataclass

logger = logging.getLogger("usare.baseline")

LEGITIMATE_TARGETS = [
    ("www.google.com", 443),
    ("www.microsoft.com", 443),
    ("www.amazon.com", 443),
    ("www.cloudflare.com", 443),
    ("www.github.com", 443),
    ("dns.google", 443),
    ("one.one.one.one", 443),
    ("www.wikipedia.org", 443),
    ("www.apple.com", 443),
]

DNS_DOMAINS = [
    "www.google.com", "www.microsoft.com", "www.amazon.com",
    "www.github.com", "mail.google.com", "login.microsoftonline.com",
    "cdn.jsdelivr.net", "fonts.googleapis.com", "api.github.com",
    "docs.python.org", "pypi.org", "stackoverflow.com",
    "www.wikipedia.org", "update.microsoft.com", "ocsp.digicert.com",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]


@dataclass
class PoisonConfig:
    duration_minutes: float = 5.0
    requests_per_minute: float = 8.0
    include_dns: bool = True
    include_https: bool = True
    include_ntp: bool = True
    include_target_traffic: bool = True
    gradual_ramp: bool = True
    target_ip: Optional[str] = None
    target_ports: Optional[List[int]] = None


class BaselinePoisoner:
    """Generates benign traffic to establish a behavioral baseline."""

    def __init__(self, config: Optional[PoisonConfig] = None):
        self.config = config or PoisonConfig()
        self._active = False
        self._thread: Optional[threading.Thread] = None
        self._concurrent_thread: Optional[threading.Thread] = None
        self._requests_made = 0
        self._dns_queries = 0
        self._ntp_queries = 0
        self._target_requests = 0
        self._rng = random.SystemRandom()

    def start(self, callback: Optional[Callable] = None):
        """Start baseline poisoning in a background thread (pre-scan)."""
        self._active = True
        self._thread = threading.Thread(
            target=self._poison_loop, args=(callback,), daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop all poisoning threads."""
        self._active = False
        if self._thread:
            self._thread.join(timeout=10)
        if self._concurrent_thread:
            self._concurrent_thread.join(timeout=10)

    def start_concurrent(self, callback: Optional[Callable] = None):
        """Start background noise that continues DURING the scan.
        
        This runs alongside the actual scan to maintain the
        established baseline pattern throughout the operation.
        """
        self._active = True
        self._concurrent_thread = threading.Thread(
            target=self._concurrent_noise_loop, args=(callback,), daemon=True
        )
        self._concurrent_thread.start()

    def run_blocking(self, callback: Optional[Callable] = None):
        """Run baseline poisoning in blocking mode (pre-scan phase)."""
        duration_sec = self.config.duration_minutes * 60
        end_time = time.time() + duration_sec
        interval = 60.0 / self.config.requests_per_minute
        self._active = True

        while time.time() < end_time and self._active:
            if self.config.gradual_ramp:
                progress = (time.time() - (end_time - duration_sec)) / duration_sec
                # Start slow, ramp up to full speed
                effective_interval = interval * (2.0 - progress)
            else:
                effective_interval = interval

            self._do_random_action()

            jitter = self._rng.gauss(0, effective_interval * 0.3)
            sleep_time = max(0.5, effective_interval + jitter)
            time.sleep(sleep_time)

            if callback:
                callback(self.stats)

        self._active = False

    def _poison_loop(self, callback: Optional[Callable] = None):
        self.run_blocking(callback)

    def _concurrent_noise_loop(self, callback: Optional[Callable] = None):
        """Lower-frequency noise that runs during the actual scan."""
        interval = 60.0 / max(1.0, self.config.requests_per_minute * 0.3)

        while self._active:
            self._do_random_action()
            jitter = self._rng.gauss(0, interval * 0.4)
            sleep_time = max(1.0, interval + jitter)
            time.sleep(sleep_time)

            if callback:
                callback(self.stats)

    def _do_random_action(self):
        """Perform a random legitimate-looking action."""
        actions = []
        if self.config.include_https:
            actions.append("https")
        if self.config.include_dns:
            actions.append("dns")
        if self.config.include_ntp:
            actions.append("ntp")
        if self.config.include_target_traffic and self.config.target_ip:
            actions.append("target_https")
            actions.append("target_dns")

        if not actions:
            return

        action = self._rng.choice(actions)

        if action == "https":
            self._make_legitimate_https_request()
        elif action == "dns":
            self._make_dns_query()
        elif action == "ntp":
            self._make_ntp_query()
        elif action == "target_https":
            self._make_target_https_request()
        elif action == "target_dns":
            self._make_target_dns_query()

    def _make_legitimate_https_request(self):
        """Make HTTPS requests to legitimate targets to establish baseline."""
        target, port = self._rng.choice(LEGITIMATE_TARGETS)
        tls_sock = None
        sock = None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8.0)
            sock.connect((target, port))
            tls_sock = ctx.wrap_socket(sock, server_hostname=target)

            ua = self._rng.choice(USER_AGENTS)
            paths = ["/", "/favicon.ico", "/robots.txt", "/sitemap.xml"]
            path = self._rng.choice(paths)

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.9\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls_sock.sendall(request.encode())

            response = b""
            while True:
                try:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 32768:
                        break
                except socket.timeout:
                    break

            if tls_sock:
                tls_sock.close()
            self._requests_made += 1
        except Exception as e:
            logger.debug(f"Baseline HTTPS request to {target} failed: {e}")
            # Clean up socket on failure
            try:
                if tls_sock:
                    tls_sock.close()
                if sock:
                    sock.close()
            except Exception:
                pass

    def _make_target_https_request(self):
        """Make a benign HTTPS request to the actual scan target.
        
        This normalizes HTTPS traffic to the target so the real
        scan probes don't stand out.
        """
        if not self.config.target_ip:
            return

        target = self.config.target_ip
        tls_sock = None
        sock = None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8.0)
            sock.connect((target, 443))
            tls_sock = ctx.wrap_socket(sock, server_hostname=target)

            ua = self._rng.choice(USER_AGENTS)
            paths = ["/", "/favicon.ico", "/robots.txt", "/.well-known/security.txt"]
            path = self._rng.choice(paths)

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/xhtml+xml\r\n"
                f"Accept-Language: en-US,en;q=0.9\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls_sock.sendall(request.encode())

            response = b""
            try:
                response = tls_sock.recv(4096)
            except socket.timeout:
                pass

            if tls_sock:
                tls_sock.close()
            self._target_requests += 1
        except Exception as e:
            logger.debug(f"Baseline target HTTPS request failed: {e}")
            # Clean up socket on failure
            try:
                if tls_sock:
                    tls_sock.close()
                if sock:
                    sock.close()
            except Exception:
                pass

    def _make_target_dns_query(self):
        """Make DNS queries for the target's domain.
        
        This normalizes DNS traffic for the target so later
        DNS-related probes blend in.
        """
        if not self.config.target_ip:
            return

        target = self.config.target_ip
        try:
            # Forward lookup (hostname from IP is normal activity)
            socket.gethostbyaddr(target)
            self._dns_queries += 1
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            logger.debug(f"Baseline target DNS query failed: {e}")

    def _make_dns_query(self):
        """Make a DNS query to a random well-known domain."""
        domain = self._rng.choice(DNS_DOMAINS)
        try:
            txn_id = struct.pack("!H", self._rng.randint(0, 65535))
            flags = b"\x01\x00"
            counts = struct.pack("!4H", 1, 0, 0, 0)
            qname = b""
            for label in domain.split("."):
                qname += struct.pack("B", len(label)) + label.encode()
            qname += b"\x00"
            qtype = struct.pack("!H", 1)
            qclass = struct.pack("!H", 1)
            query = txn_id + flags + counts + qname + qtype + qclass

            resolver = self._rng.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(query, (resolver, 53))
            try:
                sock.recvfrom(512)
            except socket.timeout:
                pass
            sock.close()
            self._dns_queries += 1
        except Exception as e:
            logger.debug(f"Baseline DNS query for {domain} failed: {e}")

    def _make_ntp_query(self):
        """Make an NTP time sync query."""
        try:
            ntp_packet = b"\x1b" + b"\x00" * 47
            servers = ["pool.ntp.org", "time.google.com", "time.windows.com"]
            server = self._rng.choice(servers)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            ip = socket.gethostbyname(server)
            sock.sendto(ntp_packet, (ip, 123))
            try:
                sock.recvfrom(48)
            except socket.timeout:
                pass
            sock.close()
            self._ntp_queries += 1
        except Exception as e:
            logger.debug(f"Baseline NTP query failed: {e}")

    @property
    def stats(self) -> dict:
        return {
            "https_requests": self._requests_made,
            "dns_queries": self._dns_queries,
            "ntp_queries": self._ntp_queries,
            "target_requests": self._target_requests,
            "active": self._active,
        }
