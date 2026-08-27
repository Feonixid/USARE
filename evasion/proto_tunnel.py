"""
Gap 2 — Protocol Encapsulation (Covert Channels)

Encapsulates probes inside legitimate protocol traffic so that
from the network's perspective, all activity looks like normal
HTTPS browsing, DNS resolution, ICMP echo, QUIC, or DoH traffic.

Enhanced with QUIC and DNS-over-HTTPS support for advanced evasion.
"""

import socket
import ssl
import struct
import base64
import random
import time
import logging
import asyncio
import hashlib
from typing import Optional, List, Tuple, Dict, Union
from dataclasses import dataclass, field

try:
    import aioquic.asyncio
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.asyncio.connect import connect
    from aioquic.h0.connection import H0_ALPN
    from aioquic.h3.connection import H3_ALPN
    HAS_QUIC = True
except ImportError:
    HAS_QUIC = False

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

logger = logging.getLogger("usare.tunnel")


@dataclass
class TunnelResult:
    port: int
    is_open: bool
    latency_ms: Optional[float] = None
    method: str = "tunnel"
    error: Optional[str] = None
    response_size: int = 0

    def to_dict(self) -> dict:
        d = {
            "port": self.port,
            "is_open": self.is_open,
            "latency_ms": self.latency_ms,
            "method": self.method,
        }
        if self.error:
            d["error"] = self.error
        if self.response_size:
            d["response_size"] = self.response_size
        return d


class HTTPSTunnel:
    """Encapsulates probes inside real TLS connections.

    Opens a genuine TLS 1.3 connection to the target on 443 and
    sends probes as HTTP payloads. From the network's perspective,
    this is normal HTTPS browsing.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 2,
        ja3_browser: Optional[str] = None,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        # e.g. "chrome", "firefox" — use recon.ja3_rotation TLS stacks (JA3 evasion)
        self._ja3_browser = (ja3_browser or "").strip().lower() or None
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) "
            "Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.2 Safari/605.1.15",
        ]
        self._probes_sent = 0
        self._reusable_conn: Optional[ssl.SSLSocket] = None
        self._reusable_target: Optional[str] = None

    def _create_tls_context(self) -> ssl.SSLContext:
        """Create a TLS context mimicking a real browser (optional JA3-matched stack)."""
        if self._ja3_browser:
            try:
                from recon.ja3_rotation import set_browser_fingerprint, get_ja3_rotator  # type: ignore

                set_browser_fingerprint(self._ja3_browser)
                rot = get_ja3_rotator()
                ctx = rot.create_ssl_context()
                if ctx is not None:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    except (AttributeError, ValueError):
                        pass
                    return ctx
            except Exception as e:
                logger.debug("JA3 TLS context unavailable (%s), using default cipher stack", e)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers(
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES128-GCM-SHA256"
            )
        except ssl.SSLError:
            pass  # Fall back to defaults if ciphers not available
        return ctx

    def _get_connection(self, target: str) -> Optional[ssl.SSLSocket]:
        """Get or create a keep-alive TLS connection."""
        if (self._reusable_conn and self._reusable_target == target):
            try:
                # Test if connection is still alive
                self._reusable_conn.getpeername()
                return self._reusable_conn
            except (OSError, socket.error):
                self._reusable_conn = None
                self._reusable_target = None

        try:
            ctx = self._create_tls_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, 443))
            tls_sock = ctx.wrap_socket(sock, server_hostname=target)
            self._reusable_conn = tls_sock
            self._reusable_target = target
            return tls_sock
        except Exception as e:
            logger.debug(f"TLS connection to {target} failed: {e}")
            # Clean up socket on failure
            try:
                if 'sock' in locals() and sock:
                    sock.close()
            except Exception:
                pass
            return None

    def probe_through_https(self, target: str, probe_port: int,
                            keep_alive: bool = True) -> TunnelResult:
        """Probe a port by sending an HTTPS request through TLS tunnel."""
        start = time.time()
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                tls_sock = self._get_connection(target) if keep_alive else None

                if tls_sock is None:
                    ctx = self._create_tls_context()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target, 443))
                    tls_sock = ctx.wrap_socket(sock, server_hostname=target)

                ua = random.choice(self._user_agents)
                path = f"/{random.randbytes(4).hex()}"

                # Embed probe info in headers that look like normal browser headers
                accept_lang_port = f"en-US,en;q=0.{probe_port % 10}"
                headers = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    f"Accept-Language: {accept_lang_port}\r\n"
                    f"Accept-Encoding: gzip, deflate, br\r\n"
                    f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n"
                    f"Cache-Control: no-cache\r\n"
                    f"X-Request-ID: {probe_port:05d}-{random.randint(10000, 99999)}\r\n"
                    f"\r\n"
                )
                tls_sock.sendall(headers.encode())

                response = b""
                try:
                    response = tls_sock.recv(4096)
                except socket.timeout:
                    pass

                if not keep_alive:
                    tls_sock.close()

                latency = (time.time() - start) * 1000
                self._probes_sent += 1
                is_open = len(response) > 0
                return TunnelResult(
                    port=probe_port, is_open=is_open,
                    latency_ms=latency, method="https_tunnel",
                    response_size=len(response),
                )

            except ConnectionRefusedError:
                return TunnelResult(
                    port=probe_port, is_open=False,
                    latency_ms=None, method="https_tunnel",
                    error="connection_refused",
                )
            except Exception as e:
                last_error = str(e)
                logger.debug(f"HTTPS tunnel attempt {attempt + 1} failed for port {probe_port}: {e}")
                # Clean up connection on failure
                try:
                    if 'tls_sock' in locals() and tls_sock:
                        tls_sock.close()
                except Exception:
                    pass
                self._reusable_conn = None
                self._reusable_target = None
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))

        return TunnelResult(
            port=probe_port, is_open=False,
            latency_ms=None, method="https_tunnel",
            error=last_error,
        )

    def probe_connect_method(self, target: str, probe_port: int,
                             proxy_host: str = "127.0.0.1",
                             proxy_port: int = 8080) -> TunnelResult:
        """Probe via HTTP CONNECT tunnel through a proxy."""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((proxy_host, proxy_port))

            ua = random.choice(self._user_agents)
            connect_req = (
                f"CONNECT {target}:{probe_port} HTTP/1.1\r\n"
                f"Host: {target}:{probe_port}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Proxy-Connection: keep-alive\r\n"
                f"\r\n"
            )
            sock.sendall(connect_req.encode())
            response = sock.recv(4096)
            sock.close()

            latency = (time.time() - start) * 1000
            is_open = b"200" in response
            return TunnelResult(
                port=probe_port, is_open=is_open,
                latency_ms=latency, method="connect_tunnel",
                response_size=len(response),
            )
        except Exception as e:
            logger.debug(f"CONNECT tunnel failed for {target}:{probe_port}: {e}")
            return TunnelResult(
                port=probe_port, is_open=False,
                method="connect_tunnel", error=str(e),
            )

    def close(self):
        """Close any reusable connections."""
        if self._reusable_conn:
            try:
                self._reusable_conn.close()
            except Exception:
                pass
            self._reusable_conn = None
            self._reusable_target = None

    @property
    def stats(self) -> dict:
        return {
            "probes_sent": self._probes_sent,
            "method": "https_tunnel",
            "has_keep_alive": self._reusable_conn is not None,
        }


class QUICTunnel:
    """Encapsulates probes inside QUIC connections.
    
    QUIC provides excellent evasion as it's UDP-based and encrypted,
    making it harder for traditional firewalls to inspect.
    
    Uses manual packet construction as primary implementation
    with aioquic as optional enhancement when available.
    """
    
    def __init__(self, timeout: float = 10.0, max_retries: int = 2, target_ip: Optional[str] = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self._probes_sent = 0
        self.target_ip = target_ip
        
    def probe_through_quic(self, target: str, probe_port: int) -> TunnelResult:
        """Send probe through QUIC tunnel.
        
        Tries aioquic first if available, falls back to manual packet construction.
        """
        if HAS_QUIC:
            try:
                return self._probe_with_aioquic(target, probe_port)
            except Exception as e:
                logger.debug(f"[USARE] aioquic failed, falling back to manual: {e}")
        
        # Fallback to manual packet construction
        return self._probe_with_manual_quic(target, probe_port)
    
    def _probe_with_aioquic(self, target: str, probe_port: int) -> TunnelResult:
        """Use aioquic library for real QUIC connections."""
        start_time = time.time()
        
        # Create QUIC configuration
        if HAS_QUIC:
            configuration = QuicConfiguration(
                is_client=True,
                alpn_protocols=H3_ALPN,
                supported_versions=[0x00000001],  # QUIC v1
            )
        else:
            return TunnelResult(
                port=probe_port,
                is_open=False,
                latency_ms=0,
                method="quic_tunnel",
                error="aioquic not available"
            )
        
        # Connect via QUIC to target's port 443 or 80
        quic_port = 443 if probe_port == 443 else 80
        
        # Use asyncio to run QUIC connection
        async def _quic_probe():
            try:
                if HAS_QUIC:
                    async with connect(target, quic_port, configuration=configuration) as protocol:
                        # If we reach here, the QUIC handshake succeeded (port is open)
                        return TunnelResult(
                            port=probe_port,
                            is_open=True,
                            latency_ms=(time.time() - start_time) * 1000,
                            method="quic_tunnel",
                            response_size=0
                        )
            except Exception as e:
                return TunnelResult(
                    port=probe_port,
                    is_open=False,
                    method="quic_tunnel",
                    error=str(e)
                )
        
        # Run async function in sync context
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(_quic_probe())
    
    def _probe_with_manual_quic(self, target: str, probe_port: int, custom_payload: bytes = b"") -> TunnelResult:
        """Use manual QUIC-like packet construction."""
        import os
        import struct
        
        self._probes_sent += 1
        
        # Construct mock QUIC Initial Packet Header (Long Header)
        # 11000000 (0xc0) = Long header, Initial, version specific bits
        header_form = b"\xc0"
        version = b"\x00\x00\x00\x01"  # QUIC v1
        
        # Dest Connection ID (8 bytes random), Source Connection ID (8 bytes)
        dcil = b"\x08"
        dcid = os.urandom(8)
        scil = b"\x08"
        scid = os.urandom(8)
        
        # Token length (0), Length (mock 1200 bytes), Packet Num (0)
        token_len = b"\x00"
        length = struct.pack(">H", 1200) # Encoded length
        pkt_num = b"\x00\x00\x00\x00"
        
        # Encapsulate target metadata inside mock encrypted payload frame
        payload_marker = f"PROBE:{target}:{probe_port}".encode('utf-8')
        mock_crypto = os.urandom(1200 - len(payload_marker)) + payload_marker
        
        quic_pkt = header_form + version + dcil + dcid + scil + scid + token_len + length + pkt_num + mock_crypto
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            start_time = time.time()
            
            # Send to target on UDP/443 (common QUIC port)
            sock.sendto(quic_pkt, (target, 443))
            
            # Try to receive response (most firewalls won't respond)
            try:
                response = sock.recvfrom(1500)[0]
                response_time = (time.time() - start_time) * 1000
                return TunnelResult(
                    port=probe_port,
                    is_open=True,
                    latency_ms=response_time,
                    method="quic_tunnel",
                    response_size=len(response)
                )
            except socket.timeout:
                # Timeout means no response - port is filtered/closed
                return TunnelResult(
                    port=probe_port,
                    is_open=False,
                    latency_ms=(time.time() - start_time) * 1000,
                    method="quic_tunnel",
                    error="timeout"
                )
        except Exception as e:
            return TunnelResult(
                port=probe_port,
                is_open=False,
                method="quic_tunnel",
                error=str(e)
            )
        finally:
            try:
                if 'sock' in locals() and sock:
                    sock.close()
            except:
                pass
    
    @property
    def stats(self) -> dict:
        return {
            "probes_sent": self._probes_sent,
            "method": "quic_tunnel",
            "has_aioquic": HAS_QUIC,
            "target_ip": self.target_ip
        }

class DNSTunnel:
    """Encapsulates probes inside DNS queries.

    Probe data is encoded in DNS subdomains. Supports both
    A record and TXT record queries for larger payload capacity.
    """

    def __init__(self, dns_server: str = "8.8.8.8", timeout: float = 5.0):
        self.dns_server = dns_server
        self.timeout = timeout
        self._queries_sent = 0
        self._rng = random.SystemRandom()

    def probe_via_dns(self, target: str, probe_port: int,
                      query_type: str = "A") -> TunnelResult:
        """Probe using DNS query encapsulation."""
        start = time.time()
        try:
            encoded_probe = base64.b32encode(
                f"{target}:{probe_port}".encode()
            ).decode().lower().rstrip("=")

            # Split into valid DNS labels (max 63 chars each)
            labels = [encoded_probe[i:i+63] for i in range(0, len(encoded_probe), 63)]
            query_name = ".".join(labels) + ".probe.local"

            if query_type == "TXT":
                qtype_num = 16  # TXT record
            elif query_type == "CNAME":
                qtype_num = 5   # CNAME record
            else:
                qtype_num = 1   # A record

            query_packet = self._build_dns_query(query_name, qtype=qtype_num)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(query_packet, (self.dns_server, 53))

            try:
                response, _ = sock.recvfrom(4096)  # Larger buffer for TXT
                latency = (time.time() - start) * 1000
                self._queries_sent += 1
                rcode = response[3] & 0x0F if len(response) > 3 else 5
                is_open = rcode == 0
                return TunnelResult(
                    port=probe_port, is_open=is_open,
                    latency_ms=latency, method="dns_tunnel",
                    response_size=len(response),
                )
            except socket.timeout:
                return TunnelResult(
                    port=probe_port, is_open=False,
                    method="dns_tunnel", error="timeout",
                )
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"DNS tunnel probe failed for {target}:{probe_port}: {e}")
            return TunnelResult(
                port=probe_port, is_open=False,
                method="dns_tunnel", error=str(e),
            )

    def probe_via_txt(self, target: str, probe_port: int) -> TunnelResult:
        """Probe using TXT record queries for larger capacity."""
        return self.probe_via_dns(target, probe_port, query_type="TXT")

    def _build_dns_query(self, name: str, qtype: int = 1) -> bytes:
        """Build a DNS query packet with randomized transaction ID."""
        txn_id = struct.pack("!H", self._rng.randint(0, 65535))
        flags = b"\x01\x00"  # Standard query with recursion desired
        counts = struct.pack("!4H", 1, 0, 0, 0)

        qname = b""
        for label in name.split("."):
            if len(label) > 63:
                label = label[:63]
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"

        qtype_bytes = struct.pack("!H", qtype)
        qclass = struct.pack("!H", 1)  # IN class

        return txn_id + flags + counts + qname + qtype_bytes + qclass

    @property
    def stats(self) -> dict:
        return {
            "queries_sent": self._queries_sent,
            "method": "dns_tunnel",
            "dns_server": self.dns_server,
        }


class ICMPTunnel:
    """Encapsulates probes inside ICMP echo (ping) packets.

    Embeds probe data in the ICMP payload. From the network's
    perspective, this looks like normal ping traffic.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._probes_sent = 0
        self._rng = random.SystemRandom()

    def probe_via_icmp(self, target: str, probe_port: int) -> TunnelResult:
        """Encapsulate a probe inside an ICMP echo request."""
        start = time.time()
        try:
            # Build ICMP echo with probe data in payload
            icmp_type = 8   # Echo request
            icmp_code = 0
            icmp_id = self._rng.randint(1, 65535)
            icmp_seq = probe_port & 0xFFFF

            # Probe data hidden in the ICMP payload
            # Looks like normal Windows ping data
            probe_data = b"abcdefghijklmnop"  # Windows-like ping payload
            probe_data += struct.pack("!H", probe_port)
            probe_data += random.randbytes(14)  # Pad to 32 bytes

            # Build ICMP header
            header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)

            # Calculate checksum
            packet = header + probe_data
            checksum = self._icmp_checksum(packet)
            header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            packet = header + probe_data

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (target, 0))

            try:
                response, addr = sock.recvfrom(1024)
                latency = (time.time() - start) * 1000
                self._probes_sent += 1

                # Check if we got an echo reply
                if len(response) >= 28:
                    icmp_reply_type = response[20]
                    is_alive = icmp_reply_type == 0  # Echo reply
                    return TunnelResult(
                        port=probe_port, is_open=is_alive,
                        latency_ms=latency, method="icmp_tunnel",
                        response_size=len(response),
                    )
            except socket.timeout:
                pass
            finally:
                sock.close()

            return TunnelResult(
                port=probe_port, is_open=False,
                method="icmp_tunnel", error="timeout",
            )

        except PermissionError:
            logger.warning("ICMP tunnel requires raw socket privileges (admin/root)")
            return TunnelResult(
                port=probe_port, is_open=False,
                method="icmp_tunnel", error="permission_denied",
            )
        except Exception as e:
            logger.debug(f"ICMP tunnel probe failed for {target}:{probe_port}: {e}")
            return TunnelResult(
                port=probe_port, is_open=False,
                method="icmp_tunnel", error=str(e),
            )

    @staticmethod
    def _icmp_checksum(data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    @property
    def stats(self) -> dict:
        return {
            "probes_sent": self._probes_sent,
            "method": "icmp_tunnel",
        }


class DoHTunnel:
    """
    Enhanced DNS over HTTPS (RFC 8484) Tunnel.
    
    Encapsulates probes inside standard encrypted HTTPS sessions to public resolvers.
    Supports multiple DoH providers and advanced evasion techniques.
    """
    
    def __init__(self, target_ip: str = "1.1.1.1", doh_provider: str = "cloudflare", timeout: float = 5.0):
        self.target_ip = target_ip
        self.doh_provider = doh_provider.lower()
        self.timeout = timeout
        self._probes_sent = 0
        
        # DoH provider configurations
        self.doh_resolvers = {
            "cloudflare": {
                "host": "cloudflare-dns.com",
                "path": "/dns-query",
                "ip": "1.1.1.1"
            },
            "google": {
                "host": "dns.google",
                "path": "/resolve",
                "ip": "8.8.8.8"
            },
            "quad9": {
                "host": "dns.quad9.net",
                "path": "/dns-query",
                "ip": "9.9.9.9"
            },
            "cloudflare-security": {
                "host": "security.cloudflare-dns.com",
                "path": "/dns-query",
                "ip": "1.1.1.2"
            }
        }
        
        self.current_resolver = self.doh_resolvers.get(self.doh_provider, self.doh_resolvers["cloudflare"])
        
    def probe_via_doh(self, target: str, probe_port: int, custom_payload: bytes = b"") -> TunnelResult:
        """Send probe through DNS-over-HTTPS tunnel."""
        start_time = time.time()
        sock = None
        ssock = None
        
        try:
            # Build DNS query for probe
            dns_query = self._build_probe_dns_query(target, probe_port)
            
            # Encode for DoH GET request
            b64_query = base64.urlsafe_b64encode(dns_query).decode('utf-8').rstrip("=")
            
            # Create HTTPS request
            request = self._build_doh_request(b64_query)
            
            # Create SSL context
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Connect and send request
            sock = socket.create_connection((self.current_resolver["ip"], 443), timeout=self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.current_resolver["host"])
            
            ssock.sendall(request)
            response = ssock.recv(8192)
            
            latency = (time.time() - start_time) * 1000
            self._probes_sent += 1
            
            # Parse response
            is_open = self._parse_doh_response(response, probe_port)
            
            return TunnelResult(
                port=probe_port,
                is_open=is_open,
                latency_ms=latency,
                method="doh_tunnel",
                response_size=len(response)
            )
            
        except Exception as e:
            return TunnelResult(
                port=probe_port,
                is_open=False,
                method="doh_tunnel",
                error=str(e)
            )
        finally:
            # Clean up connections
            try:
                if ssock:
                    ssock.close()
                if sock:
                    sock.close()
            except Exception:
                pass
    
    def _build_probe_dns_query(self, target: str, probe_port: int) -> bytes:
        """Build DNS query with embedded probe data."""
        if HAS_DNS:
            # Use dnspython for proper DNS query construction
            query = dns.message.make_query(f"{probe_port}.probe.{target}", dns.rdatatype.A)
            query.flags |= dns.flags.RD  # Recursion desired
            return query.to_wire()
        else:
            # Fallback manual DNS construction
            # DNS header: ID=0x1337, QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
            header = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
            
            # QNAME: {probe_port}.probe.{target}
            qname = b""
            for label in [str(probe_port), "probe", target]:
                qname += bytes([len(label)]) + label.encode('utf-8')
            qname += b"\x00"
            
            # Question: QTYPE=A (1), QCLASS=IN (1)
            question = qname + struct.pack("!HH", 1, 1)
            
            return header + question
    
    def _build_doh_request(self, b64_query: str) -> bytes:
        """Build DoH HTTPS GET request."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
        ]
        
        ua = random.choice(user_agents)
        
        request = (
            f"GET {self.current_resolver['path']}?dns={b64_query} HTTP/1.1\r\n"
            f"Host: {self.current_resolver['host']}\r\n"
            f"Accept: application/dns-message\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: application/dns-json\r\n"
            f"Connection: close\r\n"
            f"Cache-Control: max-age=0\r\n"
            f"\r\n"
        )
        
        return request.encode('utf-8')
    
    def _parse_doh_response(self, response: bytes, probe_port: int) -> bool:
        """Parse DoH response to determine if port is open.
        
        Fixed implementation that properly handles binary DNS wire format
        instead of incorrectly looking for base64-encoded data.
        """
        try:
            # Find HTTP body boundary (\r\n\r\n separates headers from body)
            header_end = response.find(b'\r\n\r\n')
            if header_end == -1:
                return False
            
            # Extract the DNS message body (binary wire format)
            dns_body = response[header_end + 4:]
            
            # Check for successful HTTP response first
            response_headers = response[:header_end].decode('utf-8', errors='ignore')
            if "200 OK" not in response_headers:
                return False
            
            # Parse DNS response if dnspython is available
            if HAS_DNS:
                try:
                    dns_resp = dns.message.from_wire(dns_body)
                    # Check if we got any answers (indicates successful DNS resolution)
                    return len(dns_resp.answer) > 0
                except Exception:
                    # If DNS parsing fails, fall back to size check
                    pass
            
            # Fallback: Check if DNS body is reasonable size
            # Minimum DNS response is 12 bytes (header) + some data
            return len(dns_body) > 12
            
        except Exception as e:
            logger.debug(f"[USARE] DoH response parsing failed: {e}")
            return False
    
    def switch_provider(self, provider: str) -> bool:
        """Switch to different DoH provider."""
        if provider.lower() in self.doh_resolvers:
            self.doh_provider = provider.lower()
            self.current_resolver = self.doh_resolvers[provider.lower()]
            return True
        return False
    
    @property
    def stats(self) -> dict:
        return {
            "probes_sent": self._probes_sent,
            "method": "doh_tunnel",
            "provider": self.doh_provider,
            "resolver": self.current_resolver["host"]
        }


def create_tunnel(tunnel_type: str, **kwargs):
    """Factory function to create the appropriate tunnel."""
    if tunnel_type == "https":
        return HTTPSTunnel(**kwargs)
    elif tunnel_type == "dns":
        return DNSTunnel(**kwargs)
    elif tunnel_type == "icmp":
        return ICMPTunnel(**kwargs)
    elif tunnel_type == "doh":
        return DoHTunnel(**kwargs)
    elif tunnel_type == "quic":
        return QUICTunnel(**kwargs)
    else:
        raise ValueError(f"Unknown tunnel type: {tunnel_type}")
