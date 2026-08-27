"""
USARE TLS 1.3 0-RTT Probing

True 0-RTT early data probing via openssl CLI.

Python's ssl module can't send early_data in the ClientHello extension.
Real 0-RTT requires sending application data BEFORE the handshake
completes — this must be done at the TLS record layer, not after
wrap_socket(). We use openssl s_client -early_data for this.

Key evasion properties:
- Many IDS systems don't inspect 0-RTT data at all
- The probe data arrives before the handshake finishes
- If the server rejects early data, the probe is invisible
"""

import subprocess
import tempfile
import socket
import ssl
import time
import os
import logging
from typing import Dict, Optional, Any, List
from dataclasses import dataclass

logger = logging.getLogger("usare.tls_0rtt")


@dataclass
class ZeroRTTResult:
    """Result of a TLS 1.3 0-RTT probe."""
    port: int
    supports_tls13: bool = False
    supports_0rtt: bool = False
    early_data_accepted: bool = False
    response_data: bytes = b""
    tls_version: str = ""
    cipher_suite: str = ""
    session_ticket: bool = False
    latency_ms: float = 0.0
    error: str = ""
    method: str = ""  # "openssl" or "fallback"

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "supports_tls13": self.supports_tls13,
            "supports_0rtt": self.supports_0rtt,
            "early_data_accepted": self.early_data_accepted,
            "response_preview": self.response_data[:200].decode("utf-8", errors="replace"),
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "latency_ms": round(self.latency_ms, 2),
            "method": self.method,
        }


def _check_openssl() -> bool:
    """Check if openssl CLI supports -early_data."""
    try:
        r = subprocess.run(
            ["openssl", "s_client", "-help"],
            capture_output=True, text=True, timeout=5
        )
        return "-early_data" in r.stderr or "-early_data" in r.stdout
    except Exception:
        return False


HAS_OPENSSL_0RTT = _check_openssl()


class TLS0RTTProber:
    """
    TLS 1.3 Early Data (0-RTT) prober.

    Two-phase approach:
    1. openssl s_client -sess_out   → get session ticket with TLS 1.3
    2. openssl s_client -sess_in -early_data → send early data on reconnect

    Falls back to Python ssl for basic TLS 1.3 detection if openssl
    doesn't support -early_data.
    """

    PROBE_PAYLOADS = {
        "http": "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        "http_head": "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._session_dir = tempfile.mkdtemp(prefix="usare_tls_")

    def probe(self, target: str, port: int,
              probe_type: str = "http") -> ZeroRTTResult:
        """Attempt real TLS 1.3 0-RTT probe."""
        if HAS_OPENSSL_0RTT:
            return self._probe_openssl(target, port, probe_type)
        return self._probe_fallback(target, port)

    def _probe_openssl(self, target: str, port: int,
                       probe_type: str) -> ZeroRTTResult:
        """Real 0-RTT via openssl s_client."""
        t0 = time.time()
        result = ZeroRTTResult(port=port, method="openssl")
        sess_file = os.path.join(self._session_dir, f"{target}_{port}.sess")

        try:
            # Phase 1: Get session ticket
            phase1 = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{target}:{port}",
                    "-tls1_3",
                    "-sess_out", sess_file,
                    "-brief",
                ],
                input=b"",
                capture_output=True,
                timeout=self.timeout,
            )

            p1_output = phase1.stdout.decode("utf-8", errors="replace") + \
                         phase1.stderr.decode("utf-8", errors="replace")

            if "TLSv1.3" in p1_output:
                result.supports_tls13 = True
            else:
                result.tls_version = "pre-1.3"
                result.latency_ms = (time.time() - t0) * 1000
                return result

            # Extract cipher
            for line in p1_output.split("\n"):
                if "Ciphersuite:" in line:
                    result.cipher_suite = line.split("Ciphersuite:")[1].strip()
                    break

            if not os.path.exists(sess_file):
                result.session_ticket = False
                result.error = "no_session_ticket"
                result.latency_ms = (time.time() - t0) * 1000
                return result

            result.session_ticket = True

            # Phase 2: Send early data with session ticket
            payload = self.PROBE_PAYLOADS.get(probe_type, "")
            payload = payload.replace("{host}", target)

            early_file = os.path.join(self._session_dir, f"{target}_{port}.early")
            with open(early_file, "w") as f:
                f.write(payload)

            phase2 = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{target}:{port}",
                    "-tls1_3",
                    "-sess_in", sess_file,
                    "-early_data", early_file,
                    "-brief",
                ],
                input=b"",
                capture_output=True,
                timeout=self.timeout,
            )

            p2_output = phase2.stdout.decode("utf-8", errors="replace") + \
                         phase2.stderr.decode("utf-8", errors="replace")

            if "Early data was accepted" in p2_output:
                result.supports_0rtt = True
                result.early_data_accepted = True
            elif "Early data was rejected" in p2_output:
                result.supports_0rtt = False
                result.early_data_accepted = False

            # Capture server response after early data
            result.response_data = phase2.stdout
            result.tls_version = "TLSv1.3"

            # Cleanup
            for f in (sess_file, early_file):
                try:
                    os.unlink(f)
                except Exception:
                    pass

        except subprocess.TimeoutExpired:
            result.error = "timeout"
        except Exception as e:
            result.error = str(e)

        result.latency_ms = (time.time() - t0) * 1000
        return result

    def _probe_fallback(self, target: str, port: int) -> ZeroRTTResult:
        """Fallback: basic TLS 1.3 detection without real 0-RTT."""
        t0 = time.time()
        result = ZeroRTTResult(port=port, method="fallback")

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            except (AttributeError, ValueError):
                pass

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            tls_sock = ctx.wrap_socket(sock, server_hostname=target)

            version = tls_sock.version()
            if version and "TLSv1.3" in version:
                result.supports_tls13 = True
                result.tls_version = version

            cipher = tls_sock.cipher()
            if cipher:
                result.cipher_suite = cipher[0]

            tls_sock.close()
            result.error = "0rtt_not_available_without_openssl"

        except Exception as e:
            result.error = str(e)

        result.latency_ms = (time.time() - t0) * 1000
        return result

    def batch_probe(self, target: str, ports: List[int],
                    probe_type: str = "http") -> List[ZeroRTTResult]:
        """Probe multiple ports."""
        return [self.probe(target, port, probe_type) for port in ports]
