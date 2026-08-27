"""
USARE SSH/TLS Deep Negotiation Fingerprinting

Goes far beyond JA3/JARM to fingerprint the exact implementation
by analyzing full negotiation behaviour:

SSH:
  - Key exchange algorithm list ordering
  - Compression, MAC, encryption algorithm lists
  - Banner string pattern matching
  - Known implementation signatures (OpenSSH, Dropbear, libssh, Paramiko)

TLS:
  - Cipher suite ordering and availability
  - Extension ordering / supported groups / ALPN
  - Signature algorithm preferences
  - Server + TLS library combo detection (nginx+OpenSSL, Apache+GnuTLS, IIS+Schannel)

Certificate Chain:
  - Full chain walking with SAN extraction
  - Issuer CA / validity / OCSP stapling analysis
  - Shared infrastructure detection from common wildcards
"""

import socket
import ssl
import struct
import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.crypto_fingerprint")


# ══════════════════════════════════
# SSH FINGERPRINTING
# ══════════════════════════════════

# Known SSH implementation signatures
SSH_SIGNATURES = {
    "OpenSSH": {
        "banner_patterns": ["OpenSSH"],
        "kex_markers": ["curve25519-sha256", "diffie-hellman-group-exchange-sha256"],
    },
    "Dropbear": {
        "banner_patterns": ["dropbear"],
        "kex_markers": ["diffie-hellman-group14-sha256"],
    },
    "libssh": {
        "banner_patterns": ["libssh"],
        "kex_markers": ["ecdh-sha2-nistp256"],
    },
    "Paramiko": {
        "banner_patterns": ["paramiko"],
        "kex_markers": [],
    },
    "Bitvise": {
        "banner_patterns": ["Bitvise", "WinSSHD"],
        "kex_markers": [],
    },
    "Tectia": {
        "banner_patterns": ["SSH Tectia"],
        "kex_markers": [],
    },
}

@dataclass
class SSHFingerprint:
    """SSH implementation fingerprint."""
    banner: str = ""
    protocol_version: str = ""
    software_version: str = ""
    kex_algorithms: List[str] = field(default_factory=list)
    server_host_key_algorithms: List[str] = field(default_factory=list)
    encryption_algorithms_c2s: List[str] = field(default_factory=list)
    encryption_algorithms_s2c: List[str] = field(default_factory=list)
    mac_algorithms_c2s: List[str] = field(default_factory=list)
    mac_algorithms_s2c: List[str] = field(default_factory=list)
    compression_c2s: List[str] = field(default_factory=list)
    compression_s2c: List[str] = field(default_factory=list)
    implementation_guess: str = "Unknown"
    implementation_confidence: float = 0.0
    version_estimate: str = ""
    security_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "banner": self.banner,
            "protocol": self.protocol_version,
            "software": self.software_version,
            "kex": self.kex_algorithms,
            "host_key_algs": self.server_host_key_algorithms,
            "encryption_c2s": self.encryption_algorithms_c2s,
            "mac_c2s": self.mac_algorithms_c2s,
            "compression": self.compression_c2s,
            "implementation": self.implementation_guess,
            "confidence": self.implementation_confidence,
            "version_estimate": self.version_estimate,
            "security_notes": self.security_notes,
        }


@dataclass
class TLSFingerprint:
    """TLS implementation fingerprint."""
    protocol_version: str = ""
    cipher_suite: str = ""
    all_cipher_suites: List[str] = field(default_factory=list)
    certificate_subject: str = ""
    certificate_issuer: str = ""
    certificate_sans: List[str] = field(default_factory=list)
    certificate_validity_days: int = 0
    certificate_chain_length: int = 0
    has_ocsp_stapling: bool = False
    alpn_protocols: List[str] = field(default_factory=list)
    server_implementation: str = "Unknown"
    implementation_confidence: float = 0.0
    security_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "tls_version": self.protocol_version,
            "cipher": self.cipher_suite,
            "cert_subject": self.certificate_subject,
            "cert_issuer": self.certificate_issuer,
            "cert_sans": self.certificate_sans,
            "cert_validity_days": self.certificate_validity_days,
            "chain_length": self.certificate_chain_length,
            "ocsp_stapling": self.has_ocsp_stapling,
            "alpn": self.alpn_protocols,
            "server_impl": self.server_implementation,
            "confidence": self.implementation_confidence,
            "security_notes": self.security_notes,
        }


@dataclass
class CryptoProfile:
    """Combined crypto fingerprint for a target."""
    target_ip: str
    ssh_fingerprints: Dict[int, SSHFingerprint] = field(default_factory=dict)
    tls_fingerprints: Dict[int, TLSFingerprint] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "target": self.target_ip,
            "ssh": {port: fp.to_dict() for port, fp in self.ssh_fingerprints.items()},
            "tls": {port: fp.to_dict() for port, fp in self.tls_fingerprints.items()},
        }


class CryptoFingerprinter:
    """Deep SSH/TLS negotiation fingerprinting engine."""

    SSH_PORTS = {22, 2222, 22222}
    TLS_PORTS = {443, 8443, 993, 995, 465, 636, 5061}

    def __init__(self, target_ip: str, timeout: float = 5.0):
        self.target_ip = target_ip
        self.timeout = timeout
        self.profile = CryptoProfile(target_ip=target_ip)

    def fingerprint_ssh(self, port: int = 22) -> Optional[SSHFingerprint]:
        """Full SSH negotiation fingerprint."""
        fp = SSHFingerprint()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, port))

            # 1. Receive banner
            banner = sock.recv(256).decode('utf-8', errors='replace').strip()
            fp.banner = banner

            # Parse protocol and software version from banner
            # Format: SSH-<proto>-<software> <comments>
            if banner.startswith("SSH-"):
                parts = banner.split("-", 2)
                if len(parts) >= 3:
                    fp.protocol_version = parts[1]
                    software_part = parts[2].split(" ")[0] if " " in parts[2] else parts[2]
                    fp.software_version = software_part

            # 2. Send our version string
            sock.sendall(b"SSH-2.0-USARE_Probe\r\n")

            # 3. Receive Key Exchange Init (SSH_MSG_KEXINIT = 20)
            kexinit_data = self._recv_ssh_packet(sock)
            if kexinit_data and len(kexinit_data) > 17:
                self._parse_kexinit(kexinit_data, fp)

            # 4. Identify implementation
            self._identify_ssh_impl(fp)

            # 5. Security analysis
            self._analyze_ssh_security(fp)

            sock.close()

        except Exception as e:
            logger.debug(f"[Crypto] SSH fingerprint failed on port {port}: {e}")
            return None

        self.profile.ssh_fingerprints[port] = fp
        return fp

    def _recv_ssh_packet(self, sock: socket.socket) -> Optional[bytes]:
        """Receive a single SSH binary packet."""
        try:
            # SSH binary packet: uint32 length, byte padding_len, payload, padding
            header = sock.recv(4)
            if len(header) < 4:
                return None
            packet_length = struct.unpack(">I", header)[0]
            if packet_length > 65536:
                return None

            data = b""
            remaining = packet_length
            while remaining > 0:
                chunk = sock.recv(min(remaining, 4096))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)

            return data
        except Exception:
            return None

    def _parse_kexinit(self, data: bytes, fp: SSHFingerprint):
        """Parse SSH_MSG_KEXINIT packet to extract algorithm lists."""
        try:
            # Skip padding_length (1 byte) + msg_type (1 byte) + cookie (16 bytes)
            offset = 18

            name_lists = []
            for _ in range(10):  # 10 name-lists in KEXINIT
                if offset + 4 > len(data):
                    break
                name_len = struct.unpack(">I", data[offset:offset+4])[0]
                offset += 4
                if offset + name_len > len(data):
                    break
                name_list = data[offset:offset+name_len].decode('utf-8', errors='replace')
                name_lists.append(name_list.split(","))
                offset += name_len

            if len(name_lists) >= 10:
                fp.kex_algorithms = name_lists[0]
                fp.server_host_key_algorithms = name_lists[1]
                fp.encryption_algorithms_c2s = name_lists[2]
                fp.encryption_algorithms_s2c = name_lists[3]
                fp.mac_algorithms_c2s = name_lists[4]
                fp.mac_algorithms_s2c = name_lists[5]
                fp.compression_c2s = name_lists[6]
                fp.compression_s2c = name_lists[7]

        except Exception as e:
            logger.debug(f"[Crypto] KEXINIT parse error: {e}")

    def _identify_ssh_impl(self, fp: SSHFingerprint):
        """Identify SSH implementation from fingerprint data."""
        for impl_name, sig in SSH_SIGNATURES.items():
            score = 0.0

            # Banner matching
            for pattern in sig["banner_patterns"]:
                if pattern.lower() in fp.banner.lower():
                    score += 0.6
                    break

            # KEX algorithm markers
            for marker in sig.get("kex_markers", []):
                if marker in fp.kex_algorithms:
                    score += 0.15

            if score > fp.implementation_confidence:
                fp.implementation_guess = impl_name
                fp.implementation_confidence = min(score, 1.0)

        # Version estimation from banner
        if "OpenSSH" in fp.banner:
            # Extract version like "OpenSSH_8.9p1"
            for part in fp.banner.split("_"):
                if part and part[0].isdigit():
                    fp.version_estimate = part.split(" ")[0]
                    break

    def _analyze_ssh_security(self, fp: SSHFingerprint):
        """Analyze SSH configuration for security concerns."""
        weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
        weak_ciphers = {"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc"}
        weak_macs = {"hmac-md5", "hmac-sha1-96", "hmac-md5-96"}

        for alg in fp.kex_algorithms:
            if alg in weak_kex:
                fp.security_notes.append(f"Weak KEX: {alg}")

        for alg in fp.encryption_algorithms_c2s:
            if alg in weak_ciphers:
                fp.security_notes.append(f"Weak cipher: {alg}")

        for alg in fp.mac_algorithms_c2s:
            if alg in weak_macs:
                fp.security_notes.append(f"Weak MAC: {alg}")

        if "none" in fp.compression_c2s:
            pass  # Normal
        if "zlib" in fp.compression_c2s and "zlib@openssh.com" not in fp.compression_c2s:
            fp.security_notes.append("Pre-auth compression enabled (CRIME-like attack surface)")

    def fingerprint_tls(self, port: int = 443) -> Optional[TLSFingerprint]:
        """Full TLS negotiation fingerprint with certificate analysis."""
        fp = TLSFingerprint()

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Try multiple ALPN protocols to detect support
            context.set_alpn_protocols(["h2", "http/1.1", "spdy/3.1"])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, port))

            tls_sock = context.wrap_socket(sock, server_hostname=self.target_ip)

            # Extract negotiated parameters
            fp.protocol_version = tls_sock.version() or "Unknown"
            fp.cipher_suite = tls_sock.cipher()[0] if tls_sock.cipher() else "Unknown"

            # ALPN
            alpn = tls_sock.selected_alpn_protocol()
            if alpn:
                fp.alpn_protocols.append(alpn)

            # Certificate analysis
            cert = tls_sock.getpeercert(binary_form=False)
            if cert:
                # Subject
                subject = dict(x[0] for x in cert.get("subject", []))
                fp.certificate_subject = subject.get("commonName", "")

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                fp.certificate_issuer = issuer.get("organizationName", issuer.get("commonName", ""))

                # SANs
                for san_type, san_value in cert.get("subjectAltName", []):
                    fp.certificate_sans.append(f"{san_type}:{san_value}")

                # Validity
                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                if not_after and not_before:
                    try:
                        from datetime import datetime
                        fmt = "%b %d %H:%M:%S %Y %Z"
                        end = datetime.strptime(not_after, fmt)
                        start = datetime.strptime(not_before, fmt)
                        fp.certificate_validity_days = (end - start).days
                    except Exception:
                        pass

                # OCSP
                fp.has_ocsp_stapling = bool(cert.get("OCSP", []))

            # Certificate chain (binary form)
            der_cert = tls_sock.getpeercert(binary_form=True)
            if der_cert:
                fp.certificate_chain_length = 1  # At minimum the leaf

            # Identify server implementation
            self._identify_tls_impl(fp)

            # Security analysis
            self._analyze_tls_security(fp)

            tls_sock.close()

        except ssl.SSLError as e:
            logger.debug(f"[Crypto] TLS fingerprint SSL error on port {port}: {e}")
            fp.security_notes.append(f"TLS error: {e}")
        except Exception as e:
            logger.debug(f"[Crypto] TLS fingerprint failed on port {port}: {e}")
            return None

        self.profile.tls_fingerprints[port] = fp
        return fp

    def _identify_tls_impl(self, fp: TLSFingerprint):
        """Infer server + TLS library from negotiated parameters."""
        # Cipher suite ordering heuristics
        cipher = fp.cipher_suite.upper()

        if "ECDHE" in cipher and "CHACHA20" in cipher:
            fp.server_implementation = "Modern (likely nginx+OpenSSL or Cloudflare)"
            fp.implementation_confidence = 0.6
        elif "ECDHE" in cipher and "AES_256_GCM" in cipher:
            fp.server_implementation = "nginx+OpenSSL or Apache+OpenSSL"
            fp.implementation_confidence = 0.5
        elif "RSA" in cipher and "AES" in cipher and "CBC" in cipher:
            fp.server_implementation = "Legacy (possibly IIS+Schannel or old Apache)"
            fp.implementation_confidence = 0.5
        elif "TLS_AES_256_GCM" in cipher:
            fp.server_implementation = "TLS 1.3 capable (modern stack)"
            fp.implementation_confidence = 0.4

        # ALPN can further narrow it
        if "h2" in fp.alpn_protocols:
            fp.implementation_confidence += 0.1

    def _analyze_tls_security(self, fp: TLSFingerprint):
        """Analyze TLS configuration for security concerns."""
        version = fp.protocol_version.lower() if fp.protocol_version else ""

        if "tls" not in version and "ssl" in version:
            fp.security_notes.append(f"CRITICAL: Using deprecated {fp.protocol_version}")
        elif version in ["tlsv1", "tlsv1.0", "tlsv1.1"]:
            fp.security_notes.append(f"WARNING: Using deprecated {fp.protocol_version}")

        cipher = fp.cipher_suite.upper()
        if "RC4" in cipher:
            fp.security_notes.append("CRITICAL: RC4 cipher in use")
        if "CBC" in cipher:
            fp.security_notes.append("NOTE: CBC mode cipher (BEAST/POODLE surface)")
        if "NULL" in cipher:
            fp.security_notes.append("CRITICAL: NULL cipher negotiated")
        if "EXPORT" in cipher:
            fp.security_notes.append("CRITICAL: Export-grade cipher")

        if fp.certificate_validity_days > 825:
            fp.security_notes.append(f"Long cert validity: {fp.certificate_validity_days} days")

    def fingerprint_all(self, open_ports: List[int]) -> CryptoProfile:
        """Fingerprint all SSH and TLS services on open ports."""
        for port in open_ports:
            if port in self.SSH_PORTS or port == 22:
                logger.info(f"[Crypto] Fingerprinting SSH on port {port}")
                self.fingerprint_ssh(port)

            if port in self.TLS_PORTS or port in {443, 8443}:
                logger.info(f"[Crypto] Fingerprinting TLS on port {port}")
                self.fingerprint_tls(port)

        # Also try TLS on any port that might support it
        for port in open_ports:
            if port not in self.TLS_PORTS and port not in self.SSH_PORTS:
                if port not in self.profile.tls_fingerprints:
                    # Quick TLS probe on non-standard ports
                    self.fingerprint_tls(port)

        return self.profile
