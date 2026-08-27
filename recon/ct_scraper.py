"""
USARE Certificate Transparency Log Scraper

Queries crt.sh and Google CT logs pre-scan to discover:
- Subdomains from certificate SANs
- Historical certificates (issuance timeline)
- Certificate issuers (Let's Encrypt vs enterprise CA)
- Wildcard coverage
- Recently issued certs (infrastructure changes)

All of this without touching the target — purely passive OSINT.
"""

import json
import socket
import ssl
import time
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ct_scraper")


@dataclass
class CTCertificate:
    """A certificate from CT logs."""
    common_name: str
    san_names: List[str] = field(default_factory=list)
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    serial: str = ""

    def to_dict(self) -> Dict:
        return {
            "cn": self.common_name,
            "sans": self.san_names,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }


@dataclass
class CTResult:
    """Complete CT scrape result."""
    domain: str
    certificates: List[CTCertificate] = field(default_factory=list)
    subdomains: Set[str] = field(default_factory=set)
    issuers: Set[str] = field(default_factory=set)
    wildcard_certs: int = 0
    total_certs: int = 0
    scrape_time_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "total_certs": self.total_certs,
            "unique_subdomains": len(self.subdomains),
            "subdomains": sorted(self.subdomains),
            "issuers": sorted(self.issuers),
            "wildcard_certs": self.wildcard_certs,
            "certificates": [c.to_dict() for c in self.certificates[:50]],
            "scrape_time_ms": round(self.scrape_time_ms, 1),
        }


class CTScraper:
    """
    Certificate Transparency log scraper.
    Queries crt.sh API — zero packets to target.
    """

    CRT_SH_HOST = "crt.sh"
    CRT_SH_IP = None  # Resolved at runtime

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def scrape(self, domain: str, include_expired: bool = True,
               include_wildcard: bool = True) -> CTResult:
        """
        Query CT logs for all certificates matching a domain.
        """
        result = CTResult(domain=domain)
        t0 = time.time()

        try:
            # Query crt.sh JSON API
            json_data = self._query_crtsh(domain, include_expired)
            if json_data:
                self._parse_crtsh(json_data, domain, result, include_wildcard)
        except Exception as e:
            logger.warning(f"[CT] crt.sh query failed: {e}")

        result.scrape_time_ms = (time.time() - t0) * 1000
        return result

    def _query_crtsh(self, domain: str, include_expired: bool) -> Optional[List[Dict]]:
        """Send HTTPS request to crt.sh JSON API."""
        try:
            # Resolve crt.sh IP
            ip = socket.getaddrinfo(self.CRT_SH_HOST, 443, socket.AF_INET)[0][4][0]

            # Build request
            exclude = "" if include_expired else "&exclude=expired"
            path = f"/?q=%.{domain}&output=json{exclude}"

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.CRT_SH_HOST}\r\n"
                f"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            ctx = ssl.create_default_context()
            sock = socket.create_connection((ip, 443), timeout=self.timeout)
            tls_sock = ctx.wrap_socket(sock, server_hostname=self.CRT_SH_HOST)
            tls_sock.sendall(request)

            # Read full response
            response = b""
            while True:
                chunk = tls_sock.recv(8192)
                if not chunk:
                    break
                response += chunk

            tls_sock.close()

            # Extract JSON body
            decoded = response.decode("utf-8", errors="replace")
            body_start = decoded.find("\r\n\r\n")
            if body_start < 0:
                return None

            body = decoded[body_start + 4:].strip()

            # Handle chunked transfer encoding
            if "Transfer-Encoding: chunked" in decoded[:body_start]:
                unchunked = self._unchunk(body)
                body = unchunked

            if body.startswith("["):
                return json.loads(body)

        except json.JSONDecodeError:
            logger.debug("[CT] Failed to parse crt.sh JSON response")
        except Exception as e:
            logger.debug(f"[CT] crt.sh request failed: {e}")

        return None

    def _unchunk(self, body: str) -> str:
        """Decode chunked transfer encoding."""
        result = []
        lines = body.split("\r\n")
        i = 0
        while i < len(lines):
            try:
                size = int(lines[i], 16)
                if size == 0:
                    break
                i += 1
                result.append(lines[i])
                i += 1
            except (ValueError, IndexError):
                i += 1
        return "".join(result)

    def _parse_crtsh(self, entries: List[Dict], domain: str,
                     result: CTResult, include_wildcard: bool):
        """Parse crt.sh JSON entries into structured result."""
        seen_ids: Set[str] = set()

        for entry in entries:
            cert_id = str(entry.get("id", ""))
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)

            cn = entry.get("common_name", "")
            name_value = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "")
            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")

            # Parse SAN names (newline-separated in crt.sh)
            san_names = [n.strip() for n in name_value.split("\n") if n.strip()]

            # Track subdomains
            for san in san_names:
                clean = san.lstrip("*.")
                if clean.endswith(domain) and clean != domain:
                    result.subdomains.add(clean)
                elif clean == domain:
                    result.subdomains.add(clean)

            # Track wildcards
            is_wildcard = any("*" in san for san in san_names)
            if is_wildcard:
                result.wildcard_certs += 1

            if not include_wildcard and is_wildcard and not any(
                not san.startswith("*") for san in san_names
            ):
                continue

            # Track issuers
            if issuer:
                # Extract O= from issuer DN
                for part in issuer.split(","):
                    if "O=" in part:
                        org = part.split("O=")[1].strip()
                        result.issuers.add(org)
                        break

            cert = CTCertificate(
                common_name=cn,
                san_names=san_names,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
                serial=cert_id,
            )
            result.certificates.append(cert)

        result.total_certs = len(result.certificates)
