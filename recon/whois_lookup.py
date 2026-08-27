import socket
import re
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.whois")

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "info": "whois.afilias.net",
    "default": "whois.iana.org",
}

CLOUD_RANGES = [
    # More specific prefixes first (longer CIDR ranges)
    ("Amazon", [
        "52.84.", "52.92.", "52.94.", "52.95.",  # More specific Amazon ranges
        "54.230.", "54.231.", "54.232.", "54.233.",  # More specific Amazon ranges
        "18.244.", "18.245.", "18.246.", "18.247.",  # More specific Amazon ranges
        "3.80.", "3.81.", "3.82.", "3.83.",  # More specific Amazon ranges
        "13.248.", "13.249.", "13.250.", "13.251.",  # More specific Amazon ranges
        "35.160.", "35.161.", "35.162.", "35.163.",  # More specific Amazon ranges
        "52.", "54.", "18.", "3.", "13.", "35."  # Broader ranges last
    ]),
    ("Google Cloud", [
        "34.64.", "34.65.", "34.66.", "34.67.",  # More specific Google ranges
        "35.192.", "35.193.", "35.194.", "35.195.",  # More specific Google ranges
        "104.196.", "104.197.", "104.198.", "104.199.",  # More specific Google ranges
        "130.211.", "130.212.", "130.213.", "130.214.",  # More specific Google ranges
        "34.", "35.", "104.", "130."  # Broader ranges last
    ]),
    ("Azure", [
        "13.77.", "13.78.", "13.79.", "13.80.",  # More specific Azure ranges
        "20.36.", "20.37.", "20.38.", "20.39.",  # More specific Azure ranges
        "40.64.", "40.65.", "40.66.", "40.67.",  # More specific Azure ranges
        "52.136.", "52.137.", "52.138.", "52.139.",  # More specific Azure ranges
        "104.40.", "104.41.", "104.42.", "104.43.",  # More specific Azure ranges
        "13.", "20.", "40.", "52.", "104."  # Broader ranges last
    ]),
    ("DigitalOcean", ["104.131.", "159.65.", "167.99.", "178.128."]),
    ("Cloudflare", ["104.16.", "104.17.", "104.18.", "172.67.", "104.21."]),
]

HONEYPOT_INDICATORS = [
    "honeypot", "tarpit", "canary", "deception",
    "thinkst", "canarytokens",
]

@dataclass
class WHOISResult:
    target: str
    resolved_ip: Optional[str] = None
    registrar: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    cloud_provider: Optional[str] = None
    is_cloud: bool = False
    honeypot_warning: bool = False
    raw_whois: Optional[str] = None
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None and k != "raw_whois"}

class WHOISLookup:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def lookup(self, target: str) -> WHOISResult:
        result = WHOISResult(target=target)
        try:
            resolved = socket.gethostbyname(target)
            result.resolved_ip = resolved
        except socket.gaierror:
            result.warnings.append(f"Could not resolve {target}")
            return result

        self._check_cloud_provider(result)
        try:
            whois_data = self._query_whois(target)
            if whois_data:
                result.raw_whois = whois_data
                self._parse_whois(whois_data, result)
                self._check_honeypot(whois_data, result)
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {target}: {e}")

        return result

    def _query_whois(self, target: str) -> Optional[str]:
        tld = target.rsplit(".", 1)[-1].lower() if "." in target else "default"
        server = WHOIS_SERVERS.get(tld, WHOIS_SERVERS["default"])
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            sock.sendall(f"{target}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            return response.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _parse_whois(self, data: str, result: WHOISResult):
        registrar = re.search(r"Registrar:\s*(.+)", data, re.IGNORECASE)
        if registrar:
            result.registrar = registrar.group(1).strip()

        org = re.search(r"(?:Org(?:anization)?|OrgName):\s*(.+)", data, re.IGNORECASE)
        if org:
            result.organization = org.group(1).strip()

        country = re.search(r"Country:\s*(\S+)", data, re.IGNORECASE)
        if country:
            result.country = country.group(1).strip().upper()

        asn = re.search(r"(?:OriginAS|ASNumber):\s*(?:AS)?(\d+)", data, re.IGNORECASE)
        if asn:
            result.asn = f"AS{asn.group(1)}"

    def _check_cloud_provider(self, result: WHOISResult):
        if not result.resolved_ip:
            return
        ip: str = result.resolved_ip or ""
        for provider, prefixes in CLOUD_RANGES:
            for prefix in prefixes:
                if ip.startswith(prefix):
                    result.cloud_provider = provider
                    result.is_cloud = True
                    result.warnings.append(
                        f"Target appears to be hosted on {provider} — "
                        f"scan may hit cloud WAF/load balancer instead of actual host"
                    )
                    return

    def _check_honeypot(self, whois_data: str, result: WHOISResult):
        lower_data = whois_data.lower()
        for indicator in HONEYPOT_INDICATORS:
            if indicator in lower_data:
                result.honeypot_warning = True
                result.warnings.append(
                    f"Honeypot indicator detected in WHOIS data: '{indicator}'"
                )
                break
