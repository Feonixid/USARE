"""
ASN / IP Ownership Intelligence.

Determines whether an IP belongs to a CDN/cloud edge node vs actual
target infrastructure.  Uses RDAP (registration data access protocol)
and BGP prefix lookups — both completely passive, no packets to target.

Providers used (no API key required):
  1. team-cymru.com whois (ASN + org)
  2. ip-api.com  (country, ISP, ASN, proxy detection) — 45 req/min free
  3. RDAP (ARIN/RIPE/APNIC) for allocation details
"""

import socket
import logging
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import requests  # type: ignore

logger = logging.getLogger("usare.asn_intel")

# Known CDN / hosting ASN numbers (sample set — covers most common)
CDN_ASNS: Dict[int, str] = {
    13335: "Cloudflare",
    20940: "Akamai",
    16509: "Amazon (AWS)",
    14618: "Amazon (AWS)",
    8075:  "Microsoft (Azure)",
    15169: "Google (GCP)",
    396982:"Google (GCP)",
    54113: "Fastly",
    46489: "Twitch/Amazon",
    19679: "Dropbox",
    2906:  "Netflix",
    32934: "Facebook/Meta",
    36351: "SoftLayer/IBM",
    24940: "Hetzner",
    51167: "Contabo",
    47846: "SEEWEB",
    33070: "Rackspace",
    27357: "Rackspace",
    7224:  "Amazon CloudFront",
}

# ip-api.com free endpoint (no key needed, 45 req/min)
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,isp,org,as,asname,proxy,hosting,query"
# Team Cymru whois — uses socket
CYMRU_WHOIS = ("whois.cymru.com", 43)


@dataclass
class ASNResult:
    ip: str
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    is_cdn: bool = False
    cdn_name: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False
    prefix: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def is_edge_node(self) -> bool:
        """True if this IP is likely a CDN/proxy edge, not origin infra."""
        return self.is_cdn or self.is_proxy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "asn": self.asn,
            "asn_name": self.asn_name,
            "organization": self.organization,
            "isp": self.isp,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "is_cdn": self.is_cdn,
            "cdn_name": self.cdn_name,
            "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting,
            "is_edge_node": self.is_edge_node,
            "prefix": self.prefix,
            "notes": self.notes,
        }


def _query_ip_api(ip: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Query ip-api.com for enrichment data."""
    try:
        url = IP_API_URL.format(ip=ip)
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 429:
            logger.warning("[asn_intel] ip-api.com rate limited")
            return None
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("status") != "success":
            return None
        return data
    except Exception as e:
        logger.debug("[asn_intel] ip-api.com error: %s", e)
        return None


def _query_cymru(ip: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """
    Query Team Cymru whois for ASN + prefix info.
    Protocol: connect to whois.cymru.com:43, send "begin\nverbose\nIP\nend\n"
    Response: | ASN | IP | Prefix | CC | Org
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(CYMRU_WHOIS)
        query = f"begin\nverbose\n{ip}\nend\n"
        sock.sendall(query.encode())
        data = b""
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode("utf-8", errors="ignore")
        # Parse: "Bulk mode; whois.cymru.com\nASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n..."
        for line in text.splitlines():
            if "|" in line and not line.startswith("Bulk") and not line.startswith("ASN"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 5:
                    try:
                        asn_num = int(parts[0])
                    except ValueError:
                        continue
                    return {
                        "asn": asn_num,
                        "ip": parts[1],
                        "prefix": parts[2],
                        "country_code": parts[3],
                        "asn_name": parts[6] if len(parts) > 6 else "",
                    }
    except Exception as e:
        logger.debug("[asn_intel] Cymru whois error: %s", e)
    return None


def lookup_asn(ip: str, timeout: float = 5.0) -> ASNResult:
    """
    Enrich an IP with ASN, organization, CDN classification, and geo data.
    """
    result = ASNResult(ip=ip)

    # Primary: ip-api.com (has proxy/hosting flags)
    api_data = _query_ip_api(ip, timeout)
    if api_data:
        # Parse ASN number from "AS13335 Cloudflare, Inc." format
        as_str = api_data.get("as", "")
        m = re.match(r"AS(\d+)", as_str)
        if m:
            result.asn = int(m.group(1))
        result.asn_name = api_data.get("asname", "")
        result.organization = api_data.get("org", "")
        result.isp = api_data.get("isp", "")
        result.country = api_data.get("country", "")
        result.country_code = api_data.get("countryCode", "")
        result.city = api_data.get("city", "")
        result.is_proxy = bool(api_data.get("proxy", False))
        result.is_hosting = bool(api_data.get("hosting", False))

    # Secondary: Cymru whois for prefix + ASN confirmation
    cymru_data = _query_cymru(ip, timeout)
    if cymru_data:
        if not result.asn:
            result.asn = cymru_data.get("asn")
        if not result.asn_name:
            result.asn_name = cymru_data.get("asn_name", "")
        if not result.country_code:
            result.country_code = cymru_data.get("country_code", "")
        result.prefix = cymru_data.get("prefix", "")

    # CDN classification
    if result.asn and result.asn in CDN_ASNS:
        result.is_cdn = True
        result.cdn_name = CDN_ASNS[result.asn]
        result.notes.append(
            f"CDN edge node detected — {result.cdn_name} ASN {result.asn}. "
            "This IP may not be the origin server."
        )
    else:
        # Fuzzy CDN detection by org/ISP name
        combined = " ".join(filter(None, [result.organization, result.isp, result.asn_name])).lower()
        cdn_keywords = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "fastly": "Fastly",
            "cloudfront": "AWS CloudFront",
            "incapsula": "Imperva/Incapsula",
            "sucuri": "Sucuri",
            "stackpath": "StackPath",
            "cdn77": "CDN77",
        }
        for keyword, name in cdn_keywords.items():
            if keyword in combined:
                result.is_cdn = True
                result.cdn_name = name
                result.notes.append(
                    f"CDN edge node detected — {name} (name match). "
                    "Origin server IP may differ."
                )
                break

    if result.is_hosting and not result.is_cdn:
        result.notes.append("Hosting/cloud infrastructure detected — may be shared hosting.")

    return result
