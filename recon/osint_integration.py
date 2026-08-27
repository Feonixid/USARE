"""
OSINT Integration — Shodan + Censys live API queries.

Queries external intelligence databases for known ports, banners,
CVEs, and historical data associated with a target IP.  All queries
are passive (no packets reach the target).

Requires API keys passed via CLI flags:
  --shodan-key   API key from account.shodan.io
  --censys-id    Censys API ID  (censys.io → Account → API)
  --censys-secret Censys API Secret
"""

import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

import requests  # type: ignore

logger = logging.getLogger("usare.osint")

REQUEST_TIMEOUT = 10
SHODAN_HOST_URL  = "https://api.shodan.io/shodan/host/{ip}?key={key}"
CENSYS_HOSTS_URL = "https://search.censys.io/api/v2/hosts/{ip}"


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OSINTPort:
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cves: List[str] = field(default_factory=list)


@dataclass
class OSINTResult:
    source: str
    ip: str
    ports: List[OSINTPort] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    organization: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    os_guess: Optional[str] = None
    cves: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    last_seen: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "ip": self.ip,
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "cves": p.cves,
                }
                for p in self.ports
            ],
            "hostnames": self.hostnames,
            "organization": self.organization,
            "asn": self.asn,
            "country": self.country,
            "os_guess": self.os_guess,
            "cves": self.cves,
            "tags": self.tags,
            "last_seen": self.last_seen,
            "notes": self.notes,
        }

    @property
    def known_ports(self) -> List[int]:
        return [p.port for p in self.ports]


# ─────────────────────────────────────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────────────────────────────────────

def query_shodan(ip: str, api_key: str) -> Optional[OSINTResult]:
    """
    Query Shodan host endpoint for a given IP.
    Returns OSINTResult or None on error.
    """
    if not api_key:
        return None
    url = SHODAN_HOST_URL.format(ip=ip, key=api_key)
    try:
        logger.info("[OSINT] Querying Shodan for %s", ip)
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 401:
            logger.warning("[OSINT] Shodan: invalid API key")
            return None
        if resp.status_code == 404:
            logger.info("[OSINT] Shodan: no data for %s", ip)
            return OSINTResult(source="shodan", ip=ip, notes=["No Shodan data for this IP"])
        if resp.status_code != 200:
            logger.warning("[OSINT] Shodan returned HTTP %s", resp.status_code)
            return None
        data = resp.json()
        result = OSINTResult(
            source="shodan",
            ip=ip,
            hostnames=data.get("hostnames", []),
            organization=data.get("org"),
            asn=str(data.get("asn", "")),
            country=data.get("country_name"),
            os_guess=data.get("os"),
            tags=data.get("tags", []),
            last_seen=data.get("last_update"),
        )
        # Ports / banners
        for svc in data.get("data", []):
            port_obj = OSINTPort(
                port=svc.get("port", 0),
                protocol=svc.get("transport", "tcp"),
                service=svc.get("_shodan", {}).get("module"),
                product=svc.get("product"),
                version=svc.get("version"),
                banner=(svc.get("data", "") or "").strip()[:200],
            )
            # CVEs per service
            for vuln_id in svc.get("vulns", {}).keys():
                port_obj.cves.append(vuln_id)
                if vuln_id not in result.cves:
                    result.cves.append(vuln_id)
            result.ports.append(port_obj)
        return result
    except requests.RequestException as e:
        logger.warning("[OSINT] Shodan request failed: %s", e)
        return None
    except Exception as e:
        logger.debug("[OSINT] Shodan parse error: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Censys
# ─────────────────────────────────────────────────────────────────────────────

def query_censys(ip: str, api_id: str, api_secret: str) -> Optional[OSINTResult]:
    """
    Query Censys Hosts v2 API for a given IP.
    Returns OSINTResult or None on error.
    """
    if not api_id or not api_secret:
        return None
    url = CENSYS_HOSTS_URL.format(ip=ip)
    try:
        logger.info("[OSINT] Querying Censys for %s", ip)
        resp = requests.get(
            url,
            auth=(api_id, api_secret),
            headers={"Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code in (401, 403):
            logger.warning("[OSINT] Censys: authentication failed")
            return None
        if resp.status_code == 404:
            logger.info("[OSINT] Censys: no data for %s", ip)
            return OSINTResult(source="censys", ip=ip, notes=["No Censys data for this IP"])
        if resp.status_code == 429:
            logger.warning("[OSINT] Censys: rate limited")
            return None
        if resp.status_code != 200:
            logger.warning("[OSINT] Censys returned HTTP %s", resp.status_code)
            return None
        data = resp.json().get("result", {})
        result = OSINTResult(
            source="censys",
            ip=ip,
            last_seen=data.get("last_updated_at"),
        )
        # Autonomous system
        as_info = data.get("autonomous_system", {})
        result.asn = str(as_info.get("asn", ""))
        result.organization = as_info.get("name") or as_info.get("description")
        result.country = (
            data.get("location", {}).get("country")
            or data.get("location", {}).get("country_code")
        )
        # Reverse DNS / hostnames
        rdns = data.get("reverse_dns", {}).get("reverse_dns_names", [])
        result.hostnames = rdns[:10]
        # Services
        for svc in data.get("services", []):
            transport = svc.get("transport_protocol", "TCP").lower()
            port_num = svc.get("port", 0)
            port_obj = OSINTPort(
                port=port_num,
                protocol=transport,
                service=svc.get("service_name"),
                product=svc.get("software", [{}])[0].get("product") if svc.get("software") else None,
                version=svc.get("software", [{}])[0].get("version") if svc.get("software") else None,
                banner=svc.get("banner", "")[:200] if svc.get("banner") else None,
            )
            result.ports.append(port_obj)
        return result
    except requests.RequestException as e:
        logger.warning("[OSINT] Censys request failed: %s", e)
        return None
    except Exception as e:
        logger.debug("[OSINT] Censys parse error: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Unified interface
# ─────────────────────────────────────────────────────────────────────────────

class OSINTIntegration:
    """
    Unified OSINT wrapper that queries available providers and merges results.
    """

    def __init__(
        self,
        shodan_key: Optional[str] = None,
        censys_id: Optional[str] = None,
        censys_secret: Optional[str] = None,
    ):
        self.shodan_key = shodan_key
        self.censys_id = censys_id
        self.censys_secret = censys_secret

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_key)

    @property
    def has_censys(self) -> bool:
        return bool(self.censys_id and self.censys_secret)

    @property
    def any_configured(self) -> bool:
        return self.has_shodan or self.has_censys

    def query_all(self, ip: str) -> Dict[str, OSINTResult]:
        """
        Query all configured providers.  Returns dict keyed by provider name.
        """
        results: Dict[str, OSINTResult] = {}
        if self.has_shodan:
            r = query_shodan(ip, self.shodan_key)
            if r:
                results["shodan"] = r
        if self.has_censys:
            r = query_censys(ip, self.censys_id, self.censys_secret)
            if r:
                results["censys"] = r
        return results

    def get_known_ports(self, ip: str) -> List[int]:
        """
        Convenience: return combined port list from all providers.
        """
        ports: set = set()
        for result in self.query_all(ip).values():
            ports.update(result.known_ports)
        return sorted(ports)

    def merged_summary(self, ip: str) -> Dict[str, Any]:
        """
        Return a merged dict with the best data from all providers.
        """
        all_results = self.query_all(ip)
        if not all_results:
            return {"ip": ip, "sources": [], "ports": [], "cves": [], "notes": ["No OSINT data"]}

        ports: Dict[int, dict] = {}
        all_cves: set = set()
        org = asn = country = os_guess = last_seen = None
        hostnames: list = []
        tags: list = []

        for src, res in all_results.items():
            org = org or res.organization
            asn = asn or res.asn
            country = country or res.country
            os_guess = os_guess or res.os_guess
            last_seen = last_seen or res.last_seen
            hostnames = hostnames or res.hostnames
            tags = list(set(tags) | set(res.tags))
            all_cves.update(res.cves)
            for p in res.ports:
                if p.port not in ports:
                    ports[p.port] = {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                        "banner_snippet": (p.banner or "")[:80],
                        "cves": p.cves,
                        "source": src,
                    }

        return {
            "ip": ip,
            "sources": list(all_results.keys()),
            "organization": org,
            "asn": asn,
            "country": country,
            "os_guess": os_guess,
            "last_seen": last_seen,
            "hostnames": hostnames[:10],
            "tags": tags,
            "ports": sorted(ports.values(), key=lambda x: x["port"]),
            "cves": sorted(all_cves),
            "total_known_ports": len(ports),
            "total_cves": len(all_cves),
        }
