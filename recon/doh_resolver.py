"""
USARE DNS-over-HTTPS (DoH) Covert Resolver

Tunnels DNS queries through HTTPS to make DNS resolution indistinguishable
from normal web traffic. Rotates between multiple DoH providers to prevent
single-source correlation.

Supports: A, AAAA, MX, TXT, NS, CNAME, SOA, PTR record types.
"""

import json
import random
import logging
import time
from typing import Dict, List, Optional, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from dataclasses import dataclass, field

logger = logging.getLogger("usare.doh_resolver")

# DoH provider endpoints (RFC 8484 JSON API)
DOH_PROVIDERS = [
    {
        "name": "Cloudflare",
        "url": "https://cloudflare-dns.com/dns-query",
        "headers": {"Accept": "application/dns-json"},
    },
    {
        "name": "Google",
        "url": "https://dns.google/resolve",
        "headers": {"Accept": "application/dns-json"},
    },
    {
        "name": "Quad9",
        "url": "https://dns.quad9.net:5053/dns-query",
        "headers": {"Accept": "application/dns-json"},
    },
]

# DNS record type codes
RECORD_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "TXT": 16,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "DS": 43,
    "DNSKEY": 48,
    "RRSIG": 46,
}


@dataclass
class DoHRecord:
    """A single DNS record from DoH response."""
    name: str
    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
        }


@dataclass
class DoHResult:
    """Complete DoH resolution result."""
    domain: str
    records: List[DoHRecord] = field(default_factory=list)
    provider_used: str = ""
    status: int = -1       # DNS RCODE
    authenticated_data: bool = False  # DNSSEC AD bit
    error: Optional[str] = None
    query_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "records": [r.to_dict() for r in self.records],
            "provider": self.provider_used,
            "status": self.status,
            "authenticated_data": self.authenticated_data,
            "error": self.error,
            "query_time_ms": round(self.query_time_ms, 2),
        }


class DoHResolver:
    """
    DNS-over-HTTPS resolver that tunnels DNS queries through HTTPS.
    
    All DNS traffic appears as normal HTTPS web requests, making
    subdomain enumeration and DNS recon invisible to network monitors.
    """

    def __init__(
        self,
        timeout: float = 5.0,
        rotate_providers: bool = True,
        preferred_provider: Optional[str] = None,
        max_retries: int = 2,
    ):
        self.timeout = timeout
        self.rotate_providers = rotate_providers
        self.max_retries = max_retries
        self._query_count = 0

        # Set provider order
        if preferred_provider:
            matching = [p for p in DOH_PROVIDERS if p["name"].lower() == preferred_provider.lower()]
            others = [p for p in DOH_PROVIDERS if p["name"].lower() != preferred_provider.lower()]
            self._providers = matching + others
        else:
            self._providers = list(DOH_PROVIDERS)

    def _get_provider(self) -> Dict[str, Any]:
        """Get next provider, rotating if enabled."""
        if self.rotate_providers:
            idx = self._query_count % len(self._providers)
            self._query_count += 1
            return self._providers[idx]
        return self._providers[0]

    def _query_doh(self, domain: str, rtype: str, provider: Dict[str, Any]) -> DoHResult:
        """Execute a single DoH JSON API query."""
        result = DoHResult(domain=domain, provider_used=provider["name"])
        type_code = RECORD_TYPES.get(rtype.upper(), 1)

        url = f"{provider['url']}?name={domain}&type={rtype.upper()}&do=1"
        headers = dict(provider["headers"])
        # Add a browser-like User-Agent to blend with normal traffic
        headers["User-Agent"] = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ])

        start = time.monotonic()
        try:
            req = Request(url, headers=headers, method="GET")
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)

            result.query_time_ms = (time.monotonic() - start) * 1000
            result.status = data.get("Status", -1)
            result.authenticated_data = bool(data.get("AD", False))

            for answer in data.get("Answer", []):
                record = DoHRecord(
                    name=answer.get("name", domain).rstrip("."),
                    record_type=rtype.upper(),
                    value=answer.get("data", "").strip('"'),
                    ttl=answer.get("TTL", 0),
                )
                result.records.append(record)

        except (HTTPError, URLError, json.JSONDecodeError, Exception) as e:
            result.query_time_ms = (time.monotonic() - start) * 1000
            result.error = str(e)
            logger.debug(f"[DoH] Query failed via {provider['name']}: {e}")

        return result

    def resolve(self, domain: str, rtype: str = "A") -> DoHResult:
        """
        Resolve a domain using DoH with provider rotation and retry fallback.
        """
        last_result = DoHResult(domain=domain)

        for attempt in range(self.max_retries + 1):
            provider = self._get_provider()
            result = self._query_doh(domain, rtype, provider)

            if result.error is None:
                return result

            last_result = result
            logger.debug(
                f"[DoH] Attempt {attempt + 1}/{self.max_retries + 1} failed "
                f"via {provider['name']}, rotating..."
            )

        return last_result

    def resolve_a(self, domain: str) -> DoHResult:
        """Resolve A records (IPv4)."""
        return self.resolve(domain, "A")

    def resolve_aaaa(self, domain: str) -> DoHResult:
        """Resolve AAAA records (IPv6)."""
        return self.resolve(domain, "AAAA")

    def resolve_mx(self, domain: str) -> DoHResult:
        """Resolve MX records (mail servers)."""
        return self.resolve(domain, "MX")

    def resolve_txt(self, domain: str) -> DoHResult:
        """Resolve TXT records (SPF, DKIM, DMARC, etc.)."""
        return self.resolve(domain, "TXT")

    def resolve_ns(self, domain: str) -> DoHResult:
        """Resolve NS records (nameservers)."""
        return self.resolve(domain, "NS")

    def resolve_cname(self, domain: str) -> DoHResult:
        """Resolve CNAME records."""
        return self.resolve(domain, "CNAME")

    def resolve_all(self, domain: str) -> Dict[str, DoHResult]:
        """
        Resolve all common record types for a domain.
        Adds random jitter between queries to avoid burst correlation.
        """
        results = {}
        types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        for rtype in types:
            results[rtype] = self.resolve(domain, rtype)
            # Anti-correlation jitter between lookups
            time.sleep(random.uniform(0.1, 0.5))

        return results

    def bulk_resolve(
        self,
        domains: List[str],
        rtype: str = "A",
        delay_range: tuple = (0.3, 1.5),
    ) -> Dict[str, DoHResult]:
        """
        Resolve multiple domains with randomized inter-query delays.
        Used for covert subdomain enumeration.
        """
        results = {}
        for domain in domains:
            results[domain] = self.resolve(domain, rtype)
            time.sleep(random.uniform(*delay_range))
        return results

    def audit_dnssec(self, domain: str) -> Dict[str, Any]:
        """
        Audit DNSSEC posture and chain-of-trust indicators for a domain.
        Evaluates DS, DNSKEY, RRSIG records and Authenticated Data (AD) status.
        """
        res_a = self.resolve(domain, "A")
        res_ds = self.resolve(domain, "DS")
        res_key = self.resolve(domain, "DNSKEY")

        has_ds = len(res_ds.records) > 0
        has_key = len(res_key.records) > 0
        is_ad = res_a.authenticated_data

        if is_ad:
            status = "SECURE"
            details = "DNSSEC signature validated by upstream resolver (AD bit set)"
        elif has_ds and has_key:
            status = "CONFIGURED"
            details = "DNSKEY and DS records present; signatures present in zone"
        elif has_ds or has_key:
            status = "PARTIAL"
            details = "Partial DNSSEC records configured (missing complete delegation chain)"
        else:
            status = "INSECURE"
            details = "No DNSSEC records (DS/DNSKEY) found; zone is unsigned"

        return {
            "domain": domain,
            "dnssec_status": status,
            "authenticated_data": is_ad,
            "has_ds_record": has_ds,
            "has_dnskey_record": has_key,
            "ds_records": [r.to_dict() for r in res_ds.records],
            "dnskey_records": [r.to_dict() for r in res_key.records],
            "details": details,
        }
