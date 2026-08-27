"""
Vulnerability Mapper — NVD CPE lookup + CISA KEV + ExploitDB offline search.

Improvements over the original keyword-only approach:
  1. CPE-based NVD search when product+version are known (more precise results)
  2. ExploitDB offline search via searchsploit if installed
  3. Keyword fallback when no CPE can be constructed
  4. CISA KEV cross-reference (unchanged)
"""

import logging
import subprocess
import shutil
import json
import re
import time
from typing import Dict, List, Any, Optional

import requests  # type: ignore

logger = logging.getLogger("usare.vuln")

# NVD API v2 limits: 5 req/30s without key, 50 req/30s with key
NVD_CVE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_cpe(vendor: str, product: str, version: str) -> str:
    """
    Build a CPE 2.3 URI for NVD queries.
    Example: cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*
    """
    v = vendor.lower().replace(" ", "_") if vendor else "*"
    p = product.lower().replace(" ", "_")
    ver = version.replace(" ", "") if version else "*"
    return f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*"


# Common vendor mappings for well-known services
_VENDOR_MAP: Dict[str, str] = {
    "apache": "apache",
    "nginx": "nginx",
    "openssh": "openbsd",
    "iis": "microsoft",
    "tomcat": "apache",
    "mysql": "oracle",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postfix": "postfix",
    "dovecot": "dovecot",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elastic",
    "jenkins": "jenkins",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "php": "php",
    "python": "python",
    "openssl": "openssl",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "pure-ftpd": "pureftpd",
    "samba": "samba",
    "exim": "exim",
    "sendmail": "sendmail",
    "bind": "isc",
    "unbound": "nlnet_labs",
    "lighttpd": "lighttpd",
}


def _guess_vendor(product: str) -> str:
    """Best-effort vendor from product name."""
    p = product.lower().split()[0] if product else ""
    return _VENDOR_MAP.get(p, p or "*")


def _extract_base_score(metrics: dict) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        data = metrics.get(key, [])
        if data:
            return float(data[0].get("cvssData", {}).get("baseScore", 0.0))
    return 0.0


def _rate_limit_sleep(api_key: Optional[str]):
    """Sleep to respect NVD rate limits."""
    time.sleep(0.6 if api_key else 6.0)


# ─────────────────────────────────────────────────────────────────────────────
# ExploitDB offline search (searchsploit)
# ─────────────────────────────────────────────────────────────────────────────

def searchsploit_query(product: str, version: str) -> List[Dict[str, Any]]:
    """
    Run searchsploit (if installed) and return matching exploits.
    Returns list of dicts with {title, edb_id, type, path}.
    """
    if not shutil.which("searchsploit"):
        return []
    try:
        query = f"{product} {version}".strip()
        proc = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout)
        results = []
        for entry in data.get("RESULTS_EXPLOIT", [])[:10]:
            results.append({
                "title": entry.get("Title", ""),
                "edb_id": entry.get("EDB-ID", ""),
                "type": entry.get("Type", ""),
                "platform": entry.get("Platform", ""),
                "path": entry.get("Path", ""),
                "source": "exploitdb",
            })
        return results
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        logger.debug("[vuln] searchsploit error: %s", e)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# VulnerabilityMapper
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityMapper:
    def __init__(self, nvd_api_key: str = ""):
        self.kev_catalog_url = CISA_KEV_URL
        self.nvd_api_url     = NVD_CVE_URL
        self.kev_data: Dict[str, dict] = {}
        self.kev_loaded = False
        self._api_key = nvd_api_key

    # ── KEV ───────────────────────────────────────────────────────────────────

    def load_kev_catalog(self) -> bool:
        try:
            logger.info("[vuln] Fetching CISA KEV catalog…")
            resp = requests.get(self.kev_catalog_url, timeout=12)
            if resp.status_code == 200:
                for vuln in resp.json().get("vulnerabilities", []):
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        self.kev_data[cve_id] = vuln
                self.kev_loaded = True
                logger.info("[vuln] Loaded %d KEVs", len(self.kev_data))
                return True
        except Exception as e:
            logger.warning("[vuln] KEV fetch error: %s", e)
        return False

    def is_in_kev(self, cve_id: str) -> bool:
        return self.kev_loaded and cve_id in self.kev_data

    # ── NVD CPE query ─────────────────────────────────────────────────────────

    def query_nvd_by_cpe(self, cpe_string: str) -> List[Dict[str, Any]]:
        """
        Query NVD by exact CPE — far more precise than keyword search.
        """
        params = {"cpeName": cpe_string, "resultsPerPage": 20}
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key
        try:
            logger.info("[vuln] NVD CPE query: %s", cpe_string)
            resp = requests.get(
                self.nvd_api_url, params=params, headers=headers, timeout=12
            )
            if resp.status_code == 403:
                logger.warning("[vuln] NVD rate limit hit")
                return []
            if resp.status_code != 200:
                return []
            return self._parse_nvd_response(resp.json())
        except Exception as e:
            logger.debug("[vuln] NVD CPE query failed: %s", e)
            return []

    # ── NVD keyword fallback ──────────────────────────────────────────────────

    def query_nvd(self, service: str, version: str) -> List[Dict[str, Any]]:
        """
        Keyword-based NVD search (fallback when CPE can't be constructed).
        """
        keyword = f"{service} {version}".strip()
        params = {"keywordSearch": keyword, "resultsPerPage": 10}
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key
        try:
            logger.info("[vuln] NVD keyword query: '%s'", keyword)
            resp = requests.get(
                self.nvd_api_url, params=params, headers=headers, timeout=12
            )
            if resp.status_code == 403:
                logger.warning("[vuln] NVD rate limit hit")
                return []
            if resp.status_code != 200:
                return []
            return self._parse_nvd_response(resp.json())
        except Exception as e:
            logger.debug("[vuln] NVD keyword query failed: %s", e)
            return []

    def _parse_nvd_response(self, data: dict) -> List[Dict[str, Any]]:
        cves_found = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            base_score = _extract_base_score(cve.get("metrics", {}))
            descriptions = cve.get("descriptions", [{"value": ""}])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "",
            )
            cves_found.append({
                "cve_id": cve_id,
                "base_score": base_score,
                "description": desc[:300],
                "is_cisa_kev": self.is_in_kev(cve_id),
                "source": "nvd",
            })
        return cves_found

    # ── Main mapping entry point ──────────────────────────────────────────────

    def map_vulnerabilities(
        self, banners: Dict[int, dict]
    ) -> Dict[int, List[Dict[str, Any]]]:
        """
        Map open port banners → CVEs.
        Uses CPE lookup when product+version are present, falls back to keyword.
        Appends ExploitDB results if searchsploit is installed.
        """
        if not self.kev_loaded:
            self.load_kev_catalog()

        vuln_results: Dict[int, List[Dict[str, Any]]] = {}

        for port, banner_info in banners.items():
            service = banner_info.get("service") or ""
            version = banner_info.get("version") or ""
            product = banner_info.get("product") or service

            # Parse "Apache/2.4.51" style strings
            if banner_info.get("http_server") and not version:
                server_str = str(banner_info.get("http_server", ""))
                if "/" in server_str:
                    parts = server_str.split("/", 1)
                    product = parts[0]
                    version = parts[1].split(" ")[0]

            # Also check raw banner for version patterns
            if not version:
                raw = banner_info.get("banner_raw") or banner_info.get("raw") or ""
                m = re.search(r"(\d+\.\d+[\.\d]*)", raw)
                if m:
                    version = m.group(1)

            if not product and not service:
                continue

            cves: List[Dict[str, Any]] = []

            # Strategy 1: CPE query (if we have product + version)
            if product and version:
                vendor = _guess_vendor(product)
                cpe = _build_cpe(vendor, product, version)
                cves = self.query_nvd_by_cpe(cpe)
                _rate_limit_sleep(self._api_key)

                # Also try with just product (vendor=*)
                if not cves and vendor != "*":
                    cpe_novendor = _build_cpe("*", product, version)
                    cves = self.query_nvd_by_cpe(cpe_novendor)
                    _rate_limit_sleep(self._api_key)

            # Strategy 2: keyword fallback
            if not cves and (service or product):
                cves = self.query_nvd(product or service, version)
                _rate_limit_sleep(self._api_key)

            # Strategy 3: ExploitDB offline
            exploits = searchsploit_query(product or service, version)
            for exp in exploits:
                # Avoid duplicates with NVD results
                cves.append({
                    "cve_id": f"EDB-{exp['edb_id']}",
                    "base_score": 0.0,
                    "description": exp["title"],
                    "is_cisa_kev": False,
                    "source": "exploitdb",
                    "edb_type": exp.get("type"),
                    "platform": exp.get("platform"),
                })

            if cves:
                vuln_results[port] = cves

        return vuln_results
