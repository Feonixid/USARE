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
                # Enrich with EPSS scores
                cve_ids_to_enrich = [c["cve_id"] for c in cves if c.get("cve_id", "").startswith("CVE-")]
                if cve_ids_to_enrich:
                    epss_map = fetch_epss_scores(cve_ids_to_enrich)
                    for c in cves:
                        cid = c.get("cve_id", "")
                        if cid in epss_map:
                            c["epss_score"] = epss_map[cid]["epss"]
                            c["epss_percentile"] = epss_map[cid]["percentile"]
                        else:
                            c["epss_score"] = 0.0
                            c["epss_percentile"] = 0.0
                vuln_results[port] = cves

        return vuln_results


EPSS_API_URL = "https://api.first.org/data/v1/epss"
_EPSS_CACHE: Dict[str, Dict[str, float]] = {}


def fetch_epss_scores(cve_ids: List[str], timeout: float = 8.0) -> Dict[str, Dict[str, float]]:
    """
    Query FIRST.org EPSS API for exploit probability and percentile ranking.
    Returns: {cve_id: {"epss": float, "percentile": float}}
    """
    global _EPSS_CACHE
    to_fetch = [c for c in cve_ids if c.startswith("CVE-") and c not in _EPSS_CACHE]
    if not to_fetch:
        return {c: _EPSS_CACHE[c] for c in cve_ids if c in _EPSS_CACHE}

    # Batch queries up to 50 CVEs per request
    for i in range(0, len(to_fetch), 50):
        batch = to_fetch[i:i + 50]
        try:
            url = f"{EPSS_API_URL}?cve={','.join(batch)}"
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []):
                    c_id = item.get("cve")
                    epss_val = float(item.get("epss", 0.0) or 0.0)
                    pct_val = float(item.get("percentile", 0.0) or 0.0)
                    if c_id:
                        _EPSS_CACHE[c_id] = {"epss": epss_val, "percentile": pct_val}
        except Exception as e:
            logger.debug(f"[vuln] EPSS query failed: {e}")

    return {c: _EPSS_CACHE[c] for c in cve_ids if c in _EPSS_CACHE}


def map_mitre_attack_techniques(
    banners: Dict[Any, dict],
    vulns: Optional[Dict[Any, List[dict]]] = None,
) -> Dict[str, Any]:
    """
    Map discovered network services and CVE vulnerabilities to the
    MITRE ATT&CK Enterprise Matrix with actionable defensive remediations.
    """
    techniques = []
    remediations = []

    # General discovery technique
    techniques.append({
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "reference": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
    })

    port_mapping = {
        21: ("T1078", "Valid Accounts: Unencrypted FTP", "Initial Access", "Enforce SFTP/FTPS and disable anonymous login"),
        22: ("T1133", "External Remote Services: SSH", "Initial Access / Persistence", "Enforce key-based authentication, disable root login, place behind VPN"),
        23: ("T1078", "Valid Accounts: Unencrypted Telnet", "Initial Access", "Disable Telnet service completely; migrate to SSHv2"),
        80: ("T1190", "Exploit Public-Facing Application: HTTP", "Initial Access", "Upgrade server to latest version, enable WAF, enforce HTTPS redirect"),
        443: ("T1190", "Exploit Public-Facing Application: HTTPS", "Initial Access", "Maintain patch levels, configure strict TLS ciphers, deploy WAF"),
        445: ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "Block SMB (port 445) at boundary firewall; disable SMBv1"),
        139: ("T1021.002", "Remote Services: NetBIOS SMB", "Lateral Movement", "Block port 139 at network perimeter"),
        3389: ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement / Initial Access", "Require Network Level Authentication (NLA), enforce MFA, restrict via VPN"),
        3306: ("T1190", "Exploit Public-Facing Application: MySQL", "Initial Access", "Bind MySQL to localhost or internal subnet; disable public exposure"),
        5432: ("T1190", "Exploit Public-Facing Application: PostgreSQL", "Initial Access", "Restrict PostgreSQL access using pg_hba.conf; bind to internal IP"),
        6379: ("T1190", "Exploit Public-Facing Application: Redis", "Initial Access", "Enable requirepass authentication, bind to 127.0.0.1, disable dangerous commands"),
        27017: ("T1190", "Exploit Public-Facing Application: MongoDB", "Initial Access", "Enable auth and TLS; restrict network access via firewall"),
    }

    seen_techs = {"T1046"}

    for p_key, b_info in banners.items():
        try:
            port = int(p_key)
        except (ValueError, TypeError):
            continue

        if port in port_mapping:
            tid, tname, tactic, rem = port_mapping[port]
            if tid not in seen_techs:
                seen_techs.add(tid)
                techniques.append({
                    "technique_id": tid,
                    "technique_name": tname,
                    "tactic": tactic,
                    "reference": f"https://attack.mitre.org/techniques/{tid.split('.')[0]}/",
                    "port": port,
                })
            remediations.append({
                "port": port,
                "service": b_info.get("service") or b_info.get("name") or str(port),
                "remediation": rem,
                "priority": "HIGH" if port in (445, 3389, 23, 6379) else "MEDIUM",
            })

    # CVE vulnerability attack mappings
    if vulns:
        for p_str, cve_list in vulns.items():
            for cve in cve_list:
                score = float(cve.get("cvss_score", 0.0) or 0.0)
                cid = cve.get("cve_id", "")
                if score >= 7.0:
                    if "T1190" not in seen_techs:
                        seen_techs.add("T1190")
                        techniques.append({
                            "technique_id": "T1190",
                            "technique_name": "Exploit Public-Facing Application",
                            "tactic": "Initial Access",
                            "reference": "https://attack.mitre.org/techniques/T1190/",
                        })
                    remediations.append({
                        "port": p_str,
                        "cve_id": cid,
                        "remediation": f"Apply vendor patch for {cid} (CVSS {score}) immediately.",
                        "priority": "CRITICAL" if score >= 9.0 or cve.get("is_cisa_kev") else "HIGH",
                    })

    return {
        "mitre_techniques": techniques,
        "remediations": remediations,
        "total_techniques_mapped": len(techniques),
    }

