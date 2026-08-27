"""
Export Formats — Nessus XML (.nessus) and Metasploit db_import XML exporters.

These make USARE results importable into:
  - Nessus / Tenable.io (via File → Import → .nessus)
  - Metasploit Framework (via db_import path/to/file.xml)
  - Other tools that accept these standard formats (Dradis, Plextrac, etc.)
"""

import os
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Any, Dict, List, Optional
import time
import datetime
import logging

logger = logging.getLogger("usare.export_formats")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _pretty_xml(element: ET.Element) -> str:
    """Return a pretty-printed XML string from an Element."""
    raw = ET.tostring(element, encoding="unicode")
    reparsed = minidom.parseString(raw)
    return reparsed.toprettyxml(indent="  ", encoding=None)


def _cve_severity(base_score: float) -> str:
    if base_score >= 9.0:
        return "Critical"
    if base_score >= 7.0:
        return "High"
    if base_score >= 4.0:
        return "Medium"
    if base_score > 0:
        return "Low"
    return "Info"


def _nessus_severity_int(base_score: float) -> int:
    """Nessus severity: 0=Info, 1=Low, 2=Med, 3=High, 4=Critical."""
    if base_score >= 9.0:
        return 4
    if base_score >= 7.0:
        return 3
    if base_score >= 4.0:
        return 2
    if base_score > 0:
        return 1
    return 0


def _port_protocol(port_num: int, service_info: dict) -> str:
    proto = service_info.get("protocol", "")
    if proto:
        return proto.lower()
    # Common UDP ports
    if port_num in (53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 5353):
        return "udp"
    return "tcp"


# ─────────────────────────────────────────────────────────────────────────────
# Nessus .nessus export
# ─────────────────────────────────────────────────────────────────────────────

def export_nessus(
    scan_data: Dict[str, Any],
    out_dir: str = "logs",
) -> str:
    """
    Export scan_data to Nessus .nessus XML format.
    Returns path to the written file.
    """
    os.makedirs(out_dir, exist_ok=True)
    target = scan_data.get("target", "unknown")
    ts = int(scan_data.get("scan_start", time.time()))
    filename = os.path.join(out_dir, f"usare_{target.replace('.','_')}_{ts}.nessus")

    # Root
    nessus_run = ET.Element("NessusClientData_v2")
    policy_el = ET.SubElement(nessus_run, "Policy")
    pname = ET.SubElement(policy_el, "policyName")
    pname.text = "USARE Export"

    report = ET.SubElement(nessus_run, "Report", attrib={"name": f"USARE Scan — {target}"})

    # One ReportHost per target
    report_host = ET.SubElement(report, "ReportHost", attrib={"name": target})

    # HostProperties
    props = ET.SubElement(report_host, "HostProperties")
    def _tag(name: str, value: str):
        t = ET.SubElement(props, "tag", attrib={"name": name})
        t.text = str(value)

    _tag("host-ip", target)
    _tag("HOST_START", datetime.datetime.utcfromtimestamp(ts).strftime("%a %b %d %H:%M:%S %Y"))
    _tag("HOST_END", datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S %Y"))

    os_fp = scan_data.get("os_detection") or scan_data.get("os_fingerprint") or {}
    if os_fp:
        _tag("operating-system", os_fp.get("os_name", ""))
        _tag("os-confidence", str(os_fp.get("confidence", "")))

    whois = scan_data.get("whois") or {}
    if whois:
        if whois.get("organization"):
            _tag("netbios-name", whois["organization"])

    # Open ports → ReportItem elements
    scan_results = scan_data.get("scan_results", [])
    service_info: Dict[int, dict] = scan_data.get("service_info", {}) or {}
    banners: Dict[int, dict] = scan_data.get("banners", {}) or {}
    vulns: Dict[int, list] = scan_data.get("vulnerabilities", {}) or {}

    plugin_id = 10000  # Synthetic plugin IDs start here

    for port_entry in scan_results:
        port = port_entry.get("port", 0)
        state = str(port_entry.get("state", "")).lower()
        if state not in ("open", "open_filtered"):
            continue
        svc = service_info.get(port) or service_info.get(str(port)) or {}
        banner = banners.get(port) or banners.get(str(port)) or {}
        service_name = svc.get("service") or port_entry.get("service_guess") or "unknown"
        proto = _port_protocol(port, svc)
        svc_version = svc.get("version") or svc.get("product") or banner.get("version") or ""

        plugin_id += 1
        item = ET.SubElement(
            report_host, "ReportItem",
            attrib={
                "port": str(port),
                "svc_name": service_name,
                "protocol": proto,
                "severity": "0",          # Info for open port
                "pluginID": str(plugin_id),
                "pluginName": "USARE: Open Port",
                "pluginFamily": "Port Scanners",
            },
        )
        desc = ET.SubElement(item, "description")
        desc.text = (
            f"Port {port}/{proto} is open.\n"
            f"Service: {service_name}\n"
            f"Version: {svc_version}\n"
            f"Banner: {banner.get('banner_raw', '')[:200]}"
        ).strip()
        risk = ET.SubElement(item, "risk_factor")
        risk.text = "None"

        # Vulnerabilities for this port
        port_vulns = vulns.get(port) or vulns.get(str(port)) or []
        for cve_entry in port_vulns[:20]:
            plugin_id += 1
            cve_id  = cve_entry.get("cve_id", "")
            score   = float(cve_entry.get("base_score") or 0.0)
            sev_int = _nessus_severity_int(score)
            sev_str = _cve_severity(score)

            vuln_item = ET.SubElement(
                report_host, "ReportItem",
                attrib={
                    "port": str(port),
                    "svc_name": service_name,
                    "protocol": proto,
                    "severity": str(sev_int),
                    "pluginID": str(plugin_id),
                    "pluginName": f"USARE: {cve_id}",
                    "pluginFamily": "General",
                },
            )
            v_desc = ET.SubElement(vuln_item, "description")
            v_desc.text = cve_entry.get("description", "")[:500]
            v_risk = ET.SubElement(vuln_item, "risk_factor")
            v_risk.text = sev_str
            v_score = ET.SubElement(vuln_item, "cvss_base_score")
            v_score.text = str(score)
            if cve_id.startswith("CVE-"):
                cve_el = ET.SubElement(vuln_item, "cve")
                cve_el.text = cve_id
            if cve_entry.get("is_cisa_kev"):
                kev_el = ET.SubElement(vuln_item, "see_also")
                kev_el.text = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    xml_str = _pretty_xml(nessus_run)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(xml_str)
    logger.info("[export] Nessus XML written: %s", filename)
    return filename


# ─────────────────────────────────────────────────────────────────────────────
# Metasploit db_import XML export
# ─────────────────────────────────────────────────────────────────────────────

def export_metasploit(
    scan_data: Dict[str, Any],
    out_dir: str = "logs",
) -> str:
    """
    Export scan_data to Metasploit db_import-compatible XML.
    Returns path to the written file.

    Format: <MetasploitV5><hosts><host>...<services>...<vulns>...
    (Accepted by: db_import /path/to/file.xml in msfconsole)
    """
    os.makedirs(out_dir, exist_ok=True)
    target = scan_data.get("target", "unknown")
    ts = int(scan_data.get("scan_start", time.time()))
    filename = os.path.join(out_dir, f"usare_{target.replace('.','_')}_{ts}_msf.xml")

    root = ET.Element("MetasploitV5")
    db = ET.SubElement(root, "db", attrib={"version": "1"})
    hosts_el = ET.SubElement(db, "hosts")

    host_el = ET.SubElement(hosts_el, "host")
    ET.SubElement(host_el, "address").text = target
    ET.SubElement(host_el, "mac").text = ""
    ET.SubElement(host_el, "comm").text = ""
    ET.SubElement(host_el, "name").text = target

    # OS
    os_fp = scan_data.get("os_detection") or scan_data.get("os_fingerprint") or {}
    ET.SubElement(host_el, "os_name").text = os_fp.get("os_name", "Unknown")
    ET.SubElement(host_el, "os_flavor").text = ""
    ET.SubElement(host_el, "os_sp").text = ""
    ET.SubElement(host_el, "os_lang").text = ""
    ET.SubElement(host_el, "os_family").text = ""

    whois = scan_data.get("whois") or {}
    ET.SubElement(host_el, "purpose").text = "device"
    ET.SubElement(host_el, "info").text = whois.get("organization", "")
    ET.SubElement(host_el, "comments").text = "Imported from USARE"
    ET.SubElement(host_el, "scope").text = ""
    ET.SubElement(host_el, "virtual_host").text = ""
    ET.SubElement(host_el, "arch").text = ""
    ET.SubElement(host_el, "state").text = "alive"

    # Services
    svcs_el = ET.SubElement(host_el, "services")
    scan_results = scan_data.get("scan_results", [])
    service_info = scan_data.get("service_info", {}) or {}
    banners = scan_data.get("banners", {}) or {}

    for port_entry in scan_results:
        port = port_entry.get("port", 0)
        state = str(port_entry.get("state", "")).lower()
        if state not in ("open", "open_filtered"):
            continue
        svc = service_info.get(port) or service_info.get(str(port)) or {}
        banner = banners.get(port) or banners.get(str(port)) or {}
        service_name = svc.get("service") or port_entry.get("service_guess") or ""
        proto = _port_protocol(port, svc)
        version = svc.get("version") or svc.get("product") or banner.get("version") or ""

        svc_el = ET.SubElement(svcs_el, "service")
        ET.SubElement(svc_el, "port").text = str(port)
        ET.SubElement(svc_el, "proto").text = proto
        ET.SubElement(svc_el, "state").text = "open"
        ET.SubElement(svc_el, "name").text = service_name
        ET.SubElement(svc_el, "info").text = version

    # Vulns
    vulns_el = ET.SubElement(host_el, "vulns")
    vulns = scan_data.get("vulnerabilities", {}) or {}

    for port_str, port_vulns in vulns.items():
        port = int(port_str) if str(port_str).isdigit() else port_str
        svc = service_info.get(port) or service_info.get(str(port)) or {}
        service_name = svc.get("service") or ""
        for cve_entry in (port_vulns or [])[:20]:
            cve_id   = cve_entry.get("cve_id", "")
            score    = float(cve_entry.get("base_score") or 0.0)
            desc     = cve_entry.get("description", "")[:500]
            is_kev   = cve_entry.get("is_cisa_kev", False)
            refs = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else ""
            if is_kev:
                refs += " https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

            vuln_el = ET.SubElement(vulns_el, "vuln")
            ET.SubElement(vuln_el, "title").text = cve_id
            ET.SubElement(vuln_el, "vuln_detail").text = desc
            ET.SubElement(vuln_el, "refs").text = refs.strip()
            ET.SubElement(vuln_el, "exploited_at").text = ""
            info = ET.SubElement(vuln_el, "info")
            info.text = f"Port: {port} | Service: {service_name} | CVSS: {score}"

    xml_str = _pretty_xml(root)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(xml_str)
    logger.info("[export] Metasploit XML written: %s", filename)
    return filename


# ─────────────────────────────────────────────────────────────────────────────
# Second-pass OPEN_FILTERED verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_open_filtered(
    target: str,
    filtered_ports: List[int],
    timeout: float = 3.0,
) -> Dict[int, str]:
    """
    For each OPEN_FILTERED port, attempt a TCP connect + ACK probe to push
    to definitive OPEN or FILTERED.
    Returns dict {port: "open" | "filtered" | "closed"}.
    """
    import socket as _sock
    results: Dict[int, str] = {}
    for port in filtered_ports:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((target, port))
            s.close()
            if rc == 0:
                results[port] = "open"
            elif rc in (111, 10061):   # ECONNREFUSED
                results[port] = "closed"
            else:
                results[port] = "filtered"
        except Exception:
            results[port] = "filtered"
    return results
