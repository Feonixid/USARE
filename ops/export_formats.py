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


def export_sarif(
    all_data: Dict[str, Any],
    filename: str = "logs/usare_report.sarif",
) -> str:
    """
    Export USARE scan results to OASIS SARIF 2.1.0 JSON format for
    standardized SIEM, GitHub Security, and CI/CD ingestion.
    """
    import json
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    target = all_data.get("target") or all_data.get("target_ip") or "127.0.0.1"

    results_list = []
    rules_dict = {}

    # Open ports findings
    open_ports = all_data.get("open_ports", []) or []
    for p in open_ports:
        rule_id = f"USARE-PORT-{p}"
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": "OpenPortExposed",
                "shortDescription": {"text": f"Exposed open port {p}"},
                "defaultConfiguration": {"level": "note"}
            }
        results_list.append({
            "ruleId": rule_id,
            "level": "note",
            "message": {"text": f"Open port {p} detected on target {target}."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"net://{target}:{p}"}
                }
            }]
        })

    # CVE findings
    vulns = all_data.get("vulnerabilities", {}) or {}
    for port_str, cve_list in vulns.items():
        for cve in cve_list:
            cve_id = cve.get("cve_id", "CVE-UNKNOWN")
            score = float(cve.get("cvss_score", 0.0) or 0.0)
            level = "error" if score >= 7.0 else "warning" if score >= 4.0 else "note"
            if cve_id not in rules_dict:
                rules_dict[cve_id] = {
                    "id": cve_id,
                    "name": "VulnerabilityFinding",
                    "shortDescription": {"text": cve.get("description", "")[:200] or cve_id},
                    "defaultConfiguration": {"level": level}
                }
            results_list.append({
                "ruleId": cve_id,
                "level": level,
                "message": {"text": f"{cve_id} (CVSS {score}): {cve.get('description', '')[:300]}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"net://{target}:{port_str}"}
                    }
                }]
            })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "USARE",
                    "version": "2.1.0",
                    "informationUri": "https://github.com/Feonixid/USARE",
                    "rules": list(rules_dict.values())
                }
            },
            "results": results_list
        }]
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2)
    logger.info("[export] SARIF 2.1.0 written: %s", filename)
    return filename


def export_stix(
    all_data: Dict[str, Any],
    filename: str = "logs/usare_report.stix.json",
) -> str:
    """
    Export USARE scan results to OASIS STIX 2.1 JSON bundle format for
    threat intelligence platforms (OpenCTI, MISP, SIEM).
    """
    import json
    import uuid
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    target = all_data.get("target") or all_data.get("target_ip") or "127.0.0.1"
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'usare.engine')}"
    infra_id = f"infrastructure--{uuid.uuid5(uuid.NAMESPACE_DNS, f'usare.infra.{target}')}"
    ip_id = f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_DNS, f'usare.ip.{target}')}"

    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_str,
            "modified": now_str,
            "name": "USARE Recon Engine",
            "identity_class": "system",
        },
        {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": now_str,
            "modified": now_str,
            "name": f"Target Host {target}",
            "description": f"Network infrastructure evaluated by USARE at {target}",
            "infrastructure_types": ["endpoint"],
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": ip_id,
            "value": target if not target.replace(".", "").isdigit() is False else "127.0.0.1",
        }
    ]

    # Add observed vulnerabilities
    vulns = all_data.get("vulnerabilities", {}) or {}
    for port_str, cve_list in vulns.items():
        for cve in cve_list:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                vuln_stix_id = f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_DNS, cve_id)}"
                objects.append({
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": vuln_stix_id,
                    "created": now_str,
                    "modified": now_str,
                    "name": cve_id,
                    "description": cve.get("description", ""),
                    "external_references": [
                        {
                            "source_name": "cve",
                            "external_id": cve_id,
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        }
                    ]
                })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    logger.info("[export] STIX 2.1 bundle written: %s", filename)
    return filename


def export_cyclonedx(
    all_data: Dict[str, Any],
    filename: str = "logs/usare_report.cdx.json",
) -> str:
    """
    Export USARE scan results to OWASP CycloneDX 1.5 JSON SBOM format
    for DevSecOps asset management and supply chain security tools.
    """
    import json
    import uuid
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    target = all_data.get("target") or all_data.get("target_ip") or "127.0.0.1"
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    components: List[Dict[str, Any]] = []
    vulnerabilities: List[Dict[str, Any]] = []

    # Map discovered services/banners as CycloneDX components
    banners = all_data.get("banners", {}) or {}
    open_ports = all_data.get("open_ports", []) or []

    for port in open_ports:
        b_info = banners.get(port) or banners.get(str(port)) or {}
        srv_name = b_info.get("service") or b_info.get("name") or f"service-{port}"
        srv_version = b_info.get("version") or "unknown"
        bom_ref = f"component-{target}-{port}"

        comp_entry: Dict[str, Any] = {
            "type": "service",
            "bom-ref": bom_ref,
            "name": srv_name,
            "version": srv_version,
            "properties": [
                {"name": "network:target", "value": target},
                {"name": "network:port", "value": str(port)},
                {"name": "network:transport", "value": "tcp"}
            ]
        }
        if b_info.get("cpe"):
            comp_entry["cpe"] = b_info["cpe"]
        components.append(comp_entry)

    # Map CVE vulnerabilities to CycloneDX vulnerability objects
    vulns = all_data.get("vulnerabilities", {}) or {}
    for port_str, cve_list in vulns.items():
        bom_ref = f"component-{target}-{port_str}"
        for cve in cve_list:
            cve_id = cve.get("cve_id", "CVE-UNKNOWN")
            score = float(cve.get("cvss_score", 0.0) or 0.0)
            severity = "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium" if score >= 4.0 else "low"

            vuln_obj: Dict[str, Any] = {
                "id": cve_id,
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                "ratings": [{
                    "score": score,
                    "severity": severity,
                    "method": "CVSSv31"
                }],
                "description": cve.get("description", ""),
                "affects": [{"ref": bom_ref}]
            }
            if cve.get("epss_score") is not None:
                vuln_obj["properties"] = [
                    {"name": "epss:score", "value": str(cve.get("epss_score", 0.0))},
                    {"name": "epss:percentile", "value": str(cve.get("epss_percentile", 0.0))}
                ]
            vulnerabilities.append(vuln_obj)

    cdx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now_str,
            "tools": [{
                "vendor": "USARE",
                "name": "USARE Recon Engine",
                "version": "2.1.0"
            }],
            "component": {
                "type": "device",
                "name": target,
                "description": f"Audited network target: {target}"
            }
        },
        "components": components,
        "vulnerabilities": vulnerabilities
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(cdx_doc, f, indent=2)
    logger.info("[export] CycloneDX 1.5 SBOM written: %s", filename)
    return filename
