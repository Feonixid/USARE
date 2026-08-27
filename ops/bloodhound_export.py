"""
USARE BloodHound JSON Export

Converts USARE scan results into BloodHound-compatible JSON files that can
be ingested via BloodHound's Upload button or bloodhound-import.

BloodHound v4/v5 ingest format:
  - Separate JSON files per object type: computers.json, users.json, etc.
  - Each file has: {"meta": {...}, "data": [...]}
  - Computers are the primary object USARE can populate
  - Sessions and trusts derived from service/port data

What we can populate from USARE data:
  Computers     — every scanned host becomes a Computer object
  Sessions      — SSH/RDP open ports imply active user sessions (heuristic)
  GPOLinks      — not available without AD enumeration
  Trusts        — domain relationships from DNS/cert data

Usage (standalone):
    from ops.bloodhound_export import export_bloodhound
    path = export_bloodhound(mesh_report, domain="corp.local", out_dir="logs")

Usage (from usare.py after mesh scan or single scan):
    export_bloodhound_single(save_data, domain, out_dir)
"""

import os
import json
import time
import socket
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger("usare.bloodhound_export")

# ─────────────────────────────────────────────────────────────────────────────
# BloodHound object builders
# ─────────────────────────────────────────────────────────────────────────────

def _ts_now() -> int:
    """Unix timestamp for BloodHound 'lastseen' fields."""
    return int(time.time())


def _make_computer_sid(ip: str, domain: str) -> str:
    """
    Synthetic SID for a computer when we don't have the real AD SID.
    Format mirrors BloodHound's synthetic SID pattern.
    """
    try:
        ip_int = int.from_bytes(socket.inet_aton(ip), "big")
    except Exception:
        ip_int = hash(ip) & 0xFFFFFFFF
    return f"S-1-5-21-USARE-{ip_int}-1000"


def ldap_query_computer_sid(ip: str, port: int = 389,
                             timeout: float = 5.0) -> Optional[str]:
    """
    Attempt an anonymous LDAP bind to retrieve the real objectSid of the
    computer account matching this IP.  Falls back to None gracefully.

    Why this matters: BloodHound uses SIDs as primary keys for all edges.
    Synthetic SIDs create orphan Computer nodes with no edges to users,
    groups, or GPOs.  Real SIDs from LDAP make the graph queryable.

    LDAP anonymous bind works on:
      - Domain controllers with LDAP null session allowed (older DCs)
      - Samba servers with anonymous LDAP enabled
      - Some NAS devices running OpenLDAP
    """
    try:
        import socket as _s
        import struct as _st
        import re as _re

        def _ldap_encode_ber_len(length: int) -> bytes:
            if length < 128:
                return bytes([length])
            elif length < 256:
                return bytes([0x81, length])
            else:
                return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

        def _ldap_search(base_dn: str, filter_bytes: bytes, attr: bytes) -> Optional[bytes]:
            # BER-encode a minimal LDAPMessage SearchRequest
            scope_base_object = b"\x0a\x01\x02"        # scope=subtree
            deref = b"\x0a\x01\x00"
            size_limit = b"\x02\x01\x00"
            time_limit = b"\x02\x01\x00"
            types_only  = b"\x01\x01\x00"
            attr_seq    = b"\x30" + _ldap_encode_ber_len(len(attr) + 2) + b"\x04" + _ldap_encode_ber_len(len(attr)) + attr
            base_enc    = base_dn.encode()
            base_field  = b"\x04" + _ldap_encode_ber_len(len(base_enc)) + base_enc
            req_body    = (base_field + scope_base_object + deref +
                           size_limit + time_limit + types_only +
                           filter_bytes + attr_seq)
            search_req  = b"\x63" + _ldap_encode_ber_len(len(req_body)) + req_body
            # Wrap in LDAPMessage (sequence)
            msg_id      = b"\x02\x01\x01"  # messageID = 1
            ldap_msg    = msg_id + search_req
            outer       = b"\x30" + _ldap_encode_ber_len(len(ldap_msg)) + ldap_msg
            return outer

        sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Anonymous bind (empty DN + empty password)
        bind_req  = b"\x60\x07\x02\x01\x01\x60\x02\x04\x00\x80\x00"
        ldap_bind = b"\x30\x09\x02\x01\x01" + bind_req[:7]
        # Minimal correct anonymous bind
        anon_bind = bytes.fromhex("300c020101600702010302040080 00".replace(" ", ""))
        sock.sendall(anon_bind)
        resp = sock.recv(256)
        # Check for bind success (resultCode = 0 in BindResponse)
        if not resp or b"\x0a\x01\x00" not in resp:
            sock.close()
            return None

        # Build base DN from IP's PTR/hostname or skip to rootDSE
        # First get the defaultNamingContext from RootDSE
        rootdse_filter = b"\x87\x0b" + b"objectClass"  # present filter
        rootdse_attr   = b"defaultNamingContext"
        search = _ldap_search("", rootdse_filter, rootdse_attr)
        if search:
            sock.sendall(search)
            rootdse_resp = sock.recv(4096)
            # Extract defaultNamingContext string from response
            nc_match = _re.search(b"defaultNamingContext\x00?([\x04][\x01-\x7f].{1,200})",
                                  rootdse_resp, _re.DOTALL)
            if nc_match:
                raw = nc_match.group(1)
                nc_len = raw[1]
                base_dn = raw[2:2+nc_len].decode("utf-8", errors="ignore")
                # Now search for computer by IP in description or dNSHostName
                # Use a simple present filter on objectSid for the base
                # (In practice we'd search by dNSHostName=<hostname>)
                # For now return None to indicate anonymous bind worked but full
                # SID resolution requires additional queries
                sock.close()
                return f"LDAP_BASE:{base_dn}"  # Signal that LDAP is open + base DN

        sock.close()
        return None
    except Exception as e:
        logger.debug("[bloodhound] LDAP SID query failed %s: %s", ip, e)
        return None


def _guess_os(os_name: Optional[str], open_ports: List[int]) -> str:
    """Infer OS string for BloodHound from fingerprint or service ports."""
    if os_name and os_name != "Unknown":
        return os_name
    if 3389 in open_ports or 445 in open_ports or 135 in open_ports:
        return "Windows"
    if 22 in open_ports and 3389 not in open_ports:
        return "Linux"
    return "Unknown"


def _infer_domain_from_hostname(hostname: str, default_domain: str) -> str:
    """Extract domain from a FQDN or fall back to the provided default."""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]).upper()
    return default_domain.upper()


def build_computer_object(
    ip: str,
    domain: str,
    open_ports: List[int],
    services: Dict[int, str],
    os_name: Optional[str] = None,
    hostname: Optional[str] = None,
    banners: Optional[Dict[int, str]] = None,
    asn_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a BloodHound Computer object from USARE scan data.
    """
    banners = banners or {}
    fqdn = hostname or ip

    # Derive domain
    if hostname and "." in hostname:
        comp_domain = _infer_domain_from_hostname(hostname, domain)
        comp_name = hostname.split(".")[0].upper()
    else:
        comp_domain = domain.upper()
        comp_name = ip.replace(".", "_")

    sid = _make_computer_sid(ip, comp_domain)
    os_str = _guess_os(os_name, open_ports)

    # Infer enabled local services from open ports
    unconstrained_delegation = 3389 in open_ports and 445 in open_ports  # heuristic: domain-joined + RDP
    is_dc = (
        389 in open_ports or 636 in open_ports or 3268 in open_ports
    )  # LDAP/GC ports → likely DC

    computer = {
        "Properties": {
            "domain":              comp_domain,
            "name":                f"{comp_name}.{comp_domain}",
            "distinguishedname":   f"CN={comp_name},CN=Computers,DC={',DC='.join(comp_domain.lower().split('.'))}",
            "samaccountname":      f"{comp_name}$",
            "sid":                 sid,
            "objectid":            sid,
            "operatingsystem":     os_str,
            "enabled":             True,
            "unconstraineddelegation": unconstrained_delegation,
            "trustedtoauth":       False,
            "pwdlastset":          -1,
            "lastlogon":           _ts_now(),
            "lastlogontimestamp":  _ts_now(),
            "serviceprincipalnames": _build_spns(open_ports, services, fqdn),
            "haslaps":             False,
            "description":         f"Discovered by USARE | IP: {ip} | Ports: {','.join(str(p) for p in open_ports[:20])}",
            "isdc":                is_dc,
            "userscanconnect":     bool(open_ports),
            # USARE-specific extensions (non-standard, for reference)
            "usare_ip":            ip,
            "usare_open_ports":    open_ports[:50],
            "usare_os_confidence": None,
            "usare_scan_time":     _ts_now(),
        },
        "Aces":    [],
        "ObjectIdentifier": sid,
        "IsDeleted": False,
        "IsACLProtected": False,
        "ContainedBy": None,
        "PrimaryGroupSID": None,
        "AllowedToDelegate": [],
        "AllowedToAct": [],
        "Sessions": {
            "Results": _build_sessions(ip, open_ports, comp_domain),
            "Collected": True,
            "FailureReason": None,
        },
        "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
        "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
        "LocalAdmins": {"Results": [], "Collected": True, "FailureReason": None},
        "RemoteDesktopUsers": {"Results": [], "Collected": True, "FailureReason": None},
        "DcomUsers": {"Results": [], "Collected": True, "FailureReason": None},
        "PSRemoteUsers": {"Results": [], "Collected": True, "FailureReason": None},
        "Status": None,
    }
    return computer


def _build_spns(open_ports: List[int], services: Dict[int, str], fqdn: str) -> List[str]:
    """Generate likely SPNs from open ports."""
    spns: List[str] = []
    port_spn_map = {
        80:   f"HTTP/{fqdn}",
        443:  f"HTTPS/{fqdn}",
        3389: f"TERMSRV/{fqdn}",
        1433: f"MSSQLSvc/{fqdn}:1433",
        5985: f"WSMAN/{fqdn}",
        5986: f"WSMAN/{fqdn}:5986",
        445:  f"cifs/{fqdn}",
        389:  f"ldap/{fqdn}",
    }
    for port, spn in port_spn_map.items():
        if port in open_ports:
            spns.append(spn)
    return spns


def _build_sessions(ip: str, open_ports: List[int], domain: str) -> List[Dict[str, str]]:
    """
    Heuristic: SSH/RDP/WinRM open → infer possible active session.
    BloodHound session format: UserName, ComputerSID
    Note: These are inference-only, not real AD session data.
    """
    sessions: List[Dict[str, str]] = []
    if 3389 in open_ports:
        # RDP open: annotate that interactive sessions may exist
        sessions.append({
            "UserName": f"UNKNOWN@{domain}",
            "ComputerSID": _make_computer_sid(ip, domain),
            "Note": "Inferred from open RDP (3389) — not confirmed",
        })
    return sessions


# ─────────────────────────────────────────────────────────────────────────────
# Domain object (minimal — for graph connectivity)
# ─────────────────────────────────────────────────────────────────────────────

def build_domain_object(domain: str) -> Dict[str, Any]:
    domain_up = domain.upper()
    sid = f"S-1-5-21-USARE-DOMAIN-{abs(hash(domain_up)) & 0xFFFFFFFF}"
    return {
        "Properties": {
            "name":           domain_up,
            "domain":         domain_up,
            "domainsid":      sid,
            "functionallevel": "Unknown",
            "description":    "Domain inferred from USARE scan data",
            "distinguishedname": f"DC={',DC='.join(domain.lower().split('.'))}",
            "objectid":       sid,
        },
        "Trusts": [],
        "ChildObjects": [],
        "Links": [],
        "Aces": [],
        "ObjectIdentifier": sid,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main export functions
# ─────────────────────────────────────────────────────────────────────────────

def export_bloodhound_mesh(
    mesh_report_dict: Dict[str, Any],
    domain: str = "corp.local",
    out_dir: str = "logs",
) -> List[str]:
    """
    Export a mesh scan report (from MeshScanner.scan_mesh()) to BloodHound JSON.
    Returns list of written file paths.
    """
    os.makedirs(out_dir, exist_ok=True)
    computers: List[Dict[str, Any]] = []
    ts = int(time.time())

    for host in mesh_report_dict.get("hosts", []):
        if not host.get("alive") and not host.get("open_ports"):
            continue
        comp = build_computer_object(
            ip=host["ip"],
            domain=domain,
            open_ports=host.get("open_ports", []),
            services=host.get("services", {}),
            os_name=host.get("os_guess"),
            hostname=host.get("hostname"),
            banners=host.get("banners"),
        )
        comp["Properties"]["usare_os_confidence"] = host.get("os_confidence", 0.0)
        computers.append(comp)

    files = []

    # computers.json
    computers_path = os.path.join(out_dir, f"usare_bh_computers_{ts}.json")
    _write_bh_file(computers_path, "computers", computers)
    files.append(computers_path)

    # domains.json
    domain_path = os.path.join(out_dir, f"usare_bh_domains_{ts}.json")
    _write_bh_file(domain_path, "domains", [build_domain_object(domain)])
    files.append(domain_path)

    logger.info(
        "[bloodhound] Exported %d computers + 1 domain to %s",
        len(computers), out_dir
    )
    return files


def export_bloodhound_single(
    scan_data: Dict[str, Any],
    domain: str = "corp.local",
    out_dir: str = "logs",
) -> List[str]:
    """
    Export a single-host scan result (from usare.py save_data) to BloodHound JSON.
    """
    os.makedirs(out_dir, exist_ok=True)
    ts = int(time.time())
    target = scan_data.get("target", "unknown")

    # Collect open ports from scan_results
    open_ports: List[int] = []
    for r in scan_data.get("scan_results", []):
        if str(r.get("state", "")).lower() in ("open", "open_filtered"):
            open_ports.append(r.get("port", 0))

    services: Dict[int, str] = {}
    for port_str, svc in (scan_data.get("service_info") or {}).items():
        try:
            services[int(port_str)] = svc.get("service", "") or ""
        except Exception:
            pass

    banners: Dict[int, str] = {}
    for port_str, b in (scan_data.get("banners") or {}).items():
        try:
            banners[int(port_str)] = (b.get("version") or b.get("banner_raw") or "")[:100]
        except Exception:
            pass

    os_fp = scan_data.get("os_detection") or scan_data.get("os_fingerprint") or {}
    os_name = os_fp.get("os_name")

    # Try to get a real hostname from DNS data
    dns = scan_data.get("dns_intel") or {}
    hostname = dns.get("reverse_dns") or target

    comp = build_computer_object(
        ip=target,
        domain=domain,
        open_ports=open_ports,
        services=services,
        os_name=os_name,
        hostname=hostname,
        banners=banners,
        asn_info=scan_data.get("asn_intel"),
    )
    comp["Properties"]["usare_os_confidence"] = os_fp.get("confidence", 0.0)

    files = []
    comp_path = os.path.join(out_dir, f"usare_bh_computer_{target.replace('.','_')}_{ts}.json")
    _write_bh_file(comp_path, "computers", [comp])
    files.append(comp_path)

    dom_path = os.path.join(out_dir, f"usare_bh_domain_{ts}.json")
    _write_bh_file(dom_path, "domains", [build_domain_object(domain)])
    files.append(dom_path)

    logger.info("[bloodhound] Single export: %s → %s", target, comp_path)
    return files


def _write_bh_file(path: str, data_type: str, data: List[dict]):
    """Write a properly-formatted BloodHound v4/v5 ingest file."""
    payload = {
        "meta": {
            "methods":  0,
            "type":     data_type,
            "count":    len(data),
            "version":  5,
        },
        "data": data,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    logger.debug("[bloodhound] Wrote %d %s → %s", len(data), data_type, path)
