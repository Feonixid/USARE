"""
USARE Scan Diff / Change Tracking Engine

Compares encrypted scan outputs over time to detect:
- New ports opened / previously open ports now closed
- Service version changes (upgrades, downgrades)
- Certificate changes (issuer, expiry, SANs)
- Firewall rule changes (new filtering, removed filtering)
- OS fingerprint changes
- New services appearing on the network

Enables continuous monitoring by building a timeline of changes.
"""

import json
import time
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("usare.scan_diff")


@dataclass
class PortChange:
    """A change in port state between two scans."""
    port: int
    protocol: str
    change_type: str       # "opened", "closed", "service_changed", "version_changed"
    old_value: str = ""
    new_value: str = ""
    severity: str = "info"  # "info", "warning", "critical"

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "change": self.change_type,
            "old": self.old_value,
            "new": self.new_value,
            "severity": self.severity,
        }


@dataclass
class CertChange:
    """A change in TLS certificate."""
    port: int
    change_type: str      # "issuer_changed", "expiry_changed", "san_changed", "new_cert"
    old_value: str = ""
    new_value: str = ""
    severity: str = "warning"

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "change": self.change_type,
            "old": self.old_value,
            "new": self.new_value,
            "severity": self.severity,
        }


@dataclass
class DiffResult:
    """Complete diff between two scans."""
    target: str
    scan_a_time: str          # ISO timestamp of older scan
    scan_b_time: str          # ISO timestamp of newer scan
    port_changes: List[PortChange] = field(default_factory=list)
    cert_changes: List[CertChange] = field(default_factory=list)
    os_change: Optional[Tuple[str, str]] = None   # (old_os, new_os)
    firewall_change: Optional[Tuple[str, str]] = None
    new_services: List[Dict[str, Any]] = field(default_factory=list)
    removed_services: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    @property
    def total_changes(self) -> int:
        count = len(self.port_changes) + len(self.cert_changes) + len(self.new_services) + len(self.removed_services)
        if self.os_change:
            count += 1
        if self.firewall_change:
            count += 1
        return count

    @property
    def has_critical(self) -> bool:
        return any(
            c.severity == "critical"
            for c in self.port_changes + self.cert_changes
        )

    def to_dict(self) -> Dict:
        d: Dict[str, Any] = {
            "target": self.target,
            "scan_a": self.scan_a_time,
            "scan_b": self.scan_b_time,
            "total_changes": self.total_changes,
            "has_critical": self.has_critical,
            "port_changes": [c.to_dict() for c in self.port_changes],
            "cert_changes": [c.to_dict() for c in self.cert_changes],
            "summary": self.summary,
        }
        if self.os_change:
            d["os_change"] = {"old": self.os_change[0], "new": self.os_change[1]}
        if self.firewall_change:
            d["firewall_change"] = {"old": self.firewall_change[0], "new": self.firewall_change[1]}
        return d


class ScanDiffEngine:
    """
    Compares two scan result dictionaries and produces a structured diff.
    """

    # Ports that are security-critical when they appear/disappear
    CRITICAL_PORTS = {
        22, 23, 3389, 445, 139, 3306, 5432, 6379, 27017,
        2375, 8080, 8443, 9200, 11211, 6443,
    }

    def __init__(self):
        pass

    def diff(self, scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> DiffResult:
        """
        Compare two scan result dicts.

        Args:
            scan_a: The older scan (baseline)
            scan_b: The newer scan (current)
        """
        target = scan_b.get("target", scan_a.get("target", "unknown"))
        time_a = scan_a.get("scan_timestamp", scan_a.get("timestamp", "unknown"))
        time_b = scan_b.get("scan_timestamp", scan_b.get("timestamp", "unknown"))

        result = DiffResult(
            target=target,
            scan_a_time=str(time_a),
            scan_b_time=str(time_b),
        )

        self._diff_ports(scan_a, scan_b, result)
        self._diff_certs(scan_a, scan_b, result)
        self._diff_os(scan_a, scan_b, result)
        self._diff_firewall(scan_a, scan_b, result)
        self._diff_services(scan_a, scan_b, result)

        result.summary = self._build_summary(result)
        return result

    def _extract_ports(self, scan: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
        """Extract port → info mapping from scan results."""
        ports: Dict[int, Dict[str, Any]] = {}

        results = scan.get("scan_results", scan.get("results", []))
        if isinstance(results, list):
            for r in results:
                if isinstance(r, dict):
                    port = r.get("port", 0)
                    if port:
                        ports[port] = {
                            "state": r.get("state", "unknown"),
                            "service": r.get("service_guess", r.get("service", "")),
                            "version": r.get("version", ""),
                            "protocol": r.get("protocol", "tcp"),
                        }

        return ports

    def _diff_ports(self, scan_a: Dict, scan_b: Dict, result: DiffResult):
        """Compare port states between scans."""
        ports_a = self._extract_ports(scan_a)
        ports_b = self._extract_ports(scan_b)

        all_ports: Set[int] = set(ports_a.keys()) | set(ports_b.keys())

        for port in sorted(all_ports):
            in_a = port in ports_a
            in_b = port in ports_b

            a_state = ports_a.get(port, {}).get("state", "closed")
            b_state = ports_b.get(port, {}).get("state", "closed")
            a_open = "open" in str(a_state).lower()
            b_open = "open" in str(b_state).lower()

            proto = ports_b.get(port, ports_a.get(port, {})).get("protocol", "tcp")

            # New port opened
            if (not in_a or not a_open) and b_open:
                severity = "critical" if port in self.CRITICAL_PORTS else "warning"
                result.port_changes.append(PortChange(
                    port=port, protocol=proto,
                    change_type="opened",
                    old_value=str(a_state) if in_a else "not scanned",
                    new_value=str(b_state),
                    severity=severity,
                ))

            # Port closed
            elif a_open and (not in_b or not b_open):
                result.port_changes.append(PortChange(
                    port=port, protocol=proto,
                    change_type="closed",
                    old_value=str(a_state),
                    new_value=str(b_state) if in_b else "not scanned",
                    severity="info",
                ))

            # Service changed
            elif in_a and in_b and a_open and b_open:
                a_svc = ports_a[port].get("service", "")
                b_svc = ports_b[port].get("service", "")
                a_ver = ports_a[port].get("version", "")
                b_ver = ports_b[port].get("version", "")

                if a_svc and b_svc and a_svc != b_svc:
                    result.port_changes.append(PortChange(
                        port=port, protocol=proto,
                        change_type="service_changed",
                        old_value=a_svc,
                        new_value=b_svc,
                        severity="warning",
                    ))

                if a_ver and b_ver and a_ver != b_ver:
                    result.port_changes.append(PortChange(
                        port=port, protocol=proto,
                        change_type="version_changed",
                        old_value=f"{a_svc} {a_ver}",
                        new_value=f"{b_svc} {b_ver}",
                        severity="info",
                    ))

    def _diff_certs(self, scan_a: Dict, scan_b: Dict, result: DiffResult):
        """Compare TLS certificates."""
        certs_a = scan_a.get("crypto_fingerprint", {}).get("tls", {})
        certs_b = scan_b.get("crypto_fingerprint", {}).get("tls", {})

        all_ports: Set[str] = set(str(k) for k in certs_a.keys()) | set(str(k) for k in certs_b.keys())

        for port_str in sorted(all_ports):
            port = int(port_str) if port_str.isdigit() else 0
            a = certs_a.get(port_str, certs_a.get(port, {}))
            b = certs_b.get(port_str, certs_b.get(port, {}))

            if not a and b:
                result.cert_changes.append(CertChange(
                    port=port, change_type="new_cert",
                    new_value=b.get("cert_subject", ""),
                    severity="warning",
                ))
                continue

            if a and not b:
                continue

            # Issuer change
            a_issuer = a.get("cert_issuer", "")
            b_issuer = b.get("cert_issuer", "")
            if a_issuer and b_issuer and a_issuer != b_issuer:
                result.cert_changes.append(CertChange(
                    port=port, change_type="issuer_changed",
                    old_value=a_issuer, new_value=b_issuer,
                    severity="critical",
                ))

            # Subject change
            a_subject = a.get("cert_subject", "")
            b_subject = b.get("cert_subject", "")
            if a_subject and b_subject and a_subject != b_subject:
                result.cert_changes.append(CertChange(
                    port=port, change_type="subject_changed",
                    old_value=a_subject, new_value=b_subject,
                    severity="warning",
                ))

            # SAN changes
            a_sans = set(a.get("cert_sans", []))
            b_sans = set(b.get("cert_sans", []))
            if a_sans and b_sans and a_sans != b_sans:
                added = b_sans - a_sans
                removed = a_sans - b_sans
                if added or removed:
                    result.cert_changes.append(CertChange(
                        port=port, change_type="san_changed",
                        old_value=f"{len(a_sans)} SANs",
                        new_value=f"+{len(added)}/-{len(removed)} SANs",
                        severity="warning",
                    ))

    def _diff_os(self, scan_a: Dict, scan_b: Dict, result: DiffResult):
        """Compare OS fingerprints."""
        os_a = scan_a.get("correlation", {}).get("best_os",
               scan_a.get("os_fingerprint", {}).get("os_guess", ""))
        os_b = scan_b.get("correlation", {}).get("best_os",
               scan_b.get("os_fingerprint", {}).get("os_guess", ""))

        if os_a and os_b and os_a != os_b:
            result.os_change = (os_a, os_b)

    def _diff_firewall(self, scan_a: Dict, scan_b: Dict, result: DiffResult):
        """Compare firewall configurations."""
        fw_a = scan_a.get("acl_map", {}).get("firewall_summary", "")
        fw_b = scan_b.get("acl_map", {}).get("firewall_summary", "")

        if fw_a and fw_b and fw_a != fw_b:
            result.firewall_change = (fw_a, fw_b)

    def _diff_services(self, scan_a: Dict, scan_b: Dict, result: DiffResult):
        """Compare application-level services."""
        svcs_a = set(scan_a.get("app_probes", {}).get("services", {}).keys())
        svcs_b = set(scan_b.get("app_probes", {}).get("services", {}).keys())

        for port in svcs_b - svcs_a:
            svc = scan_b["app_probes"]["services"][port]
            result.new_services.append({
                "port": port,
                "protocol": svc.get("protocol", "unknown"),
                "version": svc.get("version", ""),
            })

        for port in svcs_a - svcs_b:
            svc = scan_a["app_probes"]["services"][port]
            result.removed_services.append({
                "port": port,
                "protocol": svc.get("protocol", "unknown"),
            })

    def _build_summary(self, result: DiffResult) -> str:
        """Build human-readable summary."""
        parts = []
        opened = sum(1 for c in result.port_changes if c.change_type == "opened")
        closed = sum(1 for c in result.port_changes if c.change_type == "closed")

        if opened:
            parts.append(f"{opened} port(s) opened")
        if closed:
            parts.append(f"{closed} port(s) closed")
        if result.cert_changes:
            parts.append(f"{len(result.cert_changes)} cert change(s)")
        if result.os_change:
            parts.append(f"OS changed: {result.os_change[0]} → {result.os_change[1]}")
        if result.firewall_change:
            parts.append("Firewall rules changed")
        if result.new_services:
            parts.append(f"{len(result.new_services)} new service(s)")

        if not parts:
            return "No significant changes detected."

        return "; ".join(parts) + "."


def diff_encrypted_scans(file_a: str, file_b: str, password: str) -> DiffResult:
    """
    Compare two encrypted scan files and return a structured diff.

    Args:
        file_a: Path to the older encrypted scan file
        file_b: Path to the newer encrypted scan file
        password: Decryption password
    """
    from ops.encryption import load_encrypted  # type: ignore

    scan_a = load_encrypted(file_a, password)
    scan_b = load_encrypted(file_b, password)

    engine = ScanDiffEngine()
    return engine.diff(scan_a, scan_b)
