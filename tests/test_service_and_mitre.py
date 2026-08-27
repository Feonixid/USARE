import pytest
from unittest.mock import patch, MagicMock

from recon.syn_scanner import StealthScanner, ScanConfig, PortState
from recon.vuln_mapping import map_mitre_attack_techniques
from ops.correlator import IntelCorrelator


class TestServiceDetectionAndOSFingerprint:
    def test_stealth_scanner_get_os_fingerprint(self):
        config = ScanConfig(target_ip="192.168.1.50")
        scanner = StealthScanner(config=config, show_progress=False)

        # Inject simulated response packets from a Windows host (TTL=128, Window=64240, DF=True)
        scanner._response_data = [
            {"ttl": 128, "window": 64240, "df": True, "ip_id": 1001},
            {"ttl": 128, "window": 64240, "df": True, "ip_id": 1002},
            {"ttl": 128, "window": 64240, "df": True, "ip_id": 1003},
        ]

        fp = scanner.get_os_fingerprint()
        assert "os_name" in fp
        assert fp["ttl_initial"] == 128
        assert fp["window_size"] == 64240
        assert fp["df_flag"] is True
        assert fp["confidence"] > 0.0

    def test_stealth_scanner_get_os_fingerprint_empty(self):
        config = ScanConfig(target_ip="10.0.0.1")
        scanner = StealthScanner(config=config, show_progress=False)
        scanner._response_data = []

        fp = scanner.get_os_fingerprint()
        assert fp["os_name"] == "Unknown"
        assert fp["confidence"] == 0.0


class TestMitreAttackMapping:
    def test_map_mitre_attack_techniques(self):
        banners = {
            22: {"service": "ssh", "product": "OpenSSH", "version": "8.2p1"},
            80: {"service": "http", "product": "Apache", "version": "2.4.41"},
            445: {"service": "microsoft-ds", "product": "SMB"},
            3389: {"service": "ms-wbt-server", "product": "RDP"},
        }
        vulns = {
            "80": [
                {
                    "cve_id": "CVE-2021-41773",
                    "cvss_score": 7.5,
                    "description": "Path traversal in Apache",
                }
            ]
        }

        res = map_mitre_attack_techniques(banners, vulns)
        assert "mitre_techniques" in res
        assert "remediations" in res
        tech_ids = [t["technique_id"] for t in res["mitre_techniques"]]

        # Should map general discovery, SSH, HTTP, SMB, and RDP
        assert "T1046" in tech_ids
        assert "T1133" in tech_ids
        assert "T1190" in tech_ids
        assert "T1021.002" in tech_ids
        assert "T1021.001" in tech_ids

        # Should contain actionable remediations
        rem_priorities = [r["priority"] for r in res["remediations"]]
        assert "HIGH" in rem_priorities

    def test_intel_correlator_with_mitre(self):
        correlator = IntelCorrelator("192.168.1.1")
        all_data = {
            "banners": {
                22: {"service": "ssh", "version": "OpenSSH_7.4"},
            },
            "vulnerabilities": {},
            "open_ports": [22],
        }

        result = correlator.correlate(all_data)
        assert len(result.mitre_attack) >= 2  # T1046 + T1133
        assert len(result.remediations) >= 1
        d = result.to_dict()
        assert "mitre_attack" in d
        assert "remediations" in d
