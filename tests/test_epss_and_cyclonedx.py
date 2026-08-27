import os
import json
import pytest
from unittest.mock import patch, MagicMock

from recon.vuln_mapping import fetch_epss_scores, _EPSS_CACHE
from recon.doh_resolver import DoHResolver, DoHResult, DoHRecord
from ops.export_formats import export_cyclonedx
from recon.cert_intelligence import assess_tls_posture


class TestEPSSMapping:
    @patch("recon.vuln_mapping.requests.get")
    def test_fetch_epss_scores(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.97520",
                    "percentile": "0.99990",
                    "date": "2024-01-01",
                }
            ],
        }
        mock_get.return_value = mock_resp

        # Clear cache for test
        _EPSS_CACHE.pop("CVE-2021-44228", None)

        res = fetch_epss_scores(["CVE-2021-44228"])
        assert "CVE-2021-44228" in res
        assert res["CVE-2021-44228"]["epss"] == pytest.approx(0.9752, rel=1e-3)
        assert res["CVE-2021-44228"]["percentile"] == pytest.approx(0.9999, rel=1e-3)


class TestDNSSECAudit:
    def test_audit_dnssec_secure(self):
        resolver = DoHResolver()

        with patch.object(resolver, "resolve") as mock_resolve:
            # Mock A record with AD=True
            res_a = DoHResult(domain="example.com", status=0, authenticated_data=True)
            # Mock DS record
            res_ds = DoHResult(
                domain="example.com",
                records=[DoHRecord(name="example.com", record_type="DS", value="12345 8 2 ABCDEF")],
            )
            # Mock DNSKEY record
            res_key = DoHResult(
                domain="example.com",
                records=[DoHRecord(name="example.com", record_type="DNSKEY", value="257 3 8 AwEAA...")],
            )

            mock_resolve.side_effect = lambda domain, rtype: (
                res_a if rtype == "A" else res_ds if rtype == "DS" else res_key
            )

            audit = resolver.audit_dnssec("example.com")
            assert audit["dnssec_status"] == "SECURE"
            assert audit["authenticated_data"] is True
            assert audit["has_ds_record"] is True
            assert audit["has_dnskey_record"] is True


class TestCycloneDXExport:
    def test_export_cyclonedx_sbom(self, tmp_path):
        sample_data = {
            "target": "192.168.1.100",
            "open_ports": [80, 443],
            "banners": {
                80: {
                    "service": "http",
                    "name": "apache",
                    "version": "2.4.51",
                    "cpe": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
                },
                443: {
                    "service": "https",
                    "name": "nginx",
                    "version": "1.18.0",
                },
            },
            "vulnerabilities": {
                "80": [
                    {
                        "cve_id": "CVE-2021-41773",
                        "cvss_score": 7.5,
                        "description": "Path traversal in Apache 2.4.49/2.4.50",
                        "epss_score": 0.945,
                        "epss_percentile": 0.998,
                    }
                ]
            },
        }

        out_file = str(tmp_path / "sbom.cdx.json")
        res_path = export_cyclonedx(sample_data, filename=out_file)
        assert os.path.exists(res_path)

        with open(res_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert len(doc["components"]) == 2
        assert len(doc["vulnerabilities"]) == 1

        v = doc["vulnerabilities"][0]
        assert v["id"] == "CVE-2021-41773"
        assert v["ratings"][0]["score"] == 7.5
        assert v["ratings"][0]["severity"] == "high"


class TestTLSPosture:
    def test_assess_tls_posture_structure(self):
        # Test with unreachable mock port to verify schema return
        res = assess_tls_posture("127.0.0.1", port=65530, timeout=0.2)
        assert "target" in res
        assert "port" in res
        assert "tls13_supported" in res
        assert "grade" in res
        assert isinstance(res["deprecated_protocols"], list)
