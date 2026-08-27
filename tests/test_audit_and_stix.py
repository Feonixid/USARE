import json
import os
import pytest
from recon.http_security_intel import grade_http_security_headers
from ops.export_formats import export_sarif, export_stix


def test_grade_http_security_headers_perfect():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    res = grade_http_security_headers(headers)
    assert res["score"] == 100
    assert res["grade"] == "A+"
    assert len(res["missing_headers"]) == 0
    assert len(res["warnings"]) == 0


def test_grade_http_security_headers_weak():
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
    }
    res = grade_http_security_headers(headers)
    assert res["score"] == 0
    assert res["grade"] == "F"
    assert len(res["missing_headers"]) >= 5
    assert len(res["warnings"]) >= 1


def test_export_sarif(tmp_path):
    test_data = {
        "target": "192.168.1.10",
        "open_ports": [80, 443],
        "vulnerabilities": {
            "80": [
                {
                    "cve_id": "CVE-2021-41773",
                    "cvss_score": 7.5,
                    "description": "Path traversal in Apache HTTP Server",
                }
            ]
        },
    }
    out_file = str(tmp_path / "report.sarif")
    res_path = export_sarif(test_data, filename=out_file)
    assert os.path.exists(res_path)

    with open(res_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    results = doc["runs"][0]["results"]
    assert len(results) == 3  # 2 ports + 1 CVE


def test_export_stix(tmp_path):
    test_data = {
        "target": "10.0.0.5",
        "open_ports": [22],
        "vulnerabilities": {
            "22": [
                {
                    "cve_id": "CVE-2023-38408",
                    "cvss_score": 9.8,
                    "description": "OpenSSH PKCS#11 provider vulnerability",
                }
            ]
        },
    }
    out_file = str(tmp_path / "bundle.stix.json")
    res_path = export_stix(test_data, filename=out_file)
    assert os.path.exists(res_path)

    with open(res_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    assert doc["type"] == "bundle"
    assert len(doc["objects"]) >= 4  # identity, infra, ip, vuln
    types = [o["type"] for o in doc["objects"]]
    assert "identity" in types
    assert "infrastructure" in types
    assert "ipv4-addr" in types
    assert "vulnerability" in types
