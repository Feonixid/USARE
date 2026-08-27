import os
import json
import pytest
from unittest.mock import patch, MagicMock
from io import BytesIO

from recon.doh_resolver import DoHResolver, DoHRecord, DoHResult
from ops.session_checkpoint import SessionCheckpointer, ScanCheckpoint


class TestDoHResolver:
    def test_init_default_providers(self):
        resolver = DoHResolver()
        assert len(resolver._providers) >= 3
        provider_names = [p["name"] for p in resolver._providers]
        assert "Cloudflare" in provider_names
        assert "Google" in provider_names
        assert "Quad9" in provider_names

    def test_init_preferred_provider(self):
        resolver = DoHResolver(preferred_provider="Google")
        assert resolver._providers[0]["name"] == "Google"

    def test_provider_rotation(self):
        resolver = DoHResolver(rotate_providers=True)
        p1 = resolver._get_provider()
        p2 = resolver._get_provider()
        p3 = resolver._get_provider()
        p4 = resolver._get_provider()
        assert p1["name"] != p2["name"] or len(resolver._providers) == 1
        assert p4["name"] == p1["name"]  # cycled back

    @patch("recon.doh_resolver.urlopen")
    def test_query_doh_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "Status": 0,
            "Answer": [
                {"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}
            ]
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        resolver = DoHResolver()
        res = resolver.resolve("example.com", "A")

        assert res.domain == "example.com"
        assert res.status == 0
        assert len(res.records) == 1
        assert res.records[0].name == "example.com"
        assert res.records[0].value == "93.184.216.34"
        assert res.records[0].ttl == 300
        assert res.error is None

    @patch("recon.doh_resolver.urlopen")
    def test_query_doh_error_handling(self, mock_urlopen):
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("Network unreachable")

        resolver = DoHResolver(max_retries=1)
        res = resolver.resolve("nonexistent.invalid", "A")

        assert res.error is not None
        assert len(res.records) == 0

    def test_record_to_dict(self):
        record = DoHRecord(name="test.org", record_type="A", value="1.2.3.4", ttl=60)
        d = record.to_dict()
        assert d["name"] == "test.org"
        assert d["type"] == "A"
        assert d["value"] == "1.2.3.4"
        assert d["ttl"] == 60


class TestSessionCheckpoint:
    def test_checkpoint_roundtrip(self, tmp_path):
        session_file = str(tmp_path / "test.usare_session")
        password = "test_secure_password_12345"

        cp = SessionCheckpointer(filepath=session_file, password=password)

        state = ScanCheckpoint(
            target="192.168.1.50",
            ports_probed=[22, 80, 443, 8080],
            ports_open=[80, 443],
            ports_closed=[22],
            ports_filtered=[8080],
            banners={"80": "nginx/1.18", "443": "nginx/1.18"},
            heat_level=0.15,
            packets_sent=4,
            scan_start_time=1000.0,
        )

        saved_path = cp.save(state)
        assert os.path.exists(saved_path)

        restored = cp.load()
        assert restored is not None
        assert restored.target == "192.168.1.50"
        assert restored.ports_probed == [22, 80, 443, 8080]
        assert restored.ports_open == [80, 443]
        assert restored.banners["80"] == "nginx/1.18"
        assert restored.heat_level == 0.15

    def test_get_remaining_ports(self, tmp_path):
        session_file = str(tmp_path / "test2.usare_session")
        cp = SessionCheckpointer(filepath=session_file, password="key")

        state = ScanCheckpoint(
            target="10.0.0.1",
            ports_probed=[21, 22, 80],
            ports_open=[80],
        )

        all_ports = [21, 22, 23, 25, 80, 443]
        remaining = cp.get_remaining_ports(state, all_ports)
        assert remaining == [23, 25, 443]

    def test_auto_interval_and_cleanup(self, tmp_path):
        session_file = str(tmp_path / "test3.usare_session")
        cp = SessionCheckpointer(filepath=session_file, password="key", auto_interval=3)

        state = ScanCheckpoint(target="10.0.0.1")

        assert cp.record_port(state) is None  # 1st
        assert cp.record_port(state) is None  # 2nd
        saved = cp.record_port(state)         # 3rd -> triggers save
        assert saved is not None
        assert os.path.exists(session_file)

        cp.cleanup()
        assert not os.path.exists(session_file)
