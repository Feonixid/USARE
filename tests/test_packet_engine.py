import pytest
from core.packet_engine import (
    PacketEngine, PacketConfig, IPIDGenerator, TCPSeqGenerator,
    WIN10_BUILD_19045_TTL, WIN10_BUILD_19045_WINDOW, WIN10_BUILD_19045_WSCALE,
)
from scapy.all import IP, TCP

class TestIPIDGenerator:
    def test_incremental(self):
        gen = IPIDGenerator()
        ids = [gen.next_id() for _ in range(100)]
        for i in range(1, len(ids)):
            diff = (ids[i] - ids[i-1]) & 0xFFFF
            assert 1 <= diff <= 4, f"IP ID jump too large: {diff}"

    def test_wraps_at_65535(self):
        gen = IPIDGenerator()
        gen._counters["192.168.1.1"] = 0xFFFE
        id1 = gen.next_id("192.168.1.1")
        id2 = gen.next_id("192.168.1.1")
        assert id2 < id1 or id2 <= 0x0005

    def test_initial_offset(self):
        gen = IPIDGenerator()
        assert 256 <= gen.peek() <= 8192

class TestTCPSeqGenerator:
    def test_generates_32bit(self):
        isn = TCPSeqGenerator.generate_isn()
        assert 0 <= isn <= 0xFFFFFFFF

    def test_generates_unique(self):
        isns = {TCPSeqGenerator.generate_isn() for _ in range(1000)}
        assert len(isns) > 900

class TestPacketEngine:
    engine: PacketEngine

    def setup_method(self):
        self.engine = PacketEngine()

    def test_syn_ttl(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        assert pkt[IP].ttl == WIN10_BUILD_19045_TTL

    def test_syn_window(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        assert pkt[TCP].window == WIN10_BUILD_19045_WINDOW

    def test_syn_flags(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        assert pkt[TCP].flags == "S"

    def test_syn_df_flag(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        assert pkt[IP].flags == "DF"

    def test_syn_tcp_options(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        opts = pkt[TCP].options
        opt_names = [o[0] for o in opts]
        assert "MSS" in opt_names
        assert "WScale" in opt_names
        assert "SAckOK" in opt_names

    def test_syn_mss_value(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        for name, val in pkt[TCP].options:
            if name == "MSS":
                assert 1200 <= val <= 1460
                break

    def test_syn_wscale_value(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80)
        for name, val in pkt[TCP].options:
            if name == "WScale":
                assert val == WIN10_BUILD_19045_WSCALE
                break

    def test_syn_incremental_ip_id(self):
        pkt1 = self.engine.craft_syn("127.0.0.1", 80)
        pkt2 = self.engine.craft_syn("127.0.0.1", 81)
        assert pkt2[IP].id > pkt1[IP].id or pkt2[IP].id < 10

    def test_syn_custom_src_port(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80, src_port=443)
        assert pkt[TCP].sport == 443

    def test_syn_custom_src_ip(self):
        pkt = self.engine.craft_syn("127.0.0.1", 80, src_ip="10.0.0.1")
        assert pkt[IP].src == "10.0.0.1"

    def test_rst_flags(self):
        pkt = self.engine.craft_rst("127.0.0.1", 80, 12345, 1000)
        assert pkt[TCP].flags == "R"
        assert pkt[TCP].window == 0

    def test_fin_flags(self):
        pkt = self.engine.craft_fin("127.0.0.1", 80, 12345, 1000, 2000)
        assert "F" in str(pkt[TCP].flags)
        assert "A" in str(pkt[TCP].flags)

    def test_xmas_flags(self):
        pkt = self.engine.craft_xmas("127.0.0.1", 80)
        flags = str(pkt[TCP].flags)
        assert "F" in flags
        assert "P" in flags
        assert "U" in flags

    def test_null_flags(self):
        pkt = self.engine.craft_null("127.0.0.1", 80)
        assert int(pkt[TCP].flags) == 0

    def test_ack_flags(self):
        pkt = self.engine.craft_ack("127.0.0.1", 80)
        assert pkt[TCP].flags == "A"

    def test_packet_count(self):
        engine = PacketEngine()
        assert engine.packets_crafted == 0
        engine.craft_syn("127.0.0.1", 80)
        assert engine.packets_crafted == 1
        engine.craft_rst("127.0.0.1", 80, 12345, 1000)
        assert engine.packets_crafted == 2

    def test_fingerprint_summary(self):
        summary = self.engine.get_fingerprint_summary()
        assert summary["os_mimic"] == "Windows 10 Pro Build 19045 (Dynamic)"
        assert summary["ttl"] == WIN10_BUILD_19045_TTL
        assert summary["window_size"] == WIN10_BUILD_19045_WINDOW
        assert summary["mss"] == "Dynamic (1200-1460)"
        assert summary["wscale"] == WIN10_BUILD_19045_WSCALE
        assert summary["ip_id_strategy"] == "per_destination_incremental"

    def test_icmp_echo(self):
        pkt = self.engine.craft_icmp_echo("127.0.0.1")
        assert pkt[IP].ttl == WIN10_BUILD_19045_TTL
        assert pkt[IP].dst == "127.0.0.1"

    def test_rst_blocker_context_manager(self):
        from ops.rst_blocker import RSTBlocker
        blocker = RSTBlocker("192.168.1.100")
        assert blocker.target_ip == "192.168.1.100"
        with blocker as b:
            pass
        assert blocker.active is False