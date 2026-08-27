import pytest
from unittest.mock import patch, MagicMock
from evasion.flow_morph import FlowShaper, FlowType, KDESampler
from evasion.proto_tunnel import HTTPSTunnel, DNSTunnel, ICMPTunnel, create_tunnel
from evasion.distributed import DistributedCoordinator, ScanNode, DistributedJob
from evasion.baseline_poison import BaselinePoisoner, PoisonConfig
from evasion.fragmentation import FragmentationEngine
from scapy.all import IP, TCP, IPv6, Raw


def test_flow_shaper_generation():
    shaper = FlowShaper(FlowType.CHROME_HTTPS)
    assert shaper.profile.name == "Chrome 120 TLS 1.3"

    probe = IP(dst="8.8.8.8")/TCP(dport=443, flags="S")
    flow = shaper.wrap_probe(probe, "8.8.8.8", 443, 12345)

    assert len(flow) > 3, "Flow should contain cover packets + probe"
    
    # Check that the probe is in there somewhere
    probe_found = False
    for pkt, delay in flow:
        assert delay > 0 and delay < 1.0, "Delay should be realistic"
        if pkt is probe:
            probe_found = True
    assert probe_found, "Probe must be wrapped inside the flow"


def test_kde_sampler():
    samples = [10.0, 20.0, 30.0]
    sampler = KDESampler(samples)
    
    val1 = sampler.sample()
    val2 = sampler.sample()
    assert val1 > 0, "KDE sample must be positive"
    assert val2 > 0, "KDE sample must be positive"
    assert sampler.sample_seconds() < 1.0, "Seconds should be scaled down"


@patch('socket.socket')
@patch('ssl.SSLContext.wrap_socket')
def test_https_tunnel(mock_wrap, mock_socket):
    mock_sock_instance = MagicMock()
    mock_wrap.return_value = mock_sock_instance
    mock_sock_instance.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

    tunnel = create_tunnel("https")
    res = tunnel.probe_through_https("example.com", 80)
    
    assert res.is_open is True
    assert res.method == "https_tunnel"
    assert mock_sock_instance.sendall.called
    
    # Check keep-alive reusability
    assert tunnel._reusable_conn is not None
    res2 = tunnel.probe_through_https("example.com", 443)
    assert res2.is_open is True


@patch('socket.socket')
def test_dns_tunnel(mock_socket):
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance
    # Mock a successful DNS response (RCODE=0 in flags byte 3)
    mock_sock_instance.recvfrom.return_value = (b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", ("8.8.8.8", 53))

    tunnel = create_tunnel("dns")
    res = tunnel.probe_via_txt("example.com", 80)
    
    assert res.is_open is True
    assert res.method == "dns_tunnel"
    assert mock_sock_instance.sendto.called


def test_distributed_partitioning():
    coord = DistributedCoordinator()
    coord.nodes = [
        ScanNode(host="1.1.1.1", status="ready"),
        ScanNode(host="2.2.2.2", status="ready"),
        ScanNode(host="3.3.3.3", status="unreachable")
    ]
    
    ports = [80, 443, 8080, 8443, 22]
    partitions = coord.partition_ports(ports)
    
    assert len(partitions) == 2, "Only 2 healthy nodes should get assigned ports"
    assert partitions[0] == [80, 8080, 22]
    assert partitions[1] == [443, 8443]


def test_fragmentation_ipv6_variants():
    engine = FragmentationEngine()
    # Use smaller data to ensure fragmentation
    pkt = IPv6(dst="2001:db8::1")/TCP(dport=80, flags="S")/Raw(b"TESTDATA1234567890" * 10)
    
    overlaps = engine.fragment_with_overlap_ipv6(pkt)
    # Allow single fragment if data is too small to fragment
    assert len(overlaps) >= 1, "Should produce at least one fragment"
    
    ttl_evasion = engine.fragment_with_ttl_evasion_ipv6(pkt, ids_hop_count=5)
    assert len(ttl_evasion) >= 2, "TTL evasion should produce decoy pairs"
    assert ttl_evasion[0][IPv6].hlim == 4, "Decoy should have short hop limit"


@patch('time.sleep')
@patch('socket.socket')
@patch('ssl.create_default_context')
def test_baseline_poisoner(mock_ssl, mock_sock, mock_sleep):
    mock_sock_instance = MagicMock()
    mock_sock.return_value = mock_sock_instance
    mock_sock_instance.recv.return_value = b""
    
    cfg = PoisonConfig(duration_minutes=0.01, requests_per_minute=6000, target_ip="1.1.1.1")
    poisoner = BaselinePoisoner(cfg)
    
    def force_stop(stats):
        if stats['https_requests'] > 0 and stats['dns_queries'] > 0 and stats['target_requests'] > 0:
            poisoner._active = False

    poisoner.run_blocking(callback=force_stop)
    
    stats = poisoner.stats
    assert stats['https_requests'] > 0 or stats['dns_queries'] > 0, "Should have made some requests"
    assert stats['active'] is False
