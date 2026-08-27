import pytest
from unittest.mock import patch
from recon.contextual_probe import (
    ContextualProber,
    NetworkOS,
    ContextualProbeResult,
    contextual_probe,
)


def test_network_os_enum():
    assert NetworkOS("windows") == NetworkOS.WINDOWS
    assert NetworkOS("apple") == NetworkOS.APPLE
    assert NetworkOS("linux") == NetworkOS.LINUX
    assert NetworkOS("iot") == NetworkOS.IOT
    assert NetworkOS("enterprise") == NetworkOS.ENTERPRISE


def test_contextual_prober_initialization():
    prober = ContextualProber(timeout=2.0)
    assert prober.timeout == 2.0
    assert prober.discovery_cache == {}


def test_contextual_prober_os_caching():
    prober = ContextualProber()
    prober.discovery_cache["192.168.1.50"] = NetworkOS.WINDOWS
    detected = prober.detect_os_family("192.168.1.50")
    assert detected == NetworkOS.WINDOWS


@patch.object(ContextualProber, "_send_syn_probe", return_value=(True, 15.0))
@patch.object(ContextualProber, "_send_llmnr_query", return_value="HOSTNAME")
def test_windows_contextual_probe(mock_llmnr, mock_syn):
    prober = ContextualProber()
    # Mock sleep to avoid real test delay
    with patch("time.sleep", return_value=None):
        res = prober.windows_contextual_probe("192.168.1.100", 445)
    assert res.target_ip == "192.168.1.100"
    assert res.target_port == 445
    assert res.os_family == NetworkOS.WINDOWS
    assert res.probe_success is True
    assert res.stealth_score >= 0.80


@patch.object(ContextualProber, "_send_syn_probe", return_value=(False, 0.0))
def test_contextual_probe_fallback_unknown(mock_syn):
    prober = ContextualProber()
    res = prober.contextual_probe("192.168.1.200", 80, NetworkOS.UNKNOWN)
    assert res.target_ip == "192.168.1.200"
    assert res.target_port == 80
    assert res.os_family == NetworkOS.UNKNOWN
    assert res.probe_success is False
