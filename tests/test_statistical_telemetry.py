import pytest
from recon.latency_baseline import ResponseTimelineAnalyzer, LatencyProfile
from recon.os_fingerprint import OSFingerprintEngine
from recon.packet_loss_analyzer import PacketLossAnalyzer, LossAnalysisResult
from recon.interference_detector import InterferenceDetector, ProbeObservation


class TestResponseTimelineAnalyzer:
    def test_latency_baseline_profile(self):
        analyzer = ResponseTimelineAnalyzer(window_size=20)
        # Record 10 baseline samples around 20ms
        for i in range(10):
            analyzer.record_response(port=80, latency_ms=20.0 + (i % 3))

        profile = analyzer.get_profile()
        assert profile is not None
        assert profile.sample_count == 10
        assert 19.0 <= profile.mean_ms <= 22.0
        assert profile.min_ms >= 19.0
        assert profile.max_ms <= 23.0

    def test_detect_artificial_delay_z_score(self):
        analyzer = ResponseTimelineAnalyzer(window_size=20, z_threshold=3.0)
        # Stable baseline: 20ms with low variance
        for _ in range(15):
            analyzer.record_response(port=80, latency_ms=20.0)
            analyzer.record_response(port=80, latency_ms=21.0)

        # 100ms should trigger outlier z-score
        assert analyzer.detect_artificial_delay(100.0) is True
        assert analyzer.detect_artificial_delay(22.0) is False

    def test_detect_synthetic_clustering(self):
        analyzer = ResponseTimelineAnalyzer(window_size=20)
        # 10 exactly identical responses
        for _ in range(10):
            analyzer.record_response(port=80, latency_ms=5.0)

        assert analyzer.detect_synthetic_clustering(recent_count=10) is True


class TestTCPOptionsFingerprint:
    def test_windows_tcp_options(self):
        engine = OSFingerprintEngine()
        options = [
            ("MSS", 1460),
            ("NOP", None),
            ("WScale", 8),
            ("NOP", None),
            ("NOP", None),
            ("SAckOK", ""),
        ]
        res = engine.fingerprint_from_tcp_options(options, observed_ttl=128, observed_window=64240)
        assert "Windows" in res["best_match"]
        assert res["wscale"] == 8
        assert res["mss"] == 1460
        assert res["confidence"] >= 0.80

    def test_linux_tcp_options(self):
        engine = OSFingerprintEngine()
        options = [
            ("MSS", 1460),
            ("SAckOK", ""),
            ("Timestamp", (123456, 0)),
            ("NOP", None),
            ("WScale", 7),
        ]
        res = engine.fingerprint_from_tcp_options(options, observed_ttl=64, observed_window=64240)
        assert "Linux" in res["best_match"]
        assert res["has_timestamps"] is True
        assert res["confidence"] >= 0.80


class TestPacketLossAnalyzer:
    def test_no_loss(self):
        analyzer = PacketLossAnalyzer()
        res = analyzer.analyze_loss_pattern(total_probes=20, received_indices=list(range(20)))
        assert res.classification == "NO_LOSS"
        assert res.dropped_probes == 0
        assert res.loss_rate == 0.0

    def test_systematic_filtering_periodic(self):
        analyzer = PacketLossAnalyzer()
        # Drop every 5th probe (indices: 0, 5, 10, 15, 20)
        all_probes = 25
        dropped = [0, 5, 10, 15, 20]
        received = [i for i in range(all_probes) if i not in dropped]

        res = analyzer.analyze_loss_pattern(total_probes=all_probes, received_indices=received)
        assert res.classification == "SYSTEMATIC_FILTERING"
        assert res.gap_variance == 0.0
        assert res.dropped_probes == 5

    def test_random_network_loss(self):
        analyzer = PacketLossAnalyzer(high_loss_threshold=0.50)
        # Gaps: [1, 20, 2] -> high variance
        all_probes = 50
        dropped = [5, 6, 26, 28]
        received = [i for i in range(all_probes) if i not in dropped]

        res = analyzer.analyze_loss_pattern(total_probes=all_probes, received_indices=received)
        assert res.classification == "RANDOM_NETWORK_LOSS"
        assert res.gap_variance > 50.0


class TestInterferenceApplianceClassification:
    def test_classify_snort_fast_rst(self):
        detector = InterferenceDetector()
        obs = [
            ProbeObservation(port=22, response_type="rst", latency_ms=0.5),
            ProbeObservation(port=80, response_type="rst", latency_ms=0.4),
            ProbeObservation(port=443, response_type="rst", latency_ms=0.6),
        ]
        appliance = detector.classify_inline_appliance(obs)
        assert appliance is not None
        assert "Snort" in appliance["appliance"]
        assert appliance["confidence"] >= 0.80

    def test_classify_waf_http_block(self):
        detector = InterferenceDetector()
        obs = [
            ProbeObservation(port=80, response_type="http_403", latency_ms=25.0),
            ProbeObservation(port=8080, response_type="http_403", latency_ms=30.0),
        ]
        appliance = detector.classify_inline_appliance(obs)
        assert appliance is not None
        assert "WAF" in appliance["appliance"] or "FortiGate" in appliance["appliance"]
