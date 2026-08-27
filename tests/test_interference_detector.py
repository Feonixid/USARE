import pytest
from recon.interference_detector import (
    InterferenceDetector,
    ProbeObservation,
    InterferenceType,
    InterferenceEvent,
)


def test_interference_detector_empty():
    detector = InterferenceDetector()
    events = detector.analyze()
    assert events == []
    assert detector.is_being_interfered() is False
    assert detector.get_recommended_profile() is None


def test_interference_detector_rst_injection():
    detector = InterferenceDetector()
    # Feed 15 observations with very fast RSTs (< 2ms)
    for port in range(1, 16):
        obs = ProbeObservation(
            port=port,
            response_type="rst",
            latency_ms=0.5,
        )
        detector.record_observation(obs)

    events = detector.analyze()
    types = [e.interference_type for e in events]
    assert InterferenceType.RST_INJECTION in types
    assert detector.is_being_interfered() is True
    assert detector.get_recommended_profile() == "shadow"


def test_interference_detector_rate_limit():
    detector = InterferenceDetector()
    # Establish baseline with 10 normal observations (10ms)
    for port in range(1, 11):
        detector.record_observation(
            ProbeObservation(port=port, response_type="synack", latency_ms=10.0)
        )

    # Add high-latency observations (> 3x baseline)
    for port in range(11, 25):
        detector.record_observation(
            ProbeObservation(port=port, response_type="synack", latency_ms=60.0)
        )

    events = detector.analyze()
    types = [e.interference_type for e in events]
    assert InterferenceType.RATE_LIMITED in types or InterferenceType.LATENCY_SPIKE in types


def test_interference_detector_summary():
    detector = InterferenceDetector()
    for port in range(1, 15):
        detector.record_observation(
            ProbeObservation(port=port, response_type="rst", latency_ms=0.3)
        )
    detector.analyze()
    summary_dict = detector.summary()
    assert summary_dict["being_interfered"] is True
    assert len(summary_dict["active_events"]) > 0
    assert summary_dict["recommended_profile"] == "shadow"
