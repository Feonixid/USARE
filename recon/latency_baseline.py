"""
USARE Response Timeline & Latency Baseline Analyzer

Statistical analysis of network probe response times to establish
empirical baselines, identify artificial delays (rate limiting / throttling),
and detect synthetic or cached responses from intermediate network devices.
"""

import math
import statistics
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("usare.latency_baseline")


@dataclass
class LatencyProfile:
    """Statistical summary of observed response latencies."""
    sample_count: int
    mean_ms: float
    variance_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float
    median_ms: float


class ResponseTimelineAnalyzer:
    """
    Maintains a sliding window of response latencies to model normal network
    jitter and flag statistical anomalies.
    """

    def __init__(self, window_size: int = 50, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self._latencies: List[float] = []
        self._probe_history: List[Dict[str, Any]] = []

    def record_response(self, port: int, latency_ms: float, response_type: str = "synack") -> Dict[str, Any]:
        """
        Record a probe response latency and evaluate against the current baseline.
        """
        is_anomaly = False
        z_score = 0.0

        if len(self._latencies) >= 5:
            mean = statistics.mean(self._latencies)
            stdev = statistics.stdev(self._latencies) if len(self._latencies) > 1 else 0.0
            if stdev > 0.001:
                z_score = (latency_ms - mean) / stdev
                if abs(z_score) >= self.z_threshold:
                    is_anomaly = True

        self._latencies.append(latency_ms)
        if len(self._latencies) > self.window_size:
            self._latencies.pop(0)

        entry = {
            "port": port,
            "latency_ms": latency_ms,
            "response_type": response_type,
            "z_score": round(z_score, 2),
            "is_anomaly": is_anomaly,
        }
        self._probe_history.append(entry)
        return entry

    def get_profile(self) -> Optional[LatencyProfile]:
        """Generate statistical latency profile from the active window."""
        if not self._latencies:
            return None

        count = len(self._latencies)
        mean_val = statistics.mean(self._latencies)
        var_val = statistics.variance(self._latencies) if count > 1 else 0.0
        stdev_val = statistics.stdev(self._latencies) if count > 1 else 0.0

        return LatencyProfile(
            sample_count=count,
            mean_ms=round(mean_val, 2),
            variance_ms=round(var_val, 2),
            stdev_ms=round(stdev_val, 2),
            min_ms=round(min(self._latencies), 2),
            max_ms=round(max(self._latencies), 2),
            median_ms=round(statistics.median(self._latencies), 2),
        )

    def detect_artificial_delay(self, latency_ms: float) -> bool:
        """
        Check if a given latency exhibits a statistically significant delay (z-score >= threshold).
        """
        if len(self._latencies) < 5:
            return False

        mean = statistics.mean(self._latencies)
        stdev = statistics.stdev(self._latencies) if len(self._latencies) > 1 else 0.0
        if stdev <= 0.001:
            return False

        z = (latency_ms - mean) / stdev
        return z >= self.z_threshold

    def detect_synthetic_clustering(self, recent_count: int = 10) -> bool:
        """
        Check if recent responses have zero or near-zero variance (indicating
        templated, synthetic responses from an intermediate proxy rather than a real host stack).
        """
        if len(self._latencies) < recent_count:
            return False

        subset = self._latencies[-recent_count:]
        unique_rounded = {round(x, 1) for x in subset}
        # If 10 responses have <= 2 unique latency values, it's artificially constant
        return len(unique_rounded) <= 2
