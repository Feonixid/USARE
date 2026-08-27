"""
USARE Temporal ML Timing Engine

Monitors target traffic volume and response patterns to find
peak-noise windows where scanning activity is best hidden.

Key capabilities:
1. Traffic Volume Profiling — passive observation of response patterns
   to build a statistical model of target busyness
2. Peak-Noise Detection — identify high-load periods where an IDS
   has degraded performance and extra traffic blends in
3. Dormant-Until-Peak — hold all probes until detected peak, then burst
4. Circadian Pattern Learning — build day/hour heatmap of target activity
5. Adaptive Jitter Injection — add timing noise proportional to target load
"""

import time
import math
import random
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime

logger = logging.getLogger("usare.temporal_timing")


@dataclass
class TrafficSample:
    """A single traffic measurement."""
    timestamp: float
    latency_ms: float       # Round-trip latency
    response_size: int      # Response bytes
    got_response: bool
    hour_of_day: int        # 0-23
    day_of_week: int        # 0=Monday, 6=Sunday


@dataclass
class PeakWindow:
    """A detected high-traffic window."""
    start_time: float
    end_time: float
    avg_latency_ms: float       # Higher latency = busier target
    response_rate: float        # Lower response rate = more load
    noise_score: float          # 0.0-1.0, how much noise to hide in
    sample_count: int


@dataclass
class CircadianProfile:
    """Activity profile by hour and day of week."""
    # hourly_load[hour] = average normalized load (0.0-1.0)
    hourly_load: Dict[int, float] = field(default_factory=dict)
    # daily_load[day_of_week] = average normalized load
    daily_load: Dict[int, float] = field(default_factory=dict)
    # hour_day_matrix[hour][day] = load
    hour_day_matrix: Dict[int, Dict[int, float]] = field(default_factory=dict)
    total_samples: int = 0

    def best_scan_windows(self, count: int = 3) -> List[Tuple[int, int, float]]:
        """Return the (hour, day, noise_score) tuples with highest noise."""
        windows = []
        for hour, day_loads in self.hour_day_matrix.items():
            for day, load in day_loads.items():
                windows.append((hour, day, load))
        windows.sort(key=lambda x: -x[2])
        return windows[:count]

    def to_dict(self) -> Dict:
        best = self.best_scan_windows(3)
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        return {
            "hourly_load": {str(h): round(l, 3) for h, l in sorted(self.hourly_load.items())},
            "daily_load": {days[d]: round(l, 3) for d, l in sorted(self.daily_load.items())},
            "best_windows": [
                {"hour": h, "day": days[d], "noise_score": round(s, 3)}
                for h, d, s in best
            ],
            "total_samples": self.total_samples,
        }


class TemporalTimingEngine:
    """
    Monitors target response patterns to find optimal scan windows.
    """

    # Window sizes for analysis
    SHORT_WINDOW = 30       # seconds — detect immediate peaks
    MEDIUM_WINDOW = 300     # 5 minutes — trend detection
    LONG_WINDOW = 3600      # 1 hour — circadian modeling

    # Thresholds
    PEAK_LATENCY_FACTOR = 1.5  # Latency > 1.5x baseline = peak
    PEAK_MIN_SAMPLES = 5
    DORMANT_TIMEOUT = 300      # Max seconds to wait for peak

    def __init__(self):
        self._samples: deque = deque(maxlen=5000)
        self._baseline_latency: float = 0.0
        self._baseline_response_rate: float = 1.0
        self._circadian = CircadianProfile()
        self._lock = threading.Lock()
        self._peak_callbacks: List[Callable] = []
        self._in_peak = False
        self._dormant = False
        self._pending_probes: deque = deque()
        self._peak_windows: List[PeakWindow] = []

        # Circadian accumulators
        self._hourly_latencies: Dict[int, List[float]] = {h: [] for h in range(24)}
        self._daily_latencies: Dict[int, List[float]] = {d: [] for d in range(7)}
        self._hour_day_latencies: Dict[int, Dict[int, List[float]]] = {
            h: {d: [] for d in range(7)} for h in range(24)
        }

    def observe(self, latency_ms: float, response_size: int, got_response: bool):
        """Record a traffic observation."""
        now = time.time()
        dt = datetime.fromtimestamp(now)

        sample = TrafficSample(
            timestamp=now,
            latency_ms=latency_ms,
            response_size=response_size,
            got_response=got_response,
            hour_of_day=dt.hour,
            day_of_week=dt.weekday(),
        )

        with self._lock:
            self._samples.append(sample)
            self._update_baseline()
            self._update_circadian(sample)
            self._check_peak()

    def _update_baseline(self):
        """Update baseline latency using exponential moving average."""
        recent = [s for s in self._samples if s.got_response
                  and s.timestamp > time.time() - self.MEDIUM_WINDOW]
        if not recent:
            return

        latencies = [s.latency_ms for s in recent]
        current_mean = sum(latencies) / len(latencies)

        if self._baseline_latency == 0:
            self._baseline_latency = current_mean
        else:
            alpha = 0.1
            self._baseline_latency = (1 - alpha) * self._baseline_latency + alpha * current_mean

        responses = sum(1 for s in recent if s.got_response)
        self._baseline_response_rate = responses / max(len(recent), 1)

    def _update_circadian(self, sample: TrafficSample):
        """Update circadian activity profile."""
        if not sample.got_response:
            return

        h = sample.hour_of_day
        d = sample.day_of_week

        self._hourly_latencies[h].append(sample.latency_ms)
        self._daily_latencies[d].append(sample.latency_ms)
        self._hour_day_latencies[h][d].append(sample.latency_ms)
        self._circadian.total_samples += 1

        # Update normalized load profile (higher latency = higher load)
        if self._baseline_latency > 0:
            for hour in range(24):
                lats = self._hourly_latencies[hour]
                if lats:
                    avg = sum(lats[-50:]) / len(lats[-50:])
                    self._circadian.hourly_load[hour] = min(
                        avg / max(self._baseline_latency, 1), 2.0
                    )

            for day in range(7):
                lats = self._daily_latencies[day]
                if lats:
                    avg = sum(lats[-50:]) / len(lats[-50:])
                    self._circadian.daily_load[day] = min(
                        avg / max(self._baseline_latency, 1), 2.0
                    )

            for hour in range(24):
                if hour not in self._circadian.hour_day_matrix:
                    self._circadian.hour_day_matrix[hour] = {}
                for day in range(7):
                    lats = self._hour_day_latencies[hour][day]
                    if lats:
                        avg = sum(lats[-20:]) / len(lats[-20:])
                        self._circadian.hour_day_matrix[hour][day] = min(
                            avg / max(self._baseline_latency, 1), 2.0
                        )

    def _check_peak(self):
        """Check if we're in a high-traffic peak."""
        now = time.time()
        recent = [s for s in self._samples
                  if s.timestamp > now - self.SHORT_WINDOW]

        if len(recent) < self.PEAK_MIN_SAMPLES:
            return

        avg_latency = sum(s.latency_ms for s in recent if s.got_response) / max(
            sum(1 for s in recent if s.got_response), 1
        )
        resp_rate = sum(1 for s in recent if s.got_response) / len(recent)

        is_peak = (
            avg_latency > self._baseline_latency * self.PEAK_LATENCY_FACTOR
            or resp_rate < self._baseline_response_rate * 0.7
        )

        if is_peak and not self._in_peak:
            self._in_peak = True
            noise_score = min(avg_latency / max(self._baseline_latency, 1) / 3.0, 1.0)

            window = PeakWindow(
                start_time=now,
                end_time=0,
                avg_latency_ms=avg_latency,
                response_rate=resp_rate,
                noise_score=noise_score,
                sample_count=len(recent),
            )
            self._peak_windows.append(window)

            logger.info(
                f"[Temporal] Peak detected: latency {avg_latency:.0f}ms "
                f"(baseline {self._baseline_latency:.0f}ms), "
                f"noise_score={noise_score:.2f}"
            )

            # Fire callbacks
            for callback in self._peak_callbacks:
                try:
                    callback(window)
                except Exception:
                    pass

        elif not is_peak and self._in_peak:
            self._in_peak = False
            if self._peak_windows:
                self._peak_windows[-1].end_time = now

    def is_peak_now(self) -> bool:
        """Check if target is currently in a high-traffic peak."""
        with self._lock:
            return self._in_peak

    def get_noise_score(self) -> float:
        """
        Get current noise score (0.0 = quiet, 1.0 = very noisy).
        Higher noise = better time to scan.
        """
        with self._lock:
            if not self._samples:
                return 0.5

            now = time.time()
            recent = [s for s in self._samples
                      if s.timestamp > now - self.SHORT_WINDOW and s.got_response]

            if not recent or self._baseline_latency == 0:
                return 0.5

            avg_lat = sum(s.latency_ms for s in recent) / len(recent)
            ratio = avg_lat / max(self._baseline_latency, 1)

            return min(ratio / 3.0, 1.0)

    def get_adaptive_delay(self, base_delay: float) -> float:
        """
        Adjust probe delay based on target noise level.

        During peaks: reduce delay (more noise to hide in)
        During quiet: increase delay (need more stealth)
        """
        noise = self.get_noise_score()

        if noise > 0.7:
            # Peak traffic — can be more aggressive
            factor = 0.3 + (1.0 - noise) * 0.7
        elif noise > 0.4:
            # Normal traffic
            factor = 1.0
        else:
            # Quiet — be very stealthy
            factor = 1.5 + (0.4 - noise) * 2.5

        # Add Gaussian jitter
        jitter = random.gauss(0, base_delay * 0.15)
        return max(base_delay * factor + jitter, 0.1)

    def on_peak(self, callback: Callable):
        """Register a callback for peak detection events."""
        self._peak_callbacks.append(callback)

    def wait_for_peak(self, timeout: Optional[float] = None) -> bool:
        """
        Block until a traffic peak is detected.
        Returns True if peak was found, False on timeout.

        This enables the dormant-until-peak-traffic behavior.
        """
        timeout = timeout or self.DORMANT_TIMEOUT
        start = time.time()

        while time.time() - start < timeout:
            if self.is_peak_now():
                return True
            time.sleep(0.5)

        return False

    def get_circadian_profile(self) -> CircadianProfile:
        """Get the built circadian activity profile."""
        with self._lock:
            return self._circadian

    def get_summary(self) -> Dict[str, Any]:
        """Get engine summary."""
        with self._lock:
            return {
                "total_samples": len(self._samples),
                "baseline_latency_ms": round(self._baseline_latency, 1),
                "baseline_response_rate": round(self._baseline_response_rate, 3),
                "current_noise_score": round(self.get_noise_score(), 3),
                "in_peak": self._in_peak,
                "peaks_detected": len(self._peak_windows),
                "circadian_profile": self._circadian.to_dict()
                    if self._circadian.total_samples > 10 else None,
            }
