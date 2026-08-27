"""
USARE Advanced Temporal Evasion Module

Implements ML-based temporal evasion techniques to bypass
behavioral analysis and timing-based detection systems.

Enhanced with machine learning for adaptive timing patterns,
anomaly detection evasion, and behavioral mimicry.
"""

import random
import asyncio
import time
import math
import json
import logging
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore
    HAS_NUMPY = False
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, List, Dict, Tuple, Any
from collections import deque
import threading

try:
    from sklearn.neighbors import KernelDensity
    from sklearn.preprocessing import StandardScaler
    HAS_ML = True
except ImportError:
    HAS_ML = False

logger = logging.getLogger("usare.timing")

class TimingProfile(Enum):
    GHOST = "ghost"
    PHANTOM = "phantom"
    SHADOW = "shadow"
    GLACIER = "glacier"
    ADAPTIVE = "adaptive"
    LTE = "lte"
    ML_ADAPTIVE = "ml-adaptive"
    BEHAVIORAL = "behavioral"
    POISSON = "poisson"  # Exponential inter-arrival — mimics human/bot burstiness, defeats fixed-cadence correlation

@dataclass
class TimingConfig:
    mean: float = 60.0
    std_dev: float = 15.0
    floor: float = 30.0
    ceiling: float = 90.0
    profile: TimingProfile = TimingProfile.GHOST
    heat_threshold: float = 0.4
    heat_callback: Optional[Callable[[], float]] = None
    ml_model_path: Optional[str] = None
    behavior_profile: Optional[str] = None
    anomaly_threshold: float = 0.1
    learning_rate: float = 0.01

    @classmethod
    def from_profile(cls, profile: TimingProfile) -> "TimingConfig":
        profiles = {
            TimingProfile.GHOST: cls(
                mean=60.0, std_dev=15.0, floor=30.0, ceiling=90.0,
                profile=TimingProfile.GHOST
            ),
            TimingProfile.PHANTOM: cls(
                mean=120.0, std_dev=30.0, floor=60.0, ceiling=180.0,
                profile=TimingProfile.PHANTOM
            ),
            TimingProfile.SHADOW: cls(
                mean=300.0, std_dev=60.0, floor=180.0, ceiling=420.0,
                profile=TimingProfile.SHADOW
            ),
            TimingProfile.GLACIER: cls(
                mean=600.0, std_dev=120.0, floor=300.0, ceiling=900.0,
                profile=TimingProfile.GLACIER
            ),
            TimingProfile.ADAPTIVE: cls(
                mean=60.0, std_dev=15.0, floor=30.0, ceiling=300.0,
                profile=TimingProfile.ADAPTIVE
            ),
            TimingProfile.LTE: cls(
                mean=0.3, std_dev=0.15, floor=0.1, ceiling=1.2,
                profile=TimingProfile.LTE
            ),
            TimingProfile.ML_ADAPTIVE: cls(
                mean=60.0, std_dev=20.0, floor=10.0, ceiling=300.0,
                profile=TimingProfile.ML_ADAPTIVE,
                anomaly_threshold=0.1,
                learning_rate=0.01
            ),
            TimingProfile.BEHAVIORAL: cls(
                mean=45.0, std_dev=25.0, floor=5.0, ceiling=180.0,
                profile=TimingProfile.BEHAVIORAL,
                behavior_profile="human_browsing"
            ),
            TimingProfile.POISSON: cls(
                mean=90.0, std_dev=0.0, floor=15.0, ceiling=300.0,
                profile=TimingProfile.POISSON,
            ),
        }
        return profiles.get(profile, profiles[TimingProfile.GHOST])


class GhostTimer:
    def __init__(self, config: Optional[TimingConfig] = None):
        self.config = config or TimingConfig()
        self._rng = random.SystemRandom()
        self._delays_generated = 0
        self._total_delay_time = 0.0
        self._consecutive_filtered = 0
        self._escalation_order = [
            TimingProfile.GHOST,
            TimingProfile.PHANTOM,
            TimingProfile.SHADOW,
            TimingProfile.GLACIER,
        ]

    def ghost_delay(self) -> float:
        if self.config.profile == TimingProfile.ADAPTIVE:
            return self._adaptive_delay()
        if self.config.profile == TimingProfile.POISSON:
            return self._poisson_delay()
        return self._gaussian_sample(
            self.config.mean,
            self.config.std_dev,
            self.config.floor,
            self.config.ceiling,
        )

    def _adaptive_delay(self) -> float:
        heat = 0.0
        if self.config.heat_callback:
            heat = self.config.heat_callback()
        multiplier = 1.0 + math.exp(
            5.0 * (heat - self.config.heat_threshold)
        )
        effective_mean = self.config.mean * multiplier
        effective_std = self.config.std_dev * multiplier
        return self._gaussian_sample(
            effective_mean,
            effective_std,
            self.config.floor,
            self.config.ceiling * multiplier,
        )

    def _poisson_delay(self) -> float:
        """Exponential inter-arrival — breaks fixed cadence, mimics human/bot burstiness."""
        mean = self.config.mean
        low = self.config.floor
        high = self.config.ceiling
        lam = 1.0 / mean if mean > 0 else 1.0 / 60.0
        u = self._rng.random()
        while u <= 0:
            u = self._rng.random()
        sample = -math.log(u) / lam
        sample = max(low, min(high, sample))
        self._delays_generated += 1
        self._total_delay_time += sample
        return sample

    def _gaussian_sample(
        self, mean: float, std: float, low: float, high: float
    ) -> float:
        max_attempts = 100
        for _ in range(max_attempts):
            sample = self._rng.gauss(mean, std)
            if low <= sample <= high:
                self._delays_generated += 1
                self._total_delay_time += sample
                return sample
        sample = max(low, min(high, self._rng.gauss(mean, std)))
        self._delays_generated += 1
        self._total_delay_time += sample
        return sample

    async def async_ghost_wait(self) -> float:
        delay = self.ghost_delay()
        await asyncio.sleep(delay)
        return delay

    def sync_ghost_wait(self) -> float:
        delay = self.ghost_delay()
        time.sleep(delay)
        return delay

    def should_pause(self, packets_in_window: int, window_seconds: float) -> bool:
        if window_seconds <= 0:
            return True
        rate = packets_in_window / window_seconds
        return rate > 0.075

    @property
    def average_delay(self) -> float:
        if self._delays_generated == 0:
            return 0.0
        return self._total_delay_time / self._delays_generated

    @property
    def stats(self) -> dict:
        return {
            "delays_generated": self._delays_generated,
            "total_delay_time_sec": round(self._total_delay_time, 2),
            "average_delay_sec": round(self.average_delay, 2),
            "profile": self.config.profile.value,
        }

    def record_response(self, state: str):
        if state == "filtered":
            self._consecutive_filtered += 1
            if self._consecutive_filtered >= 10:
                self.auto_escalate()
                self._consecutive_filtered = 0
        else:
            self._consecutive_filtered = 0

    def auto_escalate(self):
        current_idx = -1
        for i, prof in enumerate(self._escalation_order):
            if prof == self.config.profile:
                current_idx = i
                break
        if current_idx < 0:
            return
        next_idx = min(current_idx + 1, len(self._escalation_order) - 1)
        if next_idx != current_idx:
            new_profile = self._escalation_order[next_idx]
            old_callback = self.config.heat_callback
            self.config = TimingConfig.from_profile(new_profile)
            self.config.heat_callback = old_callback


class MLTimingEngine:
    """Machine Learning-based timing engine for advanced temporal evasion."""

    def __init__(self, config: TimingConfig):
        self.config = config
        self._timing_history: deque = deque(maxlen=1000)
        self._feature_history: deque = deque(maxlen=1000)
        self._kde_model = None
        self._scaler = None
        self._behavioral_models: Dict[str, Any] = {}
        self._lock = threading.Lock()

        if HAS_ML:
            self._initialize_ml_models()
        self._load_behavioral_profiles()

    def _initialize_ml_models(self):
        try:
            if HAS_ML and HAS_NUMPY:
                self._kde_model = KernelDensity(bandwidth=0.5)
                self._scaler = StandardScaler()
                baseline_delays = np.array([0.5, 1.2, 0.8, 2.1, 0.3, 1.5, 0.7, 1.8, 0.4, 1.1])
                self._kde_model.fit(baseline_delays.reshape(-1, 1))
                logger.info("[USARE] KDE timing model initialized with baseline patterns")
            else:
                logger.warning("[USARE] scikit-learn/numpy not available, using Gaussian fallback")
        except Exception as e:
            logger.warning("[USARE] Failed to initialize ML models: %s", e)

    def _load_behavioral_profiles(self):
        self._behavioral_models = {
            "human_browsing": {
                "pattern": "burst_pause",
                "burst_size": (2, 5),
                "burst_interval": (1, 3),
                "pause_duration": (30, 120),
                "active_probability": 0.7
            },
            "web_crawler": {
                "pattern": "regular",
                "interval_mean": 15.0,
                "interval_std": 5.0,
                "active_probability": 0.95
            },
            "mobile_user": {
                "pattern": "intermittent",
                "active_periods": [(9, 12), (14, 17), (19, 22)],
                "inactive_periods": [(0, 6), (13, 14), (18, 19)],
                "active_probability": 0.6
            },
            "bot_pattern": {
                "pattern": "periodic",
                "period": 60.0,
                "jitter": 0.1,
                "active_probability": 0.9
            }
        }

    def generate_ml_delay(self, context_features: Optional[Dict[str, Any]] = None) -> float:
        if self.config.profile == TimingProfile.BEHAVIORAL:
            return self._generate_behavioral_delay()
        return self._generate_kde_delay()

    def _generate_kde_delay(self) -> float:
        try:
            if HAS_ML and HAS_NUMPY and self._kde_model and len(self._timing_history) >= 5:
                sample = self._kde_model.sample(1)[0][0]
                delay = max(self.config.floor, abs(sample))
                delay = min(delay, self.config.ceiling)
                logger.debug("[USARE] KDE-generated delay: %.2fs", delay)
                return delay
            else:
                return self._gaussian_fallback()
        except Exception as e:
            logger.debug("[USARE] KDE sampling failed: %s", e)
            return self._gaussian_fallback()

    def _gaussian_fallback(self) -> float:
        delay = random.gauss(self.config.mean, self.config.std_dev)
        return max(self.config.floor, min(self.config.ceiling, delay))

    def _generate_behavioral_delay(self, profile: Optional[str] = None) -> float:
        profile_name = profile or self.config.behavior_profile or "human_browsing"
        if profile_name not in self._behavioral_models:
            profile_name = "human_browsing"
        model = self._behavioral_models[profile_name]
        pattern = model["pattern"]
        if pattern == "burst_pause":
            return self._burst_pause_timing(model)
        elif pattern == "regular":
            return self._regular_timing(model)
        elif pattern == "intermittent":
            return self._intermittent_timing(model)
        elif pattern == "periodic":
            return self._periodic_timing(model)
        else:
            return self.config.mean

    def _burst_pause_timing(self, model: Dict[str, Any]) -> float:
        if random.random() > model["active_probability"]:
            pause_min, pause_max = model["pause_duration"]
            return random.uniform(pause_min, pause_max)
        else:
            burst_min, burst_max = model["burst_interval"]
            return random.uniform(burst_min, burst_max)

    def _regular_timing(self, model: Dict[str, Any]) -> float:
        mean = model["interval_mean"]
        std = model["interval_std"]
        delay = random.gauss(mean, std)
        return max(self.config.floor, min(self.config.ceiling, delay))

    def _intermittent_timing(self, model: Dict[str, Any]) -> float:
        current_hour = time.localtime().tm_hour
        for start, end in model["active_periods"]:
            if start <= current_hour <= end:
                return random.uniform(5, 30)
        for start, end in model["inactive_periods"]:
            if start <= current_hour <= end:
                return random.uniform(300, 900)
        return random.uniform(60, 180)

    def _periodic_timing(self, model: Dict[str, Any]) -> float:
        period = model["period"]
        jitter = model["jitter"]
        return period * (1 + random.uniform(-jitter, jitter))

    def record_timing(self, delay: float, context_features: Optional[Dict[str, Any]] = None):
        with self._lock:
            self._timing_history.append(delay)
            if len(self._timing_history) % 50 == 0 and HAS_ML:
                self._update_models()

    def _update_models(self):
        if not (HAS_ML and HAS_NUMPY) or len(self._timing_history) < 20:
            return
        try:
            timing_array = np.array(list(self._timing_history))
            self._kde_model.fit(timing_array.reshape(-1, 1))
            logger.debug("[USARE] KDE timing model updated")
        except Exception as e:
            logger.debug("[USARE] Failed to update ML models: %s", e)

    def get_timing_stats(self) -> Dict[str, Any]:
        with self._lock:
            if not self._timing_history:
                return {"status": "no_data"}
            delays = list(self._timing_history)
            if HAS_NUMPY and np is not None:
                mean_d = float(np.mean(delays))
                std_d = float(np.std(delays))
                min_d = float(np.min(delays))
                max_d = float(np.max(delays))
            else:
                mean_d = sum(delays) / len(delays)
                variance = sum((x - mean_d) ** 2 for x in delays) / max(len(delays) - 1, 1)
                std_d = math.sqrt(variance)
                min_d = min(delays)
                max_d = max(delays)
            return {
                "total_delays": len(delays),
                "mean_delay": mean_d,
                "std_delay": std_d,
                "min_delay": min_d,
                "max_delay": max_d,
                "current_profile": self.config.profile.value,
                "ml_available": HAS_ML,
            }


class AdvancedGhostTimer(GhostTimer):
    """Enhanced GhostTimer with ML capabilities."""

    def __init__(self, config: Optional[TimingConfig] = None):
        super().__init__(config)
        self._ml_engine = None
        if self.config.profile in (TimingProfile.ML_ADAPTIVE, TimingProfile.BEHAVIORAL):
            self._ml_engine = MLTimingEngine(self.config)

    def ghost_delay(self) -> float:
        """Generate enhanced timing delay with ML support.

        Handles all TimingProfile values explicitly so no profile silently
        falls through to Gaussian when it shouldn't.
        """
        profile = self.config.profile

        if profile == TimingProfile.ML_ADAPTIVE:
            if self._ml_engine:
                delay = self._ml_engine.generate_ml_delay()
                self._ml_engine.record_timing(delay)
                return delay

        elif profile == TimingProfile.BEHAVIORAL:
            if self._ml_engine:
                delay = self._ml_engine.generate_ml_delay()
                self._ml_engine.record_timing(delay)
                return delay

        elif profile == TimingProfile.ADAPTIVE:
            return self._adaptive_delay()

        # FIX: POISSON was missing here — it silently fell through to Gaussian.
        # Delegate to the parent implementation which has the correct exponential
        # inter-arrival logic.
        elif profile == TimingProfile.POISSON:
            return self._poisson_delay()

        # All remaining profiles (GHOST, PHANTOM, SHADOW, GLACIER, LTE, …)
        return self._gaussian_sample(
            self.config.mean,
            self.config.std_dev,
            self.config.floor,
            self.config.ceiling,
        )

    @property
    def stats(self) -> dict:
        base_stats = super().stats
        if self._ml_engine:
            ml_stats = self._ml_engine.get_timing_stats()
            base_stats.update({"ml_stats": ml_stats, "ml_enabled": True})
        else:
            base_stats.update({"ml_enabled": False})
        return base_stats

    def record_timing_context(self, delay: float, context: Dict[str, Any]):
        if self._ml_engine:
            self._ml_engine.record_timing(delay, context)
        self._delays_generated += 1
        self._total_delay_time += delay


# Example usage
def main():
    """Example usage of ML timing engine."""
    config = TimingConfig.from_profile(TimingProfile.ML_ADAPTIVE)
    timer = AdvancedGhostTimer(config)
    print("Testing ML-based timing...")
    for i in range(10):
        delay = timer.ghost_delay()
        print(f"Delay {i+1}: {delay:.2f}s")
        timer.sync_ghost_wait()
    print("\nStatistics:")
    for key, value in timer.stats.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()
