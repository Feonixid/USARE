"""
USARE AI Active Intelligence Engine

Learns from real-time probe outcomes to optimize scanning strategy.
Where ai_modeler.py handles pre-scan passive OSINT, this module operates
DURING the scan — consuming every probe result and adapting in real-time.

Three core capabilities:

1. Response Pattern Learning
   - Trains on probe type → response outcome mappings
   - Predicts which probes will succeed vs get filtered
   - Eliminates wasted packets by skipping probes with <20% predicted success

2. IDS Evasion Learning
   - Tracks which probes trigger no response (likely detected/dropped)
   - Correlates dropped probes with timing, flag types, and packet attributes
   - Dynamically adjusts evasion parameters to minimize detection

3. Target Behavior Modeling
   - Builds a statistical model of target response latency
   - Identifies optimal timing windows (e.g., high load periods with slower IDS)
   - Detects rate-limiting patterns and adapts timing accordingly
"""

import time
import math
import random
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque, defaultdict

logger = logging.getLogger("usare.ai_response_learner")


# ══════════════════════════════════
#  Data Types
# ══════════════════════════════════

@dataclass
class ProbeOutcome:
    """A single probe and its outcome — the training data."""
    port: int
    probe_type: str          # "SYN", "ACK", "FIN", "XMAS", "NULL", "UDP"
    flags_used: str
    evasion_active: List[str]  # Which evasion layers were active
    timing_delay: float      # Actual inter-probe delay used
    timestamp: float         # When the probe was sent
    got_response: bool
    response_type: str       # "SYN-ACK", "RST", "ICMP", "timeout", "filtered"
    latency_ms: float
    detected: bool = False   # True if we suspect the probe was detected


@dataclass
class ProbeSuccessPrediction:
    """Prediction for whether a probe will succeed."""
    probe_type: str
    port: int
    predicted_success: float     # 0.0—1.0
    recommended_evasion: List[str]
    recommended_delay: float
    confidence: float


@dataclass
class TargetBehaviorModel:
    """Statistical model of target response behavior."""
    mean_latency_ms: float = 0.0
    std_latency_ms: float = 0.0
    min_latency_ms: float = float("inf")
    max_latency_ms: float = 0.0
    response_rate: float = 0.0        # Fraction of probes that get any response
    rate_limit_detected: bool = False
    rate_limit_threshold: float = 0.0  # Probes/sec that triggers rate limiting
    optimal_delay_ms: float = 0.0     # Best delay for stealth
    busy_periods: List[Tuple[float, float]] = field(default_factory=list)
    quiet_periods: List[Tuple[float, float]] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "mean_latency_ms": round(self.mean_latency_ms, 2),
            "std_latency_ms": round(self.std_latency_ms, 2),
            "response_rate": round(self.response_rate, 4),
            "rate_limit_detected": self.rate_limit_detected,
            "optimal_delay_ms": round(self.optimal_delay_ms, 2),
        }


# ══════════════════════════════════
#  Response Pattern Learner
# ══════════════════════════════════

class ResponsePatternLearner:
    """
    Bayesian learner that builds conditional probability tables:
    P(success | probe_type, port_range, evasion_layers)

    Uses a simple Beta-Binomial model per feature combination.
    No external dependencies — pure Python Bayesian updating.
    """

    def __init__(self):
        # Beta distribution parameters: (alpha, beta) per feature key
        # alpha = successes + prior, beta = failures + prior
        self._models: Dict[str, List[float]] = {}  # key → [alpha, beta]
        self._lock = threading.Lock()
        self._observation_count = 0

    def _feature_key(self, probe_type: str, port: int, evasion: List[str]) -> str:
        """Create a feature key from probe attributes."""
        port_range = (port // 100) * 100  # Group ports by hundreds
        evasion_str = ",".join(sorted(evasion)) if evasion else "none"
        return f"{probe_type}:{port_range}:{evasion_str}"

    def observe(self, outcome: ProbeOutcome):
        """Update the model with a new probe outcome."""
        with self._lock:
            key = self._feature_key(outcome.probe_type, outcome.port, outcome.evasion_active)

            if key not in self._models:
                self._models[key] = [1.0, 1.0]  # Uniform prior

            if outcome.got_response and outcome.response_type not in ("timeout", "filtered"):
                self._models[key][0] += 1  # alpha (success)
            else:
                self._models[key][1] += 1  # beta (failure)

            self._observation_count += 1

    def predict_success(self, probe_type: str, port: int,
                        evasion: List[str]) -> float:
        """
        Predict success probability using Beta posterior mean.
        P(success) = alpha / (alpha + beta)
        """
        with self._lock:
            key = self._feature_key(probe_type, port, evasion)

            if key in self._models:
                alpha, beta = self._models[key]
                return alpha / (alpha + beta)

            # Fall back to probe_type-level statistics
            type_keys = [k for k in self._models if k.startswith(f"{probe_type}:")]
            if type_keys:
                total_alpha = sum(self._models[k][0] for k in type_keys)
                total_beta = sum(self._models[k][1] for k in type_keys)
                return total_alpha / (total_alpha + total_beta)

            return 0.5  # No data — uninformative prior

    def get_best_probe_type(self, port: int, available_types: List[str],
                            evasion: List[str]) -> str:
        """Select the probe type with highest predicted success."""
        best_type = available_types[0]
        best_score = 0.0

        for ptype in available_types:
            score = self.predict_success(ptype, port, evasion)
            if score > best_score:
                best_score = score
                best_type = ptype

        return best_type

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_observations": self._observation_count,
                "unique_feature_keys": len(self._models),
            }


# ══════════════════════════════════
#  IDS Evasion Learner
# ══════════════════════════════════

class IDSEvasionLearner:
    """
    Tracks which probes appear to be detected by IDS/IPS and correlates
    detection with probe attributes to identify patterns.

    Detection indicators:
    - Sudden increase in filtered/timeout responses
    - TCP RST from upstream device (not target)
    - ICMP admin-prohibited responses
    - Response rate drop after a burst
    """

    DETECTION_WINDOW = 30  # seconds
    DETECTION_THRESHOLD = 0.6  # 60% timeout → likely detected

    def __init__(self):
        self._recent_probes: deque = deque(maxlen=500)
        self._detection_events: List[Dict[str, Any]] = []
        self._evasion_scores: Dict[str, float] = {}  # evasion_combo → effectiveness
        self._lock = threading.Lock()

        # Probe attribute correlation with detection
        self._attribute_detection_rate: Dict[str, List[float]] = defaultdict(list)

    def observe(self, outcome: ProbeOutcome):
        """Process a probe outcome for IDS detection analysis."""
        with self._lock:
            self._recent_probes.append(outcome)
            self._check_detection_pattern()
            self._update_evasion_effectiveness(outcome)

    def _check_detection_pattern(self):
        """Detect if IDS has likely caught on to our scanning."""
        now = time.time()
        window_start = now - self.DETECTION_WINDOW
        recent = [p for p in self._recent_probes if p.timestamp > window_start]

        if len(recent) < 5:
            return

        timeout_rate = sum(1 for p in recent if not p.got_response) / len(recent)

        if timeout_rate > self.DETECTION_THRESHOLD:
            # Check if this is a new detection event (not duplicate)
            if (not self._detection_events or
                    now - self._detection_events[-1]["time"] > self.DETECTION_WINDOW):

                event = {
                    "time": now,
                    "timeout_rate": timeout_rate,
                    "probes_in_window": len(recent),
                    "probe_types": list(set(p.probe_type for p in recent)),
                    "avg_delay": sum(p.timing_delay for p in recent) / len(recent),
                }
                self._detection_events.append(event)

                logger.warning(
                    f"[AI-IDS] Detection pattern: {timeout_rate:.0%} timeout rate "
                    f"in last {self.DETECTION_WINDOW}s — IDS likely triggered"
                )

    def _update_evasion_effectiveness(self, outcome: ProbeOutcome):
        """Track how effective each evasion combination is."""
        evasion_key = ",".join(sorted(outcome.evasion_active)) if outcome.evasion_active else "none"

        if evasion_key not in self._evasion_scores:
            self._evasion_scores[evasion_key] = 0.5

        # Exponential moving average
        alpha = 0.1
        success = 1.0 if outcome.got_response and outcome.response_type != "filtered" else 0.0
        self._evasion_scores[evasion_key] = (
            (1 - alpha) * self._evasion_scores[evasion_key] + alpha * success
        )

    def get_best_evasion(self, available_evasions: List[List[str]]) -> List[str]:
        """Return the evasion combination with highest effectiveness."""
        with self._lock:
            best_combo: List[str] = []
            best_score = 0.0

            for combo in available_evasions:
                key = ",".join(sorted(combo)) if combo else "none"
                score = self._evasion_scores.get(key, 0.5)
                if score > best_score:
                    best_score = score
                    best_combo = combo

            return best_combo

    def is_detected(self) -> bool:
        """Check if we appear to be currently detected."""
        with self._lock:
            if not self._detection_events:
                return False
            last_event = self._detection_events[-1]
            return time.time() - last_event["time"] < self.DETECTION_WINDOW * 2

    @property
    def detection_count(self) -> int:
        return len(self._detection_events)

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "detection_events": len(self._detection_events),
                "currently_detected": self.is_detected(),
                "evasion_rankings": dict(
                    sorted(self._evasion_scores.items(), key=lambda x: -x[1])[:5]
                ),
            }


# ══════════════════════════════════
#  Target Behavior Modeler
# ══════════════════════════════════

class TargetBehaviorModeler:
    """
    Builds a statistical model of target response patterns to find:
    - Optimal timing (delays that minimize detection while maintaining speed)
    - Rate limiting thresholds
    - Busy vs quiet periods
    """

    def __init__(self, window_size: int = 200):
        self._latencies: deque = deque(maxlen=window_size)
        self._timestamps: deque = deque(maxlen=window_size)
        self._response_flags: deque = deque(maxlen=window_size)
        self._probe_rates: deque = deque(maxlen=50)  # Rate measurements
        self._lock = threading.Lock()

    def observe(self, outcome: ProbeOutcome):
        """Record a probe outcome for behavior modeling."""
        with self._lock:
            self._timestamps.append(outcome.timestamp)

            if outcome.got_response:
                self._latencies.append(outcome.latency_ms)
                self._response_flags.append(True)
            else:
                self._response_flags.append(False)

            # Calculate current probe rate
            if len(self._timestamps) >= 2:
                window = self._timestamps[-1] - self._timestamps[0]
                if window > 0:
                    rate = len(self._timestamps) / window
                    self._probe_rates.append((outcome.timestamp, rate))

    def build_model(self) -> TargetBehaviorModel:
        """Build the current behavior model."""
        with self._lock:
            model = TargetBehaviorModel()

            if not self._latencies:
                return model

            latencies = list(self._latencies)
            model.mean_latency_ms = sum(latencies) / len(latencies)
            model.min_latency_ms = min(latencies)
            model.max_latency_ms = max(latencies)

            if len(latencies) >= 2:
                mean = model.mean_latency_ms
                model.std_latency_ms = math.sqrt(
                    sum((x - mean) ** 2 for x in latencies) / (len(latencies) - 1)
                )

            # Response rate
            if self._response_flags:
                model.response_rate = sum(1 for f in self._response_flags if f) / len(self._response_flags)

            # Rate limiting detection
            if len(self._probe_rates) >= 10:
                self._detect_rate_limiting(model)

            # Optimal delay recommendation
            # Formula: 2x mean latency + 1 std dev → gives breathing room
            model.optimal_delay_ms = model.mean_latency_ms * 2 + model.std_latency_ms

            return model

    def _detect_rate_limiting(self, model: TargetBehaviorModel):
        """Detect if the target applies rate limiting."""
        rates = list(self._probe_rates)

        # Split into time windows and check if high-rate windows
        # correlate with lower response rates
        for i in range(len(rates) - 5):
            window_rates = [r[1] for r in rates[i:i+5]]
            avg_rate = sum(window_rates) / len(window_rates)

            # Check response rate during this window
            window_start = rates[i][0]
            window_end = rates[min(i+4, len(rates)-1)][0]

            responses_in_window = [
                f for t, f in zip(self._timestamps, self._response_flags)
                if window_start <= t <= window_end
            ]

            if responses_in_window:
                resp_rate = sum(1 for f in responses_in_window if f) / len(responses_in_window)

                if avg_rate > 2.0 and resp_rate < 0.5:
                    model.rate_limit_detected = True
                    model.rate_limit_threshold = avg_rate
                    break

    def get_recommended_delay(self) -> float:
        """Get the AI-recommended inter-probe delay in seconds."""
        model = self.build_model()
        if model.rate_limit_detected:
            # Stay well below the rate limit
            safe_rate = model.rate_limit_threshold * 0.5
            return max(1.0 / safe_rate, 1.0) if safe_rate > 0 else 5.0

        if model.optimal_delay_ms > 0:
            return model.optimal_delay_ms / 1000.0  # Convert to seconds

        return 1.0  # Default 1 second


# ══════════════════════════════════
#  Unified AI Engine
# ══════════════════════════════════

class AIActiveEngine:
    """
    Unified AI engine that combines all three learning subsystems.
    Attach to the scan pipeline and feed it every probe outcome.
    """

    # Minimum predicted success to attempt a probe
    MIN_SUCCESS_THRESHOLD = 0.20

    def __init__(self):
        self.pattern_learner = ResponsePatternLearner()
        self.ids_learner = IDSEvasionLearner()
        self.behavior_modeler = TargetBehaviorModeler()
        self._total_probes = 0
        self._skipped_probes = 0

    def observe(self, outcome: ProbeOutcome):
        """Feed a probe outcome to all subsystems."""
        self.pattern_learner.observe(outcome)
        self.ids_learner.observe(outcome)
        self.behavior_modeler.observe(outcome)
        self._total_probes += 1

    def should_probe(self, probe_type: str, port: int,
                     evasion: List[str]) -> ProbeSuccessPrediction:
        """
        AI decision: should we send this probe?

        Returns a prediction with recommended adjustments.
        """
        predicted_success = self.pattern_learner.predict_success(probe_type, port, evasion)

        # If IDS has detected us, reduce predicted success
        if self.ids_learner.is_detected():
            predicted_success *= 0.3

        # Get best evasion recommendation
        best_evasion = self.ids_learner.get_best_evasion([
            evasion,
            evasion + ["fragmentation"],
            evasion + ["flow_morph"],
            ["tunnel_doh"],
        ])

        # Get optimal delay
        delay = self.behavior_modeler.get_recommended_delay()

        prediction = ProbeSuccessPrediction(
            probe_type=probe_type,
            port=port,
            predicted_success=predicted_success,
            recommended_evasion=best_evasion,
            recommended_delay=delay,
            confidence=min(self._total_probes / 50.0, 1.0),  # Confidence grows with data
        )

        if predicted_success < self.MIN_SUCCESS_THRESHOLD and self._total_probes > 30:
            self._skipped_probes += 1
            logger.debug(
                f"[AI] Skipping {probe_type} on port {port}: "
                f"predicted success {predicted_success:.0%}"
            )

        return prediction

    def get_best_strategy(self, port: int, available_types: List[str],
                          available_evasions: List[List[str]]) -> Dict[str, Any]:
        """Get the AI-recommended scan strategy for a specific port."""
        best_type = self.pattern_learner.get_best_probe_type(
            port, available_types, []
        )
        best_evasion = self.ids_learner.get_best_evasion(available_evasions)
        delay = self.behavior_modeler.get_recommended_delay()

        return {
            "probe_type": best_type,
            "evasion_layers": best_evasion,
            "delay_seconds": delay,
            "ids_detected": self.ids_learner.is_detected(),
        }

    def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of AI engine activity."""
        behavior = self.behavior_modeler.build_model()
        return {
            "total_probes_analyzed": self._total_probes,
            "probes_skipped_by_ai": self._skipped_probes,
            "skip_rate": (self._skipped_probes / max(self._total_probes, 1)),
            "pattern_learner": self.pattern_learner.stats,
            "ids_learner": self.ids_learner.stats,
            "behavior_model": behavior.to_dict(),
        }
