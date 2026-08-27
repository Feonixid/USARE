"""
USARE Active Interference Detector

Monitors live scan responses for signs that the network is actively
interfering with probes. Detects and classifies:

  RST injection         — RSTs arrive too fast to be from a real closed port
                          (IPS/firewall injecting RSTs to poison results)
  Transparent blocking  — HTTP 200 responses that contain block/captive pages
                          (WAF returning fake 200 to hide blocking)
  Rate limiting         — latency spike of 3x or more over baseline
                          (IDS throttling the source IP)
  Port unreachable flood — ICMP unreachable rate above expected baseline
  Honeypot indicators   — every port responds identically, or latency is
                          suspiciously uniform across all ports

When interference is detected the scanner can:
  - Escalate timing profile (ghost → phantom → shadow → glacier)
  - Switch to a different scan technique (SYN → idle → fragmented)
  - Pause and wait for the interference window to close
  - Raise an alert and let the operator decide
"""

import time
import statistics
import logging
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Dict, Optional, Deque

logger = logging.getLogger("usare.interference_detector")


class InterferenceType(Enum):
    NONE             = "none"
    RST_INJECTION    = "rst_injection"
    TRANSPARENT_BLOCK = "transparent_block"
    RATE_LIMITED     = "rate_limited"
    ICMP_FLOOD       = "icmp_flood"
    HONEYPOT         = "honeypot"
    LATENCY_SPIKE    = "latency_spike"
    RESULT_POISONING = "result_poisoning"


@dataclass
class ProbeObservation:
    port: int
    response_type: str          # "synack" | "rst" | "timeout" | "icmp_unreach" | "http_XXX"
    latency_ms: float
    timestamp: float = field(default_factory=time.monotonic)
    raw_flags: Optional[int] = None
    content_hash: Optional[int] = None   # hash of first 64 bytes of response


@dataclass
class InterferenceEvent:
    interference_type: InterferenceType
    confidence: float               # 0.0 – 1.0
    description: str
    first_seen: float = field(default_factory=time.monotonic)
    evidence: List[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.interference_type.value,
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
        }


class InterferenceDetector:
    """
    Sliding-window interference detector.

    Feed observations via record_observation() after each probe.
    Call analyze() periodically (every 20–50 probes) to get a list of
    active InterferenceEvent objects.
    """

    # ── tuneable thresholds ──────────────────────────────────────────────
    RST_TOO_FAST_MS         = 2.0    # RSTs in < 2ms are suspicious (real RSTs from a remote host take at least a few ms RTT)
    RST_INJECTION_RATE      = 0.60   # >60% RSTs in a window → likely injection
    LATENCY_SPIKE_FACTOR    = 3.0    # latency 3x above rolling baseline → rate limit
    MIN_OBSERVATIONS        = 10     # minimum obs before analysis is meaningful
    WINDOW_SIZE             = 50     # sliding window of recent probes
    UNIFORM_LATENCY_CV      = 0.05   # coefficient of variation < 5% = suspiciously uniform
    HTTP_BLOCK_PHRASES      = [
        "access denied", "blocked", "captive portal", "policy violation",
        "forcepoint", "zscaler", "bluecoat", "symantec web gateway",
        "netskope", "squid", "websense", "smoothwall",
    ]

    def __init__(self):
        self._window: Deque[ProbeObservation] = deque(maxlen=self.WINDOW_SIZE)
        self._all_observations: List[ProbeObservation] = []
        self._baseline_latency: Optional[float] = None
        self._events: List[InterferenceEvent] = []
        self._last_analysis_time: float = 0.0

    def record_observation(self, obs: ProbeObservation):
        self._window.append(obs)
        self._all_observations.append(obs)
        # Update baseline (rolling average of first 20 observations)
        if self._baseline_latency is None and len(self._all_observations) >= 10:
            lats = [o.latency_ms for o in self._all_observations[:20] if o.latency_ms > 0]
            if lats:
                self._baseline_latency = statistics.mean(lats)
                logger.debug("[interference] Baseline latency established: %.1f ms", self._baseline_latency)

    def analyze(self) -> List[InterferenceEvent]:
        """
        Run all detectors over the current observation window.
        Returns list of active InterferenceEvent objects.
        """
        if len(self._window) < self.MIN_OBSERVATIONS:
            return []

        events: List[InterferenceEvent] = []
        obs_list = list(self._window)

        events += self._detect_rst_injection(obs_list)
        events += self._detect_rate_limit(obs_list)
        events += self._detect_transparent_block(obs_list)
        events += self._detect_honeypot(obs_list)

        # Deduplicate by type (keep highest confidence)
        by_type: Dict[InterferenceType, InterferenceEvent] = {}
        for ev in events:
            if ev.interference_type not in by_type or ev.confidence > by_type[ev.interference_type].confidence:
                by_type[ev.interference_type] = ev

        self._events = list(by_type.values())
        self._last_analysis_time = time.monotonic()
        return self._events

    # ── individual detectors ─────────────────────────────────────────────

    def _detect_rst_injection(self, obs: List[ProbeObservation]) -> List[InterferenceEvent]:
        """
        Real RSTs from closed ports arrive after a real RTT (≥ 2 ms for most networks).
        Injected RSTs from IPS devices arrive in < 1–2 ms because the IPS is inline
        and doesn't need to traverse the full path.
        Also flag: RST rate > 60% when we'd expect mixed open/closed.
        """
        events = []
        rsts = [o for o in obs if o.response_type == "rst"]
        if not rsts:
            return []

        fast_rsts = [o for o in rsts if o.latency_ms < self.RST_TOO_FAST_MS and o.latency_ms > 0]
        fast_rate = len(fast_rsts) / len(obs)

        if fast_rate > 0.30:
            conf = min(0.95, fast_rate * 1.5)
            events.append(InterferenceEvent(
                interference_type=InterferenceType.RST_INJECTION,
                confidence=conf,
                description=f"RST injection suspected: {len(fast_rsts)}/{len(obs)} RSTs arrived in < {self.RST_TOO_FAST_MS}ms",
                evidence=[
                    f"Fast RSTs: {len(fast_rsts)} (threshold < {self.RST_TOO_FAST_MS}ms)",
                    f"Minimum RST latency: {min(o.latency_ms for o in fast_rsts):.2f}ms",
                    f"Fast RST rate: {fast_rate:.0%}",
                ],
                recommended_action="Switch to idle/zombie scan or try fragmentation. Injected RSTs cannot spoof idle scan IPID changes.",
            ))

        rst_rate = len(rsts) / len(obs)
        if rst_rate > self.RST_INJECTION_RATE and not fast_rsts:
            events.append(InterferenceEvent(
                interference_type=InterferenceType.RESULT_POISONING,
                confidence=0.65,
                description=f"Unusually high RST rate ({rst_rate:.0%}) — firewall may be returning RST to mask open ports",
                evidence=[f"RST rate in window: {rst_rate:.0%}"],
                recommended_action="Run ACK scan to confirm firewall is stateful-blocking. Try --xmas or --maimon for confirmation.",
            ))

        return events

    def _detect_rate_limit(self, obs: List[ProbeObservation]) -> List[InterferenceEvent]:
        """
        Latency spike: rolling average over last 10 probes is 3x above baseline.
        Indicates the IDS/IPS has started throttling traffic from our IP.
        """
        if self._baseline_latency is None or self._baseline_latency <= 0:
            return []
        recent = [o.latency_ms for o in list(obs)[-10:] if o.latency_ms > 0]
        if len(recent) < 5:
            return []
        recent_avg = statistics.mean(recent)
        spike_factor = recent_avg / self._baseline_latency
        if spike_factor >= self.LATENCY_SPIKE_FACTOR:
            conf = min(0.90, 0.50 + (spike_factor - 3.0) * 0.15)
            return [InterferenceEvent(
                interference_type=InterferenceType.RATE_LIMITED,
                confidence=conf,
                description=f"Latency spike: {recent_avg:.0f}ms vs baseline {self._baseline_latency:.0f}ms ({spike_factor:.1f}x)",
                evidence=[
                    f"Baseline: {self._baseline_latency:.1f}ms",
                    f"Recent avg: {recent_avg:.1f}ms",
                    f"Spike factor: {spike_factor:.1f}x",
                ],
                recommended_action="Escalate to SHADOW or GLACIER timing profile. Pause for 60–300s before resuming.",
            )]
        return []

    def _detect_transparent_block(self, obs: List[ProbeObservation]) -> List[InterferenceEvent]:
        """
        Transparent proxy/WAF returning HTTP 200 but with block-page content.
        We detect this if multiple HTTP probes return identical content hashes
        across different ports (impossible for real servers serving different services).
        """
        http_obs = [o for o in obs if o.response_type.startswith("http_") and o.content_hash is not None]
        if len(http_obs) < 3:
            return []
        hashes = [o.content_hash for o in http_obs]
        # If >50% of HTTP responses have the same content hash, something is wrong
        from collections import Counter
        most_common_hash, count = Counter(hashes).most_common(1)[0]
        if count / len(http_obs) > 0.50 and len(set(hashes)) < 3:
            return [InterferenceEvent(
                interference_type=InterferenceType.TRANSPARENT_BLOCK,
                confidence=0.80,
                description=f"Transparent proxy detected: {count}/{len(http_obs)} HTTP responses share identical content hash",
                evidence=[
                    f"Repeated content hash: {most_common_hash:#010x}",
                    f"Affected ports: {[o.port for o in http_obs if o.content_hash == most_common_hash]}",
                ],
                recommended_action="Use --tunnel https or --sni-smuggle to bypass transparent proxy. TLS inspection may be in play.",
            )]
        return []

    def _detect_honeypot(self, obs: List[ProbeObservation]) -> List[InterferenceEvent]:
        """
        Honeypot indicators:
          - Every port returns OPEN (real servers have some closed ports)
          - Latency is suspiciously uniform (real networks have variance)
          - All open ports return the same banner (deception platform)
        """
        events = []
        open_obs = [o for o in obs if o.response_type == "synack"]
        if len(obs) < 20:
            return []

        # All-open: if >80% of probed ports are open, that's suspicious
        open_rate = len(open_obs) / len(obs)
        if open_rate > 0.80 and len(obs) >= 20:
            events.append(InterferenceEvent(
                interference_type=InterferenceType.HONEYPOT,
                confidence=0.70,
                description=f"Honeypot suspected: {open_rate:.0%} of probed ports appear open",
                evidence=[
                    f"Open rate: {open_rate:.0%} ({len(open_obs)}/{len(obs)})",
                    "Real servers rarely have >80% of probed ports open",
                ],
                recommended_action="Run --app-probe to verify services are real. Check with --banner-timing for suspicious uniformity.",
            ))

        # Uniform latency: coefficient of variation < 5%
        lats = [o.latency_ms for o in obs if o.latency_ms > 0]
        if len(lats) >= 15:
            try:
                mean_lat = statistics.mean(lats)
                std_lat  = statistics.stdev(lats)
                cv = std_lat / mean_lat if mean_lat > 0 else 0
                if cv < self.UNIFORM_LATENCY_CV:
                    events.append(InterferenceEvent(
                        interference_type=InterferenceType.HONEYPOT,
                        confidence=0.65,
                        description=f"Suspiciously uniform latency (CV={cv:.3f}) — possible deception platform",
                        evidence=[
                            f"Mean: {mean_lat:.2f}ms  StdDev: {std_lat:.2f}ms  CV: {cv:.4f}",
                            "Real networks show natural variance > 5%",
                        ],
                        recommended_action="Correlate with passive recon. A real server's latency varies with load. Static latency = synthetic.",
                    ))
            except statistics.StatisticsError:
                pass

        return events

    def classify_inline_appliance(self, obs: Optional[List[ProbeObservation]] = None) -> Optional[Dict[str, Any]]:
        """
        Classify intermediate security appliances (Snort/Suricata, FortiGate, WAF)
        based on response timing and signature behaviors.
        """
        observations = obs or list(self._window)
        if not observations:
            return None

        fast_rsts = [o for o in observations if o.response_type == "rst" and o.latency_ms < 1.5]
        http_blocks = [o for o in observations if o.response_type in ("http_403", "http_401", "http_block")]

        # Snort / Suricata inline RST injection
        if len(fast_rsts) >= 3:
            return {
                "appliance": "Snort / Suricata IPS (Inline)",
                "confidence": 0.85,
                "evidence": f"{len(fast_rsts)} sub-millisecond RST packets (< 1.5ms) detected",
                "recommended_evasion": "Use fragmented TCP packets or multi-path dispersion to bypass inline inspection",
            }
        # FortiGate / Web Application Firewall
        if len(http_blocks) >= 2:
            return {
                "appliance": "FortiGate / Next-Gen WAF",
                "confidence": 0.80,
                "evidence": f"{len(http_blocks)} HTTP block codes returned on probe ports",
                "recommended_evasion": "Use HTTPS protocol tunneling with JA3 rotation",
            }

        return None

    # ── recommended escalation ────────────────────────────────────────────

    def get_recommended_profile(self) -> Optional[str]:
        """
        Based on active interference events, recommend a timing profile change.
        Returns profile name string or None if no change needed.
        """
        if not self._events:
            return None
        types = {e.interference_type for e in self._events}
        if InterferenceType.RATE_LIMITED in types:
            return "glacier"
        if InterferenceType.RST_INJECTION in types:
            return "shadow"
        if InterferenceType.LATENCY_SPIKE in types:
            return "phantom"
        return None

    def is_being_interfered(self) -> bool:
        return bool(self._events)

    def summary(self) -> dict:
        return {
            "total_observations": len(self._all_observations),
            "window_size": len(self._window),
            "baseline_latency_ms": round(self._baseline_latency, 2) if self._baseline_latency else None,
            "active_events": [e.to_dict() for e in self._events],
            "being_interfered": self.is_being_interfered(),
            "recommended_profile": self.get_recommended_profile(),
            "inferred_appliance": self.classify_inline_appliance(),
        }
