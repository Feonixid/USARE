"""
USARE Adaptive Strategy Controller

Closes the feedback loop between the HeatMeter and the scanner's
real-time behavior. Monitors detection probability and dynamically
switches:
  - Timing profile (GHOST → PHANTOM → SHADOW)
  - Scan method (SYN → ACK → FIN/XMAS → Idle failover)
  - Evasion layers (fragmentation → decoys → flow morph → tunnel)
  - Abort/cooldown protocol at critical heat levels

Runs as a background daemon thread, sampling heat meter every N seconds
and emitting strategy change events that the scanner consumes mid-scan.
"""

import time
import logging
import threading
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("usare.strategy_controller")


class ScanMethod(Enum):
    SYN = "syn"
    ACK = "ack"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    IDLE = "idle"


class EvasionLevel(Enum):
    MINIMAL = 0      # No evasion — raw speed
    STANDARD = 1     # Timing jitter + basic decoys
    ENHANCED = 2     # Fragmentation + entropy balancing
    MAXIMUM = 3      # Flow morphing + protocol tunneling
    CRITICAL = 4     # Full abort + cooldown


class TimingTier(Enum):
    GHOST = "ghost"        # ~60s mean delay, invisible
    PHANTOM = "phantom"    # ~120s mean delay, ultra-cautious
    SHADOW = "shadow"      # ~300s mean delay, near-zero detection
    PAUSED = "paused"      # Scan halted for cooldown


@dataclass
class StrategyState:
    """Current strategy configuration driven by heat meter."""
    timing_tier: TimingTier = TimingTier.GHOST
    scan_method: ScanMethod = ScanMethod.SYN
    evasion_level: EvasionLevel = EvasionLevel.STANDARD
    use_fragmentation: bool = False
    use_decoys: bool = True
    use_flow_morph: bool = False
    use_tunnel: bool = False
    cooldown_active: bool = False
    cooldown_until: float = 0.0
    last_change_time: float = field(default_factory=time.time)
    total_escalations: int = 0
    total_de_escalations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timing_tier": self.timing_tier.value,
            "scan_method": self.scan_method.value,
            "evasion_level": self.evasion_level.name,
            "fragmentation": self.use_fragmentation,
            "decoys": self.use_decoys,
            "flow_morph": self.use_flow_morph,
            "tunnel": self.use_tunnel,
            "cooldown_active": self.cooldown_active,
            "escalations": self.total_escalations,
            "de_escalations": self.total_de_escalations,
        }


class StrategyController:
    """
    Real-time adaptive strategy controller.

    Monitors the HeatMeter and dynamically adjusts scan configuration
    to maintain stealth while maximizing intelligence extraction.

    Threshold Table:
        P < 0.15  → MINIMAL   evasion, GHOST timing
        P < 0.30  → STANDARD  evasion, GHOST timing
        P < 0.50  → ENHANCED  evasion, PHANTOM timing  + frag on
        P < 0.70  → MAXIMUM   evasion, SHADOW timing   + flow morph + tunnel
        P >= 0.70 → CRITICAL  → PAUSE scan, inject decoy noise, cooldown
    """

    # Heat thresholds for strategy transitions
    THRESHOLDS = {
        "minimal":    0.15,
        "standard":   0.30,
        "enhanced":   0.50,
        "maximum":    0.70,
        "critical":   0.80,
    }

    # Cooldown durations in seconds by severity
    COOLDOWN_DURATIONS = {
        "warning":  120,   # 2 minutes
        "critical": 600,   # 10 minutes
    }

    # Minimum time between strategy changes (prevents oscillation)
    MIN_CHANGE_INTERVAL = 10.0  # seconds

    def __init__(self, heat_meter, poll_interval: float = 2.0):
        """
        Args:
            heat_meter: HeatMeter instance to monitor
            poll_interval: How often to check heat meter (seconds)
        """
        self.heat_meter = heat_meter
        self.poll_interval = poll_interval
        self.state = StrategyState()
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[StrategyState], None]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._change_history: List[Dict[str, Any]] = []

    def register_callback(self, callback: Callable[[StrategyState], None]):
        """Register a callback to be notified on strategy changes."""
        self._callbacks.append(callback)

    def start(self):
        """Start the background monitoring thread."""
        if self._running:
            return self
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="USARE-StrategyController"
        )
        self._thread.start()
        logger.info("[Strategy] Controller started — monitoring heat meter")
        return self

    def stop(self):
        """Stop the monitoring thread."""
        self._running = False
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("[Strategy] Controller stopped")

    def close(self):
        """Alias for stop() to provide clean resource lifecycle."""
        self.stop()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _monitor_loop(self):
        """Background loop polling heat meter and adjusting strategy."""
        while self._running:
            try:
                self._evaluate_and_adapt()
            except Exception as e:
                logger.debug(f"[Strategy] Monitor error: {e}")
            time.sleep(self.poll_interval)

    def _evaluate_and_adapt(self):
        """Core decision engine: read heat, compute strategy, apply changes."""
        detection_p = self.heat_meter.detection_probability()
        burst_p = self.heat_meter.burst_probability()
        effective_heat = max(detection_p, burst_p)

        with self._lock:
            # Check cooldown
            if self.state.cooldown_active:
                if time.time() < self.state.cooldown_until:
                    return  # Still in cooldown — do nothing
                else:
                    # Cooldown complete — de-escalate
                    self.state.cooldown_active = False
                    logger.info("[Strategy] Cooldown complete — resuming scan")

            # Prevent oscillation
            time_since_change = time.time() - self.state.last_change_time
            if time_since_change < self.MIN_CHANGE_INTERVAL:
                return

            # Determine target strategy based on heat
            new_state = self._compute_target_strategy(effective_heat)

            # Apply if changed
            if self._strategy_changed(new_state):
                old_state = self.state
                self.state = new_state
                self.state.last_change_time = time.time()

                direction = "ESCALATION" if new_state.evasion_level.value > old_state.evasion_level.value else "DE-ESCALATION"  # type: ignore[operator]
                if new_state.evasion_level.value > old_state.evasion_level.value:  # type: ignore[operator]
                    self.state.total_escalations = old_state.total_escalations + 1
                    self.state.total_de_escalations = old_state.total_de_escalations
                else:
                    self.state.total_de_escalations = old_state.total_de_escalations + 1
                    self.state.total_escalations = old_state.total_escalations

                logger.warning(
                    f"[Strategy] {direction}: heat={effective_heat:.2%} → "
                    f"timing={new_state.timing_tier.value}, "
                    f"method={new_state.scan_method.value}, "
                    f"evasion={new_state.evasion_level.name}"
                )

                self._change_history.append({
                    "time": time.time(),
                    "heat": effective_heat,
                    "direction": direction,
                    "new_state": new_state.to_dict(),
                })

                # Notify all registered callbacks
                for cb in self._callbacks:
                    try:
                        cb(new_state)
                    except Exception as e:
                        logger.debug(f"[Strategy] Callback error: {e}")

    def _compute_target_strategy(self, heat: float) -> StrategyState:
        """Compute the target strategy based on current heat level."""

        if heat >= self.THRESHOLDS["critical"]:
            # CRITICAL — full abort + cooldown
            cooldown_duration = self.COOLDOWN_DURATIONS["critical"]
            return StrategyState(
                timing_tier=TimingTier.PAUSED,
                scan_method=ScanMethod.SYN,
                evasion_level=EvasionLevel.CRITICAL,
                use_fragmentation=True,
                use_decoys=True,
                use_flow_morph=True,
                use_tunnel=True,
                cooldown_active=True,
                cooldown_until=time.time() + cooldown_duration,
            )

        elif heat >= self.THRESHOLDS["maximum"]:
            # MAXIMUM evasion — SHADOW timing, full stealth stack
            return StrategyState(
                timing_tier=TimingTier.SHADOW,
                scan_method=ScanMethod.FIN,  # Switch to stealthier FIN scan
                evasion_level=EvasionLevel.MAXIMUM,
                use_fragmentation=True,
                use_decoys=True,
                use_flow_morph=True,
                use_tunnel=True,
            )

        elif heat >= self.THRESHOLDS["enhanced"]:
            # ENHANCED evasion — PHANTOM timing, add fragmentation
            return StrategyState(
                timing_tier=TimingTier.PHANTOM,
                scan_method=ScanMethod.SYN,
                evasion_level=EvasionLevel.ENHANCED,
                use_fragmentation=True,
                use_decoys=True,
                use_flow_morph=False,
                use_tunnel=False,
            )

        elif heat >= self.THRESHOLDS["standard"]:
            # STANDARD evasion — GHOST timing, basic decoys
            return StrategyState(
                timing_tier=TimingTier.GHOST,
                scan_method=ScanMethod.SYN,
                evasion_level=EvasionLevel.STANDARD,
                use_fragmentation=False,
                use_decoys=True,
                use_flow_morph=False,
                use_tunnel=False,
            )

        else:
            # MINIMAL — running clean
            return StrategyState(
                timing_tier=TimingTier.GHOST,
                scan_method=ScanMethod.SYN,
                evasion_level=EvasionLevel.MINIMAL,
                use_fragmentation=False,
                use_decoys=False,
                use_flow_morph=False,
                use_tunnel=False,
            )

    def _strategy_changed(self, new_state: StrategyState) -> bool:
        """Check if the strategy actually changed."""
        return (
            new_state.timing_tier != self.state.timing_tier
            or new_state.scan_method != self.state.scan_method
            or new_state.evasion_level != self.state.evasion_level
            or new_state.cooldown_active != self.state.cooldown_active
        )

    @property
    def is_paused(self) -> bool:
        """Check if scan should be paused due to cooldown."""
        with self._lock:
            return self.state.cooldown_active

    @property
    def current_state(self) -> StrategyState:
        """Get the current strategy state (thread-safe)."""
        with self._lock:
            return self.state

    @property
    def change_history(self) -> List[Dict[str, Any]]:
        """Get the history of strategy changes."""
        return list(self._change_history)

    def get_timing_multiplier(self) -> float:
        """
        Returns a timing multiplier based on current strategy.
        The scanner uses this to adjust inter-probe delays dynamically.
        """
        with self._lock:
            multipliers = {
                TimingTier.GHOST: 1.0,
                TimingTier.PHANTOM: 2.0,
                TimingTier.SHADOW: 5.0,
                TimingTier.PAUSED: 0.0,  # Signal to stop
            }
            return multipliers.get(self.state.timing_tier, 1.0)

    def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of controller activity."""
        with self._lock:
            return {
                "current_state": self.state.to_dict(),
                "total_changes": len(self._change_history),
                "is_paused": self.state.cooldown_active,
                "history": self._change_history[-5:] if self._change_history else [],  # type: ignore[index]
            }
