import pytest
from ops.strategy_controller import (
    StrategyController,
    StrategyState,
    TimingTier,
    ScanMethod,
    EvasionLevel,
)


class MockHeatMeter:
    def __init__(self, p: float = 0.0, b: float = 0.0):
        self._p = p
        self._b = b

    def set_heat(self, p: float, b: float = 0.0):
        self._p = p
        self._b = b

    def detection_probability(self) -> float:
        return self._p

    def burst_probability(self) -> float:
        return self._b


def test_strategy_controller_initial_state():
    mock_heat = MockHeatMeter(0.05)
    controller = StrategyController(mock_heat)
    assert controller.current_state.timing_tier == TimingTier.GHOST
    assert controller.current_state.evasion_level == EvasionLevel.STANDARD
    assert not controller.is_paused
    assert controller.get_timing_multiplier() == 1.0


def test_strategy_controller_threshold_computation():
    mock_heat = MockHeatMeter()
    controller = StrategyController(mock_heat)

    # Minimal (< 0.30)
    s_min = controller._compute_target_strategy(0.10)
    assert s_min.evasion_level == EvasionLevel.MINIMAL
    assert s_min.timing_tier == TimingTier.GHOST

    # Standard (0.30 - 0.50)
    s_std = controller._compute_target_strategy(0.35)
    assert s_std.evasion_level == EvasionLevel.STANDARD
    assert s_std.use_decoys is True

    # Enhanced (0.50 - 0.70)
    s_enh = controller._compute_target_strategy(0.55)
    assert s_enh.evasion_level == EvasionLevel.ENHANCED
    assert s_enh.timing_tier == TimingTier.PHANTOM
    assert s_enh.use_fragmentation is True

    # Maximum (0.70 - 0.80)
    s_max = controller._compute_target_strategy(0.75)
    assert s_max.evasion_level == EvasionLevel.MAXIMUM
    assert s_max.timing_tier == TimingTier.SHADOW
    assert s_max.use_flow_morph is True
    assert s_max.use_tunnel is True

    # Critical (>= 0.80)
    s_crit = controller._compute_target_strategy(0.85)
    assert s_crit.evasion_level == EvasionLevel.CRITICAL
    assert s_crit.timing_tier == TimingTier.PAUSED
    assert s_crit.cooldown_active is True


def test_strategy_controller_adaptation_and_callbacks():
    mock_heat = MockHeatMeter(0.35)
    controller = StrategyController(mock_heat, poll_interval=0.05)
    controller.MIN_CHANGE_INTERVAL = 0.0  # bypass delay for testing

    changes = []
    controller.register_callback(lambda st: changes.append(st))

    # Trigger evaluation with standard heat (matches default initial state)
    controller._evaluate_and_adapt()
    assert len(changes) == 0

    # Escalate to maximum heat (0.75)
    mock_heat.set_heat(0.75)
    controller._evaluate_and_adapt()
    assert len(changes) == 1
    assert controller.current_state.timing_tier == TimingTier.SHADOW
    assert controller.get_timing_multiplier() == 5.0

    # Escalate to critical (0.85)
    mock_heat.set_heat(0.85)
    controller._evaluate_and_adapt()
    assert len(changes) == 2
    assert controller.is_paused is True
    assert controller.get_timing_multiplier() == 0.0


def test_strategy_controller_context_manager():
    mock_heat = MockHeatMeter(0.1)
    with StrategyController(mock_heat, poll_interval=0.1) as controller:
        assert controller._running is True
    assert controller._running is False
