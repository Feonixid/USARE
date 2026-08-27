import pytest
import statistics
from evasion.timing import GhostTimer, TimingConfig, TimingProfile
class TestGhostTimerDefault:
    timer: GhostTimer
    def setup_method(self):
        self.timer = GhostTimer()
    def test_delay_within_bounds(self):
        for _ in range(1000):
            delay = self.timer.ghost_delay()
            assert 30.0 <= delay <= 90.0, f"Delay {delay} out of bounds"
    def test_distribution_mean(self):
        samples = [self.timer.ghost_delay() for _ in range(10000)]
        mean = statistics.mean(samples)
        assert 55.0 <= mean <= 65.0, f"Mean {mean} too far from 60"
    def test_distribution_std_dev(self):
        samples = [self.timer.ghost_delay() for _ in range(10000)]
        std = statistics.stdev(samples)
        assert 10.0 <= std <= 20.0, f"Std dev {std} too far from 15"
class TestGhostTimerPhantom:
    def test_phantom_bounds(self):
        config = TimingConfig.from_profile(TimingProfile.PHANTOM)
        timer = GhostTimer(config)
        for _ in range(500):
            delay = timer.ghost_delay()
            assert 60.0 <= delay <= 180.0, f"PHANTOM delay {delay} out of bounds"
class TestGhostTimerShadow:
    def test_shadow_minimum(self):
        config = TimingConfig.from_profile(TimingProfile.SHADOW)
        timer = GhostTimer(config)
        delays = [timer.ghost_delay() for _ in range(100)]
        assert min(delays) >= 180.0, "SHADOW delay below 180s"
class TestGhostTimerAdaptive:
    def test_adaptive_low_heat(self):
        config = TimingConfig.from_profile(TimingProfile.ADAPTIVE)
        config.heat_callback = lambda: 0.0
        timer = GhostTimer(config)
        delays = [timer.ghost_delay() for _ in range(100)]
        mean = statistics.mean(delays)
        assert mean < 200, f"Low-heat mean {mean} too high"
    def test_adaptive_high_heat(self):
        config = TimingConfig.from_profile(TimingProfile.ADAPTIVE)
        config.heat_callback = lambda: 0.8
        timer = GhostTimer(config)
        delays = [timer.ghost_delay() for _ in range(100)]
        mean = statistics.mean(delays)
        assert mean > 100, f"High-heat mean {mean} too low"
    def test_adaptive_increases_with_heat(self):
        low_config = TimingConfig.from_profile(TimingProfile.ADAPTIVE)
        low_config.heat_callback = lambda: 0.1
        low_timer = GhostTimer(low_config)
        high_config = TimingConfig.from_profile(TimingProfile.ADAPTIVE)
        high_config.heat_callback = lambda: 0.9
        high_timer = GhostTimer(high_config)
        low_mean = statistics.mean([low_timer.ghost_delay() for _ in range(200)])
        high_mean = statistics.mean([high_timer.ghost_delay() for _ in range(200)])
        assert high_mean > low_mean * 2, "High heat should produce much longer delays"
class TestBurstDetection:
    def test_should_pause_on_burst(self):
        timer = GhostTimer()
        assert timer.should_pause(10, 60.0) is True
    def test_should_not_pause_on_slow(self):
        timer = GhostTimer()
        assert timer.should_pause(2, 60.0) is False
    def test_should_pause_on_zero_time(self):
        timer = GhostTimer()
        assert timer.should_pause(1, 0) is True
class TestTimerStats:
    def test_stats_structure(self):
        timer = GhostTimer()
        timer.ghost_delay()
        stats = timer.stats
        assert "delays_generated" in stats
        assert "total_delay_time_sec" in stats
        assert "average_delay_sec" in stats
        assert "profile" in stats
        assert stats["delays_generated"] == 1