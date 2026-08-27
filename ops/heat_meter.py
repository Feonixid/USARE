import time
import math
import threading
from typing import Optional
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
class HeatMeter:
    DEFAULT_THRESHOLD = 0.083   
    DEFAULT_K = 50.0            
    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        k: float = DEFAULT_K,
        ids_name: str = "Snort sfPortscan",
    ):
        self.threshold = threshold
        self.k = k
        self.ids_name = ids_name
        self._lock = threading.Lock()
        self._packets_sent = 0
        self._decoys_sent = 0
        self._start_time = time.time()
        self._last_packet_time: Optional[float] = None
        self._window_packets: list = []  
        self._window_size = 60.0
        self._callbacks: list = []       # Strategy controller callbacks
    def register_callback(self, callback):
        """Register a callback to be notified after each packet recording."""
        self._callbacks.append(callback)
    def record_packet(self, is_decoy: bool = False):
        with self._lock:
            now = time.time()
            if is_decoy:
                self._decoys_sent += 1
            else:
                self._packets_sent += 1
            self._last_packet_time = now
            self._window_packets.append(now)
            cutoff = now - self._window_size
            self._window_packets = [
                t for t in self._window_packets if t > cutoff
            ]
    def detection_probability(self) -> float:
        with self._lock:
            elapsed = time.time() - self._start_time
            if elapsed <= 0:
                return 0.0
            rate = self._packets_sent / elapsed
            exponent = -self.k * (rate - self.threshold)
            exponent = max(-500, min(500, exponent))
            return 1.0 / (1.0 + math.exp(exponent))
    def burst_probability(self) -> float:
        with self._lock:
            if not self._window_packets:
                return 0.0
            window_rate = len(self._window_packets) / self._window_size
            exponent = -self.k * (window_rate - self.threshold * 2)
            exponent = max(-500, min(500, exponent))
            return 1.0 / (1.0 + math.exp(exponent))
    @property
    def heat_level(self) -> str:
        p = self.detection_probability()
        if p < 0.20:
            return "🟢 INVISIBLE"
        elif p < 0.50:
            return "🟡 CAUTION"
        elif p < 0.75:
            return "🟠 DANGER"
        else:
            return "🔴 CRITICAL"
    @property
    def stats(self) -> dict:
        with self._lock:
            elapsed = time.time() - self._start_time
            return {
                "detection_probability": round(float(self.detection_probability()), 4),
                "burst_probability": round(float(self.burst_probability()), 4),
                "heat_level": self.heat_level,
                "packets_sent": self._packets_sent,
                "decoys_sent": self._decoys_sent,
                "total_packets": self._packets_sent + self._decoys_sent,
                "elapsed_seconds": round(float(elapsed), 1),
                "average_rate_pps": round(
                    float(self._packets_sent / max(elapsed, 0.001)), 6
                ),
                "window_packets": len(self._window_packets),
                "ids_target": self.ids_name,
                "threshold_pps": self.threshold,
            }
    def display(self, console: Optional[Console] = None):
        if console is None:
            console = Console()
        stats = self.stats
        p = stats["detection_probability"]
        if p < 0.20:
            color = "green"
            bar_char = "█"
        elif p < 0.50:
            color = "yellow"
            bar_char = "█"
        elif p < 0.75:
            color = "dark_orange"
            bar_char = "█"
        else:
            color = "red"
            bar_char = "█"
        bar_length = 40
        filled = int(p * bar_length)
        empty = bar_length - filled
        heat_bar = f"[{color}]{bar_char * filled}[/{color}]{'░' * empty}"
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="white")
        table.add_row("Detection P", f"{p:.2%}")
        table.add_row("Burst P", f"{stats['burst_probability']:.2%}")
        table.add_row("Heat Level", stats["heat_level"])
        table.add_row("Probes Sent", str(stats["packets_sent"]))
        table.add_row("Decoys Sent", str(stats["decoys_sent"]))
        table.add_row("Elapsed", f"{stats['elapsed_seconds']:.0f}s")
        table.add_row("Avg Rate", f"{stats['average_rate_pps']:.4f} pps")
        table.add_row("IDS Target", stats["ids_target"])
        table.add_row("Threshold", f"{stats['threshold_pps']:.3f} pps")
        panel = Panel(
            table,
            title=f"[bold]🌡️  USARE Heat Meter  🌡️[/bold]",
            subtitle=f"[dim]{heat_bar}[/dim]",
            border_style=color,
            padding=(1, 2),
        )
        console.print(panel)
    def get_recommendation(self) -> str:
        p = self.detection_probability()
        if p < 0.20:
            return "Operating normally. Continue scanning."
        elif p < 0.50:
            return "Approaching threshold. Consider switching to PHANTOM profile."
        elif p < 0.75:
            return "Likely triggering alerts. Switch to SHADOW profile immediately."
        else:
            return "ABORT RECOMMENDED. Pause all scanning for 10+ minutes."

    # ── Scan Rate Telemetry ────────────────────────────────────────────────

    def current_pps(self) -> float:
        """Actual scan rate in packets-per-second over the last 60s window."""
        with self._lock:
            if not self._window_packets:
                return 0.0
            elapsed = min(self._window_size, time.time() - self._start_time)
            return len(self._window_packets) / max(elapsed, 0.001)

    def declared_profile_pps(self, profile_mean_seconds: float) -> float:
        """
        Expected PPS for a given timing profile mean delay.
        e.g. ghost (60s mean) = 1/60 = 0.0167 pps
        """
        return 1.0 / max(profile_mean_seconds, 0.001)

    def rate_telemetry(self, declared_mean_s: float = 60.0) -> dict:
        """
        Compare actual scan rate vs the declared timing profile.
        Returns dict with actual_pps, declared_pps, overspeed_factor, warning.
        A factor > 2.0 means you're scanning twice as fast as declared —
        which can happen if port chunks run too quickly or parallelism is too high.
        """
        actual  = self.current_pps()
        declared = self.declared_profile_pps(declared_mean_s)
        factor   = actual / declared if declared > 0 else 0.0
        warning  = ""
        if factor > 5.0:
            warning = f"CRITICAL: Scanning {factor:.1f}x faster than declared profile — IDS will correlate"
        elif factor > 2.0:
            warning = f"WARNING: Scanning {factor:.1f}x faster than declared profile"
        return {
            "actual_pps":       round(actual, 6),
            "declared_pps":     round(declared, 6),
            "overspeed_factor": round(factor, 2),
            "warning":          warning,
        }