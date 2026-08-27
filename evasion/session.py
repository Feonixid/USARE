import time
import threading
import json
import hashlib
from typing import Optional, Dict, List, Any, Set, Deque
from collections import deque
from dataclasses import dataclass
from evasion.port_shuffle import PRIORITY_PORTS
@dataclass
class ProbeRecord:
    target_ip: str
    port: int
    method: str          
    src_port: int
    timestamp: float
    response: Optional[str] = None  
    latency_ms: Optional[float] = None
    retry_count: int = 0
    def to_dict(self) -> dict:
        return self.__dict__
class SessionTracker:
    def __init__(
        self,
        max_retries: int = 3,
        rtt_window_size: int = 20,
        rate_limit_window_sec: float = 60.0,
        rate_limit_max: int = 100,
    ):
        self._lock = threading.Lock()
        self.max_retries = max_retries
        self._port_states: Dict[tuple, str] = {}
        self._src_port_map: Dict[tuple, int] = {}
        self._rtt_windows: Dict[str, Deque[float]] = {}
        self._rtt_window_size = rtt_window_size
        self._probe_history: List[ProbeRecord] = []
        self._rate_window: Deque[float] = deque()
        self._rate_limit_window = rate_limit_window_sec
        self._rate_limit_max = rate_limit_max
        self._session_start = time.time()
        self._total_probes = 0
        self._total_retries = 0
    def is_scanned(self, target: str, port: int) -> bool:
        with self._lock:
            return (target, port) in self._port_states
    def get_state(self, target: str, port: int) -> Optional[str]:
        with self._lock:
            return self._port_states.get((target, port))
    def set_state(self, target: str, port: int, state: str):
        with self._lock:
            self._port_states[(target, port)] = state
    def get_unscanned_ports(self, target: str, ports: List[int]) -> List[int]:
        with self._lock:
            return [p for p in ports if (target, p) not in self._port_states]
    def get_pinned_src_port(self, target: str, port: int) -> int:
        with self._lock:
            key = (target, port)
            if key not in self._src_port_map:
                hash_val = hashlib.sha256(f"{target}:{port}".encode()).digest()
                src_port = 49152 + (int.from_bytes(hash_val[:2], 'big') % 16384)  # type: ignore[index]
                self._src_port_map[key] = src_port
            return self._src_port_map[key]
    def record_rtt(self, target: str, rtt_ms: float):
        with self._lock:
            if target not in self._rtt_windows:
                self._rtt_windows[target] = deque(maxlen=self._rtt_window_size)
            self._rtt_windows[target].append(rtt_ms)
    def get_adaptive_timeout(self, target: str, multiplier: float = 3.0) -> float:
        with self._lock:
            window = self._rtt_windows.get(target)
            if not window or len(window) < 3: # type: ignore[arg-type]
                return 3.0
            avg_rtt = sum(window) / len(window) # type: ignore[arg-type]
            sorted_rtts = sorted(window) # type: ignore[arg-type]
            p95_idx = int(len(sorted_rtts) * 0.95) # type: ignore[arg-type]
            p95_rtt = sorted_rtts[min(p95_idx, len(sorted_rtts) - 1)] # type: ignore[arg-type]
            timeout_ms = max(avg_rtt, p95_rtt) * multiplier
            timeout_sec = timeout_ms / 1000.0
            return max(1.0, min(10.0, timeout_sec))
    def record_probe(
        self,
        target: str,
        port: int,
        method: str,
        src_port: int,
        response: Optional[str] = None,
        latency_ms: Optional[float] = None,
        is_retry: bool = False,
    ):
        with self._lock:
            record = ProbeRecord(
                target_ip=target,
                port=port,
                method=method,
                src_port=src_port,
                timestamp=time.time(),
                response=response,
                latency_ms=latency_ms,
                retry_count=1 if is_retry else 0,
            )
            self._probe_history.append(record)
            self._total_probes += 1
            if is_retry:
                self._total_retries += 1
            if latency_ms:
                if target not in self._rtt_windows:
                    self._rtt_windows[target] = deque(maxlen=self._rtt_window_size)
                self._rtt_windows[target].append(latency_ms)
    def should_retry(self, target: str, port: int) -> bool:
        with self._lock:
            retries = sum(
                1 for p in self._probe_history
                if p.target_ip == target and p.port == port
            )
            return retries < self.max_retries
    def check_rate_limit(self) -> bool:
        with self._lock:
            now = time.time()
            cutoff = now - self._rate_limit_window
            while self._rate_window and self._rate_window[0] < cutoff:
                self._rate_window.popleft()
            return len(self._rate_window) < self._rate_limit_max
    def record_send(self):
        with self._lock:
            self._rate_window.append(time.time())
    def time_until_next_allowed(self) -> float:
        with self._lock:
            if len(self._rate_window) < self._rate_limit_max:
                return 0.0
            oldest = self._rate_window[0]
            return max(0.0, oldest + self._rate_limit_window - time.time())
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = time.time() - self._session_start
            return {
                "elapsed_sec": round(float(elapsed), 1),
                "total_probes": self._total_probes,
                "total_retries": self._total_retries,
                "ports_scanned": len(self._port_states),
                "open_ports": sum(
                    1 for s in self._port_states.values() if s == "open"
                ),
                "unique_targets": len(self._rtt_windows),
                "probe_rate_per_min": round(
                    float(self._total_probes / max(elapsed / 60, 0.01)), 1
                ),
            }
    def export_state(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "port_states": {
                    f"{k[0]}:{k[1]}": v
                    for k, v in self._port_states.items()
                },
                "stats": self.stats,
                "probe_count": self._total_probes,
                "session_start": self._session_start,
            }

    def save_session(self, filepath: str = ".usare_session"):
        state = self.export_state()
        with open(filepath, "w") as f:
            json.dump(state, f, indent=2)

    def load_session(self, filepath: str = ".usare_session") -> bool:
        import os
        if not os.path.exists(filepath):
            return False
        try:
            with open(filepath, "r") as f:
                state = json.load(f)
            port_states = state.get("port_states", {})
            with self._lock:
                for key_str, val in port_states.items():
                    parts = key_str.rsplit(":", 1)
                    if len(parts) == 2:
                        target, port = parts[0], int(parts[1])
                        self._port_states[(target, port)] = val
                self._total_probes = state.get("probe_count", 0)
            return True
        except Exception:
            return False

    @staticmethod
    def clear_session(filepath: str = ".usare_session"):
        import os
        if os.path.exists(filepath):
            os.remove(filepath)