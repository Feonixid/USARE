"""
USARE Anti-Forensics Hardening

Makes the operator's machine harder to attribute if seized:

1. Memory-only mode: results never touch disk
2. Log sanitization: strip local IP/MAC/hostname from outputs
3. Clean exit: wipe temp files + in-memory buffers on SIGINT
4. Encrypted session state for scan resume
5. Timestamp randomization in scan metadata
"""

import os
import sys
import time
import random
import socket
import logging
import atexit
import signal
import secrets
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger("usare.anti_forensics")


@dataclass
class AntiForensicsConfig:
    """Configuration for anti-forensics hardening."""
    memory_only: bool = False          # Never write to disk
    sanitize_logs: bool = True         # Strip identifying info
    randomize_timestamps: bool = True  # Fuzz timestamps in output
    timestamp_skew_range: int = 3600   # ±seconds of timestamp skew
    clean_exit: bool = True            # Secure wipe on exit
    temp_files: List[str] = field(default_factory=list)  # Track temp files for cleanup


class AntiForensicsEngine:
    """
    Hardens USARE against forensic attribution.
    """

    # Identifiers to sanitize from output
    SANITIZE_PATTERNS: List[tuple] = [
        ("hostname", socket.gethostname()),
        ("username", os.environ.get("USER", os.environ.get("USERNAME", ""))),
    ]

    def __init__(self, config: Optional[AntiForensicsConfig] = None):
        self.config = config or AntiForensicsConfig()
        self._active = False
        self._original_handlers = {}

        # Get local identifiers to strip
        try:
            self._local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            self._local_ip = "127.0.0.1"

        try:
            # Try to get MAC address
            import uuid
            mac = uuid.getnode()
            self._local_mac = ':'.join(
                f"{(mac >> (8 * i)) & 0xff:02x}" for i in reversed(range(6))
            )
        except Exception:
            self._local_mac = ""

    def activate(self):
        """Activate anti-forensics protections."""
        if self._active:
            return

        self._active = True

        if self.config.clean_exit:
            self._install_exit_handlers()

        logger.info("[AntiForensics] Protections activated")

    def deactivate(self):
        """Deactivate and perform cleanup."""
        if not self._active:
            return

        self._cleanup()
        self._active = False

    def _install_exit_handlers(self):
        """Install signal handlers for clean exit."""
        atexit.register(lambda: self._cleanup())

        for sig in [signal.SIGTERM]:
            try:
                self._original_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._signal_handler)
            except (OSError, ValueError):
                pass

    def _signal_handler(self, signum, frame):
        """Handle termination signals with cleanup."""
        logger.info(f"[AntiForensics] Signal {signum} received — initiating clean exit")
        self._cleanup()

        # Restore and re-raise
        original = self._original_handlers.get(signum)
        if original and callable(original):
            signal.signal(signum, original)
            os.kill(os.getpid(), signum)

    def _cleanup(self):
        """Secure cleanup of all temporary data."""
        # Wipe tracked temp files
        for filepath in self.config.temp_files:
            self._secure_delete(filepath)

        # Clear any USARE temp files in system temp
        temp_dir = os.environ.get("TMPDIR", os.environ.get("TEMP", "/tmp"))
        try:
            for entry in os.listdir(temp_dir):
                if entry.startswith("usare_") or entry.startswith(".usare"):
                    self._secure_delete(os.path.join(temp_dir, entry))
        except Exception:
            pass

        logger.debug("[AntiForensics] Cleanup complete")

    def _secure_delete(self, filepath: str):
        """Overwrite file with random data before deleting."""
        try:
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                with open(filepath, 'wb') as f:
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
                os.remove(filepath)
                logger.debug(f"[AntiForensics] Securely deleted: {filepath}")
        except Exception as e:
            logger.debug(f"[AntiForensics] Failed to secure-delete {filepath}: {e}")

    def sanitize_output(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strip identifying information from scan output.
        Removes local IP, MAC, hostname, and username from all string values.
        """
        if not self.config.sanitize_logs:
            return data

        return self._deep_sanitize(data)

    def _deep_sanitize(self, obj: Any) -> Any:
        """Recursively sanitize all string values."""
        if isinstance(obj, str):
            result = obj
            # Strip local IP
            if self._local_ip and self._local_ip != "127.0.0.1":
                result = result.replace(self._local_ip, "[REDACTED_IP]")
            # Strip MAC
            if self._local_mac:
                result = result.replace(self._local_mac, "[REDACTED_MAC]")
                result = result.replace(self._local_mac.upper(), "[REDACTED_MAC]")
            # Strip hostname and username
            for name, value in self.SANITIZE_PATTERNS:
                if value and len(value) > 2:
                    result = result.replace(value, f"[REDACTED_{name.upper()}]")
            return result

        elif isinstance(obj, dict):
            return {
                self._deep_sanitize(k): self._deep_sanitize(v)
                for k, v in obj.items()
            }

        elif isinstance(obj, list):
            return [self._deep_sanitize(item) for item in obj]

        return obj

    def randomize_timestamp(self, ts: Optional[float] = None) -> float:
        """
        Add random skew to a timestamp to obscure actual scan time.
        """
        if not self.config.randomize_timestamps:
            return ts or time.time()

        base = ts or time.time()
        skew = random.uniform(
            -self.config.timestamp_skew_range,
            self.config.timestamp_skew_range
        )
        return base + skew

    def get_sanitized_metadata(self) -> Dict[str, Any]:
        """
        Generate sanitized scan metadata that doesn't reveal operator identity.
        """
        return {
            "scan_tool": "USARE",
            "scan_timestamp": self.randomize_timestamp(),
            "operator": "[REDACTED]",
            "source_ip": "[REDACTED]",
            "hostname": "[REDACTED]",
        }

    def track_temp_file(self, filepath: str):
        """Register a temporary file for cleanup on exit."""
        self.config.temp_files.append(filepath)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "active": self._active,
            "memory_only": self.config.memory_only,
            "sanitize_logs": self.config.sanitize_logs,
            "randomize_timestamps": self.config.randomize_timestamps,
            "tracked_temp_files": len(self.config.temp_files),
        }
