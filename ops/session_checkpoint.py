"""
USARE Encrypted Scan Session Checkpointing

Saves and restores scan progress using AES-256-GCM encryption so that:
  1. Interrupted scans can resume without re-probing already-tested ports
  2. Session files on disk are encrypted and non-attributable
  3. SIGINT / network drops don't lose hours of slow ghost-scan progress

Uses the existing ops/encryption module for AES-GCM operations.
"""

import os
import time
import json
import logging
import secrets
from typing import Dict, Any, Optional, Set, List
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("usare.session_checkpoint")


@dataclass
class ScanCheckpoint:
    """Serializable scan state for checkpoint/resume."""
    target: str
    ports_probed: List[int] = field(default_factory=list)
    ports_open: List[int] = field(default_factory=list)
    ports_closed: List[int] = field(default_factory=list)
    ports_filtered: List[int] = field(default_factory=list)
    banners: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: Dict[str, Any] = field(default_factory=dict)
    heat_level: float = 0.0
    packets_sent: int = 0
    scan_start_time: float = 0.0
    last_checkpoint_time: float = 0.0
    scan_config: Dict[str, Any] = field(default_factory=dict)
    version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanCheckpoint":
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


class SessionCheckpointer:
    """
    Manages encrypted scan session checkpoints for scan resume capability.

    Usage:
        # Save during scan
        cp = SessionCheckpointer("target_scan.usare_session")
        cp.save(checkpoint_data)

        # Resume later
        cp = SessionCheckpointer("target_scan.usare_session")
        state = cp.load()
    """

    DEFAULT_PASSWORD_ENV = "USARE_SESSION_KEY"
    CHECKPOINT_INTERVAL = 50  # Save every N ports probed

    def __init__(
        self,
        filepath: str = ".usare_session",
        password: Optional[str] = None,
        auto_interval: int = 50,
    ):
        self.filepath = filepath
        self.auto_interval = auto_interval
        self._ports_since_checkpoint = 0

        # Password from explicit arg, env var, or auto-generated
        if password:
            self._password = password
        elif os.environ.get(self.DEFAULT_PASSWORD_ENV):
            self._password = os.environ[self.DEFAULT_PASSWORD_ENV]
        else:
            self._password = secrets.token_hex(32)
            logger.info(
                f"[Session] Auto-generated session key. "
                f"Set {self.DEFAULT_PASSWORD_ENV} env var to specify your own."
            )

    def save(self, checkpoint: ScanCheckpoint) -> str:
        """Save scan checkpoint to encrypted file."""
        from ops.encryption import save_encrypted

        checkpoint.last_checkpoint_time = time.time()
        data = checkpoint.to_dict()

        path = save_encrypted(data, self._password, self.filepath)
        self._ports_since_checkpoint = 0

        logger.info(
            f"[Session] Checkpoint saved: {len(checkpoint.ports_probed)} ports probed, "
            f"{len(checkpoint.ports_open)} open → {path}"
        )
        return path

    def load(self) -> Optional[ScanCheckpoint]:
        """Load scan checkpoint from encrypted file."""
        if not os.path.exists(self.filepath):
            logger.debug(f"[Session] No checkpoint file found at {self.filepath}")
            return None

        try:
            from ops.encryption import load_encrypted
            data = load_encrypted(self.filepath, self._password)
            checkpoint = ScanCheckpoint.from_dict(data)

            logger.info(
                f"[Session] Checkpoint restored: {len(checkpoint.ports_probed)} ports already probed, "
                f"{len(checkpoint.ports_open)} open, "
                f"last saved {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(checkpoint.last_checkpoint_time))}"
            )
            return checkpoint

        except Exception as e:
            logger.warning(f"[Session] Failed to restore checkpoint: {e}")
            return None

    def should_checkpoint(self) -> bool:
        """Check if we should save a checkpoint based on port count."""
        self._ports_since_checkpoint += 1
        return self._ports_since_checkpoint >= self.auto_interval

    def record_port(self, checkpoint: ScanCheckpoint) -> Optional[str]:
        """
        Record that a port was probed. Auto-saves if interval is reached.
        Returns filepath if checkpoint was saved, None otherwise.
        """
        if self.should_checkpoint():
            return self.save(checkpoint)
        return None

    def cleanup(self):
        """Remove session file after scan completes successfully."""
        if os.path.exists(self.filepath):
            try:
                os.remove(self.filepath)
                logger.debug(f"[Session] Checkpoint file removed: {self.filepath}")
            except OSError as e:
                logger.warning(f"[Session] Could not remove checkpoint: {e}")

    def get_remaining_ports(
        self,
        checkpoint: ScanCheckpoint,
        all_ports: List[int],
    ) -> List[int]:
        """
        Given a checkpoint and the full port list, return only the ports
        that haven't been probed yet.
        """
        probed = set(checkpoint.ports_probed)
        remaining = [p for p in all_ports if p not in probed]
        logger.info(
            f"[Session] Resume: {len(probed)} already probed, "
            f"{len(remaining)} remaining out of {len(all_ports)} total"
        )
        return remaining
