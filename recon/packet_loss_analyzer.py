"""
USARE Packet Loss Pattern Analyzer

Statistical analysis of dropped probe patterns to distinguish between:
  1. Real network loss (random, Poisson-distributed gaps)
  2. Firewall/IDS rate limiting (burst loss when rate threshold is exceeded)
  3. Systematic periodic filtering (fixed deterministic drop intervals)
"""

import statistics
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("usare.packet_loss")


@dataclass
class LossAnalysisResult:
    total_probes: int
    dropped_probes: int
    loss_rate: float
    classification: str  # "NO_LOSS", "RANDOM_NETWORK_LOSS", "SYSTEMATIC_FILTERING", "RATE_LIMITING_BURST"
    gap_variance: float
    details: str


class PacketLossAnalyzer:
    """
    Analyzes sequence indices of sent probes vs received responses
    to classify the nature of packet drops.
    """

    def __init__(self, high_loss_threshold: float = 0.30):
        self.high_loss_threshold = high_loss_threshold

    def analyze_loss_pattern(
        self,
        total_probes: int,
        received_indices: List[int],
    ) -> LossAnalysisResult:
        """
        Evaluate the sequence of delivered probes.
        `received_indices`: 0-indexed list of probe sequence numbers that received responses.
        """
        if total_probes <= 0:
            return LossAnalysisResult(
                total_probes=0,
                dropped_probes=0,
                loss_rate=0.0,
                classification="NO_LOSS",
                gap_variance=0.0,
                details="No probes recorded.",
            )

        recv_set = set(received_indices)
        dropped_indices = [i for i in range(total_probes) if i not in recv_set]
        dropped_count = len(dropped_indices)
        loss_rate = dropped_count / total_probes

        if dropped_count == 0:
            return LossAnalysisResult(
                total_probes=total_probes,
                dropped_probes=0,
                loss_rate=0.0,
                classification="NO_LOSS",
                gap_variance=0.0,
                details="100% probe delivery observed.",
            )

        # If only 1 dropped packet
        if dropped_count == 1:
            return LossAnalysisResult(
                total_probes=total_probes,
                dropped_probes=1,
                loss_rate=round(loss_rate, 3),
                classification="RANDOM_NETWORK_LOSS",
                gap_variance=0.0,
                details="Isolated single packet drop; consistent with random jitter.",
            )

        # Compute gaps between consecutive drop sequence numbers
        gaps = [
            dropped_indices[i + 1] - dropped_indices[i]
            for i in range(len(dropped_indices) - 1)
        ]
        gap_var = statistics.variance(gaps) if len(gaps) > 1 else 0.0

        # Classification logic
        if gap_var == 0.0 and gaps[0] > 1:
            # Deterministic periodic drop (e.g. exactly every Nth packet)
            classification = "SYSTEMATIC_FILTERING"
            details = f"Deterministic periodic packet drop detected (exact gap interval: {gaps[0]})."
        elif loss_rate >= self.high_loss_threshold:
            classification = "RATE_LIMITING_BURST"
            details = f"High-volume drop rate ({loss_rate:.1%}) indicates active rate limiting or ACL thresholding."
        elif gap_var >= 10.0 or dropped_count <= 4:
            classification = "RANDOM_NETWORK_LOSS"
            details = f"Random inter-drop gap variance ({gap_var:.1f}) matches natural network packet loss."
        else:
            classification = "SYSTEMATIC_FILTERING"
            details = f"Low inter-drop variance ({gap_var:.1f}) indicates systematic firewall drop policy."

        return LossAnalysisResult(
            total_probes=total_probes,
            dropped_probes=dropped_count,
            loss_rate=round(loss_rate, 3),
            classification=classification,
            gap_variance=round(gap_var, 2),
            details=details,
        )
