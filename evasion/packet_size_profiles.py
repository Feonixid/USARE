"""
Stochastic Packet Size Profiles for State-Level Evasion.

Samples payload sizes from real traffic histograms instead of fixed values.
Defeats IDS signatures that match on exact packet sizes and ML classifiers
trained on uniform scan traffic. Profiles derived from Chrome, Firefox,
and common enterprise traffic.
"""

import random
from typing import List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class SizeProfile(Enum):
    CHROME_TLS = "chrome_tls"
    FIREFOX_HTTP = "firefox_http"
    ENTERPRISE_MIX = "enterprise_mix"
    MINIMAL = "minimal"
    UNIFORM = "uniform"


@dataclass
class SizeHistogram:
    """Weighted (size, probability) pairs for sampling."""
    bins: List[Tuple[int, float]]
    min_size: int
    max_size: int


# Chrome 120 TLS record sizes (bytes) - real traffic capture
CHROME_TLS_BINS: List[Tuple[int, float]] = [
    (31, 0.08),
    (234, 0.12),
    (517, 0.25),
    (583, 0.10),
    (1460, 0.45),
]

# Firefox HTTP/1.1 request sizes
FIREFOX_HTTP_BINS: List[Tuple[int, float]] = [
    (200, 0.15),
    (400, 0.25),
    (600, 0.20),
    (800, 0.15),
    (1200, 0.15),
    (1460, 0.10),
]

# Enterprise: mix of RDP, SMB, HTTPS, DNS
ENTERPRISE_BINS: List[Tuple[int, float]] = [
    (64, 0.10),
    (128, 0.15),
    (256, 0.20),
    (512, 0.15),
    (1024, 0.20),
    (1460, 0.20),
]

PROFILES = {
    SizeProfile.CHROME_TLS: SizeHistogram(
        bins=CHROME_TLS_BINS,
        min_size=31,
        max_size=1500,
    ),
    SizeProfile.FIREFOX_HTTP: SizeHistogram(
        bins=FIREFOX_HTTP_BINS,
        min_size=200,
        max_size=1500,
    ),
    SizeProfile.ENTERPRISE_MIX: SizeHistogram(
        bins=ENTERPRISE_BINS,
        min_size=64,
        max_size=1500,
    ),
    SizeProfile.MINIMAL: SizeHistogram(
        bins=[(0, 0.5), (1, 0.3), (8, 0.2)],
        min_size=0,
        max_size=16,
    ),
}


def get_profile(name: str) -> SizeProfile:
    """Convert a string name to a SizeProfile, defaulting to CHROME_TLS on error."""
    try:
        return SizeProfile(name.lower())
    except ValueError:
        return SizeProfile.CHROME_TLS


def sample_payload_size(
    profile: "SizeProfile | str" = SizeProfile.CHROME_TLS,
    rng: Optional[random.Random] = None,
) -> int:
    """
    Sample a payload size from the profile histogram.
    Returns size in bytes, with small jitter applied.

    ``profile`` may be a SizeProfile enum value or a string name such as
    ``"chrome_tls"``.  Unknown string values fall back to CHROME_TLS rather
    than raising ValueError.
    """
    rng = rng or random.SystemRandom()

    # Normalise string → enum safely (was previously a bare SizeProfile(profile)
    # cast that would raise ValueError on unknown strings).
    if isinstance(profile, str):
        profile = get_profile(profile)

    if profile == SizeProfile.UNIFORM:
        return rng.randint(32, 1460)

    hist = PROFILES.get(profile)
    if not hist:
        return rng.randint(32, 1460)

    total = sum(w for _, w in hist.bins)
    r = rng.random() * total
    cumulative = 0.0
    for size, weight in hist.bins:
        cumulative += weight
        if r <= cumulative:
            jitter = rng.randint(-16, 16)
            return max(hist.min_size, min(hist.max_size, size + jitter))

    size, _ = hist.bins[-1]
    return max(hist.min_size, min(hist.max_size, size + rng.randint(-8, 8)))
