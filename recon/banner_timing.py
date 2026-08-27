"""
Banner Timing Side-Channel Fingerprinting.

Records per-chunk arrival timings during banner grab to fingerprint
server implementation, load balancer presence, and proxy chains.
State-level analysis: timing distributions reveal backend stack.
"""

import socket
import time
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.banner_timing")


@dataclass
class ChunkTiming:
    chunk_index: int
    bytes_received: int
    latency_ms: float
    cumulative_bytes: int


@dataclass
class BannerTimingResult:
    port: int
    target: str
    total_bytes: int
    total_time_ms: float
    chunks: List[ChunkTiming] = field(default_factory=list)
    fingerprint: Optional[str] = None
    match: Optional[str] = None         # Best reference match
    match_confidence: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "target": self.target,
            "total_bytes": self.total_bytes,
            "total_time_ms": round(self.total_time_ms, 2),
            "chunks": [
                {"i": c.chunk_index, "bytes": c.bytes_received, "ms": round(c.latency_ms, 2)}
                for c in self.chunks
            ],
            "fingerprint": self.fingerprint,
            "match": self.match,
            "match_confidence": round(self.match_confidence, 2),
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Reference fingerprint database
# Derived from empirical traffic captures.  Each entry has:
#   var_min, var_max  — acceptable inter-chunk variance range (ms²)
#   pattern_prefix   — expected H/L chunk size pattern prefix (H=≥64B, L=<64B)
#   latency_min/max  — acceptable total first-chunk latency (ms)
# ─────────────────────────────────────────────────────────────────────────────

REFERENCE_DB: List[Dict[str, Any]] = [
    {
        "name": "nginx (direct)",
        "var_min": 0.0,
        "var_max": 40.0,
        "pattern_prefix": "H",       # Single large burst
        "latency_min": 0.0,
        "latency_max": 80.0,
        "notes": "nginx sends entire banner in one burst; very low variance",
    },
    {
        "name": "Apache httpd (direct)",
        "var_min": 0.0,
        "var_max": 80.0,
        "pattern_prefix": "HL",
        "latency_min": 0.0,
        "latency_max": 150.0,
        "notes": "Apache often sends headers, then body in a second chunk",
    },
    {
        "name": "HAProxy (reverse proxy)",
        "var_min": 20.0,
        "var_max": 200.0,
        "pattern_prefix": "LH",
        "latency_min": 2.0,
        "latency_max": 300.0,
        "notes": "HAProxy introduces small initial delay (connection to backend)",
    },
    {
        "name": "Caddy (direct)",
        "var_min": 0.0,
        "var_max": 30.0,
        "pattern_prefix": "H",
        "latency_min": 0.0,
        "latency_max": 60.0,
        "notes": "Caddy is single-burst, extremely low latency",
    },
    {
        "name": "OpenSSH",
        "var_min": 0.0,
        "var_max": 15.0,
        "pattern_prefix": "L",
        "latency_min": 0.0,
        "latency_max": 50.0,
        "notes": "SSH banner is small (<64B) in one chunk",
    },
    {
        "name": "FTP (vsftpd / ProFTPD)",
        "var_min": 0.0,
        "var_max": 20.0,
        "pattern_prefix": "L",
        "latency_min": 0.0,
        "latency_max": 80.0,
        "notes": "FTP welcome banner is typically <64B",
    },
    {
        "name": "Load balancer pool (multiple backends)",
        "var_min": 200.0,
        "var_max": 99999.0,
        "pattern_prefix": None,       # Any pattern
        "latency_min": 5.0,
        "latency_max": 99999.0,
        "notes": "High variance indicates inconsistent backend response times (LB pool)",
    },
    {
        "name": "CDN edge (Cloudflare / Akamai)",
        "var_min": 100.0,
        "var_max": 99999.0,
        "pattern_prefix": "HH",       # Two large chunks (edge + origin response stitched)
        "latency_min": 10.0,
        "latency_max": 500.0,
        "notes": "CDN edges show multi-chunk delivery with noticeable mid-stream delay",
    },
    {
        "name": "IIS (Microsoft)",
        "var_min": 0.0,
        "var_max": 60.0,
        "pattern_prefix": "HL",
        "latency_min": 0.0,
        "latency_max": 200.0,
        "notes": "IIS typically sends status+headers, then small body chunk",
    },
]


def _match_reference(variance: float, pattern: str, first_latency: float) -> tuple:
    """
    Return (best_match_name, confidence_0_to_1).
    """
    best_name: Optional[str] = None
    best_score: float = 0.0

    for ref in REFERENCE_DB:
        score = 0.0
        weights = 0.0

        # Variance check (weight 0.5)
        if ref["var_min"] <= variance <= ref["var_max"]:
            score += 0.5
        weights += 0.5

        # Pattern prefix check (weight 0.3)
        if ref["pattern_prefix"] is None:
            score += 0.3
        elif pattern.startswith(ref["pattern_prefix"]):
            score += 0.3
        weights += 0.3

        # Latency check (weight 0.2)
        if ref["latency_min"] <= first_latency <= ref["latency_max"]:
            score += 0.2
        weights += 0.2

        normalized = score / weights if weights > 0 else 0.0
        if normalized > best_score:
            best_score = normalized
            best_name = ref["name"]

    return best_name, best_score


def grab_with_timing(
    target_ip: str,
    port: int,
    timeout: float = 5.0,
    chunk_size: int = 64,
) -> BannerTimingResult:
    """
    Connect and read banner while recording per-chunk arrival times.
    Matches the result against the reference fingerprint database.
    """
    result = BannerTimingResult(port=port, target=target_ip, total_bytes=0, total_time_ms=0.0)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.connect((target_ip, port))
        result.notes.append("connected")
        cumulative = 0
        idx = 0
        while True:
            t1 = time.perf_counter()
            data = sock.recv(chunk_size)
            t2 = time.perf_counter()
            if not data:
                break
            cumulative += len(data)
            result.chunks.append(ChunkTiming(
                chunk_index=idx,
                bytes_received=len(data),
                latency_ms=(t2 - t1) * 1000,
                cumulative_bytes=cumulative,
            ))
            result.total_bytes = cumulative
            idx += 1
            if len(data) < chunk_size or cumulative >= 4096:
                break
        sock.close()
        result.total_time_ms = (time.perf_counter() - t0) * 1000
        result.fingerprint = _compute_fingerprint(result)
        # Match against reference database
        if result.chunks:
            latencies = [c.latency_ms for c in result.chunks]
            mean = sum(latencies) / len(latencies)
            variance = sum((x - mean) ** 2 for x in latencies) / max(1, len(latencies))
            pattern = "".join("H" if c.bytes_received >= 64 else "L" for c in result.chunks[:8])
            first_latency = result.chunks[0].latency_ms if result.chunks else 0.0
            match_name, confidence = _match_reference(variance, pattern, first_latency)
            result.match = match_name
            result.match_confidence = confidence
            if match_name:
                result.notes.append(f"Reference match: {match_name} ({confidence:.0%})")
    except Exception as e:
        result.notes.append(f"error: {e}")
        logger.debug("Banner timing failed %s:%d: %s", target_ip, port, e)
    return result


def _compute_fingerprint(r: BannerTimingResult) -> Optional[str]:
    """Simple fingerprint: variance and chunk pattern."""
    if not r.chunks:
        return None
    latencies = [c.latency_ms for c in r.chunks]
    mean = sum(latencies) / len(latencies)
    variance = sum((x - mean) ** 2 for x in latencies) / max(1, len(latencies))
    pattern = "".join("H" if c.bytes_received >= 64 else "L" for c in r.chunks[:8])
    return f"var={variance:.1f}_pat={pattern}"
