"""
Gap 1 — Flow Behavioral Mimicry (Traffic Morphing)

Wraps probes inside flows that statistically match real browser traffic.
Based on Wright et al. traffic morphing concepts with kernel density
estimation for realistic inter-packet timing distributions.

IMPORTANT NOTE: This module works best with --ebpf enabled.

Without eBPF filtering, the cover traffic (SYN/ACK packets) will generate
RST responses from the target kernel when it receives unexpected SYN-ACKs.
These RSTs can appear as scan artifacts and may trigger detection.

The eBPF filter (when --ebpf is active) handles this at the kernel level
by dropping the problematic RST packets before they reach the network stack.

For optimal stealth, use: --flow-morph --ebpf
"""

import random
import time
import math
import threading
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Callable
from enum import Enum
from scapy.all import IP, TCP, Raw, send, conf


class FlowType(Enum):
    CHROME_HTTPS = "chrome_https"
    FIREFOX_HTTP = "firefox_http"
    CURL_GET = "curl_get"
    WINDOWS_UPDATE = "windows_update"


@dataclass
class FlowProfile:
    """Captures the statistical shape of a real application flow."""
    name: str
    packet_count_range: tuple = (8, 25)
    request_sizes: List[int] = field(default_factory=lambda: [517, 234, 1460, 583])
    response_sizes: List[int] = field(default_factory=lambda: [1460, 1460, 1460, 583, 234])
    inter_packet_mean_ms: float = 45.0
    inter_packet_std_ms: float = 18.0
    flow_duration_range: tuple = (0.3, 2.5)
    request_response_ratio: float = 0.35
    initial_window: int = 65535
    mss: int = 1460
    ttl: int = 128
    byte_size_histogram: List[Tuple[int, float]] = field(default_factory=list)
    timing_samples_ms: List[float] = field(default_factory=list)


# TLS 1.3 ClientHello template (first 64 bytes matching Chrome 120)
_TLS_CLIENT_HELLO_PREFIX = bytes([
    0x16, 0x03, 0x01,  # TLS record: handshake, version 3.1
    0x02, 0x00,        # length placeholder
    0x01,              # handshake type: ClientHello
    0x00, 0x01, 0xfc,  # handshake length
    0x03, 0x03,        # TLS 1.2 (actual 1.3 via extension)
]) + bytes(32)          # random bytes (will be randomized)


PROFILES: Dict[FlowType, FlowProfile] = {
    FlowType.CHROME_HTTPS: FlowProfile(
        name="Chrome 120 TLS 1.3",
        packet_count_range=(12, 30),
        request_sizes=[517, 31, 1460, 583, 234, 31, 517],
        response_sizes=[1460, 1460, 1460, 1460, 583, 234, 1460, 1460],
        inter_packet_mean_ms=35.0,
        inter_packet_std_ms=22.0,
        flow_duration_range=(0.4, 3.0),
        request_response_ratio=0.32,
        initial_window=65535,
        mss=1460,
        ttl=128,
        byte_size_histogram=[
            (31, 0.08), (234, 0.12), (517, 0.25),
            (583, 0.10), (1460, 0.45),
        ],
        timing_samples_ms=[
            12.3, 15.7, 18.2, 22.1, 25.4, 28.9, 31.3, 35.0,
            38.6, 42.1, 45.5, 50.2, 55.8, 62.3, 78.4, 95.1,
            110.5, 145.2, 200.8,
        ],
    ),
    FlowType.FIREFOX_HTTP: FlowProfile(
        name="Firefox 122 HTTP/1.1",
        packet_count_range=(8, 20),
        request_sizes=[400, 234, 800, 450],
        response_sizes=[1460, 1460, 800, 1460, 234],
        inter_packet_mean_ms=50.0,
        inter_packet_std_ms=25.0,
        flow_duration_range=(0.3, 2.0),
        request_response_ratio=0.38,
        initial_window=65535,
        mss=1460,
        ttl=64,
        byte_size_histogram=[
            (234, 0.15), (400, 0.20), (450, 0.10),
            (800, 0.15), (1460, 0.40),
        ],
        timing_samples_ms=[
            18.5, 22.0, 30.1, 38.4, 45.2, 52.7, 60.3, 72.1,
            85.4, 100.2, 120.5, 150.8,
        ],
    ),
    FlowType.CURL_GET: FlowProfile(
        name="curl/8.4 GET",
        packet_count_range=(6, 12),
        request_sizes=[234, 517],
        response_sizes=[1460, 1460, 583],
        inter_packet_mean_ms=20.0,
        inter_packet_std_ms=8.0,
        flow_duration_range=(0.1, 0.8),
        request_response_ratio=0.40,
        initial_window=65535,
        mss=1460,
        ttl=64,
        byte_size_histogram=[
            (234, 0.30), (517, 0.20), (583, 0.10), (1460, 0.40),
        ],
        timing_samples_ms=[
            5.2, 8.1, 10.5, 12.3, 15.0, 18.2, 22.4, 28.7,
        ],
    ),
    FlowType.WINDOWS_UPDATE: FlowProfile(
        name="Windows Update Client",
        packet_count_range=(15, 50),
        request_sizes=[517, 234, 1460, 1460, 1460],
        response_sizes=[1460, 1460, 1460, 1460, 1460, 1460, 1460, 583],
        inter_packet_mean_ms=25.0,
        inter_packet_std_ms=12.0,
        flow_duration_range=(1.0, 8.0),
        request_response_ratio=0.20,
        initial_window=65535,
        mss=1460,
        ttl=128,
        byte_size_histogram=[
            (234, 0.05), (517, 0.10), (583, 0.05), (1460, 0.80),
        ],
        timing_samples_ms=[
            8.0, 12.5, 15.3, 18.0, 20.1, 22.8, 25.0, 28.3,
            32.5, 38.0, 45.2,
        ],
    ),
}

FLOW_TYPE_MAP: Dict[str, FlowType] = {
    "chrome": FlowType.CHROME_HTTPS,
    "firefox": FlowType.FIREFOX_HTTP,
    "curl": FlowType.CURL_GET,
    "winupdate": FlowType.WINDOWS_UPDATE,
}


class KDESampler:
    """Kernel Density Estimation sampler for realistic delay distributions.
    
    Uses a Gaussian kernel over empirical timing samples to produce
    delays that follow the observed distribution rather than a single
    normal distribution.
    """

    def __init__(self, samples: List[float], bandwidth: Optional[float] = None):
        self._samples = samples if samples else [30.0, 45.0, 60.0]
        n = len(self._samples)
        if bandwidth is not None:
            self._bandwidth = bandwidth
        else:
            # Silverman's rule of thumb
            std = self._std(self._samples)
            self._bandwidth = max(1.0, 1.06 * std * (n ** -0.2))
        self._rng = random.SystemRandom()

    @staticmethod
    def _std(data: List[float]) -> float:
        n = len(data)
        if n < 2:
            return 1.0
        mean = sum(data) / n
        variance = sum((x - mean) ** 2 for x in data) / (n - 1)
        return max(0.001, math.sqrt(variance))

    def sample(self) -> float:
        """Draw one sample from the KDE distribution."""
        center = self._rng.choice(self._samples)
        return max(1.0, self._rng.gauss(center, self._bandwidth))

    def sample_seconds(self) -> float:
        """Draw one delay sample converted to seconds."""
        return self.sample() / 1000.0


@dataclass
class FlowState:
    """Tracks per-flow TCP state so each connection looks complete."""
    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    packets_sent: int = 0
    bytes_sent: int = 0
    phase: str = "handshake"  # handshake → data → teardown

    def advance_seq(self, payload_len: int):
        self.seq = (self.seq + payload_len) & 0xFFFFFFFF
        self.packets_sent += 1
        self.bytes_sent += payload_len

    def advance_ack(self, payload_len: int):
        self.ack = (self.ack + payload_len) & 0xFFFFFFFF


class FlowShaper:
    """Orchestrates wrapping probes inside realistic flow envelopes."""

    def __init__(
        self,
        profile: FlowType = FlowType.CHROME_HTTPS,
        entropy_profile: Optional[str] = None,
    ):
        self.profile = PROFILES[profile]
        self._entropy_profile = entropy_profile  # e.g. chrome_tls — balances cover payload entropy
        self._rng = random.SystemRandom()
        self._flows_shaped = 0
        self._kde = KDESampler(
            self.profile.timing_samples_ms
            if self.profile.timing_samples_ms
            else None
        )
        self._active_flows: Dict[Tuple[str, int], FlowState] = {}

    def _sample_delay(self) -> float:
        """Sample inter-packet delay using KDE when available."""
        if self.profile.timing_samples_ms:
            return max(0.005, min(0.5, self._kde.sample_seconds()))
        delay = self._rng.gauss(
            self.profile.inter_packet_mean_ms / 1000.0,
            self.profile.inter_packet_std_ms / 1000.0,
        )
        return max(0.005, min(0.5, delay))

    def _sample_size(self, is_request: bool) -> int:
        """Sample packet size from byte-size histogram or pool."""
        if self.profile.byte_size_histogram:
            return self._sample_from_histogram()
        pool = self.profile.request_sizes if is_request else self.profile.response_sizes
        base = self._rng.choice(pool)
        jitter = self._rng.randint(-16, 16)
        return max(1, base + jitter)

    def _sample_from_histogram(self) -> int:
        """Weighted random selection from byte-size histogram."""
        hist = self.profile.byte_size_histogram
        total = sum(w for _, w in hist)
        r = self._rng.random() * total
        cumulative = 0.0
        for size, weight in hist:
            cumulative += weight
            if r <= cumulative:
                jitter = self._rng.randint(-8, 8)
                return max(1, size + jitter)
        return hist[-1][0]

    def _get_flow_state(self, target_ip: str, target_port: int, src_port: int) -> FlowState:
        """Get or create per-flow TCP state."""
        key = (target_ip, src_port)
        if key not in self._active_flows:
            self._active_flows[key] = FlowState(
                src_port=src_port,
                dst_port=target_port,
                seq=self._rng.randint(1000000, 4000000000),
                ack=self._rng.randint(1000000, 4000000000),
                phase="handshake",
            )
        return self._active_flows[key]

    def _maybe_balance_entropy(self, raw: bytes) -> bytes:
        """Match approximate Shannon entropy to a traffic profile (evades ML payload classifiers)."""
        if not self._entropy_profile or not raw:
            return raw
        try:
            from evasion.entropy_balancer import get_entropy_balancer, TrafficType  # lazy import

            b = get_entropy_balancer()
            tt = TrafficType(self._entropy_profile.lower())
            prof = b.profiles[tt]
            # Same-length replacement (balance_entropy() only appends when growing)
            return b.padder.generate_padding(prof.target_entropy_bits, len(raw))
        except Exception:
            return raw

    def _build_tls_cover_payload(self, size: int) -> bytes:
        """Build a TLS-like payload for DPI evasion on HTTPS flows."""
        if size < len(_TLS_CLIENT_HELLO_PREFIX):
            return self._maybe_balance_entropy(random.randbytes(size))
        payload = bytearray(_TLS_CLIENT_HELLO_PREFIX[:min(size, 43)])
        # Randomize the 32-byte random field
        payload[11:43] = random.randbytes(min(32, max(0, size - 11)))
        if size > 43:
            tail = random.randbytes(size - 43)
            payload.extend(self._maybe_balance_entropy(tail))
        return bytes(payload[:size])

    def generate_cover_before(self, target_ip: str, target_port: int, src_port: int) -> List[tuple]:
        """Generate pre-probe cover packets with proper TCP state."""
        cover = []
        flow = self._get_flow_state(target_ip, target_port, src_port)
        n_before = self._rng.randint(2, 5)

        # SYN (3-way handshake start)
        if flow.phase == "handshake":
            syn_pkt = IP(dst=target_ip, ttl=self.profile.ttl) / TCP(
                sport=src_port, dport=target_port,
                flags="S", seq=flow.seq,
                window=self.profile.initial_window,
                options=[("MSS", self.profile.mss), ("SAckOK", b""), ("NOP", None), ("WScale", 7)],
            )
            cover.append((syn_pkt, self._sample_delay()))
            flow.advance_seq(1)

            # SYN-ACK simulation (we send ACK to complete handshake)
            ack_pkt = IP(dst=target_ip, ttl=self.profile.ttl) / TCP(
                sport=src_port, dport=target_port,
                flags="A", seq=flow.seq, ack=flow.ack,
                window=self.profile.initial_window,
            )
            cover.append((ack_pkt, self._sample_delay()))
            flow.phase = "data"

        # Data packets
        for i in range(n_before):
            is_req = self._rng.random() < self.profile.request_response_ratio
            size = self._sample_size(is_req)
            delay = self._sample_delay()

            # Use TLS-like payload for HTTPS profiles
            if target_port in (443, 8443) or self.profile.name.startswith("Chrome"):
                payload = self._build_tls_cover_payload(size)
            else:
                payload = self._maybe_balance_entropy(random.randbytes(size))

            pkt = IP(dst=target_ip, ttl=self.profile.ttl) / TCP(
                sport=src_port, dport=target_port,
                flags="PA", seq=flow.seq, ack=flow.ack,
                window=self.profile.initial_window,
            ) / Raw(load=payload)
            flow.advance_seq(size)
            cover.append((pkt, delay))

        return cover

    def generate_cover_after(self, target_ip: str, target_port: int, src_port: int) -> List[tuple]:
        """Generate post-probe cover packets with proper FIN/ACK teardown."""
        cover = []
        flow = self._get_flow_state(target_ip, target_port, src_port)
        n_after = self._rng.randint(1, 4)

        for i in range(n_after):
            is_req = self._rng.random() < (1.0 - self.profile.request_response_ratio)
            size = self._sample_size(is_req)
            delay = self._sample_delay()

            if target_port in (443, 8443):
                payload = self._build_tls_cover_payload(size)
            else:
                payload = self._maybe_balance_entropy(random.randbytes(size))

            pkt = IP(dst=target_ip, ttl=self.profile.ttl) / TCP(
                sport=src_port, dport=target_port,
                flags="PA", seq=flow.seq, ack=flow.ack,
                window=self.profile.initial_window,
            ) / Raw(load=payload)
            flow.advance_seq(size)
            cover.append((pkt, delay))

        # FIN-ACK teardown (matches real browser close)
        fin_pkt = IP(dst=target_ip, ttl=self.profile.ttl) / TCP(
            sport=src_port, dport=target_port,
            flags="FA", seq=flow.seq, ack=flow.ack,
            window=self.profile.initial_window,
        )
        cover.append((fin_pkt, self._sample_delay()))
        flow.advance_seq(1)
        flow.phase = "teardown"

        # Final ACK
        last_ack = IP(dst=target_ip, ttl=self.profile.ttl) / TCP(
            sport=src_port, dport=target_port,
            flags="A", seq=flow.seq, ack=(flow.ack + 1) & 0xFFFFFFFF,
            window=self.profile.initial_window,
        )
        cover.append((last_ack, self._sample_delay()))

        # Clean up flow state
        key = (target_ip, src_port)
        self._active_flows.pop(key, None)

        return cover

    def wrap_probe(self, probe_pkt, target_ip: str, target_port: int, src_port: int) -> List[tuple]:
        """Wrap a probe packet inside a full flow envelope."""
        shaped_flow = []
        shaped_flow.extend(self.generate_cover_before(target_ip, target_port, src_port))
        shaped_flow.append((probe_pkt, self._sample_delay()))
        shaped_flow.extend(self.generate_cover_after(target_ip, target_port, src_port))
        self._flows_shaped += 1
        return shaped_flow

    def send_shaped_flow(self, flow_packets: List[tuple], interface: Optional[str] = None):
        """Send all packets in a shaped flow with proper timing."""
        for pkt, delay in flow_packets:
            time.sleep(delay)
            try:
                send(pkt, iface=interface, verbose=0)
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        return {
            "profile": self.profile.name,
            "flows_shaped": self._flows_shaped,
            "active_flows": len(self._active_flows),
            "kde_bandwidth": self._kde._bandwidth if self._kde else None,
        }


class BrowserFlowMorpher:
    """High-level interface for flow morphing with background noise."""

    def __init__(self, flow_type: FlowType = FlowType.CHROME_HTTPS):
        self.shaper = FlowShaper(flow_type)
        self._active = False
        self._background_thread: Optional[threading.Thread] = None

    def morph_and_send(self, probe_pkt, target_ip: str, target_port: int,
                       src_port: int, interface: Optional[str] = None):
        """Morph a single probe and send it within a flow envelope."""
        flow = self.shaper.wrap_probe(probe_pkt, target_ip, target_port, src_port)
        self.shaper.send_shaped_flow(flow, interface)

    def start_background_noise(self, target_ip: str, ports: List[int],
                               interface: Optional[str] = None, interval: float = 5.0):
        """Start background cover traffic generation."""
        self._active = True

        def _noise_loop():
            rng = random.SystemRandom()
            while self._active:
                port = rng.choice(ports)
                src_port = rng.randint(49152, 65535)
                cover = self.shaper.generate_cover_before(target_ip, port, src_port)
                cover.extend(self.shaper.generate_cover_after(target_ip, port, src_port))
                self.shaper.send_shaped_flow(cover, interface)
                time.sleep(interval + rng.uniform(-2, 2))

        self._background_thread = threading.Thread(target=_noise_loop, daemon=True)
        self._background_thread.start()

    def stop_background_noise(self):
        """Stop background cover traffic."""
        self._active = False
        if self._background_thread:
            self._background_thread.join(timeout=5)
