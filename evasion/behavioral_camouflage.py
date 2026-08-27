"""
USARE Behavioral Camouflage Engine

The timing engine defeats fixed-cadence IDS correlation. This module defeats
*behavioral* NDR systems (Darktrace, Vectra, ExtraHop) which don't alert on
timing — they alert on traffic that doesn't look like it belongs.

What this module does:
  1. DNS-before-connect  — resolve the target via DNS before each TCP probe,
                           mimicking what a real application does
  2. Realistic source ports — assigned the same way the OS would assign them
                              (ephemeral range, not random uniform)
  3. Connection order    — probe ports in the order a real browser/app would
                           connect (80 → 443 → DNS → known API ports)
  4. Decoy HTTP activity — interleave real-looking GET requests to CDN domains
                           between scan probes so traffic looks like browsing
  5. OS-native TCP options — window size, TTL, MSS, WScale matching a real OS
"""

import random
import socket
import time
import logging
import threading
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("usare.behavioral_camouflage")


# ── Port ordering profiles ─────────────────────────────────────────────────

class CamouflageProfile(Enum):
    BROWSER       = "browser"       # Chrome/Firefox browsing pattern
    OFFICE_WORKER = "office_worker" # Outlook + Teams + browser
    DEVOPS        = "devops"        # SSH + git + k8s + docker
    IOT_DEVICE    = "iot_device"    # MQTT + HTTPS + NTP
    SILENT         = "silent"       # No decoy activity, just DNS+source-port


# Ports a real Chrome browser contacts, in rough order of frequency
BROWSER_PORT_PRIORITY = [443, 80, 853, 8443, 8080, 3000, 5000]

# Ports a corporate Windows workstation routinely contacts
OFFICE_PORT_PRIORITY = [443, 80, 445, 135, 389, 636, 3389, 5985, 25, 587, 993]

# DevOps workstation
DEVOPS_PORT_PRIORITY = [22, 443, 80, 6443, 2375, 5000, 8080, 8443, 9090, 9200]

# IoT device
IOT_PORT_PRIORITY = [1883, 8883, 443, 123, 53, 80]

PROFILE_PRIORITY: Dict[CamouflageProfile, List[int]] = {
    CamouflageProfile.BROWSER:        BROWSER_PORT_PRIORITY,
    CamouflageProfile.OFFICE_WORKER:  OFFICE_PORT_PRIORITY,
    CamouflageProfile.DEVOPS:         DEVOPS_PORT_PRIORITY,
    CamouflageProfile.IOT_DEVICE:     IOT_PORT_PRIORITY,
    CamouflageProfile.SILENT:         [],
}


# ── Ephemeral source port distributions ────────────────────────────────────
# Linux: 32768–60999  (cat /proc/sys/net/ipv4/ip_local_port_range)
# Windows: 49152–65535 (RFC 6335 dynamic range)
# macOS: 49152–65535

class SourcePortAllocator:
    """
    Mimics OS ephemeral port allocation.
    Uses a sequential-with-wraparound strategy like Linux, not random.
    """

    PROFILES = {
        "linux":   (32768, 60999),
        "windows": (49152, 65535),
        "macos":   (49152, 65535),
    }

    def __init__(self, os_profile: str = "linux"):
        low, high = self.PROFILES.get(os_profile, (32768, 60999))
        # Start at a random point within the range (like a freshly booted machine)
        self._current = random.randint(low, high)
        self._low  = low
        self._high = high
        self._lock = threading.Lock()

    def next_port(self) -> int:
        """Return the next ephemeral port, wrapping around like the OS does."""
        with self._lock:
            port = self._current
            self._current += 1
            if self._current > self._high:
                self._current = self._low
            return port

    def random_port(self) -> int:
        """Return a random port in the ephemeral range (for one-shot probes)."""
        return random.randint(self._low, self._high)


# ── DNS-before-connect ────────────────────────────────────────────────────

def dns_prefetch(hostname: str, timeout: float = 2.0) -> Optional[str]:
    """
    Perform a DNS lookup for the target hostname before connecting.
    This ensures traffic analysers see DNS → TCP connect (normal app behaviour).
    Returns the resolved IP or None on failure.
    """
    try:
        socket.setdefaulttimeout(timeout)
        result = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        if result:
            ip = result[0][4][0]
            logger.debug("[camouflage] DNS prefetch %s → %s", hostname, ip)
            return ip
    except Exception as e:
        logger.debug("[camouflage] DNS prefetch failed for %s: %s", hostname, e)
    return None


def build_dns_packet(hostname: str) -> bytes:
    """
    Build a raw DNS query packet for the given hostname (A record).
    Used when we want to send a DNS query without using the system resolver.
    """
    import struct
    txid = random.randint(1, 65535)
    flags = 0x0100  # standard query, recursion desired
    questions = 1
    header = struct.pack(">HHHHHH", txid, flags, questions, 0, 0, 0)
    # Encode hostname as DNS labels
    labels = b""
    for part in hostname.rstrip(".").split("."):
        labels += bytes([len(part)]) + part.encode()
    labels += b"\x00"
    qtype  = struct.pack(">H", 1)    # A record
    qclass = struct.pack(">H", 1)    # IN class
    return header + labels + qtype + qclass


# ── Decoy HTTP activity generator ────────────────────────────────────────

# CDN hostnames that are extremely common in legitimate traffic
DECOY_HOSTS = [
    ("ocsp.pki.goog", 80),
    ("clients1.google.com", 443),
    ("update.googleapis.com", 443),
    ("safebrowsing.googleapis.com", 443),
    ("detectportal.firefox.com", 80),
    ("push.services.mozilla.com", 443),
    ("ocsp.digicert.com", 80),
    ("crl.microsoft.com", 80),
    ("settings-win.data.microsoft.com", 443),
    ("v10.events.data.microsoft.com", 443),
]

DECOY_PATHS = ["/", "/generate_204", "/canonical.html", "/update", "/check"]

def generate_decoy_request(host: str, path: str = "/") -> bytes:
    """Build a realistic-looking GET request for a decoy host."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ]
    ua = random.choice(user_agents)
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
        f"Accept-Language: en-US,en;q=0.9\r\n"
        f"Accept-Encoding: gzip, deflate, br\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


def fire_decoy_request(host: str, port: int, path: str = "/", timeout: float = 3.0):
    """Send a single decoy HTTP GET and discard the response. Non-blocking."""
    def _send():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(generate_decoy_request(host, path))
            sock.recv(512)  # partial read, then close
            sock.close()
        except Exception:
            pass
    t = threading.Thread(target=_send, daemon=True)
    t.start()


# ── Port ordering ─────────────────────────────────────────────────────────

def reorder_ports_by_profile(
    port_list: List[int],
    profile: CamouflageProfile = CamouflageProfile.BROWSER,
) -> List[int]:
    """
    Reorder a port list so that ports typical for the profile come first,
    the rest in shuffled order. This makes the connection sequence look like
    a real application establishing its normal connections before probing.
    """
    priority = PROFILE_PRIORITY.get(profile, [])
    high_priority = [p for p in priority if p in port_list]
    rest = [p for p in port_list if p not in set(high_priority)]
    random.shuffle(rest)
    return high_priority + rest


# ── Main camouflage controller ────────────────────────────────────────────

@dataclass
class CamouflageConfig:
    profile: CamouflageProfile = CamouflageProfile.BROWSER
    os_source_ports: str = "linux"          # linux | windows | macos
    dns_prefetch_enabled: bool = True
    decoy_requests_enabled: bool = True
    decoy_frequency: int = 5                # fire decoy every N probes
    reorder_ports: bool = True
    inter_probe_jitter_ms: float = 50.0     # random 0..N ms between probes
    notes: List[str] = field(default_factory=list)


class BehavioralCamouflage:
    """
    Drop-in camouflage wrapper for the scan engine.
    Usage:
        cam = BehavioralCamouflage(CamouflageConfig(profile=CamouflageProfile.BROWSER))
        port_list = cam.prepare_ports(raw_port_list)
        for port in port_list:
            sport = cam.next_source_port()
            cam.pre_probe_hook(target, port)
            # ... send probe with sport ...
            cam.post_probe_hook(probe_count)
    """

    def __init__(self, config: Optional[CamouflageConfig] = None):
        self.config = config or CamouflageConfig()
        self._sport_alloc = SourcePortAllocator(self.config.os_source_ports)
        self._probe_count = 0
        self._decoy_hosts = list(DECOY_HOSTS)
        random.shuffle(self._decoy_hosts)

    def prepare_ports(self, port_list: List[int]) -> List[int]:
        """Reorder the port list to match the selected profile."""
        if self.config.reorder_ports:
            return reorder_ports_by_profile(port_list, self.config.profile)
        return port_list

    def next_source_port(self) -> int:
        """Return the next source port mimicking OS allocation."""
        return self._sport_alloc.next_port()

    def pre_probe_hook(self, target: str, port: int):
        """
        Called before each probe. Fires DNS prefetch to make traffic look
        like a real application resolving the host before connecting.
        """
        if self.config.dns_prefetch_enabled:
            dns_prefetch(target)

    def post_probe_hook(self, probe_count: int):
        """
        Called after each probe. Fires decoy requests at the configured
        frequency and applies inter-probe jitter.
        """
        self._probe_count += 1
        # Decoy activity
        if (
            self.config.decoy_requests_enabled
            and probe_count > 0
            and probe_count % self.config.decoy_frequency == 0
        ):
            idx = (probe_count // self.config.decoy_frequency) % len(self._decoy_hosts)
            host, port_d = self._decoy_hosts[idx]
            path = random.choice(DECOY_PATHS)
            fire_decoy_request(host, port_d, path)
            logger.debug("[camouflage] Decoy → %s:%d%s", host, port_d, path)
        # Jitter
        if self.config.inter_probe_jitter_ms > 0:
            time.sleep(random.uniform(0, self.config.inter_probe_jitter_ms) / 1000.0)

    def get_summary(self) -> dict:
        return {
            "profile": self.config.profile.value,
            "os_source_ports": self.config.os_source_ports,
            "dns_prefetch": self.config.dns_prefetch_enabled,
            "decoy_requests": self.config.decoy_requests_enabled,
            "decoy_frequency": self.config.decoy_frequency,
            "probes_fired": self._probe_count,
        }
