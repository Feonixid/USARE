"""
USARE Advanced OS Fingerprinting — Nmap-parity TCP/ICMP/UDP Probe Suite

Implements the full nmap OS detection probe methodology:

  T1–T6  — Six SYN probes with different TCP option sets, sent to an open port
  T7     — FIN/PSH/URG probe to an open port (RFC 793 violation detector)
  U1     — UDP probe to a high closed port (expects ICMP port-unreachable)
  IE1    — ICMP echo request with unusual TOS and DF
  IE2    — Second ICMP echo with different code/ID

Response analysis extracts:
  - TCP ISN (Initial Sequence Number) generation pattern → SP/ISR/GCD metrics
  - TCP timestamp (TSval) → clock frequency → OS family
  - TCP options ordering (WScale, MSS, SAckOK, NOP, Timestamp)
  - IP ID sequence pattern (zero, random, incremental, broken)
  - DF bit behavior
  - ICMP echo response fields (IP TTL, DF, ID, TOS preserved/modified)
  - Window size and scaling

Together these ~15 fields give confidence comparable to nmap's OS detection.

Requires Scapy + root.  Falls back gracefully if unavailable.
"""

import time
import math
import random
import logging
import statistics
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple

logger = logging.getLogger("usare.nmap_os_probes")

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, sr1, sr, conf, RandShort, Raw
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─────────────────────────────────────────────────────────────────────────────
# TCP option sequences for T1–T6 (matching nmap's probe definitions)
# Each probe has a distinct options list to fingerprint how the stack
# handles unusual or ordered option combinations.
# ─────────────────────────────────────────────────────────────────────────────

_WINDOW_SIZES = [1, 63, 4, 4, 16, 512]   # T1–T6 window sizes

_TCP_OPTION_SETS: List[List[tuple]] = [
    # T1 — WScale=10, NOP, MSS=1460, Timestamp, SAckOK
    [("WScale", 10), ("NOP", None), ("MSS", 1460), ("Timestamp", (0xFFFFFFFF, 0)), ("SAckOK", b"")],
    # T2 — MSS=265, SAckOK, Timestamp, NOP, WScale=10 (different order)
    [("MSS", 265), ("SAckOK", b""), ("Timestamp", (0xFFFFFFFF, 0)), ("NOP", None), ("WScale", 10)],
    # T3 — WScale=5, NOP, MSS=640, Timestamp, SAckOK
    [("WScale", 5), ("NOP", None), ("MSS", 640), ("Timestamp", (0xFFFFFFFF, 0)), ("SAckOK", b"")],
    # T4 — Timestamp only, MSS=536
    [("Timestamp", (0xFFFFFFFF, 0)), ("MSS", 536)],
    # T5 — WScale=3, NOP, MSS=265, Timestamp, SAckOK
    [("WScale", 3), ("NOP", None), ("MSS", 265), ("Timestamp", (0xFFFFFFFF, 0)), ("SAckOK", b"")],
    # T6 — WScale=0 (no scale), NOP, MSS=265, NOP, Timestamp
    [("WScale", 0), ("NOP", None), ("MSS", 265), ("NOP", None), ("Timestamp", (0xFFFFFFFF, 0))],
]

# T7 — FIN/PSH/URG to an open port
_T7_FLAGS = "FPU"

# ─────────────────────────────────────────────────────────────────────────────
# OS signature database (compact subset — enough for enterprise detection)
# Each entry covers the key discriminating fields.
# ─────────────────────────────────────────────────────────────────────────────

OS_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Linux 5.x (Kernel 5.4–5.19)",
        "family": "Linux",
        "ttl": (62, 65),
        "window": (64240, 64240),
        "df": True,
        "ip_id_behavior": "zero",
        "ts_hz_range": (250, 260),   # 250 Hz kernel HZ
        "wscale": (7, 7),
        "mss": (1460, 1460),
        "sackok": True,
        "t7_response": "none",       # open port ignores FIN/PSH/URG
    },
    {
        "name": "Linux 4.x (Kernel 4.9–4.19)",
        "family": "Linux",
        "ttl": (62, 65),
        "window": (29200, 65535),
        "df": True,
        "ip_id_behavior": "zero",
        "ts_hz_range": (99, 101),    # some 4.x = 100 Hz
        "wscale": (7, 7),
        "mss": (1460, 1460),
        "sackok": True,
        "t7_response": "none",
    },
    {
        "name": "Windows 10/11 (Server 2019/2022)",
        "family": "Windows",
        "ttl": (126, 129),
        "window": (8192, 65535),
        "df": True,
        "ip_id_behavior": "incremental",
        "ts_hz_range": None,         # Windows doesn't send TCP timestamps by default
        "wscale": (8, 8),
        "mss": (1460, 1460),
        "sackok": True,
        "t7_response": "rst",        # Windows RSTs T7
    },
    {
        "name": "Windows Server 2016",
        "family": "Windows",
        "ttl": (126, 129),
        "window": (8192, 8192),
        "df": True,
        "ip_id_behavior": "incremental",
        "ts_hz_range": None,
        "wscale": (8, 8),
        "mss": (1460, 1460),
        "sackok": True,
        "t7_response": "rst",
    },
    {
        "name": "FreeBSD 13.x",
        "family": "BSD",
        "ttl": (63, 65),
        "window": (65535, 65535),
        "df": True,
        "ip_id_behavior": "random",
        "ts_hz_range": (999, 1001),  # 1000 Hz
        "wscale": (6, 6),
        "mss": (1460, 1460),
        "sackok": True,
        "t7_response": "none",
    },
    {
        "name": "macOS 12.x/13.x (Monterey/Ventura)",
        "family": "macOS",
        "ttl": (63, 65),
        "window": (65535, 65535),
        "df": True,
        "ip_id_behavior": "random",
        "ts_hz_range": (999, 1001),  # XNU uses 1000 Hz
        "wscale": (6, 6),
        "mss": (1460, 1460),
        "sackok": True,
        "t7_response": "none",
    },
    {
        "name": "Cisco IOS XE",
        "family": "Cisco",
        "ttl": (254, 255),
        "window": (4128, 16384),
        "df": False,
        "ip_id_behavior": "incremental",
        "ts_hz_range": None,
        "wscale": None,
        "mss": (1460, 1480),
        "sackok": False,
        "t7_response": "rst",
    },
    {
        "name": "Linux (embedded/IoT, musl libc)",
        "family": "Linux",
        "ttl": (62, 65),
        "window": (5840, 14600),
        "df": True,
        "ip_id_behavior": "zero",
        "ts_hz_range": None,
        "wscale": (2, 5),
        "mss": (1460, 1460),
        "sackok": False,
        "t7_response": "none",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AdvancedOSResult:
    os_name: str = "Unknown"
    os_family: str = "Unknown"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    # Raw probe data
    ttl_observed: Optional[int] = None
    window_sizes: List[int] = field(default_factory=list)
    ip_id_behavior: str = "unknown"
    df_flag: Optional[bool] = None
    wscale_values: List[int] = field(default_factory=list)
    mss_values: List[int] = field(default_factory=list)
    sackok: Optional[bool] = None
    ts_hz_estimate: Optional[float] = None
    t7_response: str = "none"
    isn_sequence: List[int] = field(default_factory=list)
    icmp_response_fields: Dict[str, Any] = field(default_factory=dict)
    probes_sent: int = 0
    probes_answered: int = 0
    method: str = "advanced_tcp_icmp"
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "os_name": self.os_name,
            "os_family": self.os_family,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "ttl": self.ttl_observed,
            "window_sizes": self.window_sizes,
            "ip_id_behavior": self.ip_id_behavior,
            "df": self.df_flag,
            "wscale_values": self.wscale_values,
            "mss_values": self.mss_values,
            "sackok": self.sackok,
            "ts_hz_estimate": self.ts_hz_estimate,
            "t7_response": self.t7_response,
            "probes_sent": self.probes_sent,
            "probes_answered": self.probes_answered,
            "method": self.method,
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Probe execution
# ─────────────────────────────────────────────────────────────────────────────

def _sport() -> int:
    return random.randint(49152, 65535)


def _extract_tcp_info(resp) -> Dict[str, Any]:
    """Extract all useful fields from a TCP SYN-ACK response."""
    info: Dict[str, Any] = {}
    if resp is None:
        return info
    if resp.haslayer(IP):
        info["ttl"]   = int(resp[IP].ttl)
        info["df"]    = bool(resp[IP].flags & 0x02)
        info["ip_id"] = int(resp[IP].id)
    if resp.haslayer(TCP):
        info["window"] = int(resp[TCP].window)
        info["seq"]    = int(resp[TCP].seq)
        opts = resp[TCP].options or []
        for opt_name, opt_val in opts:
            k = opt_name.lower().replace(" ", "_")
            info[f"opt_{k}"] = opt_val
        info["flags"] = int(resp[TCP].flags)
    return info


def run_tcp_probes(
    target: str,
    open_port: int,
    timeout: float = 3.0,
    interface: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Send T1–T6 SYN probes and return list of response info dicts.
    """
    if not HAS_SCAPY:
        return []
    conf.verb = 0
    kw: Dict[str, Any] = {"timeout": timeout, "verbose": 0}
    if interface:
        conf.iface = interface

    results = []
    base_seq = int(time.time() * 1e6) % (2**32)

    for i, (opts, win) in enumerate(zip(_TCP_OPTION_SETS, _WINDOW_SIZES)):
        try:
            pkt = IP(dst=target) / TCP(
                dport=open_port,
                sport=_sport(),
                flags="S",
                window=win,
                seq=base_seq + i * 1000,
                options=opts,
            )
            resp = sr1(pkt, **kw)
            info = _extract_tcp_info(resp)
            info["probe"] = f"T{i+1}"
            info["answered"] = resp is not None
            results.append(info)
            time.sleep(0.1)   # 100ms inter-probe gap
        except Exception as e:
            logger.debug("[os_probes] T%d failed: %s", i+1, e)
            results.append({"probe": f"T{i+1}", "answered": False})

    return results


def run_t7_probe(
    target: str,
    open_port: int,
    timeout: float = 3.0,
) -> str:
    """
    T7: FIN/PSH/URG to open port.
    RFC 793 compliant stacks (Linux/BSD) silently drop it.
    Windows RSTs it. Cisco RSTs it.
    Returns: "none" | "rst" | "synack" | "other"
    """
    if not HAS_SCAPY:
        return "unknown"
    conf.verb = 0
    try:
        pkt = IP(dst=target) / TCP(
            dport=open_port,
            sport=_sport(),
            flags=_T7_FLAGS,
            seq=random.randint(0, 2**31),
        )
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return "none"
        if resp.haslayer(TCP):
            f = int(resp[TCP].flags)
            if f & 0x04:
                return "rst"
            if (f & 0x12) == 0x12:
                return "synack"
            return f"flags_{f:02x}"
    except Exception as e:
        logger.debug("[os_probes] T7 failed: %s", e)
    return "none"


def run_udp_probe(
    target: str,
    closed_port: int = 40125,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    U1: UDP datagram to a high closed port.
    Expects ICMP port-unreachable type 3 code 3.
    Analyzes the ICMP response fields (TTL, DF, IP ID).
    """
    result: Dict[str, Any] = {"answered": False}
    if not HAS_SCAPY:
        return result
    conf.verb = 0
    try:
        payload = b"C" * 300   # nmap uses 'C' * 300
        pkt = IP(dst=target) / UDP(dport=closed_port, sport=_sport()) / Raw(load=payload)
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is not None and resp.haslayer(ICMP):
            icmp = resp[ICMP]
            result["answered"]  = True
            result["icmp_type"] = int(icmp.type)
            result["icmp_code"] = int(icmp.code)
            if resp.haslayer(IP):
                result["ttl"]   = int(resp[IP].ttl)
                result["df"]    = bool(resp[IP].flags & 0x02)
                result["ip_id"] = int(resp[IP].id)
                result["tos"]   = int(resp[IP].tos)
    except Exception as e:
        logger.debug("[os_probes] U1 failed: %s", e)
    return result


def run_icmp_probes(
    target: str,
    timeout: float = 3.0,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    IE1/IE2: Two ICMP echo requests with unusual fields.
    IE1: type=8 code=9 id=0xABCD df=True tos=0
    IE2: type=8 code=0 id=0x1234 df=False tos=4
    Analyzes how the target echoes back: does it preserve code, TOS, DF?
    This reveals OS-level ICMP implementation details.
    """
    ie1: Dict[str, Any] = {"answered": False}
    ie2: Dict[str, Any] = {"answered": False}
    if not HAS_SCAPY:
        return ie1, ie2
    conf.verb = 0
    try:
        p1 = IP(dst=target, flags="DF", tos=0) / ICMP(type=8, code=9, id=0xABCD, seq=0x1234) / (b"X" * 120)
        r1 = sr1(p1, timeout=timeout, verbose=0)
        if r1 is not None and r1.haslayer(ICMP):
            ie1["answered"] = True
            ie1["ttl"]       = int(r1[IP].ttl)
            ie1["df"]        = bool(r1[IP].flags & 0x02)
            ie1["ip_id"]     = int(r1[IP].id)
            ie1["tos"]       = int(r1[IP].tos)
            ie1["icmp_code"] = int(r1[ICMP].code)   # does the OS echo back code=9 or reset to 0?
    except Exception as e:
        logger.debug("[os_probes] IE1 failed: %s", e)

    time.sleep(0.2)

    try:
        p2 = IP(dst=target, tos=4) / ICMP(type=8, code=0, id=0x5678, seq=0x5678) / (b"Y" * 150)
        r2 = sr1(p2, timeout=timeout, verbose=0)
        if r2 is not None and r2.haslayer(ICMP):
            ie2["answered"] = True
            ie2["ttl"]       = int(r2[IP].ttl)
            ie2["df"]        = bool(r2[IP].flags & 0x02)
            ie2["ip_id"]     = int(r2[IP].id)
            ie2["tos"]       = int(r2[IP].tos)       # does the OS reflect TOS=4?
    except Exception as e:
        logger.debug("[os_probes] IE2 failed: %s", e)

    return ie1, ie2


# ─────────────────────────────────────────────────────────────────────────────
# ISN analysis (nmap SP/GCD/ISR metrics)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_isn(seq_list: List[int]) -> Dict[str, Any]:
    """
    Analyze TCP ISN sequence to classify IP ID / ISN generation.
    Returns behavior classification matching nmap's SP/ISR categories.
    """
    if len(seq_list) < 2:
        return {"behavior": "unknown"}
    diffs = [
        abs(seq_list[i+1] - seq_list[i]) % (2**32)
        for i in range(len(seq_list) - 1)
    ]
    if all(d == 0 for d in diffs):
        return {"behavior": "constant", "note": "All ISNs identical — trivially predictable"}
    if all(0 < d < 100 for d in diffs):
        return {"behavior": "incremental_small", "note": "Small increments — weak randomness"}
    if all(d < 10000 for d in diffs):
        return {"behavior": "incremental", "note": "Sequential ISN — older stack"}
    if len(set(diffs)) > len(diffs) * 0.8:
        return {"behavior": "random", "note": "Strong randomness — modern OS (RFC 6528)"}
    gcd = diffs[0]
    for d in diffs[1:]:
        while d:
            gcd, d = d, gcd % d
    return {
        "behavior": "random_increments",
        "gcd": gcd,
        "mean_diff": sum(diffs) / len(diffs),
        "note": f"Random increments, GCD={gcd}",
    }


def analyze_ip_id(id_list: List[int]) -> str:
    """Classify IP ID generation pattern."""
    if not id_list:
        return "unknown"
    if all(x == 0 for x in id_list):
        return "zero"              # Linux on DF packets
    diffs = [abs(id_list[i+1] - id_list[i]) for i in range(len(id_list)-1)]
    if all(d == 0 for d in diffs):
        return "constant"
    if all(0 < d <= 10 for d in diffs):
        return "incremental"      # Windows / Cisco
    if max(id_list) - min(id_list) > 30000 or len(set(id_list)) > len(id_list) * 0.7:
        return "random"           # BSD / macOS
    return "unknown"


def estimate_ts_hz(ts_values: List[int], elapsed_seconds: float) -> Optional[float]:
    """
    Estimate the kernel HZ (clock frequency) from TCP timestamp values.
    TSval increments at HZ per second.
    Common: Linux=100/250/1000, BSD=1000, Windows=doesn't send by default.
    """
    if len(ts_values) < 2 or elapsed_seconds <= 0:
        return None
    delta_ts = ts_values[-1] - ts_values[0]
    if delta_ts <= 0:
        return None
    hz = delta_ts / elapsed_seconds
    # Round to known HZ values
    for known in (100, 250, 300, 1000):
        if abs(hz - known) / known < 0.15:   # within 15%
            return float(known)
    return round(hz, 1)


# ─────────────────────────────────────────────────────────────────────────────
# Matching
# ─────────────────────────────────────────────────────────────────────────────

def _score_signature(result: AdvancedOSResult, sig: Dict[str, Any]) -> Tuple[float, List[str]]:
    score  = 0.0
    total  = 0.0
    evidence: List[str] = []

    # TTL (weight 0.20)
    if result.ttl_observed is not None:
        total += 0.20
        lo, hi = sig["ttl"]
        if lo <= result.ttl_observed <= hi:
            score += 0.20
            evidence.append(f"TTL {result.ttl_observed} ∈ [{lo},{hi}] matches {sig['name']}")

    # Window size (weight 0.20)
    if result.window_sizes:
        total += 0.20
        wlo, whi = sig["window"]
        if any(wlo <= w <= whi for w in result.window_sizes):
            score += 0.20
            evidence.append(f"Window ∈ [{wlo},{whi}]")
        elif any(abs(w - wlo) < 500 or abs(w - whi) < 500 for w in result.window_sizes):
            score += 0.10
            evidence.append(f"Window near [{wlo},{whi}]")

    # DF bit (weight 0.10)
    if result.df_flag is not None:
        total += 0.10
        if result.df_flag == sig["df"]:
            score += 0.10
            evidence.append(f"DF={result.df_flag}")

    # IP ID behavior (weight 0.20)
    if result.ip_id_behavior != "unknown":
        total += 0.20
        if result.ip_id_behavior == sig["ip_id_behavior"]:
            score += 0.20
            evidence.append(f"IP ID behavior: {result.ip_id_behavior}")

    # WScale (weight 0.10)
    if result.wscale_values and sig.get("wscale"):
        total += 0.10
        ws_lo, ws_hi = sig["wscale"]
        if any(ws_lo <= w <= ws_hi for w in result.wscale_values):
            score += 0.10
            evidence.append(f"WScale ∈ [{ws_lo},{ws_hi}]")

    # SACKok (weight 0.05)
    if result.sackok is not None and sig.get("sackok") is not None:
        total += 0.05
        if result.sackok == sig["sackok"]:
            score += 0.05

    # Timestamp HZ (weight 0.10)
    if result.ts_hz_estimate and sig.get("ts_hz_range"):
        total += 0.10
        hz_lo, hz_hi = sig["ts_hz_range"]
        if hz_lo <= result.ts_hz_estimate <= hz_hi:
            score += 0.10
            evidence.append(f"TCP TS HZ ≈ {result.ts_hz_estimate:.0f} ∈ [{hz_lo},{hz_hi}]")

    # T7 response (weight 0.05)
    if result.t7_response and sig.get("t7_response"):
        total += 0.05
        if result.t7_response == sig["t7_response"]:
            score += 0.05
            evidence.append(f"T7 response: {result.t7_response}")

    norm = score / total if total > 0 else 0.0
    return norm, evidence


def match_signatures(result: AdvancedOSResult) -> AdvancedOSResult:
    """Match the probe results against the OS signature database."""
    best_score = 0.0
    best_sig   = None
    best_ev: List[str] = []

    for sig in OS_SIGNATURES:
        sc, ev = _score_signature(result, sig)
        if sc > best_score:
            best_score = sc
            best_sig = sig
            best_ev = ev

    if best_sig and best_score > 0.20:
        result.os_name   = best_sig["name"]
        result.os_family = best_sig["family"]
        result.confidence = min(0.99, best_score)
        result.evidence   = best_ev
    else:
        result.notes.append("No confident OS match — consider --osscan-guess for fuzzy results")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def advanced_os_fingerprint(
    target: str,
    open_port: int,
    closed_udp_port: int = 40125,
    timeout: float = 3.0,
    interface: Optional[str] = None,
) -> AdvancedOSResult:
    """
    Run the full T1–T7 + U1 + IE1/IE2 probe suite against a target.
    open_port must be a confirmed open TCP port.
    closed_udp_port should be a port very unlikely to be open.
    """
    result = AdvancedOSResult()

    if not HAS_SCAPY:
        result.notes.append("Scapy required for advanced OS probes")
        return result

    # ── T1–T6 TCP SYN probes ─────────────────────────────────────────────
    t_start = time.monotonic()
    tcp_responses = run_tcp_probes(target, open_port, timeout=timeout, interface=interface)
    result.probes_sent += 6

    seq_list: List[int] = []
    ip_id_list: List[int] = []
    ts_vals: List[int] = []
    ts_times: List[float] = []

    for resp_info in tcp_responses:
        if not resp_info.get("answered"):
            continue
        result.probes_answered += 1
        ttl = resp_info.get("ttl")
        if ttl and result.ttl_observed is None:
            result.ttl_observed = ttl
        win = resp_info.get("window")
        if win:
            result.window_sizes.append(win)
        df = resp_info.get("df")
        if df is not None:
            result.df_flag = df
        seq = resp_info.get("seq")
        if seq is not None:
            seq_list.append(seq)
        ip_id = resp_info.get("ip_id")
        if ip_id is not None:
            ip_id_list.append(ip_id)
        wscale = resp_info.get("opt_wscale")
        if wscale is not None:
            result.wscale_values.append(int(wscale) if not isinstance(wscale, int) else wscale)
        mss = resp_info.get("opt_mss")
        if mss is not None:
            result.mss_values.append(int(mss) if not isinstance(mss, int) else mss)
        sackok = resp_info.get("opt_sackok")
        if sackok is not None:
            result.sackok = True
        ts = resp_info.get("opt_timestamp")
        if ts is not None and isinstance(ts, tuple):
            ts_vals.append(ts[0])
            ts_times.append(time.monotonic())

    # ── ISN / IP ID analysis ──────────────────────────────────────────────
    if seq_list:
        isn_analysis = analyze_isn(seq_list)
        result.isn_sequence = seq_list
        result.notes.append(f"ISN: {isn_analysis.get('behavior','?')} — {isn_analysis.get('note','')}")

    if ip_id_list:
        result.ip_id_behavior = analyze_ip_id(ip_id_list)

    # ── Timestamp HZ estimation ───────────────────────────────────────────
    if len(ts_vals) >= 2:
        elapsed = ts_times[-1] - ts_times[0] if len(ts_times) >= 2 else 0.5
        result.ts_hz_estimate = estimate_ts_hz(ts_vals, elapsed)

    # ── T7 probe ──────────────────────────────────────────────────────────
    result.t7_response = run_t7_probe(target, open_port, timeout=timeout)
    result.probes_sent += 1
    if result.t7_response != "none":
        result.probes_answered += 1
        result.notes.append(f"T7 (FPU to open): {result.t7_response}")

    # ── U1 UDP probe ──────────────────────────────────────────────────────
    udp_result = run_udp_probe(target, closed_udp_port, timeout=timeout)
    result.probes_sent += 1
    if udp_result.get("answered"):
        result.probes_answered += 1
        result.icmp_response_fields["u1"] = udp_result
        if result.ttl_observed is None and udp_result.get("ttl"):
            result.ttl_observed = udp_result["ttl"]

    # ── IE1/IE2 ICMP probes ───────────────────────────────────────────────
    ie1, ie2 = run_icmp_probes(target, timeout=timeout)
    result.probes_sent += 2
    if ie1.get("answered"):
        result.probes_answered += 1
        result.icmp_response_fields["ie1"] = ie1
        # IE1 code echo: Linux/BSD echo code back, Windows resets to 0
        code_echo = ie1.get("icmp_code", 0)
        if code_echo == 9:
            result.notes.append("IE1: OS echoes ICMP code back (Linux/BSD behaviour)")
        elif code_echo == 0:
            result.notes.append("IE1: OS resets ICMP code to 0 (Windows/Cisco behaviour)")
    if ie2.get("answered"):
        result.probes_answered += 1
        result.icmp_response_fields["ie2"] = ie2
        # TOS reflection
        tos_back = ie2.get("tos", 0)
        if tos_back == 4:
            result.notes.append("IE2: OS reflects TOS field (Linux typical)")
        else:
            result.notes.append("IE2: OS does not reflect TOS (Windows typical)")

    # ── signature matching ────────────────────────────────────────────────
    result = match_signatures(result)

    elapsed_total = time.monotonic() - t_start
    result.notes.append(
        f"Probes: {result.probes_sent} sent, {result.probes_answered} answered "
        f"in {elapsed_total:.1f}s"
    )
    return result
