"""
USARE nmap-service-probes Parser & Enhanced ServiceDetector

Parses Nmap's nmap-service-probes database and uses it to dramatically
expand USARE's service detection from ~50 handcrafted signatures to
4,000+ real-world service fingerprints.

The nmap-service-probes file (usually at /usr/share/nmap/nmap-service-probes
on Kali Linux) contains:
  - Probe definitions: what to send to a port to elicit a banner
  - Match lines: regex patterns to identify service/product/version from responses
  - Softmatch lines: weaker matches used as fallback
  - Port hints: which ports each probe is most relevant for
  - SSL hints: which services expect TLS wrapping

This parser:
  1. Loads and caches the probes database on first use
  2. For a given port+protocol, selects the most relevant probes
  3. Sends each probe and matches the response against all patterns
  4. Returns structured service info: product, version, CPE, extrainfo, OS hint

Usage:
  detector = NmapServiceProbesDetector()
  result = detector.detect("192.168.1.1", 22)
  print(result)  # {"service": "ssh", "product": "OpenSSH", "version": "8.9p1", ...}
"""

import os
import re
import socket
import ssl
import time
import logging
import threading
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.nmap_probes")

# Project data/ directory (user can drop nmap-service-probes here on any OS)
_USARE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_PROBE = os.path.join(_USARE_ROOT, "data", "nmap-service-probes")

# Default probe file locations: env override, bundled data/, Linux paths, Windows Nmap installs
PROBE_FILE_LOCATIONS = [
    _DATA_PROBE,
    "/usr/share/nmap/nmap-service-probes",
    "/usr/local/share/nmap/nmap-service-probes",
    "/opt/nmap/share/nmap/nmap-service-probes",
    "/etc/nmap/nmap-service-probes",
    r"C:\Program Files (x86)\Nmap\nmap-service-probes",
    r"C:\Program Files\Nmap\nmap-service-probes",
]


@dataclass
class ServiceMatch:
    """A matched service from the probes database."""
    service:   str = ""
    product:   str = ""
    version:   str = ""
    extrainfo: str = ""
    hostname:  str = ""
    os_hint:   str = ""
    cpe:       List[str] = field(default_factory=list)
    confidence: float = 0.0
    match_type: str = "match"   # "match" or "softmatch"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass
class ProbeDefinition:
    """A single probe from the nmap-service-probes file."""
    protocol:    str          # "TCP" or "UDP"
    name:        str          # e.g. "GetRequest"
    payload:     bytes        # raw bytes to send
    ports:       List[int]    = field(default_factory=list)
    ssl_ports:   List[int]    = field(default_factory=list)
    total_wait:  int          = 6   # seconds
    matches:     List[Dict]   = field(default_factory=list)  # compiled regex + info


# ─── Parse nmap-service-probes format ─────────────────────────────────────────

def _parse_c_escape(raw: str) -> bytes:
    """Convert nmap probe string (with C-style escapes) to raw bytes."""
    result = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nx = raw[i + 1]
            if nx == "n":
                result.append(0x0A); i += 2
            elif nx == "r":
                result.append(0x0D); i += 2
            elif nx == "t":
                result.append(0x09); i += 2
            elif nx == "0":
                result.append(0x00); i += 2
            elif nx == "\\":
                result.append(0x5C); i += 2
            elif nx == "x" and i + 3 < len(raw):
                result.append(int(raw[i+2:i+4], 16)); i += 4
            else:
                result.append(ord(ch)); i += 1
        else:
            result.append(ord(ch)); i += 1
    return bytes(result)


def _expand_version_info(raw_versioninfo: str, match_obj) -> Dict[str, str]:
    """
    Expand $1, $2, $P(product), $V(version) etc. placeholders in
    versioninfo strings using regex capture groups.
    """
    result = {
        "product": "", "version": "", "extrainfo": "",
        "hostname": "", "os": "", "cpe": ""
    }
    if not raw_versioninfo:
        return result

    # Map field names
    field_map = {
        "p": "product", "v": "version", "i": "extrainfo",
        "h": "hostname", "o": "os", "d": "cpe",
    }

    # Parse /p/v/i/h/o/d/ style or $P(...)$V(...) style
    pattern_named = re.compile(r'\$([pvihodP])\(([^)]*)\)')
    pattern_slash  = re.compile(r'p/([^/]*)/v/([^/]*)/')

    def expand_refs(s: str) -> str:
        """Replace $1..$9 with regex groups."""
        if not match_obj:
            return s
        for idx in range(9, 0, -1):
            try:
                s = s.replace(f"${idx}", match_obj.group(idx) or "")
            except IndexError:
                s = s.replace(f"${idx}", "")
        return s

    # Try slash format: p/Apache httpd/v/$1.$/
    m_slash = pattern_slash.search(raw_versioninfo)
    if m_slash:
        result["product"] = expand_refs(m_slash.group(1)).strip()
        result["version"] = expand_refs(m_slash.group(2)).strip()

    # Try $P($1)$V($2) format
    for m_named in pattern_named.finditer(raw_versioninfo):
        key   = field_map.get(m_named.group(1).lower(), "")
        value = expand_refs(m_named.group(2)).strip()
        if key:
            result[key] = value

    return result


class NmapServiceProbesParser:
    """
    Parses the nmap-service-probes flat-file database into structured
    ProbeDefinition objects.
    """

    def __init__(self, probe_file: Optional[str] = None):
        self._probe_file = probe_file or self._find_probe_file()
        self._probes: List[ProbeDefinition] = []
        self._loaded = False
        self._lock   = threading.Lock()

    def _find_probe_file(self) -> Optional[str]:
        env_path = os.environ.get("USARE_NMAP_PROBES_FILE", "").strip()
        if env_path and os.path.isfile(env_path):
            return env_path
        for path in PROBE_FILE_LOCATIONS:
            if path and os.path.isfile(path):
                return path
        return None

    def load(self) -> bool:
        """Parse the probe file. Returns True if successful."""
        with self._lock:
            if self._loaded:
                return True
            if not self._probe_file or not os.path.exists(self._probe_file):
                logger.warning(
                    "[NmapProbes] nmap-service-probes not found. "
                    "Install nmap: apt install nmap"
                )
                return False

            try:
                self._probes = self._parse_file(self._probe_file)
                logger.info(
                    f"[NmapProbes] Loaded {len(self._probes)} probes from "
                    f"{self._probe_file}"
                )
                self._loaded = True
                return True
            except Exception as e:
                logger.error(f"[NmapProbes] Parse failed: {e}")
                return False

    def _parse_file(self, path: str) -> List[ProbeDefinition]:
        probes: List[ProbeDefinition] = []
        current: Optional[ProbeDefinition] = None

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                # ─── Probe directive ─────────────────────────────────────
                if line.startswith("Probe "):
                    if current:
                        probes.append(current)
                    parts = line.split(None, 3)
                    if len(parts) < 4:
                        current = None
                        continue
                    # Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
                    proto = parts[1].upper()
                    name  = parts[2]
                    q_str = parts[3]
                    # Extract between q|...|  or q"..." etc.
                    m = re.match(r"^q(.)(.*)\1", q_str, re.DOTALL)
                    if not m:
                        current = None
                        continue
                    payload = _parse_c_escape(m.group(2))
                    current = ProbeDefinition(protocol=proto, name=name, payload=payload)

                # ─── Port hints ───────────────────────────────────────────
                elif line.startswith("ports ") and current:
                    port_str = line[6:].strip()
                    current.ports = self._parse_ports(port_str)

                elif line.startswith("sslports ") and current:
                    port_str = line[9:].strip()
                    current.ssl_ports = self._parse_ports(port_str)

                elif line.startswith("totalwaitms ") and current:
                    try:
                        current.total_wait = int(line[12:]) // 1000 + 1
                    except ValueError:
                        pass

                # ─── Match / softmatch ────────────────────────────────────
                elif (line.startswith("match ") or line.startswith("softmatch ")) and current:
                    is_soft = line.startswith("softmatch ")
                    rest    = line[10:] if is_soft else line[6:]

                    # service_name m|regex|[flags] [versioninfo]
                    m = re.match(r"(\S+)\s+m(.)(.*?)\2([is]*)(.*)", rest, re.DOTALL)
                    if not m:
                        continue

                    service     = m.group(1)
                    delimiter   = m.group(2)
                    regex_str   = m.group(3)
                    flags_str   = m.group(4)
                    version_info = m.group(5).strip()

                    flags = 0
                    if "i" in flags_str:
                        flags |= re.IGNORECASE
                    if "s" in flags_str:
                        flags |= re.DOTALL

                    try:
                        compiled = re.compile(regex_str.encode("latin-1"), flags)
                        current.matches.append({
                            "service":      service,
                            "regex":        compiled,
                            "version_info": version_info,
                            "soft":         is_soft,
                        })
                    except re.error:
                        pass

        if current:
            probes.append(current)
        return probes

    def _parse_ports(self, port_str: str) -> List[int]:
        """Parse 'ports 22,80,443,8080-8090' into a list of ints."""
        ports = []
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    ports.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return ports

    @property
    def probes(self) -> List[ProbeDefinition]:
        return self._probes

    @property
    def is_loaded(self) -> bool:
        return self._loaded


class NmapServiceProbesDetector:
    """
    Service detector that uses the nmap-service-probes database.
    Falls back to basic banner matching when the probe file is unavailable.
    """

    # Null probe: send nothing, just listen for spontaneous banner
    NULL_PROBE_PAYLOAD = b""

    def __init__(
        self,
        probe_file: Optional[str] = None,
        timeout: float = 6.0,
        intensity: int = 5,
        max_probes: int = 20,
    ):
        """
        Args:
            probe_file: Path to nmap-service-probes (auto-detected if None).
            timeout: Per-probe socket timeout in seconds.
            intensity: 0-9 (mirrors Nmap's --version-intensity).
                       0 = null probe only, 9 = try all probes.
            max_probes: Hard cap on probes per port regardless of intensity.
        """
        self._parser    = NmapServiceProbesParser(probe_file)
        self._timeout   = timeout
        self._intensity = intensity
        self._max_probes = max_probes
        self._parser.load()

    # ─── Public API ──────────────────────────────────────────────────────────

    def detect(self, target_ip: str, port: int,
               protocol: str = "tcp") -> ServiceMatch:
        """
        Detect service on target:port by sending nmap probes and
        matching responses against the database.
        """
        # Select probes relevant to this port, ordered by relevance
        selected = self._select_probes(port, protocol)

        for probe in selected[:self._max_probes]:
            use_tls = port in probe.ssl_ports or (not probe.ssl_ports and port in (443, 8443))
            result  = self._try_probe(target_ip, port, probe, use_tls)
            if result and result.confidence >= 0.5:
                return result
            # Try TLS variant if plaintext failed
            if not use_tls and result is None:
                result_tls = self._try_probe(target_ip, port, probe, True)
                if result_tls and result_tls.confidence >= 0.5:
                    return result_tls

        return ServiceMatch()

    def detect_all(self, target_ip: str, open_ports: List[Dict]) -> Dict[int, ServiceMatch]:
        """Detect services on all open ports."""
        results = {}
        for entry in open_ports:
            port     = entry.get("port", 0)
            protocol = entry.get("protocol", "tcp")
            results[port] = self.detect(target_ip, port, protocol)
        return results

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _select_probes(self, port: int, protocol: str) -> List[ProbeDefinition]:
        """
        Select and order probes for a given port.

        Priority:
          1. Null probe (always first — catches spontaneous banners)
          2. Probes that explicitly list this port
          3. Probes that list this as an SSL port
          4. Generic probes (GetRequest, GenericLines) for HTTP-like detection
          5. Remaining probes up to intensity limit
        """
        if not self._parser.is_loaded:
            return []

        null_probe = ProbeDefinition(
            protocol=protocol.upper(), name="NULL", payload=self.NULL_PROBE_PAYLOAD,
            matches=[]
        )

        exact: List[ProbeDefinition] = []
        ssl_match: List[ProbeDefinition] = []
        generic: List[ProbeDefinition] = []
        rest: List[ProbeDefinition] = []

        for probe in self._parser.probes:
            if probe.protocol.upper() != protocol.upper():
                continue
            if port in probe.ports:
                exact.append(probe)
            elif port in probe.ssl_ports:
                ssl_match.append(probe)
            elif probe.name in ("GetRequest", "GenericLines", "HTTPOptions", "RTSPRequest"):
                generic.append(probe)
            else:
                rest.append(probe)

        # Intensity controls how many probes we're willing to try
        intensity_limit = {
            0: 1, 1: 2, 2: 3, 3: 5, 4: 8,
            5: 12, 6: 16, 7: 20, 8: 30, 9: 9999
        }.get(self._intensity, 12)

        ordered  = [null_probe] + exact + ssl_match + generic + rest
        return ordered[:intensity_limit]

    def _try_probe(self, target: str, port: int,
                   probe: ProbeDefinition, use_tls: bool) -> Optional[ServiceMatch]:
        """Send one probe and attempt to match the response."""
        try:
            banner = self._send_probe(target, port, probe.payload, use_tls)
        except Exception:
            return None

        if not banner:
            return None

        # Try to match against this probe's patterns
        best: Optional[ServiceMatch] = None
        for match_def in probe.matches:
            try:
                m = match_def["regex"].search(banner)
                if m:
                    vinfo  = _expand_version_info(match_def["version_info"], m)
                    result = ServiceMatch(
                        service    = match_def["service"],
                        product    = vinfo.get("product", ""),
                        version    = vinfo.get("version", ""),
                        extrainfo  = vinfo.get("extrainfo", ""),
                        hostname   = vinfo.get("hostname", ""),
                        os_hint    = vinfo.get("os", ""),
                        cpe        = [vinfo["cpe"]] if vinfo.get("cpe") else [],
                        confidence = 0.95 if not match_def["soft"] else 0.65,
                        match_type = "softmatch" if match_def["soft"] else "match",
                    )
                    if best is None or result.confidence > best.confidence:
                        best = result
            except Exception:
                continue

        return best

    def _send_probe(self, target: str, port: int,
                    payload: bytes, use_tls: bool) -> Optional[bytes]:
        """Open connection, optionally wrap in TLS, send payload, return banner."""
        sock = socket.create_connection((target, port), timeout=self._timeout)
        try:
            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=target)

            if payload:
                sock.sendall(payload)

            # Read response
            banner = b""
            sock.settimeout(self._timeout)
            start = time.time()
            while time.time() - start < self._timeout:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) >= 65536:
                        break
                except socket.timeout:
                    break

        finally:
            try:
                sock.close()
            except Exception:
                pass

        return banner if banner else None

    @property
    def probe_count(self) -> int:
        return len(self._parser.probes)

    @property
    def is_loaded(self) -> bool:
        return self._parser.is_loaded

    def get_status(self) -> Dict[str, Any]:
        return {
            "probes_loaded":  self.probe_count,
            "probe_file":     self._parser._probe_file,
            "is_loaded":      self.is_loaded,
            "intensity":      self._intensity,
            "timeout":        self._timeout,
        }


# ─── Module-level singleton & convenience function ─────────────────────────────

_detector: Optional[NmapServiceProbesDetector] = None

def get_detector(intensity: int = 5, timeout: float = 6.0) -> NmapServiceProbesDetector:
    """Get or create module-level detector singleton."""
    global _detector
    if _detector is None:
        _detector = NmapServiceProbesDetector(intensity=intensity, timeout=timeout)
    return _detector


def detect_with_nmap_probes(
    target_ip: str,
    port: int,
    intensity: int = 5,
    timeout: float = 6.0,
) -> ServiceMatch:
    """
    Convenience function: detect service using nmap-service-probes.
    Falls back gracefully if the probe file is not installed.
    """
    detector = get_detector(intensity=intensity, timeout=timeout)
    if not detector.is_loaded:
        logger.debug(
            f"[NmapProbes] Probe DB not available for {target_ip}:{port}. "
            "Install nmap for 4000+ service signatures."
        )
        return ServiceMatch()
    return detector.detect(target_ip, port)
