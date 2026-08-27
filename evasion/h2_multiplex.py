"""
USARE HTTP/2 Multiplexing Evasion

Hides multiple port probes inside a single HTTP/2 session using
stream multiplexing. One TCP connection, many concurrent streams
to different paths — IDS sees one connection, we're probing
many endpoints.

Key evasion properties:
- Single TCP connection = single flow in firewall state table
- 50+ HEADERS frames in parallel streams
- IDS must parse HTTP/2 framing to detect individual probes
- Many IDS systems only inspect the initial HEADERS frame
"""

import socket
import ssl
import struct
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
import os

logger = logging.getLogger("usare.h2_multiplex")

try:
    import hpack  # type: ignore
    HAS_HPACK = True
except ImportError:
    HAS_HPACK = False
    logger.warning("[H2Multiplex] hpack not installed — pip install hpack for correct HPACK encoding")


# HTTP/2 frame types
H2_HEADERS = 0x01
H2_SETTINGS = 0x04
H2_WINDOW_UPDATE = 0x08
H2_GOAWAY = 0x07

# HTTP/2 settings
H2_SETTINGS_MAX_CONCURRENT = 0x03
H2_SETTINGS_INITIAL_WINDOW = 0x04

# HTTP/2 connection preface
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclass
class H2ProbeResult:
    """Result of probing through an HTTP/2 multiplexed stream."""
    stream_id: int
    target_path: str
    status_code: int = 0
    response_size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    detected_service: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "stream_id": self.stream_id,
            "path": self.target_path,
            "status": self.status_code,
            "response_size": self.response_size,
            "service": self.detected_service,
            "latency_ms": round(self.latency_ms, 2),
        }


@dataclass
class H2MultiplexResult:
    """Complete HTTP/2 multiplex scan result."""
    target: str
    port: int
    streams_sent: int
    responses_received: int
    probes: List[H2ProbeResult] = field(default_factory=list)
    total_latency_ms: float = 0.0
    h2_supported: bool = False

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "port": self.port,
            "h2_supported": self.h2_supported,
            "streams_sent": self.streams_sent,
            "responses_received": self.responses_received,
            "probes": [p.to_dict() for p in self.probes],
            "total_latency_ms": round(self.total_latency_ms, 2),
        }


class H2MultiplexScanner:
    """
    HTTP/2 multiplexed port/endpoint scanner.
    Sends many concurrent requests through a single connection.
    """

    # Probe paths for service detection
    DEFAULT_PROBE_PATHS = [
        "/",
        "/api",
        "/api/v1",
        "/health",
        "/healthz",
        "/ready",
        "/status",
        "/metrics",
        "/admin",
        "/login",
        "/graphql",
        "/.well-known/openid-configuration",
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/.env",
        "/server-status",
        "/api-docs",
        "/swagger.json",
        "/openapi.json",
    ]

    # Port-specific paths for targeted probing
    PORT_PROBE_PATHS = {
        8080: ["/api", "/actuator/health", "/jolokia"],
        8443: ["/api/v1", "/healthz"],
        9090: ["/metrics", "/-/healthy"],
        3000: ["/api/health", "/api/v1/version"],
        5000: ["/v2/_catalog"],
        9200: ["/", "/_cluster/health"],
        8888: ["/api/kernels"],
    }

    def __init__(self, timeout: float = 10.0, max_streams: int = 50):
        self.timeout = timeout
        self.max_streams = max_streams

    def multiplex_scan(self, target: str, port: int,
                       paths: Optional[List[str]] = None,
                       use_tls: bool = True) -> H2MultiplexResult:
        """
        Open single HTTP/2 connection and send multiple stream probes.
        """
        result = H2MultiplexResult(
            target=target, port=port,
            streams_sent=0, responses_received=0,
        )
        t0 = time.time()

        if not paths:
            paths = list(self.DEFAULT_PROBE_PATHS)
            if port in self.PORT_PROBE_PATHS:
                paths = self.PORT_PROBE_PATHS[port] + paths

        paths = paths[:self.max_streams]

        try:
            # Connect with TLS + ALPN for HTTP/2
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                sock = ctx.wrap_socket(sock, server_hostname=target)

                # Check if HTTP/2 was negotiated
                selected = sock.selected_alpn_protocol()
                if selected != "h2":
                    result.h2_supported = False
                    sock.close()
                    result.total_latency_ms = (time.time() - t0) * 1000
                    return result

            result.h2_supported = True

            # Send HTTP/2 preface
            sock.sendall(H2_PREFACE)

            # Send SETTINGS frame
            settings = self._build_settings_frame()
            sock.sendall(settings)

            # Send WINDOW_UPDATE for large window
            window_update = self._build_window_update(0, 65535)
            sock.sendall(window_update)

            # Send all HEADERS frames (one per stream)
            for i, path in enumerate(paths):
                stream_id = 1 + (i * 2)  # Odd stream IDs for client
                if stream_id > self.max_streams * 2:
                    break

                headers_frame = self._build_headers_frame(
                    stream_id, target, port, path
                )
                sock.sendall(headers_frame)
                result.streams_sent += 1

            # Read responses
            sock.settimeout(self.timeout)
            response_data = b""
            try:
                while True:
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    response_data += chunk
            except socket.timeout:
                pass

            # Parse HTTP/2 frames from response
            parsed = self._parse_h2_responses(response_data, paths)
            result.probes = parsed
            result.responses_received = len(parsed)

            sock.close()

        except Exception as e:
            logger.debug(f"[H2Multiplex] Scan failed: {e}")

        result.total_latency_ms = (time.time() - t0) * 1000
        return result

    def _build_settings_frame(self) -> bytes:
        """Build HTTP/2 SETTINGS frame."""
        # Settings payload: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=65535
        payload = struct.pack(">HI", H2_SETTINGS_MAX_CONCURRENT, 100)
        payload += struct.pack(">HI", H2_SETTINGS_INITIAL_WINDOW, 65535)

        length = struct.pack(">I", len(payload))[1:]  # 3-byte length
        frame_type = struct.pack("B", H2_SETTINGS)
        flags = struct.pack("B", 0)
        stream_id = struct.pack(">I", 0)

        return length + frame_type + flags + stream_id + payload

    def _build_window_update(self, stream_id: int, increment: int) -> bytes:
        """Build HTTP/2 WINDOW_UPDATE frame."""
        payload = struct.pack(">I", increment)
        length = struct.pack(">I", 4)[1:]
        frame_type = struct.pack("B", H2_WINDOW_UPDATE)
        flags = struct.pack("B", 0)
        sid = struct.pack(">I", stream_id)
        return length + frame_type + flags + sid + payload

    def _build_headers_frame(self, stream_id: int,
                              host: str, port: int, path: str) -> bytes:
        """
        Build HTTP/2 HEADERS frame with proper HPACK encoding.
        Uses hpack library if available, otherwise falls back to
        uncompressed literal representation.
        """
        if HAS_HPACK:
            headers_payload = self._hpack_encode(host, port, path)
        else:
            headers_payload = self._manual_encode(host, port, path)

        # Build frame header
        length = struct.pack(">I", len(headers_payload))[1:]
        frame_type = struct.pack("B", H2_HEADERS)
        flags = struct.pack("B", 0x05)  # END_STREAM | END_HEADERS
        sid = struct.pack(">I", stream_id)

        return length + frame_type + flags + sid + headers_payload

    def _hpack_encode(self, host: str, port: int, path: str) -> bytes:
        """Encode headers using the hpack library (correct HPACK)."""
        encoder = hpack.Encoder()
        headers = [
            (":method", "GET"),
            (":path", path),
            (":scheme", "https"),
            (":authority", f"{host}:{port}"),
            ("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"),
            ("accept", "*/*"),
        ]
        return encoder.encode(headers)

    def _manual_encode(self, host: str, port: int, path: str) -> bytes:
        """Fallback: uncompressed literal header encoding (RFC 7541 §6.2.1)."""
        payload = b""

        # Each header: 0x00 (literal, no indexing) + name-len + name + val-len + val
        for name, value in [
            (":method", "GET"),
            (":path", path),
            (":scheme", "https"),
            (":authority", f"{host}:{port}"),
            ("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:122.0)"),
            ("accept", "*/*"),
        ]:
            name_bytes = name.encode()
            value_bytes = value.encode()
            payload += b"\x00"  # Literal, no indexing, new name
            payload += self._encode_integer(len(name_bytes), 7)
            payload += name_bytes
            payload += self._encode_integer(len(value_bytes), 7)
            payload += value_bytes

        return payload

    @staticmethod
    def _encode_integer(value: int, prefix_bits: int) -> bytes:
        """HPACK integer encoding (RFC 7541 §5.1)."""
        max_first = (1 << prefix_bits) - 1
        if value < max_first:
            return struct.pack("B", value)
        result = [max_first]
        value -= max_first
        while value >= 128:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    def _parse_h2_responses(self, data: bytes,
                             paths: List[str]) -> List[H2ProbeResult]:
        """Parse HTTP/2 response frames."""
        results = []
        offset = 0
        path_by_stream: Dict[int, str] = {}

        for i, path in enumerate(paths):
            path_by_stream[1 + (i * 2)] = path

        while offset + 9 <= len(data):
            # Parse frame header (9 bytes)
            length_bytes = data[offset:offset + 3]
            frame_len = int.from_bytes(length_bytes, "big")
            frame_type = data[offset + 3]
            flags = data[offset + 4]
            stream_id = int.from_bytes(data[offset + 5:offset + 9], "big") & 0x7FFFFFFF

            offset += 9  # Move past frame header

            if offset + frame_len > len(data):
                break

            frame_payload = data[offset:offset + frame_len]
            offset += frame_len

            # HEADERS frame (contains response status)
            if frame_type == H2_HEADERS and stream_id in path_by_stream:
                path = path_by_stream[stream_id]
                status = self._extract_status_from_headers(frame_payload)

                probe_result = H2ProbeResult(
                    stream_id=stream_id,
                    target_path=path,
                    status_code=status,
                    response_size=frame_len,
                )

                # Detect service from path + status
                if status == 200:
                    probe_result.detected_service = self._infer_service(path, status)

                results.append(probe_result)

            # GOAWAY frame — server is done
            elif frame_type == H2_GOAWAY:
                break

        return results

    def _extract_status_from_headers(self, payload: bytes) -> int:
        """Extract HTTP status code from HPACK-encoded headers."""
        # Check for indexed :status headers
        if len(payload) > 0:
            first_byte = payload[0]
            # HPACK indexed header field: status codes
            status_map = {
                0x88: 200, 0x89: 204, 0x8A: 206,
                0x8B: 304, 0x8C: 400, 0x8D: 404, 0x8E: 500,
            }
            if first_byte in status_map:
                return status_map[first_byte]

            # Try literal header field
            if first_byte == 0x48:  # :status with literal value
                if len(payload) > 4:
                    try:
                        status_str = payload[2:5].decode("ascii")
                        return int(status_str)
                    except (ValueError, UnicodeDecodeError):
                        pass

        return 0

    def _infer_service(self, path: str, status: int) -> str:
        """Infer service type from response path and status."""
        service_map = {
            "/metrics": "prometheus",
            "/healthz": "kubernetes",
            "/ready": "kubernetes",
            "/actuator/health": "spring_boot",
            "/jolokia": "java_jmx",
            "/graphql": "graphql",
            "/api-docs": "swagger",
            "/swagger.json": "swagger",
            "/openapi.json": "openapi",
            "/v2/_catalog": "docker_registry",
            "/_cluster/health": "elasticsearch",
            "/.well-known/openid-configuration": "oidc",
            "/server-status": "apache",
        }

        for p, svc in service_map.items():
            if path == p:
                return svc

        return "http_service"
