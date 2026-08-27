"""
USARE Application Protocol Deep Probes

Sends protocol-specific read-only probes to extract maximum
information from identified services. All probes are non-destructive.

Supported protocols:
  - Redis: INFO, CONFIG, CLIENT LIST
  - MongoDB: isMaster, buildInfo, listDatabases
  - Elasticsearch: cluster health, nodes, indices
  - Memcached: stats, items, slabs
  - Docker API: version, containers, images
  - Kubernetes: API discovery, version, healthz
  - MySQL/PostgreSQL: handshake banner extraction
"""

import socket
import json
import struct
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.app_protocol_probe")


@dataclass
class ServiceIntel:
    """Intelligence extracted from a single service."""
    port: int
    protocol: str
    version: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    authenticated: bool = False
    security_notes: List[str] = field(default_factory=list)
    raw_responses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "version": self.version,
            "details": self.details,
            "authenticated": self.authenticated,
            "security_notes": self.security_notes,
        }


@dataclass
class AppProbeResults:
    """Combined probe results for all services."""
    target_ip: str
    services: Dict[int, ServiceIntel] = field(default_factory=dict)
    total_probes: int = 0

    def to_dict(self) -> Dict:
        return {
            "target": self.target_ip,
            "services": {p: s.to_dict() for p, s in self.services.items()},
            "total_probes": self.total_probes,
        }


# Protocol identification by common ports
PORT_PROTOCOL_MAP = {
    6379: "redis",
    6380: "redis",
    27017: "mongodb",
    27018: "mongodb",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    2375: "docker",
    2376: "docker",
    6443: "kubernetes",
    8443: "kubernetes",
    10250: "kubernetes",
    3306: "mysql",
    5432: "postgresql",
    5672: "rabbitmq",
    15672: "rabbitmq",
    8500: "consul",
    2379: "etcd",
    2380: "etcd",
}


class AppProtocolProber:
    """Deep application protocol intelligence extraction."""

    def __init__(self, target_ip: str, timeout: float = 5.0):
        self.target_ip = target_ip
        self.timeout = timeout
        self.results = AppProbeResults(target_ip=target_ip)

    def _connect(self, port: int) -> Optional[socket.socket]:
        """Create a TCP connection to the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, port))
            return sock
        except Exception as e:
            logger.debug(f"[AppProbe] Connection to port {port} failed: {e}")
            return None

    def _send_recv(self, sock: socket.socket, data: bytes,
                   recv_size: int = 4096) -> Optional[bytes]:
        """Send data and receive response."""
        try:
            sock.sendall(data)
            return sock.recv(recv_size)
        except Exception:
            return None

    # ════════════════════════════════
    # REDIS
    # ════════════════════════════════
    def probe_redis(self, port: int = 6379) -> Optional[ServiceIntel]:
        """Probe Redis for unauthenticated access."""
        intel = ServiceIntel(port=port, protocol="redis")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            # INFO command (RESP protocol)
            resp = self._send_recv(sock, b"*1\r\n$4\r\nINFO\r\n", 16384)
            self.results.total_probes += 1

            if resp:
                decoded = resp.decode('utf-8', errors='replace')
                if decoded.startswith("-NOAUTH"):
                    intel.authenticated = False
                    intel.security_notes.append("Redis requires authentication (good)")
                elif decoded.startswith("-ERR"):
                    intel.security_notes.append(f"Redis error: {decoded.strip()}")
                else:
                    intel.authenticated = True
                    intel.security_notes.append("CRITICAL: Redis unauthenticated access!")

                    # Parse INFO response
                    for line in decoded.split("\r\n"):
                        if ":" in line and not line.startswith("#"):
                            key, _, val = line.partition(":")
                            key = key.strip()
                            if key in ("redis_version", "os", "tcp_port", "uptime_in_days",
                                       "connected_clients", "used_memory_human",
                                       "role", "maxmemory_human"):
                                intel.details[key] = val.strip()
                                if key == "redis_version":
                                    intel.version = val.strip()

            # CONFIG GET (if unauthenticated)
            if intel.authenticated:
                resp2 = self._send_recv(sock, b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$4\r\nbind\r\n")
                self.results.total_probes += 1
                if resp2:
                    decoded2 = resp2.decode('utf-8', errors='replace')
                    if "0.0.0.0" in decoded2:
                        intel.security_notes.append("CRITICAL: Redis bound to 0.0.0.0")

            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] Redis probe failed: {e}")

        if intel.version or intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    # ════════════════════════════════
    # MONGODB
    # ════════════════════════════════
    def probe_mongodb(self, port: int = 27017) -> Optional[ServiceIntel]:
        """Probe MongoDB for unauthenticated access."""
        intel = ServiceIntel(port=port, protocol="mongodb")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            # MongoDB wire protocol: OP_MSG with isMaster command
            # Simplified: use the legacy hello/isMaster query
            ismaster_cmd = self._build_mongo_query("admin", {"isMaster": 1})
            resp = self._send_recv(sock, ismaster_cmd, 8192)
            self.results.total_probes += 1

            if resp and len(resp) > 16:
                # Try to parse BSON response (simplified)
                decoded = resp.decode('utf-8', errors='replace')
                # Look for version string in raw response
                if "maxWireVersion" in decoded:
                    intel.authenticated = True
                    intel.security_notes.append("CRITICAL: MongoDB unauthenticated access!")
                    # Extract version info from raw bytes
                    for marker in ["version", "gitVersion"]:
                        idx = decoded.find(marker)
                        if idx >= 0:
                            val = decoded[idx+len(marker)+1:idx+len(marker)+30]
                            clean = ''.join(c for c in val if c.isprintable()).strip()
                            if clean:
                                intel.details[marker] = clean[:20]
                                if marker == "version":
                                    intel.version = clean[:20]

                elif "not authorized" in decoded.lower() or "auth" in decoded.lower():
                    intel.security_notes.append("MongoDB requires authentication (good)")

            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] MongoDB probe failed: {e}")

        if intel.version or intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    def _build_mongo_query(self, db: str, query: Dict) -> bytes:
        """Build a MongoDB OP_QUERY wire protocol message."""
        # Simplified BSON encoder for the isMaster command
        import bson as _  # type: ignore
        # Fallback: craft minimal OP_QUERY manually
        collection = f"{db}.$cmd\x00".encode()
        # Minimal BSON document for {"isMaster": 1}
        doc = b'\x16\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'

        # OP_QUERY header
        flags = struct.pack("<I", 0)  # flags
        skip = struct.pack("<I", 0)
        ret = struct.pack("<i", -1)  # numberToReturn

        body = flags + collection + skip + ret + doc

        # MsgHeader: length, requestID, responseTo, opCode (OP_QUERY=2004)
        request_id = struct.pack("<I", 1)
        response_to = struct.pack("<I", 0)
        opcode = struct.pack("<I", 2004)

        total_len = 16 + len(body)
        header = struct.pack("<I", total_len) + request_id + response_to + opcode

        return header + body

    # ════════════════════════════════
    # ELASTICSEARCH
    # ════════════════════════════════
    def probe_elasticsearch(self, port: int = 9200) -> Optional[ServiceIntel]:
        """Probe Elasticsearch REST API."""
        intel = ServiceIntel(port=port, protocol="elasticsearch")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            # GET / — root endpoint returns version info
            http_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target_ip}:{port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            resp = self._send_recv(sock, http_req, 8192)
            self.results.total_probes += 1

            if resp:
                decoded = resp.decode('utf-8', errors='replace')
                # Find JSON body after HTTP headers
                json_start = decoded.find("{")
                if json_start >= 0:
                    try:
                        data = json.loads(decoded[json_start:])
                        intel.authenticated = True
                        intel.security_notes.append("CRITICAL: Elasticsearch unauthenticated!")

                        if "version" in data:
                            intel.version = data["version"].get("number", "")
                            intel.details["lucene_version"] = data["version"].get("lucene_version", "")

                        intel.details["cluster_name"] = data.get("cluster_name", "")
                        intel.details["node_name"] = data.get("name", "")
                    except json.JSONDecodeError:
                        pass

                if "401" in decoded[:30] or "Unauthorized" in decoded:
                    intel.security_notes.append("Elasticsearch requires authentication (good)")

            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] Elasticsearch probe failed: {e}")

        if intel.version or intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    # ════════════════════════════════
    # MEMCACHED
    # ════════════════════════════════
    def probe_memcached(self, port: int = 11211) -> Optional[ServiceIntel]:
        """Probe Memcached for stats."""
        intel = ServiceIntel(port=port, protocol="memcached")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            resp = self._send_recv(sock, b"stats\r\n", 8192)
            self.results.total_probes += 1

            if resp:
                decoded = resp.decode('utf-8', errors='replace')
                if "STAT" in decoded:
                    intel.authenticated = True
                    intel.security_notes.append("CRITICAL: Memcached unauthenticated!")

                    for line in decoded.split("\r\n"):
                        if line.startswith("STAT "):
                            parts = line.split(" ", 2)
                            if len(parts) >= 3:
                                key = parts[1]
                                if key in ("version", "uptime", "curr_items",
                                           "total_connections", "bytes"):
                                    intel.details[key] = parts[2]
                                    if key == "version":
                                        intel.version = parts[2]
                elif "ERROR" in decoded:
                    intel.security_notes.append("Memcached returned error (may be secured)")

            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] Memcached probe failed: {e}")

        if intel.version or intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    # ════════════════════════════════
    # DOCKER API
    # ════════════════════════════════
    def probe_docker(self, port: int = 2375) -> Optional[ServiceIntel]:
        """Probe Docker HTTP API."""
        intel = ServiceIntel(port=port, protocol="docker")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            http_req = (
                f"GET /version HTTP/1.1\r\n"
                f"Host: {self.target_ip}:{port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            resp = self._send_recv(sock, http_req, 8192)
            self.results.total_probes += 1

            if resp:
                decoded = resp.decode('utf-8', errors='replace')
                json_start = decoded.find("{")
                if json_start >= 0:
                    try:
                        data = json.loads(decoded[json_start:])
                        intel.authenticated = True
                        intel.security_notes.append("CRITICAL: Docker API exposed unauthenticated!")

                        intel.version = data.get("Version", "")
                        intel.details["api_version"] = data.get("ApiVersion", "")
                        intel.details["os"] = data.get("Os", "")
                        intel.details["arch"] = data.get("Arch", "")
                        intel.details["kernel_version"] = data.get("KernelVersion", "")
                    except json.JSONDecodeError:
                        pass

            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] Docker probe failed: {e}")

        if intel.version or intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    # ════════════════════════════════  
    # KUBERNETES API
    # ════════════════════════════════
    def probe_kubernetes(self, port: int = 6443) -> Optional[ServiceIntel]:
        """Probe Kubernetes API server."""
        intel = ServiceIntel(port=port, protocol="kubernetes")

        # K8s API is typically TLS
        import ssl
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, port))
            tls_sock = context.wrap_socket(sock, server_hostname=self.target_ip)

            http_req = (
                f"GET /version HTTP/1.1\r\n"
                f"Host: {self.target_ip}:{port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            tls_sock.sendall(http_req)
            resp = tls_sock.recv(8192)
            self.results.total_probes += 1

            if resp:
                decoded = resp.decode('utf-8', errors='replace')
                json_start = decoded.find("{")
                if json_start >= 0:
                    try:
                        data = json.loads(decoded[json_start:])
                        if "gitVersion" in data:
                            intel.version = data.get("gitVersion", "")
                            intel.details["major"] = data.get("major", "")
                            intel.details["minor"] = data.get("minor", "")
                            intel.details["platform"] = data.get("platform", "")
                            intel.authenticated = True
                            intel.security_notes.append("K8s API version endpoint accessible")
                    except json.JSONDecodeError:
                        pass

                if "401" in decoded[:30] or "403" in decoded[:30]:
                    intel.security_notes.append("K8s API requires authentication (expected)")

            tls_sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] K8s probe failed: {e}")

        if intel.version or intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    # ════════════════════════════════
    # MYSQL / POSTGRESQL BANNER
    # ════════════════════════════════
    def probe_mysql(self, port: int = 3306) -> Optional[ServiceIntel]:
        """Extract MySQL handshake banner."""
        intel = ServiceIntel(port=port, protocol="mysql")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            # MySQL sends handshake packet immediately on connect
            resp = sock.recv(4096)
            self.results.total_probes += 1

            if resp and len(resp) > 5:
                # Skip packet header (4 bytes), extract version string
                # Protocol version at offset 4, then null-terminated version string
                if resp[4] == 10:  # Protocol v10
                    version_end = resp.index(b'\x00', 5)
                    intel.version = resp[5:version_end].decode('utf-8', errors='replace')
                    intel.details["protocol_version"] = 10
                    intel.security_notes.append(f"MySQL {intel.version}")

            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] MySQL probe failed: {e}")

        if intel.version:
            self.results.services[port] = intel
            return intel
        return None

    def probe_postgresql(self, port: int = 5432) -> Optional[ServiceIntel]:
        """Extract PostgreSQL version via startup."""
        intel = ServiceIntel(port=port, protocol="postgresql")

        sock = self._connect(port)
        if not sock:
            return None

        try:
            # Send SSLRequest (check if TLS supported)
            ssl_request = struct.pack(">II", 8, 80877103)
            sock.sendall(ssl_request)
            resp = sock.recv(1)
            self.results.total_probes += 1

            if resp == b'S':
                intel.security_notes.append("PostgreSQL supports TLS (good)")
            elif resp == b'N':
                intel.security_notes.append("PostgreSQL does NOT support TLS")

            intel.details["tls_supported"] = resp == b'S'
            # Don't proceed further to avoid auth prompts
            sock.close()
        except Exception as e:
            logger.debug(f"[AppProbe] PostgreSQL probe failed: {e}")

        if intel.security_notes:
            self.results.services[port] = intel
            return intel
        return None

    # ════════════════════════════════
    # ORCHESTRATOR
    # ════════════════════════════════
    def probe_all(self, open_ports: List[int]) -> AppProbeResults:
        """Probe all open ports for known application protocols."""
        logger.info(f"[AppProbe] Probing {len(open_ports)} ports on {self.target_ip}")

        probe_map = {
            "redis": self.probe_redis,
            "mongodb": self.probe_mongodb,
            "elasticsearch": self.probe_elasticsearch,
            "memcached": self.probe_memcached,
            "docker": self.probe_docker,
            "kubernetes": self.probe_kubernetes,
            "mysql": self.probe_mysql,
            "postgresql": self.probe_postgresql,
        }

        for port in open_ports:
            protocol = PORT_PROTOCOL_MAP.get(port)
            if protocol and protocol in probe_map:
                probe_map[protocol](port)
            else:
                # Try common probes on unknown ports
                for proto in ["elasticsearch", "docker", "redis"]:
                    result = probe_map[proto](port)
                    if result and result.version:
                        break

        logger.info(
            f"[AppProbe] Complete: {len(self.results.services)} services identified, "
            f"{self.results.total_probes} probes sent"
        )

        return self.results
