"""
USARE Modern Service Detector

Detects microservice infrastructure that traditional banner grabbing misses:

1. gRPC Health Check — /grpc.health.v1.Health/Check via HTTP/2
2. GraphQL Introspection — {__schema{types{name}}} query
3. Kubernetes API — /api/v1 endpoint detection
4. REST API detection — OpenAPI/Swagger probe
5. WebSocket detection — Upgrade: websocket negotiation

These are critical for modern cloud-native infrastructure where
services run on non-standard ports with no traditional banners.
"""

import socket
import ssl
import struct
import time
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger("usare.modern_service_detect")


@dataclass
class ModernServiceResult:
    """Detection result for a modern service."""
    port: int
    service_type: str       # "grpc", "graphql", "k8s_api", "rest_api", "websocket"
    detected: bool
    version: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "service": self.service_type,
            "detected": self.detected,
            "version": self.version,
            "metadata": self.metadata,
            "latency_ms": round(self.latency_ms, 2),
        }


class ModernServiceDetector:
    """
    Probes for modern microservice infrastructure.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def probe_all(self, target: str, port: int,
                  use_tls: bool = False) -> List[ModernServiceResult]:
        """Run all detection probes against a port."""
        results = []
        results.append(self.probe_grpc(target, port, use_tls))
        results.append(self.probe_graphql(target, port, use_tls))
        results.append(self.probe_k8s_api(target, port, use_tls))
        results.append(self.probe_openapi(target, port, use_tls))
        results.append(self.probe_websocket(target, port, use_tls))
        results.append(self.probe_prometheus_metrics(target, port, use_tls))
        return [r for r in results if r.detected]

    def _connect(self, target: str, port: int,
                 use_tls: bool = False) -> Optional[socket.socket]:
        """Create connection, optionally with TLS."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=target)

            return sock
        except Exception:
            return None

    def _connect_h2(self, target: str, port: int,
                    use_tls: bool = True) -> Optional[socket.socket]:
        """Create TLS connection with HTTP/2 ALPN negotiation."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                sock = ctx.wrap_socket(sock, server_hostname=target)

                # Verify HTTP/2 was negotiated
                selected = sock.selected_alpn_protocol()
                if selected != "h2":
                    sock.close()
                    return None

            return sock
        except Exception:
            return None

    def probe_grpc(self, target: str, port: int,
                   use_tls: bool = False) -> ModernServiceResult:
        """
        Probe for gRPC via HTTP/2.

        gRPC strictly requires HTTP/2. We:
        1. TLS connect with ALPN ["h2"] to negotiate HTTP/2
        2. Send HTTP/2 connection preface + SETTINGS
        3. Send HEADERS frame for POST /grpc.health.v1.Health/Check
        4. Check response for gRPC markers

        Falls back to HTTP/1.1 gRPC-Web detection if HTTP/2 fails.
        """
        t0 = time.time()
        result = ModernServiceResult(port=port, service_type="grpc", detected=False)

        try:
            # Try HTTP/2 first (real gRPC)
            h2_sock = self._connect_h2(target, port, use_tls or port in (443, 8443, 50051))
            if h2_sock:
                detected = self._probe_grpc_h2(h2_sock, target, port, result)
                if detected:
                    result.latency_ms = (time.time() - t0) * 1000
                    result.metadata["transport"] = "h2"
                    return result

            # Fallback: HTTP/1.1 gRPC-Web probe
            sock = self._connect(target, port, use_tls)
            if sock:
                path = "/grpc.health.v1.Health/Check"
                grpc_request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}:{port}\r\n"
                    f"Content-Type: application/grpc-web+proto\r\n"
                    f"TE: trailers\r\n"
                    f"X-Grpc-Web: 1\r\n"
                    f"Content-Length: 5\r\n"
                    f"\r\n"
                ).encode()
                grpc_request += b"\x00\x00\x00\x00\x00"

                sock.sendall(grpc_request)
                try:
                    response = sock.recv(4096)
                    resp_text = response.decode("utf-8", errors="replace").lower()
                    if any(m in resp_text for m in [
                        "grpc", "application/grpc", "grpc-status",
                        "grpc-message", "trailers"
                    ]):
                        result.detected = True
                        result.metadata["transport"] = "grpc-web"
                        result.metadata["response_preview"] = resp_text[:200]
                except socket.timeout:
                    pass
                sock.close()

        except Exception as e:
            logger.debug(f"[ModernDetect] gRPC probe failed: {e}")

        result.latency_ms = (time.time() - t0) * 1000
        return result

    def _probe_grpc_h2(self, sock: socket.socket, target: str,
                       port: int, result: ModernServiceResult) -> bool:
        """Send gRPC health check over HTTP/2 binary framing."""
        try:
            # HTTP/2 connection preface
            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

            # SETTINGS frame (type=0x04, stream=0)
            settings = struct.pack(">I", 0)[1:]  # length=0
            settings += struct.pack("B", 0x04)    # SETTINGS
            settings += struct.pack("B", 0x00)    # no flags
            settings += struct.pack(">I", 0)      # stream 0
            sock.sendall(settings)

            # Build HEADERS for gRPC health check using literal encoding
            headers_payload = b""
            for name, value in [
                (":method", "POST"),
                (":path", "/grpc.health.v1.Health/Check"),
                (":scheme", "https"),
                (":authority", f"{target}:{port}"),
                ("content-type", "application/grpc"),
                ("te", "trailers"),
                ("grpc-accept-encoding", "identity"),
            ]:
                n = name.encode()
                v = value.encode()
                headers_payload += b"\x00"
                headers_payload += struct.pack("B", len(n)) + n
                headers_payload += struct.pack("B", len(v)) + v

            # HEADERS frame (type=0x01, END_HEADERS=0x04)
            h_len = struct.pack(">I", len(headers_payload))[1:]
            headers_frame = h_len + struct.pack("B", 0x01) + struct.pack("B", 0x04)
            headers_frame += struct.pack(">I", 1)  # stream 1
            sock.sendall(headers_frame + headers_payload)

            # DATA frame with empty gRPC message (compressed=0, length=0)
            grpc_msg = b"\x00\x00\x00\x00\x00"
            d_len = struct.pack(">I", len(grpc_msg))[1:]
            data_frame = d_len + struct.pack("B", 0x00)  # DATA
            data_frame += struct.pack("B", 0x01)  # END_STREAM
            data_frame += struct.pack(">I", 1)    # stream 1
            sock.sendall(data_frame + grpc_msg)

            # Read response
            sock.settimeout(self.timeout)
            response = b""
            try:
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            # Check for gRPC response markers in raw bytes
            resp_text = response.decode("utf-8", errors="replace").lower()
            if any(m in resp_text for m in [
                "grpc-status", "grpc-message", "application/grpc"
            ]) or any(m in response for m in [
                b"grpc-status", b"grpc-message"
            ]):
                result.detected = True
                result.metadata["response_preview"] = resp_text[:200]
                return True

            # Also check if we got proper HTTP/2 frames back (SETTINGS ACK, HEADERS)
            if len(response) >= 9:
                # Any valid HTTP/2 response to our gRPC request = gRPC server
                frame_type = response[3] if len(response) > 3 else 0
                if frame_type in (0x01, 0x04):  # HEADERS or SETTINGS
                    result.detected = True
                    result.metadata["h2_frame_type"] = frame_type
                    return True

        except Exception as e:
            logger.debug(f"[ModernDetect] gRPC H2 probe failed: {e}")

        return False

    def probe_graphql(self, target: str, port: int,
                      use_tls: bool = False) -> ModernServiceResult:
        """
        Probe for GraphQL by sending introspection query.
        """
        t0 = time.time()
        result = ModernServiceResult(port=port, service_type="graphql", detected=False)

        try:
            sock = self._connect(target, port, use_tls)
            if not sock:
                return result

            # GraphQL introspection query
            query = json.dumps({
                "query": "{__schema{types{name}}}"
            })

            for path in ["/graphql", "/api/graphql", "/v1/graphql", "/query"]:
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}:{port}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(query)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{query}"
                ).encode()

                try:
                    sock.sendall(request)
                    response = sock.recv(8192)
                    resp_text = response.decode("utf-8", errors="replace")

                    if "__schema" in resp_text or "__type" in resp_text:
                        result.detected = True
                        result.metadata["endpoint"] = path

                        # Extract type names
                        try:
                            body_start = resp_text.find("\r\n\r\n")
                            if body_start >= 0:
                                body = resp_text[body_start + 4:]
                                gql_data = json.loads(body)
                                types = gql_data.get("data", {}).get("__schema", {}).get("types", [])
                                type_names = [t["name"] for t in types
                                              if not t["name"].startswith("__")]
                                result.metadata["types"] = type_names[:10]
                        except (json.JSONDecodeError, KeyError):
                            pass
                        break

                except socket.timeout:
                    continue
                except Exception:
                    break

                # Need new connection for each path
                sock.close()
                sock = self._connect(target, port, use_tls)
                if not sock:
                    break

            try:
                sock.close()
            except Exception:
                pass
            result.latency_ms = (time.time() - t0) * 1000

        except Exception as e:
            logger.debug(f"[ModernDetect] GraphQL probe failed: {e}")

        return result

    def probe_k8s_api(self, target: str, port: int,
                      use_tls: bool = False) -> ModernServiceResult:
        """Probe for Kubernetes API server."""
        t0 = time.time()
        result = ModernServiceResult(port=port, service_type="k8s_api", detected=False)

        try:
            sock = self._connect(target, port, use_tls or port in (443, 6443, 8443))
            if not sock:
                return result

            request = (
                f"GET /api/v1 HTTP/1.1\r\n"
                f"Host: {target}:{port}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            sock.sendall(request)
            response = sock.recv(4096)
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")

            if any(marker in resp_text for marker in [
                "apiVersion", "kind", "resources",
                '"serverAddress"', "kubernetes"
            ]):
                result.detected = True
                try:
                    body_start = resp_text.find("\r\n\r\n")
                    if body_start >= 0:
                        body = resp_text[body_start + 4:]
                        k8s_data = json.loads(body)
                        result.version = k8s_data.get("serverVersion", {}).get("gitVersion", "")
                except Exception:
                    pass

            result.latency_ms = (time.time() - t0) * 1000

        except Exception as e:
            logger.debug(f"[ModernDetect] K8s API probe failed: {e}")

        return result

    def probe_openapi(self, target: str, port: int,
                      use_tls: bool = False) -> ModernServiceResult:
        """Probe for OpenAPI/Swagger endpoints."""
        t0 = time.time()
        result = ModernServiceResult(port=port, service_type="rest_api", detected=False)

        paths = ["/openapi.json", "/swagger.json", "/api-docs",
                 "/v2/api-docs", "/v3/api-docs"]

        try:
            for path in paths:
                sock = self._connect(target, port, use_tls)
                if not sock:
                    continue

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target}:{port}\r\n"
                    f"Accept: application/json\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()

                sock.sendall(request)
                response = sock.recv(4096)
                sock.close()

                resp_text = response.decode("utf-8", errors="replace")
                if any(marker in resp_text for marker in [
                    '"openapi"', '"swagger"', '"paths"', '"info"'
                ]):
                    result.detected = True
                    result.metadata["endpoint"] = path
                    try:
                        body_start = resp_text.find("\r\n\r\n")
                        if body_start >= 0:
                            api_data = json.loads(resp_text[body_start + 4:])
                            result.version = api_data.get("openapi",
                                            api_data.get("swagger", ""))
                            info = api_data.get("info", {})
                            result.metadata["title"] = info.get("title", "")
                    except Exception:
                        pass
                    break

            result.latency_ms = (time.time() - t0) * 1000

        except Exception as e:
            logger.debug(f"[ModernDetect] OpenAPI probe failed: {e}")

        return result

    def probe_websocket(self, target: str, port: int,
                        use_tls: bool = False) -> ModernServiceResult:
        """Probe for WebSocket support."""
        t0 = time.time()
        result = ModernServiceResult(port=port, service_type="websocket", detected=False)

        try:
            sock = self._connect(target, port, use_tls)
            if not sock:
                return result

            import hashlib
            import base64
            key = base64.b64encode(hashlib.sha1(b"usare-probe").digest()).decode()

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()

            sock.sendall(request)
            response = sock.recv(4096)
            sock.close()

            resp_text = response.decode("utf-8", errors="replace").lower()
            if "101" in resp_text and "upgrade" in resp_text:
                result.detected = True
            elif "sec-websocket" in resp_text:
                result.detected = True

            result.latency_ms = (time.time() - t0) * 1000

        except Exception as e:
            logger.debug(f"[ModernDetect] WebSocket probe failed: {e}")

        return result

    def probe_prometheus_metrics(self, target: str, port: int,
                                 use_tls: bool = False) -> ModernServiceResult:
        """
        Probe for Prometheus /metrics endpoint.
        Prometheus exposition format is simple text-based data with
        # HELP and # TYPE lines.
        """
        t0 = time.time()
        result = ModernServiceResult(port=port, service_type="prometheus", detected=False)

        try:
            sock = self._connect(target, port, use_tls)
            if not sock:
                return result

            request = (
                f"GET /metrics HTTP/1.1\r\n"
                f"Host: {target}:{port}\r\n"
                f"Accept: text/plain, version=0.0.4;q=1, */*;q=0.5\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            sock.sendall(request)
            
            # Read enough to determine if it's prometheus
            response = b""
            sock.settimeout(2.0)
            try:
                while len(response) < 16384:  # Read up to 16KB
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
                
            sock.close()

            # Need to separate headers from body
            resp_str = response.decode("utf-8", errors="replace")
            body_start = resp_str.find("\r\n\r\n")
            
            if body_start >= 0:
                body = resp_str[body_start + 4:]
            else:
                body = resp_str
                
            # Check for Prometheus exposition format markers
            lines = body.split("\n")
            help_count = 0
            type_count = 0
            metrics_found: List[str] = []
            
            for line in lines[:50]:  # Just check first 50 lines
                if line.startswith("# HELP "):
                    help_count += 1
                elif line.startswith("# TYPE "):
                    type_count += 1
                    parts = line.split(" ")
                    if len(parts) >= 3:
                        metrics_found.append(parts[2])
                        
            if help_count > 0 and type_count > 0:
                result.detected = True
                result.metadata["metrics_exposed"] = len(metrics_found)
                if metrics_found:
                    result.metadata["sample_metrics"] = metrics_found[:10]
                    
                # Try to guess component based on metrics
                metrics_text = " ".join(metrics_found)
                if "go_memstats" in metrics_text:
                    result.metadata["technology"] = "Go App"
                elif "jvm_memory" in metrics_text:
                    result.metadata["technology"] = "Java/JVM"
                elif "python_gc" in metrics_text:
                    result.metadata["technology"] = "Python App"
                elif "nodejs_" in metrics_text:
                    result.metadata["technology"] = "Node.js"
                elif "nginx_" in metrics_text or "nginx_ingress" in metrics_text:
                    result.metadata["technology"] = "NGINX/Ingress"

            result.latency_ms = (time.time() - t0) * 1000

        except Exception as e:
            logger.debug(f"[ModernDetect] Prometheus probe failed: {e}")

        return result
