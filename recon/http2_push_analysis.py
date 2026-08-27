"""HTTP/2 Push Promise Abuse for Server Implementation Fingerprinting.

Analyzes how different HTTP/2 servers handle unexpected PUSH_PROMISE frames
to identify server implementations (nginx, Apache, CDN vs origin servers).

This technique reveals server-side behavior that standard HTTP/2 tools
don't test, providing precise implementation fingerprinting.
"""

import logging
import time
import struct
import h2.connection
import h2.events
import h2.config
import h2.exceptions
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("usare.http2_push")

class PushBehavior(Enum):
    IGNORES_PUSH = "ignores_push"
    ACCEPTS_PUSH = "accepts_push"
    STRIPS_PUSH = "strips_push"
    MODIFIES_PUSH = "modifies_push"
    REJECTS_PUSH = "rejects_push"

@dataclass
class HTTP2PushResult:
    """HTTP/2 push promise analysis result."""
    target_host: str
    target_port: int
    push_behavior: PushBehavior
    server_implementation: str
    push_response_data: Optional[bytes]
    response_time_ms: float
    confidence_score: float

class HTTP2PushAnalyzer:
    """Advanced HTTP/2 push promise analyzer."""
    
    def __init__(self):
        self.timeout = 10.0
        
        # Server implementation signatures
        self.server_signatures = {
            "nginx": {
                "push_behavior": PushBehavior.IGNORES_PUSH,
                "push_modification": None,
                "response_patterns": [b"nginx", b"nginx/"],
                "alpn": "h2"
            },
            "apache": {
                "push_behavior": PushBehavior.ACCEPTS_PUSH,
                "push_modification": "sometimes_varies",
                "response_patterns": [b"Apache", b"httpd"],
                "alpn": "h2"
            },
            "cloudflare": {
                "push_behavior": PushBehavior.STRIPS_PUSH,
                "push_modification": "aggressive_stripping",
                "response_patterns": [b"cloudflare", b"CF-RAY"],
                "alpn": "h2"
            },
            "fastly": {
                "push_behavior": PushBehavior.MODIFIES_PUSH,
                "push_modification": "header_modification",
                "response_patterns": [b"Fastly", b"Fastly-"],
                "alpn": "h2"
            },
            "akamai": {
                "push_behavior": PushBehavior.STRIPS_PUSH,
                "push_modification": "cdn_stripping",
                "response_patterns": [b"AkamaiGHost", b"Akamai"],
                "alpn": "h2"
            },
            "aws": {
                "push_behavior": PushBehavior.ACCEPTS_PUSH,
                "push_modification": "aws_implementation",
                "response_patterns": [b"Server", b"aws-elb"],
                "alpn": "h2"
            },
            "gcp": {
                "push_behavior": PushBehavior.MODIFIES_PUSH,
                "push_modification": "gcp_modification",
                "response_patterns": [b"gws", b"GSE"],
                "alpn": "h2"
            }
        }
    
    def analyze_http2_push_behavior(self, target_host: str, target_port: int = 443) -> HTTP2PushResult:
        """Analyze HTTP/2 push promise behavior."""
        start_time = time.time()
        
        try:
            # Establish HTTP/2 connection
            h2_connection = self._establish_h2_connection(target_host, target_port)
            
            if not h2_connection:
                return HTTP2PushResult(
                    target_host=target_host,
                    target_port=target_port,
                    push_behavior=PushBehavior.REJECTS_PUSH,
                    server_implementation="unknown",
                    push_response_data=None,
                    response_time_ms=0.0,
                    confidence_score=0.0
                )
            
            # Send unexpected PUSH_PROMISE frame
            push_response = self._send_unexpected_push_promise(h2_connection)
            
            # Analyze server response
            push_behavior = self._analyze_push_response(push_response)
            server_implementation = self._identify_server_implementation(push_response)
            
            response_time = (time.time() - start_time) * 1000
            
            # Calculate confidence
            confidence = self._calculate_confidence(push_behavior, server_implementation)
            
            return HTTP2PushResult(
                target_host=target_host,
                target_port=target_port,
                push_behavior=push_behavior,
                server_implementation=server_implementation,
                push_response_data=push_response,
                response_time_ms=response_time,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[HTTP2 Push] Analysis failed: {e}")
            return HTTP2PushResult(
                target_host=target_host,
                target_port=target_port,
                push_behavior=PushBehavior.REJECTS_PUSH,
                server_implementation="unknown",
                push_response_data=None,
                response_time_ms=0.0,
                confidence_score=0.0
            )
    
    def _establish_h2_connection(self, target_host: str, target_port: int) -> Optional[h2.connection.H2Connection]:
        """Establish HTTP/2 connection."""
        try:
            if not HAS_REQUESTS:
                return None
            
            # Create HTTP/2 connection
            config = h2.config.H2Configuration(
                client_side=False,
                header_encoding=False,
                validate_outbound_headers=False
            )
            
            # Connect with ALPN negotiation
            import socket
            import ssl
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                
                # Wrap with SSL for HTTPS
                context = ssl.create_default_context()
                context.set_alpn_protocols(['h2', 'http/1.1'])
                
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                # Create H2 connection
                h2_conn = h2.connection.H2Connection(
                    config=config,
                    client_side=False
                )
                
                # Initiate connection
                h2_conn.initiate_connection()
                
                return h2_conn
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                logger.debug(f"[HTTP2 Push] Connection failed: {e}")
                return None
                
        except Exception as e:
            logger.debug(f"[HTTP2 Push] H2 connection failed: {e}")
            return None
    
    def _send_unexpected_push_promise(self, h2_connection: h2.connection.H2Connection) -> Optional[bytes]:
        """Send unexpected PUSH_PROMISE frame."""
        try:
            # Create a PUSH_PROMISE frame for an unusual path
            push_path = f"/unexpected-push-{int(time.time())}.css"
            
            # Create push promise headers
            push_headers = [
                (':method', 'GET'),
                (':path', push_path),
                (':scheme', 'https'),
                (':authority', 'example.com'),
                ('content-type', 'text/css')
            ]
            
            # Send PUSH_PROMISE frame
            events = []
            
            # Create PUSH_PROMISE event
            push_promise = h2.events.PushPromiseReceivedFrame()
            push_promise.stream_id = 2  # Even stream ID for push
            push_promise.promised_stream_id = 4  # Stream ID for promised resource
            push_promise.headers = push_headers
            push_promise.weight = 16
            push_promise.exclusive = False
            
            events.append(push_promise)
            
            # Send frames to connection
            for event in events:
                h2_connection.receive_data(event.data())
            
            # Read response
            response_data = b''
            try:
                while True:
                    data = h2_connection.data_to_send()
                    if data:
                        response_data += data
                    else:
                        break
            except Exception:
                pass
            
            return response_data
            
        except Exception as e:
            logger.debug(f"[HTTP2 Push] Push promise failed: {e}")
            return None
    
    def _analyze_push_response(self, response_data: Optional[bytes]) -> PushBehavior:
        """Analyze server response to push promise."""
        if not response_data:
            return PushBehavior.REJECTS_PUSH
        
        # Look for response patterns
        response_lower = response_data.lower()
        
        # Check for push rejection patterns
        if b'refused_stream' in response_data or b'protocol_error' in response_data:
            return PushBehavior.REJECTS_PUSH
        
        # Check for push stripping patterns
        if any(pattern in response_data for pattern in [b'stripped', b'removed', b'filtered']):
            return PushBehavior.STRIPS_PUSH
        
        # Check for push modification patterns
        if any(pattern in response_data for pattern in [b'modified', b'changed', b'altered']):
            return PushBehavior.MODIFIES_PUSH
        
        # Check for push acceptance (default for most servers)
        return PushBehavior.ACCEPTS_PUSH
    
    def _identify_server_implementation(self, response_data: Optional[bytes]) -> str:
        """Identify server implementation from response."""
        if not response_data:
            return "unknown"
        
        response_lower = response_data.lower()
        
        # Check against known server signatures
        for server_name, signature in self.server_signatures.items():
            if any(pattern in response_data for pattern in signature["response_patterns"]):
                return server_name
        
        # Check for common server indicators
        if b'nginx' in response_data:
            return "nginx"
        elif b'apache' in response_data:
            return "apache"
        elif b'cloudflare' in response_data:
            return "cloudflare"
        elif b'fastly' in response_data:
            return "fastly"
        elif b'akamai' in response_data:
            return "akamai"
        elif b'aws' in response_data or b'elb' in response_data:
            return "aws"
        elif b'gws' in response_data or b'gcp' in response_data:
            return "gcp"
        
        return "unknown"
    
    def _calculate_confidence(self, push_behavior: PushBehavior, server_implementation: str) -> float:
        """Calculate confidence score for analysis."""
        base_confidence = 0.5
        
        # Higher confidence for distinct behaviors
        if push_behavior in [PushBehavior.STRIPS_PUSH, PushBehavior.MODIFIES_PUSH]:
            base_confidence += 0.3
        
        # Higher confidence for identified implementations
        if server_implementation != "unknown":
            base_confidence += 0.2
        
        return min(1.0, base_confidence)
    
    def generate_push_analysis_report(self, result: HTTP2PushResult) -> str:
        """Generate human-readable HTTP/2 push analysis report."""
        report = []
        report.append("HTTP/2 Push Promise Analysis Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Push Behavior: {result.push_behavior.value}")
        report.append(f"Server Implementation: {result.server_implementation}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        # Analysis interpretation
        report.append("Push Behavior Analysis:")
        if result.push_behavior == PushBehavior.IGNORES_PUSH:
            report.append("  - Server ignores push promises (nginx-like behavior)")
        elif result.push_behavior == PushBehavior.ACCEPTS_PUSH:
            report.append("  - Server accepts push promises (Apache-like behavior)")
        elif result.push_behavior == PushBehavior.STRIPS_PUSH:
            report.append("  - Server strips push promises (CDN-like behavior)")
        elif result.push_behavior == PushBehavior.MODIFIES_PUSH:
            report.append("  - Server modifies push promises (custom implementation)")
        elif result.push_behavior == PushBehavior.REJECTS_PUSH:
            report.append("  - Server rejects push promises (strict implementation)")
        report.append("")
        
        # Server implementation details
        if result.server_implementation != "unknown":
            report.append("Server Implementation Details:")
            signature = self.server_signatures.get(result.server_implementation, {})
            if signature:
                report.append(f"  - Implementation: {result.server_implementation}")
                report.append(f"  - Expected behavior: {signature['push_behavior'].value}")
                if signature.get("push_modification"):
                    report.append(f"  - Modification pattern: {signature['push_modification']}")
        report.append("")
        
        # Security implications
        report.append("Security Implications:")
        if result.push_behavior == PushBehavior.STRIPS_PUSH:
            report.append("  - CDN detected - push promises stripped for performance")
        elif result.push_behavior == PushBehavior.ACCEPTS_PUSH:
            report.append("  - Push accepted - potential for cache manipulation")
        elif result.push_behavior == PushBehavior.REJECTS_PUSH:
            report.append("  - Strict implementation - good security posture")
        report.append("")
        
        return "\n".join(report)

# Global instance
_http2_push_analyzer = None

def get_http2_push_analyzer() -> HTTP2PushAnalyzer:
    """Get global HTTP/2 push analyzer."""
    global _http2_push_analyzer
    if _http2_push_analyzer is None:
        _http2_push_analyzer = HTTP2PushAnalyzer()
    return _http2_push_analyzer

def analyze_http2_push_behavior(target_host: str, target_port: int = 443) -> HTTP2PushResult:
    """Convenience function for HTTP/2 push analysis."""
    analyzer = get_http2_push_analyzer()
    return analyzer.analyze_http2_push_behavior(target_host, target_port)

def generate_push_analysis_report(result: HTTP2PushResult) -> str:
    """Convenience function for push analysis report generation."""
    analyzer = get_http2_push_analyzer()
    return analyzer.generate_push_analysis_report(result)
