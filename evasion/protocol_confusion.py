"""Protocol Confusion via Malformed Application Layer Probes.

Sends deliberately wrong application layer protocols to open ports to
reveal service implementation details, error handling behavior,
and version information more precisely than banner grabbing.

Techniques:
- HTTP to SSH port
- SMTP to web server  
- RDP to database port
- FTP to HTTP port
- SSL handshake to non-SSL service
"""

import logging
import time
import ssl
import socket
import struct
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, TCP, UDP, sr1, send, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.protocol_confusion")

class ConfusionProbe(Enum):
    HTTP_TO_SSH = "http_to_ssh"
    SMTP_TO_HTTP = "smtp_to_http"
    RDP_TO_DATABASE = "rdp_to_database"
    FTP_TO_HTTP = "ftp_to_http"
    SSL_TO_PLAIN = "ssl_to_plain"
    MALFORMED_HTTP = "malformed_http"
    MALFORMED_SMTP = "malformed_smtp"
    MALFORMED_FTP = "malformed_ftp"

@dataclass
class ConfusionConfig:
    """Configuration for protocol confusion probes."""
    enable_cross_protocol: bool = True
    enable_malformed_probes: bool = True
    probe_timeout: float = 5.0
    max_retries: int = 2
    analyze_error_codes: bool = True
    capture_full_response: bool = True

@dataclass
class ConfusionResult:
    """Result of protocol confusion probe."""
    probe_type: str
    target_port: int
    protocol_sent: str
    response_received: bool
    response_time_ms: float
    response_data: Optional[bytes]
    error_code: Optional[str]
    error_message: Optional[str]
    service_implementation: str
    version_hints: List[str]
    confidence: float
    stealth_score: float

class ProtocolConfusionEngine:
    """Advanced protocol confusion engine."""
    
    def __init__(self, config: ConfusionConfig):
        self.config = config
        self.probe_results = []
    
    def send_http_to_ssh_port(self, target_ip: str, target_port: int) -> ConfusionResult:
        """Send HTTP request to SSH port to analyze SSH implementation."""
        start_time = time.time()
        
        try:
            # Create HTTP GET request
            http_request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0 (compatible; protocol-confusion-probe)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            
            # Send to SSH port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.probe_timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(http_request)
                
                # Try to read response
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                return self._analyze_ssh_response(response, "HTTP", target_port, response_time)
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.HTTP_TO_SSH.value,
                    target_port=target_port,
                    protocol_sent="HTTP",
                    response_received=False,
                    response_time_ms=response_time,
                    response_data=None,
                    error_code="timeout",
                    error_message="Connection timeout",
                    service_implementation="ssh_no_response",
                    version_hints=["timeout_behavior"],
                    confidence=0.4,
                    stealth_score=0.8
                )
            except Exception as e:
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.HTTP_TO_SSH.value,
                    target_port=target_port,
                    protocol_sent="HTTP",
                    response_received=False,
                    response_time_ms=0,
                    response_data=None,
                    error_code="socket_error",
                    error_message=str(e),
                    service_implementation="ssh_error",
                    version_hints=[],
                    confidence=0.0,
                    stealth_score=0.0
                )
                
        except Exception as e:
            logger.error(f"[Confusion] HTTP to SSH probe failed: {e}")
            return ConfusionResult(
                probe_type=ConfusionProbe.HTTP_TO_SSH.value,
                target_port=target_port,
                protocol_sent="HTTP",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                error_code="probe_error",
                error_message=str(e),
                service_implementation="ssh_unknown",
                version_hints=[],
                confidence=0.0,
                stealth_score=0.0
            )
    
    def send_smtp_to_http_port(self, target_ip: str, target_port: int) -> ConfusionResult:
        """Send SMTP EHLO to HTTP port to analyze web server behavior."""
        start_time = time.time()
        
        try:
            # Create SMTP EHLO command
            smtp_command = f"EHLO confusion-probe-{random.randint(1000, 9999)}\r\n".encode()
            
            # Send to HTTP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.probe_timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(smtp_command)
                
                # Try to read response
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                return self._analyze_http_response(response, "SMTP", target_port, response_time)
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.SMTP_TO_HTTP.value,
                    target_port=target_port,
                    protocol_sent="SMTP",
                    response_received=False,
                    response_time_ms=response_time,
                    response_data=None,
                    error_code="timeout",
                    error_message="Connection timeout",
                    service_implementation="http_no_response",
                    version_hints=["timeout_behavior"],
                    confidence=0.4,
                    stealth_score=0.8
                )
            except Exception as e:
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.SMTP_TO_HTTP.value,
                    target_port=target_port,
                    protocol_sent="SMTP",
                    response_received=False,
                    response_time_ms=0,
                    response_data=None,
                    error_code="socket_error",
                    error_message=str(e),
                    service_implementation="http_error",
                    version_hints=[],
                    confidence=0.0,
                    stealth_score=0.0
                )
                
        except Exception as e:
            logger.error(f"[Confusion] SMTP to HTTP probe failed: {e}")
            return ConfusionResult(
                probe_type=ConfusionProbe.SMTP_TO_HTTP.value,
                target_port=target_port,
                protocol_sent="SMTP",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                error_code="probe_error",
                error_message=str(e),
                service_implementation="http_unknown",
                version_hints=[],
                confidence=0.0,
                stealth_score=0.0
            )
    
    def send_rdp_to_database_port(self, target_ip: str, target_port: int) -> ConfusionResult:
        """Send RDP handshake to database port to analyze database behavior."""
        start_time = time.time()
        
        try:
            # Create RDP connection request (simplified)
            # RDP uses X.224 protocol over TCP
            rdp_request = self._create_rdp_handshake()
            
            # Send to database port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.probe_timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(rdp_request)
                
                # Try to read response
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                return self._analyze_database_response(response, "RDP", target_port, response_time)
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.RDP_TO_DATABASE.value,
                    target_port=target_port,
                    protocol_sent="RDP",
                    response_received=False,
                    response_time_ms=response_time,
                    response_data=None,
                    error_code="timeout",
                    error_message="Connection timeout",
                    service_implementation="database_no_response",
                    version_hints=["timeout_behavior"],
                    confidence=0.4,
                    stealth_score=0.8
                )
            except Exception as e:
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.RDP_TO_DATABASE.value,
                    target_port=target_port,
                    protocol_sent="RDP",
                    response_received=False,
                    response_time_ms=0,
                    response_data=None,
                    error_code="socket_error",
                    error_message=str(e),
                    service_implementation="database_error",
                    version_hints=[],
                    confidence=0.0,
                    stealth_score=0.0
                )
                
        except Exception as e:
            logger.error(f"[Confusion] RDP to database probe failed: {e}")
            return ConfusionResult(
                probe_type=ConfusionProbe.RDP_TO_DATABASE.value,
                target_port=target_port,
                protocol_sent="RDP",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                error_code="probe_error",
                error_message=str(e),
                service_implementation="database_unknown",
                version_hints=[],
                confidence=0.0,
                stealth_score=0.0
            )
    
    def send_malformed_http_probe(self, target_ip: str, target_port: int) -> ConfusionResult:
        """Send malformed HTTP request to analyze web server behavior."""
        start_time = time.time()
        
        try:
            # Create malformed HTTP request
            malformed_requests = [
                # Invalid HTTP version
                b"GET / HTTP/9.9\r\nHost: " + target_ip.encode() + b"\r\n\r\n",
                
                # Invalid method
                b"INVALID / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n",
                
                # Malformed headers
                b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nX-Invalid-Header: \x00\x01\x02\x03\r\n\r\n",
                
                # Oversized URI
                b"GET /" + b"A" * 2000 + b" HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n",
                
                # Invalid CRLF sequence
                b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\n\nHost: " + target_ip.encode() + b"\r\n\r\n"
            ]
            
            # Send malformed request
            malformed_request = random.choice(malformed_requests)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.probe_timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(malformed_request)
                
                # Try to read response
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                return self._analyze_malformed_response(response, "HTTP", target_port, response_time)
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.MALFORMED_HTTP.value,
                    target_port=target_port,
                    protocol_sent="HTTP",
                    response_received=False,
                    response_time_ms=response_time,
                    response_data=None,
                    error_code="timeout",
                    error_message="Connection timeout",
                    service_implementation="http_timeout",
                    version_hints=["malformed_timeout"],
                    confidence=0.5,
                    stealth_score=0.7
                )
            except Exception as e:
                sock.close()
                return ConfusionResult(
                    probe_type=ConfusionProbe.MALFORMED_HTTP.value,
                    target_port=target_port,
                    protocol_sent="HTTP",
                    response_received=False,
                    response_time_ms=0,
                    response_data=None,
                    error_code="socket_error",
                    error_message=str(e),
                    service_implementation="http_error",
                    version_hints=[],
                    confidence=0.0,
                    stealth_score=0.0
                )
                
        except Exception as e:
            logger.error(f"[Confusion] Malformed HTTP probe failed: {e}")
            return ConfusionResult(
                probe_type=ConfusionProbe.MALFORMED_HTTP.value,
                target_port=target_port,
                protocol_sent="HTTP",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                error_code="probe_error",
                error_message=str(e),
                service_implementation="http_unknown",
                version_hints=[],
                confidence=0.0,
                stealth_score=0.0
            )
    
    def _create_rdp_handshake(self) -> bytes:
        """Create simplified RDP handshake packet."""
        # RDP X.224 Connection Request PDU
        # This is a simplified version for confusion probing
        x224_data = struct.pack("!BBHHH", 
                                   0x03,  # X.224 Core Protocol (RDP)
                                   0x00,  # X.224 Reference Number (Connection Request)
                                   random.randint(1, 65535),  # Initiator ID
                                   0,  # Channel ID
                                   0x0000)  # Length placeholder
        
        # Add some RDP-specific data
        rdp_data = b"\x00\x00" + x224_data + b"\x00\x00\x00\x00\x00\x00"
        
        return rdp_data
    
    def _analyze_ssh_response(self, response: bytes, protocol_sent: str, target_port: int,
                          response_time: float) -> ConfusionResult:
        """Analyze SSH port response to HTTP request."""
        if not response:
            return ConfusionResult(
                probe_type=ConfusionProbe.HTTP_TO_SSH.value,
                target_port=target_port,
                protocol_sent=protocol_sent,
                response_received=False,
                response_time_ms=response_time,
                response_data=None,
                error_code="no_response",
                error_message="No response from SSH port",
                service_implementation="ssh_filtered",
                version_hints=["ssh_port_filtered"],
                confidence=0.6,
                stealth_score=0.8
            )
        
        response_str = response.decode('utf-8', errors='ignore')
        
        # Check for SSH protocol responses
        ssh_indicators = ["SSH-", "Protocol mismatch", "identification string"]
        service_implementation = "ssh_unknown"
        version_hints = []
        confidence = 0.8
        
        for indicator in ssh_indicators:
            if indicator in response_str:
                service_implementation = "ssh_responding"
                version_hints.append("ssh_protocol_detected")
                confidence = 0.9
                break
        
        # Check for HTTP-like responses (web server on wrong port)
        http_indicators = ["HTTP/", "Server:", "Content-Type", "404", "400", "500"]
        for indicator in http_indicators:
            if indicator in response_str:
                service_implementation = "http_on_ssh_port"
                version_hints.append("http_service_on_wrong_port")
                confidence = 0.9
                break
        
        # Check for connection reset
        if "Connection reset" in response_str or "refused" in response_str.lower():
            service_implementation = "ssh_connection_reset"
            version_hints.append("connection_reset_behavior")
            confidence = 0.7
        
        return ConfusionResult(
            probe_type=ConfusionProbe.HTTP_TO_SSH.value,
            target_port=target_port,
            protocol_sent=protocol_sent,
            response_received=True,
            response_time_ms=response_time,
            response_data=response,
            error_code=None,
            error_message=None,
            service_implementation=service_implementation,
            version_hints=version_hints,
            confidence=confidence,
            stealth_score=0.8
        )
    
    def _analyze_http_response(self, response: bytes, protocol_sent: str, target_port: int,
                          response_time: float) -> ConfusionResult:
        """Analyze HTTP port response to SMTP request."""
        if not response:
            return ConfusionResult(
                probe_type=ConfusionProbe.SMTP_TO_HTTP.value,
                target_port=target_port,
                protocol_sent=protocol_sent,
                response_received=False,
                response_time_ms=response_time,
                response_data=None,
                error_code="no_response",
                error_message="No response from HTTP port",
                service_implementation="http_filtered",
                version_hints=["http_port_filtered"],
                confidence=0.6,
                stealth_score=0.8
            )
        
        response_str = response.decode('utf-8', errors='ignore')
        
        # Check for HTTP responses
        http_indicators = ["HTTP/", "Server:", "Content-Type"]
        service_implementation = "http_unknown"
        version_hints = []
        confidence = 0.8
        
        for indicator in http_indicators:
            if indicator in response_str:
                service_implementation = "http_responding"
                version_hints.append("http_protocol_detected")
                
                # Extract server info
                if "Server:" in response_str:
                    server_line = [line for line in response_str.split('\n') if 'Server:' in line]
                    if server_line:
                        server_info = server_line[0].split(':', 1)[1].strip()
                        version_hints.append(f"server:{server_info}")
                
                confidence = 0.9
                break
        
        # Check for SMTP-like responses
        smtp_indicators = ["220", "EHLO", "MAIL FROM", "RCPT TO"]
        for indicator in smtp_indicators:
            if indicator in response_str:
                service_implementation = "smtp_on_http_port"
                version_hints.append("smtp_service_on_wrong_port")
                confidence = 0.9
                break
        
        return ConfusionResult(
            probe_type=ConfusionProbe.SMTP_TO_HTTP.value,
            target_port=target_port,
            protocol_sent=protocol_sent,
            response_received=True,
            response_time_ms=response_time,
            response_data=response,
            error_code=None,
            error_message=None,
            service_implementation=service_implementation,
            version_hints=version_hints,
            confidence=confidence,
            stealth_score=0.8
        )
    
    def _analyze_database_response(self, response: bytes, protocol_sent: str, target_port: int,
                               response_time: float) -> ConfusionResult:
        """Analyze database port response to RDP request."""
        if not response:
            return ConfusionResult(
                probe_type=ConfusionProbe.RDP_TO_DATABASE.value,
                target_port=target_port,
                protocol_sent=protocol_sent,
                response_received=False,
                response_time_ms=response_time,
                response_data=None,
                error_code="no_response",
                error_message="No response from database port",
                service_implementation="database_filtered",
                version_hints=["database_port_filtered"],
                confidence=0.6,
                stealth_score=0.8
            )
        
        response_str = response.decode('utf-8', errors='ignore')
        
        # Check for database responses
        db_indicators = ["mysql", "postgresql", "mongodb", "redis", "Error", "OK"]
        service_implementation = "database_unknown"
        version_hints = []
        confidence = 0.8
        
        for indicator in db_indicators:
            if indicator.lower() in response_str.lower():
                service_implementation = "database_responding"
                version_hints.append("database_protocol_detected")
                
                # Extract database info
                if "mysql" in response_str.lower():
                    version_hints.append("mysql_database")
                elif "postgresql" in response_str.lower():
                    version_hints.append("postgresql_database")
                elif "mongodb" in response_str.lower():
                    version_hints.append("mongodb_database")
                elif "redis" in response_str.lower():
                    version_hints.append("redis_database")
                
                confidence = 0.9
                break
        
        # Check for RDP responses
        rdp_indicators = ["X.224", "rdp", "mstsc"]
        for indicator in rdp_indicators:
            if indicator.lower() in response_str.lower():
                service_implementation = "rdp_on_database_port"
                version_hints.append("rdp_service_on_wrong_port")
                confidence = 0.9
                break
        
        return ConfusionResult(
            probe_type=ConfusionProbe.RDP_TO_DATABASE.value,
            target_port=target_port,
            protocol_sent=protocol_sent,
            response_received=True,
            response_time_ms=response_time,
            response_data=response,
            error_code=None,
            error_message=None,
            service_implementation=service_implementation,
            version_hints=version_hints,
            confidence=confidence,
            stealth_score=0.8
        )
    
    def _analyze_malformed_response(self, response: bytes, protocol_sent: str, target_port: int,
                                response_time: float) -> ConfusionResult:
        """Analyze response to malformed HTTP request."""
        if not response:
            return ConfusionResult(
                probe_type=ConfusionProbe.MALFORMED_HTTP.value,
                target_port=target_port,
                protocol_sent=protocol_sent,
                response_received=False,
                response_time_ms=response_time,
                response_data=None,
                error_code="no_response",
                error_message="No response to malformed request",
                service_implementation="http_filtered",
                version_hints=["malformed_no_response"],
                confidence=0.5,
                stealth_score=0.9
            )
        
        response_str = response.decode('utf-8', errors='ignore')
        
        # Analyze error codes
        service_implementation = "http_unknown"
        version_hints = []
        confidence = 0.7
        
        # Check for specific HTTP error codes
        if "400" in response_str:
            service_implementation = "http_strict_validation"
            version_hints.append("strict_http_validation")
            confidence = 0.9
        elif "414" in response_str:
            service_implementation = "http_security_conscious"
            version_hints.append("security_aware_server")
            confidence = 0.9
        elif "500" in response_str:
            service_implementation = "http_server_error"
            version_hints.append("internal_server_error")
            confidence = 0.8
        elif "501" in response_str:
            service_implementation = "http_method_not_implemented"
            version_hints.append("limited_http_implementation")
            confidence = 0.8
        
        # Check for server software
        if "Server:" in response_str:
            server_line = [line for line in response_str.split('\n') if 'Server:' in line]
            if server_line:
                server_info = server_line[0].split(':', 1)[1].strip()
                version_hints.append(f"server:{server_info}")
                confidence = 0.9
        
        return ConfusionResult(
            probe_type=ConfusionProbe.MALFORMED_HTTP.value,
            target_port=target_port,
            protocol_sent=protocol_sent,
            response_received=True,
            response_time_ms=response_time,
            response_data=response,
            error_code=None,
            error_message=None,
            service_implementation=service_implementation,
            version_hints=version_hints,
            confidence=confidence,
            stealth_score=0.7
        )
    
    def comprehensive_confusion_analysis(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Perform comprehensive protocol confusion analysis."""
        results = {
            "cross_protocol_probes": [],
            "malformed_probes": [],
            "analysis": {},
            "service_implementation": {},
            "confidence_score": 0.0
        }
        
        # Send cross-protocol probes
        if self.config.enable_cross_protocol:
            cross_results = [
                self.send_http_to_ssh_port(target_ip, target_port),
                self.send_smtp_to_http_port(target_ip, target_port),
                self.send_rdp_to_database_port(target_ip, target_port)
            ]
            results["cross_protocol_probes"] = cross_results
        
        # Send malformed probes
        if self.config.enable_malformed_probes:
            malformed_result = self.send_malformed_http_probe(target_ip, target_port)
            results["malformed_probes"] = [malformed_result]
        
        # Analyze results
        all_results = results["cross_protocol_probes"] + results["malformed_probes"]
        if all_results:
            results["analysis"] = self._analyze_comprehensive_confusion_results(all_results)
            results["service_implementation"] = self._determine_service_implementation(all_results)
            results["confidence_score"] = sum(r.confidence for r in all_results) / len(all_results)
        
        return results
    
    def _analyze_comprehensive_confusion_results(self, results: List[ConfusionResult]) -> Dict[str, Any]:
        """Analyze comprehensive confusion probe results."""
        analysis = {
            "protocol_mismatches": [],
            "error_patterns": [],
            "implementation_hints": [],
            "security_posture": "unknown"
        }
        
        for result in results:
            if result.response_received:
                if result.protocol_sent != "HTTP" and "http" in result.service_implementation:
                    analysis["protocol_mismatches"].append({
                        "probe": result.probe_type,
                        "sent": result.protocol_sent,
                        "detected": result.service_implementation,
                        "confidence": result.confidence
                    })
                
                # Analyze error handling
                if result.error_code:
                    analysis["error_patterns"].append({
                        "probe": result.probe_type,
                        "error_code": result.error_code,
                        "error_message": result.error_message,
                        "implementation": result.service_implementation
                    })
                
                # Collect implementation hints
                if result.version_hints:
                    analysis["implementation_hints"].extend(result.version_hints)
        
        # Determine security posture
        if len(analysis["protocol_mismatches"]) > 0:
            analysis["security_posture"] = "service_misconfiguration"
        elif len(analysis["error_patterns"]) > 0:
            analysis["security_posture"] = "error_handling_exposed"
        else:
            analysis["security_posture"] = "standard_configuration"
        
        return analysis
    
    def _determine_service_implementation(self, results: List[ConfusionResult]) -> Dict[str, Any]:
        """Determine the actual service implementation."""
        implementation_votes = {}
        confidence_weights = {}
        
        for result in results:
            if result.response_received:
                service = result.service_implementation
                if service not in implementation_votes:
                    implementation_votes[service] = []
                    confidence_weights[service] = []
                
                implementation_votes[service].append(result)
                confidence_weights[service].append(result.confidence)
        
        if not implementation_votes:
            return {"primary_service": "unknown", "confidence": 0.0}
        
        # Determine primary service
        primary_service = max(implementation_votes.items(), 
                          key=lambda x: len(x[1]) * sum(confidence_weights[x[0]]) / len(x[1]))[0]
        
        avg_confidence = sum(confidence_weights[primary_service]) / len(confidence_weights[primary_service])
        
        return {
            "primary_service": primary_service,
            "confidence": avg_confidence,
            "all_detections": list(implementation_votes.keys()),
            "detection_counts": {k: len(v) for k, v in implementation_votes.items()}
        }

# Global instance
_confusion_engine = None

def get_confusion_engine(config: Optional[ConfusionConfig] = None) -> ProtocolConfusionEngine:
    """Get global protocol confusion engine."""
    global _confusion_engine
    if _confusion_engine is None:
        _confusion_engine = ProtocolConfusionEngine(config or ConfusionConfig())
    return _confusion_engine

def confusion_probe(target_ip: str, target_port: int, 
                   probe_type: str) -> ConfusionResult:
    """Convenience function for protocol confusion probe."""
    engine = get_confusion_engine()
    
    try:
        probe_enum = ConfusionProbe(probe_type.lower())
        if probe_enum == ConfusionProbe.HTTP_TO_SSH:
            return engine.send_http_to_ssh_port(target_ip, target_port)
        elif probe_enum == ConfusionProbe.SMTP_TO_HTTP:
            return engine.send_smtp_to_http_port(target_ip, target_port)
        elif probe_enum == ConfusionProbe.RDP_TO_DATABASE:
            return engine.send_rdp_to_database_port(target_ip, target_port)
        elif probe_enum == ConfusionProbe.MALFORMED_HTTP:
            return engine.send_malformed_http_probe(target_ip, target_port)
        else:
            return ConfusionResult(
                probe_type=probe_type,
                target_port=target_port,
                protocol_sent="unknown",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                error_code="invalid_probe_type",
                error_message=f"Unknown probe type: {probe_type}",
                service_implementation="unknown",
                version_hints=[],
                confidence=0.0,
                stealth_score=0.0
            )
    except ValueError:
        return ConfusionResult(
            probe_type=probe_type,
            target_port=target_port,
            protocol_sent="unknown",
            response_received=False,
            response_time_ms=0,
            response_data=None,
            error_code="invalid_probe_type",
            error_message=f"Invalid probe type: {probe_type}",
            service_implementation="unknown",
            version_hints=[],
            confidence=0.0,
            stealth_score=0.0
        )

def comprehensive_confusion_analysis(target_ip: str, target_port: int) -> Dict[str, Any]:
    """Convenience function for comprehensive confusion analysis."""
    engine = get_confusion_engine()
    return engine.comprehensive_confusion_analysis(target_ip, target_port)
