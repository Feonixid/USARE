"""RFC Compliance Protocol Fingerprinting for Exact Version Detection.

Tests protocol edge cases and RFC non-compliance behaviors to fingerprint
exact software versions and patch levels beyond what banner analysis reveals.

Uses legitimate protocol operations that appear as unusual but valid
implementations to identify subtle behavioral differences.
"""

import logging
import time
import socket
import struct
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, TCP, Raw, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.rfc_compliance")

class Protocol(Enum):
    SSH = "ssh"
    HTTP = "http"
    TLS = "tls"
    FTP = "ftp"
    SMTP = "smtp"

class RFCComplianceType(Enum):
    EDGE_CASE = "edge_case"
    NON_COMPLIANCE = "non_compliance"
    OPTIONAL_BEHAVIOR = "optional_behavior"
    ERROR_HANDLING = "error_handling"
    TIMEOUT_BEHAVIOR = "timeout_behavior"

@dataclass
class RFCProbeResult:
    """RFC compliance probe result."""
    protocol: str
    test_type: str
    test_name: str
    success: bool
    response_time_ms: float
    response_data: Optional[bytes]
    compliance_level: str
    version_hints: List[str]
    confidence: float

@dataclass
class RFCComplianceAnalysis:
    """RFC compliance analysis result."""
    target_host: str
    target_port: int
    protocol: str
    probe_results: List[RFCProbeResult]
    version_fingerprint: Dict[str, Any]
    compliance_score: float
    security_assessment: List[str]
    recommendations: List[str]

class RFCComplianceProber:
    """Advanced RFC compliance protocol prober."""
    
    def __init__(self):
        self.timeout = 10.0
        
        # RFC test definitions for different protocols
        self.rfc_tests = {
            Protocol.SSH: {
                "protocol_version_negotiation": {
                    "description": "Test SSH protocol version negotiation edge cases",
                    "tests": [
                        "invalid_version_string",
                        "multiple_version_strings",
                        "version_string_with_nulls",
                        "version_string_overflow"
                    ]
                },
                "key_exchange_edge_cases": {
                    "description": "Test SSH key exchange edge cases",
                    "tests": [
                        "invalid_key_exchange",
                        "multiple_key_exchange_requests",
                        "key_exchange_with_invalid_data",
                        "key_exchange_timeout"
                    ]
                },
                "message_sequence_edge_cases": {
                    "description": "Test SSH message sequence edge cases",
                    "tests": [
                        "out_of_order_messages",
                        "duplicate_messages",
                        "message_with_invalid_length",
                        "message_with_invalid_padding",
                        "message_sequence_overflow"
                    ]
                },
                "authentication_edge_cases": {
                    "description": "Test SSH authentication edge cases",
                    "tests": [
                        "invalid_authentication_method",
                        "multiple_authentication_attempts",
                        "authentication_with_invalid_data",
                        "authentication_buffer_overflow"
                    ]
                }
            },
            Protocol.HTTP: {
                "header_parsing_edge_cases": {
                    "description": "Test HTTP header parsing edge cases",
                    "tests": [
                        "header_with_null_bytes",
                        "header_with_invalid_characters",
                        "oversized_header",
                        "duplicate_headers",
                        "invalid_header_line_endings"
                    ]
                },
                "method_parsing_edge_cases": {
                    "description": "Test HTTP method parsing edge cases",
                    "tests": [
                        "invalid_method",
                        "method_with_null_bytes",
                        "oversized_method",
                        "method_with_invalid_characters"
                    ]
                },
                "version_parsing_edge_cases": {
                    "description": "Test HTTP version parsing edge cases",
                    "tests": [
                        "invalid_version",
                        "version_with_null_bytes",
                        "version_with_invalid_characters",
                        "multiple_versions"
                    ]
                }
            },
            Protocol.TLS: {
                "handshake_edge_cases": {
                    "description": "Test TLS handshake edge cases",
                    "tests": [
                        "invalid_client_hello",
                        "client_hello_with_invalid_extensions",
                        "client_hello_with_invalid_cipher_suites",
                        "client_hello_with_invalid_compression_methods",
                        "client_hello_with_invalid_session_id",
                        "client_hello_with_oversized_data"
                    ]
                },
                "certificate_parsing_edge_cases": {
                    "description": "Test certificate parsing edge cases",
                    "tests": [
                        "invalid_certificate_format",
                        "certificate_with_invalid_extensions",
                        "certificate_with_invalid_signature_algorithms",
                        "certificate_with_oversized_data"
                    ]
                }
            }
        }
        
        # Version fingerprint database (simplified)
        self.version_signatures = {
            Protocol.SSH: {
                "OpenSSH_8.9p1": {
                    "edge_case_responses": {
                        "invalid_version_string": "protocol_mismatch",
                        "multiple_version_strings": "protocol_mismatch",
                        "version_string_with_nulls": "protocol_mismatch"
                    },
                    "timeout_behavior": "connection_closed",
                    "error_handling": "disconnect_with_error"
                },
                "OpenSSH_8.9p1_2": {
                    "edge_case_responses": {
                        "invalid_version_string": "protocol_mismatch",
                        "multiple_version_strings": "protocol_mismatch",
                        "version_string_with_nulls": "protocol_mismatch"
                    },
                    "timeout_behavior": "connection_closed",
                    "error_handling": "disconnect_with_error"
                },
                "OpenSSH_8.9p1_3": {
                    "edge_case_responses": {
                        "invalid_version_string": "protocol_mismatch",
                        "multiple_version_strings": "protocol_mismatch",
                        "version_string_with_nulls": "protocol_mismatch"
                    },
                    "timeout_behavior": "connection_closed",
                    "error_handling": "disconnect_with_error"
                }
            },
            Protocol.HTTP: {
                "Apache_2.4": {
                    "edge_case_responses": {
                        "header_with_null_bytes": "bad_request",
                        "header_with_invalid_characters": "bad_request",
                        "oversized_header": "request_header_fields_too_large"
                    },
                    "timeout_behavior": "connection_timeout",
                    "error_handling": "error_400"
                }
            }
        }
    
    def probe_rfc_compliance(self, target_host: str, target_port: int, 
                           protocol: Protocol) -> RFCComplianceAnalysis:
        """Probe RFC compliance for specific protocol."""
        start_time = time.time()
        
        try:
            # Get RFC tests for protocol
            protocol_tests = self.rfc_tests.get(protocol, {})
            
            # Execute all tests
            all_results = []
            
            for test_category, test_info in protocol_tests.items():
                for test_name in test_info["tests"]:
                    result = self._execute_rfc_test(target_host, target_port, protocol, 
                                                   test_category, test_name)
                    if result:
                        all_results.append(result)
                        logger.debug(f"[RFC] {protocol.value} {test_category} {test_name}: {result.compliance_level}")
            
            # Analyze results
            version_fingerprint = self._analyze_version_fingerprint(all_results, protocol)
            compliance_score = self._calculate_compliance_score(all_results)
            security_assessment = self._assess_protocol_security(all_results, protocol)
            recommendations = self._generate_recommendations(all_results, protocol)
            
            return RFCComplianceAnalysis(
                target_host=target_host,
                target_port=target_port,
                protocol=protocol.value,
                probe_results=all_results,
                version_fingerprint=version_fingerprint,
                compliance_score=compliance_score,
                security_assessment=security_assessment,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"[RFC] Compliance probing failed: {e}")
            return RFCComplianceAnalysis(
                target_host=target_host,
                target_port=target_port,
                protocol=protocol.value,
                probe_results=[],
                version_fingerprint={},
                compliance_score=0.0,
                security_assessment=[f"Analysis failed: {e}"],
                recommendations=[]
            )
    
    def _execute_rfc_test(self, target_host: str, target_port: int, 
                          protocol: Protocol, test_category: str, test_name: str) -> Optional[RFCProbeResult]:
        """Execute specific RFC compliance test."""
        try:
            if protocol == Protocol.SSH:
                return self._execute_ssh_rfc_test(target_host, target_port, test_category, test_name)
            elif protocol == Protocol.HTTP:
                return self._execute_http_rfc_test(target_host, target_port, test_category, test_name)
            elif protocol == Protocol.TLS:
                return self._execute_tls_rfc_test(target_host, target_port, test_category, test_name)
            else:
                return None
                
        except Exception as e:
            logger.debug(f"[RFC] {protocol.value} {test_category} {test_name} failed: {e}")
            return None
    
    def _execute_ssh_rfc_test(self, target_host: str, target_port: int, 
                           test_category: str, test_name: str) -> Optional[RFCProbeResult]:
        """Execute SSH RFC compliance test."""
        try:
            if test_category == "protocol_version_negotiation":
                return self._test_ssh_version_negotiation(target_host, target_port, test_name)
            elif test_category == "key_exchange_edge_cases":
                return self._test_ssh_key_exchange(target_host, target_port, test_name)
            elif test_category == "message_sequence_edge_cases":
                return self._test_ssh_message_sequence(target_host, target_port, test_name)
            elif test_category == "authentication_edge_cases":
                return self._test_ssh_authentication(target_host, target_port, test_name)
            else:
                return None
                
        except Exception as e:
            logger.debug(f"[RFC] SSH test failed: {e}")
            return None
    
    def _test_ssh_version_negotiation(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test SSH version negotiation edge cases."""
        try:
            # Create SSH version string based on test
            if test_name == "invalid_version_string":
                version_string = "SSH-9.99-invalid"
            elif test_name == "multiple_version_strings":
                version_string = "SSH-2.0-SSH-2.0"
            elif test_name == "version_string_with_nulls":
                version_string = "SSH-2.0\x00\x00invalid"
            elif test_name == "version_string_overflow":
                version_string = "SSH-2.0-" + "A" * 1000
            else:
                return None
            
            # Connect and send version string
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                sock.send(version_string.encode())
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_ssh_version_response(response)
                version_hints = self._extract_ssh_version_hints(response)
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=version_hints,
                    confidence=0.8
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Connection failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] SSH version test failed: {e}")
            return None
    
    def _test_ssh_key_exchange(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test SSH key exchange edge cases."""
        # This is a simplified implementation
        # Real implementation would need to handle SSH protocol details
        
        try:
            # Create SSH key exchange message based on test
            if test_name == "invalid_key_exchange":
                # Send invalid key exchange message
                key_exchange_data = b"\x00\x00\x00\x00\x00"  # Invalid key exchange
            elif test_name == "multiple_key_exchange_requests":
                # Send multiple key exchange requests
                key_exchange_data = b"\x00\x00\x00\x00" * 3
            elif test_name == "key_exchange_with_invalid_data":
                # Send key exchange with invalid data
                key_exchange_data = b"\x00\x00" + b"\xFF" * 1000
            elif test_name == "key_exchange_timeout":
                # Send key exchange and wait for timeout
                key_exchange_data = b"\x00\x00\x00\x00"
            else:
                return None
            
            # Connect and send key exchange
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                
                # Send SSH protocol identifier first
                sock.send(b"SSH-2.0-OpenSSH_8.9p1")
                
                # Send key exchange data
                sock.send(key_exchange_data)
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_ssh_key_exchange_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.7
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Key exchange failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] SSH key exchange test failed: {e}")
            return None
    
    def _test_ssh_message_sequence(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test SSH message sequence edge cases."""
        # This is a simplified implementation
        # Real implementation would need to handle SSH protocol details
        
        try:
            # Create SSH message based on test
            if test_name == "out_of_order_messages":
                # Send messages out of order
                message_data = b"\x00\x00\x00\x00"  # Invalid sequence
            elif test_name == "duplicate_messages":
                # Send duplicate messages
                message_data = b"\x00\x00\x00\x00" * 2
            elif test_name == "message_with_invalid_length":
                # Send message with invalid length
                message_data = b"\xFF\xFF\xFF\xFF"  # Invalid length
            elif test_name == "message_with_invalid_padding":
                # Send message with invalid padding
                message_data = b"\x00\x00\x00\x00" + b"\xFF" * 1000
            elif test_name == "message_sequence_overflow":
                # Send message sequence overflow
                message_data = b"\x00\x00\x00\x00" * 1000
            else:
                return None
            
            # Connect and send messages
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                
                # Send SSH protocol identifier first
                sock.send(b"SSH-2.0-OpenSSH_8.9p1")
                
                # Send message data
                sock.send(message_data)
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_ssh_message_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.7
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Message sequence failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] SSH message test failed: {e}")
            return None
    
    def _test_ssh_authentication(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test SSH authentication edge cases."""
        # This is a simplified implementation
        # Real implementation would need to handle SSH protocol details
        
        try:
            # Create authentication request based on test
            if test_name == "invalid_authentication_method":
                # Send invalid authentication method
                auth_data = b"\x00\x00\x00\x00"  # Invalid method
            elif test_name == "multiple_authentication_attempts":
                # Send multiple authentication attempts
                auth_data = b"\x00\x00\x00\x00" * 3
            elif test_name == "authentication_with_invalid_data":
                # Send authentication with invalid data
                auth_data = b"\x00\x00\x00\x00" + b"\xFF" * 1000
            elif test_name == "authentication_buffer_overflow":
                # Send authentication buffer overflow
                auth_data = b"\x00\x00\x00\x00" * 1000
            else:
                return None
            
            # Connect and send authentication
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                
                # Send SSH protocol identifier first
                sock.send(b"SSH-2.0-OpenSSH_8.9p1")
                
                # Send authentication data
                sock.send(auth_data)
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_ssh_auth_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.6
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.SSH.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Authentication failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] SSH authentication test failed: {e}")
            return None
    
    def _execute_http_rfc_test(self, target_host: str, target_port: int, 
                           test_category: str, test_name: str) -> Optional[RFCProbeResult]:
        """Execute HTTP RFC compliance test."""
        try:
            # Create HTTP request based on test
            if test_category == "header_parsing_edge_cases":
                return self._test_http_header_parsing(target_host, target_port, test_name)
            elif test_category == "method_parsing_edge_cases":
                return self._test_http_method_parsing(target_host, target_port, test_name)
            elif test_category == "version_parsing_edge_cases":
                return self._test_http_version_parsing(target_host, target_port, test_name)
            else:
                return None
                
        except Exception as e:
            logger.debug(f"[RFC] HTTP test failed: {e}")
            return None
    
    def _test_http_header_parsing(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test HTTP header parsing edge cases."""
        try:
            # Create HTTP request with problematic headers
            if test_name == "header_with_null_bytes":
                headers = "Host: " + target_host + "\x00\x00Invalid"
            elif test_name == "header_with_invalid_characters":
                headers = "Host: " + target_host + "\xFF\xFFInvalid"
            elif test_name == "oversized_header":
                headers = "Host: " + target_host + "\r\n" + "X-Oversized: " + "A" * 10000
            elif test_name == "duplicate_headers":
                headers = "Host: " + target_host + "\r\n" + "Host: " + target_host
            elif test_name == "invalid_header_line_endings":
                headers = "Host: " + target_host + "\n\nInvalid"
            else:
                return None
            
            request = f"GET / HTTP/1.1\r\n{headers}\r\n\r\n"
            
            # Send request
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                sock.send(request.encode())
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_http_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.HTTP.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.8
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.HTTP.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Header test failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] HTTP header test failed: {e}")
            return None
    
    def _test_http_method_parsing(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test HTTP method parsing edge cases."""
        try:
            # Create HTTP request with problematic method
            if test_name == "invalid_method":
                method = "INVALID_METHOD"
            elif test_name == "method_with_null_bytes":
                method = "GET\x00\x00"
            elif test_name == "oversized_method":
                method = "A" * 1000
            elif test_name == "method_with_invalid_characters":
                method = "GET\xFF\xFF"
            else:
                return None
            
            request = f"{method} / HTTP/1.1\r\nHost: {target_host}\r\n\r\n"
            
            # Send request
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                sock.send(request.encode())
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_http_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.HTTP.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.8
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.HTTP.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Method test failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] HTTP method test failed: {e}")
            return None
    
    def _test_http_version_parsing(self, target_host: str, target_port: int, test_name: str) -> Optional[RFCProbeResult]:
        """Test HTTP version parsing edge cases."""
        try:
            # Create HTTP request with problematic version
            if test_name == "invalid_version":
                version = "HTTP/9.99"
            elif test_name == "version_with_null_bytes":
                version = "HTTP/1.1\x00\x00"
            elif test_name == "version_with_invalid_characters":
                version = "HTTP/1.1\xFF\xFF"
            elif test_name == "multiple_versions":
                version = "HTTP/1.1 HTTP/1.1"
            else:
                return None
            
            request = f"GET / {version}\r\nHost: {target_host}\r\n\r\n"
            
            # Send request
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                sock.send(request.encode())
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_http_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.HTTP.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.8
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.HTTP.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"Version test failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] HTTP version test failed: {e}")
            return None
    
    def _execute_tls_rfc_test(self, target_host: str, target_port: int, 
                           test_category: str, test_name: str) -> Optional[RFCProbeResult]:
        """Execute TLS RFC compliance test."""
        # This is a simplified implementation
        # Real implementation would need to handle TLS protocol details
        
        try:
            # Create TLS ClientHello with problematic data
            if test_name == "invalid_client_hello":
                # Send invalid ClientHello
                client_hello_data = b"\x00\x00\x00\x00"  # Invalid handshake
            elif test_name == "client_hello_with_invalid_extensions":
                # Send ClientHello with invalid extensions
                client_hello_data = b"\x00\x00\x00\x00" + b"\xFF" * 1000
            elif test_name == "client_hello_with_invalid_cipher_suites":
                # Send ClientHello with invalid cipher suites
                client_hello_data = b"\x00\x00\x00\x00"
            elif test_name == "client_hello_with_invalid_compression_methods":
                # Send ClientHello with invalid compression methods
                client_hello_data = b"\x00\x00\x00\x00"
            elif test_name == "client_hello_with_invalid_session_id":
                # Send ClientHello with invalid session ID
                client_hello_data = b"\x00\x00\x00\x00"
            elif test_name == "client_hello_with_oversized_data":
                # Send ClientHello with oversized data
                client_hello_data = b"\x00\x00\x00\x00" + b"\xFF" * 10000
            else:
                return None
            
            # Connect and send ClientHello
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                sock.send(client_hello_data)
                
                # Read response
                response = sock.recv(1024)
                response_time = (time.time() - start_time) * 1000
                
                sock.close()
                
                # Analyze response
                compliance_level = self._analyze_tls_response(response)
                
                return RFCProbeResult(
                    protocol=Protocol.TLS.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=True,
                    response_time_ms=response_time,
                    response_data=response,
                    compliance_level=compliance_level,
                    version_hints=[],
                    confidence=0.7
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return RFCProbeResult(
                    protocol=Protocol.TLS.value,
                    test_type=test_category,
                    test_name=test_name,
                    success=False,
                    response_time_ms=0.0,
                    response_data=None,
                    compliance_level="connection_failed",
                    version_hints=[f"TLS test failed: {e}"],
                    confidence=0.0
                )
                
        except Exception as e:
            logger.debug(f"[RFC] TLS test failed: {e}")
            return None
    
    def _analyze_ssh_version_response(self, response: bytes) -> str:
        """Analyze SSH version negotiation response."""
        if not response:
            return "no_response"
        
        # Look for SSH protocol mismatch
        if b"Protocol mismatch" in response:
            return "strict_compliance"
        elif b"Protocol major versions differ" in response:
            return "version_mismatch"
        elif b"Bad protocol version" in response:
            return "invalid_version"
        else:
            return "standard_compliance"
    
    def _analyze_ssh_key_exchange_response(self, response: bytes) -> str:
        """Analyze SSH key exchange response."""
        if not response:
            return "no_response"
        
        # Look for key exchange errors
        if b"Invalid key exchange" in response:
            return "strict_compliance"
        elif b"Key exchange failed" in response:
            return "key_exchange_failed"
        else:
            return "standard_compliance"
    
    def _analyze_ssh_message_response(self, response: bytes) -> str:
        """Analyze SSH message sequence response."""
        if not response:
            return "no_response"
        
        # Look for message sequence errors
        if b"Invalid message" in response:
            return "strict_compliance"
        elif b"Message sequence error" in response:
            return "sequence_error"
        else:
            return "standard_compliance"
    
    def _analyze_ssh_auth_response(self, response: bytes) -> str:
        """Analyze SSH authentication response."""
        if not response:
            return "no_response"
        
        # Look for authentication errors
        if b"Invalid authentication method" in response:
            return "strict_compliance"
        elif b"Authentication failed" in response:
            return "auth_failed"
        else:
            return "standard_compliance"
    
    def _analyze_http_response(self, response: bytes) -> str:
        """Analyze HTTP response."""
        if not response:
            return "no_response"
        
        # Look for HTTP status codes
        if b"400 Bad Request" in response:
            return "strict_compliance"
        elif b"411 Length Required" in response:
            return "strict_compliance"
        elif b"414 Request-URI Too Long" in response:
            return "strict_compliance"
        elif b"500 Internal Server Error" in response:
            return "server_error"
        else:
            return "standard_compliance"
    
    def _analyze_tls_response(self, response: bytes) -> str:
        """Analyze TLS response."""
        if not response:
            return "no_response"
        
        # Look for TLS handshake errors
        if b"decode error" in response:
            return "strict_compliance"
        elif b"handshake failure" in response:
            return "handshake_failed"
        elif b"unsupported protocol" in response:
            return "protocol_error"
        else:
            return "standard_compliance"
    
    def _extract_ssh_version_hints(self, response: bytes) -> List[str]:
        """Extract SSH version hints from response."""
        hints = []
        
        # Look for version information in response
        if b"OpenSSH" in response:
            hints.append("OpenSSH_detected")
        
        # Look for version numbers
        import re
        version_match = re.search(r"OpenSSH[_\s-]+(\d+\.\d+)", response.decode('utf-8', errors='ignore'))
        if version_match:
            hints.append(f"OpenSSH_{version_match.group(1)}")
        
        return hints
    
    def _analyze_version_fingerprint(self, results: List[RFCProbeResult], protocol: Protocol) -> Dict[str, Any]:
        """Analyze version fingerprint from RFC compliance results."""
        fingerprint = {
            "protocol": protocol.value,
            "compliance_profile": {},
            "version_indicators": [],
            "patch_level_hints": []
        }
        
        # Group results by compliance level
        compliance_levels = {}
        for result in results:
            level = result.compliance_level
            if level not in compliance_levels:
                compliance_levels[level] = []
            compliance_levels[level].append(result)
        
        # Analyze compliance patterns
        for level, level_results in compliance_levels.items():
            fingerprint["compliance_profile"][level] = {
                "count": len(level_results),
                "average_response_time": sum(r.response_time_ms for r in level_results) / len(level_results),
                "success_rate": sum(1 for r in level_results if r.success) / len(level_results)
            }
        
        # Extract version indicators
        for result in results:
            if result.version_hints:
                fingerprint["version_indicators"].extend(result.version_hints)
        
        # Determine patch level hints
        if "strict_compliance" in compliance_levels:
            fingerprint["patch_level_hints"].append("fully_patched")
        elif len(compliance_levels.get("standard_compliance", [])) > 0:
            fingerprint["patch_level_hints"].append("likely_patched")
        else:
            fingerprint["patch_level_hints"].append("unknown_patch_level")
        
        return fingerprint
    
    def _calculate_compliance_score(self, results: List[RFCProbeResult]) -> float:
        """Calculate RFC compliance score."""
        if not results:
            return 0.0
        
        # Score based on compliance levels
        compliance_scores = {
            "strict_compliance": 1.0,
            "standard_compliance": 0.8,
            "protocol_error": 0.3,
            "handshake_failed": 0.2,
            "connection_failed": 0.1,
            "no_response": 0.0
        }
        
        total_score = 0
        for result in results:
            score = compliance_scores.get(result.compliance_level, 0.0)
            total_score += score
        
        return min(1.0, total_score / len(results))
    
    def _assess_protocol_security(self, results: List[RFCProbeResult], protocol: Protocol) -> List[str]:
        """Assess protocol security based on RFC compliance."""
        assessment = []
        
        # Check for strict compliance
        strict_compliance = [r for r in results if r.compliance_level == "strict_compliance"]
        if len(strict_compliance) > 0:
            assessment.append(f"{protocol.value} implementation appears RFC compliant")
        
        # Check for security issues
        non_compliant = [r for r in results if r.compliance_level not in ["strict_compliance", "standard_compliance"]]
        if len(non_compliant) > 0:
            assessment.append(f"{protocol.value} implementation has RFC compliance issues")
        
        # Protocol-specific assessments
        if protocol == Protocol.SSH:
            if any("key_exchange_failed" in r.compliance_level for r in results):
                assessment.append("SSH key exchange may be vulnerable")
        
        elif protocol == Protocol.HTTP:
            if any("server_error" in r.compliance_level for r in results):
                assessment.append("HTTP server may have security issues")
        
        return assessment
    
    def _generate_recommendations(self, results: List[RFCProbeResult], protocol: Protocol) -> List[str]:
        """Generate recommendations based on RFC compliance results."""
        recommendations = []
        
        # General recommendations
        recommendations.extend([
            f"Update {protocol.value} software to latest version",
            f"Monitor {protocol.value} service logs for unusual activity",
            f"Implement proper {protocol.value} security configurations"
        ])
        
        # Protocol-specific recommendations
        if protocol == Protocol.SSH:
            recommendations.extend([
                "Disable weak SSH algorithms and ciphers",
                "Implement SSH key-based authentication",
                "Use SSH bastion hosts for access control",
                "Regularly audit SSH configurations"
            ])
        
        elif protocol == Protocol.HTTP:
            recommendations.extend([
                "Implement proper HTTP security headers",
                "Use HTTPS for sensitive communications",
                "Regularly update web server software",
                "Implement web application firewall"
            ])
        
        return recommendations
    
    def generate_rfc_report(self, result: RFCComplianceAnalysis) -> str:
        """Generate human-readable RFC compliance report."""
        report = []
        report.append("RFC Compliance Protocol Fingerprinting Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Protocol: {result.protocol}")
        report.append(f"Compliance Score: {result.compliance_score:.2f}")
        report.append("")
        
        if result.version_fingerprint:
            report.append("Version Fingerprint:")
            report.append(f"  Protocol: {result.version_fingerprint.get('protocol', 'Unknown')}")
            report.append(f"  Version Indicators: {', '.join(result.version_fingerprint.get('version_indicators', []))}")
            report.append(f"  Patch Level: {', '.join(result.version_fingerprint.get('patch_level_hints', []))}")
            report.append("")
        
        if result.probe_results:
            report.append("RFC Compliance Tests:")
            for i, probe_result in enumerate(result.probe_results[:20]):  # Show first 20
                report.append(f"  {i+1}. {probe_result.test_type}.{probe_result.test_name}")
                report.append(f"     Compliance: {probe_result.compliance_level}")
                report.append(f"     Success: {probe_result.success}")
                report.append(f"     Response Time: {probe_result.response_time_ms:.1f}ms")
                if probe_result.version_hints:
                    report.append(f"     Version Hints: {', '.join(probe_result.version_hints)}")
            if len(result.probe_results) > 20:
                report.append(f"    ... and {len(result.probe_results) - 20} more tests")
            report.append("")
        
        if result.security_assessment:
            report.append("Security Assessment:")
            for assessment in result.security_assessment:
                report.append(f"  - {assessment}")
            report.append("")
        
        if result.recommendations:
            report.append("Recommendations:")
            for recommendation in result.recommendations:
                report.append(f"  - {recommendation}")
            report.append("")
        
        return "\n".join(report)

# Global instance
_rfc_prober = None

def get_rfc_prober() -> RFCComplianceProber:
    """Get global RFC compliance prober."""
    global _rfc_prober
    if _rfc_prober is None:
        _rfc_prober = RFCComplianceProber()
    return _rfc_prober

def probe_rfc_compliance(target_host: str, target_port: int, protocol: Protocol) -> RFCComplianceAnalysis:
    """Convenience function for RFC compliance probing."""
    prober = get_rfc_prober()
    return prober.probe_rfc_compliance(target_host, target_port, protocol)

def generate_rfc_report(result: RFCComplianceAnalysis) -> str:
    """Convenience function for RFC report generation."""
    prober = get_rfc_prober()
    return prober.generate_rfc_report(result)
