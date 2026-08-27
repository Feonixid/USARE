"""Advanced Deception Detection for Security Auditing.

Identifies honeytokens, deception environments, and simulated
services to distinguish legitimate production systems from security traps.

Uses behavior-based verification, response pattern analysis,
and consistency checking to detect deception infrastructure.
"""

import logging
import time
import random
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, TCP, UDP, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.deception_detection")

class DeceptionType(Enum):
    HONEYPOT = "honeypot"
    HONEYTOKEN = "honeytoken"
    SIMULATED_ENV = "simulated_environment"
    DECEPTION_NETWORK = "deception_network"
    FAKE_SERVICE = "fake_service"
    INCONSISTENT_RESPONSES = "inconsistent_responses"

@dataclass
class DeceptionDetectionConfig:
    """Configuration for deception detection."""
    enable_behavior_analysis: bool = True
    enable_consistency_checking: bool = True
    enable_response_pattern_analysis: bool = True
    enable_timing_analysis: bool = True
    probe_variations: int = 5
    consistency_threshold: float = 0.8
    behavior_threshold: float = 0.7
    timeout: float = 5.0

@dataclass
class DeceptionTestResult:
    """Result of individual deception test."""
    test_type: str
    probe_data: str
    response_received: bool
    response_time_ms: float
    response_data: Optional[bytes]
    consistency_score: float
    behavior_score: float
    deception_indicators: List[str]
    confidence: float
    is_deception: bool

@dataclass
class DeceptionAnalysisResult:
    """Comprehensive deception analysis result."""
    target_ip: str
    target_port: int
    deception_probability: float
    deception_type: Optional[str]
    deception_confidence: float
    behavior_profile: Dict[str, Any]
    consistency_analysis: Dict[str, Any]
    response_patterns: Dict[str, Any]
    recommendations: List[str]
    is_legitimate: bool

class DeceptionDetector:
    """Advanced deception detection engine."""
    
    def __init__(self, config: DeceptionDetectionConfig):
        self.config = config
        self.test_history = []
        self.behavior_baseline = {}
        
    def analyze_service_legitimacy(self, target_ip: str, target_port: int,
                                   service_type: str = "unknown") -> DeceptionAnalysisResult:
        """Analyze service for deception indicators."""
        test_results = []
        
        # 1. Behavior-based verification
        if self.config.enable_behavior_analysis:
            behavior_result = self._test_behavior_consistency(target_ip, target_port, service_type)
            test_results.append(behavior_result)
        
        # 2. Response consistency checking
        if self.config.enable_consistency_checking:
            consistency_result = self._test_response_consistency(target_ip, target_port, service_type)
            test_results.append(consistency_result)
        
        # 3. Response pattern analysis
        if self.config.enable_response_pattern_analysis:
            pattern_result = self._test_response_patterns(target_ip, target_port, service_type)
            test_results.append(pattern_result)
        
        # 4. Timing analysis
        if self.config.enable_timing_analysis:
            timing_result = self._test_timing_behavior(target_ip, target_port)
            test_results.append(timing_result)
        
        # Analyze all results
        analysis = self._analyze_deception_results(test_results)
        
        return DeceptionAnalysisResult(
            target_ip=target_ip,
            target_port=target_port,
            deception_probability=analysis["deception_probability"],
            deception_type=analysis["deception_type"],
            deception_confidence=analysis["confidence"],
            behavior_profile=analysis["behavior_profile"],
            consistency_analysis=analysis["consistency_analysis"],
            response_patterns=analysis["response_patterns"],
            recommendations=analysis["recommendations"],
            is_legitimate=analysis["is_legitimate"]
        )
    
    def _test_behavior_consistency(self, target_ip: str, target_port: int,
                                 service_type: str) -> DeceptionTestResult:
        """Test behavior consistency across different probes."""
        start_time = time.time()
        
        try:
            # Send varied probes to test behavior
            probe_results = []
            
            for i in range(self.config.probe_variations):
                probe_type = f"behavior_test_{i}"
                
                # Create different probe types
                if service_type.lower() in ["http", "https"]:
                    result = self._send_http_behavior_probe(target_ip, target_port, i)
                elif service_type.lower() in ["ssh"]:
                    result = self._send_ssh_behavior_probe(target_ip, target_port, i)
                elif service_type.lower() in ["ftp"]:
                    result = self._send_ftp_behavior_probe(target_ip, target_port, i)
                else:
                    result = self._send_generic_behavior_probe(target_ip, target_port, i)
                
                probe_results.append(result)
                
                # Small delay between probes
                if i < self.config.probe_variations - 1:
                    time.sleep(0.1)
            
            # Analyze behavior consistency
            consistency_score = self._calculate_behavior_consistency(probe_results)
            behavior_score = self._calculate_behavior_score(probe_results)
            deception_indicators = self._identify_deception_indicators(probe_results)
            
            return DeceptionTestResult(
                test_type="behavior_consistency",
                probe_data=f"varied_probes_{self.config.probe_variations}",
                response_received=any(r.response_received for r in probe_results),
                response_time_ms=sum(r.response_time_ms for r in probe_results if r.response_received) / len(probe_results),
                response_data=None,
                consistency_score=consistency_score,
                behavior_score=behavior_score,
                deception_indicators=deception_indicators,
                confidence=0.8,
                is_deception=consistency_score < self.config.consistency_threshold
            )
            
        except Exception as e:
            logger.error(f"[Deception] Behavior test failed: {e}")
            return DeceptionTestResult(
                test_type="behavior_consistency",
                probe_data="error",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                consistency_score=0.0,
                behavior_score=0.0,
                deception_indicators=["test_error"],
                confidence=0.0,
                is_deception=True
            )
    
    def _test_response_consistency(self, target_ip: str, target_port: int,
                                service_type: str) -> DeceptionTestResult:
        """Test response consistency across multiple identical requests."""
        start_time = time.time()
        
        try:
            # Send identical probes multiple times
            responses = []
            
            for i in range(self.config.probe_variations):
                # Create identical probe
                if service_type.lower() in ["http", "https"]:
                    response = self._send_identical_http_probe(target_ip, target_port)
                elif service_type.lower() in ["ssh"]:
                    response = self._send_identical_ssh_probe(target_ip, target_port)
                elif service_type.lower() in ["ftp"]:
                    response = self._send_identical_ftp_probe(target_ip, target_port)
                else:
                    response = self._send_identical_generic_probe(target_ip, target_port)
                
                responses.append(response)
                
                # Small delay between probes
                if i < self.config.probe_variations - 1:
                    time.sleep(0.2)
            
            # Analyze consistency
            consistency_score = self._calculate_response_consistency(responses)
            deception_indicators = self._identify_consistency_deception(responses)
            
            return DeceptionTestResult(
                test_type="response_consistency",
                probe_data=f"identical_probes_{self.config.probe_variations}",
                response_received=any(r is not None for r in responses),
                response_time_ms=sum(r.response_time_ms if r else 0 for r in responses) / len(responses),
                response_data=None,
                consistency_score=consistency_score,
                behavior_score=0.0,
                deception_indicators=deception_indicators,
                confidence=0.8,
                is_deception=consistency_score < self.config.consistency_threshold
            )
            
        except Exception as e:
            logger.error(f"[Deception] Consistency test failed: {e}")
            return DeceptionTestResult(
                test_type="response_consistency",
                probe_data="error",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                consistency_score=0.0,
                behavior_score=0.0,
                deception_indicators=["test_error"],
                confidence=0.0,
                is_deception=True
            )
    
    def _test_response_patterns(self, target_ip: str, target_port: int,
                              service_type: str) -> DeceptionTestResult:
        """Test response patterns for deception indicators."""
        start_time = time.time()
        
        try:
            # Send probes designed to elicit pattern responses
            pattern_results = []
            
            # Test 1: Malformed request
            malformed_result = self._send_malformed_probe(target_ip, target_port, service_type)
            pattern_results.append(malformed_result)
            
            # Test 2: Oversized request
            oversized_result = self._send_oversized_probe(target_ip, target_port, service_type)
            pattern_results.append(oversized_result)
            
            # Test 3: Invalid method/command
            invalid_result = self._send_invalid_method_probe(target_ip, target_port, service_type)
            pattern_results.append(invalid_result)
            
            # Test 4: Timeout test
            timeout_result = self._send_timeout_probe(target_ip, target_port, service_type)
            pattern_results.append(timeout_result)
            
            # Analyze patterns
            pattern_score = self._calculate_pattern_score(pattern_results)
            deception_indicators = self._identify_pattern_deception(pattern_results)
            
            return DeceptionTestResult(
                test_type="response_patterns",
                probe_data="pattern_analysis_probes",
                response_received=any(r.response_received for r in pattern_results),
                response_time_ms=sum(r.response_time_ms for r in pattern_results if r.response_received) / len(pattern_results),
                response_data=None,
                consistency_score=0.0,
                behavior_score=pattern_score,
                deception_indicators=deception_indicators,
                confidence=0.7,
                is_deception=len(deception_indicators) > 0
            )
            
        except Exception as e:
            logger.error(f"[Deception] Pattern test failed: {e}")
            return DeceptionTestResult(
                test_type="response_patterns",
                probe_data="error",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                consistency_score=0.0,
                behavior_score=0.0,
                deception_indicators=["test_error"],
                confidence=0.0,
                is_deception=True
            )
    
    def _test_timing_behavior(self, target_ip: str, target_port: int) -> DeceptionTestResult:
        """Test timing behavior for deception indicators."""
        start_time = time.time()
        
        try:
            # Send probes with different timing patterns
            timing_results = []
            
            # Test 1: Rapid succession
            rapid_result = self._send_rapid_probes(target_ip, target_port)
            timing_results.append(rapid_result)
            
            # Test 2: Slow connection
            slow_result = self._send_slow_probe(target_ip, target_port)
            timing_results.append(slow_result)
            
            # Test 3: Reconnection test
            reconnect_result = self._send_reconnection_test(target_ip, target_port)
            timing_results.append(reconnect_result)
            
            # Analyze timing behavior
            timing_score = self._calculate_timing_score(timing_results)
            deception_indicators = self._identify_timing_deception(timing_results)
            
            return DeceptionTestResult(
                test_type="timing_behavior",
                probe_data="timing_analysis_probes",
                response_received=any(r.response_received for r in timing_results),
                response_time_ms=sum(r.response_time_ms for r in timing_results if r.response_received) / len(timing_results),
                response_data=None,
                consistency_score=0.0,
                behavior_score=timing_score,
                deception_indicators=deception_indicators,
                confidence=0.6,
                is_deception=len(deception_indicators) > 0
            )
            
        except Exception as e:
            logger.error(f"[Deception] Timing test failed: {e}")
            return DeceptionTestResult(
                test_type="timing_behavior",
                probe_data="error",
                response_received=False,
                response_time_ms=0,
                response_data=None,
                consistency_score=0.0,
                behavior_score=0.0,
                deception_indicators=["test_error"],
                confidence=0.0,
                is_deception=True
            )
    
    def _send_http_behavior_probe(self, target_ip: str, target_port: int, 
                               variation: int) -> Dict[str, Any]:
        """Send HTTP behavior probe with variation."""
        try:
            # Different HTTP requests for behavior testing
            requests = [
                f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: curl/7.68.0\r\n\r\n",
                f"POST / HTTP/1.1\r\nHost: {target_ip}\r\nContent-Length: 0\r\n\r\n",
                f"GET /nonexistent{variation}.html HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                f"GET / HTTP/1.0\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            ]
            
            request = requests[variation % len(requests)]
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(request.encode())
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "request_type": request.split('\r\n')[0].split(' ')[0]
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "request_type": request.split('\r\n')[0].split(' ')[0]
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "request_type": request.split('\r\n')[0].split(' ')[0],
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "request_type": "http_behavior",
                "error": str(e)
            }
    
    def _send_ssh_behavior_probe(self, target_ip: str, target_port: int,
                              variation: int) -> Dict[str, Any]:
        """Send SSH behavior probe with variation."""
        try:
            # Different SSH probes for behavior testing
            probes = [
                b"SSH-2.0-OpenSSH_7.4\r\n",
                b"SSH-2.0-OpenSSH_8.0\r\n",
                b"SSH-1.99-OpenSSH_7.4\r\n",
                b"SSH-2.0-PuTTY_Release_0.76\r\n",
                b"INVALID-PROTOCOL-1.0\r\n"
            ]
            
            probe = probes[variation % len(probes)]
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(probe)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_type": "ssh_behavior"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_type": "ssh_behavior"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_type": "ssh_behavior",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_type": "ssh_behavior",
                "error": str(e)
            }
    
    def _send_ftp_behavior_probe(self, target_ip: str, target_port: int,
                              variation: int) -> Dict[str, Any]:
        """Send FTP behavior probe with variation."""
        try:
            # Different FTP commands for behavior testing
            commands = [
                b"HELP\r\n",
                b"USER anonymous\r\n",
                b"PASS guest@\r\n",
                b"LIST\r\n",
                b"SYST\r\n"
            ]
            
            command = commands[variation % len(commands)]
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(command)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "command": command.decode().strip()
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "command": command.decode().strip()
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "command": command.decode().strip(),
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "command": "ftp_behavior",
                "error": str(e)
            }
    
    def _send_generic_behavior_probe(self, target_ip: str, target_port: int,
                                 variation: int) -> Dict[str, Any]:
        """Send generic behavior probe with variation."""
        try:
            # Different generic probes
            probes = [
                b"\x00" * 64,  # Null bytes
                b"A" * 64,  # Repeated 'A'
                b"\xFF" * 64,  # Repeated 0xFF
                b"GET / HTTP/1.1\r\n\r\n",  # HTTP probe
                b"SSH-2.0-Test\r\n"  # SSH probe
            ]
            
            probe = probes[variation % len(probes)]
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(probe)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_type": "generic_behavior"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_type": "generic_behavior"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_type": "generic_behavior",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_type": "generic_behavior",
                "error": str(e)
            }
    
    def _send_identical_http_probe(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send identical HTTP probe for consistency testing."""
        try:
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(request.encode())
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "request_hash": hashlib.md5(request.encode()).hexdigest()
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "request_hash": hashlib.md5(request.encode()).hexdigest()
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "request_hash": hashlib.md5(request.encode()).hexdigest(),
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "request_hash": None,
                "error": str(e)
            }
    
    def _send_identical_ssh_probe(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send identical SSH probe for consistency testing."""
        try:
            probe = b"SSH-2.0-OpenSSH_7.4\r\n"
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(probe)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_hash": hashlib.md5(probe).hexdigest()
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_hash": hashlib.md5(probe).hexdigest()
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_hash": hashlib.md5(probe).hexdigest(),
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_hash": None,
                "error": str(e)
            }
    
    def _send_identical_ftp_probe(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send identical FTP probe for consistency testing."""
        try:
            command = b"HELP\r\n"
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(command)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "command_hash": hashlib.md5(command).hexdigest()
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "command_hash": hashlib.md5(command).hexdigest()
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "command_hash": hashlib.md5(command).hexdigest(),
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "command_hash": None,
                "error": str(e)
            }
    
    def _send_identical_generic_probe(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send identical generic probe for consistency testing."""
        try:
            probe = b"TEST_PROBE_" + str(random.randint(1000, 9999)).encode()
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(probe)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_hash": hashlib.md5(probe).hexdigest()
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_hash": hashlib.md5(probe).hexdigest()
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_hash": hashlib.md5(probe).hexdigest(),
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_hash": None,
                "error": str(e)
            }
    
    def _send_malformed_probe(self, target_ip: str, target_port: int,
                            service_type: str) -> Dict[str, Any]:
        """Send malformed probe to test error handling."""
        try:
            if service_type.lower() in ["http", "https"]:
                # Malformed HTTP
                malformed_request = b"GET / HTTP/9.9\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
            else:
                # Generic malformed
                malformed_request = b"\x00\xFF" * 32
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(malformed_request)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_type": "malformed"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_type": "malformed"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_type": "malformed",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_type": "malformed",
                "error": str(e)
            }
    
    def _send_oversized_probe(self, target_ip: str, target_port: int,
                            service_type: str) -> Dict[str, Any]:
        """Send oversized probe to test buffer handling."""
        try:
            if service_type.lower() in ["http", "https"]:
                # Oversized HTTP request
                oversized_request = b"GET /" + b"A" * 2000 + b" HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
            else:
                # Generic oversized
                oversized_request = b"A" * 5000
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(oversized_request)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_type": "oversized"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_type": "oversized"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_type": "oversized",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_type": "oversized",
                "error": str(e)
            }
    
    def _send_invalid_method_probe(self, target_ip: str, target_port: int,
                               service_type: str) -> Dict[str, Any]:
        """Send invalid method/command to test error handling."""
        try:
            if service_type.lower() in ["http", "https"]:
                # Invalid HTTP method
                invalid_request = b"INVALID / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
            elif service_type.lower() in ["ssh"]:
                # Invalid SSH protocol
                invalid_request = b"SSH-9.9-Invalid\r\n"
            elif service_type.lower() in ["ftp"]:
                # Invalid FTP command
                invalid_request = b"INVALID_COMMAND\r\n"
            else:
                # Generic invalid
                invalid_request = b"\xFF\xFE" * 32
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(invalid_request)
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_type": "invalid_method"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_type": "invalid_method"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_type": "invalid_method",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_type": "invalid_method",
                "error": str(e)
            }
    
    def _send_timeout_probe(self, target_ip: str, target_port: int,
                          service_type: str) -> Dict[str, Any]:
        """Send timeout test probe."""
        try:
            # Normal request with long timeout
            if service_type.lower() in ["http", "https"]:
                request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            else:
                request = b"TIMEOUT_TEST_PROBE"
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout * 2)  # Longer timeout
            
            try:
                sock.connect((target_ip, target_port))
                sock.send(request.encode() if isinstance(request, str) else request)
                
                # Wait for response or timeout
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "response_data": response,
                    "probe_type": "timeout_test"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "response_data": None,
                    "probe_type": "timeout_test"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "response_data": None,
                    "probe_type": "timeout_test",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "response_data": None,
                "probe_type": "timeout_test",
                "error": str(e)
            }
    
    def _send_rapid_probes(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send rapid succession probes."""
        try:
            responses = []
            
            for i in range(5):
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)  # Short timeout
                
                try:
                    sock.connect((target_ip, target_port))
                    sock.send(b"RAPID_TEST")
                    response = sock.recv(1024)
                    response_time = (time.time() - start_time) * 1000
                    sock.close()
                    
                    responses.append({
                        "response_received": True,
                        "response_time_ms": response_time,
                        "iteration": i
                    })
                    
                except socket.timeout:
                    response_time = (time.time() - start_time) * 1000
                    sock.close()
                    
                    responses.append({
                        "response_received": False,
                        "response_time_ms": response_time,
                        "iteration": i
                    })
                except Exception:
                    sock.close()
            
            return {
                "response_received": any(r["response_received"] for r in responses),
                "response_time_ms": sum(r["response_time_ms"] for r in responses) / len(responses),
                "responses": responses,
                "probe_type": "rapid_succession"
            }
            
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "responses": [],
                "probe_type": "rapid_succession",
                "error": str(e)
            }
    
    def _send_slow_probe(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send slow connection probe."""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout * 3)  # Very long timeout
            
            try:
                sock.connect((target_ip, target_port))
                
                # Send data very slowly
                for i in range(10):
                    sock.send(b"SLOW_DATA")
                    time.sleep(0.5)
                
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                sock.close()
                
                return {
                    "response_received": True,
                    "response_time_ms": response_time,
                    "probe_type": "slow_connection"
                }
                
            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": response_time,
                    "probe_type": "slow_connection"
                }
            except Exception as e:
                sock.close()
                return {
                    "response_received": False,
                    "response_time_ms": 0,
                    "probe_type": "slow_connection",
                    "error": str(e)
                }
            
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "probe_type": "slow_connection",
                "error": str(e)
            }
    
    def _send_reconnection_test(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Send reconnection behavior test."""
        try:
            connections = []
            
            for i in range(3):
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                
                try:
                    sock.connect((target_ip, target_port))
                    sock.send(b"RECONNECT_TEST")
                    response = sock.recv(1024)
                    response_time = (time.time() - start_time) * 1000
                    sock.close()
                    
                    connections.append({
                        "response_received": True,
                        "response_time_ms": response_time,
                        "iteration": i
                    })
                    
                except socket.timeout:
                    response_time = (time.time() - start_time) * 1000
                    sock.close()
                    
                    connections.append({
                        "response_received": False,
                        "response_time_ms": response_time,
                        "iteration": i
                    })
                except Exception:
                    sock.close()
                
                time.sleep(1.0)  # Delay between reconnections
            
            return {
                "response_received": any(c["response_received"] for c in connections),
                "response_time_ms": sum(c["response_time_ms"] for c in connections) / len(connections),
                "connections": connections,
                "probe_type": "reconnection_behavior"
            }
            
        except Exception as e:
            return {
                "response_received": False,
                "response_time_ms": 0,
                "connections": [],
                "probe_type": "reconnection_behavior",
                "error": str(e)
            }
    
    def _calculate_behavior_consistency(self, probe_results: List[Dict[str, Any]]) -> float:
        """Calculate behavior consistency score."""
        if not probe_results:
            return 0.0
        
        # Extract response times
        response_times = [r["response_time_ms"] for r in probe_results if r.get("response_received", False)]
        
        if len(response_times) < 2:
            return 0.5
        
        # Calculate variance in response times
        mean_time = sum(response_times) / len(response_times)
        variance = sum((t - mean_time) ** 2 for t in response_times) / len(response_times)
        std_dev = variance ** 0.5
        
        # Lower variance = higher consistency
        consistency_score = max(0.0, 1.0 - (std_dev / mean_time))
        
        return consistency_score
    
    def _calculate_behavior_score(self, probe_results: List[Dict[str, Any]]) -> float:
        """Calculate overall behavior score."""
        if not probe_results:
            return 0.0
        
        # Score based on response patterns
        score = 0.0
        total_tests = len(probe_results)
        
        for result in probe_results:
            if result.get("response_received", False):
                score += 1.0
            
            # Check for error patterns
            if "error" in result:
                score -= 0.5
        
        return max(0.0, score / total_tests)
    
    def _calculate_response_consistency(self, responses: List[Optional[Dict[str, Any]]]) -> float:
        """Calculate response consistency score."""
        if not responses:
            return 0.0
        
        valid_responses = [r for r in responses if r is not None]
        
        if len(valid_responses) < 2:
            return 0.5
        
        # Check for identical responses
        first_response = valid_responses[0]
        identical_count = 0
        
        for response in valid_responses[1:]:
            if response == first_response:
                identical_count += 1
        
        consistency_score = identical_count / (len(valid_responses) - 1)
        
        return consistency_score
    
    def _calculate_pattern_score(self, pattern_results: List[Dict[str, Any]]) -> float:
        """Calculate pattern analysis score."""
        if not pattern_results:
            return 0.0
        
        score = 0.0
        total_tests = len(pattern_results)
        
        for result in pattern_results:
            if result.get("response_received", False):
                # Check for expected error patterns
                if result.get("probe_type") == "malformed":
                    # Legitimate services should return proper error codes
                    if result.get("response_data"):
                        response_str = result["response_data"].decode('utf-8', errors='ignore')
                        if "400" in response_str or "500" in response_str:
                            score += 1.0
                        else:
                            score += 0.5
                else:
                    score += 0.5
        
        return max(0.0, score / total_tests)
    
    def _calculate_timing_score(self, timing_results: List[Dict[str, Any]]) -> float:
        """Calculate timing behavior score."""
        if not timing_results:
            return 0.0
        
        score = 0.0
        total_tests = len(timing_results)
        
        for result in timing_results:
            if result.get("response_received", False):
                # Check for realistic timing patterns
                if result.get("probe_type") == "rapid_succession":
                    # Legitimate services might rate limit
                    if result.get("responses"):
                        response_received = sum(1 for r in result["responses"] if r.get("response_received"))
                        if response_received < 5:  # Some rate limiting is normal
                            score += 0.8
                        else:
                            score += 0.3
                elif result.get("probe_type") == "slow_connection":
                    # Legitimate services should handle slow connections
                    score += 0.7
                elif result.get("probe_type") == "reconnection_behavior":
                    # Check reconnection handling
                    if result.get("connections"):
                        successful_reconnects = sum(1 for c in result["connections"] if c.get("response_received"))
                        if successful_reconnects > 1:
                            score += 0.6
                        else:
                            score += 0.3
        
        return max(0.0, score / total_tests)
    
    def _identify_deception_indicators(self, test_results: List[Dict[str, Any]]) -> List[str]:
        """Identify deception indicators from test results."""
        indicators = []
        
        for result in test_results:
            if not result.get("response_received", False):
                indicators.append("no_response")
            
            # Check for overly consistent responses (possible honeypot)
            if result.get("consistency_score", 0.0) > 0.95:
                indicators.append("overly_consistent")
            
            # Check for suspicious timing patterns
            if result.get("behavior_score", 0.0) < 0.3:
                indicators.append("suspicious_timing")
        
        return indicators
    
    def _identify_consistency_deception(self, responses: List[Optional[Dict[str, Any]]]) -> List[str]:
        """Identify consistency-based deception indicators."""
        indicators = []
        
        if len(responses) > 0:
            # Check for identical responses (possible simulation)
            first_response = responses[0]
            if first_response:
                identical_count = sum(1 for r in responses[1:] if r == first_response)
                if identical_count == len(responses) - 1:
                    indicators.append("identical_responses")
            
            # Check for static response times (possible simulation)
            response_times = [r["response_time_ms"] for r in responses if r]
            if response_times:
                time_variance = sum((t - response_times[0]) ** 2 for t in response_times) / len(response_times)
                if time_variance < 10:  # Very low variance
                    indicators.append("static_timing")
        
        return indicators
    
    def _identify_pattern_deception(self, pattern_results: List[Dict[str, Any]]) -> List[str]:
        """Identify pattern-based deception indicators."""
        indicators = []
        
        for result in pattern_results:
            if result.get("response_received", False):
                # Check for generic error responses (possible honeypot)
                if result.get("response_data"):
                    response_str = result["response_data"].decode('utf-8', errors='ignore')
                    if response_str in ["Connection refused", "Access denied", "Not implemented"]:
                        indicators.append("generic_error_response")
                
                # Check for missing error details (possible simulation)
                if len(response_str) < 20:
                    indicators.append("minimal_error_response")
        
        return indicators
    
    def _identify_timing_deception(self, timing_results: List[Dict[str, Any]]) -> List[str]:
        """Identify timing-based deception indicators."""
        indicators = []
        
        for result in timing_results:
            if not result.get("response_received", False):
                continue
            
            # Check for immediate responses (possible simulation)
            if result.get("response_time_ms", 0) < 50:
                indicators.append("immediate_response")
            
            # Check for perfect consistency (possible simulation)
            if result.get("probe_type") == "rapid_succession":
                if result.get("responses"):
                    response_times = [r["response_time_ms"] for r in result["responses"] if r.get("response_received")]
                    if len(response_times) > 1:
                        time_variance = sum((t - response_times[0]) ** 2 for t in response_times) / len(response_times)
                        if time_variance < 5:
                            indicators.append("perfect_timing_consistency")
        
        return indicators
    
    def _analyze_deception_results(self, test_results: List[DeceptionTestResult]) -> Dict[str, Any]:
        """Analyze all deception test results."""
        if not test_results:
            return {
                "deception_probability": 1.0,
                "deception_type": "unknown",
                "confidence": 0.0,
                "behavior_profile": {},
                "consistency_analysis": {},
                "response_patterns": {},
                "recommendations": ["Unable to analyze - no test results"],
                "is_legitimate": False
            }
        
        # Calculate overall deception probability
        deception_scores = []
        confidence_scores = []
        all_indicators = []
        
        for result in test_results:
            if result.is_deception:
                deception_scores.append(1.0)
            else:
                deception_scores.append(0.0)
            
            confidence_scores.append(result.confidence)
            all_indicators.extend(result.deception_indicators)
        
        overall_deception_prob = sum(deception_scores) / len(deception_scores)
        overall_confidence = sum(confidence_scores) / len(confidence_scores)
        
        # Determine deception type
        deception_type = None
        if overall_deception_prob > 0.7:
            if "identical_responses" in all_indicators:
                deception_type = "simulated_environment"
            elif "overly_consistent" in all_indicators:
                deception_type = "honeypot"
            elif "suspicious_timing" in all_indicators:
                deception_type = "deception_network"
            else:
                deception_type = "possible_deception"
        elif overall_deception_prob > 0.4:
            deception_type = "suspicious_behavior"
        else:
            deception_type = None
        
        # Generate recommendations
        recommendations = []
        if overall_deception_prob > 0.7:
            recommendations.append("High probability of deception - exercise caution")
            recommendations.append("Verify service legitimacy through alternative channels")
            recommendations.append("Consider service fingerprinting from different source")
        elif overall_deception_prob > 0.4:
            recommendations.append("Moderate deception indicators detected")
            recommendations.append("Additional verification recommended")
        else:
            recommendations.append("Low deception probability - service appears legitimate")
        
        return {
            "deception_probability": overall_deception_prob,
            "deception_type": deception_type,
            "confidence": overall_confidence,
            "behavior_profile": {
                "overall_consistency": sum(r.consistency_score for r in test_results) / len(test_results),
                "overall_behavior": sum(r.behavior_score for r in test_results) / len(test_results),
                "timing_analysis": sum(1 for r in test_results if "timing" in r.test_type)
            },
            "consistency_analysis": {
                "response_consistency": sum(r.consistency_score for r in test_results if "consistency" in r.test_type) / max(1, sum(1 for r in test_results if "consistency" in r.test_type)),
                "pattern_consistency": sum(1 for r in test_results if r.is_deception) / len(test_results)
            },
            "response_patterns": {
                "error_responses": len([i for i, r in enumerate(test_results) if "generic_error" in str(r.deception_indicators)]),
                "minimal_responses": len([i for i, r in enumerate(test_results) if "minimal_error" in str(r.deception_indicators)])
            },
            "recommendations": recommendations,
            "is_legitimate": overall_deception_prob < 0.5
        }

# Global instance
_deception_detector = None

def get_deception_detector(config: Optional[DeceptionDetectionConfig] = None) -> DeceptionDetector:
    """Get global deception detector."""
    global _deception_detector
    if _deception_detector is None:
        _deception_detector = DeceptionDetector(config or DeceptionDetectionConfig())
    return _deception_detector

def analyze_service_legitimacy(target_ip: str, target_port: int,
                              service_type: str = "unknown") -> DeceptionAnalysisResult:
    """Convenience function for deception analysis."""
    detector = get_deception_detector()
    return detector.analyze_service_legitimacy(target_ip, target_port, service_type)
