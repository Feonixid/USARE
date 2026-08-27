"""TCP Window Probe Sequence for Advanced OS Fingerprinting.

Sends multiple SYNs with different window sizes to the same port
to analyze TCP stack implementation and behavior with high confidence.

Window scaling behavior reveals:
- TCP stack implementation (Windows vs Linux vs BSD)
- Window scaling configuration
- Buffer management strategies
- Congestion control algorithms
- Network interface characteristics
"""

import logging
import time
import struct
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, TCP, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.tcp_window")

class WindowProbeType(Enum):
    STANDARD = "standard"
    SCALING_TEST = "scaling_test"
    BUFFER_PROBE = "buffer_probe"
    CONGESTION_TEST = "congestion_test"
    ZERO_WINDOW = "zero_window"
    MAX_WINDOW = "max_window"

@dataclass
class WindowProbeConfig:
    """Configuration for TCP window probing."""
    enable_window_sequence: bool = True
    window_sizes: List[int] = None
    probe_delay: float = 0.1
    timeout: float = 3.0
    max_retries: int = 3
    analyze_acks: bool = True
    analyze_window_changes: bool = True

@dataclass
class WindowProbeResult:
    """Result of TCP window probe."""
    window_size: int
    response_received: bool
    response_time_ms: float
    window_echoed: int
    window_scaled: bool
    ack_number: int
    flags: str
    os_hints: List[str]
    confidence: float
    tcp_stack_profile: str

class TCPWindowProber:
    """Advanced TCP window probing engine."""
    
    def __init__(self, config: WindowProbeConfig):
        self.config = config
        self.probe_history = []
        
        # Default window sizes if not specified
        if config.window_sizes is None:
            self.config.window_sizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65535]
    
    def craft_window_syn_packet(self, target_ip: str, target_port: int,
                              window_size: int, seq_num: int) -> bytes:
        """Craft SYN packet with specific window size."""
        if not HAS_SCAPY:
            return b""
        
        src_port = random.randint(49152, 65535)
        
        # TCP layer with specific window size
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=seq_num,
            window=window_size,
            options=[("MSS", 1460), ("WScale", 7)]  # Enable window scaling
        )
        
        # IP layer
        ip_layer = IP(
            dst=target_ip,
            ttl=64,
            id=random.randint(1, 65535),
            flags="DF"
        )
        
        packet = ip_layer / tcp_layer
        return packet
    
    def send_window_probe_sequence(self, target_ip: str, target_port: int) -> List[WindowProbeResult]:
        """Send sequence of window probes to analyze TCP behavior."""
        results = []
        base_seq = random.randint(1000, 9000)
        
        for i, window_size in enumerate(self.config.window_sizes):
            try:
                # Calculate sequence number
                seq_num = base_seq + i * 1000
                
                # Craft SYN with specific window size
                packet = self.craft_window_syn_packet(target_ip, target_port, window_size, seq_num)
                
                # Send and receive response
                start_time = time.time()
                response = sr1(packet, timeout=self.config.timeout, verbose=0)
                response_time = (time.time() - start_time) * 1000
                
                if not response:
                    result = WindowProbeResult(
                        window_size=window_size,
                        response_received=False,
                        response_time_ms=response_time,
                        window_echoed=0,
                        window_scaled=False,
                        ack_number=0,
                        flags="no_response",
                        os_hints=["filtered_or_dropped"],
                        confidence=0.3,
                        tcp_stack_profile="unknown"
                    )
                else:
                    # Analyze response
                    analysis = self._analyze_window_response(response, window_size)
                    result = WindowProbeResult(
                        window_size=window_size,
                        response_received=True,
                        response_time_ms=response_time,
                        window_echoed=analysis["window_echoed"],
                        window_scaled=analysis["window_scaled"],
                        ack_number=analysis["ack_number"],
                        flags=analysis["flags"],
                        os_hints=analysis["os_hints"],
                        confidence=analysis["confidence"],
                        tcp_stack_profile=analysis["tcp_stack_profile"]
                    )
                
                results.append(result)
                
                # Small delay between probes
                if i < len(self.config.window_sizes) - 1:
                    time.sleep(self.config.probe_delay)
                
            except Exception as e:
                logger.error(f"[Window Probe] Failed for window {window_size}: {e}")
                results.append(WindowProbeResult(
                    window_size=window_size,
                    response_received=False,
                    response_time_ms=0,
                    window_echoed=0,
                    window_scaled=False,
                    ack_number=0,
                    flags="error",
                    os_hints=[],
                    confidence=0.0,
                    tcp_stack_profile="error"
                ))
        
        return results
    
    def send_scaling_test_probes(self, target_ip: str, target_port: int) -> List[WindowProbeResult]:
        """Send probes to test window scaling behavior."""
        results = []
        base_seq = random.randint(1000, 9000)
        
        # Test different window scaling factors
        scaling_factors = [0, 1, 2, 3, 7, 14]  # Common scaling values
        
        for i, scale_factor in enumerate(scaling_factors):
            try:
                seq_num = base_seq + i * 1000
                
                # Craft SYN with window scaling
                src_port = random.randint(49152, 65535)
                tcp_layer = TCP(
                    sport=src_port,
                    dport=target_port,
                    flags="S",
                    seq=seq_num,
                    window=65535,  # Max window to trigger scaling
                    options=[("MSS", 1460), ("WScale", scale_factor)]
                )
                
                ip_layer = IP(dst=target_ip, ttl=64, id=random.randint(1, 65535), flags="DF")
                packet = ip_layer / tcp_layer
                
                # Send and receive
                start_time = time.time()
                response = sr1(packet, timeout=self.config.timeout, verbose=0)
                response_time = (time.time() - start_time) * 1000
                
                if not response:
                    result = WindowProbeResult(
                        window_size=65535,
                        response_received=False,
                        response_time_ms=response_time,
                        window_echoed=0,
                        window_scaled=False,
                        ack_number=0,
                        flags="no_response",
                        os_hints=["filtered_or_dropped"],
                        confidence=0.3,
                        tcp_stack_profile="unknown"
                    )
                else:
                    # Analyze scaling response
                    analysis = self._analyze_scaling_response(response, scale_factor)
                    result = WindowProbeResult(
                        window_size=65535,
                        response_received=True,
                        response_time_ms=response_time,
                        window_echoed=analysis["window_echoed"],
                        window_scaled=analysis["window_scaled"],
                        ack_number=analysis["ack_number"],
                        flags=analysis["flags"],
                        os_hints=analysis["os_hints"],
                        confidence=analysis["confidence"],
                        tcp_stack_profile=analysis["tcp_stack_profile"]
                    )
                
                results.append(result)
                time.sleep(self.config.probe_delay)
                
            except Exception as e:
                logger.error(f"[Window Probe] Scaling test failed: {e}")
        
        return results
    
    def _analyze_window_response(self, response, expected_window: int) -> Dict[str, Any]:
        """Analyze window probe response."""
        if not response or not response.haslayer(TCP):
            return {
                "window_echoed": 0,
                "window_scaled": False,
                "ack_number": 0,
                "flags": "no_response",
                "os_hints": ["filtered_or_dropped"],
                "confidence": 0.3,
                "tcp_stack_profile": "unknown"
            }
        
        tcp_layer = response[TCP]
        ip_layer = response[IP]
        
        # Extract response information
        window_echoed = tcp_layer.window
        ack_number = tcp_layer.ack
        flags = str(tcp_layer.flags)
        
        # Analyze window behavior
        window_scaled = False
        os_hints = []
        confidence = 0.7
        
        # Check if window was scaled
        if window_echoed > expected_window:
            window_scaled = True
            os_hints.append("window_scaling_active")
        
        # Check for specific window behaviors
        if window_echoed == expected_window:
            os_hints.append("window_echo_exact")
            confidence = 0.8
        elif window_echoed == 0:
            os_hints.append("window_zero_response")
            confidence = 0.6
        elif window_echoed < expected_window:
            os_hints.append("window_reduced")
            confidence = 0.7
        elif window_echoed > expected_window * 2:
            os_hints.append("window_inflated")
            confidence = 0.6
        
        # OS-specific hints based on window behavior
        tcp_stack_profile = self._classify_tcp_stack_from_window(window_echoed, expected_window, ack_number, flags)
        os_hints.extend(self._get_os_window_hints(tcp_stack_profile, window_echoed, expected_window))
        
        return {
            "window_echoed": window_echoed,
            "window_scaled": window_scaled,
            "ack_number": ack_number,
            "flags": flags,
            "os_hints": os_hints,
            "confidence": confidence,
            "tcp_stack_profile": tcp_stack_profile
        }
    
    def _analyze_scaling_response(self, response, scale_factor: int) -> Dict[str, Any]:
        """Analyze window scaling test response."""
        if not response or not response.haslayer(TCP):
            return {
                "window_echoed": 0,
                "window_scaled": False,
                "ack_number": 0,
                "flags": "no_response",
                "os_hints": ["filtered_or_dropped"],
                "confidence": 0.3,
                "tcp_stack_profile": "unknown"
            }
        
        tcp_layer = response[TCP]
        window_echoed = tcp_layer.window
        ack_number = tcp_layer.ack
        flags = str(tcp_layer.flags)
        
        # Check if scaling was accepted
        window_scaled = False
        os_hints = []
        confidence = 0.7
        
        # Look for window scaling acknowledgment
        if scale_factor > 0 and window_echoed == 65535:
            window_scaled = True
            os_hints.append(f"window_scaling_accepted_factor_{scale_factor}")
            confidence = 0.9
        elif scale_factor == 0 and window_echoed < 65535:
            os_hints.append("window_scaling_disabled")
            confidence = 0.8
        else:
            os_hints.append("window_scaling_ignored")
            confidence = 0.6
        
        tcp_stack_profile = self._classify_tcp_stack_from_scaling(scale_factor, window_echoed, ack_number, flags)
        os_hints.extend(self._get_os_scaling_hints(tcp_stack_profile, scale_factor, window_echoed))
        
        return {
            "window_echoed": window_echoed,
            "window_scaled": window_scaled,
            "ack_number": ack_number,
            "flags": flags,
            "os_hints": os_hints,
            "confidence": confidence,
            "tcp_stack_profile": tcp_stack_profile
        }
    
    def _classify_tcp_stack_from_window(self, window_echoed: int, expected_window: int,
                                      ack_number: int, flags: str) -> str:
        """Classify TCP stack based on window behavior."""
        # Windows typically uses smaller windows and specific scaling
        if window_echoed <= 8192:
            return "windows_tcp"
        # Linux often uses larger windows and different scaling
        elif window_echoed >= 32768:
            return "linux_tcp"
        # BSD systems often use moderate windows
        elif 16384 <= window_echoed < 32768:
            return "bsd_tcp"
        # Cisco/IOS often uses specific window patterns
        elif window_echoed == 65535:
            return "cisco_ios"
        # Default classification
        else:
            return "unknown_tcp"
    
    def _classify_tcp_stack_from_scaling(self, scale_factor: int, window_echoed: int,
                                     ack_number: int, flags: str) -> str:
        """Classify TCP stack based on window scaling behavior."""
        if scale_factor == 0:
            if window_echoed < 65535:
                return "windows_tcp"  # Windows often disables scaling
            else:
                return "linux_tcp"  # Linux with scaling disabled
        elif scale_factor <= 2:
            return "bsd_tcp"  # BSD often uses conservative scaling
        elif scale_factor >= 7:
            return "linux_tcp"  # Linux often uses aggressive scaling
        else:
            return "unknown_tcp"
    
    def _get_os_window_hints(self, tcp_stack_profile: str, window_echoed: int,
                             expected_window: int) -> List[str]:
        """Get OS-specific hints from window behavior."""
        hints = []
        
        if tcp_stack_profile == "windows_tcp":
            hints.extend(["windows_os", "conservative_window", "microsoft_stack"])
        elif tcp_stack_profile == "linux_tcp":
            hints.extend(["linux_os", "aggressive_window", "gnu_tcp_stack"])
        elif tcp_stack_profile == "bsd_tcp":
            hints.extend(["bsd_os", "moderate_window", "berkeley_tcp_stack"])
        elif tcp_stack_profile == "cisco_ios":
            hints.extend(["cisco_ios", "network_equipment", "ios_tcp_stack"])
        
        # Add window-specific hints
        if window_echoed == expected_window:
            hints.append("window_behavior_normal")
        elif window_echoed < expected_window:
            hints.append("window_behavior_conservative")
        else:
            hints.append("window_behavior_aggressive")
        
        return hints
    
    def _get_os_scaling_hints(self, tcp_stack_profile: str, scale_factor: int,
                              window_echoed: int) -> List[str]:
        """Get OS-specific hints from scaling behavior."""
        hints = []
        
        if tcp_stack_profile == "windows_tcp":
            if scale_factor == 0:
                hints.extend(["windows_scaling_disabled", "windows_default_behavior"])
            else:
                hints.extend(["windows_scaling_enabled", "windows_modified_behavior"])
        elif tcp_stack_profile == "linux_tcp":
            if scale_factor >= 7:
                hints.extend(["linux_aggressive_scaling", "linux_default_behavior"])
            else:
                hints.extend(["linux_conservative_scaling", "linux_modified_behavior"])
        elif tcp_stack_profile == "bsd_tcp":
            hints.extend(["bsd_conservative_scaling", "bsd_default_behavior"])
        
        return hints
    
    def comprehensive_window_analysis(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Perform comprehensive TCP window analysis."""
        results = {
            "window_sequence": [],
            "scaling_tests": [],
            "analysis": {},
            "os_fingerprint": {},
            "confidence_score": 0.0
        }
        
        # Send window size sequence
        if self.config.enable_window_sequence:
            window_results = self.send_window_probe_sequence(target_ip, target_port)
            results["window_sequence"] = window_results
        
        # Send scaling test probes
        if self.config.analyze_acks:
            scaling_results = self.send_scaling_test_probes(target_ip, target_port)
            results["scaling_tests"] = scaling_results
        
        # Analyze results
        results["analysis"] = self._analyze_comprehensive_window_results(results)
        results["os_fingerprint"] = self._create_window_os_fingerprint(results)
        
        # Calculate overall confidence
        all_results = window_results + scaling_results
        if all_results:
            results["confidence_score"] = sum(r.confidence for r in all_results) / len(all_results)
        
        return results
    
    def _analyze_comprehensive_window_results(self, results: Dict[str, List[WindowProbeResult]]) -> Dict[str, Any]:
        """Analyze comprehensive window probe results."""
        analysis = {
            "window_patterns": [],
            "scaling_behavior": {},
            "consistency_score": 0.0,
            "stack_classification": "unknown"
        }
        
        # Analyze window sequence
        window_results = results.get("window_sequence", [])
        if window_results:
            window_sizes = [r.window_size for r in window_results if r.response_received]
            response_windows = [r.window_echoed for r in window_results if r.response_received]
            
            if window_sizes and response_windows:
                analysis["window_patterns"] = {
                    "expected_sizes": window_sizes,
                    "echoed_sizes": response_windows,
                    "window_variance": max(response_windows) - min(response_windows),
                    "scaling_detected": any(r.window_scaled for r in window_results)
                }
        
        # Analyze scaling tests
        scaling_results = results.get("scaling_tests", [])
        if scaling_results:
            scaling_factors = []
            for r in scaling_results:
                if r.response_received and "window_scaling_accepted" in r.os_hints:
                    # Extract scale factor from hints
                    for hint in r.os_hints:
                        if hint.startswith("window_scaling_accepted_factor_"):
                            scaling_factors.append(int(hint.split("_")[-1]))
            
            if scaling_factors:
                analysis["scaling_behavior"] = {
                    "scaling_supported": True,
                    "accepted_factors": scaling_factors,
                    "max_factor": max(scaling_factors),
                    "scaling_consistency": len(set(scaling_factors)) == 1
                }
        
        return analysis
    
    def _create_window_os_fingerprint(self, results: Dict[str, List[WindowProbeResult]]) -> Dict[str, Any]:
        """Create OS fingerprint from window analysis."""
        fingerprint = {
            "primary_stack": "unknown",
            "confidence": 0.0,
            "os_family": "unknown",
            "version_hints": [],
            "behavioral_traits": []
        }
        
        all_results = []
        if "window_sequence" in results:
            all_results.extend(results["window_sequence"])
        if "scaling_tests" in results:
            all_results.extend(results["scaling_tests"])
        
        if not all_results:
            return fingerprint
        
        # Count TCP stack classifications
        stack_votes = {}
        for result in all_results:
            if result.tcp_stack_profile != "unknown":
                stack_votes[result.tcp_stack_profile] = stack_votes.get(result.tcp_stack_profile, 0) + result.confidence
        
        if stack_votes:
            # Determine primary stack
            primary_stack = max(stack_votes.items(), key=lambda x: x[1])[0]
            fingerprint["primary_stack"] = primary_stack
            fingerprint["confidence"] = stack_votes[primary_stack] / sum(stack_votes.values())
            
            # Add OS family
            if "windows" in primary_stack:
                fingerprint["os_family"] = "Windows"
            elif "linux" in primary_stack:
                fingerprint["os_family"] = "Linux"
            elif "bsd" in primary_stack:
                fingerprint["os_family"] = "BSD"
            elif "cisco" in primary_stack:
                fingerprint["os_family"] = "Cisco IOS"
            
            # Collect behavioral traits
            all_hints = []
            for result in all_results:
                all_hints.extend(result.os_hints)
            
            # Remove duplicates and count
            hint_counts = {}
            for hint in all_hints:
                hint_counts[hint] = hint_counts.get(hint, 0) + 1
            
            fingerprint["behavioral_traits"] = sorted(hint_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            fingerprint["version_hints"] = [hint for hint, count in fingerprint["behavioral_traits"] if count > 1]
        
        return fingerprint

# Global instance
_window_prober = None

def get_window_prober(config: Optional[WindowProbeConfig] = None) -> TCPWindowProber:
    """Get global TCP window prober."""
    global _window_prober
    if _window_prober is None:
        _window_prober = TCPWindowProber(config or WindowProbeConfig())
    return _window_prober

def probe_window_sequence(target_ip: str, target_port: int) -> List[WindowProbeResult]:
    """Convenience function for window sequence probing."""
    prober = get_window_prober()
    return prober.send_window_probe_sequence(target_ip, target_port)

def comprehensive_window_analysis(target_ip: str, target_port: int) -> Dict[str, Any]:
    """Convenience function for comprehensive window analysis."""
    prober = get_window_prober()
    return prober.comprehensive_window_analysis(target_ip, target_port)
