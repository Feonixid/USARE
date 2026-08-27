"""IP Options Fingerprinting for Advanced Infrastructure Analysis.

Crafts SYN packets with various IP options to reveal network
topology, firewall behavior, and system configuration.

IP options analysis provides insights that TTL, window size,
and timestamp analysis cannot reveal, particularly for identifying:
- Load balancers and proxies
- Router configurations
- Firewall types and policies
- Network path characteristics
"""

import logging
import time
import struct
import random
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, TCP, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.ip_options")

class IPOptionType(Enum):
    RECORD_ROUTE = "record_route"      # LSRR - Loose Source and Record Route
    TIMESTAMP = "timestamp"          # Timestamp option
    SECURITY = "security"            # Security option
    STREAM_ID = "stream_id"          # Stream identifier
    ROUTER_ALERT = "router_alert"    # Router alert
    MTU_PROBE = "mtu_probe"         # MTU discovery
    TRACEROUTE = "traceroute"      # Traceroute option

@dataclass
class IPOptionsConfig:
    """Configuration for IP options fingerprinting."""
    enable_record_route: bool = True
    enable_timestamp: bool = True
    enable_security: bool = True
    enable_stream_id: bool = True
    enable_router_alert: bool = True
    enable_mtu_probe: bool = True
    max_options_size: int = 40  # Maximum IP options size
    probe_timeout: float = 3.0

@dataclass
class IPOptionsResult:
    """Result of IP options probing."""
    option_type: str
    option_data: Optional[bytes] = None
    response_received: bool = False
    response_options: List[Dict[str, Any]] = None
    response_time_ms: float = 0.0
    infrastructure_hints: List[str] = None
    firewall_behavior: str = None
    confidence: float = 0.0
    
    def __post_init__(self):
        if self.response_options is None:
            self.response_options = []
        if self.infrastructure_hints is None:
            self.infrastructure_hints = []

class IPOptionsFingerprinter:
    """Advanced IP options fingerprinting engine."""
    
    def __init__(self, config: IPOptionsConfig):
        self.config = config
        self.option_responses = {}
        
    def craft_syn_with_record_route(self, target_ip: str, target_port: int,
                                  route_hops: List[str] = None) -> bytes:
        """Craft SYN with Record Route option."""
        if not HAS_SCAPY:
            return b""
        
        # Default route if not specified
        if route_hops is None:
            route_hops = ["8.8.8.8", "192.168.1.1", "10.0.0.1"]
        
        # Build Record Route option
        route_data = b""
        for hop in route_hops:
            try:
                # Convert IP to bytes
                hop_bytes = socket.inet_aton(hop)
                route_data += hop_bytes
            except:
                # Skip invalid IPs
                continue
        
        # Create SYN packet
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # TCP layer with Record Route option
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460), ("Record Route", route_data)]
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
    
    def craft_syn_with_timestamp(self, target_ip: str, target_port: int,
                             timestamp: Optional[int] = None,
                             timestamp_echo: bool = False) -> bytes:
        """Craft SYN with Timestamp option."""
        if not HAS_SCAPY:
            return b""
        
        # Generate timestamp if not provided
        if timestamp is None:
            timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # Build timestamp option
        if timestamp_echo:
            # Timestamp with echo request
            timestamp_opt = (timestamp, 0)  # (timestamp, echo)
        else:
            # Regular timestamp
            timestamp_opt = (timestamp,)
        
        # TCP layer with Timestamp option
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460), ("Timestamp", timestamp_opt)]
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
    
    def craft_syn_with_security(self, target_ip: str, target_port: int,
                           security_data: bytes = b"\x90\x00\x00\x00") -> bytes:
        """Craft SYN with Security option."""
        if not HAS_SCAPY:
            return b""
        
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # TCP layer with Security option
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460), ("Security", security_data)]
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
    
    def craft_syn_with_stream_id(self, target_ip: str, target_port: int,
                              stream_id: int = 0x12345678) -> bytes:
        """Craft SYN with Stream ID option."""
        if not HAS_SCAPY:
            return b""
        
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # TCP layer with Stream ID option
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460), ("Stream ID", stream_id)]
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
    
    def craft_syn_with_router_alert(self, target_ip: str, target_port: int,
                                alert_data: bytes = b"\x00\x00\x00\x00") -> bytes:
        """Craft SYN with Router Alert option."""
        if not HAS_SCAPY:
            return b""
        
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # TCP layer with Router Alert option
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460), ("Router Alert", alert_data)]
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
    
    def craft_syn_with_mtu_probe(self, target_ip: str, target_port: int,
                              mtu_size: int = 1500) -> bytes:
        """Craft SYN with MTU probe option."""
        if not HAS_SCAPY:
            return b""
        
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # TCP layer with MTU probe
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", mtu_size)]
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
    
    def probe_with_ip_options(self, target_ip: str, target_port: int,
                            option_type: IPOptionType) -> IPOptionsResult:
        """Probe target with specific IP option."""
        start_time = time.time()
        
        try:
            # Craft packet based on option type
            if option_type == IPOptionType.RECORD_ROUTE:
                packet = self.craft_syn_with_record_route(target_ip, target_port)
            elif option_type == IPOptionType.TIMESTAMP:
                packet = self.craft_syn_with_timestamp(target_ip, target_port)
            elif option_type == IPOptionType.SECURITY:
                packet = self.craft_syn_with_security(target_ip, target_port)
            elif option_type == IPOptionType.STREAM_ID:
                packet = self.craft_syn_with_stream_id(target_ip, target_port)
            elif option_type == IPOptionType.ROUTER_ALERT:
                packet = self.craft_syn_with_router_alert(target_ip, target_port)
            elif option_type == IPOptionType.MTU_PROBE:
                packet = self.craft_syn_with_mtu_probe(target_ip, target_port)
            else:
                return IPOptionsResult(
                    option_type=option_type.value,
                    response_received=False,
                    response_time_ms=0,
                    infrastructure_hints=[],
                    firewall_behavior="invalid_option",
                    confidence=0.0
                )
            
            # Send packet and receive response
            response = sr1(packet, timeout=self.config.probe_timeout, verbose=0)
            
            response_time = (time.time() - start_time) * 1000
            
            if not response:
                return IPOptionsResult(
                    option_type=option_type.value,
                    response_received=False,
                    response_time_ms=response_time,
                    infrastructure_hints=["filtered_or_dropped"],
                    firewall_behavior="no_response",
                    confidence=0.6
                )
            
            # Analyze response
            analysis = self._analyze_response(response, option_type)
            
            return IPOptionsResult(
                option_type=option_type.value,
                option_data=self._extract_option_data(response, option_type),
                response_received=True,
                response_options=analysis["response_options"],
                response_time_ms=response_time,
                infrastructure_hints=analysis["infrastructure_hints"],
                firewall_behavior=analysis["firewall_behavior"],
                confidence=analysis["confidence"]
            )
            
        except Exception as e:
            logger.error(f"[IP Options] Probe failed: {e}")
            return IPOptionsResult(
                option_type=option_type.value,
                response_received=False,
                response_time_ms=0,
                infrastructure_hints=[],
                firewall_behavior="error",
                confidence=0.0
            )
    
    def _analyze_response(self, response, option_type: IPOptionType) -> Dict[str, Any]:
        """Analyze response to extract infrastructure hints."""
        analysis = {
            "response_options": [],
            "infrastructure_hints": [],
            "firewall_behavior": "unknown",
            "confidence": 0.5
        }
        
        if not response or not response.haslayer(TCP):
            analysis["firewall_behavior"] = "no_tcp_response"
            analysis["confidence"] = 0.3
            return analysis
        
        tcp_layer = response[TCP]
        ip_layer = response[IP]
        
        # Check TCP options in response
        response_options = []
        if tcp_layer.options:
            for opt in tcp_layer.options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    opt_name, opt_data = opt[0], opt[1]
                    response_options.append({
                        "name": opt_name,
                        "data": opt_data,
                        "preserved": True
                    })
        
        analysis["response_options"] = response_options
        
        # Analyze based on option type
        if option_type == IPOptionType.RECORD_ROUTE:
            analysis.update(self._analyze_record_route_response(response))
        elif option_type == IPOptionType.TIMESTAMP:
            analysis.update(self._analyze_timestamp_response(response))
        elif option_type == IPOptionType.SECURITY:
            analysis.update(self._analyze_security_response(response))
        elif option_type == IPOptionType.STREAM_ID:
            analysis.update(self._analyze_stream_id_response(response))
        elif option_type == IPOptionType.ROUTER_ALERT:
            analysis.update(self._analyze_router_alert_response(response))
        elif option_type == IPOptionType.MTU_PROBE:
            analysis.update(self._analyze_mtu_probe_response(response))
        
        return analysis
    
    def _analyze_record_route_response(self, response) -> Dict[str, Any]:
        """Analyze Record Route option response."""
        hints = []
        behavior = "route_stripped"
        confidence = 0.7
        
        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            
            # Check if route option was echoed back
            for opt in tcp_layer.options or []:
                if isinstance(opt, tuple) and opt[0] == "Record Route":
                    hints.append("router_supports_record_route")
                    behavior = "route_echoed"
                    confidence = 0.9
                    break
            else:
                hints.append("router_strips_record_route")
        
        return {
            "infrastructure_hints": hints,
            "firewall_behavior": behavior,
            "confidence": confidence
        }
    
    def _analyze_timestamp_response(self, response) -> Dict[str, Any]:
        """Analyze Timestamp option response."""
        hints = []
        behavior = "timestamp_stripped"
        confidence = 0.7
        
        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            
            # Check for timestamp option
            for opt in tcp_layer.options or []:
                if isinstance(opt, tuple) and opt[0] == "Timestamp":
                    timestamp_data = opt[1]
                    if isinstance(timestamp_data, tuple) and len(timestamp_data) >= 1:
                        hints.append("router_supports_timestamp")
                        hints.append(f"timestamp_value:{timestamp_data[0]}")
                        behavior = "timestamp_echoed"
                        confidence = 0.9
                    break
            else:
                hints.append("router_strips_timestamp")
        
        return {
            "infrastructure_hints": hints,
            "firewall_behavior": behavior,
            "confidence": confidence
        }
    
    def _analyze_security_response(self, response) -> Dict[str, Any]:
        """Analyze Security option response."""
        hints = []
        behavior = "security_stripped"
        confidence = 0.7
        
        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            
            # Check for security option
            for opt in tcp_layer.options or []:
                if isinstance(opt, tuple) and opt[0] == "Security":
                    security_data = opt[1]
                    hints.append("router_supports_security")
                    hints.append(f"security_response:{security_data}")
                    behavior = "security_echoed"
                    confidence = 0.9
                    break
            else:
                hints.append("router_strips_security")
        
        return {
            "infrastructure_hints": hints,
            "firewall_behavior": behavior,
            "confidence": confidence
        }
    
    def _analyze_stream_id_response(self, response) -> Dict[str, Any]:
        """Analyze Stream ID option response."""
        hints = []
        behavior = "stream_id_stripped"
        confidence = 0.7
        
        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            
            # Check for stream ID option
            for opt in tcp_layer.options or []:
                if isinstance(opt, tuple) and opt[0] == "Stream ID":
                    stream_data = opt[1]
                    hints.append("router_supports_stream_id")
                    hints.append(f"stream_id_echoed:{stream_data}")
                    behavior = "stream_id_echoed"
                    confidence = 0.9
                    break
            else:
                hints.append("router_strips_stream_id")
        
        return {
            "infrastructure_hints": hints,
            "firewall_behavior": behavior,
            "confidence": confidence
        }
    
    def _analyze_router_alert_response(self, response) -> Dict[str, Any]:
        """Analyze Router Alert option response."""
        hints = []
        behavior = "alert_ignored"
        confidence = 0.6
        
        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            
            # Router alerts are typically not echoed
            # Any response might indicate advanced router
            hints.append("router_alert_sent")
            behavior = "alert_processed"
            confidence = 0.8
        
        return {
            "infrastructure_hints": hints,
            "firewall_behavior": behavior,
            "confidence": confidence
        }
    
    def _analyze_mtu_probe_response(self, response) -> Dict[str, Any]:
        """Analyze MTU probe response."""
        hints = []
        behavior = "mtu_ignored"
        confidence = 0.7
        
        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            
            # Check MSS option in response
            for opt in tcp_layer.options or []:
                if isinstance(opt, tuple) and opt[0] == "MSS":
                    mss_value = opt[1]
                    hints.append(f"mss_response:{mss_value}")
                    behavior = "mtu_echoed"
                    confidence = 0.9
                    break
            else:
                hints.append("router_strips_mss")
        
        return {
            "infrastructure_hints": hints,
            "firewall_behavior": behavior,
            "confidence": confidence
        }
    
    def _extract_option_data(self, response, option_type: IPOptionType) -> Optional[bytes]:
        """Extract specific option data from response."""
        if not response or not response.haslayer(TCP):
            return None
        
        tcp_layer = response[TCP]
        
        for opt in tcp_layer.options or []:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opt_name = opt[0]
                opt_data = opt[1]
                
                if option_type == IPOptionType.RECORD_ROUTE and opt_name == "Record Route":
                    return opt_data if isinstance(opt_data, bytes) else None
                elif option_type == IPOptionType.TIMESTAMP and opt_name == "Timestamp":
                    return opt_data if isinstance(opt_data, tuple) else None
                elif option_type == IPOptionType.SECURITY and opt_name == "Security":
                    return opt_data if isinstance(opt_data, bytes) else None
                elif option_type == IPOptionType.STREAM_ID and opt_name == "Stream ID":
                    return opt_data if isinstance(opt_data, int) else None
                elif option_type == IPOptionType.ROUTER_ALERT and opt_name == "Router Alert":
                    return opt_data if isinstance(opt_data, bytes) else None
                elif option_type == IPOptionType.MTU_PROBE and opt_name == "MSS":
                    return struct.pack("!H", opt_data) if isinstance(opt_data, int) else None
        
        return None
    
    def comprehensive_fingerprint(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """Perform comprehensive IP options fingerprinting."""
        results = {}
        
        # Test all option types
        for option_type in IPOptionType:
            if option_type == IPOptionType.RECORD_ROUTE and not self.config.enable_record_route:
                continue
            elif option_type == IPOptionType.TIMESTAMP and not self.config.enable_timestamp:
                continue
            elif option_type == IPOptionType.SECURITY and not self.config.enable_security:
                continue
            elif option_type == IPOptionType.STREAM_ID and not self.config.enable_stream_id:
                continue
            elif option_type == IPOptionType.ROUTER_ALERT and not self.config.enable_router_alert:
                continue
            elif option_type == IPOptionType.MTU_PROBE and not self.config.enable_mtu_probe:
                continue
            
            result = self.probe_with_ip_options(target_ip, target_port, option_type)
            results[option_type.value] = result
        
        # Analyze overall patterns
        analysis = self._analyze_comprehensive_results(results)
        
        return {
            "target_ip": target_ip,
            "target_port": target_port,
            "option_results": results,
            "analysis": analysis,
            "infrastructure_profile": self._create_infrastructure_profile(results),
            "firewall_classification": self._classify_firewall(results)
        }
    
    def _analyze_comprehensive_results(self, results: Dict[str, IPOptionsResult]) -> Dict[str, Any]:
        """Analyze patterns across all option tests."""
        analysis = {
            "supported_options": [],
            "stripped_options": [],
            "preserved_options": [],
            "infrastructure_hints": set(),
            "confidence_score": 0.0
        }
        
        for option_type, result in results.items():
            if result.response_received:
                if any("echoed" in result.firewall_behavior):
                    analysis["preserved_options"].append(option_type)
                    analysis["supported_options"].append(option_type)
                elif "stripped" in result.firewall_behavior:
                    analysis["stripped_options"].append(option_type)
                
                analysis["infrastructure_hints"].update(result.infrastructure_hints)
                analysis["confidence_score"] += result.confidence
        
        # Normalize confidence score
        total_tests = len(results)
        if total_tests > 0:
            analysis["confidence_score"] /= total_tests
        
        analysis["infrastructure_hints"] = list(analysis["infrastructure_hints"])
        
        return analysis
    
    def _create_infrastructure_profile(self, results: Dict[str, IPOptionsResult]) -> Dict[str, Any]:
        """Create infrastructure profile from results."""
        profile = {
            "router_capabilities": [],
            "load_balancer_detected": False,
            "proxy_detected": False,
            "firewall_type": "unknown",
            "network_complexity": "simple"
        }
        
        # Analyze router capabilities
        for result in results.values():
            if result.response_received:
                if "router_supports" in result.firewall_behavior:
                    profile["router_capabilities"].append(result.option_type)
        
        # Detect load balancers (often strip options but preserve some)
        stripped_count = len([r for r in results.values() 
                           if r.response_received and "stripped" in r.firewall_behavior])
        preserved_count = len([r for r in results.values() 
                            if r.response_received and "echoed" in r.firewall_behavior])
        
        if stripped_count > 0 and preserved_count > 0:
            profile["load_balancer_detected"] = True
            profile["network_complexity"] = "complex"
        
        # Classify firewall type
        if stripped_count > preserved_count * 2:
            profile["firewall_type"] = "restrictive"
        elif stripped_count == preserved_count:
            profile["firewall_type"] = "moderate"
        else:
            profile["firewall_type"] = "permissive"
        
        return profile
    
    def _classify_firewall(self, results: Dict[str, IPOptionsResult]) -> str:
        """Classify firewall type based on option handling."""
        behaviors = [r.firewall_behavior for r in results.values() if r.response_received]
        
        if not behaviors:
            return "unknown"
        
        # Count different behavior types
        restrictive_count = len([b for b in behaviors if "stripped" in b])
        moderate_count = len([b for b in behaviors if "echoed" in b])
        
        if restrictive_count > moderate_count * 2:
            return "restrictive_firewall"
        elif restrictive_count > moderate_count:
            return "moderate_firewall"
        else:
            return "permissive_firewall"

# Global instance
_ip_options_engine = None

def get_ip_options_engine(config: Optional[IPOptionsConfig] = None) -> IPOptionsFingerprinter:
    """Get global IP options fingerprinting engine."""
    global _ip_options_engine
    if _ip_options_engine is None:
        _ip_options_engine = IPOptionsFingerprinter(config or IPOptionsConfig())
    return _ip_options_engine

def probe_ip_options(target_ip: str, target_port: int,
                    option_type: str) -> IPOptionsResult:
    """Convenience function for IP options probing."""
    engine = get_ip_options_engine()
    
    try:
        option_enum = IPOptionType(option_type.lower())
        return engine.probe_with_ip_options(target_ip, target_port, option_enum)
    except ValueError:
        return IPOptionsResult(
            option_type=option_type,
            response_received=False,
            response_time_ms=0,
            infrastructure_hints=[],
            firewall_behavior="invalid_option",
            confidence=0.0
        )

def comprehensive_ip_fingerprint(target_ip: str, target_port: int) -> Dict[str, Any]:
    """Convenience function for comprehensive IP options fingerprinting."""
    engine = get_ip_options_engine()
    return engine.comprehensive_fingerprint(target_ip, target_port)
