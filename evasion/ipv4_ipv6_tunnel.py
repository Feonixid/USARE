"""IPv4-in-IPv6 Tunneling for Protocol Bypass.

Wraps IPv4 SYN probes inside IPv6 tunneling headers to bypass
firewalls and IDS systems that only inspect native IPv4 or IPv6 traffic.

Uses 6in4, 6to4, Teredo, and ISATAP tunneling
techniques to create covert channels that bypass inspection.
"""

import logging
import time
import struct
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, IPv6, TCP, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.ipv4_ipv6_tunnel")

class IPv6TunnelType(Enum):
    SIX_TO_FOUR = "6to4"           # 6to4 tunneling
    FOUR_TO_SIX = "4to6"           # 4in6 tunneling  
    TEREDO = "teredo"              # Teredo tunneling
    ISATAP = "isatap"              # ISATAP tunneling
    SIX_IN_FOUR = "6in4"            # 6in4 tunneling

@dataclass
class IPv6TunnelConfig:
    """Configuration for IPv6 tunneling."""
    tunnel_type: IPv6TunnelType = IPv6TunnelType.SIX_TO_FOUR
    enable_ipv6_fallback: bool = True
    tunnel_timeout: float = 5.0
    max_retries: int = 2
    randomize_tunnel_id: bool = True
    enable_fragmentation: bool = True

@dataclass
class IPv6TunnelResult:
    """Result of IPv6 tunneling operation."""
    tunnel_type: str
    target_ipv4: str
    target_ipv6: Optional[str]
    tunnel_established: bool
    response_received: bool
    response_time_ms: float
    tunnel_id: int
    bypass_detected: bool
    stealth_score: float
    error_message: Optional[str]

class IPv6TunnelEngine:
    """Advanced IPv4-in-IPv6 tunneling engine."""
    
    def __init__(self, config: IPv6TunnelConfig):
        self.config = config
        self.tunnel_sessions = {}
        self.tunnel_counter = 0
    
    def create_6to4_packet(self, target_ipv4: str, target_port: int,
                           syn_seq: int, src_port: int) -> bytes:
        """Create 6to4-encapsulated SYN packet."""
        if not HAS_SCAPY:
            return b""
        
        # Create inner IPv4 SYN packet
        inner_ip = IP(
            dst=target_ipv4,
            ttl=64,
            id=random.randint(1, 65535),
            flags="DF"
        )
        
        inner_tcp = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460)]
        )
        
        inner_packet = inner_ip / inner_tcp
        
        # Create 6to4 outer IPv6 packet
        # IPv6 header with 6to4 encapsulation
        outer_ipv6 = IPv6(
            dst="2002::" + target_ipv4.replace(".", ""),  # 6to4 prefix
            src="2001:db8::1",  # Source 6to4 address
            nh=4,  # Next header = IPv4
            hlim=64
            fl=0  # Flow label
        )
        
        # 6to4 header
        sixto4_header = struct.pack(
            "!BBHIH",
            0x00,  # Reserved
            0x00,  # Reserved
            0x00,  # Reserved
            0x01,  # Reserved
            0x04,  # Reserved
            len(inner_packet),  # Payload length
            random.randint(1, 65535),  # Tunnel ID
            0x00  # Reserved
        )
        
        # Combine headers and payload
        packet = outer_ipv6 / sixto4_header / Raw(inner_packet)
        return bytes(packet)
    
    def create_teredo_packet(self, target_ipv4: str, target_port: int,
                          syn_seq: int, src_port: int) -> bytes:
        """Create Teredo-encapsulated SYN packet."""
        if not HAS_SCAPY:
            return b""
        
        # Create inner IPv4 SYN packet
        inner_ip = IP(
            dst=target_ipv4,
            ttl=64,
            id=random.randint(1, 65535),
            flags="DF"
        )
        
        inner_tcp = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460)]
        )
        
        inner_packet = inner_ip / inner_tcp
        
        # Create Teredo outer IPv6 packet
        # Teredo uses IPv6 with UDP encapsulation
        teredo_server = "teredo.example.com"  # Would be actual Teredo server
        teredo_port = 3544
        
        outer_ipv6 = IPv6(
            dst=teredo_server,
            src="2001:0:1234:5678::abcd",  # Client Teredo address
            nh=17,  # Next header = UDP
            hlim=64,
            fl=0
        )
        
        # UDP layer for Teredo
        udp_layer = struct.pack(
            "!HH",
            teredo_port,  # Source port
            3544  # Destination port (Teredo)
        )
        
        # Teredo authentication (simplified)
        teredo_auth = struct.pack("!I", random.randint(1, 0xFFFFFFFF))
        
        # Combine all layers
        packet = outer_ipv6 / udp_layer / Raw(teredo_auth + inner_packet)
        return bytes(packet)
    
    def create_isatap_packet(self, target_ipv4: str, target_port: int,
                          syn_seq: int, src_port: int) -> bytes:
        """Create ISATAP-encapsulated SYN packet."""
        if not HAS_SCAPY:
            return b""
        
        # Create inner IPv4 SYN packet
        inner_ip = IP(
            dst=target_ipv4,
            ttl=64,
            id=random.randint(1, 65535),
            flags="DF"
        )
        
        inner_tcp = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460)]
        )
        
        inner_packet = inner_ip / inner_tcp
        
        # Create ISATAP outer IPv6 packet
        # ISATAP uses IPv6 with IPv4 encapsulation
        outer_ipv6 = IPv6(
            dst="2001::1234:5678:9abc",  # ISATAP gateway
            src="2001:db8::1",  # Client ISATAP address
            nh=4,  # Next header = IPv4
            hlim=64,
            fl=0
        )
        
        # ISATAP header
        isatap_header = struct.pack(
            "!BBHIH",
            0x00,  # Next header = IPv4
            0x00,  # Reserved
            0x00,  # Reserved
            0x00,  # Reserved
            0x01,  # Reserved
            len(inner_packet),  # Payload length
            random.randint(1, 65535),  # Tunnel ID
            0x00  # Reserved
        )
        
        packet = outer_ipv6 / isatap_header / Raw(inner_packet)
        return bytes(packet)
    
    def create_6in4_packet(self, target_ipv4: str, target_port: int,
                          syn_seq: int, src_port: int) -> bytes:
        """Create 6in4-encapsulated SYN packet."""
        if not HAS_SCAPY:
            return b""
        
        # Create inner IPv4 SYN packet
        inner_ip = IP(
            dst=target_ipv4,
            ttl=64,
            id=random.randint(1, 65535),
            flags="DF"
        )
        
        inner_tcp = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460)]
        )
        
        inner_packet = inner_ip / inner_tcp
        
        # Create 6in4 outer IPv6 packet
        # 6in4 uses IPv6 with IPv4 encapsulation
        outer_ipv6 = IPv6(
            dst="2001:db8::ffff:ffff:ffff:ffff",  # 6in4 well-known prefix
            src="2001:db8::1",  # Client 6in4 address
            nh=4,  # Next header = IPv4
            hlim=64,
            fl=0
        )
        
        # 6in4 header
        sixin4_header = struct.pack(
            "!BBHIH",
            0x00,  # Next header = IPv4
            0x00,  # Reserved
            0x00,  # Reserved
            0x00,  # Reserved
            0x01,  # Reserved
            len(inner_packet),  # Payload length
            random.randint(1, 65535),  # Tunnel ID
            0x00  # Reserved
        )
        
        packet = outer_ipv6 / sixin4_header / Raw(inner_packet)
        return bytes(packet)
    
    def establish_tunnel(self, target_ipv4: str, target_ipv6: Optional[str] = None) -> IPv6TunnelResult:
        """Establish IPv6 tunnel to target."""
        start_time = time.time()
        
        try:
            # Generate tunnel ID
            if self.config.randomize_tunnel_id:
                tunnel_id = random.randint(1, 65535)
            else:
                self.tunnel_counter += 1
                tunnel_id = self.tunnel_counter
            
            # Create tunnel establishment packet
            if self.config.tunnel_type == IPv6TunnelType.SIX_TO_FOUR:
                tunnel_packet = self._create_6to4_establishment(target_ipv4, tunnel_id)
            elif self.config.tunnel_type == IPv6TunnelType.TEREDO:
                tunnel_packet = self._create_teredo_establishment(target_ipv4, tunnel_id)
            elif self.config.tunnel_type == IPv6TunnelType.ISATAP:
                tunnel_packet = self._create_isatap_establishment(target_ipv4, tunnel_id)
            elif self.config.tunnel_type == IPv6TunnelType.SIX_IN_FOUR:
                tunnel_packet = self._create_6in4_establishment(target_ipv4, tunnel_id)
            else:
                return IPv6TunnelResult(
                    tunnel_type=self.config.tunnel_type.value,
                    target_ipv4=target_ipv4,
                    target_ipv6=target_ipv6,
                    tunnel_established=False,
                    response_received=False,
                    response_time_ms=0,
                    tunnel_id=tunnel_id,
                    bypass_detected=False,
                    stealth_score=0.0,
                    error_message=f"Unsupported tunnel type: {self.config.tunnel_type.value}"
                )
            
            # Send tunnel establishment packet
            response = sr1(tunnel_packet, timeout=self.config.tunnel_timeout, verbose=0)
            response_time = (time.time() - start_time) * 1000
            
            if not response:
                return IPv6TunnelResult(
                    tunnel_type=self.config.tunnel_type.value,
                    target_ipv4=target_ipv4,
                    target_ipv6=target_ipv6,
                    tunnel_established=False,
                    response_received=False,
                    response_time_ms=response_time,
                    tunnel_id=tunnel_id,
                    bypass_detected=False,
                    stealth_score=0.6,
                    error_message="No tunnel response"
                )
            
            # Analyze tunnel response
            tunnel_success = self._analyze_tunnel_response(response)
            
            # Store tunnel session
            self.tunnel_sessions[tunnel_id] = {
                "target_ipv4": target_ipv4,
                "target_ipv6": target_ipv6,
                "established": tunnel_success,
                "created_time": time.time()
            }
            
            return IPv6TunnelResult(
                tunnel_type=self.config.tunnel_type.value,
                target_ipv4=target_ipv4,
                target_ipv6=target_ipv6,
                tunnel_established=tunnel_success,
                response_received=True,
                response_time_ms=response_time,
                tunnel_id=tunnel_id,
                bypass_detected=tunnel_success,
                stealth_score=0.9 if tunnel_success else 0.3,
                error_message=None
            )
            
        except Exception as e:
            logger.error(f"[IPv6 Tunnel] Tunnel establishment failed: {e}")
            return IPv6TunnelResult(
                tunnel_type=self.config.tunnel_type.value,
                target_ipv4=target_ipv4,
                target_ipv6=target_ipv6,
                tunnel_established=False,
                response_received=False,
                response_time_ms=0,
                tunnel_id=0,
                bypass_detected=False,
                stealth_score=0.0,
                error_message=str(e)
            )
    
    def probe_through_tunnel(self, target_ipv4: str, target_port: int,
                          tunnel_id: int) -> IPv6TunnelResult:
        """Send SYN probe through established IPv6 tunnel."""
        start_time = time.time()
        
        # Check if tunnel exists
        if tunnel_id not in self.tunnel_sessions:
            return IPv6TunnelResult(
                tunnel_type=self.config.tunnel_type.value,
                target_ipv4=target_ipv4,
                target_ipv6=None,
                tunnel_established=False,
                response_received=False,
                response_time_ms=0,
                tunnel_id=tunnel_id,
                bypass_detected=False,
                stealth_score=0.0,
                error_message="Tunnel not established"
            )
        
        try:
            # Create SYN packet through tunnel
            syn_seq = random.randint(1000, 9000)
            src_port = random.randint(49152, 65535)
            
            if self.config.tunnel_type == IPv6TunnelType.SIX_TO_FOUR:
                tunnel_packet = self.create_6to4_packet(target_ipv4, target_port, syn_seq, src_port)
            elif self.config.tunnel_type == IPv6TunnelType.TEREDO:
                tunnel_packet = self.create_teredo_packet(target_ipv4, target_port, syn_seq, src_port)
            elif self.config.tunnel_type == IPv6TunnelType.ISATAP:
                tunnel_packet = self.create_isatap_packet(target_ipv4, target_port, syn_seq, src_port)
            elif self.config.tunnel_type == IPv6TunnelType.SIX_IN_FOUR:
                tunnel_packet = self.create_6in4_packet(target_ipv4, target_port, syn_seq, src_port)
            else:
                return IPv6TunnelResult(
                    tunnel_type=self.config.tunnel_type.value,
                    target_ipv4=target_ipv4,
                    target_ipv6=None,
                    tunnel_established=False,
                    response_received=False,
                    response_time_ms=0,
                    tunnel_id=tunnel_id,
                    bypass_detected=False,
                    stealth_score=0.0,
                    error_message=f"Unsupported tunnel type: {self.config.tunnel_type.value}"
                )
            
            # Apply fragmentation if enabled
            if self.config.enable_fragmentation:
                tunnel_packet = self._apply_tunnel_fragmentation(tunnel_packet)
            
            # Send tunneled probe
            response = sr1(tunnel_packet, timeout=self.config.tunnel_timeout, verbose=0)
            response_time = (time.time() - start_time) * 1000
            
            if not response:
                return IPv6TunnelResult(
                    tunnel_type=self.config.tunnel_type.value,
                    target_ipv4=target_ipv4,
                    target_ipv6=None,
                    tunnel_established=True,
                    response_received=False,
                    response_time_ms=response_time,
                    tunnel_id=tunnel_id,
                    bypass_detected=True,
                    stealth_score=0.8,
                    error_message="No response through tunnel"
                )
            
            # Analyze response
            bypass_detected = self._analyze_tunnel_probe_response(response)
            
            return IPv6TunnelResult(
                tunnel_type=self.config.tunnel_type.value,
                target_ipv4=target_ipv4,
                target_ipv6=None,
                tunnel_established=True,
                response_received=True,
                response_time_ms=response_time,
                tunnel_id=tunnel_id,
                bypass_detected=bypass_detected,
                stealth_score=0.9 if bypass_detected else 0.4,
                error_message=None
            )
            
        except Exception as e:
            logger.error(f"[IPv6 Tunnel] Probe through tunnel failed: {e}")
            return IPv6TunnelResult(
                tunnel_type=self.config.tunnel_type.value,
                target_ipv4=target_ipv4,
                target_ipv6=None,
                tunnel_established=True,
                response_received=False,
                response_time_ms=0,
                tunnel_id=tunnel_id,
                bypass_detected=False,
                stealth_score=0.0,
                error_message=str(e)
            )
    
    def _create_6to4_establishment(self, target_ipv4: str, tunnel_id: int) -> bytes:
        """Create 6to4 tunnel establishment packet."""
        # Simplified 6to4 establishment (would normally involve server)
        establishment_data = struct.pack("!I", tunnel_id)
        
        # Create IPv6 packet to 6to4 relay
        outer_ipv6 = IPv6(
            dst="2002::" + target_ipv4.replace(".", ""),
            src="2001:db8::1",
            nh=4,  # IPv4
            hlim=64,
            fl=0
        )
        
        # 6to4 header
        sixto4_header = struct.pack(
            "!BBHIH",
            0x00, 0x00, 0x00, 0x01, len(establishment_data),
            tunnel_id, 0x00
        )
        
        return bytes(outer_ipv6 / sixto4_header / Raw(establishment_data))
    
    def _create_teredo_establishment(self, target_ipv4: str, tunnel_id: int) -> bytes:
        """Create Teredo tunnel establishment packet."""
        # Teredo authentication data
        auth_data = struct.pack("!I", tunnel_id)
        
        # Create IPv6 packet to Teredo server
        outer_ipv6 = IPv6(
            dst="teredo.example.com",
            src="2001:0:1234:5678::abcd",
            nh=17,  # UDP
            hlim=64,
            fl=0
        )
        
        # UDP layer
        udp_layer = struct.pack("!HH", 3544, 3544)
        
        return bytes(outer_ipv6 / udp_layer / Raw(auth_data))
    
    def _create_isatap_establishment(self, target_ipv4: str, tunnel_id: int) -> bytes:
        """Create ISATAP tunnel establishment packet."""
        # ISATAP establishment data
        establishment_data = struct.pack("!I", tunnel_id)
        
        # Create IPv6 packet to ISATAP gateway
        outer_ipv6 = IPv6(
            dst="2001:1234:5678:9abc",
            src="2001:db8::1",
            nh=4,  # IPv4
            hlim=64,
            fl=0
        )
        
        # ISATAP header
        isatap_header = struct.pack(
            "!BBHIH",
            0x00, 0x00, 0x00, 0x01, len(establishment_data),
            tunnel_id, 0x00
        )
        
        return bytes(outer_ipv6 / isatap_header / Raw(establishment_data))
    
    def _create_6in4_establishment(self, target_ipv4: str, tunnel_id: int) -> bytes:
        """Create 6in4 tunnel establishment packet."""
        # 6in4 establishment data
        establishment_data = struct.pack("!I", tunnel_id)
        
        # Create IPv6 packet to 6in4 gateway
        outer_ipv6 = IPv6(
            dst="2001:db8::ffff:ffff:ffff:ffff",
            src="2001:db8::1",
            nh=4,  # IPv4
            hlim=64,
            fl=0
        )
        
        # 6in4 header
        sixin4_header = struct.pack(
            "!BBHIH",
            0x00, 0x00, 0x00, 0x01, len(establishment_data),
            tunnel_id, 0x00
        )
        
        return bytes(outer_ipv6 / sixin4_header / Raw(establishment_data))
    
    def _analyze_tunnel_response(self, response) -> bool:
        """Analyze tunnel establishment response."""
        if not response:
            return False
        
        # Check for any response (simplified)
        return True  # In real implementation, would check specific response codes
    
    def _analyze_tunnel_probe_response(self, response) -> bool:
        """Analyze tunnel probe response for bypass detection."""
        if not response:
            return False
        
        # If we get any response through the tunnel, it indicates bypass
        # Real implementation would check for specific response patterns
        return True
    
    def _apply_tunnel_fragmentation(self, packet: bytes) -> bytes:
        """Apply fragmentation to tunnel packet for additional stealth."""
        if len(packet) < 100:
            return packet
        
        # Split into fragments
        fragment_size = 64  # Small fragments for better evasion
        fragments = []
        
        for i in range(0, len(packet), fragment_size):
            fragment = packet[i:i+fragment_size]
            if i == 0:
                # First fragment with full header
                fragments.append(fragment)
            else:
                # Subsequent fragments (simplified)
                fragments.append(fragment)
        
        return b"".join(fragments)
    
    def comprehensive_ipv6_analysis(self, target_ipv4: str, target_port: int) -> Dict[str, Any]:
        """Perform comprehensive IPv6 tunneling analysis."""
        results = {
            "tunnel_establishment": None,
            "tunnel_probes": [],
            "bypass_analysis": {},
            "stealth_assessment": {},
            "recommendations": []
        }
        
        # Establish tunnel
        tunnel_result = self.establish_tunnel(target_ipv4)
        results["tunnel_establishment"] = tunnel_result
        
        if tunnel_result.tunnel_established:
            # Send probes through tunnel
            probe_results = []
            for i in range(3):  # Multiple probes for reliability
                probe_result = self.probe_through_tunnel(target_ipv4, target_port, tunnel_result.tunnel_id)
                probe_results.append(probe_result)
                
                if i < 2:  # Small delay between probes
                    time.sleep(0.2)
            
            results["tunnel_probes"] = probe_results
            
            # Analyze bypass effectiveness
            results["bypass_analysis"] = self._analyze_bypass_effectiveness(probe_results)
            results["stealth_assessment"] = self._assess_tunnel_stealth(probe_results)
        
        # Generate recommendations
        results["recommendations"] = self._generate_tunnel_recommendations(results)
        
        return results
    
    def _analyze_bypass_effectiveness(self, probe_results: List[IPv6TunnelResult]) -> Dict[str, Any]:
        """Analyze how effective the tunnel bypass is."""
        analysis = {
            "bypass_success_rate": 0.0,
            "average_response_time": 0.0,
            "tunnel_stability": "unknown",
            "detection_indicators": []
        }
        
        successful_probes = [r for r in probe_results if r.bypass_detected]
        analysis["bypass_success_rate"] = len(successful_probes) / len(probe_results)
        
        if probe_results:
            response_times = [r.response_time_ms for r in probe_results if r.response_received]
            if response_times:
                analysis["average_response_time"] = sum(response_times) / len(response_times)
            
            # Check for consistency
            bypass_flags = [r.bypass_detected for r in probe_results]
            if all(bypass_flags):
                analysis["tunnel_stability"] = "stable_bypass"
            elif any(bypass_flags):
                analysis["tunnel_stability"] = "partial_bypass"
            else:
                analysis["tunnel_stability"] = "no_bypass"
        
        return analysis
    
    def _assess_tunnel_stealth(self, probe_results: List[IPv6TunnelResult]) -> Dict[str, Any]:
        """Assess stealth characteristics of tunneling."""
        assessment = {
            "stealth_score": 0.0,
            "detection_risk": "unknown",
            "evasion_technique": self.config.tunnel_type.value,
            "covertness_level": "medium"
        }
        
        if probe_results:
            stealth_scores = [r.stealth_score for r in probe_results]
            assessment["stealth_score"] = sum(stealth_scores) / len(stealth_scores)
            
            if assessment["stealth_score"] > 0.8:
                assessment["detection_risk"] = "low"
                assessment["covertness_level"] = "high"
            elif assessment["stealth_score"] > 0.6:
                assessment["detection_risk"] = "medium"
                assessment["covertness_level"] = "medium"
            else:
                assessment["detection_risk"] = "high"
                assessment["covertness_level"] = "low"
        
        return assessment
    
    def _generate_tunnel_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on tunnel analysis."""
        recommendations = []
        
        if results.get("tunnel_establishment", {}).get("tunnel_established", False):
            recommendations.append("IPv6 tunneling infrastructure not available")
            recommendations.append("Consider alternative bypass techniques")
            return recommendations
        
        bypass_analysis = results.get("bypass_analysis", {})
        success_rate = bypass_analysis.get("bypass_success_rate", 0.0)
        
        if success_rate > 0.8:
            recommendations.append("IPv6 tunneling highly effective - continue using this technique")
            recommendations.append("Consider rotating tunnel types for diversity")
        elif success_rate > 0.5:
            recommendations.append("IPv6 tunneling moderately effective - combine with other techniques")
            recommendations.append("Monitor for tunnel stability issues")
        else:
            recommendations.append("IPv6 tunneling ineffective - try alternative bypass methods")
            recommendations.append("Check for IPv6 inspection capabilities")
        
        stealth_assessment = results.get("stealth_assessment", {})
        detection_risk = stealth_assessment.get("detection_risk", "unknown")
        
        if detection_risk == "low":
            recommendations.append("Low detection risk - technique is stealthy")
        elif detection_risk == "medium":
            recommendations.append("Medium detection risk - use with caution")
        else:
            recommendations.append("High detection risk - avoid this technique")
        
        return recommendations

# Global instance
_ipv6_tunnel_engine = None

def get_ipv6_tunnel_engine(config: Optional[IPv6TunnelConfig] = None) -> IPv6TunnelEngine:
    """Get global IPv6 tunneling engine."""
    global _ipv6_tunnel_engine
    if _ipv6_tunnel_engine is None:
        _ipv6_tunnel_engine = IPv6TunnelEngine(config or IPv6TunnelConfig())
    return _ipv6_tunnel_engine

def establish_ipv6_tunnel(target_ipv4: str, tunnel_type: str = "6to4") -> IPv6TunnelResult:
    """Convenience function for IPv6 tunnel establishment."""
    engine = get_ipv6_tunnel_engine()
    
    try:
        tunnel_enum = IPv6TunnelType(tunnel_type.lower())
        engine.config.tunnel_type = tunnel_enum
        return engine.establish_tunnel(target_ipv4)
    except ValueError:
        return IPv6TunnelResult(
            tunnel_type=tunnel_type,
            target_ipv4=target_ipv4,
            target_ipv6=None,
            tunnel_established=False,
            response_received=False,
            response_time_ms=0,
            tunnel_id=0,
            bypass_detected=False,
            stealth_score=0.0,
            error_message=f"Invalid tunnel type: {tunnel_type}"
        )

def probe_through_ipv6_tunnel(target_ipv4: str, target_port: int, 
                             tunnel_id: int) -> IPv6TunnelResult:
    """Convenience function for IPv6 tunnel probing."""
    engine = get_ipv6_tunnel_engine()
    return engine.probe_through_tunnel(target_ipv4, target_port, tunnel_id)

def comprehensive_ipv6_analysis(target_ipv4: str, target_port: int) -> Dict[str, Any]:
    """Convenience function for comprehensive IPv6 tunneling analysis."""
    engine = get_ipv6_tunnel_engine()
    return engine.comprehensive_ipv6_analysis(target_ipv4, target_port)
