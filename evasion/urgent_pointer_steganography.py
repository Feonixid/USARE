"""TCP Urgent Pointer Steganography for Covert Communication.

Encodes probe data in TCP urgent pointer field to create
covert coordination channels and reveal firewall behavior.

URG flag is largely ignored by most firewalls and IDS systems,
making it perfect for steganographic data transmission and fingerprinting.
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

logger = logging.getLogger("usare.urgent_pointer")

class UrgentDataType(Enum):
    PORT_NUMBER = "port_number"
    SCAN_ID = "scan_id"
    SEQUENCE_INFO = "sequence_info"
    COORDINATION = "coordination"
    FINGERPRINT = "fingerprint"

@dataclass
class UrgentPointerConfig:
    """Configuration for urgent pointer steganography."""
    enable_encoding: bool = True
    enable_firewall_detection: bool = True
    max_pointer_value: int = 0xFFFF  # 16-bit max
    encoding_method: str = "lsb"  # lsb, bit_field, checksum
    coordination_port: int = 443  # For covert coordination
    probe_port_range: Tuple[int, int] = (1, 65535)

@dataclass
class UrgentPointerResult:
    """Result of urgent pointer steganography operation."""
    success: bool = False
    data_encoded: Optional[bytes] = None
    data_decoded: Optional[Any] = None
    firewall_behavior: str = "unknown"
    response_time_ms: float = 0.0
    pointer_value: int = 0
    urgent_flag_set: bool = False
    stealth_score: float = 0.0

class TCPSteganographyEngine:
    """Engine for TCP urgent pointer steganography."""
    
    def __init__(self, config: UrgentPointerConfig):
        self.config = config
        self.coordination_channel = None
        self.probe_history = []
        
    def encode_data_in_urgent_pointer(self, data: bytes, 
                                     data_type: UrgentDataType) -> int:
        """Encode data into TCP urgent pointer field."""
        if data_type == UrgentDataType.PORT_NUMBER:
            # Encode port number (16 bits)
            if len(data) >= 2:
                port = struct.unpack("!H", data[:2])[0]
                return port & self.config.max_pointer_value
            return 0
        
        elif data_type == UrgentDataType.SCAN_ID:
            # Encode scan ID (8 bits)
            if len(data) >= 1:
                scan_id = data[0]
                return scan_id & 0xFF
            return 0
        
        elif data_type == UrgentDataType.SEQUENCE_INFO:
            # Encode sequence info (timestamp, packet count)
            if len(data) >= 4:
                timestamp = struct.unpack("!I", data[:4])[0]
                return timestamp & self.config.max_pointer_value
            return 0
        
        elif data_type == UrgentDataType.COORDINATION:
            # Encode coordination data
            if len(data) >= 2:
                coord = struct.unpack("!H", data[:2])[0]
                return coord & self.config.max_pointer_value
            return 0
        
        elif data_type == UrgentDataType.FINGERPRINT:
            # Encode fingerprint data
            if len(data) >= 2:
                fp = struct.unpack("!H", data[:2])[0]
                return fp & self.config.max_pointer_value
            return 0
        
        return 0
    
    def decode_urgent_pointer_data(self, pointer_value: int, 
                               data_type: UrgentDataType) -> Optional[bytes]:
        """Decode data from TCP urgent pointer field."""
        if data_type == UrgentDataType.PORT_NUMBER:
            return struct.pack("!H", pointer_value)
        elif data_type == UrgentDataType.SCAN_ID:
            return struct.pack("!B", pointer_value & 0xFF)
        elif data_type == UrgentDataType.SEQUENCE_INFO:
            return struct.pack("!I", pointer_value)
        elif data_type == UrgentDataType.COORDINATION:
            return struct.pack("!H", pointer_value)
        elif data_type == UrgentDataType.FINGERPRINT:
            return struct.pack("!H", pointer_value)
        
        return None
    
    def craft_urgent_syn_packet(self, target_ip: str, target_port: int,
                             urgent_data: Optional[bytes] = None,
                             data_type: Optional[UrgentDataType] = None) -> bytes:
        """Craft SYN packet with urgent pointer data."""
        if not HAS_SCAPY:
            return b""
        
        # Base SYN packet
        syn_seq = random.randint(1000, 9000)
        src_port = random.randint(49152, 65535)
        
        # Create TCP layer with SYN flag
        tcp_layer = TCP(
            sport=src_port,
            dport=target_port,
            flags="S",  # SYN flag
            seq=syn_seq,
            window=8192,
            options=[("MSS", 1460)]
        )
        
        # Add urgent pointer if data provided
        if urgent_data and data_type:
            pointer_value = self.encode_data_in_urgent_pointer(urgent_data, data_type)
            if pointer_value > 0:
                # Set URG flag and urgent pointer
                tcp_layer.flags = "SU"  # SYN + URG together
                tcp_layer.urgptr = pointer_value
        
        # Create IP layer
        ip_layer = IP(
            dst=target_ip,
            ttl=64,
            id=random.randint(1, 65535),
            flags="DF"
        )
        
        # Build packet
        packet = ip_layer / tcp_layer
        return bytes(packet)
    
    def send_covert_coordination(self, target_ip: str, 
                                command: str, 
                                parameters: Dict[str, Any]) -> bool:
        """Send covert coordination through urgent pointer."""
        try:
            # Encode coordination command
            coord_data = command.encode()[:16]  # Limit to 16 bytes
            coord_data += b"\x00" * (16 - len(coord_data))
            
            # Send to coordination port (usually 443)
            coord_packet = self.craft_urgent_syn_packet(
                target_ip, 
                self.config.coordination_port,
                coord_data,
                UrgentDataType.COORDINATION
            )
            
            # Send packet
            send(coord_packet, verbose=0)
            logger.debug(f"[Urgent] Sent coordination to {target_ip}:{self.config.coordination_port}")
            return True
            
        except Exception as e:
            logger.error(f"[Urgent] Coordination failed: {e}")
            return False
    
    def probe_with_steganography(self, target_ip: str, target_port: int,
                               scan_id: int = 0,
                               sequence_info: Optional[int] = None) -> UrgentPointerResult:
        """Probe port using urgent pointer steganography."""
        start_time = time.time()
        
        try:
            # Encode scan data
            scan_data = struct.pack("!BI", scan_id, target_port & 0xFF)
            
            if sequence_info:
                seq_data = struct.pack("!I", sequence_info)
                scan_data += seq_data[:4]  # Add sequence info if available
            
            # Craft SYN with urgent pointer
            syn_packet = self.craft_urgent_syn_packet(
                target_ip, target_port, scan_data, UrgentDataType.SCAN_ID
            )
            
            # Send and receive response
            response = sr1(syn_packet, timeout=3, verbose=0)
            
            response_time = (time.time() - start_time) * 1000
            
            if not response:
                return UrgentPointerResult(
                    success=False,
                    firewall_behavior="no_response",
                    response_time_ms=response_time,
                    pointer_value=0,
                    urgent_flag_set=False,
                    stealth_score=0.8
                )
            
            # Analyze response for firewall behavior
            firewall_behavior = self._analyze_firewall_behavior(response)
            
            # Check if URG flag was preserved
            urgent_preserved = False
            if response and response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                urgent_preserved = bool(tcp_flags & 0x20)  # URG flag
            
            # Extract urgent pointer from response (if any)
            response_pointer = 0
            if response and response.haslayer(TCP):
                response_pointer = response[TCP].urgptr or 0
            
            # Decode response data
            decoded_data = None
            if response_pointer > 0:
                decoded_data = self.decode_urgent_pointer_data(
                    response_pointer, UrgentDataType.SCAN_ID
                )
            
            return UrgentPointerResult(
                success=True,
                data_encoded=scan_data,
                data_decoded=decoded_data,
                firewall_behavior=firewall_behavior,
                response_time_ms=response_time,
                pointer_value=response_pointer,
                urgent_flag_set=urgent_preserved,
                stealth_score=self._calculate_stealth_score(firewall_behavior, urgent_preserved)
            )
            
        except Exception as e:
            logger.error(f"[Urgent] Steganography probe failed: {e}")
            return UrgentPointerResult(
                success=False,
                firewall_behavior="error",
                response_time_ms=0,
                pointer_value=0,
                urgent_flag_set=False,
                stealth_score=0.0
            )
    
    def _analyze_firewall_behavior(self, response) -> str:
        """Analyze firewall behavior based on response."""
        if not response:
            return "filtered_or_dropped"
        
        if not response.haslayer(TCP):
            return "non_tcp_response"
        
        tcp_flags = response[TCP].flags
        
        # Check for RST responses
        if tcp_flags & 0x04:  # RST flag
            if tcp_flags & 0x20:  # URG flag also set
                return "rst_with_urg_preserved"
            else:
                return "rst_urg_stripped"
        
        # Check for SYN-ACK
        if tcp_flags & 0x12 == 0x12:  # SYN+ACK
            if tcp_flags & 0x20:  # URG flag preserved
                return "synack_with_urg_preserved"
            else:
                return "synack_urg_stripped"
        
        # Check for other responses
        if tcp_flags & 0x20:  # URG flag
            return "urg_preserved_other"
        
        return "urg_stripped"
    
    def _calculate_stealth_score(self, firewall_behavior: str, 
                              urgent_preserved: bool) -> float:
        """Calculate stealth score based on firewall behavior."""
        # Higher score = more stealthy (less detection)
        behavior_scores = {
            "filtered_or_dropped": 0.9,  # Can't tell if filtered
            "non_tcp_response": 0.8,  # Unexpected response
            "rst_with_urg_preserved": 0.3,  # Firewall preserved URG (suspicious)
            "rst_urg_stripped": 0.7,  # Normal behavior
            "synack_with_urg_preserved": 0.2,  # Very suspicious
            "synack_urg_stripped": 0.8,  # Normal behavior
            "urg_preserved_other": 0.6,  # Some preservation
            "urg_stripped": 0.8,  # Normal stripping
        }
        
        base_score = behavior_scores.get(firewall_behavior, 0.5)
        
        # Adjust based on URG preservation
        if urgent_preserved:
            base_score *= 0.7  # Penalty for preservation (more detectable)
        
        return min(1.0, max(0.0, base_score))
    
    def fingerprint_firewall_types(self, target_ip: str, 
                                   ports: List[int]) -> Dict[str, Any]:
        """Fingerprint different firewall types using urgent pointer responses."""
        results = {
            "firewall_types": {},
            "stealth_scores": {},
            "coordination_channel": None
        }
        
        for port in ports:
            result = self.probe_with_steganography(target_ip, port, scan_id=1)
            
            if result.firewall_behavior not in results["firewall_types"]:
                results["firewall_types"][result.firewall_behavior] = 0
            
            results["firewall_types"][result.firewall_behavior] += 1
            results["stealth_scores"][port] = result.stealth_score
        
        # Determine dominant firewall type
        if results["firewall_types"]:
            dominant_type = max(results["firewall_types"].items(), key=lambda x: x[1])[0]
            results["dominant_firewall"] = dominant_type
            results["firewall_confidence"] = results["firewall_types"][dominant_type] / len(ports)
        
        return results
    
    def establish_coordination_channel(self, target_ip: str) -> bool:
        """Establish covert coordination channel."""
        try:
            # Send initial coordination packet
            init_cmd = "INIT_CHANNEL"
            success = self.send_covert_coordination(target_ip, init_cmd, {"timestamp": int(time.time())})
            
            if success:
                self.coordination_channel = target_ip
                logger.info(f"[Urgent] Established coordination channel with {target_ip}")
            
            return success
            
        except Exception as e:
            logger.error(f"[Urgent] Failed to establish coordination: {e}")
            return False
    
    def send_steganographic_probe_sequence(self, target_ip: str, 
                                       ports: List[int],
                                       sequence_delay: float = 0.1) -> List[UrgentPointerResult]:
        """Send sequence of steganographic probes."""
        results = []
        
        for i, port in enumerate(ports):
            # Include sequence information in urgent pointer
            seq_info = int(time.time() * 1000) & 0xFFFFFFFF
            
            result = self.probe_with_steganography(
                target_ip, port, scan_id=i, sequence_info=seq_info
            )
            
            results.append(result)
            
            # Small delay between probes
            if i < len(ports) - 1:
                time.sleep(sequence_delay)
        
        return results

# Global instance
_urgent_engine = None

def get_urgent_engine(config: Optional[UrgentPointerConfig] = None) -> TCPSteganographyEngine:
    """Get global urgent pointer steganography engine."""
    global _urgent_engine
    if _urgent_engine is None:
        _urgent_engine = TCPSteganographyEngine(config or UrgentPointerConfig())
    return _urgent_engine

def urgent_pointer_probe(target_ip: str, target_port: int, 
                        scan_id: int = 0) -> UrgentPointerResult:
    """Convenience function for urgent pointer probing."""
    engine = get_urgent_engine()
    return engine.probe_with_steganography(target_ip, target_port, scan_id)

def fingerprint_firewall(target_ip: str, ports: List[int]) -> Dict[str, Any]:
    """Convenience function for firewall fingerprinting."""
    engine = get_urgent_engine()
    return engine.fingerprint_firewall_types(target_ip, ports)

def establish_coordination(target_ip: str) -> bool:
    """Convenience function for coordination channel establishment."""
    engine = get_urgent_engine()
    return engine.establish_coordination_channel(target_ip)
