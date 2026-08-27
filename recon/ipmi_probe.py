"""IPMI Out-of-Band Management Discovery.

Probes IPMI interfaces on port 623/UDP to discover physical server
management infrastructure that security teams often overlook.

IPMI runs on a separate network stack from the main OS and
provides hardware-level management access even when servers are off.
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
    from scapy.all import IP, UDP, Raw, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.ipmi_probe")

class IPMICommand(Enum):
    GET_CHANNEL_AUTH_CMD = 0x38
    GET_SESSION_CHALLENGE_CMD = 0x39
    ACTIVATE_SESSION_CMD = 0x3A
    SET_SESSION_PRIVILEGE_CMD = 0x3B
    CLOSE_SESSION_CMD = 0x3C
    GET_DEVICE_ID_CMD = 0x01
    COLD_RESET_CMD = 0x02
    WARM_RESET_CMD = 0x03
    GET_SELF_TEST_RESULTS_CMD = 0x04

class IPMIPrivilegeLevel(Enum):
    NO_ACCESS = 0x00
    CALLBACK = 0x01
    USER = 0x02
    OPERATOR = 0x03
    ADMIN = 0x04
    OEM = 0x05

@dataclass
class IPMIResponse:
    """IPMI response information."""
    command: int
    completion_code: int
    data: bytes
    timestamp: float
    source_ip: str
    source_mac: Optional[str]
    hardware_model: Optional[str]
    firmware_version: Optional[str]
    device_id: Optional[str]
    is_physical: bool
    management_network: Optional[str]

@dataclass
class IPMIProbeResult:
    """IPMI probe result."""
    target_ip: str
    target_port: int
    ipmi_responsive: bool
    responses: List[IPMIResponse]
    hardware_info: Dict[str, str]
    management_topology: Dict[str, Any]
    security_assessment: List[str]
    confidence_score: float

class IPMIProber:
    """Advanced IPMI out-of-band management prober."""
    
    def __init__(self):
        self.ipmi_port = 623
        self.timeout = 5.0
        
        # IPMI constants
        self.RMCP_CLASS_IPMI = 0x06
        self.RMCP_CLASS_ASF = 0x11
        self.IPMI_NETFN_APP = 0x06
        self.IPMI_NETFN_SENSOR_EVENT = 0x04
        self.IPMI_NETFN_STORAGE = 0x0A
        self.IPMI_NETFN_TRANSPORT = 0x0C
        
        # Hardware vendor signatures
        self.vendor_signatures = {
            "DELL": {
                "device_id_patterns": [0x00, 0x10, 0x20],
                "firmware_patterns": [b"Dell", b"PowerEdge"],
                "model_patterns": [b"PowerEdge", b"PowerVault"]
            },
            "HP": {
                "device_id_patterns": [0x01, 0x11, 0x21],
                "firmware_patterns": [b"HP", b"ProLiant"],
                "model_patterns": [b"ProLiant", b"Integrity"]
            },
            "IBM": {
                "device_id_patterns": [0x02, 0x12, 0x22],
                "firmware_patterns": [b"IBM", b"System x"],
                "model_patterns": [b"System x", b"BladeCenter"]
            },
            "SUPERMICRO": {
                "device_id_patterns": [0x03, 0x13, 0x23],
                "firmware_patterns": [b"Supermicro", b"X9"],
                "model_patterns": [b"X9", b"X10", b"X11"]
            }
        }
    
    def probe_ipmi_interface(self, target_ip: str, target_port: int = 623) -> IPMIProbeResult:
        """Probe IPMI interface for management information."""
        start_time = time.time()
        
        try:
            responses = []
            
            # Send Get Device ID command
            device_id_response = self._send_get_device_id(target_ip, target_port)
            if device_id_response:
                responses.append(device_id_response)
            
            # Send Get Channel Authentication command
            auth_response = self._send_get_channel_auth(target_ip, target_port)
            if auth_response:
                responses.append(auth_response)
            
            # Analyze responses
            hardware_info = self._analyze_hardware_info(responses)
            management_topology = self._analyze_management_topology(responses, target_ip)
            security_assessment = self._assess_ipmi_security(responses, hardware_info)
            
            # Calculate confidence
            confidence = self._calculate_confidence(responses)
            
            return IPMIProbeResult(
                target_ip=target_ip,
                target_port=target_port,
                ipmi_responsive=len(responses) > 0,
                responses=responses,
                hardware_info=hardware_info,
                management_topology=management_topology,
                security_assessment=security_assessment,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[IPMI] Probe failed: {e}")
            return IPMIProbeResult(
                target_ip=target_ip,
                target_port=target_port,
                ipmi_responsive=False,
                responses=[],
                hardware_info={},
                management_topology={},
                security_assessment=[f"Probe failed: {e}"],
                confidence_score=0.0
            )
    
    def _send_get_device_id(self, target_ip: str, target_port: int) -> Optional[IPMIResponse]:
        """Send Get Device ID command."""
        try:
            # Create IPMI Get Device ID request
            request_data = self._create_ipmi_request(
                netfn=self.IPMI_NETFN_APP,
                lun=0,
                cmd=IPMICommand.GET_DEVICE_ID_CMD.value,
                data=b""
            )
            
            # Create RMCP packet
            rmcp_packet = self._create_rmcp_packet(request_data)
            
            # Send packet
            start_time = time.time()
            response = self._send_ipmi_packet(target_ip, target_port, rmcp_packet)
            response_time = (time.time() - start_time) * 1000
            
            if response:
                return IPMIResponse(
                    command=IPMICommand.GET_DEVICE_ID_CMD.value,
                    completion_code=response[0] if len(response) > 0 else 0xFF,
                    data=response[1:] if len(response) > 1 else b"",
                    timestamp=response_time,
                    source_ip=target_ip,
                    source_mac=None,
                    hardware_model=None,
                    firmware_version=None,
                    device_id=None,
                    is_physical=True,
                    management_network=None
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"[IPMI] Get Device ID failed: {e}")
            return None
    
    def _send_get_channel_auth(self, target_ip: str, target_port: int) -> Optional[IPMIResponse]:
        """Send Get Channel Authentication command."""
        try:
            # Create IPMI Get Channel Authentication request
            request_data = self._create_ipmi_request(
                netfn=self.IPMI_NETFN_APP,
                lun=0,
                cmd=IPMICommand.GET_CHANNEL_AUTH_CMD.value,
                data=bytes([0x0E, 0x00])  # Channel 0xE, get info
            )
            
            # Create RMCP packet
            rmcp_packet = self._create_rmcp_packet(request_data)
            
            # Send packet
            start_time = time.time()
            response = self._send_ipmi_packet(target_ip, target_port, rmcp_packet)
            response_time = (time.time() - start_time) * 1000
            
            if response:
                return IPMIResponse(
                    command=IPMICommand.GET_CHANNEL_AUTH_CMD.value,
                    completion_code=response[0] if len(response) > 0 else 0xFF,
                    data=response[1:] if len(response) > 1 else b"",
                    timestamp=response_time,
                    source_ip=target_ip,
                    source_mac=None,
                    hardware_model=None,
                    firmware_version=None,
                    device_id=None,
                    is_physical=True,
                    management_network=None
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"[IPMI] Get Channel Auth failed: {e}")
            return None
    
    def _create_ipmi_request(self, netfn: int, lun: int, cmd: int, data: bytes) -> bytes:
        """Create IPMI request packet."""
        # IPMI request header
        header = struct.pack(
            "!BBBB",
            netfn << 2,  # Net function + target address
            lun,           # Logical unit number
            cmd,           # Command
            0x00           # Sequence number
        )
        
        return header + data
    
    def _create_rmcp_packet(self, ipmi_data: bytes) -> bytes:
        """Create RMCP packet containing IPMI data."""
        # RMCP header
        rmcp_header = struct.pack(
            "!BBHI",
            0x06,           # Version
            0x00,           # Reserved
            len(ipmi_data) + 1,  # Sequence + data length
            0xFF,           # Sequence number
            self.RMCP_CLASS_IPMI,  # Class
            0x00            # Auth type (none)
        )
        
        return rmcp_header + ipmi_data
    
    def _send_ipmi_packet(self, target_ip: str, target_port: int, packet: bytes) -> Optional[bytes]:
        """Send IPMI packet and receive response."""
        try:
            if HAS_SCAPY:
                # Use Scapy for packet crafting
                ip_packet = IP(dst=target_ip)
                udp_packet = UDP(sport=623, dport=target_port)
                raw_packet = Raw(packet)
                
                full_packet = ip_packet / udp_packet / raw_packet
                
                response = sr1(full_packet, timeout=self.timeout, verbose=0)
                
                if response and response.haslayer(UDP):
                    return bytes(response[UDP].payload)
            else:
                # Fallback to raw sockets
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                try:
                    sock.sendto(packet, (target_ip, target_port))
                    response, addr = sock.recvfrom(1024)
                    return response
                finally:
                    sock.close()
            
            return None
            
        except Exception as e:
            logger.debug(f"[IPMI] Packet send failed: {e}")
            return None
    
    def _analyze_hardware_info(self, responses: List[IPMIResponse]) -> Dict[str, str]:
        """Analyze hardware information from IPMI responses."""
        hardware_info = {
            "vendor": "unknown",
            "model": "unknown",
            "firmware_version": "unknown",
            "device_id": "unknown",
            "ipmi_version": "unknown"
        }
        
        for response in responses:
            if response.command == IPMICommand.GET_DEVICE_ID_CMD.value:
                # Parse device ID response
                if len(response.data) >= 10:
                    # Device ID and revision
                    device_id = response.data[0]
                    revision = response.data[1]
                    
                    # Firmware revision
                    fw_major = response.data[2]
                    fw_minor = response.data[3]
                    
                    # IPMI version
                    ipmi_major = response.data[5]
                    ipmi_minor = response.data[6]
                    
                    # Manufacturer ID
                    mfg_id = struct.unpack("!I", response.data[7:11])[0] & 0xFFFFFF
                    
                    # Product ID
                    prod_id = struct.unpack("!H", response.data[11:13])[0]
                    
                    hardware_info["device_id"] = f"0x{device_id:02X}"
                    hardware_info["firmware_version"] = f"{fw_major}.{fw_minor}"
                    hardware_info["ipmi_version"] = f"{ipmi_major}.{ipmi_minor}"
                    hardware_info["manufacturer_id"] = f"0x{mfg_id:06X}"
                    hardware_info["product_id"] = f"0x{prod_id:04X}"
                    
                    # Identify vendor
                    vendor = self._identify_vendor(mfg_id, response.data)
                    hardware_info["vendor"] = vendor
                    
                    # Extract additional data if available
                    if len(response.data) > 15:
                        # Device string
                        device_str = response.data[15:].decode('ascii', errors='ignore').rstrip('\x00')
                        if device_str:
                            hardware_info["device_string"] = device_str
                            hardware_info["model"] = self._extract_model_from_string(device_str, vendor)
        
        return hardware_info
    
    def _identify_vendor(self, mfg_id: int, response_data: bytes) -> str:
        """Identify vendor from manufacturer ID."""
        # Common IPMI manufacturer IDs
        vendor_ids = {
            0x0000A2: "Dell",
            0x0000A7: "HP",
            0x0000A4: "IBM",
            0x0000A8: "Intel",
            0x0000A1: "Supermicro",
            0x0000A0: "NEC",
            0x0000A3: "Fujitsu",
            0x0000A6: "Oracle",
            0x0000A9: "Quanta",
            0x0000AA: "Wistron",
            0x0000AB: "Inventec",
            0x0000AC: "Arima",
            0x0000AD: "Casio"
        }
        
        return vendor_ids.get(mfg_id, "unknown")
    
    def _extract_model_from_string(self, device_str: str, vendor: str) -> str:
        """Extract model from device string."""
        if vendor in self.vendor_signatures:
            patterns = self.vendor_signatures[vendor]["model_patterns"]
            for pattern in patterns:
                if isinstance(pattern, bytes):
                    pattern_str = pattern.decode('ascii', errors='ignore')
                else:
                    pattern_str = pattern
                
                if pattern_str.lower() in device_str.lower():
                    return pattern_str
        
        return device_str
    
    def _analyze_management_topology(self, responses: List[IPMIResponse], target_ip: str) -> Dict[str, Any]:
        """Analyze management topology from IPMI responses."""
        topology = {
            "management_ip": target_ip,
            "management_network": "unknown",
            "is_physical": True,
            "management_subnet": "unknown",
            "oob_network": False
        }
        
        # Determine if this is out-of-band management
        if responses:
            # Check if management IP is different from typical ranges
            management_ip = target_ip
            
            # Check for private management networks
            if (management_ip.startswith("192.168.") or 
                management_ip.startswith("10.") or
                management_ip.startswith("172.")):
                topology["management_network"] = "private"
                topology["oob_network"] = True
            elif (management_ip.startswith("169.254.") or
                  management_ip.startswith("127.")):
                topology["management_network"] = "link_local"
            else:
                topology["management_network"] = "public"
            
            # Extract subnet information
            if "." in management_ip:
                octets = management_ip.split(".")
                if len(octets) >= 3:
                    topology["management_subnet"] = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        
        return topology
    
    def _assess_ipmi_security(self, responses: List[IPMIResponse], hardware_info: Dict[str, str]) -> List[str]:
        """Assess IPMI security configuration."""
        assessment = []
        
        if not responses:
            assessment.append("No IPMI response - interface may be filtered or disabled")
            return assessment
        
        # Check for known vulnerabilities
        vendor = hardware_info.get("vendor", "unknown")
        firmware_version = hardware_info.get("firmware_version", "unknown")
        
        if vendor == "Dell":
            assessment.append("Dell iDRAC detected - check for iDRAC vulnerabilities")
            if firmware_version and self._is_vulnerable_firmware(firmware_version, "dell"):
                assessment.append("CRITICAL: Vulnerable Dell iDRAC firmware detected")
        
        elif vendor == "HP":
            assessment.append("HP iLO detected - check for iLO vulnerabilities")
            if firmware_version and self._is_vulnerable_firmware(firmware_version, "hp"):
                assessment.append("CRITICAL: Vulnerable HP iLO firmware detected")
        
        elif vendor == "Supermicro":
            assessment.append("Supermicro IPMI detected - check for IPMI 2.0 vulnerabilities")
            assessment.append("WARNING: IPMI 2.0 cipher suite 0 vulnerability may be present")
        
        # Check for authentication bypasses
        for response in responses:
            if response.command == IPMICommand.GET_CHANNEL_AUTH_CMD.value:
                if response.completion_code == 0x00:
                    # Check authentication capabilities
                    if len(response.data) >= 8:
                        auth_types = response.data[8]
                        if auth_types & 0x02:  # MD5
                            assessment.append("WARNING: MD5 authentication enabled")
                        if auth_types & 0x04:  # MD2
                            assessment.append("WARNING: MD2 authentication enabled")
                        if not (auth_types & 0x10):  # No OEM auth
                            assessment.append("INFO: No OEM authentication detected")
        
        # General security recommendations
        assessment.append("IPMI provides out-of-band management access")
        assessment.append("Ensure IPMI is isolated from production networks")
        assessment.append("Use strong authentication and encryption")
        assessment.append("Regularly update IPMI firmware")
        
        return assessment
    
    def _is_vulnerable_firmware(self, firmware_version: str, vendor: str) -> bool:
        """Check if firmware version is known to be vulnerable."""
        # This is a simplified implementation
        # Real implementation would maintain a vulnerability database
        
        vulnerable_versions = {
            "dell": ["1.5", "1.6", "2.0", "2.1"],
            "hp": ["1.0", "1.1", "2.0", "2.1"],
            "supermicro": ["2.0", "2.1", "3.0"]
        }
        
        vendor_vulns = vulnerable_versions.get(vendor.lower(), [])
        return firmware_version in vendor_vulns
    
    def _calculate_confidence(self, responses: List[IPMIResponse]) -> float:
        """Calculate confidence score for IPMI analysis."""
        if not responses:
            return 0.0
        
        # Base confidence from number of responses
        base_confidence = min(1.0, len(responses) / 2.0)
        
        # Adjust for response quality
        successful_responses = [r for r in responses if r.completion_code == 0x00]
        quality_confidence = min(1.0, len(successful_responses) / len(responses))
        
        # Combined confidence
        overall_confidence = (base_confidence + quality_confidence) / 2.0
        
        return min(1.0, overall_confidence)
    
    def generate_ipmi_report(self, result: IPMIProbeResult) -> str:
        """Generate human-readable IPMI report."""
        report = []
        report.append("IPMI Out-of-Band Management Discovery Report")
        report.append("=" * 50)
        report.append(f"Target IP: {result.target_ip}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"IPMI Responsive: {result.ipmi_responsive}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        if result.hardware_info:
            report.append("Hardware Information:")
            for key, value in result.hardware_info.items():
                if value != "unknown":
                    report.append(f"  - {key}: {value}")
            report.append("")
        
        if result.management_topology:
            report.append("Management Topology:")
            for key, value in result.management_topology.items():
                if value != "unknown":
                    report.append(f"  - {key}: {value}")
            report.append("")
        
        if result.security_assessment:
            report.append("Security Assessment:")
            for assessment in result.security_assessment:
                report.append(f"  - {assessment}")
            report.append("")
        
        return "\n".join(report)

# Global instance
_ipmi_prober = None

def get_ipmi_prober() -> IPMIProber:
    """Get global IPMI prober."""
    global _ipmi_prober
    if _ipmi_prober is None:
        _ipmi_prober = IPMIProber()
    return _ipmi_prober

def probe_ipmi_interface(target_ip: str, target_port: int = 623) -> IPMIProbeResult:
    """Convenience function for IPMI probing."""
    prober = get_ipmi_prober()
    return prober.probe_ipmi_interface(target_ip, target_port)

def generate_ipmi_report(result: IPMIProbeResult) -> str:
    """Convenience function for IPMI report generation."""
    prober = get_ipmi_prober()
    return prober.generate_ipmi_report(result)
