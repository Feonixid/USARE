"""NTP Intelligence Fingerprinting for Network Topology Mapping.

Fingerprints NTP servers to extract software versions, uptime,
peer lists, and client information for network topology analysis.

Uses NTP mode 6 (control messages) and mode 7 (private commands)
to gather intelligence that most firewalls allow through.
"""

import logging
import time
import socket
import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, UDP, Raw, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.ntp_intelligence")

class NTPMode(Enum):
    MODE_0 = 0    # Reserved
    MODE_1 = 1    # Symmetric active
    MODE_2 = 2    # Symmetric passive
    MODE_3 = 3    # Client
    MODE_4 = 4    # Server
    MODE_5 = 5    # Broadcast
    MODE_6 = 6    # Control message
    MODE_7 = 7    # Private/implementation-specific

class NTPControlCode(Enum):
    READ_STAT = 1
    READ_VARS = 2
    WRITE_VARS = 3
    READ_CLOCK = 4
    WRITE_CLOCK = 5
    SET_PROCESSOR = 6
    REQ_PEER_LIST = 7
    SET_HOLD_OFF = 8
    CLEAR_HOLD_OFF = 9
    READ_KERNEL = 10
    READ_VAR_LIST = 11

@dataclass
class NTPResponse:
    """NTP response information."""
    mode: int
    stratum: int
    precision: int
    root_delay: int
    root_dispersion: int
    reference_identifier: str
    reference_timestamp: float
    originate_timestamp: float
    receive_timestamp: float
    transmit_timestamp: float
    peer_list: List[str]
    uptime_seconds: int
    software_version: str
    client_list: List[str]
    timestamp: float
    source_ip: str

@dataclass
class NTPIntelligenceResult:
    """NTP intelligence analysis result."""
    target_ip: str
    target_port: int
    ntp_responsive: bool
    software_info: Dict[str, str]
    uptime_info: Dict[str, int]
    peer_topology: List[str]
    client_topology: List[str]
    network_hierarchy: Dict[str, Any]
    security_assessment: List[str]
    confidence_score: float

class NTPIntelligence:
    """Advanced NTP intelligence gatherer."""
    
    def __init__(self):
        self.ntp_port = 123
        self.timeout = 5.0
        
        # NTP software signatures
        self.software_signatures = {
            "ntpd": {
                "version_patterns": [b"ntpd", b"Network Time Protocol"],
                "stratum_range": (1, 15),
                "precision_range": (-20, -6)
            },
            "chrony": {
                "version_patterns": [b"chronyd", b"chrony"],
                "stratum_range": (1, 15),
                "precision_range": (-20, -6)
            },
            "windows_time": {
                "version_patterns": [b"Windows Time", b"W32Time"],
                "stratum_range": (1, 15),
                "precision_range": (-10, -6)
            },
            "openntpd": {
                "version_patterns": [b"OpenNTPD", b"openntpd"],
                "stratum_range": (1, 15),
                "precision_range": (-20, -6)
            }
        }
        
        # NTP leap indicators
        self.leap_indicators = {
            0: "No warning",
            1: "Last minute has 61 seconds",
            2: "Last minute has 59 seconds",
            3: "Alarm condition (clock not synchronized)"
        }
    
    def gather_ntp_intelligence(self, target_ip: str, target_port: int = 123) -> NTPIntelligenceResult:
        """Gather comprehensive NTP intelligence."""
        start_time = time.time()
        
        try:
            responses = []
            
            # Send standard NTP request (mode 3)
            standard_response = self._send_ntp_request(target_ip, target_port, NTPMode.MODE_3)
            if standard_response:
                responses.append(standard_response)
            
            # Send control message (mode 6) - read variables
            control_response = self._send_control_message(target_ip, target_port, NTPControlCode.READ_VARS)
            if control_response:
                responses.append(control_response)
            
            # Send control message (mode 6) - read peer list
            peer_response = self._send_control_message(target_ip, target_port, NTPControlCode.REQ_PEER_LIST)
            if peer_response:
                responses.append(peer_response)
            
            # Send private message (mode 7) - monlist (if available)
            monlist_response = self._send_private_message(target_ip, target_port, 42)  # monlist code
            if monlist_response:
                responses.append(monlist_response)
            
            # Analyze collected responses
            software_info = self._analyze_software_info(responses)
            uptime_info = self._analyze_uptime_info(responses)
            peer_topology = self._analyze_peer_topology(responses)
            client_topology = self._analyze_client_topology(responses)
            network_hierarchy = self._analyze_network_hierarchy(responses)
            security_assessment = self._assess_ntp_security(responses, software_info)
            
            # Calculate confidence
            confidence = self._calculate_confidence(responses)
            
            return NTPIntelligenceResult(
                target_ip=target_ip,
                target_port=target_port,
                ntp_responsive=len(responses) > 0,
                software_info=software_info,
                uptime_info=uptime_info,
                peer_topology=peer_topology,
                client_topology=client_topology,
                network_hierarchy=network_hierarchy,
                security_assessment=security_assessment,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[NTP Intel] Intelligence gathering failed: {e}")
            return NTPIntelligenceResult(
                target_ip=target_ip,
                target_port=target_port,
                ntp_responsive=False,
                software_info={},
                uptime_info={},
                peer_topology=[],
                client_topology=[],
                network_hierarchy={},
                security_assessment=[f"Analysis failed: {e}"],
                confidence_score=0.0
            )
    
    def _send_ntp_request(self, target_ip: str, target_port: int, mode: NTPMode) -> Optional[NTPResponse]:
        """Send NTP request and parse response."""
        try:
            # Create NTP packet
            ntp_packet = self._create_ntp_packet(mode)
            
            # Send packet
            start_time = time.time()
            response_data = self._send_ntp_packet_raw(target_ip, target_port, ntp_packet)
            response_time = (time.time() - start_time) * 1000
            
            if response_data:
                return self._parse_ntp_response(response_data, mode, response_time)
            
            return None
            
        except Exception as e:
            logger.debug(f"[NTP Intel] NTP request failed: {e}")
            return None
    
    def _send_control_message(self, target_ip: str, target_port: int, control_code: NTPControlCode) -> Optional[NTPResponse]:
        """Send NTP control message."""
        try:
            # Create control message packet
            control_packet = self._create_control_packet(control_code)
            
            # Send packet
            start_time = time.time()
            response_data = self._send_ntp_packet_raw(target_ip, target_port, control_packet)
            response_time = (time.time() - start_time) * 1000
            
            if response_data:
                return self._parse_control_response(response_data, response_time)
            
            return None
            
        except Exception as e:
            logger.debug(f"[NTP Intel] Control message failed: {e}")
            return None
    
    def _send_private_message(self, target_ip: str, target_port: int, request_code: int) -> Optional[NTPResponse]:
        """Send NTP private message."""
        try:
            # Create private message packet
            private_packet = self._create_private_packet(request_code)
            
            # Send packet
            start_time = time.time()
            response_data = self._send_ntp_packet_raw(target_ip, target_port, private_packet)
            response_time = (time.time() - start_time) * 1000
            
            if response_data:
                return self._parse_private_response(response_data, request_code, response_time)
            
            return None
            
        except Exception as e:
            logger.debug(f"[NTP Intel] Private message failed: {e}")
            return None
    
    def _create_ntp_packet(self, mode: NTPMode) -> bytes:
        """Create NTP packet."""
        # NTP packet header (48 bytes)
        li_vn_mode = (0 << 6) | (4 << 3) | mode.value  # LI=0, VN=4, Mode=specified
        stratum = 1
        poll = 4
        precision = -6
        root_delay = 0
        root_dispersion = 0
        reference_identifier = 0
        
        # Timestamps (all zero for request)
        reference_timestamp = 0
        originate_timestamp = 0
        receive_timestamp = 0
        transmit_timestamp = time.time() + 2208988800  # NTP epoch
        
        return struct.pack(
            "!BBBBIIIIIIII",
            li_vn_mode, stratum, poll, precision,
            root_delay, root_dispersion, reference_identifier,
            reference_timestamp, originate_timestamp, receive_timestamp,
            transmit_timestamp
        )
    
    def _create_control_packet(self, control_code: NTPControlCode) -> bytes:
        """Create NTP control message packet."""
        # Control message format
        li_vn_mode = (0 << 6) | (4 << 3) | NTPMode.MODE_6.value
        sequence = 0
        status = 0
        association_id = 0
        offset = 0
        count = 0
        data = b""
        
        # Pack header
        header = struct.pack(
            "!BBBBHHH",
            li_vn_mode, sequence, status, association_id,
            offset, count
        )
        
        # Add control code and data
        if control_code == NTPControlCode.READ_VARS:
            data = struct.pack("!H", control_code.value)
        elif control_code == NTPControlCode.REQ_PEER_LIST:
            data = struct.pack("!H", control_code.value)
        
        return header + data
    
    def _create_private_packet(self, request_code: int) -> bytes:
        """Create NTP private message packet."""
        # Private message format
        li_vn_mode = (0 << 6) | (4 << 3) | NTPMode.MODE_7.value
        sequence = 0
        status = 0
        association_id = 0
        offset = 0
        count = 0
        data = struct.pack("!H", request_code)
        
        # Pack header
        header = struct.pack(
            "!BBBBHHH",
            li_vn_mode, sequence, status, association_id,
            offset, count
        )
        
        return header + data
    
    def _send_ntp_packet_raw(self, target_ip: str, target_port: int, packet: bytes) -> Optional[bytes]:
        """Send NTP packet and receive response."""
        try:
            if HAS_SCAPY:
                # Use Scapy for packet crafting
                ip_packet = IP(dst=target_ip)
                udp_packet = UDP(sport=123, dport=target_port)
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
            logger.debug(f"[NTP Intel] Packet send failed: {e}")
            return None
    
    def _parse_ntp_response(self, response_data: bytes, mode: NTPMode, response_time: float) -> NTPResponse:
        """Parse NTP response."""
        try:
            if len(response_data) < 48:
                return self._create_empty_response(response_time)
            
            # Unpack NTP header
            (li_vn_mode, stratum, poll, precision,
             root_delay, root_dispersion, reference_identifier,
             reference_timestamp, originate_timestamp, receive_timestamp,
             transmit_timestamp) = struct.unpack("!BBBBIIIIIIII", response_data[:48])
            
            # Extract fields
            li = (li_vn_mode >> 6) & 0x03
            vn = (li_vn_mode >> 3) & 0x07
            response_mode = li_vn_mode & 0x07
            
            # Convert timestamps
            ref_ts = self._ntp_to_unix_time(reference_timestamp)
            orig_ts = self._ntp_to_unix_time(originate_timestamp)
            recv_ts = self._ntp_to_unix_time(receive_timestamp)
            tx_ts = self._ntp_to_unix_time(transmit_timestamp)
            
            # Convert reference identifier
            if stratum == 1:
                ref_id = bytes([reference_identifier & 0xFF, 
                              (reference_identifier >> 8) & 0xFF,
                              (reference_identifier >> 16) & 0xFF,
                              (reference_identifier >> 24) & 0xFF]).decode('ascii', errors='ignore')
            else:
                ref_id = socket.inet_ntoa(struct.pack("!I", reference_identifier))
            
            return NTPResponse(
                mode=response_mode,
                stratum=stratum,
                precision=precision,
                root_delay=root_delay,
                root_dispersion=root_dispersion,
                reference_identifier=ref_id,
                reference_timestamp=ref_ts,
                originate_timestamp=orig_ts,
                receive_timestamp=recv_ts,
                transmit_timestamp=tx_ts,
                peer_list=[],
                uptime_seconds=0,
                software_version="",
                client_list=[],
                timestamp=response_time,
                source_ip=""
            )
            
        except Exception as e:
            logger.debug(f"[NTP Intel] NTP response parsing failed: {e}")
            return self._create_empty_response(response_time)
    
    def _parse_control_response(self, response_data: bytes, response_time: float) -> NTPResponse:
        """Parse NTP control response."""
        try:
            if len(response_data) < 12:
                return self._create_empty_response(response_time)
            
            # Unpack control response header
            (li_vn_mode, sequence, status, association_id,
             offset, count) = struct.unpack("!BBBBHHH", response_data[:12])
            
            response_mode = li_vn_mode & 0x07
            
            # Parse data based on count
            data = response_data[12+offset:]
            variables = {}
            
            if count > 0:
                # Parse variable list
                pos = 0
                while pos < len(data) - 4:
                    # Variable format: name=value\x00
                    end_pos = data.find(b'\x00', pos)
                    if end_pos == -1:
                        break
                    
                    var_data = data[pos:end_pos].decode('ascii', errors='ignore')
                    if '=' in var_data:
                        name, value = var_data.split('=', 1)
                        variables[name] = value
                    
                    pos = end_pos + 1
            
            return NTPResponse(
                mode=response_mode,
                stratum=0,
                precision=0,
                root_delay=0,
                root_dispersion=0,
                reference_identifier="",
                reference_timestamp=0,
                originate_timestamp=0,
                receive_timestamp=0,
                transmit_timestamp=0,
                peer_list=[],
                uptime_seconds=0,
                software_version=variables.get("version", ""),
                client_list=[],
                timestamp=response_time,
                source_ip=""
            )
            
        except Exception as e:
            logger.debug(f"[NTP Intel] Control response parsing failed: {e}")
            return self._create_empty_response(response_time)
    
    def _parse_private_response(self, response_data: bytes, request_code: int, response_time: float) -> NTPResponse:
        """Parse NTP private message response."""
        try:
            if request_code == 42:  # monlist
                return self._parse_monlist_response(response_data, response_time)
            else:
                return self._parse_control_response(response_data, response_time)
                
        except Exception as e:
            logger.debug(f"[NTP Intel] Private response parsing failed: {e}")
            return self._create_empty_response(response_time)
    
    def _parse_monlist_response(self, response_data: bytes, response_time: float) -> NTPResponse:
        """Parse monlist response (client list)."""
        try:
            if len(response_data) < 4:
                return self._create_empty_response(response_time)
            
            # monlist format: count (2 bytes) + list of IP addresses
            count = struct.unpack("!H", response_data[:2])[0]
            client_list = []
            
            pos = 4  # Skip count and reserved bytes
            for i in range(count):
                if pos + 4 > len(response_data):
                    break
                
                # Extract IP address
                ip_bytes = response_data[pos:pos+4]
                ip_addr = socket.inet_ntoa(ip_bytes)
                client_list.append(ip_addr)
                pos += 4
            
            return NTPResponse(
                mode=7,
                stratum=0,
                precision=0,
                root_delay=0,
                root_dispersion=0,
                reference_identifier="",
                reference_timestamp=0,
                originate_timestamp=0,
                receive_timestamp=0,
                transmit_timestamp=0,
                peer_list=[],
                uptime_seconds=0,
                software_version="",
                client_list=client_list,
                timestamp=response_time,
                source_ip=""
            )
            
        except Exception as e:
            logger.debug(f"[NTP Intel] Monlist parsing failed: {e}")
            return self._create_empty_response(response_time)
    
    def _ntp_to_unix_time(self, ntp_timestamp: int) -> float:
        """Convert NTP timestamp to Unix timestamp."""
        return ntp_timestamp - 2208988800
    
    def _create_empty_response(self, response_time: float) -> NTPResponse:
        """Create empty NTP response."""
        return NTPResponse(
            mode=0,
            stratum=0,
            precision=0,
            root_delay=0,
            root_dispersion=0,
            reference_identifier="",
            reference_timestamp=0,
            originate_timestamp=0,
            receive_timestamp=0,
            transmit_timestamp=0,
            peer_list=[],
            uptime_seconds=0,
            software_version="",
            client_list=[],
            timestamp=response_time,
            source_ip=""
        )
    
    def _analyze_software_info(self, responses: List[NTPResponse]) -> Dict[str, str]:
        """Analyze software information from NTP responses."""
        software_info = {
            "software": "unknown",
            "version": "unknown",
            "stratum": "unknown",
            "precision": "unknown"
        }
        
        for response in responses:
            if response.software_version:
                # Identify software from version string
                for software_name, signature in self.software_signatures.items():
                    for pattern in signature["version_patterns"]:
                        if pattern in response.software_version.encode():
                            software_info["software"] = software_name
                            software_info["version"] = response.software_version
                            break
            
            if response.stratum > 0:
                software_info["stratum"] = str(response.stratum)
            
            if response.precision != 0:
                software_info["precision"] = str(response.precision)
        
        return software_info
    
    def _analyze_uptime_info(self, responses: List[NTPResponse]) -> Dict[str, int]:
        """Analyze uptime information from NTP responses."""
        uptime_info = {
            "uptime_seconds": 0,
            "uptime_days": 0,
            "uptime_hours": 0
        }
        
        # Some NTP implementations provide uptime in variables
        for response in responses:
            if response.software_version and "uptime" in response.software_version.lower():
                # Extract uptime from version string
                try:
                    uptime_str = response.software_version
                    if "uptime=" in uptime_str:
                        uptime_part = uptime_str.split("uptime=")[1].split()[0]
                        uptime_seconds = int(uptime_part)
                        
                        uptime_info["uptime_seconds"] = uptime_seconds
                        uptime_info["uptime_days"] = uptime_seconds // 86400
                        uptime_info["uptime_hours"] = (uptime_seconds % 86400) // 3600
                        break
                except:
                    pass
        
        return uptime_info
    
    def _analyze_peer_topology(self, responses: List[NTPResponse]) -> List[str]:
        """Analyze peer topology from NTP responses."""
        peer_list = []
        
        for response in responses:
            if response.peer_list:
                peer_list.extend(response.peer_list)
            
            # Some implementations provide peer information in variables
            if response.software_version:
                version_str = response.software_version.lower()
                if "peer" in version_str:
                    # Extract peer information
                    try:
                        for line in version_str.split('\n'):
                            if 'peer' in line and '=' in line:
                                peer_info = line.split('=')[1].strip()
                                peer_list.append(peer_info)
                    except:
                        pass
        
        return list(set(peer_list))
    
    def _analyze_client_topology(self, responses: List[NTPResponse]) -> List[str]:
        """Analyze client topology from NTP responses."""
        client_list = []
        
        for response in responses:
            if response.client_list:
                client_list.extend(response.client_list)
        
        return list(set(client_list))
    
    def _analyze_network_hierarchy(self, responses: List[NTPResponse]) -> Dict[str, Any]:
        """Analyze network hierarchy from NTP responses."""
        hierarchy = {
            "stratum_level": "unknown",
            "sync_source": "unknown",
            "reference_clock": "unknown",
            "leap_indicator": "unknown"
        }
        
        for response in responses:
            if response.stratum > 0:
                hierarchy["stratum_level"] = str(response.stratum)
                
                if response.stratum == 1:
                    hierarchy["sync_source"] = "reference_clock"
                    hierarchy["reference_clock"] = response.reference_identifier
                else:
                    hierarchy["sync_source"] = "upstream_server"
                    hierarchy["reference_clock"] = response.reference_identifier
        
        return hierarchy
    
    def _assess_ntp_security(self, responses: List[NTPResponse], software_info: Dict[str, str]) -> List[str]:
        """Assess NTP security configuration."""
        assessment = []
        
        if not responses:
            assessment.append("No NTP response - service may be filtered")
            return assessment
        
        software = software_info.get("software", "unknown")
        version = software_info.get("version", "unknown")
        
        # Check for known vulnerable versions
        if software == "ntpd" and version:
            if "4.2.6" in version:
                assessment.append("WARNING: ntpd 4.2.6 has known vulnerabilities")
            elif "4.2.8" in version:
                assessment.append("INFO: ntpd 4.2.8 is relatively secure")
        
        # Check for monlist availability (potential DDoS amplification)
        for response in responses:
            if response.client_list and len(response.client_list) > 0:
                assessment.append("WARNING: Monlist command enabled - potential DDoS amplification vector")
                assessment.append(f"INFO: Server revealed {len(response.client_list)} recent clients")
                break
        
        # Check stratum configuration
        stratum = software_info.get("stratum", "unknown")
        if stratum != "unknown":
            stratum_int = int(stratum) if stratum.isdigit() else 0
            if stratum_int == 0:
                assessment.append("WARNING: Unspecified stratum - clock not synchronized")
            elif stratum_int > 5:
                assessment.append("INFO: High stratum level - many hops from reference clock")
        
        # General security recommendations
        assessment.append("NTP is critical infrastructure - ensure proper security")
        assessment.append("Monitor NTP logs for unusual activity")
        assessment.append("Keep NTP software updated")
        assessment.append("Restrict NTP access to authorized clients only")
        
        return assessment
    
    def _calculate_confidence(self, responses: List[NTPResponse]) -> float:
        """Calculate confidence score for NTP intelligence."""
        if not responses:
            return 0.0
        
        # Base confidence from number of responses
        base_confidence = min(1.0, len(responses) / 3.0)
        
        # Quality confidence from response types
        response_types = set()
        for response in responses:
            if response.mode == 3:
                response_types.add("standard")
            elif response.mode == 6:
                response_types.add("control")
            elif response.mode == 7:
                response_types.add("private")
        
        quality_confidence = min(1.0, len(response_types) / 3.0)
        
        # Combined confidence
        overall_confidence = (base_confidence + quality_confidence) / 2.0
        
        return min(1.0, overall_confidence)
    
    def generate_ntp_report(self, result: NTPIntelligenceResult) -> str:
        """Generate human-readable NTP intelligence report."""
        report = []
        report.append("NTP Intelligence Fingerprinting Report")
        report.append("=" * 50)
        report.append(f"Target IP: {result.target_ip}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"NTP Responsive: {result.ntp_responsive}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        if result.software_info:
            report.append("Software Information:")
            for key, value in result.software_info.items():
                if value != "unknown":
                    report.append(f"  - {key}: {value}")
            report.append("")
        
        if result.uptime_info:
            report.append("Uptime Information:")
            for key, value in result.uptime_info.items():
                if value > 0:
                    report.append(f"  - {key}: {value}")
            report.append("")
        
        if result.peer_topology:
            report.append("Peer Topology:")
            for peer in result.peer_topology:
                report.append(f"  - {peer}")
            report.append("")
        
        if result.client_topology:
            report.append("Client Topology:")
            report.append(f"  - Recent clients: {len(result.client_topology)}")
            for client in result.client_topology[:10]:  # Show first 10
                report.append(f"    {client}")
            if len(result.client_topology) > 10:
                report.append(f"    ... and {len(result.client_topology) - 10} more")
            report.append("")
        
        if result.network_hierarchy:
            report.append("Network Hierarchy:")
            for key, value in result.network_hierarchy.items():
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
_ntp_intel = None

def get_ntp_intel() -> NTPIntelligence:
    """Get global NTP intelligence instance."""
    global _ntp_intel
    if _ntp_intel is None:
        _ntp_intel = NTPIntelligence()
    return _ntp_intel

def gather_ntp_intelligence(target_ip: str, target_port: int = 123) -> NTPIntelligenceResult:
    """Convenience function for NTP intelligence gathering."""
    intel = get_ntp_intel()
    return intel.gather_ntp_intelligence(target_ip, target_port)

def generate_ntp_report(result: NTPIntelligenceResult) -> str:
    """Convenience function for NTP report generation."""
    intel = get_ntp_intel()
    return intel.generate_ntp_report(result)
