"""SNMP Community String Inference for Network Device Discovery.

Generates targeted community string candidates from collected intelligence
and probes network equipment for complete infrastructure mapping.

Uses hostname patterns, domain components, and organizational data
to create highly effective targeted wordlists instead of brute force.
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

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("usare.snmp_inference")

class SNMPVersion(Enum):
    SNMPV1 = "1"
    SNMPV2C = "2c"

class SNMPRequestType(Enum):
    GET_REQUEST = 0xA0
    GET_NEXT_REQUEST = 0xA1
    GET_BULK_REQUEST = 0xA5

class SNMPErrorCode(Enum):
    NO_ERROR = 0
    TOO_BIG = 1
    NO_SUCH_NAME = 2
    BAD_VALUE = 3
    READ_ONLY = 4
    GEN_ERR = 5
    NO_ACCESS = 6
    WRONG_TYPE = 7
    WRONG_LENGTH = 8
    WRONG_ENCODING = 9
    WRONG_VALUE = 10
    NO_CREATION = 11
    INCONSISTENT_VALUE = 12
    RESOURCE_UNAVAILABLE = 13
    COMMIT_FAILED = 14
    UNDO_FAILED = 15
    AUTHORIZATION_ERROR = 16
    NOT_WRITABLE = 17
    INCONSISTENT_NAME = 18

@dataclass
class SNMPResponse:
    """SNMP response information."""
    community_string: str
    request_type: str
    oid: str
    value: Any
    error_code: int
    response_time_ms: float
    source_ip: str
    device_info: Dict[str, Any]

@dataclass
class SNMPInferenceResult:
    """SNMP inference analysis result."""
    target_ip: str
    target_port: int
    successful_communities: List[str]
    device_info: Dict[str, Any]
    routing_table: List[Dict[str, str]]
    arp_table: List[Dict[str, str]]
    interface_info: List[Dict[str, Any]]
    system_description: Optional[str]
    security_assessment: List[str]
    confidence_score: float

class SNMPCommunityInferencer:
    """Advanced SNMP community string inferencer."""
    
    def __init__(self):
        self.snmp_port = 161
        self.timeout = 3.0
        
        # Common SNMP community patterns
        self.common_communities = [
            "public", "private", "community", "snmp", "monitor", "read", "write",
            "admin", "manager", "cisco", "hp", "dell", "ibm", "sun", "net",
            "switch", "router", "firewall", "apc", "ups", "printer", "camera"
        ]
        
        # SNMP OID mappings
        self.snmp_oids = {
            "system": {
                "description": "1.3.6.1.2.1.1.1.0",
                "name": "1.3.6.1.2.1.1.5.0",
                "uptime": "1.3.6.1.2.1.1.3.0",
                "location": "1.3.6.1.2.1.1.6.0",
                "contact": "1.3.6.1.2.1.1.4.0",
                "services": "1.3.6.1.2.1.1.7.0"
            },
            "interfaces": {
                "number": "1.3.6.1.2.1.2.1.0",
                "table": "1.3.6.1.2.1.2.2.1",
                "if_index": "1.3.6.1.2.1.2.2.1.1",
                "if_desc": "1.3.6.1.2.1.2.2.1.2",
                "if_type": "1.3.6.1.2.1.2.2.1.3",
                "if_mtu": "1.3.6.1.2.1.2.2.1.4",
                "if_speed": "1.3.6.1.2.1.2.2.1.5",
                "if_phys": "1.3.6.1.2.1.2.2.1.6",
                "if_admin": "1.3.6.1.2.1.2.2.1.7",
                "if_oper": "1.3.6.1.2.1.2.2.1.8",
                "if_in_octets": "1.3.6.1.2.1.2.2.1.10",
                "if_out_octets": "1.3.6.1.2.1.2.2.1.16"
            },
            "ip": {
                "forwarding": "1.3.6.1.2.1.3.1.0",
                "default_ttl": "1.3.6.1.2.1.4.1.0",
                "route_table": "1.3.6.1.2.1.4.21.1",
                "net_to_media": "1.3.6.1.2.1.4.1.0"
            },
            "arp": {
                "table": "1.3.6.1.2.1.4.22.1",
                "arp_ip": "1.3.6.1.2.1.4.22.1.2",
                "arp_phys": "1.3.6.1.2.1.4.22.1.3",
                "arp_netmask": "1.3.6.1.2.1.4.22.1.4"
            }
        }
    
    def infer_snmp_communities(self, target_ip: str, target_port: int = 161,
                           collected_intel: Optional[Dict[str, Any]] = None) -> SNMPInferenceResult:
        """Infer SNMP community strings and probe network device."""
        start_time = time.time()
        
        try:
            # Generate targeted community strings
            community_candidates = self._generate_community_candidates(target_ip, collected_intel)
            
            # Probe with generated communities
            successful_communities = []
            device_info = {}
            
            for community in community_candidates:
                try:
                    # Test community with system OID
                    response = self._send_snmp_request(target_ip, target_port, community, 
                                                   "1.3.6.1.2.1.1.1.0", SNMPVersion.SNMPV2C)
                    
                    if response and response.error_code == 0:
                        successful_communities.append(community)
                        logger.debug(f"[SNMP] Found community: {community}")
                        
                        # Gather device information
                        device_info = self._gather_device_info(target_ip, target_port, community)
                        if device_info:
                            break  # Stop after first successful community
                        
                except Exception as e:
                    logger.debug(f"[SNMP] Community test failed: {e}")
            
            # If successful community found, gather comprehensive info
            if successful_communities:
                primary_community = successful_communities[0]
                device_info = self._gather_comprehensive_info(target_ip, target_port, primary_community)
            
            # Calculate confidence
            confidence = self._calculate_confidence(successful_communities, device_info)
            
            return SNMPInferenceResult(
                target_ip=target_ip,
                target_port=target_port,
                successful_communities=successful_communities,
                device_info=device_info,
                routing_table=device_info.get("routing_table", []),
                arp_table=device_info.get("arp_table", []),
                interface_info=device_info.get("interface_info", []),
                system_description=device_info.get("system_description"),
                security_assessment=self._assess_snmp_security(device_info),
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[SNMP] Inference failed: {e}")
            return SNMPInferenceResult(
                target_ip=target_ip,
                target_port=target_port,
                successful_communities=[],
                device_info={},
                routing_table=[],
                arp_table=[],
                interface_info=[],
                system_description=None,
                security_assessment=[f"Analysis failed: {e}"],
                confidence_score=0.0
            )
    
    def _generate_community_candidates(self, target_ip: str, 
                                  collected_intel: Optional[Dict[str, Any]]) -> List[str]:
        """Generate targeted community string candidates."""
        candidates = []
        
        # Add common communities
        candidates.extend(self.common_communities)
        
        # Generate from hostname patterns
        hostname = self._resolve_hostname(target_ip)
        if hostname:
            candidates.extend(self._generate_hostname_communities(hostname))
        
        # Generate from domain patterns
        domain = self._extract_domain_from_hostname(hostname) if hostname else ""
        if domain:
            candidates.extend(self._generate_domain_communities(domain))
        
        # Generate from collected intelligence
        if collected_intel:
            candidates.extend(self._generate_intelligence_communities(collected_intel))
        
        # Generate location-based communities
        location = collected_intel.get("location") if collected_intel else ""
        if location:
            candidates.extend(self._generate_location_communities(location))
        
        # Generate vendor-specific communities
        vendor = collected_intel.get("vendor") if collected_intel else ""
        if vendor:
            candidates.extend(self._generate_vendor_communities(vendor))
        
        # Remove duplicates and add variations
        unique_candidates = list(set(candidates))
        extended_candidates = self._add_community_variations(unique_candidates)
        
        return extended_candidates
    
    def _resolve_hostname(self, target_ip: str) -> Optional[str]:
        """Resolve hostname from IP address."""
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            return hostname
        except:
            return None
    
    def _extract_domain_from_hostname(self, hostname: str) -> str:
        """Extract domain from hostname."""
        if not hostname:
            return ""
        
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
    
    def _generate_hostname_communities(self, hostname: str) -> List[str]:
        """Generate community strings from hostname."""
        communities = []
        
        # Base hostname variations
        base_name = hostname.split('.')[0]
        communities.extend([
            base_name.lower(),
            base_name.upper(),
            base_name + "snmp",
            base_name + "ro",
            base_name + "rw",
            base_name + "public",
            base_name + "private"
        ])
        
        # Hostname fragments
        if len(base_name) > 3:
            fragments = [base_name[:3], base_name[-3:], base_name[:4], base_name[-4:]]
            for fragment in fragments:
                communities.extend([
                    fragment.lower(),
                    fragment.upper(),
                    fragment + "snmp",
                    fragment + "ro"
                ])
        
        return communities
    
    def _generate_domain_communities(self, domain: str) -> List[str]:
        """Generate community strings from domain."""
        communities = []
        
        # Domain variations
        communities.extend([
            domain.lower(),
            domain.upper(),
            domain + "snmp",
            domain + "ro",
            domain + "public",
            domain + "private"
        ])
        
        # Domain fragments
        parts = domain.split('.')
        for part in parts:
            if len(part) > 2:
                communities.extend([
                    part.lower(),
                    part.upper(),
                    part + "snmp",
                    part + "ro"
                ])
        
        return communities
    
    def _generate_intelligence_communities(self, intel: Dict[str, Any]) -> List[str]:
        """Generate community strings from collected intelligence."""
        communities = []
        
        # Organization name
        org = intel.get("organization", "")
        if org:
            org_clean = org.replace(" ", "").replace("-", "").replace("_", "")
            communities.extend([
                org_clean.lower(),
                org_clean.upper(),
                org_clean + "snmp",
                org_clean + "ro"
            ])
        
        # Location
        location = intel.get("location", "")
        if location:
            location_clean = location.replace(" ", "").replace("-", "").replace("_", "")
            communities.extend([
                location_clean.lower(),
                location_clean.upper(),
                location_clean + "snmp",
                location_clean + "ro"
            ])
        
        # Product names
        products = intel.get("products", [])
        for product in products:
            product_clean = product.replace(" ", "").replace("-", "").replace("_", "")
            communities.extend([
                product_clean.lower(),
                product_clean.upper(),
                product_clean + "snmp",
                product_clean + "ro"
            ])
        
        return communities
    
    def _generate_location_communities(self, location: str) -> List[str]:
        """Generate location-based community strings."""
        communities = []
        
        location_clean = location.replace(" ", "").replace("-", "").replace("_", "")
        communities.extend([
            location_clean.lower(),
            location_clean.upper(),
            location_clean + "snmp",
            location_clean + "ro",
            location_clean + "public",
            location_clean + "private"
        ])
        
        # Common location prefixes
        prefixes = ["site", "campus", "building", "floor", "room"]
        for prefix in prefixes:
            communities.extend([
                prefix + location_clean.lower(),
                location_clean.lower() + prefix,
                prefix + location_clean.upper(),
                location_clean.upper() + prefix
            ])
        
        return communities
    
    def _generate_vendor_communities(self, vendor: str) -> List[str]:
        """Generate vendor-specific community strings."""
        communities = []
        
        vendor_lower = vendor.lower()
        
        # Vendor-specific patterns
        if "cisco" in vendor_lower:
            communities.extend(["cisco", "cisco_ro", "cisco_rw", "cisco_private"])
        elif "hp" in vendor_lower:
            communities.extend(["hp", "hp_ro", "hp_rw", "hp_private"])
        elif "dell" in vendor_lower:
            communities.extend(["dell", "dell_ro", "dell_rw", "dell_private"])
        elif "ibm" in vendor_lower:
            communities.extend(["ibm", "ibm_ro", "ibm_rw", "ibm_private"])
        elif "juniper" in vendor_lower:
            communities.extend(["juniper", "juniper_ro", "juniper_rw", "juniper_private"])
        
        # Generic vendor patterns
        communities.extend([
            vendor_lower,
            vendor_lower + "_ro",
            vendor_lower + "_rw",
            vendor_lower + "_snmp",
            vendor_lower + "_public",
            vendor_lower + "_private"
        ])
        
        return communities
    
    def _add_community_variations(self, communities: List[str]) -> List[str]:
        """Add common variations to community strings."""
        extended = []
        
        for community in communities:
            # Case variations
            extended.extend([community.lower(), community.upper(), community.capitalize()])
            
            # Number suffixes
            for num in range(1, 10):
                extended.extend([f"{community}{num}", f"{community}_{num}"])
            
            # Common prefixes/suffixes
            prefixes = ["", "net", "sys", "mng", "dev"]
            suffixes = ["", "ro", "rw", "snmp", "public", "private"]
            
            for prefix in prefixes:
                for suffix in suffixes:
                    if prefix and suffix:
                        extended.extend([f"{prefix}_{community}_{suffix}", f"{prefix}{community}{suffix}"])
        
        return list(set(extended))
    
    def _send_snmp_request(self, target_ip: str, target_port: int, community: str,
                          oid: str, version: SNMPVersion) -> Optional[SNMPResponse]:
        """Send SNMP request and parse response."""
        try:
            # Create SNMP packet
            snmp_packet = self._create_snmp_packet(community, oid, version)
            
            # Send packet
            start_time = time.time()
            response_data = self._send_snmp_packet_raw(target_ip, target_port, snmp_packet)
            response_time = (time.time() - start_time) * 1000
            
            if response_data:
                return self._parse_snmp_response(response_data, community, oid, response_time)
            
            return None
            
        except Exception as e:
            logger.debug(f"[SNMP] SNMP request failed: {e}")
            return None
    
    def _create_snmp_packet(self, community: str, oid: str, version: SNMPVersion) -> bytes:
        """Create SNMP packet."""
        if version == SNMPVersion.SNMPV2C:
            return self._create_snmpv2c_packet(community, oid)
        else:
            return self._create_snmpv1_packet(community, oid)
    
    def _create_snmpv2c_packet(self, community: str, oid: str) -> bytes:
        """Create SNMPv2c packet."""
        # SNMPv2c header
        version = 0x01  # SNMPv2c
        community_bytes = community.encode('ascii')
        community_len = len(community_bytes)
        
        # GetRequest PDU
        request_type = SNMPRequestType.GET_REQUEST.value
        request_id = 12345
        error_status = 0
        error_index = 0
        
        # Variable binding
        oid_bytes = oid.encode('ascii')
        oid_len = len(oid_bytes)
        
        # Build variable binding
        varbind = struct.pack("!B", oid_len) + oid_bytes + struct.pack("!B", 0x05) + struct.pack("!B", 0x00)
        
        # Build PDU
        pdu = struct.pack("!BIIB", request_type, request_id, error_status, error_index)
        pdu += struct.pack("!B", 0x30)  # Sequence
        pdu += struct.pack("!B", len(varbind) + 2)  # Length
        pdu += struct.pack("!B", 0x30)  # Sequence
        pdu += struct.pack("!B", len(varbind))
        pdu += varbind
        
        # Build complete packet
        packet = struct.pack("!B", version)
        packet += struct.pack("!B", community_len)
        packet += community_bytes
        packet += pdu
        
        return packet
    
    def _create_snmpv1_packet(self, community: str, oid: str) -> bytes:
        """Create SNMPv1 packet."""
        # SNMPv1 header
        version = 0x00  # SNMPv1
        community_bytes = community.encode('ascii')
        community_len = len(community_bytes)
        
        # GetRequest PDU
        request_type = SNMPRequestType.GET_REQUEST.value
        request_id = 12345
        error_status = 0
        error_index = 0
        
        # Variable binding
        oid_bytes = oid.encode('ascii')
        oid_len = len(oid_bytes)
        
        # Build PDU
        pdu = struct.pack("!BIIB", request_type, request_id, error_status, error_index)
        pdu += struct.pack("!B", 0x30)  # Sequence
        pdu += struct.pack("!B", len(oid_bytes) + 4)  # Length
        pdu += struct.pack("!B", 0x06)  # OID tag
        pdu += struct.pack("!B", oid_len)
        pdu += oid_bytes
        pdu += struct.pack("!B", 0x05)  # NULL tag
        pdu += struct.pack("!B", 0x00)  # NULL length
        
        # Build complete packet
        packet = struct.pack("!B", version)
        packet += struct.pack("!B", community_len)
        packet += community_bytes
        packet += pdu
        
        return packet
    
    def _send_snmp_packet_raw(self, target_ip: str, target_port: int, packet: bytes) -> Optional[bytes]:
        """Send SNMP packet and receive response."""
        try:
            if HAS_SCAPY:
                # Use Scapy for packet crafting
                ip_packet = IP(dst=target_ip)
                udp_packet = UDP(sport=161, dport=target_port)
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
            logger.debug(f"[SNMP] Packet send failed: {e}")
            return None
    
    def _parse_snmp_response(self, response_data: bytes, community: str, oid: str, response_time: float) -> SNMPResponse:
        """Parse SNMP response."""
        try:
            if len(response_data) < 4:
                return SNMPResponse(
                    community_string=community,
                    request_type="GET",
                    oid=oid,
                    value=None,
                    error_code=-1,
                    response_time_ms=response_time,
                    source_ip="",
                    device_info={}
                )
            
            # Check for SNMP error response
            if response_data[0] == 0x80:  # Error response
                error_code = response_data[3] if len(response_data) > 3 else -1
                return SNMPResponse(
                    community_string=community,
                    request_type="GET",
                    oid=oid,
                    value=None,
                    error_code=error_code,
                    response_time_ms=response_time,
                    source_ip="",
                    device_info={}
                )
            
            # Parse successful response
            if len(response_data) >= 6:
                # Extract value from response
                value = self._extract_snmp_value(response_data[6:])
                
                return SNMPResponse(
                    community_string=community,
                    request_type="GET",
                    oid=oid,
                    value=value,
                    error_code=0,
                    response_time_ms=response_time,
                    source_ip="",
                    device_info={}
                )
            
            return SNMPResponse(
                community_string=community,
                request_type="GET",
                oid=oid,
                value=None,
                error_code=-1,
                response_time_ms=response_time,
                source_ip="",
                device_info={}
            )
            
        except Exception as e:
            logger.debug(f"[SNMP] Response parsing failed: {e}")
            return SNMPResponse(
                community_string=community,
                request_type="GET",
                oid=oid,
                value=None,
                error_code=-1,
                response_time_ms=response_time,
                source_ip="",
                device_info={}
            )
    
    def _extract_snmp_value(self, data: bytes) -> Any:
        """Extract value from SNMP response data."""
        try:
            if len(data) < 2:
                return None
            
            # Check data type
            data_type = data[0]
            data_len = data[1]
            
            if data_len + 2 > len(data):
                return None
            
            value_data = data[2:2+data_len]
            
            if data_type == 0x04:  # Octet String
                return value_data.decode('ascii', errors='ignore')
            elif data_type == 0x02:  # Integer
                if data_len == 1:
                    return struct.unpack("!B", value_data)[0]
                elif data_len == 2:
                    return struct.unpack("!H", value_data)[0]
                elif data_len == 4:
                    return struct.unpack("!I", value_data)[0]
            elif data_type == 0x06:  # OID
                return ".".join(str(b) for b in value_data)
            elif data_type == 0x40:  # IPAddress
                if data_len == 4:
                    return socket.inet_ntoa(value_data)
            
            return value_data
            
        except Exception as e:
            logger.debug(f"[SNMP] Value extraction failed: {e}")
            return None
    
    def _gather_device_info(self, target_ip: str, target_port: int, community: str) -> Dict[str, Any]:
        """Gather comprehensive device information."""
        device_info = {}
        
        try:
            # System information
            system_info = {}
            for name, oid in self.snmp_oids["system"].items():
                response = self._send_snmp_request(target_ip, target_port, community, oid, SNMPVersion.SNMPV2C)
                if response and response.error_code == 0:
                    system_info[name] = response.value
            
            device_info["system"] = system_info
            
            # Interface information
            interface_info = []
            if_index = 1
            while if_index <= 10:  # Limit to first 10 interfaces
                if_desc_response = self._send_snmp_request(target_ip, target_port, community, 
                                                               f"1.3.6.1.2.1.2.2.1.2.{if_index}", SNMPVersion.SNMPV2C)
                if if_desc_response and if_desc_response.error_code == 0:
                    interface = {
                        "index": if_index,
                        "description": if_desc_response.value
                    }
                    
                    # Get additional interface info
                    for attr_name, oid_template in self.snmp_oids["interfaces"].items():
                        if attr_name != "number":
                            oid = oid_template.replace("1", str(if_index))
                            attr_response = self._send_snmp_request(target_ip, target_port, community, oid, SNMPVersion.SNMPV2C)
                            if attr_response and attr_response.error_code == 0:
                                interface[attr_name] = attr_response.value
                    
                    interface_info.append(interface)
                    if_index += 1
                else:
                    break
            
            device_info["interface_info"] = interface_info
            
            # Routing table
            routing_table = []
            route_index = 1
            while route_index <= 20:  # Limit to first 20 routes
                route_oid = f"1.3.6.1.2.1.4.21.1.{route_index}"
                route_response = self._send_snmp_request(target_ip, target_port, community, route_oid, SNMPVersion.SNMPV2C)
                if route_response and route_response.error_code == 0:
                    routing_table.append({
                        "index": route_index,
                        "route": route_response.value
                    })
                    route_index += 1
                else:
                    break
            
            device_info["routing_table"] = routing_table
            
            # ARP table
            arp_table = []
            arp_index = 1
            while arp_index <= 20:  # Limit to first 20 ARP entries
                arp_ip_oid = f"1.3.6.1.2.1.4.22.1.2.{arp_index}"
                arp_ip_response = self._send_snmp_request(target_ip, target_port, community, arp_ip_oid, SNMPVersion.SNMPV2C)
                
                if arp_ip_response and arp_ip_response.error_code == 0:
                    arp_entry = {"ip": arp_ip_response.value}
                    
                    # Get MAC address
                    arp_mac_oid = f"1.3.6.1.2.1.4.22.1.3.{arp_index}"
                    arp_mac_response = self._send_snmp_request(target_ip, target_port, community, arp_mac_oid, SNMPVersion.SNMPV2C)
                    if arp_mac_response and arp_mac_response.error_code == 0:
                        arp_entry["mac"] = arp_mac_response.value
                    
                    arp_table.append(arp_entry)
                    arp_index += 1
                else:
                    break
            
            device_info["arp_table"] = arp_table
            
        except Exception as e:
            logger.debug(f"[SNMP] Device info gathering failed: {e}")
        
        return device_info
    
    def _gather_comprehensive_info(self, target_ip: str, target_port: int, community: str) -> Dict[str, Any]:
        """Gather comprehensive device information."""
        device_info = self._gather_device_info(target_ip, target_port, community)
        
        # Add system description
        if "system" in device_info and "description" in device_info["system"]:
            device_info["system_description"] = device_info["system"]["description"]
        
        return device_info
    
    def _assess_snmp_security(self, device_info: Dict[str, Any]) -> List[str]:
        """Assess SNMP security configuration."""
        assessment = []
        
        if not device_info:
            assessment.append("No SNMP access - device may be filtered or disabled")
            return assessment
        
        # Check for default communities
        system_info = device_info.get("system", {})
        if system_info:
            assessment.append("SNMP accessible - review access controls")
        
        # Check for information disclosure
        if "routing_table" in device_info and device_info["routing_table"]:
            assessment.append(f"Routing table exposed: {len(device_info['routing_table'])} routes")
        
        if "arp_table" in device_info and device_info["arp_table"]:
            assessment.append(f"ARP table exposed: {len(device_info['arp_table'])} entries")
        
        if "interface_info" in device_info and device_info["interface_info"]:
            assessment.append(f"Interface information exposed: {len(device_info['interface_info'])} interfaces")
        
        # Security recommendations
        assessment.append("Restrict SNMP access to authorized management stations")
        assessment.append("Use SNMPv3 with authentication and encryption")
        assessment.append("Implement SNMP access control lists")
        assessment.append("Regularly review SNMP community strings")
        assessment.append("Monitor SNMP logs for unauthorized access")
        
        return assessment
    
    def _calculate_confidence(self, successful_communities: List[str], device_info: Dict[str, Any]) -> float:
        """Calculate confidence score for SNMP analysis."""
        if not successful_communities:
            return 0.0
        
        # Base confidence from successful communities
        base_confidence = min(1.0, len(successful_communities) / 5.0)
        
        # Quality confidence from device information
        info_score = 0
        if device_info.get("system"):
            info_score += 0.3
        if device_info.get("interface_info"):
            info_score += 0.3
        if device_info.get("routing_table"):
            info_score += 0.2
        if device_info.get("arp_table"):
            info_score += 0.2
        
        # Combined confidence
        overall_confidence = (base_confidence + info_score) / 2.0
        
        return min(1.0, overall_confidence)
    
    def generate_snmp_report(self, result: SNMPInferenceResult) -> str:
        """Generate human-readable SNMP inference report."""
        report = []
        report.append("SNMP Community String Inference Report")
        report.append("=" * 50)
        report.append(f"Target IP: {result.target_ip}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Successful Communities: {len(result.successful_communities)}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        if result.successful_communities:
            report.append("Successful Community Strings:")
            for community in result.successful_communities:
                report.append(f"  - {community}")
            report.append("")
        
        if result.system_description:
            report.append("System Description:")
            report.append(f"  - {result.system_description}")
            report.append("")
        
        if result.interface_info:
            report.append("Interface Information:")
            for interface in result.interface_info[:10]:  # Show first 10
                report.append(f"  - Interface {interface.get('index', '?')}: {interface.get('description', 'Unknown')}")
                if 'speed' in interface:
                    report.append(f"    Speed: {interface['speed']}")
                if 'phys' in interface:
                    report.append(f"    MAC: {interface['phys']}")
            if len(result.interface_info) > 10:
                report.append(f"    ... and {len(result.interface_info) - 10} more interfaces")
            report.append("")
        
        if result.routing_table:
            report.append("Routing Table:")
            for route in result.routing_table[:10]:  # Show first 10
                report.append(f"  - Route {route.get('index', '?')}: {route.get('route', 'Unknown')}")
            if len(result.routing_table) > 10:
                report.append(f"    ... and {len(result.routing_table) - 10} more routes")
            report.append("")
        
        if result.arp_table:
            report.append("ARP Table:")
            for arp_entry in result.arp_table[:10]:  # Show first 10
                report.append(f"  - {arp_entry.get('ip', '?')}: {arp_entry.get('mac', 'Unknown')}")
            if len(result.arp_table) > 10:
                report.append(f"    ... and {len(result.arp_table) - 10} more entries")
            report.append("")
        
        if result.security_assessment:
            report.append("Security Assessment:")
            for assessment in result.security_assessment:
                report.append(f"  - {assessment}")
            report.append("")
        
        return "\n".join(report)

# Global instance
_snmp_inferencer = None

def get_snmp_inferencer() -> SNMPCommunityInferencer:
    """Get global SNMP community inferencer."""
    global _snmp_inferencer
    if _snmp_inferencer is None:
        _snmp_inferencer = SNMPCommunityInferencer()
    return _snmp_inferencer

def infer_snmp_communities(target_ip: str, target_port: int = 161,
                        collected_intel: Optional[Dict[str, Any]] = None) -> SNMPInferenceResult:
    """Convenience function for SNMP community inference."""
    inferencer = get_snmp_inferencer()
    return inferencer.infer_snmp_communities(target_ip, target_port, collected_intel)

def generate_snmp_report(result: SNMPInferenceResult) -> str:
    """Convenience function for SNMP report generation."""
    inferencer = get_snmp_inferencer()
    return inferencer.generate_snmp_report(result)
