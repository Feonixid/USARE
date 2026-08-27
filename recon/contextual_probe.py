"""Contextual Probing Framework for Stealth Reconnaissance.

Implements protocol-specific discovery workflows that justify subsequent
SYN probes to avoid detection by behavioral analysis systems.

Windows: LLMNR/NetBIOS name query → delay → SYN probe
Apple: mDNS/Bonjour discovery → delay → SYN probe  
IoT: UPnP/SSDP discovery → delay → SYN probe
Enterprise: LDAP/Kerberos queries → delay → SYN probe
"""

import logging
import time
import socket
import struct
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import IP, UDP, TCP, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.contextual_probe")

class NetworkOS(Enum):
    WINDOWS = "windows"
    APPLE = "apple"
    LINUX = "linux"
    IOT = "iot"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"

@dataclass
class ContextualProbeResult:
    """Result of contextual probing sequence."""
    target_ip: str
    target_port: int
    os_family: NetworkOS
    discovery_method: str
    discovery_response: Optional[str]
    probe_success: bool
    probe_response_time_ms: float
    stealth_score: float  # 0-1, higher = more stealthy
    justification: str

class ContextualProber:
    """Implements contextual probing workflows."""
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.discovery_cache = {}
        
    def detect_os_family(self, target_ip: str) -> NetworkOS:
        """Detect target OS family using passive analysis."""
        # Check cache first
        if target_ip in self.discovery_cache:
            return self.discovery_cache[target_ip]
        
        os_family = NetworkOS.UNKNOWN
        
        # Quick port-based heuristics
        common_ports = [22, 23, 53, 80, 135, 139, 445, 548, 631, 1900]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    if port in [135, 139, 445]:
                        os_family = NetworkOS.WINDOWS
                        break
                    elif port in [548, 631]:
                        os_family = NetworkOS.APPLE
                        break
                    elif port == 22:
                        os_family = NetworkOS.LINUX
                        break
                    elif port == 1900:
                        os_family = NetworkOS.IOT
                        break
            except Exception:
                continue
        
        self.discovery_cache[target_ip] = os_family
        return os_family
    
    def windows_contextual_probe(self, target_ip: str, target_port: int) -> ContextualProbeResult:
        """Windows contextual probing: LLMNR/NetBIOS → delay → SYN."""
        start_time = time.time()
        
        # Step 1: Send LLMNR name query
        llmnr_response = self._send_llmnr_query(target_ip)
        
        # Step 2: Wait 2-3 seconds (natural timing)
        time.sleep(random.uniform(2.0, 3.0))
        
        # Step 3: Send SYN probe
        probe_success, response_time = self._send_syn_probe(target_ip, target_port)
        
        total_time = (time.time() - start_time) * 1000
        
        return ContextualProbeResult(
            target_ip=target_ip,
            target_port=target_port,
            os_family=NetworkOS.WINDOWS,
            discovery_method="LLMNR query",
            discovery_response=llmnr_response,
            probe_success=probe_success,
            probe_response_time_ms=response_time,
            stealth_score=0.85 if llmnr_response else 0.60,
            justification="Windows name resolution followed by legitimate port check"
        )
    
    def apple_contextual_probe(self, target_ip: str, target_port: int) -> ContextualProbeResult:
        """Apple contextual probing: mDNS/Bonjour → delay → SYN."""
        start_time = time.time()
        
        # Step 1: Send mDNS query
        mdns_response = self._send_mdns_query(target_ip)
        
        # Step 2: Wait 2-4 seconds
        time.sleep(random.uniform(2.0, 4.0))
        
        # Step 3: Send SYN probe
        probe_success, response_time = self._send_syn_probe(target_ip, target_port)
        
        total_time = (time.time() - start_time) * 1000
        
        return ContextualProbeResult(
            target_ip=target_ip,
            target_port=target_port,
            os_family=NetworkOS.APPLE,
            discovery_method="mDNS/Bonjour query",
            discovery_response=mdns_response,
            probe_success=probe_success,
            probe_response_time_ms=response_time,
            stealth_score=0.80 if mdns_response else 0.55,
            justification="Apple service discovery followed by legitimate port check"
        )
    
    def iot_contextual_probe(self, target_ip: str, target_port: int) -> ContextualProbeResult:
        """IoT contextual probing: UPnP/SSDP → delay → SYN."""
        start_time = time.time()
        
        # Step 1: Send UPnP discovery
        upnp_response = self._send_upnp_discovery(target_ip)
        
        # Step 2: Wait 1-2 seconds (IoT devices respond faster)
        time.sleep(random.uniform(1.0, 2.0))
        
        # Step 3: Send SYN probe
        probe_success, response_time = self._send_syn_probe(target_ip, target_port)
        
        total_time = (time.time() - start_time) * 1000
        
        return ContextualProbeResult(
            target_ip=target_ip,
            target_port=target_port,
            os_family=NetworkOS.IOT,
            discovery_method="UPnP/SSDP discovery",
            discovery_response=upnp_response,
            probe_success=probe_success,
            probe_response_time_ms=response_time,
            stealth_score=0.75 if upnp_response else 0.50,
            justification="IoT device discovery followed by legitimate port check"
        )
    
    def enterprise_contextual_probe(self, target_ip: str, target_port: int) -> ContextualProbeResult:
        """Enterprise contextual probing: LDAP query → delay → SYN."""
        start_time = time.time()
        
        # Step 1: Send LDAP query
        ldap_response = self._send_ldap_query(target_ip)
        
        # Step 2: Wait 3-5 seconds (enterprise networks are slower)
        time.sleep(random.uniform(3.0, 5.0))
        
        # Step 3: Send SYN probe
        probe_success, response_time = self._send_syn_probe(target_ip, target_port)
        
        total_time = (time.time() - start_time) * 1000
        
        return ContextualProbeResult(
            target_ip=target_ip,
            target_port=target_port,
            os_family=NetworkOS.ENTERPRISE,
            discovery_method="LDAP service query",
            discovery_response=ldap_response,
            probe_success=probe_success,
            probe_response_time_ms=response_time,
            stealth_score=0.90 if ldap_response else 0.65,
            justification="Enterprise service discovery followed by legitimate port check"
        )
    
    def _send_llmnr_query(self, target_ip: str) -> Optional[str]:
        """Send LLMNR name query for Windows networks."""
        if not HAS_SCAPY:
            return None
        
        try:
            # LLMNR query for workstation name
            query_name = f"WPAD.{target_ip.split('.')[-1]}"
            query_data = self._build_dns_query(query_name, qtype=12)  # PTR request
            
            pkt = IP(dst=target_ip) / UDP(dport=5355, sport=random.randint(49152, 65535)) / query_data
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(UDP):
                return f"LLMNR response from {target_ip}"
            
        except Exception as e:
            logger.debug(f"[Contextual] LLMNR query failed: {e}")
        
        return None
    
    def _send_mdns_query(self, target_ip: str) -> Optional[str]:
        """Send mDNS query for Apple networks."""
        if not HAS_SCAPY:
            return None
        
        try:
            # mDNS query for _http._tcp.local
            query_data = self._build_dns_query("_http._tcp.local", qtype=12)
            
            pkt = IP(dst=target_ip) / UDP(dport=5353, sport=random.randint(49152, 65535)) / query_data
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(UDP):
                return f"mDNS response from {target_ip}"
            
        except Exception as e:
            logger.debug(f"[Contextual] mDNS query failed: {e}")
        
        return None
    
    def _send_upnp_discovery(self, target_ip: str) -> Optional[str]:
        """Send UPnP/SSDP discovery for IoT networks."""
        if not HAS_SCAPY:
            return None
        
        try:
            # SSDP M-SEARCH message
            ssdp_data = (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 3\r\n"
                b"ST: upnp:rootdevice\r\n"
                b"\r\n"
            )
            
            pkt = IP(dst=target_ip) / UDP(dport=1900, sport=random.randint(49152, 65535)) / ssdp_data
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(UDP):
                return f"UPnP response from {target_ip}"
            
        except Exception as e:
            logger.debug(f"[Contextual] UPnP discovery failed: {e}")
        
        return None
    
    def _send_ldap_query(self, target_ip: str) -> Optional[str]:
        """Send LDAP query for enterprise networks."""
        try:
            # Simple LDAP bind attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_ip, 389))
                
                # LDAP bind request
                ldap_bind = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
                sock.send(ldap_bind)
                
                response = sock.recv(1024)
                sock.close()
                
                if response:
                    return f"LDAP response from {target_ip}"
                    
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"[Contextual] LDAP query failed: {e}")
        
        return None
    
    def _send_syn_probe(self, target_ip: str, target_port: int) -> Tuple[bool, float]:
        """Send SYN probe and measure response time."""
        if not HAS_SCAPY:
            return False, 0.0
        
        try:
            start_time = time.time()
            
            # Craft SYN packet
            syn_pkt = IP(dst=target_ip) / TCP(
                dport=target_port,
                sport=random.randint(49152, 65535),
                flags="S",
                seq=random.randint(1000, 9000)
            )
            
            response = sr1(syn_pkt, timeout=self.timeout, verbose=0)
            
            response_time = (time.time() - start_time) * 1000
            
            if response and response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                
                # SYN-ACK = 0x12 (SYN + ACK)
                if (tcp_flags & 0x12) == 0x12:  # SYN+ACK
                    return True, response_time
                elif tcp_flags & 0x04:  # RST
                    return False, response_time
            
            return False, response_time
            
        except Exception as e:
            logger.debug(f"[Contextual] SYN probe failed: {e}")
            return False, 0.0
    
    def _build_dns_query(self, name: str, qtype: int = 1) -> bytes:
        """Build DNS query packet."""
        # DNS header
        header = struct.pack("!HHHHHH", random.randint(1, 65535), 0x0100, 1, 0, 0, 0)
        
        # Query section
        query = b""
        
        # Encode name
        for part in name.split('.'):
            if part:
                query += bytes([len(part)]) + part.encode()
        
        query += b"\x00"  # End of name
        
        # QTYPE and QCLASS
        query += struct.pack("!HH", qtype, 1)
        
        return header + query
    
    def contextual_probe(self, target_ip: str, target_port: int, 
                        os_family: Optional[NetworkOS] = None) -> ContextualProbeResult:
        """Execute contextual probe based on OS family."""
        if os_family is None:
            os_family = self.detect_os_family(target_ip)
        
        logger.debug(f"[Contextual] Probing {target_ip}:{target_port} as {os_family.value}")
        
        if os_family == NetworkOS.WINDOWS:
            return self.windows_contextual_probe(target_ip, target_port)
        elif os_family == NetworkOS.APPLE:
            return self.apple_contextual_probe(target_ip, target_port)
        elif os_family == NetworkOS.IOT:
            return self.iot_contextual_probe(target_ip, target_port)
        elif os_family == NetworkOS.ENTERPRISE:
            return self.enterprise_contextual_probe(target_ip, target_port)
        else:
            # Fallback to standard SYN probe
            probe_success, response_time = self._send_syn_probe(target_ip, target_port)
            
            return ContextualProbeResult(
                target_ip=target_ip,
                target_port=target_port,
                os_family=NetworkOS.UNKNOWN,
                discovery_method="Direct SYN probe",
                discovery_response=None,
                probe_success=probe_success,
                probe_response_time_ms=response_time,
                stealth_score=0.30,  # Low stealth for direct probe
                justification="No contextual justification available"
            )

# Global instance
_contextual_prober = None

def get_contextual_prober() -> ContextualProber:
    """Get global contextual prober instance."""
    global _contextual_prober
    if _contextual_prober is None:
        _contextual_prober = ContextualProber()
    return _contextual_prober

def contextual_probe(target_ip: str, target_port: int, 
                   os_family: Optional[str] = None) -> ContextualProbeResult:
    """Convenience function for contextual probing."""
    prober = get_contextual_prober()
    
    if os_family:
        try:
            os_enum = NetworkOS(os_family.lower())
        except ValueError:
            os_enum = None
    else:
        os_enum = None
    
    return prober.contextual_probe(target_ip, target_port, os_enum)
