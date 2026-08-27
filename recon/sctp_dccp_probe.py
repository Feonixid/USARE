"""SCTP and DCCP Protocol Probing - Advanced reconnaissance.

Most IDS and firewall deployments focus on TCP and UDP. SCTP and DCCP are
legitimate protocols that most enterprise environments allow through untouched
because security teams never configured rules for them.

SCTP (Stream Control Transmission Protocol) and DCCP (Datagram Congestion 
Control Protocol) can bypass signature-based detection entirely because there
are virtually no SCTP/DCCP-specific IDS rules.

Requires: Scapy with SCTP/DCCP support
"""

import logging
import time
import random
from typing import Dict, Optional, List, Any
from dataclasses import dataclass

try:
    from scapy.all import IP, SCTP, SCTPChunkInit, SCTPChunkInitAck, DCCP, Raw
    from scapy.all import sr1, send
    HAS_SCTP_DCCP = True
except ImportError:
    HAS_SCTP_DCCP = False
    SCTP = DCCP = None

logger = logging.getLogger("usare.sctp_dccp_probe")

@dataclass
class ProbeResult:
    protocol: str
    port: int
    is_open: bool
    response_time_ms: float
    response_type: Optional[str] = None
    raw_response: Optional[str] = None
    confidence: float = 0.0

class SCTPDCCPProber:
    """Advanced protocol probing using SCTP and DCCP."""
    
    def __init__(self, timeout: float = 3.0):
        if not HAS_SCTP_DCCP:
            raise RuntimeError("SCTP/DCCP not available in Scapy")
        
        self.timeout = timeout
        self.probes_sent = 0
        self.responses_received = 0
    
    def probe_sctp_port(self, target_ip: str, port: int, 
                       src_port: Optional[int] = None) -> Optional[ProbeResult]:
        """Probe port using SCTP INIT chunk."""
        try:
            start_time = time.time()
            
            # Craft SCTP INIT packet
            sctp_init = SCTPChunkInit(
                init_tag=random.randint(0, 0xFFFFFFFF),
                a_rwnd=32768,
                num_outbound_streams=10,
                num_inbound_streams=10,
                initial_tsn=random.randint(0, 0xFFFFFFFF)
            )
            
            pkt = IP(dst=target_ip) / SCTP(sport=src_port or random.randint(49152, 65535), 
                                        dport=port) / sctp_init
            
            # Send and wait for response
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            response_time = (time.time() - start_time) * 1000
            self.probes_sent += 1
            
            if response and response.haslayer(SCTP):
                self.responses_received += 1
                
                # Check for INIT-ACK (port open) or ABORT (port closed)
                if response.haslayer(SCTPChunkInitAck):
                    return ProbeResult(
                        protocol="SCTP",
                        port=port,
                        is_open=True,
                        response_time_ms=response_time,
                        response_type="INIT_ACK",
                        raw_response=str(response)[:200],
                        confidence=0.9
                    )
                else:
                    # Other SCTP response (likely ABORT)
                    return ProbeResult(
                        protocol="SCTP",
                        port=port,
                        is_open=False,
                        response_time_ms=response_time,
                        response_type="SCTP_OTHER",
                        raw_response=str(response)[:200],
                        confidence=0.7
                    )
            else:
                # No response (filtered)
                return ProbeResult(
                    protocol="SCTP",
                    port=port,
                    is_open=False,
                    response_time_ms=response_time,
                    response_type="NO_RESPONSE",
                    confidence=0.3
                )
                
        except Exception as e:
            logger.debug(f"SCTP probe failed for {target_ip}:{port} - {e}")
            return None
    
    def probe_dccp_port(self, target_ip: str, port: int,
                       src_port: Optional[int] = None) -> Optional[ProbeResult]:
        """Probe port using DCCP REQUEST packet."""
        try:
            start_time = time.time()
            
            # Craft DCCP REQUEST packet
            pkt = IP(dst=target_ip) / DCCP(
                sport=src_port or random.randint(49152, 65535),
                dport=port,
                ccval=0,
                type=0  # DCCP Request
            )
            
            # Send and wait for response
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            response_time = (time.time() - start_time) * 1000
            self.probes_sent += 1
            
            if response and response.haslayer(DCCP):
                self.responses_received += 1
                
                # Check DCCP response type
                dccp_type = response[DCCP].type
                
                if dccp_type == 2:  # DCCP Response
                    return ProbeResult(
                        protocol="DCCP",
                        port=port,
                        is_open=True,
                        response_time_ms=response_time,
                        response_type="DCCP_RESPONSE",
                        raw_response=str(response)[:200],
                        confidence=0.9
                    )
                elif dccp_type == 3:  # DCCP Reset
                    return ProbeResult(
                        protocol="DCCP",
                        port=port,
                        is_open=False,
                        response_time_ms=response_time,
                        response_type="DCCP_RESET",
                        raw_response=str(response)[:200],
                        confidence=0.8
                    )
                else:
                    return ProbeResult(
                        protocol="DCCP",
                        port=port,
                        is_open=False,
                        response_time_ms=response_time,
                        response_type=f"DCCP_{dccp_type}",
                        raw_response=str(response)[:200],
                        confidence=0.6
                    )
            else:
                # No response (filtered)
                return ProbeResult(
                    protocol="DCCP",
                    port=port,
                    is_open=False,
                    response_time_ms=response_time,
                    response_type="NO_RESPONSE",
                    confidence=0.3
                )
                
        except Exception as e:
            logger.debug(f"DCCP probe failed for {target_ip}:{port} - {e}")
            return None
    
    def scan_ports(self, target_ip: str, ports: List[int], 
                   protocols: List[str] = ["SCTP", "DCCP"]) -> Dict[str, List[ProbeResult]]:
        """Scan multiple ports using alternative protocols."""
        results = {"SCTP": [], "DCCP": []}
        
        for port in ports:
            if "SCTP" in protocols:
                sctp_result = self.probe_sctp_port(target_ip, port)
                if sctp_result:
                    results["SCTP"].append(sctp_result)
            
            if "DCCP" in protocols:
                dccp_result = self.probe_dccp_port(target_ip, port)
                if dccp_result:
                    results["DCCP"].append(dccp_result)
        
        return results
    
    def analyze_protocol_support(self, target_ip: str, port: int) -> Dict[str, Any]:
        """Comprehensive protocol support analysis."""
        results = {
            "target": target_ip,
            "port": port,
            "protocols": {}
        }
        
        # Test SCTP
        sctp_result = self.probe_sctp_port(target_ip, port)
        if sctp_result:
            results["protocols"]["SCTP"] = {
                "supported": sctp_result.is_open,
                "response_type": sctp_result.response_type,
                "confidence": sctp_result.confidence
            }
        
        # Test DCCP
        dccp_result = self.probe_dccp_port(target_ip, port)
        if dccp_result:
            results["protocols"]["DCCP"] = {
                "supported": dccp_result.is_open,
                "response_type": dccp_result.response_type,
                "confidence": dccp_result.confidence
            }
        
        # Analysis
        open_protocols = [p for p, info in results["protocols"].items() if info.get("supported", False)]
        
        results["analysis"] = {
            "alternative_protocols_supported": len(open_protocols) > 0,
            "open_protocols": open_protocols,
            "bypass_potential": len(open_protocols) > 0,
            "security_posture": "low" if len(open_protocols) > 0 else "medium"
        }
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get probing statistics."""
        return {
            "probes_sent": self.probes_sent,
            "responses_received": self.responses_received,
            "response_rate": self.responses_received / max(1, self.probes_sent),
            "protocols_available": ["SCTP", "DCCP"] if HAS_SCTP_DCCP else []
        }

def scan_target_with_alternative_protocols(target_ip: str, ports: List[int]) -> Optional[Dict[str, Any]]:
    """Convenience function for comprehensive alternative protocol scanning."""
    try:
        prober = SCTPDCCPProber()
        
        # Scan all ports with both protocols
        scan_results = prober.scan_ports(target_ip, ports)
        
        # Analyze each port comprehensively
        detailed_analysis = {}
        for port in ports:
            detailed_analysis[port] = prober.analyze_protocol_support(target_ip, port)
        
        return {
            "target": target_ip,
            "scan_results": scan_results,
            "detailed_analysis": detailed_analysis,
            "stats": prober.get_stats()
        }
        
    except Exception as e:
        logger.error(f"Alternative protocol scan failed: {e}")
        return None

# Example usage
if __name__ == "__main__":
    if not HAS_SCTP_DCCP:
        print("SCTP/DCCP not available in Scapy")
        exit(1)
    
    target = "192.168.1.1"
    ports = [80, 443, 22, 53]
    
    prober = SCTPDCCPProber()
    
    # Test single port
    result = prober.analyze_protocol_support(target, 80)
    print(f"Port 80 analysis: {result}")
    
    # Scan multiple ports
    scan_results = prober.scan_ports(target, ports)
    print(f"Scan results: {scan_results}")
    
    print(f"Stats: {prober.get_stats()}")
