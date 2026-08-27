"""Idle Scan Implementation - True stealth port scanning."""

import time
import logging
from typing import Optional, Dict, List
from dataclasses import dataclass
from enum import Enum

from scapy.all import IP, sr1, send
from core.packet_engine import PacketEngine
from recon.ipid_analysis import IPIDAnalyzer

logger = logging.getLogger("usare.idle_scan")

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"

@dataclass
class IdleScanResult:
    port: int
    state: PortState
    confidence: float
    ipid_diff: int

class IdleScanner:
    """Coordinates idle scan using zombie hosts for true stealth scanning.
    
    Concept:
    1. Probe zombie's IP ID (baseline)
    2. Send spoofed SYN to target using zombie's IP as source
    3. Probe zombie's IP ID again
    4. IP ID increment pattern reveals port state:
       - +1: Target sent RST (port closed)
       - +2: Target sent SYN-ACK (port open) 
       - >2: Zombie busy (unreliable)
    """
    
    def __init__(self, zombie_ip: str, zombie_port: int, packet_engine: PacketEngine):
        self.zombie_ip = zombie_ip
        self.zombie_port = zombie_port
        self.engine = packet_engine
        self.ipid_analyzer = IPIDAnalyzer()
        self.probes_sent = 0
        
    def _get_zombie_ipid(self) -> Optional[int]:
        """Probe zombie to get current IP ID."""
        try:
            syn_pkt = self.engine.craft_syn(self.zombie_ip, self.zombie_port)
            response = sr1(syn_pkt, timeout=2.0, verbose=0)
            
            if response and response.haslayer(IP):
                # Send RST to close half-open connection cleanly
                if response.haslayer('TCP') and response['TCP'].flags & 0x12 == 0x12:
                    rst = self.engine.craft_syn_ack_response_rst(response)
                    send(rst, verbose=0)
                self.probes_sent += 1
                return response[IP].id
                
        except Exception as e:
            logger.debug(f"Failed to probe zombie IP ID: {e}")
            
        return None
    
    def _probe_via_zombie(self, target_ip: str, target_port: int) -> Optional[IdleScanResult]:
        """Execute single idle scan probe via zombie."""
        
        # 1. Get baseline zombie IP ID
        baseline_ipid = self._get_zombie_ipid()
        if baseline_ipid is None:
            return None
            
        # 2. Send spoofed SYN to target using zombie as source
        try:
            spoofed_syn = self.engine.craft_syn(target_ip, target_port, src_ip=self.zombie_ip)
            send(spoofed_syn, verbose=0)
            self.probes_sent += 1
            
            # Small delay to allow target response
            time.sleep(0.1)
            
        except Exception as e:
            logger.debug(f"Failed to send spoofed SYN: {e}")
            return None
            
        # 3. Get post-probe zombie IP ID
        post_probe_ipid = self._get_zombie_ipid()
        if post_probe_ipid is None:
            return None
            
        # 4. Analyze IP ID difference
        ipid_diff = (post_probe_ipid - baseline_ipid) & 0xFFFF
        
        # Determine port state based on IP ID pattern
        if ipid_diff == 1:
            # Zombie got RST from target (port closed)
            state = PortState.CLOSED
            confidence = 0.9
        elif ipid_diff == 2:
            # Zombie got SYN-ACK from target (port open)
            state = PortState.OPEN
            confidence = 0.9
        elif ipid_diff > 2:
            # Zombie was busy, unreliable result
            state = PortState.UNKNOWN
            confidence = 0.3
        else:
            # No increment (filtered)
            state = PortState.FILTERED
            confidence = 0.7
            
        return IdleScanResult(
            port=target_port,
            state=state,
            confidence=confidence,
            ipid_diff=ipid_diff
        )
    
    def scan_ports(self, target_ip: str, ports: List[int], max_retries: int = 3) -> Dict[int, IdleScanResult]:
        """Scan multiple ports via idle scan."""
        results = {}
        
        for port in ports:
            best_result = None
            best_confidence = 0.0
            
            # Retry for better confidence
            for attempt in range(max_retries):
                result = self._probe_via_zombie(target_ip, port)
                
                if result and result.confidence > best_confidence:
                    best_result = result
                    best_confidence = result.confidence
                    
                    # Early exit if high confidence
                    if best_confidence >= 0.9:
                        break
                        
            if best_result:
                results[port] = best_result
                
        return results
    
    @property
    def stats(self) -> Dict[str, any]:
        return {
            "zombie_ip": self.zombie_ip,
            "zombie_port": self.zombie_port,
            "probes_sent": self.probes_sent,
            "method": "idle_scan"
        }

def execute_idle_scan(target_ip: str, zombie_ip: str, ports: List[int]) -> Optional[Dict[str, any]]:
    """Execute complete idle scan operation."""
    try:
        from core.packet_engine import PacketEngine
        
        engine = PacketEngine()
        scanner = IdleScanner(zombie_ip, 80, engine)  # Use port 80 for zombie
        
        results = scanner.scan_ports(target_ip, ports)
        
        # Convert to serializable format
        scan_results = {}
        for port, result in results.items():
            scan_results[port] = {
                "state": result.state.value,
                "confidence": result.confidence,
                "ipid_diff": result.ipid_diff
            }
            
        return {
            "method": "idle_scan",
            "target": target_ip,
            "zombie": zombie_ip,
            "results": scan_results,
            "stats": scanner.stats
        }
        
    except Exception as e:
        logger.error(f"Idle scan failed: {e}")
        return None
