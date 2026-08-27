"""TTL Distance Masquerading for IDS/IPS Evasion.

Manipulates TTL field to send different packets to IDS vs target.
Creates dual-packet strategies that confuse IDS reassembly engines.

Strategy 1: Short TTL packet reaches IDS but expires before target
Strategy 2: Normal TTL packet reaches target but IDS sees different data
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
    from scapy.all import IP, TCP, ICMP, sr1, send, traceroute  # type: ignore[import-untyped, import-not-found]
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.ttl_masquerading")

class TTLStrategy(Enum):
    IDS_ONLY = "ids_only"          # Short TTL, reaches IDS only
    TARGET_ONLY = "target_only"    # Normal TTL, reaches target
    DUAL_PACKET = "dual_packet"    # Both packets for confusion
    ADAPTIVE = "adaptive"          # Auto-select based on analysis

@dataclass
class TTLAnalysisResult:
    """Results from TTL distance analysis."""
    target_ip: str
    hops_to_target: int
    estimated_ids_hops: int
    optimal_ids_ttl: int
    optimal_target_ttl: int
    confidence: float
    strategy: TTLStrategy

class TTLDistanceAnalyzer:
    """Analyzes network topology to determine optimal TTL values."""
    
    def __init__(self):
        self.cache = {}
        self.default_ids_hops = 5  # Default assumption for IDS positioning
    
    def analyze_target(self, target_ip: str) -> TTLAnalysisResult:
        """Analyze target to determine TTL distances."""
        if target_ip in self.cache:
            return self.cache[target_ip]
        
        if not HAS_SCAPY:
            # Fallback to assumptions
            return self._fallback_analysis(target_ip)
        
        try:
            # Use traceroute to determine hop count
            ans, unans = traceroute(target_ip, maxttl=30, timeout=2, verbose=0)
            
            if ans and len(ans) > 0:
                hops_to_target = max([snd[IP].ttl for snd, rcv in ans], default=10)  # type: ignore[misc]
            else:
                hops_to_target = 10  # Default assumption
            
            # Estimate IDS position (usually 1-3 hops before target)
            estimated_ids_hops = max(1, hops_to_target - random.randint(1, 3))
            
            # Calculate optimal TTL values
            optimal_ids_ttl = estimated_ids_hops
            optimal_target_ttl = hops_to_target + 2  # Add buffer
            
            # Select strategy
            if hops_to_target > estimated_ids_hops + 2:
                strategy = TTLStrategy.DUAL_PACKET
            elif estimated_ids_hops > 3:
                strategy = TTLStrategy.IDS_ONLY
            else:
                strategy = TTLStrategy.TARGET_ONLY
            
            confidence = 0.8 if hops_to_target < 20 else 0.6
            
            result = TTLAnalysisResult(
                target_ip=target_ip,
                hops_to_target=hops_to_target,
                estimated_ids_hops=estimated_ids_hops,
                optimal_ids_ttl=optimal_ids_ttl,
                optimal_target_ttl=optimal_target_ttl,
                confidence=confidence,
                strategy=strategy
            )
            
            self.cache[target_ip] = result
            return result
            
        except Exception as e:
            logger.debug(f"[TTL] Traceroute analysis failed: {e}")
            return self._fallback_analysis(target_ip)
    
    def _fallback_analysis(self, target_ip: str) -> TTLAnalysisResult:
        """Fallback analysis when traceroute fails."""
        # Use Scapy ping instead of raw sockets to avoid checksum issues
        if not HAS_SCAPY:
            # Ultimate fallback without network access
            return TTLAnalysisResult(
                target_ip=target_ip,
                hops_to_target=10,
                estimated_ids_hops=7,
                optimal_ids_ttl=7,
                optimal_target_ttl=12,
                confidence=0.3,
                strategy=TTLStrategy.ADAPTIVE
            )
        
        try:
            # Use Scapy for ping to handle checksums automatically
            from scapy.all import IP, ICMP, sr1  # type: ignore[import-untyped, import-not-found]
            
            # Craft ICMP echo request
            ping_pkt = IP(dst=target_ip, ttl=64) / ICMP(type=8, id=random.randint(1, 65535), seq=1)
            
            # Send and receive
            response = sr1(ping_pkt, timeout=2, verbose=0)
            
            if response and response.haslayer(IP):
                response_ttl = response[IP].ttl
                hops_to_target = 64 - response_ttl
                
                estimated_ids_hops = max(1, hops_to_target - 2)
                optimal_ids_ttl = estimated_ids_hops
                optimal_target_ttl = hops_to_target + 2
                
                result = TTLAnalysisResult(
                    target_ip=target_ip,
                    hops_to_target=hops_to_target,
                    estimated_ids_hops=estimated_ids_hops,
                    optimal_ids_ttl=optimal_ids_ttl,
                    optimal_target_ttl=optimal_target_ttl,
                    confidence=0.5,  # Lower confidence with ping
                    strategy=TTLStrategy.ADAPTIVE
                )
                
                self.cache[target_ip] = result
                return result
            
        except Exception as e:
            logger.debug(f"[TTL] Scapy ping analysis failed: {e}")
        
        # Ultimate fallback
        return TTLAnalysisResult(
            target_ip=target_ip,
            hops_to_target=10,
            estimated_ids_hops=7,
            optimal_ids_ttl=7,
            optimal_target_ttl=12,
            confidence=0.3,
            strategy=TTLStrategy.ADAPTIVE
        )

class TTLMasqueradingEngine:
    """Engine for TTL-based packet masquerading."""
    
    def __init__(self):
        self.analyzer = TTLDistanceAnalyzer()
        self.strategy_cache = {}
    
    def craft_ids_only_packet(self, target_ip: str, target_port: int, 
                             payload: bytes = b"") -> Optional[bytes]:
        """Craft packet that reaches IDS but expires before target."""
        if not HAS_SCAPY:
            return None
        
        analysis = self.analyzer.analyze_target(target_ip)
        
        try:
            # Create packet with short TTL
            pkt = IP(
                dst=target_ip,
                ttl=analysis.optimal_ids_ttl,
                id=random.randint(1, 65535)
            ) / TCP(
                dport=target_port,
                sport=random.randint(49152, 65535),
                flags="S",  # SYN packet
                seq=random.randint(1000, 9000)
            )
            
            if payload:
                pkt = pkt / payload
            
            return bytes(pkt)
            
        except Exception as e:
            logger.debug(f"[TTL] IDS-only packet creation failed: {e}")
            return None
    
    def craft_target_only_packet(self, target_ip: str, target_port: int,
                                payload: bytes = b"") -> Optional[bytes]:
        """Craft packet that reaches target but bypasses IDS analysis."""
        if not HAS_SCAPY:
            return None
        
        analysis = self.analyzer.analyze_target(target_ip)
        
        try:
            # Create packet with normal TTL
            pkt = IP(
                dst=target_ip,
                ttl=analysis.optimal_target_ttl,
                id=random.randint(1, 65535)
            ) / TCP(
                dport=target_port,
                sport=random.randint(49152, 65535),
                flags="S",  # SYN packet
                seq=random.randint(1000, 9000)
            )
            
            if payload:
                pkt = pkt / payload
            
            return bytes(pkt)
            
        except Exception as e:
            logger.debug(f"[TTL] Target-only packet creation failed: {e}")
            return None
    
    def craft_dual_packet_sequence(self, target_ip: str, target_port: int,
                                  payload1: bytes = b"", payload2: bytes = b"") -> Tuple[Optional[bytes], Optional[bytes]]:
        """Craft dual packet sequence for IDS confusion."""
        ids_packet = self.craft_ids_only_packet(target_ip, target_port, payload1)
        target_packet = self.craft_target_only_packet(target_ip, target_port, payload2)
        
        return ids_packet, target_packet
    
    def execute_ttl_masquerading_probe(self, target_ip: str, target_port: int,
                                       strategy: Optional[TTLStrategy] = None) -> Dict[str, Any]:
        """Execute TTL masquerading probe with specified strategy."""
        if not HAS_SCAPY:
            return {"error": "Scapy not available"}
        
        analysis = self.analyzer.analyze_target(target_ip)
        
        if strategy is None:
            strategy = analysis.strategy
        
        results: Dict[str, Any] = {
            "target_ip": target_ip,
            "target_port": target_port,
            "strategy": strategy.value,
            "analysis": analysis,
            "packets_sent": 0,
            "responses_received": 0,
            "success": False
        }
        
        try:
            if strategy == TTLStrategy.IDS_ONLY:
                packet = self.craft_ids_only_packet(target_ip, target_port)
                if packet:
                    response = sr1(packet, timeout=3, verbose=0)
                    results["packets_sent"] = 1
                    if response:
                        results["responses_received"] = int(results["responses_received"]) + 1
                        results["ids_response"] = str(response)[:100]  # type: ignore[index, call-overload]
            
            elif strategy == TTLStrategy.TARGET_ONLY:
                packet = self.craft_target_only_packet(target_ip, target_port)
                if packet:
                    response = sr1(packet, timeout=5, verbose=0)
                    results["packets_sent"] = 1
                    if response:
                        results["responses_received"] = int(results["responses_received"]) + 1
                        results["target_response"] = str(response)[:100]  # type: ignore[index, call-overload]
                        results["success"] = True
            
            elif strategy == TTLStrategy.DUAL_PACKET:
                ids_packet, target_packet = self.craft_dual_packet_sequence(target_ip, target_port)
                
                # Send IDS-only packet first
                if ids_packet:
                    ids_response = sr1(ids_packet, timeout=2, verbose=0)
                    results["packets_sent"] = int(results["packets_sent"]) + 1
                    if ids_response:
                        results["responses_received"] = int(results["responses_received"]) + 1
                        results["ids_response"] = str(ids_response)[:100]  # type: ignore[index, call-overload]
                
                # Small delay
                time.sleep(0.1)
                
                # Send target packet
                if target_packet:
                    target_response = sr1(target_packet, timeout=5, verbose=0)
                    results["packets_sent"] = int(results["packets_sent"]) + 1
                    if target_response:
                        results["responses_received"] = int(results["responses_received"]) + 1
                        results["target_response"] = str(target_response)[:100]  # type: ignore[index, call-overload]
                        results["success"] = True
            
            elif strategy == TTLStrategy.ADAPTIVE:
                # Auto-select based on analysis
                if analysis.confidence > 0.7:
                    return self.execute_ttl_masquerading_probe(target_ip, target_port, analysis.strategy)
                else:
                    # Fall back to target-only with conservative TTL
                    return self.execute_ttl_masquerading_probe(target_ip, target_port, TTLStrategy.TARGET_ONLY)
            
        except Exception as e:
            logger.debug(f"[TTL] TTL masquerading probe failed: {e}")
            results["error"] = str(e)
        
        return results
    
    def get_optimal_ttl_values(self, target_ip: str) -> Dict[str, int]:
        """Get optimal TTL values for target."""
        analysis = self.analyzer.analyze_target(target_ip)
        
        return {
            "ids_ttl": analysis.optimal_ids_ttl,
            "target_ttl": analysis.optimal_target_ttl,
            "hops_to_target": analysis.hops_to_target,
            "estimated_ids_hops": analysis.estimated_ids_hops
        }

# Global instance
_ttl_engine = None

def get_ttl_engine() -> TTLMasqueradingEngine:
    """Get global TTL masquerading engine."""
    global _ttl_engine
    if _ttl_engine is None:
        _ttl_engine = TTLMasqueradingEngine()
    return _ttl_engine

def ttl_masquerade_probe(target_ip: str, target_port: int, 
                        strategy: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function for TTL masquerading probe."""
    engine = get_ttl_engine()
    
    if strategy:
        try:
            strategy_enum = TTLStrategy(strategy.lower())
        except ValueError:
            strategy_enum = None
    else:
        strategy_enum = None
    
    return engine.execute_ttl_masquerading_probe(target_ip, target_port, strategy_enum)

def get_ttl_analysis(target_ip: str) -> Dict[str, Any]:
    """Get TTL analysis for target."""
    engine = get_ttl_engine()
    analysis = engine.analyzer.analyze_target(target_ip)
    
    return {
        "target_ip": target_ip,
        "hops_to_target": analysis.hops_to_target,
        "estimated_ids_hops": analysis.estimated_ids_hops,
        "optimal_ids_ttl": analysis.optimal_ids_ttl,
        "optimal_target_ttl": analysis.optimal_target_ttl,
        "confidence": analysis.confidence,
        "recommended_strategy": analysis.strategy.value
    }
