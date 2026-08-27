"""
USARE IPID/TTL Consistency Mapping

Analyzes TTL values across multiple ports to detect infrastructure
topology indicators like load balancing, CDN edge nodes, and reverse proxies.

Features:
- TTL inconsistency detection
- Load balancer identification
- CDN edge node analysis
- Reverse proxy detection
- Infrastructure topology mapping
"""

import statistics
import time
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger("usare.consistency_analysis")

@dataclass
class TTLAnalysis:
    """TTL consistency analysis results."""
    ttl_values: List[int]
    ttl_ranges: Dict[str, List[int]]
    consistency_score: float  # 0-1, higher = more consistent
    infrastructure_indicators: Dict[str, str]
    topology_hints: List[str]
    confidence: float

@dataclass
class IPIDTTLAnalysis:
    """Combined IP ID and TTL analysis."""
    ttl_analysis: TTLAnalysis
    ipid_patterns: Dict[int, str]  # port -> ipid_pattern
    cross_protocol_consistency: float
    backend_diversity: int
    load_balancing_detected: bool

class ConsistencyAnalyzer:
    """Advanced consistency analysis for infrastructure topology detection."""
    
    # Known TTL patterns by OS
    OS_TTL_PATTERNS = {
        'Windows': {'typical_ttl': 128, 'range': (120, 136)},
        'Linux': {'typical_ttl': 64, 'range': (60, 68)},
        'Cisco': {'typical_ttl': 255, 'range': (250, 255)},
        'Juniper': {'typical_ttl': 64, 'range': (60, 68)},
        'BSD': {'typical_ttl': 64, 'range': (60, 68)},
        'macOS': {'typical_ttl': 64, 'range': (60, 68)},
        'Network Equipment': {'typical_ttl': 255, 'range': (250, 255)}
    }
    
    # TTL ranges indicating different infrastructure
    INFRASTRUCTURE_TTL_RANGES = {
        'direct_connection': {'range': (60, 68), 'description': 'Direct Linux/BSD connection'},
        'windows_backend': {'range': (120, 136), 'description': 'Windows backend servers'},
        'network_hardware': {'range': (250, 255), 'description': 'Network equipment/CDN edge'},
        'cloudflare_edge': {'range': (64, 68), 'description': 'Cloudflare edge nodes'},
        'aws_elb': {'range': (113, 119), 'description': 'AWS Elastic Load Balancer'},
        'azure_lb': {'range': (118, 128), 'description': 'Azure Load Balancer'},
        'gcp_lb': {'range': (112, 118), 'description': 'Google Cloud Load Balancer'}
    }
    
    def __init__(self):
        self.observations = []
        
    def analyze_ttl_consistency(self, scan_results: List) -> TTLAnalysis:
        """Analyze TTL consistency across multiple ports."""
        logger.info(f"[USARE] Analyzing TTL consistency across {len(scan_results)} scan results")
        
        # Extract TTL values from scan results
        ttl_values = []
        port_ttl_mapping = {}
        
        for result in scan_results:
            if hasattr(result, 'ttl_received') and result.ttl_received:
                ttl_values.append(result.ttl_received)
                port_ttl_mapping[result.port] = result.ttl_received
                
        if not ttl_values:
            return TTLAnalysis(
                ttl_values=[],
                ttl_ranges={},
                consistency_score=0.0,
                infrastructure_indicators={},
                topology_hints=[],
                confidence=0.0
            )
            
        # Group TTL values by ranges
        ttl_ranges = self._group_ttl_by_ranges(ttl_values)
        
        # Calculate consistency score
        consistency_score = self._calculate_ttl_consistency(ttl_values)
        
        # Analyze infrastructure indicators
        infrastructure_indicators = self._analyze_infrastructure_indicators(ttl_ranges)
        
        # Generate topology hints
        topology_hints = self._generate_topology_hints(ttl_values, ttl_ranges)
        
        # Calculate confidence based on data quality
        confidence = min(1.0, len(ttl_values) / 10.0)  # More ports = higher confidence
        
        logger.info(f"[USARE] TTL analysis complete: consistency={consistency_score:.2f}, "
                   f"ranges={len(ttl_ranges)}, confidence={confidence:.2f}")
        
        return TTLAnalysis(
            ttl_values=ttl_values,
            ttl_ranges=ttl_ranges,
            consistency_score=consistency_score,
            infrastructure_indicators=infrastructure_indicators,
            topology_hints=topology_hints,
            confidence=confidence
        )
        
    def _group_ttl_by_ranges(self, ttl_values: List[int]) -> Dict[str, List[int]]:
        """Group TTL values by infrastructure ranges."""
        ranges = defaultdict(list)
        
        for ttl in ttl_values:
            matched_range = None
            
            for range_name, range_info in self.INFRASTRUCTURE_TTL_RANGES.items():
                min_ttl, max_ttl = range_info['range']
                if min_ttl <= ttl <= max_ttl:
                    matched_range = range_name
                    break
                    
            if matched_range:
                ranges[matched_range].append(ttl)
            else:
                # Custom range for unknown TTLs
                ranges[f"custom_{ttl}"].append(ttl)
                
        return dict(ranges)
        
    def _calculate_ttl_consistency(self, ttl_values: List[int]) -> float:
        """Calculate TTL consistency score."""
        if len(ttl_values) < 2:
            return 1.0
            
        # Calculate standard deviation
        mean_ttl = statistics.mean(ttl_values)
        if len(ttl_values) > 1:
            std_ttl = statistics.stdev(ttl_values)
        else:
            std_ttl = 0
            
        # Consistency score based on standard deviation
        # Lower standard deviation = higher consistency
        if mean_ttl > 0:
            cv = std_ttl / mean_ttl  # Coefficient of variation
            consistency = max(0.0, 1.0 - cv * 2)  # Penalize variation
        else:
            consistency = 0.0
            
        return consistency
        
    def _analyze_infrastructure_indicators(self, ttl_ranges: Dict[str, List[int]]) -> Dict[str, str]:
        """Analyze infrastructure indicators from TTL ranges."""
        indicators = {}
        
        # Detect multiple TTL ranges (indicates load balancing)
        if len(ttl_ranges) > 1:
            indicators['multiple_ttl_ranges'] = f"Multiple TTL ranges detected: {list(ttl_ranges.keys())}"
            
        # Detect specific infrastructure patterns
        for range_name, ttls in ttl_ranges.items():
            if 'direct_connection' in range_name:
                indicators['direct_connections'] = f"Direct connections detected: {len(ttls)} ports"
            elif 'windows_backend' in range_name:
                indicators['windows_backends'] = f"Windows backend servers: {len(ttls)} ports"
            elif 'network_hardware' in range_name:
                indicators['network_equipment'] = f"Network equipment/CDN: {len(ttls)} ports"
            elif 'cloudflare_edge' in range_name:
                indicators['cloudflare'] = f"Cloudflare edge nodes: {len(ttls)} ports"
            elif 'aws_elb' in range_name:
                indicators['aws_elb'] = f"AWS Load Balancer: {len(ttls)} ports"
            elif 'azure_lb' in range_name:
                indicators['azure_lb'] = f"Azure Load Balancer: {len(ttls)} ports"
            elif 'gcp_lb' in range_name:
                indicators['gcp_lb'] = f"Google Cloud Load Balancer: {len(ttls)} ports"
                
        return indicators
        
    def _generate_topology_hints(self, ttl_values: List[int], ttl_ranges: Dict[str, List[int]]) -> List[str]:
        """Generate topology hints from TTL analysis."""
        hints = []
        
        # Consistency hints
        if len(set(ttl_values)) == 1:
            hints.append("Single TTL value suggests single host or consistent infrastructure")
        elif len(set(ttl_values)) > 3:
            hints.append("Multiple TTL values suggest load balancing or CDN")
            
        # Range-specific hints
        if any('cloudflare_edge' in range_name for range_name in ttl_ranges.keys()):
            hints.append("Cloudflare CDN edge nodes detected")
            
        if any('aws_elb' in range_name or 'azure_lb' in range_name or 'gcp_lb' in range_name 
               for range_name in ttl_ranges.keys()):
            hints.append("Cloud provider load balancer detected")
            
        if 'network_hardware' in ttl_ranges:
            hints.append("Network equipment or CDN edge nodes present")
            
        # OS diversity hints
        os_diversity = set()
        for ttl in ttl_values:
            for os_name, os_pattern in self.OS_TTL_PATTERNS.items():
                min_ttl, max_ttl = os_pattern['range']
                if min_ttl <= ttl <= max_ttl:
                    os_diversity.add(os_name)
                    break
                    
        if len(os_diversity) > 1:
            hints.append(f"Multiple OS types detected: {', '.join(os_diversity)}")
            
        return hints
        
    def analyze_ipid_ttl_consistency(self, scan_results: List, ipid_analysis: Optional[Dict] = None) -> IPIDTTLAnalysis:
        """Perform combined IP ID and TTL consistency analysis."""
        logger.info("[USARE] Performing combined IP ID/TTL consistency analysis")
        
        # TTL analysis
        ttl_analysis = self.analyze_ttl_consistency(scan_results)
        
        # IP ID patterns (if provided)
        ipid_patterns = {}
        if ipid_analysis:
            # Extract IP ID patterns per port (simplified)
            for result in scan_results:
                if hasattr(result, 'ip_id_received') and result.ip_id_received:
                    # Simplified IP ID pattern detection
                    ipid_patterns[result.port] = "incrementing"  # Placeholder
                    
        # Cross-protocol consistency
        cross_protocol_consistency = ttl_analysis.consistency_score
        
        # Backend diversity (number of different TTL ranges)
        backend_diversity = len(ttl_analysis.ttl_ranges)
        
        # Load balancing detection
        load_balancing_detected = backend_diversity > 1 or ttl_analysis.consistency_score < 0.7
        
        return IPIDTTLAnalysis(
            ttl_analysis=ttl_analysis,
            ipid_patterns=ipid_patterns,
            cross_protocol_consistency=cross_protocol_consistency,
            backend_diversity=backend_diversity,
            load_balancing_detected=load_balancing_detected
        )

# Integration function for existing scanner
def analyze_ttl_consistency(scan_results: List) -> Optional[Dict[str, any]]:
    """Analyze TTL consistency and return results as dict."""
    try:
        analyzer = ConsistencyAnalyzer()
        ttl_analysis = analyzer.analyze_ttl_consistency(scan_results)
        
        return {
            'ttl_values': ttl_analysis.ttl_values,
            'ttl_ranges': ttl_analysis.ttl_ranges,
            'consistency_score': ttl_analysis.consistency_score,
            'infrastructure_indicators': ttl_analysis.infrastructure_indicators,
            'topology_hints': ttl_analysis.topology_hints,
            'confidence': ttl_analysis.confidence
        }
        
    except Exception as e:
        logger.error(f"[USARE] TTL consistency analysis failed: {e}")
        return None

def analyze_full_consistency(scan_results: List, ipid_analysis: Optional[Dict] = None) -> Optional[Dict[str, any]]:
    """Perform full consistency analysis including IP ID and TTL."""
    try:
        analyzer = ConsistencyAnalyzer()
        analysis = analyzer.analyze_ipid_ttl_consistency(scan_results, ipid_analysis)
        
        return {
            'ttl_analysis': {
                'ttl_values': analysis.ttl_analysis.ttl_values,
                'ttl_ranges': analysis.ttl_analysis.ttl_ranges,
                'consistency_score': analysis.ttl_analysis.consistency_score,
                'infrastructure_indicators': analysis.ttl_analysis.infrastructure_indicators,
                'topology_hints': analysis.ttl_analysis.topology_hints,
                'confidence': analysis.ttl_analysis.confidence
            },
            'ipid_patterns': analysis.ipid_patterns,
            'cross_protocol_consistency': analysis.cross_protocol_consistency,
            'backend_diversity': analysis.backend_diversity,
            'load_balancing_detected': analysis.load_balancing_detected
        }
        
    except Exception as e:
        logger.error(f"[USARE] Full consistency analysis failed: {e}")
        return None
