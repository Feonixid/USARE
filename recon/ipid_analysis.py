"""
USARE IP ID Sequence Analysis

Analyzes IP ID sequences to identify potential idle scan zombies.
Predictable IP ID sequences indicate hosts suitable for idle scanning.

Features:
- IP ID sequence analysis
- Idle scan zombie detection
- OS fingerprinting from IP ID behavior
- Network topology inference
"""

import time
import statistics
import random
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from scapy.all import IP, TCP, sr1, send
import logging

logger = logging.getLogger("usare.ipid_analysis")

@dataclass
class IPIDObservation:
    """Single IP ID observation."""
    ip_id: int
    timestamp: float
    source_port: int
    response_received: bool

@dataclass
class IPIDAnalysis:
    """Results of IP ID sequence analysis."""
    is_predictable: bool
    prediction_confidence: float
    ip_id_pattern: str  # 'incrementing', 'random', 'zero', 'broken'
    increment_value: int
    os_guess: str
    zombie_suitability: float  # 0-1, higher = better zombie
    observations_count: int
    analysis_confidence: float

class IPIDAnalyzer:
    """Advanced IP ID sequence analyzer for idle scan preparation."""
    
    # IP ID patterns by OS
    OS_IPID_PATTERNS = {
        'Windows': {'pattern': 'incrementing', 'increment': 256, 'suitability': 0.9},
        'Linux': {'pattern': 'incrementing', 'increment': 1, 'suitability': 0.8},
        'FreeBSD': {'pattern': 'random', 'increment': 0, 'suitability': 0.2},
        'OpenBSD': {'pattern': 'random', 'increment': 0, 'suitability': 0.2},
        'Cisco IOS': {'pattern': 'incrementing', 'increment': 1, 'suitability': 0.7},
        'Juniper': {'pattern': 'incrementing', 'increment': 1, 'suitability': 0.7},
        'Printer': {'pattern': 'zero', 'increment': 0, 'suitability': 0.1},
        'Embedded': {'pattern': 'broken', 'increment': 0, 'suitability': 0.1},
    }
    
    MIN_OBSERVATIONS = 6  # Need at least 6 observations for analysis
    PREDICTION_THRESHOLD = 0.7  # 70% prediction accuracy for predictable
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.observations: List[IPIDObservation] = []
        
    def probe_ip_id(self, target_ip: str, target_port: int, source_port: int) -> Optional[IPIDObservation]:
        """Send a probe to capture IP ID from response."""
        # Create SYN packet
        syn_packet = IP(dst=target_ip)/TCP(sport=source_port, dport=target_port, flags="S")
        
        try:
            # Send packet and receive response
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            
            timestamp = time.time()
            
            if response and response.haslayer(IP):
                ip_id = response[IP].id
                return IPIDObservation(
                    ip_id=ip_id,
                    timestamp=timestamp,
                    source_port=source_port,
                    response_received=True
                )
            else:
                # No response, still record the attempt
                return IPIDObservation(
                    ip_id=0,
                    timestamp=timestamp,
                    source_port=source_port,
                    response_received=False
                )
                
        except Exception as e:
            logger.debug(f"[USARE] IP ID probe failed for {target_ip}:{target_port} - {e}")
            return None
            
    def collect_ip_id_sequence(self, target_ip: str, target_port: int, count: int = 10) -> None:
        """Collect a sequence of IP ID observations."""
        logger.info(f"[USARE] Collecting {count} IP ID observations from {target_ip}:{target_port}")
        
        source_port_base = random.randint(20000, 30000)
        
        for i in range(count):
            source_port = source_port_base + i
            observation = self.probe_ip_id(target_ip, target_port, source_port)
            
            if observation:
                self.observations.append(observation)
                logger.debug(f"[USARE] IP ID observation {i+1}: {observation.ip_id}")
                
            # Small delay between probes
            time.sleep(0.1)
            
        logger.info(f"[USARE] Collected {len(self.observations)} IP ID observations")
        
    def analyze_ip_id_pattern(self) -> Tuple[str, int]:
        """Analyze the IP ID pattern and determine increment value."""
        if len(self.observations) < self.MIN_OBSERVATIONS:
            return "insufficient_data", 0
            
        # Extract IP IDs from successful responses
        ip_ids = [obs.ip_id for obs in self.observations if obs.response_received and obs.ip_id > 0]
        
        if len(ip_ids) < self.MIN_OBSERVATIONS:
            return "insufficient_responses", 0
            
        # Check for zero IP IDs (some devices always return 0)
        if all(ip_id == 0 for ip_id in ip_ids):
            return "zero", 0
            
        # Calculate differences between consecutive IP IDs
        differences = []
        for i in range(1, len(ip_ids)):
            diff = (ip_ids[i] - ip_ids[i-1]) % 65536  # Handle 16-bit wraparound
            differences.append(diff)
            
        if not differences:
            return "no_differences", 0
            
        # Analyze the differences
        diff_counts = {}
        for diff in differences:
            diff_counts[diff] = diff_counts.get(diff, 0) + 1
            
        # Find the most common difference
        most_common_diff = max(diff_counts.keys(), key=lambda x: diff_counts[x])
        most_common_count = diff_counts[most_common_diff]
        
        # Calculate consistency
        consistency = most_common_count / len(differences)
        
        # Determine pattern
        if consistency > 0.8:
            if most_common_diff == 0:
                return "static", 0
            elif most_common_diff == 1:
                return "incrementing", 1
            elif most_common_diff == 256:
                return "incrementing", 256
            elif most_common_diff < 1000:
                return "incrementing", most_common_diff
            else:
                return "incrementing", most_common_diff
        elif consistency > 0.5:
            return "mostly_incrementing", most_common_diff
        else:
            # Check if differences are random
            unique_diffs = len(set(differences))
            if unique_diffs > len(differences) * 0.7:
                return "random", 0
            else:
                return "broken", 0
                
    def predict_next_ip_id(self) -> Tuple[int, float]:
        """Predict the next IP ID and confidence."""
        if len(self.observations) < self.MIN_OBSERVATIONS:
            return 0, 0.0
            
        pattern, increment = self.analyze_ip_id_pattern()
        
        if pattern not in ["incrementing", "mostly_incrementing"]:
            return 0, 0.0
            
        # Get the last few IP IDs
        ip_ids = [obs.ip_id for obs in self.observations if obs.response_received and obs.ip_id > 0]
        
        if len(ip_ids) < 3:
            return 0, 0.0
            
        # Calculate predicted next IP ID
        last_ip_id = ip_ids[-1]
        predicted_next = (last_ip_id + increment) % 65536
        
        # Calculate confidence based on pattern consistency
        pattern, _ = self.analyze_ip_id_pattern()
        
        if pattern == "incrementing":
            confidence = 0.9
        elif pattern == "mostly_incrementing":
            confidence = 0.7
        else:
            confidence = 0.0
            
        return predicted_next, confidence
        
    def assess_zombie_suitability(self) -> float:
        """Assess how suitable this host is as an idle scan zombie."""
        pattern, increment = self.analyze_ip_id_pattern()
        
        # Base suitability from pattern
        if pattern == "incrementing":
            if increment == 1:  # Linux-like
                base_suitability = 0.8
            elif increment == 256:  # Windows-like
                base_suitability = 0.9
            else:
                base_suitability = 0.6
        elif pattern == "mostly_incrementing":
            base_suitability = 0.5
        elif pattern == "random":
            base_suitability = 0.1
        elif pattern == "zero":
            base_suitability = 0.0
        else:  # broken, static, insufficient_data
            base_suitability = 0.0
            
        # Adjust based on response rate
        response_rate = len([obs for obs in self.observations if obs.response_received]) / len(self.observations)
        if response_rate < 0.8:  # Need reliable responses
            base_suitability *= response_rate
            
        return min(1.0, base_suitability)
        
    def guess_os_from_ipid(self) -> Tuple[str, float]:
        """Guess the OS based on IP ID behavior."""
        pattern, increment = self.analyze_ip_id_pattern()
        
        os_matches = []
        
        for os_name, os_profile in self.OS_IPID_PATTERNS.items():
            if os_profile['pattern'] == pattern:
                if pattern == "incrementing":
                    # Check if increment matches
                    if abs(increment - os_profile['increment']) <= max(1, increment * 0.1):
                        confidence = 0.8
                    else:
                        confidence = 0.4
                else:
                    confidence = 0.7
                    
                os_matches.append((os_name, confidence))
                
        # Sort by confidence and return the best match
        if os_matches:
            os_matches.sort(key=lambda x: x[1], reverse=True)
            return os_matches[0]
        else:
            return "Unknown", 0.0
            
    def analyze(self) -> IPIDAnalysis:
        """Perform complete IP ID sequence analysis."""
        logger.info(f"[USARE] Analyzing {len(self.observations)} IP ID observations")
        
        if len(self.observations) < self.MIN_OBSERVATIONS:
            return IPIDAnalysis(
                is_predictable=False,
                prediction_confidence=0.0,
                ip_id_pattern="insufficient_data",
                increment_value=0,
                os_guess="Unknown",
                zombie_suitability=0.0,
                observations_count=len(self.observations),
                analysis_confidence=0.0
            )
            
        # Analyze pattern
        pattern, increment = self.analyze_ip_id_pattern()
        
        # Predict next IP ID
        predicted_next, prediction_confidence = self.predict_next_ip_id()
        
        # Assess zombie suitability
        zombie_suitability = self.assess_zombie_suitability()
        
        # Guess OS
        os_guess, os_confidence = self.guess_os_from_ipid()
        
        # Overall confidence
        is_predictable = prediction_confidence > self.PREDICTION_THRESHOLD
        analysis_confidence = min(1.0, len(self.observations) / 10.0)
        
        logger.info(f"[USARE] IP ID analysis complete: pattern={pattern}, "
                   f"predictable={is_predictable}, zombie_suitability={zombie_suitability:.2f}")
        
        return IPIDAnalysis(
            is_predictable=is_predictable,
            prediction_confidence=prediction_confidence,
            ip_id_pattern=pattern,
            increment_value=increment,
            os_guess=os_guess,
            zombie_suitability=zombie_suitability,
            observations_count=len(self.observations),
            analysis_confidence=analysis_confidence
        )

# Integration function for existing scanner
def analyze_ipid_from_scan_results(target_ip: str, scan_results: List) -> Optional[Dict[str, any]]:
    """Analyze IP ID sequence from existing scan results."""
    try:
        analyzer = IPIDAnalyzer()
        
        # Find open ports to probe
        open_ports = [result.port for result in scan_results if result.state.value == "open"]
        
        if not open_ports:
            return None
            
        # Use the first open port for IP ID analysis
        target_port = open_ports[0]
        
        # Collect IP ID sequence
        analyzer.collect_ip_id_sequence(target_ip, target_port, count=8)
        
        # Analyze
        analysis = analyzer.analyze()
        
        return {
            'is_predictable': analysis.is_predictable,
            'prediction_confidence': analysis.prediction_confidence,
            'ip_id_pattern': analysis.ip_id_pattern,
            'increment_value': analysis.increment_value,
            'os_guess': analysis.os_guess,
            'zombie_suitability': analysis.zombie_suitability,
            'observations_count': analysis.observations_count,
            'analysis_confidence': analysis.analysis_confidence
        }
        
    except Exception as e:
        logger.error(f"[USARE] IP ID analysis failed: {e}")
        return None

def find_idle_scan_zombies(network_range: str, scan_results: Dict[str, List]) -> List[Dict[str, any]]:
    """Find potential idle scan zombies from scan results."""
    zombies = []
    
    for target_ip, results in scan_results.items():
        ipid_analysis = analyze_ipid_from_scan_results(target_ip, results)
        
        if ipid_analysis and ipid_analysis['zombie_suitability'] > 0.5:
            zombies.append({
                'ip': target_ip,
                'suitability': ipid_analysis['zombie_suitability'],
                'pattern': ipid_analysis['ip_id_pattern'],
                'os_guess': ipid_analysis['os_guess'],
                'confidence': ipid_analysis['analysis_confidence']
            })
            
    # Sort by suitability
    zombies.sort(key=lambda x: x['suitability'], reverse=True)
    
    return zombies
