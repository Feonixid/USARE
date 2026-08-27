"""
USARE Banner Mutation Detection

Sends the same banner grab request twice with a delay between them
and compares the responses to detect infrastructure patterns.

Detects:
- Load balancers (different backend servers respond differently)
- WAF behavioral patterns (WAFs respond differently to repeated requests)
- Active vs passive monitoring (IDS systems inject responses)
- CDN edge node behavior
- Application layer load balancing
"""

import time
import difflib
import hashlib
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from scapy.all import IP, TCP, sr1, send
import logging
import re

logger = logging.getLogger("usare.banner_mutation")

@dataclass
class BannerResponse:
    """Single banner response."""
    response: str
    headers: Dict[str, str]
    timestamp: float
    latency_ms: float
    response_hash: str
    server_signature: str
    content_length: int

@dataclass
class BannerDiff:
    """Differences between two banner responses."""
    header_differences: Dict[str, Tuple[str, str]]
    content_differences: List[str]
    timing_difference: float
    signature_difference: bool
    structural_differences: List[str]
    mutation_score: float  # 0-1, higher = more mutation

@dataclass
class MutationAnalysis:
    """Complete banner mutation analysis."""
    first_response: BannerResponse
    second_response: BannerResponse
    differences: BannerDiff
    infrastructure_indicators: Dict[str, str]
    mutation_type: str
    confidence: float

class BannerMutationDetector:
    """Advanced banner mutation detection for infrastructure analysis."""
    
    MUTATION_PATTERNS = {
        'load_balancer': {
            'indicators': ['server_signature_change', 'header_variation', 'timing_variance'],
            'confidence_threshold': 0.6
        },
        'cdn_edge_nodes': {
            'indicators': ['server_signature_change', 'timing_variance', 'geo_hints'],
            'confidence_threshold': 0.5
        },
        'waf_behavior': {
            'indicators': ['header_injection', 'content_modification', 'timing_increase'],
            'confidence_threshold': 0.7
        },
        'active_monitoring': {
            'indicators': ['header_injection', 'unexpected_headers', 'timing_increase'],
            'confidence_threshold': 0.8
        },
        'app_load_balancer': {
            'indicators': ['content_variation', 'session_id_change', 'header_variation'],
            'confidence_threshold': 0.6
        }
    }
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        
    def grab_banner(self, target_ip: str, target_port: int, request_data: bytes = None) -> Optional[BannerResponse]:
        """Grab a single banner response."""
        if request_data is None:
            request_data = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            
        try:
            start_time = time.time()
            
            # Create and send packet
            packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
            syn_ack = sr1(packet, timeout=self.timeout, verbose=0)
            
            if not syn_ack or not syn_ack.haslayer(TCP):
                return None
                
            # Complete handshake and send request
            tcp_layer = TCP(sport=syn_ack[TCP].dport, dport=target_port, flags="A", ack=syn_ack[TCP].seq + 1)
            ack_packet = IP(dst=target_ip)/tcp_layer
            send(ack_packet, verbose=0)
            
            # Send HTTP request
            http_packet = IP(dst=target_ip)/TCP(sport=syn_ack[TCP].dport, dport=target_port, flags="PA", ack=syn_ack[TCP].seq + 1)/request_data
            response = sr1(http_packet, timeout=self.timeout, verbose=0)
            
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            
            if response and response.haslayer(TCP) and response[TCP].payload:
                raw_response = bytes(response[TCP].payload)
                response_str = raw_response.decode('utf-8', errors='ignore')
                
                # Parse response
                return self._parse_response(response_str, latency_ms, end_time)
                
        except Exception as e:
            logger.debug(f"[USARE] Banner grab failed for {target_ip}:{target_port} - {e}")
            return None
            
    def _parse_response(self, response: str, latency_ms: float, timestamp: float) -> BannerResponse:
        """Parse HTTP response into structured format."""
        lines = response.split('\n')
        
        # Extract headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines):
            if ':' in line and i > 0:  # Skip first line (status line)
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif line.strip() == '':
                body_start = i + 1
                break
                
        # Extract body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Extract server signature
        server_signature = headers.get('server', 'Unknown')
        
        # Calculate content length
        content_length = len(body.encode('utf-8'))
        
        # Calculate response hash
        response_hash = hashlib.sha256(response.encode('utf-8')).hexdigest()
        
        return BannerResponse(
            response=response,
            headers=headers,
            timestamp=timestamp,
            latency_ms=latency_ms,
            response_hash=response_hash,
            server_signature=server_signature,
            content_length=content_length
        )
        
    def grab_with_mutation(self, target_ip: str, target_port: int, 
                          delay_seconds: int = 30) -> Optional[MutationAnalysis]:
        """Grab banner twice with delay and analyze for mutations."""
        logger.info(f"[USARE] Performing banner mutation analysis on {target_ip}:{target_port}")
        
        # First grab
        logger.debug("[USARE] Grabbing first banner...")
        first_response = self.grab_banner(target_ip, target_port)
        
        if not first_response:
            logger.warning(f"[USARE] Failed to grab first banner from {target_ip}:{target_port}")
            return None
            
        # Wait for specified delay
        logger.debug(f"[USARE] Waiting {delay_seconds} seconds...")
        time.sleep(delay_seconds)
        
        # Second grab
        logger.debug("[USARE] Grabbing second banner...")
        second_response = self.grab_banner(target_ip, target_port)
        
        if not second_response:
            logger.warning(f"[USARE] Failed to grab second banner from {target_ip}:{target_port}")
            return None
            
        # Analyze differences
        differences = self._compare_responses(first_response, second_response)
        
        # Analyze infrastructure indicators
        infrastructure_indicators = self._analyze_infrastructure_indicators(
            first_response, second_response, differences
        )
        
        # Determine mutation type
        mutation_type, confidence = self._classify_mutation(differences, infrastructure_indicators)
        
        logger.info(f"[USARE] Banner mutation analysis complete: {mutation_type} (confidence: {confidence:.2f})")
        
        return MutationAnalysis(
            first_response=first_response,
            second_response=second_response,
            differences=differences,
            infrastructure_indicators=infrastructure_indicators,
            mutation_type=mutation_type,
            confidence=confidence
        )
        
    def _compare_responses(self, resp1: BannerResponse, resp2: BannerResponse) -> BannerDiff:
        """Compare two banner responses and identify differences."""
        header_differences = {}
        content_differences = []
        structural_differences = []
        
        # Compare headers
        all_headers = set(resp1.headers.keys()) | set(resp2.headers.keys())
        
        for header in all_headers:
            val1 = resp1.headers.get(header, '')
            val2 = resp2.headers.get(header, '')
            
            if val1 != val2:
                header_differences[header] = (val1, val2)
                
        # Compare content
        if resp1.response != resp2.response:
            # Generate unified diff
            diff_lines = list(difflib.unified_diff(
                resp1.response.splitlines(),
                resp2.response.splitlines(),
                lineterm='',
                fromfile='response1',
                tofile='response2'
            ))
            content_differences = diff_lines
            
        # Timing difference
        timing_difference = abs(resp2.latency_ms - resp1.latency_ms)
        
        # Server signature difference
        signature_difference = resp1.server_signature != resp2.server_signature
        
        # Structural differences
        if resp1.content_length != resp2.content_length:
            structural_differences.append(f"Content length changed: {resp1.content_length} -> {resp2.content_length}")
            
        if resp1.response_hash != resp2.response_hash:
            structural_differences.append("Response hash changed")
            
        # Calculate mutation score
        mutation_score = self._calculate_mutation_score(
            len(header_differences), len(content_differences), 
            timing_difference, signature_difference
        )
        
        return BannerDiff(
            header_differences=header_differences,
            content_differences=content_differences,
            timing_difference=timing_difference,
            signature_difference=signature_difference,
            structural_differences=structural_differences,
            mutation_score=mutation_score
        )
        
    def _calculate_mutation_score(self, header_diffs: int, content_diffs: int, 
                                timing_diff: float, signature_diff: bool) -> float:
        """Calculate a mutation score (0-1, higher = more mutation)."""
        score = 0.0
        
        # Header differences (0-0.3)
        if header_diffs > 0:
            score += min(0.3, header_diffs * 0.1)
            
        # Content differences (0-0.4)
        if content_diffs > 0:
            score += min(0.4, len(content_diffs) * 0.05)
            
        # Timing differences (0-0.2)
        if timing_diff > 100:  # More than 100ms difference
            score += min(0.2, timing_diff / 1000)
            
        # Server signature change (0-0.1)
        if signature_diff:
            score += 0.1
            
        return min(1.0, score)
        
    def _analyze_infrastructure_indicators(self, resp1: BannerResponse, resp2: BannerResponse, 
                                         diff: BannerDiff) -> Dict[str, str]:
        """Analyze infrastructure indicators from response differences."""
        indicators = {}
        
        # Load balancer indicators
        if diff.signature_difference:
            indicators['server_signature_change'] = 'Different backend servers'
            
        if diff.timing_difference > 200:
            indicators['timing_variance'] = 'Variable response times suggest load balancing'
            
        # CDN indicators
        if 'cf-ray' in diff.header_differences or 'x-cache' in diff.header_differences:
            indicators['cdn_hints'] = 'CDN-related headers detected'
            
        # WAF indicators
        injected_headers = ['x-waf-', 'x-modsecurity', 'x-sucuri']
        for header in diff.header_differences:
            if any(waf_indicator in header.lower() for waf_indicator in injected_headers):
                indicators['waf_injection'] = 'WAF header injection detected'
                break
                
        # Active monitoring indicators
        monitoring_headers = ['x-ids', 'x-request-id', 'x-trace-id']
        for header in diff.header_differences:
            if any(monitoring_indicator in header.lower() for monitoring_indicator in monitoring_headers):
                indicators['monitoring_injection'] = 'Active monitoring system detected'
                break
                
        # Session indicators
        session_headers = ['set-cookie', 'jsessionid', 'phpsessid']
        for header in diff.header_differences:
            if any(session_indicator in header.lower() for session_indicator in session_headers):
                indicators['session_variation'] = 'Session management variation detected'
                break
                
        return indicators
        
    def _classify_mutation(self, diff: BannerDiff, indicators: Dict[str, str]) -> Tuple[str, float]:
        """Classify the type of mutation and calculate confidence."""
        mutation_scores = {}
        
        for mutation_type, pattern in self.MUTATION_PATTERNS.items():
            score = 0.0
            matching_indicators = 0
            
            for indicator in pattern['indicators']:
                if indicator in indicators:
                    matching_indicators += 1
                    score += 1.0
                    
            # Normalize score
            if pattern['indicators']:
                score = score / len(pattern['indicators'])
                
            # Boost score if enough indicators match
            if matching_indicators >= 2:
                score *= 1.2
                
            mutation_scores[mutation_type] = min(1.0, score)
            
        # Find best match
        if mutation_scores:
            best_mutation = max(mutation_scores.keys(), key=lambda x: mutation_scores[x])
            confidence = mutation_scores[best_mutation]
            
            # Apply confidence threshold
            threshold = self.MUTATION_PATTERNS[best_mutation]['confidence_threshold']
            if confidence < threshold:
                return "unknown", confidence
                
            return best_mutation, confidence
        else:
            return "no_mutation", 0.0

# Integration function for existing scanner
def analyze_banner_mutation(target_ip: str, target_port: int, delay_seconds: int = 30) -> Optional[Dict[str, any]]:
    """Analyze banner mutation and return results as dict."""
    try:
        detector = BannerMutationDetector()
        analysis = detector.grab_with_mutation(target_ip, target_port, delay_seconds)
        
        if not analysis:
            return None
            
        return {
            'mutation_type': analysis.mutation_type,
            'confidence': analysis.confidence,
            'mutation_score': analysis.differences.mutation_score,
            'header_differences': len(analysis.differences.header_differences),
            'content_differences': len(analysis.differences.content_differences),
            'timing_difference': analysis.differences.timing_difference,
            'signature_difference': analysis.differences.signature_difference,
            'infrastructure_indicators': analysis.infrastructure_indicators,
            'first_response_hash': analysis.first_response.response_hash,
            'second_response_hash': analysis.second_response.response_hash
        }
        
    except Exception as e:
        logger.error(f"[USARE] Banner mutation analysis failed: {e}")
        return None
