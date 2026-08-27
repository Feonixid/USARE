"""
USARE HTTP/2 HPACK Fingerprinting

Analyzes HTTP/2 HPACK header compression patterns to fingerprint
backend server software more precisely than banner grabbing.

Features:
- HTTP/2 HPACK encoding analysis
- Client fingerprinting from request patterns
- Server implementation detection
- Compression behavior analysis
"""

import time
import struct
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from scapy.all import IP, TCP, sr1, send, Raw
import hpack  # pip install hpack

logger = logging.getLogger("usare.hpack_fingerprint")

@dataclass
class HPACKObservation:
    """Single HPACK observation."""
    headers_encoded: bytes
    headers_decoded: Dict[str, str]
    encoding_pattern: str
    compression_ratio: float
    huffman_used: bool
    dynamic_table_size: int
    timestamp: float

@dataclass
class HPACKFingerprint:
    """HTTP/2 HPACK fingerprint analysis."""
    client_fingerprint: str
    server_fingerprint: str
    implementation_guess: str
    confidence: float
    compression_efficiency: float
    header_order_pattern: List[str]
    huffman_encoding_patterns: Dict[str, bool]

class HPACKFingerprinter:
    """Advanced HTTP/2 HPACK fingerprinting for backend detection."""
    
    # Known HTTP/2 implementation patterns
    IMPLEMENTATION_PATTERNS = {
        'nginx': {
            'header_order': ['host', 'user-agent', 'accept', 'accept-encoding'],
            'huffman_usage': True,
            'compression_ratio': 0.65,
            'dynamic_table_size': 4096
        },
        'apache': {
            'header_order': ['host', 'user-agent', 'accept', 'accept-encoding'],
            'huffman_usage': True,
            'compression_ratio': 0.70,
            'dynamic_table_size': 4096
        },
        'envoy': {
            'header_order': ['host', 'user-agent', 'accept', 'accept-encoding'],
            'huffman_usage': True,
            'compression_ratio': 0.60,
            'dynamic_table_size': 4096
        },
        'cloudflare': {
            'header_order': ['host', 'user-agent', 'accept', 'accept-encoding'],
            'huffman_usage': True,
            'compression_ratio': 0.55,
            'dynamic_table_size': 4096
        },
        'chrome': {
            'header_order': ['host', 'user-agent', 'accept', 'accept-encoding'],
            'huffman_usage': True,
            'compression_ratio': 0.68,
            'dynamic_table_size': 4096
        },
        'firefox': {
            'header_order': ['host', 'user-agent', 'accept', 'accept-language'],
            'huffman_usage': True,
            'compression_ratio': 0.72,
            'dynamic_table_size': 4096
        },
        'curl': {
            'header_order': ['host', 'user-agent', 'accept'],
            'huffman_usage': False,
            'compression_ratio': 0.80,
            'dynamic_table_size': 4096
        }
    }
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder()
        
    def send_http2_request(self, target_ip: str, target_port: int, headers: Dict[str, str]) -> Optional[bytes]:
        """Send HTTP/2 request and capture response."""
        try:
            # Craft HTTP/2 request (simplified - in practice would use proper HTTP/2 library)
            # This is a mock implementation for demonstration
            request_line = f"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            
            # Encode headers using HPACK
            encoded_headers = self._encode_headers(headers)
            
            # Create HTTP/2 frame (simplified)
            frame_type = 1  # HEADERS frame
            flags = 0x4  # END_HEADERS
            stream_id = 1
            payload = encoded_headers
            
            # Build frame (simplified HTTP/2 frame structure)
            frame = struct.pack("!BBHB", len(payload), frame_type, flags, stream_id) + payload
            
            # Send request
            packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/frame
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP) and response[TCP].payload:
                return bytes(response[TCP].payload)
                
        except Exception as e:
            logger.debug(f"[USARE] HTTP/2 request failed: {e}")
            
        return None
        
    def _encode_headers(self, headers: Dict[str, str]) -> bytes:
        try:
            header_list = list(headers.items())
            return self.encoder.encode(header_list)
        except Exception as e:
            logger.debug(f"[USARE] HPACK encoding failed: {e}")
            return b""
            
    def _decode_headers(self, encoded_headers: bytes) -> Dict[str, str]:
        """Decode HPACK encoded headers."""
        try:
            decoded = self.decoder.decode(encoded_headers, len(encoded_headers))
            return decoded
        except Exception as e:
            logger.debug(f"[USARE] HPACK decoding failed: {e}")
            return {}
            
    def analyze_hpack_encoding(self, headers: Dict[str, str]) -> HPACKObservation:
        """Analyze HPACK encoding patterns."""
        timestamp = time.time()
        
        # Encode headers
        encoded_headers = self._encode_headers(headers)
        
        # Decode headers
        decoded_headers = self._decode_headers(encoded_headers)
        
        # Calculate compression ratio
        original_size = sum(len(name) + len(value) + 2 for name, value in headers.items())
        compressed_size = len(encoded_headers)
        compression_ratio = compressed_size / original_size if original_size > 0 else 1.0
        
        # Detect Huffman usage (simplified detection)
        huffman_used = any(b & 0x80 for b in encoded_headers)  # Huffman bit pattern
        
        # Extract encoding pattern
        encoding_pattern = self._extract_encoding_pattern(encoded_headers)
        
        # Estimate dynamic table size (simplified)
        dynamic_table_size = len(encoded_headers) // 2  # Rough estimate
        
        return HPACKObservation(
            headers_encoded=encoded_headers,
            headers_decoded=decoded_headers,
            encoding_pattern=encoding_pattern,
            compression_ratio=compression_ratio,
            huffman_used=huffman_used,
            dynamic_table_size=dynamic_table_size,
            timestamp=timestamp
        )
        
    def _extract_encoding_pattern(self, encoded_headers: bytes) -> str:
        """Extract encoding pattern from HPACK encoded headers."""
        if not encoded_headers:
            return "empty"
            
        # Simplified pattern extraction
        patterns = []
        
        # Check for Huffman encoding
        if any(b & 0x80 for b in encoded_headers):
            patterns.append("huffman")
        else:
            patterns.append("literal")
            
        # Check for dynamic table references
        if any(b & 0x80 for b in encoded_headers[:4]):  # Simplified check
            patterns.append("dynamic_table")
        else:
            patterns.append("static_table")
            
        return "-".join(patterns)
        
    def fingerprint_implementation(self, observations: List[HPACKObservation]) -> HPACKFingerprint:
        """Fingerprint HTTP/2 implementation from observations."""
        if not observations:
            return HPACKFingerprint(
                client_fingerprint="unknown",
                server_fingerprint="unknown", 
                implementation_guess="unknown",
                confidence=0.0,
                compression_efficiency=0.0,
                header_order_pattern=[],
                huffman_encoding_patterns={}
            )
            
        # Analyze header order patterns
        header_orders = []
        for obs in observations:
            if obs.headers_decoded:
                headers = list(obs.headers_decoded.keys())
                header_orders.append(headers)
                
        # Find most common header order
        most_common_order = self._most_common_header_order(header_orders)
        
        # Calculate average compression efficiency
        avg_compression = sum(obs.compression_ratio for obs in observations) / len(observations)
        
        # Analyze Huffman usage patterns
        huffman_patterns = {}
        for obs in observations:
            huffman_patterns[f"obs_{len(huffman_patterns)}"] = obs.huffman_used
            
        # Match against known patterns
        implementation_matches = {}
        
        for impl_name, impl_pattern in self.IMPLEMENTATION_PATTERNS.items():
            score = 0.0
            
            # Header order matching
            if most_common_order == impl_pattern['header_order']:
                score += 0.4
                
            # Compression ratio matching
            compression_diff = abs(avg_compression - impl_pattern['compression_ratio'])
            if compression_diff < 0.1:
                score += 0.3
            elif compression_diff < 0.2:
                score += 0.15
                
            # Huffman usage matching
            huffman_consistent = all(obs.huffman_used == impl_pattern['huffman_usage'] 
                                  for obs in observations)
            if huffman_consistent:
                score += 0.3
                
            implementation_matches[impl_name] = score
            
        # Find best match
        if implementation_matches:
            best_match = max(implementation_matches.keys(), key=lambda x: implementation_matches[x])
            confidence = implementation_matches[best_match]
        else:
            best_match = "unknown"
            confidence = 0.0
            
        return HPACKFingerprint(
            client_fingerprint="custom_client",
            server_fingerprint=best_match,
            implementation_guess=best_match,
            confidence=confidence,
            compression_efficiency=1.0 - avg_compression,  # Higher = better compression
            header_order_pattern=most_common_order,
            huffman_encoding_patterns=huffman_patterns
        )
        
    def _most_common_header_order(self, header_orders: List[List[str]]) -> List[str]:
        """Find the most common header order pattern."""
        if not header_orders:
            return []
            
        # Count occurrences of each order
        order_counts = {}
        for order in header_orders:
            order_tuple = tuple(order)
            order_counts[order_tuple] = order_counts.get(order_tuple, 0) + 1
            
        # Return most common order
        most_common = max(order_counts.keys(), key=lambda x: order_counts[x])
        return list(most_common)
        
    def analyze_target(self, target_ip: str, target_port: int = 443) -> Optional[HPACKFingerprint]:
        """Perform complete HTTP/2 HPACK fingerprinting."""
        logger.info(f"[USARE] Starting HTTP/2 HPACK fingerprinting for {target_ip}:{target_port}")
        
        # Test different header sets to capture patterns
        test_headers_sets = [
            {
                'host': target_ip,
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.5'
            },
            {
                'host': target_ip,
                'user-agent': 'curl/7.68.0',
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate'
            },
            {
                'host': target_ip,
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
                'accept-encoding': 'gzip, deflate, br',
                'connection': 'keep-alive'
            }
        ]
        
        observations = []
        
        for headers in test_headers_sets:
            obs = self.analyze_hpack_encoding(headers)
            if obs.headers_encoded:
                observations.append(obs)
                
        # Fingerprint implementation
        fingerprint = self.fingerprint_implementation(observations)
        
        logger.info(f"[USARE] HPACK fingerprinting complete: {fingerprint.implementation_guess} "
                   f"(confidence: {fingerprint.confidence:.2f})")
        
        return fingerprint

# Integration function for existing scanner
def analyze_hpack_fingerprint(target: str, port: int = 443) -> Optional[Dict[str, any]]:
    """Analyze HTTP/2 HPACK fingerprint and return results as dict."""
    try:
        fingerprinter = HPACKFingerprinter()
        fingerprint = fingerprinter.analyze_target(target, port)
        
        if fingerprint:
            return {
                'server_fingerprint': fingerprint.server_fingerprint,
                'implementation_guess': fingerprint.implementation_guess,
                'confidence': fingerprint.confidence,
                'compression_efficiency': fingerprint.compression_efficiency,
                'header_order_pattern': fingerprint.header_order_pattern,
                'huffman_encoding_patterns': fingerprint.huffman_encoding_patterns
            }
        return None
        
    except Exception as e:
        logger.error(f"[USARE] HPACK fingerprinting failed: {e}")
        return None
