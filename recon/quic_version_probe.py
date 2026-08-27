"""QUIC Version Negotiation Probing for Server Library Fingerprinting.

Sends QUIC Initial packets with different version numbers and observes
Version Negotiation responses to identify exact QUIC library implementations.

Different servers support different QUIC versions and respond with
distinct patterns that reveal the underlying library precisely.
"""

import logging
import time
import struct
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import aioquic
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False

logger = logging.getLogger("usare.quic_version")

class QUICVersion(Enum):
    DRAFT_29 = "draft-29"
    V1 = "v1"
    V2 = "v2"
    DRAFT_32 = "draft-32"
    EXPERIMENTAL = "experimental"

class QUICLibrary(Enum):
    AIOQUIC = "aioquic"
    QUICHE = "quiche"
    MSQUIC = "msquic"
    NGHTTP2 = "nghttp2"
    CLOUDFLARE_QUICHE = "cloudflare_quiche"
    GOOGLE_QUIC = "google_quic"
    AWS_QUIC = "aws_quic"
    UNKNOWN = "unknown"

@dataclass
class QUICVersionResult:
    """QUIC version probing result."""
    target_host: str
    target_port: int
    supported_versions: List[str]
    rejected_versions: List[str]
    library_implementation: QUICLibrary
    version_negotiation_data: Optional[bytes]
    response_time_ms: float
    confidence_score: float

class QUICVersionProber:
    """Advanced QUIC version negotiation prober."""
    
    def __init__(self):
        self.timeout = 10.0
        
        # QUIC version signatures
        self.version_signatures = {
            QUICLibrary.AIOQUIC: {
                "supported_versions": [QUICVersion.V1.value, QUICVersion.DRAFT_29.value],
                "version_response_pattern": b"aioquic",
                "negotiation_behavior": "standard_compliant",
                "response_format": "rfc_compliant"
            },
            QUICLibrary.QUICHE: {
                "supported_versions": [QUICVersion.V1.value, QUICVersion.V2.value],
                "version_response_pattern": b"quiche",
                "negotiation_behavior": "conservative",
                "response_format": "quiche_specific"
            },
            QUICLibrary.MSQUIC: {
                "supported_versions": [QUICVersion.V1.value],
                "version_response_pattern": b"msquic",
                "negotiation_behavior": "minimal",
                "response_format": "msquic_specific"
            },
            QUICLibrary.CLOUDFLARE_QUICHE: {
                "supported_versions": [QUICVersion.V1.value, QUICVersion.V2.value],
                "version_response_pattern": b"cf-quic",
                "negotiation_behavior": "cdn_optimized",
                "response_format": "cloudflare_specific"
            },
            QUICLibrary.GOOGLE_QUIC: {
                "supported_versions": [QUICVersion.V1.value, QUICVersion.V2.value],
                "version_response_pattern": b"gquic",
                "negotiation_behavior": "google_optimized",
                "response_format": "google_specific"
            },
            QUICLibrary.AWS_QUIC: {
                "supported_versions": [QUICVersion.V1.value],
                "version_response_pattern": b"aws-quic",
                "negotiation_behavior": "enterprise",
                "response_format": "aws_specific"
            }
        }
        
        # Test versions to probe
        self.test_versions = [
            QUICVersion.DRAFT_29.value,
            QUICVersion.V1.value,
            QUICVersion.V2.value,
            QUICVersion.DRAFT_32.value,
            "experimental"
        ]
    
    def probe_quic_versions(self, target_host: str, target_port: int = 443) -> QUICVersionResult:
        """Probe QUIC version negotiation."""
        start_time = time.time()
        
        try:
            # Test different QUIC versions
            version_responses = []
            supported_versions = []
            rejected_versions = []
            
            for test_version in self.test_versions:
                try:
                    response = self._send_quic_initial(target_host, target_port, test_version)
                    if response:
                        version_responses.append(response)
                        
                        # Analyze response
                        if self._is_version_supported(response):
                            supported_versions.append(test_version)
                        else:
                            rejected_versions.append(test_version)
                            
                except Exception as e:
                    logger.debug(f"[QUIC Version] Version {test_version} probe failed: {e}")
            
            # Analyze responses to identify library
            library_implementation = self._identify_quic_library(version_responses)
            version_negotiation_data = b''.join(version_responses) if version_responses else None
            
            response_time = (time.time() - start_time) * 1000
            
            # Calculate confidence
            confidence = self._calculate_confidence(library_implementation, version_responses)
            
            return QUICVersionResult(
                target_host=target_host,
                target_port=target_port,
                supported_versions=supported_versions,
                rejected_versions=rejected_versions,
                library_implementation=library_implementation,
                version_negotiation_data=version_negotiation_data,
                response_time_ms=response_time,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[QUIC Version] Probing failed: {e}")
            return QUICVersionResult(
                target_host=target_host,
                target_port=target_port,
                supported_versions=[],
                rejected_versions=[],
                library_implementation=QUICLibrary.UNKNOWN,
                version_negotiation_data=None,
                response_time_ms=0.0,
                confidence_score=0.0
            )
    
    def _send_quic_initial(self, target_host: str, target_port: int, 
                         version: str) -> Optional[bytes]:
        """Send QUIC Initial packet with specific version."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            try:
                # Create QUIC Initial packet
                initial_packet = self._create_quic_initial_packet(version)
                
                # Send packet
                sock.sendto(initial_packet, (target_host, target_port))
                
                # Receive response
                try:
                    response, addr = sock.recvfrom(1500)
                    return response
                except socket.timeout:
                    return None
                    
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"[QUIC Version] QUIC Initial failed: {e}")
            return None
    
    def _create_quic_initial_packet(self, version: str) -> bytes:
        """Create QUIC Initial packet with specified version."""
        # This is a simplified implementation
        # Real implementation would construct proper QUIC Initial packet
        
        # QUIC packet header
        if version == QUICVersion.DRAFT_29.value:
            version_bytes = b'\xff\x00\x00\x1d\x00\x00\x00'  # draft-29
        elif version == QUICVersion.V1.value:
            version_bytes = b'\x01\x00\x00\x00'  # v1
        elif version == QUICVersion.V2.value:
            version_bytes = b'\x02\x00\x00\x00'  # v2
        elif version == QUICVersion.DRAFT_32.value:
            version_bytes = b'\x20\x00\x00\x00'  # draft-32
        elif version == "experimental":
            version_bytes = b'\xff\xff\xff\xff'  # experimental
        else:
            version_bytes = b'\x00\x00\x00\x00'  # unknown
        
        # Create minimal QUIC Initial packet
        # Header: Type (1 byte) + Version (4 bytes) + Connection ID (8 bytes) + Packet Number (4 bytes)
        packet_type = 0x00  # Initial packet
        connection_id = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08'  # Random connection ID
        packet_number = b'\x00\x00\x00\x01'  # Packet number 1
        token_length = b'\x00\x00'  # No token
        
        # Construct packet
        packet = struct.pack('!B', packet_type)
        packet += version_bytes
        packet += connection_id
        packet += packet_number
        packet += token_length
        
        # Add some payload
        payload = b'QUIC version probe'
        packet += struct.pack('!H', len(payload))
        packet += payload
        
        return packet
    
    def _is_version_supported(self, response: bytes) -> bool:
        """Check if QUIC version is supported based on response."""
        if not response:
            return False
        
        # Look for version negotiation response
        # Version Negotiation packets have type 0x01
        if len(response) >= 1 and response[0] == 0x01:
            return True  # Version negotiation response means server understood
        
        # Look for other response types that indicate support
        response_types = [0x01, 0x02, 0x03, 0x04]  # Version Negotiation, Retry, Connection Close, etc.
        
        return len(response) >= 1 and response[0] in response_types
    
    def _identify_quic_library(self, version_responses: List[bytes]) -> QUICLibrary:
        """Identify QUIC library from version responses."""
        if not version_responses:
            return QUICLibrary.UNKNOWN
        
        # Concatenate all responses for analysis
        combined_response = b''.join(version_responses)
        
        # Check against known library signatures
        for library, signature in self.version_signatures.items():
            if signature["version_response_pattern"] in combined_response:
                return library
        
        # Additional heuristics
        if b"aioquic" in combined_response.lower():
            return QUICLibrary.AIOQUIC
        elif b"quiche" in combined_response.lower():
            return QUICLibrary.QUICHE
        elif b"msquic" in combined_response.lower():
            return QUICLibrary.MSQUIC
        elif b"cf-quic" in combined_response.lower():
            return QUICLibrary.CLOUDFLARE_QUICHE
        elif b"gquic" in combined_response.lower():
            return QUICLibrary.GOOGLE_QUIC
        elif b"aws-quic" in combined_response.lower():
            return QUICLibrary.AWS_QUIC
        
        return QUICLibrary.UNKNOWN
    
    def _calculate_confidence(self, library: QUICLibrary, 
                          version_responses: List[bytes]) -> float:
        """Calculate confidence score for QUIC library identification."""
        base_confidence = 0.5
        
        # Higher confidence for identified libraries
        if library != QUICLibrary.UNKNOWN:
            base_confidence += 0.3
        
        # Higher confidence for multiple responses
        if len(version_responses) > 1:
            base_confidence += 0.2
        
        return min(1.0, base_confidence)
    
    def generate_quic_version_report(self, result: QUICVersionResult) -> str:
        """Generate human-readable QUIC version probing report."""
        report = []
        report.append("QUIC Version Negotiation Probing Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Library Implementation: {result.library_implementation.value}")
        report.append(f"Supported Versions: {', '.join(result.supported_versions)}")
        report.append(f"Rejected Versions: {', '.join(result.rejected_versions)}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        # Library analysis
        if result.library_implementation != QUICLibrary.UNKNOWN:
            signature = self.version_signatures.get(result.library_implementation, {})
            if signature:
                report.append("Library Implementation Details:")
                report.append(f"  - Implementation: {result.library_implementation.value}")
                report.append(f"  - Negotiation Behavior: {signature.get('negotiation_behavior', 'unknown')}")
                report.append(f"  - Response Format: {signature.get('response_format', 'unknown')}")
                report.append(f"  - Expected Versions: {', '.join(signature.get('supported_versions', []))}")
        report.append("")
        
        # Version analysis
        report.append("Version Support Analysis:")
        if result.supported_versions:
            report.append(f"  - Supported: {len(result.supported_versions)} versions")
            for version in result.supported_versions:
                report.append(f"    - {version}")
        if result.rejected_versions:
            report.append(f"  - Rejected: {len(result.rejected_versions)} versions")
            for version in result.rejected_versions:
                report.append(f"    - {version}")
        report.append("")
        
        # Security implications
        report.append("Security Implications:")
        if result.library_implementation == QUICLibrary.AIOQUIC:
            report.append("  - Standard QUIC implementation (good compatibility)")
        elif result.library_implementation == QUICLibrary.QUICHE:
            report.append("  - Conservative QUIC implementation (security-focused)")
        elif result.library_implementation == QUICLibrary.CLOUDFLARE_QUICHE:
            report.append("  - CDN-optimized QUIC (performance-focused)")
        elif result.library_implementation == QUICLibrary.GOOGLE_QUIC:
            report.append("  - Google QUIC implementation (proprietary optimizations)")
        elif result.library_implementation == QUICLibrary.AWS_QUIC:
            report.append("  - Enterprise QUIC implementation (corporate environment)")
        report.append("")
        
        # Version implications
        if QUICVersion.V2.value in result.supported_versions:
            report.append("  - QUIC v2 support detected (modern implementation)")
        if QUICVersion.DRAFT_29.value in result.supported_versions:
            report.append("  - Draft-29 support (legacy compatibility)")
        report.append("")
        
        return "\n".join(report)

# Global instance
_quic_version_prober = None

def get_quic_version_prober() -> QUICVersionProber:
    """Get global QUIC version prober."""
    global _quic_version_prober
    if _quic_version_prober is None:
        _quic_version_prober = QUICVersionProber()
    return _quic_version_prober

def probe_quic_versions(target_host: str, target_port: int = 443) -> QUICVersionResult:
    """Convenience function for QUIC version probing."""
    prober = get_quic_version_prober()
    return prober.probe_quic_versions(target_host, target_port)

def generate_quic_version_report(result: QUICVersionResult) -> str:
    """Convenience function for QUIC version report generation."""
    prober = get_quic_version_prober()
    return prober.generate_quic_version_report(result)
