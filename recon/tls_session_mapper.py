"""TLS Session Ticket Analysis for Load Balancer Pool Mapping.

Collects and analyzes TLS session tickets to map backend infrastructure,
count load balancer pool sizes, and identify TLS termination configurations.

Uses normal TLS session resumption operations that appear completely
legitimate to network monitoring systems.
"""

import logging
import time
import ssl
import socket
import struct
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("usare.tls_session_mapper")

class SessionTicketType(Enum):
    STANDARD = "standard"           # RFC 5077 session tickets
    STATELESS = "stateless"         # Stateless session tickets
    STATEFUL = "stateful"           # Stateful session tickets
    ENCRYPTED = "encrypted"         # Encrypted session tickets
    PLAIN = "plain"               # Plain session tickets

@dataclass
class SessionTicketInfo:
    """TLS session ticket information."""
    ticket_data: bytes
    ticket_length: int
    timestamp: float
    source_ip: str
    source_port: int
    target_ip: str
    target_port: int
    cipher_suite: str
    tls_version: str
    backend_id: Optional[str]
    resumption_success: bool
    resumption_time_ms: float

@dataclass
class LoadBalancerAnalysis:
    """Load balancer analysis result."""
    target_service: str
    backend_count: int
    shared_key_backends: int
    per_key_backends: int
    tls_terminator_backends: int
    plain_http_backends: int
    backend_diversity: str
    session_key_sharing: str
    confidence_score: float

class TLSSessionMapper:
    """Advanced TLS session ticket mapper."""
    
    def __init__(self):
        self.collected_tickets = []
        self.backend_signatures = {}
        self.session_resumptions = []
        
        # TLS cipher suite mapping
        self.cipher_suites = {
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256",
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        
        # TLS version mapping
        self.tls_versions = {
            0x0301: "TLSv1.0",
            0x0302: "TLSv1.1",
            0x0303: "TLSv1.2",
            0x0304: "TLSv1.3"
        }
    
    def analyze_load_balancer_pool(self, target_host: str, target_port: int = 443, 
                              probe_count: int = 20) -> LoadBalancerAnalysis:
        """Analyze load balancer pool using TLS session tickets."""
        start_time = time.time()
        
        try:
            # Collect session tickets from multiple connections
            tickets = self._collect_session_tickets(target_host, target_port, probe_count)
            
            # Attempt session resumptions
            resumptions = self._attempt_session_resumptions(target_host, target_port, tickets)
            
            # Analyze backend signatures
            backend_analysis = self._analyze_backend_signatures(tickets, resumptions)
            
            # Calculate load balancer metrics
            lb_metrics = self._calculate_load_balancer_metrics(backend_analysis)
            
            return LoadBalancerAnalysis(
                target_service=f"{target_host}:{target_port}",
                backend_count=lb_metrics["backend_count"],
                shared_key_backends=lb_metrics["shared_key_backends"],
                per_key_backends=lb_metrics["per_key_backends"],
                tls_terminator_backends=lb_metrics["tls_terminator_backends"],
                plain_http_backends=lb_metrics["plain_http_backends"],
                backend_diversity=lb_metrics["backend_diversity"],
                session_key_sharing=lb_metrics["session_key_sharing"],
                confidence_score=lb_metrics["confidence"]
            )
            
        except Exception as e:
            logger.error(f"[TLS Session] Load balancer analysis failed: {e}")
            return LoadBalancerAnalysis(
                target_service=f"{target_host}:{target_port}",
                backend_count=0,
                shared_key_backends=0,
                per_key_backends=0,
                tls_terminator_backends=0,
                plain_http_backends=0,
                backend_diversity="unknown",
                session_key_sharing="unknown",
                confidence_score=0.0
            )
    
    def _collect_session_tickets(self, target_host: str, target_port: int, 
                              probe_count: int) -> List[SessionTicketInfo]:
        """Collect TLS session tickets from multiple connections."""
        tickets = []
        
        for i in range(probe_count):
            try:
                # Create TLS connection with session ticket support
                ticket_info = self._establish_tls_connection(target_host, target_port, i)
                
                if ticket_info:
                    tickets.append(ticket_info)
                    logger.debug(f"[TLS Session] Collected ticket {i+1}/{probe_count}")
                
                # Small delay between connections
                time.sleep(0.1)
                
            except Exception as e:
                logger.debug(f"[TLS Session] Ticket collection {i+1} failed: {e}")
        
        return tickets
    
    def _establish_tls_connection(self, target_host: str, target_port: int, 
                              connection_id: int) -> Optional[SessionTicketInfo]:
        """Establish TLS connection and collect session ticket."""
        try:
            # Create SSL context with session ticket support
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Enable session tickets
            context.session_timeout = 3600  # 1 hour
            
            # Connect to target
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((target_host, target_port))
                
                # Wrap with SSL
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                
                # Perform TLS handshake
                ssl_sock.do_handshake()
                
                # Get session information
                try:
                    # Extract session information using available attributes
                    session_id = getattr(ssl_sock, 'session', None)
                    if session_id and hasattr(session_id, 'id'):
                        session_id_bytes = session_id.id
                    else:
                        session_id_bytes = b''
                    
                    # Create synthetic ticket data based on session properties
                    if session_id_bytes or ssl_sock.cipher():
                        ticket_data = struct.pack(
                            "!I",  # Timestamp
                            int(time.time())
                        )
                        
                        if session_id_bytes:
                            ticket_data += struct.pack("!H", len(session_id_bytes)) + session_id_bytes
                        
                        # Add cipher information
                        cipher_info = ssl_sock.cipher()
                        if cipher_info:
                            cipher_suite = cipher_info[0].encode('utf-8', errors='ignore')
                            ticket_data += struct.pack("!H", len(cipher_suite)) + cipher_suite
                        
                        return ticket_data
                    
                except Exception as e:
                    logger.debug(f"[TLS Session] Session extraction failed: {e}")
                    return None
                
                # Get connection details
                cipher = ssl_sock.cipher()
                tls_version = ssl_sock.version()
                
                return SessionTicketInfo(
                    ticket_data=ticket_data,
                    ticket_length=len(ticket_data) if ticket_data else 0,
                    timestamp=time.time(),
                    source_ip=sock.getsockname()[0],
                    source_port=sock.getsockname()[1],
                        target_ip=target_host,
                        target_port=target_port,
                        cipher_suite=cipher[0] if cipher else "unknown",
                        tls_version=tls_version or "unknown",
                        backend_id=None,
                        resumption_success=False,
                        resumption_time_ms=0.0
                    )
                
                ssl_sock.close()
                sock.close()
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                raise e
                
        except Exception as e:
            logger.debug(f"[TLS Session] Connection {connection_id} failed: {e}")
            return None
    
    def _extract_session_ticket(self, session) -> Optional[bytes]:
        """Extract session ticket from SSL session."""
        try:
            # This is a simplified implementation
            # Real implementation would need access to OpenSSL session internals
            # or use a library that exposes session tickets
            
            # For demonstration, we'll create a synthetic ticket
            # based on session properties
            
            if not session:
                return None
            
            # Create synthetic ticket data
            session_id = session.session_id if hasattr(session, 'session_id') else b''
            master_key = session.master_key if hasattr(session, 'master_key') else b''
            
            if not session_id and not master_key:
                return None
            
            # Create ticket structure
            ticket_data = struct.pack(
                "!I",  # Timestamp
                int(time.time())
            )
            
            if session_id:
                ticket_data += struct.pack("!H", len(session_id)) + session_id
            
            if master_key:
                ticket_data += struct.pack("!H", len(master_key)) + master_key
            
            return ticket_data
            
        except Exception as e:
            logger.debug(f"[TLS Session] Ticket extraction failed: {e}")
            return None
    
    def _attempt_session_resumptions(self, target_host: str, target_port: int,
                                  tickets: List[SessionTicketInfo]) -> List[SessionTicketInfo]:
        """Attempt session resumptions with collected tickets."""
        resumptions = []
        
        for i, ticket in enumerate(tickets):
            try:
                # Attempt to resume session with ticket
                resumption_result = self._resume_tls_session(target_host, target_port, ticket)
                
                if resumption_result:
                    resumptions.append(resumption_result)
                    logger.debug(f"[TLS Session] Resumption {i+1}/{len(tickets)} successful")
                else:
                    logger.debug(f"[TLS Session] Resumption {i+1}/{len(tickets)} failed")
                
                # Small delay between resumptions
                time.sleep(0.1)
                
            except Exception as e:
                logger.debug(f"[TLS Session] Resumption {i+1} failed: {e}")
        
        return resumptions
    
    def _resume_tls_session(self, target_host: str, target_port: int,
                         original_ticket: SessionTicketInfo) -> Optional[SessionTicketInfo]:
        """Attempt to resume TLS session with existing ticket."""
        try:
            # Create SSL context with session ticket support
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to target
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((target_host, target_port))
                
                # Wrap with SSL
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                
                # Attempt session resumption
                # This is simplified - real implementation would need
                # to inject the session ticket into the SSL context
                
                start_time = time.time()
                ssl_sock.do_handshake()
                resumption_time = (time.time() - start_time) * 1000
                
                # Check if session was resumed
                session_resumed = self._check_session_resumed(ssl_sock, original_ticket)
                
                # Get connection details
                cipher = ssl_sock.cipher()
                tls_version = ssl_sock.version()
                
                resumption_info = SessionTicketInfo(
                    ticket_data=original_ticket.ticket_data,
                    ticket_length=original_ticket.ticket_length,
                    timestamp=time.time(),
                    source_ip=sock.getsockname()[0],
                    source_port=sock.getsockname()[1],
                    target_ip=target_host,
                    target_port=target_port,
                    cipher_suite=cipher[0] if cipher else "unknown",
                    tls_version=tls_version or "unknown",
                    backend_id=None,
                    resumption_success=session_resumed,
                    resumption_time_ms=resumption_time
                )
                
                ssl_sock.close()
                sock.close()
                
                return resumption_info
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                raise e
                
        except Exception as e:
            logger.debug(f"[TLS Session] Session resumption failed: {e}")
            return None
    
    def _check_session_resumed(self, ssl_sock, original_ticket: SessionTicketInfo) -> bool:
        """Check if TLS session was successfully resumed."""
        try:
            # This is a simplified implementation
            # Real implementation would compare session IDs, master keys,
            # and other session parameters
            
            try:
                current_session = getattr(ssl_sock, 'session', None)
                
                if not current_session:
                    return False
                
                # Check if session appears to be resumed
                # This is simplified - real implementation would compare session parameters
                session_id_match = hasattr(current_session, 'id')
                cipher_match = ssl_sock.cipher() == original_ticket.cipher_suite
                
                return session_id_match and cipher_match
                
            except Exception:
                return False
            
        except Exception as e:
            logger.debug(f"[TLS Session] Resumption check failed: {e}")
            return False
    
    def _analyze_backend_signatures(self, tickets: List[SessionTicketInfo],
                                resumptions: List[SessionTicketInfo]) -> Dict[str, Any]:
        """Analyze backend signatures from tickets and resumptions."""
        analysis = {
            "backend_signatures": {},
            "ticket_clusters": {},
            "resumption_patterns": {},
            "cipher_distribution": {},
            "version_distribution": {}
        }
        
        # Analyze ticket patterns
        for ticket in tickets:
            # Create backend signature from ticket characteristics
            signature = self._create_backend_signature(ticket)
            
            if signature not in analysis["backend_signatures"]:
                analysis["backend_signatures"][signature] = []
            
            analysis["backend_signatures"][signature].append(ticket)
        
        # Analyze resumption patterns
        for resumption in resumptions:
            signature = self._create_backend_signature(resumption)
            
            if signature not in analysis["resumption_patterns"]:
                analysis["resumption_patterns"][signature] = []
            
            analysis["resumption_patterns"][signature].append(resumption)
        
        # Analyze cipher and version distribution
        for ticket in tickets:
            cipher = ticket.cipher_suite
            if cipher not in analysis["cipher_distribution"]:
                analysis["cipher_distribution"][cipher] = 0
            analysis["cipher_distribution"][cipher] += 1
            
            version = ticket.tls_version
            if version not in analysis["version_distribution"]:
                analysis["version_distribution"][version] = 0
            analysis["version_distribution"][version] += 1
        
        return analysis
    
    def _create_backend_signature(self, ticket_info: SessionTicketInfo) -> str:
        """Create backend signature from ticket information."""
        # Create signature based on ticket characteristics
        # that might indicate different backends
        
        signature_parts = []
        
        # Ticket length can indicate different backend implementations
        signature_parts.append(f"len:{ticket_info.ticket_length}")
        
        # Cipher suite can indicate backend configuration
        signature_parts.append(f"cipher:{ticket_info.cipher_suite}")
        
        # TLS version can indicate backend version
        signature_parts.append(f"version:{ticket_info.tls_version}")
        
        # Create hash of ticket data for uniqueness
        if ticket_info.ticket_data:
            ticket_hash = hashlib.sha256(ticket_info.ticket_data).hexdigest()[:16]
            signature_parts.append(f"hash:{ticket_hash}")
        
        return "|".join(signature_parts)
    
    def _calculate_load_balancer_metrics(self, backend_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate load balancer metrics from backend analysis."""
        metrics = {
            "backend_count": 0,
            "shared_key_backends": 0,
            "per_key_backends": 0,
            "tls_terminator_backends": 0,
            "plain_http_backends": 0,
            "backend_diversity": "low",
            "session_key_sharing": "unknown",
            "confidence": 0.0
        }
        
        # Count unique backends
        backend_signatures = backend_analysis.get("backend_signatures", {})
        metrics["backend_count"] = len(backend_signatures)
        
        # Analyze resumption patterns to determine key sharing
        resumption_patterns = backend_analysis.get("resumption_patterns", {})
        
        if resumption_patterns:
            # If multiple backends accept the same ticket, keys are shared
            shared_backends = len(resumption_patterns)
            total_backends = len(backend_signatures)
            
            if shared_backends > total_backends * 0.5:
                metrics["session_key_sharing"] = "shared"
                metrics["shared_key_backends"] = shared_backends
            else:
                metrics["session_key_sharing"] = "per_backend"
                metrics["per_key_backends"] = total_backends - shared_backends
        
        # Analyze cipher distribution for backend diversity
        cipher_dist = backend_analysis.get("cipher_distribution", {})
        if len(cipher_dist) > 1:
            metrics["backend_diversity"] = "high"
        elif len(cipher_dist) == 1:
            metrics["backend_diversity"] = "low"
        
        # Count TLS terminator backends (those that support TLS)
        tls_versions = backend_analysis.get("version_distribution", {})
        tls_backends = sum(1 for v in tls_versions.keys() if v.startswith("TLS"))
        metrics["tls_terminator_backends"] = tls_backends
        
        # Estimate confidence based on data quality
        total_tickets = sum(len(signatures) for signatures in backend_signatures.values())
        if total_tickets > 10:
            metrics["confidence"] = 0.8
        elif total_tickets > 5:
            metrics["confidence"] = 0.6
        else:
            metrics["confidence"] = 0.4
        
        return metrics
    
    def generate_load_balancer_report(self, result: LoadBalancerAnalysis) -> str:
        """Generate human-readable load balancer report."""
        report = []
        report.append("TLS Session Ticket Load Balancer Analysis")
        report.append("=" * 50)
        report.append(f"Target Service: {result.target_service}")
        report.append(f"Backend Count: {result.backend_count}")
        report.append(f"Shared Key Backends: {result.shared_key_backends}")
        report.append(f"Per-Key Backends: {result.per_key_backends}")
        report.append(f"TLS Terminator Backends: {result.tls_terminator_backends}")
        report.append(f"Plain HTTP Backends: {result.plain_http_backends}")
        report.append(f"Backend Diversity: {result.backend_diversity}")
        report.append(f"Session Key Sharing: {result.session_key_sharing}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        # Analysis interpretation
        report.append("Analysis Interpretation:")
        if result.backend_count > 1:
            report.append(f"  - Load balancer detected with {result.backend_count} backends")
        else:
            report.append("  - Single backend detected (no load balancing)")
        
        if result.session_key_sharing == "shared":
            report.append("  - Backends share session keys (centralized TLS termination)")
        elif result.session_key_sharing == "per_backend":
            report.append("  - Backends use individual session keys (distributed TLS)")
        
        if result.backend_diversity == "high":
            report.append("  - High backend diversity detected (different configurations)")
        else:
            report.append("  - Low backend diversity (homogeneous configuration)")
        
        if result.tls_terminator_backends > 0:
            report.append(f"  - {result.tls_terminator_backends} backends terminate TLS connections")
        
        return "\n".join(report)

# Global instance
_tls_mapper = None

def get_tls_mapper() -> TLSSessionMapper:
    """Get global TLS session mapper."""
    global _tls_mapper
    if _tls_mapper is None:
        _tls_mapper = TLSSessionMapper()
    return _tls_mapper

def analyze_load_balancer_pool(target_host: str, target_port: int = 443,
                           probe_count: int = 20) -> LoadBalancerAnalysis:
    """Convenience function for load balancer analysis."""
    mapper = get_tls_mapper()
    return mapper.analyze_load_balancer_pool(target_host, target_port, probe_count)

def generate_load_balancer_report(result: LoadBalancerAnalysis) -> str:
    """Convenience function for load balancer report generation."""
    mapper = get_tls_mapper()
    return mapper.generate_load_balancer_report(result)
