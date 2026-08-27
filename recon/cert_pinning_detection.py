"""TLS Certificate Pinning Detection for Security Maturity Assessment.

Detects certificate pinning behavior by sending multiple TLS connections
with different client certificates and observing server rejection patterns.

Pinning behavior reveals whether target uses mobile app backends,
API gateways, or standard web infrastructure.
"""

import logging
import time
import ssl
import socket
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("usare.cert_pinning")

class PinningBehavior(Enum):
    NO_PINNING = "no_pinning"
    PUBLIC_CA_PINNING = "public_ca_pinning"
    PRIVATE_CA_PINNING = "private_ca_pinning"
    CERTIFICATE_PINNING = "certificate_pinning"
    STRICT_PINNING = "strict_pinning"
    KEY_PINNING = "key_pinning"

@dataclass
class CertificatePinningResult:
    """Certificate pinning analysis result."""
    target_host: str
    target_port: int
    pinning_behavior: PinningBehavior
    security_maturity: str
    backend_type: str
    certificate_chain: List[Dict[str, Any]]
    pinning_indicators: List[str]
    confidence_score: float

class CertificatePinningDetector:
    """Advanced certificate pinning detector."""
    
    def __init__(self):
        self.timeout = 10.0
        
        # Pinning behavior patterns
        self.pinning_patterns = {
            PinningBehavior.NO_PINNING: {
                "indicators": ["accepts_any_cert", "no_pinning_headers"],
                "certificate_types": ["public_ca"],
                "security_level": "low"
            },
            PinningBehavior.PUBLIC_CA_PINNING: {
                "indicators": ["ca_restriction", "trusted_ca_only"],
                "certificate_types": ["public_ca"],
                "security_level": "medium"
            },
            PinningBehavior.PRIVATE_CA_PINNING: {
                "indicators": ["private_ca", "enterprise_ca"],
                "certificate_types": ["private_ca"],
                "security_level": "high"
            },
            PinningBehavior.CERTIFICATE_PINNING: {
                "indicators": ["certificate_hash_pinning", "static_certificate"],
                "certificate_types": ["pinned"],
                "security_level": "high"
            },
            PinningBehavior.STRICT_PINNING: {
                "indicators": ["strict_validation", "rejection_on_change"],
                "certificate_types": ["strictly_pinned"],
                "security_level": "very_high"
            },
            PinningBehavior.KEY_PINNING: {
                "indicators": ["public_key_pinning", "spki_pinning"],
                "certificate_types": ["key_pinned"],
                "security_level": "very_high"
            }
        }
    
    def detect_certificate_pinning(self, target_host: str, target_port: int = 443) -> CertificatePinningResult:
        """Detect certificate pinning behavior."""
        start_time = time.time()
        
        try:
            # Collect certificate information with different client scenarios
            cert_chain = self._get_certificate_chain(target_host, target_port)
            
            if not cert_chain:
                return CertificatePinningResult(
                    target_host=target_host,
                    target_port=target_port,
                    pinning_behavior=PinningBehavior.NO_PINNING,
                    security_maturity="unknown",
                    backend_type="unknown",
                    certificate_chain=[],
                    pinning_indicators=["no_certificate"],
                    confidence_score=0.0
                )
            
            # Analyze pinning behavior
            pinning_behavior = self._analyze_pinning_behavior(cert_chain)
            security_maturity = self._assess_security_maturity(pinning_behavior)
            backend_type = self._identify_backend_type(pinning_behavior, cert_chain)
            pinning_indicators = self._extract_pinning_indicators(cert_chain)
            
            response_time = (time.time() - start_time) * 1000
            
            # Calculate confidence
            confidence = self._calculate_confidence(pinning_behavior, cert_chain)
            
            return CertificatePinningResult(
                target_host=target_host,
                target_port=target_port,
                pinning_behavior=pinning_behavior,
                security_maturity=security_maturity,
                backend_type=backend_type,
                certificate_chain=cert_chain,
                pinning_indicators=pinning_indicators,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[Cert Pinning] Detection failed: {e}")
            return CertificatePinningResult(
                target_host=target_host,
                target_port=target_port,
                pinning_behavior=PinningBehavior.NO_PINNING,
                security_maturity="unknown",
                backend_type="unknown",
                certificate_chain=[],
                pinning_indicators=[f"analysis_failed: {e}"],
                confidence_score=0.0
            )
    
    def _get_certificate_chain(self, target_host: str, target_port: int) -> List[Dict[str, Any]]:
        """Get certificate chain with multiple connection attempts."""
        cert_chain = []
        
        # Test with different client certificate scenarios
        test_scenarios = [
            ("no_client_cert", None),
            ("self_signed_cert", self._generate_self_signed_cert()),
            ("different_ca_cert", self._generate_different_ca_cert()),
            ("expired_cert", self._generate_expired_cert()),
            ("wrong_hostname", self._generate_wrong_hostname_cert())
        ]
        
        for scenario_name, client_cert in test_scenarios:
            try:
                cert_info = self._get_certificate_info(target_host, target_port, client_cert)
                if cert_info:
                    cert_info["scenario"] = scenario_name
                    cert_chain.append(cert_info)
                    
            except Exception as e:
                logger.debug(f"[Cert Pinning] Scenario {scenario_name} failed: {e}")
                cert_chain.append({
                    "scenario": scenario_name,
                    "error": str(e),
                    "success": False
                })
        
        return cert_chain
    
    def _get_certificate_info(self, target_host: str, target_port: int, 
                          client_cert: Optional[ssl.SSLContext]) -> Optional[Dict[str, Any]]:
        """Get certificate information for specific scenario."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Use client certificate if provided
            if client_cert:
                context.load_cert_chain(client_cert)
            
            # Connect and get certificate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, target_port))
                
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                # Get certificate information
                cert = ssl_sock.getpeercert()
                der_cert = ssl_sock.getpeercert(binary_form=True)
                
                if cert:
                    cert_info = {
                        "success": True,
                        "certificate": cert,
                        "der_certificate": der_cert,
                        "subject": self._extract_subject(cert),
                        "issuer": self._extract_issuer(cert),
                        "validity": self._extract_validity(cert),
                        "signature_algorithm": self._extract_signature_algorithm(cert),
                        "public_key_info": self._extract_public_key_info(cert),
                        "extensions": self._extract_extensions(cert),
                        "fingerprint": self._calculate_certificate_fingerprint(der_cert),
                        "is_self_signed": self._is_self_signed(cert),
                        "is_public_ca": self._is_public_ca(cert),
                        "is_private_ca": self._is_private_ca(cert)
                    }
                    
                    return cert_info
                
                ssl_sock.close()
                sock.close()
                return None
                
            except ssl.SSLCertVerificationError as e:
                return {
                    "success": False,
                    "verification_error": str(e),
                    "error_type": "certificate_verification"
                }
            except ssl.SSLError as e:
                return {
                    "success": False,
                    "ssl_error": str(e),
                    "error_type": "ssl_error"
                }
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                return {
                    "success": False,
                    "error": str(e),
                    "error_type": "connection_error"
                }
                
        except Exception as e:
            logger.debug(f"[Cert Pinning] Certificate info extraction failed: {e}")
            return None
    
    def _generate_self_signed_cert(self) -> ssl.SSLContext:
        """Generate self-signed certificate for testing."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID
        import datetime
        
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create self-signed certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                subject
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("test.example.com")
                ])
            ).sign(private_key, hashes.SHA256())
            
            # Create SSL context
            context = ssl.create_default_context()
            context.load_cert_chain(cert, private_key)
            
            return context
            
        except ImportError:
            # Fallback if cryptography not available
            return None
    
    def _generate_different_ca_cert(self) -> ssl.SSLContext:
        """Generate certificate from different CA for testing."""
        # This is a simplified implementation
        # Real implementation would use a different CA than expected
        return self._generate_self_signed_cert()
    
    def _generate_expired_cert(self) -> ssl.SSLContext:
        """Generate expired certificate for testing."""
        try:
            cert = self._generate_self_signed_cert()
            if cert:
                # Modify the certificate to be expired
                # This would require more complex certificate manipulation
                pass
            return cert
        except:
            return None
    
    def _generate_wrong_hostname_cert(self) -> ssl.SSLContext:
        """Generate certificate with wrong hostname for testing."""
        return self._generate_self_signed_cert()
    
    def _extract_subject(self, cert: dict) -> Dict[str, str]:
        """Extract subject information from certificate."""
        subject = {}
        for rdn in cert.get("subject", []):
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                field, value = rdn[0], rdn[1]
                if field == "commonName":
                    subject["cn"] = value if isinstance(value, str) else str(value)
        return subject
    
    def _extract_issuer(self, cert: dict) -> Dict[str, str]:
        """Extract issuer information from certificate."""
        issuer = {}
        for rdn in cert.get("issuer", []):
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                field, value = rdn[0], rdn[1]
                if field == "organizationName":
                    issuer["organization"] = value if isinstance(value, str) else str(value)
                elif field == "commonName":
                    issuer["cn"] = value if isinstance(value, str) else str(value)
        return issuer
    
    def _extract_validity(self, cert: dict) -> Dict[str, str]:
        """Extract validity period from certificate."""
        validity = {}
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        
        if not_before:
            validity["not_before"] = str(not_before)
        if not_after:
            validity["not_after"] = str(not_after)
            
        return validity
    
    def _extract_signature_algorithm(self, cert: dict) -> str:
        """Extract signature algorithm from certificate."""
        # This is simplified - real implementation would parse the signature algorithm
        return cert.get("signatureAlgorithm", "unknown")
    
    def _extract_public_key_info(self, cert: dict) -> Dict[str, str]:
        """Extract public key information from certificate."""
        pub_key = cert.get("subjectPublicKeyInfo", {})
        return {
            "algorithm": pub_key.get("algorithm", "unknown"),
            "key_size": str(pub_key.get("bits", "unknown"))
        }
    
    def _extract_extensions(self, cert: dict) -> Dict[str, Any]:
        """Extract extensions from certificate."""
        extensions = {}
        
        # Look for common extensions
        for ext in cert.get("extensions", []):
            if isinstance(ext, tuple) and len(ext) >= 2:
                ext_name, ext_value = ext[0], ext[1]
                extensions[str(ext_name)] = ext_value
        
        return extensions
    
    def _calculate_certificate_fingerprint(self, der_cert: bytes) -> str:
        """Calculate certificate fingerprint."""
        return hashlib.sha256(der_cert).hexdigest()
    
    def _is_self_signed(self, cert: dict) -> bool:
        """Check if certificate is self-signed."""
        issuer = cert.get("issuer", [])
        subject = cert.get("subject", [])
        return issuer == subject
    
    def _is_public_ca(self, cert: dict) -> bool:
        """Check if certificate is from public CA."""
        # This is simplified - real implementation would check against known CA lists
        issuer = cert.get("issuer", [])
        for rdn in issuer:
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                field, value = rdn[0], rdn[1]
                if field == "organizationName":
                    # Check against known public CA organizations
                    public_ca_orgs = [
                        "DigiCert", "GlobalSign", "Comodo", "Let's Encrypt",
                        "Sectigo", "GoDaddy", "Network Solutions",
                        "Entrust", "GeoTrust", "Thawte"
                    ]
                    if any(ca in str(value) for ca in public_ca_orgs):
                        return True
        return False
    
    def _is_private_ca(self, cert: dict) -> bool:
        """Check if certificate is from private CA."""
        # This is simplified - real implementation would check against known private CA patterns
        return not self._is_public_ca(cert) and not self._is_self_signed(cert)
    
    def _analyze_pinning_behavior(self, cert_chain: List[Dict[str, Any]]) -> PinningBehavior:
        """Analyze certificate pinning behavior from certificate chain."""
        if not cert_chain:
            return PinningBehavior.NO_PINNING
        
        # Count successful vs failed connections
        successful_certs = [c for c in cert_chain if c.get("success", False)]
        failed_certs = [c for c in cert_chain if not c.get("success", False)]
        
        # Analyze failure patterns
        verification_errors = [c for c in failed_certs if c.get("error_type") == "certificate_verification"]
        ssl_errors = [c for c in failed_certs if c.get("error_type") == "ssl_error"]
        
        if verification_errors:
            # Certificate verification failures indicate pinning
            error_messages = [c.get("verification_error", "") for c in verification_errors]
            
            if any("certificate verify failed" in msg.lower() for msg in error_messages):
                return PinningBehavior.CERTIFICATE_PINNING
            elif any("self signed certificate" in msg.lower() for msg in error_messages):
                return PinningBehavior.PRIVATE_CA_PINNING
            else:
                return PinningBehavior.STRICT_PINNING
        
        elif ssl_errors:
            # SSL errors without certificate verification might indicate key pinning
            return PinningBehavior.KEY_PINNING
        
        elif len(successful_certs) > 0:
            # Some connections successful - check certificate types
            cert_types = []
            for cert in successful_certs:
                if cert.get("is_public_ca", False):
                    cert_types.append("public_ca")
                elif cert.get("is_private_ca", False):
                    cert_types.append("private_ca")
                elif cert.get("is_self_signed", False):
                    cert_types.append("self_signed")
            
            if "private_ca" in cert_types:
                return PinningBehavior.PRIVATE_CA_PINNING
            elif all(ct == "public_ca" for ct in cert_types):
                return PinningBehavior.PUBLIC_CA_PINNING
        
        return PinningBehavior.NO_PINNING
    
    def _assess_security_maturity(self, pinning_behavior: PinningBehavior) -> str:
        """Assess security maturity based on pinning behavior."""
        maturity_mapping = {
            PinningBehavior.NO_PINNING: "low",
            PinningBehavior.PUBLIC_CA_PINNING: "medium",
            PinningBehavior.PRIVATE_CA_PINNING: "high",
            PinningBehavior.CERTIFICATE_PINNING: "high",
            PinningBehavior.STRICT_PINNING: "very_high",
            PinningBehavior.KEY_PINNING: "very_high"
        }
        
        return maturity_mapping.get(pinning_behavior, "unknown")
    
    def _identify_backend_type(self, pinning_behavior: PinningBehavior, 
                           cert_chain: List[Dict[str, Any]]) -> str:
        """Identify backend type based on pinning behavior."""
        if pinning_behavior in [PinningBehavior.CERTIFICATE_PINNING, PinningBehavior.STRICT_PINNING]:
            return "mobile_app"
        elif pinning_behavior == PinningBehavior.PRIVATE_CA_PINNING:
            return "api_gateway"
        elif pinning_behavior == PinningBehavior.NO_PINNING:
            # Check certificate patterns
            successful_certs = [c for c in cert_chain if c.get("success", False)]
            if successful_certs:
                cert = successful_certs[0].get("certificate", {})
                issuer = cert.get("issuer", {})
                
                # Check for cloud/load balancer indicators
                if any(indicator in str(issuer) for indicator in ["aws", "azure", "gcp", "cloudflare"]):
                    return "cloud_load_balancer"
                elif any(indicator in str(issuer) for indicator in ["akamai", "fastly", "cdn"]):
                    return "cdn"
                else:
                    return "standard_web"
        
        return "unknown"
    
    def _extract_pinning_indicators(self, cert_chain: List[Dict[str, Any]]) -> List[str]:
        """Extract pinning indicators from certificate chain."""
        indicators = []
        
        for cert in cert_chain:
            if cert.get("success", False):
                cert_info = cert.get("certificate", {})
                
                # Check for pinning-related indicators
                if cert_info.get("is_self_signed", False):
                    indicators.append("self_signed_certificate")
                
                if cert_info.get("is_private_ca", False):
                    indicators.append("private_ca_certificate")
                
                # Check for certificate pinning extensions
                extensions = cert_info.get("extensions", {})
                if extensions:
                    for ext_name, ext_value in extensions.items():
                        if "pinning" in str(ext_name).lower():
                            indicators.append(f"pinning_extension_{ext_name}")
        
        # Check for verification errors
        failed_certs = [c for c in cert_chain if not c.get("success", False)]
        for cert in failed_certs:
            error_type = cert.get("error_type", "")
            if error_type == "certificate_verification":
                indicators.append("certificate_verification_failure")
            elif error_type == "ssl_error":
                indicators.append("ssl_handshake_failure")
        
        return indicators
    
    def _calculate_confidence(self, pinning_behavior: PinningBehavior, 
                          cert_chain: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for pinning detection."""
        base_confidence = 0.5
        
        # Higher confidence for distinct pinning behaviors
        if pinning_behavior in [PinningBehavior.CERTIFICATE_PINNING, PinningBehavior.STRICT_PINNING]:
            base_confidence += 0.3
        
        # Higher confidence for successful certificate analysis
        successful_certs = [c for c in cert_chain if c.get("success", False)]
        if len(successful_certs) > 0:
            base_confidence += 0.2
        
        return min(1.0, base_confidence)
    
    def generate_pinning_report(self, result: CertificatePinningResult) -> str:
        """Generate human-readable certificate pinning report."""
        report = []
        report.append("Certificate Pinning Detection Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Pinning Behavior: {result.pinning_behavior.value}")
        report.append(f"Security Maturity: {result.security_maturity}")
        report.append(f"Backend Type: {result.backend_type}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        # Certificate chain analysis
        if result.certificate_chain:
            report.append("Certificate Chain Analysis:")
            for i, cert in enumerate(result.certificate_chain):
                if cert.get("success", False):
                    cert_info = cert.get("certificate", {})
                    subject = cert_info.get("subject", {})
                    issuer = cert_info.get("issuer", {})
                    
                    report.append(f"  Certificate {i+1}:")
                    report.append(f"    Subject CN: {subject.get('cn', 'unknown')}")
                    report.append(f"    Issuer: {issuer.get('organization', issuer.get('cn', 'unknown'))}")
                    report.append(f"    Self-signed: {cert_info.get('is_self_signed', False)}")
                    report.append(f"    Public CA: {cert_info.get('is_public_ca', False)}")
                    report.append(f"    Private CA: {cert_info.get('is_private_ca', False)}")
                else:
                    report.append(f"  Certificate {i+1}: Failed - {cert.get('error', 'unknown')}")
            report.append("")
        
        # Pinning indicators
        if result.pinning_indicators:
            report.append("Pinning Indicators:")
            for indicator in result.pinning_indicators:
                report.append(f"  - {indicator}")
            report.append("")
        
        # Security assessment
        report.append("Security Assessment:")
        if result.pinning_behavior == PinningBehavior.NO_PINNING:
            report.append("  - No certificate pinning detected")
            report.append("  - Standard web infrastructure likely")
        elif result.pinning_behavior == PinningBehavior.PUBLIC_CA_PINNING:
            report.append("  - Public CA restriction detected")
            report.append("  - Moderate security posture")
        elif result.pinning_behavior == PinningBehavior.PRIVATE_CA_PINNING:
            report.append("  - Private CA detected")
            report.append("  - High security posture (enterprise/api gateway)")
        elif result.pinning_behavior == PinningBehavior.CERTIFICATE_PINNING:
            report.append("  - Certificate pinning detected")
            report.append("  - High security posture (mobile app)")
        elif result.pinning_behavior == PinningBehavior.STRICT_PINNING:
            report.append("  - Strict pinning detected")
            report.append("  - Very high security posture")
        elif result.pinning_behavior == PinningBehavior.KEY_PINNING:
            report.append("  - Key pinning detected")
            report.append("  - Very high security posture")
        report.append("")
        
        # Backend type implications
        report.append("Backend Type Implications:")
        if result.backend_type == "mobile_app":
            report.append("  - Mobile application backend detected")
            report.append("  - Likely uses certificate pinning for security")
        elif result.backend_type == "api_gateway":
            report.append("  - API gateway detected")
            report.append("  - Enterprise security controls likely")
        elif result.backend_type == "cloud_load_balancer":
            report.append("  - Cloud load balancer detected")
            report.append("  - Multi-region deployment likely")
        elif result.backend_type == "cdn":
            report.append("  - CDN detected")
            report.append("  - Content delivery optimization in place")
        elif result.backend_type == "standard_web":
            report.append("  - Standard web infrastructure")
            report.append("  - Conventional security posture")
        report.append("")
        
        return "\n".join(report)

# Global instance
_cert_pinning_detector = None

def get_cert_pinning_detector() -> CertificatePinningDetector:
    """Get global certificate pinning detector."""
    global _cert_pinning_detector
    if _cert_pinning_detector is None:
        _cert_pinning_detector = CertificatePinningDetector()
    return _cert_pinning_detector

def detect_certificate_pinning(target_host: str, target_port: int = 443) -> CertificatePinningResult:
    """Convenience function for certificate pinning detection."""
    detector = get_cert_pinning_detector()
    return detector.detect_certificate_pinning(target_host, target_port)

def generate_pinning_report(result: CertificatePinningResult) -> str:
    """Convenience function for pinning report generation."""
    detector = get_cert_pinning_detector()
    return detector.generate_pinning_report(result)
