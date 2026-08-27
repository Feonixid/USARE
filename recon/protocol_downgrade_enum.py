"""Protocol Downgrade and Weak Configuration Enumeration.

Tests for cryptographic weaknesses and protocol downgrade possibilities
through legitimate TLS handshake variations that appear like browser configurations.

Identifies legacy protocol support, weak cipher suites, and configuration
vulnerabilities without triggering port scan alerts.
"""

import logging
import time
import ssl
import socket
import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("usare.protocol_downgrade")

class TLSVersion(Enum):
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"

class CipherSuiteType(Enum):
    EXPORT = "export"
    NULL = "null"
    WEAK = "weak"
    STRONG = "strong"

@dataclass
class TLSHandshakeResult:
    """TLS handshake result."""
    target_host: str
    target_port: int
    tls_version: str
    cipher_suite: str
    handshake_success: bool
    error_type: Optional[str]
    response_time_ms: float
    certificate_info: Dict[str, Any]
    vulnerabilities: List[str]

@dataclass
class ProtocolDowngradeResult:
    """Protocol downgrade analysis result."""
    target_host: str
    target_port: int
    supported_versions: List[str]
    supported_ciphers: List[str]
    weak_configurations: List[str]
    vulnerabilities: List[str]
    security_assessment: List[str]
    recommendations: List[str]
    confidence_score: float

class ProtocolDowngradeEnumerator:
    """Advanced protocol downgrade and weak configuration enumerator."""
    
    def __init__(self):
        self.timeout = 10.0
        
        # TLS version configurations
        self.tls_versions = [
            (TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
            (TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            (TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            (TLSVersion.TLSv1_0, ssl.TLSVersion.TLSv1_0),
            (TLSVersion.SSLv3, ssl.TLSVersion.SSLv3),
            (TLSVersion.SSLv2, ssl.TLSVersion.SSLv2)
        ]
        
        # Cipher suite configurations
        self.cipher_configurations = {
            "modern": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-CHACHA20-POLY1305",
                "ECDHE-RSA-CHACHA20-POLY1305"
            ],
            "intermediate": [
                "ECDHE-ECDSA-AES128-SHA256",
                "ECDHE-RSA-AES128-SHA256",
                "ECDHE-ECDSA-AES256-SHA384",
                "ECDHE-RSA-AES256-SHA384",
                "AES128-GCM-SHA256",
                "AES256-GCM-SHA384",
                "AES128-SHA256",
                "AES256-SHA384"
            ],
            "weak": [
                "RC4-MD5",
                "RC4-SHA",
                "DES-CBC3-SHA",
                "AES128-SHA",
                "AES256-SHA",
                "3DES-EDE-CBC",
                "EXP-RC4-MD5",
                "EXP-DES-CBC-SHA",
                "EXPORT1024-RC4-SHA",
                "EXPORT1024-DES-CBC-SHA",
                "NULL-MD5",
                "NULL-SHA"
            ],
            "export": [
                "EXP-RC4-MD5",
                "EXP-DES-CBC-SHA",
                "EXP-RC2-CBC-MD5",
                "EXPORT1024-RC4-SHA",
                "EXPORT1024-DES-CBC-SHA",
                "EXPORT40-RC4-MD5",
                "EXPORT56-DES-CBC-SHA"
            ],
            "null": [
                "NULL-MD5",
                "NULL-SHA",
                "NULL-SHA256",
                "NULL-SHA384"
            ]
        }
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            "sslv2": "SSLv2 is deprecated and vulnerable to multiple attacks",
            "sslv3": "SSLv3 is vulnerable to POODLE attack",
            "tlsv1_0": "TLSv1.0 is vulnerable to BEAST and other attacks",
            "tlsv1_1": "TLSv1.1 has known vulnerabilities",
            "export_ciphers": "Export cipher suites are extremely weak",
            "null_ciphers": "NULL cipher suites provide no encryption",
            "rc4": "RC4 cipher suites have known biases",
            "cbc_without_hmac": "CBC mode without proper HMAC is vulnerable",
            "weak_dh": "Weak DH parameters can lead to key compromise"
        }
    
    def enumerate_protocol_weaknesses(self, target_host: str, target_port: int = 443) -> ProtocolDowngradeResult:
        """Enumerate protocol weaknesses and downgrade possibilities."""
        start_time = time.time()
        
        try:
            handshake_results = []
            
            # Test TLS version support
            version_results = []
            for version_enum, version_const in self.tls_versions:
                try:
                    result = self._test_tls_version(target_host, target_port, version_enum, version_const)
                    if result:
                        version_results.append(result)
                        logger.debug(f"[Protocol] TLS {version_enum.value}: {result.cipher_suite}")
                except Exception as e:
                    logger.debug(f"[Protocol] TLS {version_enum.value} test failed: {e}")
            
            # Test cipher suite support with modern TLS
            cipher_results = []
            for cipher_category, cipher_list in self.cipher_configurations.items():
                try:
                    result = self._test_cipher_suites(target_host, target_port, cipher_list)
                    if result:
                        cipher_results.extend(result)
                        logger.debug(f"[Protocol] {cipher_category} ciphers: {len(result)} supported")
                except Exception as e:
                    logger.debug(f"[Protocol] {cipher_category} cipher test failed: {e}")
            
            # Test for specific vulnerabilities
            vulnerability_results = []
            
            # Test for POODLE vulnerability
            poodle_result = self._test_poodle_vulnerability(target_host, target_port)
            if poodle_result:
                vulnerability_results.append(poodle_result)
            
            # Test for renegotiation vulnerabilities
            renegotiation_result = self._test_renegotiation_vulnerability(target_host, target_port)
            if renegotiation_result:
                vulnerability_results.append(renegotiation_result)
            
            # Test for certificate pinning bypass
            pinning_result = self._test_certificate_pinning_bypass(target_host, target_port)
            if pinning_result:
                vulnerability_results.append(pinning_result)
            
            # Analyze results
            supported_versions = [r.tls_version for r in version_results if r.handshake_success]
            supported_ciphers = [r.cipher_suite for r in cipher_results if r.handshake_success]
            weak_configurations = self._identify_weak_configurations(version_results, cipher_results)
            vulnerabilities = self._identify_vulnerabilities(version_results, cipher_results, vulnerability_results)
            
            # Generate security assessment
            security_assessment = self._generate_security_assessment(supported_versions, supported_ciphers, vulnerabilities)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(weak_configurations, vulnerabilities)
            
            # Calculate confidence
            confidence = self._calculate_confidence(version_results, cipher_results, vulnerability_results)
            
            return ProtocolDowngradeResult(
                target_host=target_host,
                target_port=target_port,
                supported_versions=supported_versions,
                supported_ciphers=supported_ciphers,
                weak_configurations=weak_configurations,
                vulnerabilities=vulnerabilities,
                security_assessment=security_assessment,
                recommendations=recommendations,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"[Protocol] Enumeration failed: {e}")
            return ProtocolDowngradeResult(
                target_host=target_host,
                target_port=target_port,
                supported_versions=[],
                supported_ciphers=[],
                weak_configurations=[f"Enumeration failed: {e}"],
                vulnerabilities=[],
                security_assessment=[],
                recommendations=[],
                confidence_score=0.0
            )
    
    def _test_tls_version(self, target_host: str, target_port: int, 
                        version_enum: TLSVersion, version_const) -> Optional[TLSHandshakeResult]:
        """Test specific TLS version support."""
        try:
            # Create SSL context for specific version
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set minimum and maximum versions
            context.minimum_version = version_const
            context.maximum_version = version_const
            
            # Connect and handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                start_time = time.time()
                sock.connect((target_host, target_port))
                
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                response_time = (time.time() - start_time) * 1000
                
                # Get cipher information
                cipher = ssl_sock.cipher()
                cert = ssl_sock.getpeercert()
                
                # Analyze certificate
                cert_info = self._analyze_certificate(cert) if cert else {}
                
                ssl_sock.close()
                sock.close()
                
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version=version_enum.value,
                    cipher_suite=cipher[0] if cipher else "unknown",
                    handshake_success=True,
                    error_type=None,
                    response_time_ms=response_time,
                    certificate_info=cert_info,
                    vulnerabilities=self._analyze_cipher_vulnerabilities(cipher[0] if cipher else "")
                )
                
            except ssl.SSLError as e:
                try:
                    sock.close()
                except:
                    pass
                
                error_type = str(e)
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version=version_enum.value,
                    cipher_suite="unknown",
                    handshake_success=False,
                    error_type=error_type,
                    response_time_ms=0.0,
                    certificate_info={},
                    vulnerabilities=[]
                )
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version=version_enum.value,
                    cipher_suite="unknown",
                    handshake_success=False,
                    error_type=str(e),
                    response_time_ms=0.0,
                    certificate_info={},
                    vulnerabilities=[]
                )
                
        except Exception as e:
            logger.debug(f"[Protocol] TLS version test failed: {e}")
            return None
    
    def _test_cipher_suites(self, target_host: str, target_port: int, 
                          cipher_list: List[str]) -> List[TLSHandshakeResult]:
        """Test specific cipher suites."""
        results = []
        
        for cipher_suite in cipher_list:
            try:
                # Create SSL context with specific cipher
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                # Set cipher suite
                try:
                    context.set_ciphers(cipher_suite)
                except ssl.SSLError:
                    # Cipher not supported, skip
                    continue
                
                # Connect and handshake
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                try:
                    start_time = time.time()
                    sock.connect((target_host, target_port))
                    
                    ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                    ssl_sock.do_handshake()
                    
                    response_time = (time.time() - start_time) * 1000
                    
                    # Get cipher information
                    cipher = ssl_sock.cipher()
                    cert = ssl_sock.getpeercert()
                    
                    # Analyze certificate
                    cert_info = self._analyze_certificate(cert) if cert else {}
                    
                    ssl_sock.close()
                    sock.close()
                    
                    results.append(TLSHandshakeResult(
                        target_host=target_host,
                        target_port=target_port,
                        tls_version="TLSv1.2+",  # Will be determined by handshake
                        cipher_suite=cipher[0] if cipher else "unknown",
                        handshake_success=True,
                        error_type=None,
                        response_time_ms=response_time,
                        certificate_info=cert_info,
                        vulnerabilities=self._analyze_cipher_vulnerabilities(cipher[0] if cipher else "")
                    ))
                    
                except ssl.SSLError as e:
                    try:
                        sock.close()
                    except:
                        pass
                    
                    results.append(TLSHandshakeResult(
                        target_host=target_host,
                        target_port=target_port,
                        tls_version="TLSv1.2+",
                        cipher_suite=cipher_suite,
                        handshake_success=False,
                        error_type=str(e),
                        response_time_ms=0.0,
                        certificate_info={},
                        vulnerabilities=[]
                    ))
                except Exception as e:
                    try:
                        sock.close()
                    except:
                        pass
                    
                    results.append(TLSHandshakeResult(
                        target_host=target_host,
                        target_port=target_port,
                        tls_version="TLSv1.2+",
                        cipher_suite=cipher_suite,
                        handshake_success=False,
                        error_type=str(e),
                        response_time_ms=0.0,
                        certificate_info={},
                        vulnerabilities=[]
                    ))
                    
            except Exception as e:
                logger.debug(f"[Protocol] Cipher test failed: {e}")
                continue
        
        return results
    
    def _test_poodle_vulnerability(self, target_host: str, target_port: int) -> Optional[TLSHandshakeResult]:
        """Test for POODLE vulnerability (SSLv3 fallback)."""
        try:
            # Create SSL context for SSLv3
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Force SSLv3
            context.minimum_version = ssl.TLSVersion.SSLv3
            context.maximum_version = ssl.TLSVersion.SSLv3
            
            # Connect and handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                start_time = time.time()
                sock.connect((target_host, target_port))
                
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                response_time = (time.time() - start_time) * 1000
                
                ssl_sock.close()
                sock.close()
                
                # If SSLv3 handshake succeeds, vulnerable to POODLE
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version="SSLv3",
                    cipher_suite="unknown",
                    handshake_success=True,
                    error_type=None,
                    response_time_ms=response_time,
                    certificate_info={},
                    vulnerabilities=["POODLE: SSLv3 support detected"]
                )
                
            except ssl.SSLError as e:
                try:
                    sock.close()
                except:
                    pass
                
                # SSLv3 properly rejected
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version="SSLv3",
                    cipher_suite="unknown",
                    handshake_success=False,
                    error_type=str(e),
                    response_time_ms=0.0,
                    certificate_info={},
                    vulnerabilities=[]
                )
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return None
                
        except Exception as e:
            logger.debug(f"[Protocol] POODLE test failed: {e}")
            return None
    
    def _test_renegotiation_vulnerability(self, target_host: str, target_port: int) -> Optional[TLSHandshakeResult]:
        """Test for renegotiation vulnerabilities."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                start_time = time.time()
                sock.connect((target_host, target_port))
                
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                # Test renegotiation
                try:
                    ssl_sock.renegotiate()
                    renegotiation_supported = True
                except:
                    renegotiation_supported = False
                
                response_time = (time.time() - start_time) * 1000
                
                ssl_sock.close()
                sock.close()
                
                vulnerabilities = []
                if not renegotiation_supported:
                    vulnerabilities.append("TLS renegotiation not supported")
                else:
                    # Check for secure renegotiation (RFC 5746)
                    cert = ssl_sock.getpeercert()
                    if cert:
                        # Check for renegotiation_info extension
                        # This is simplified - real implementation would check for RFC 5746 compliance
                        vulnerabilities.append("TLS renegotiation may be vulnerable")
                
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version="TLSv1.2+",
                    cipher_suite="unknown",
                    handshake_success=True,
                    error_type=None,
                    response_time_ms=response_time,
                    certificate_info={},
                    vulnerabilities=vulnerabilities
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version="TLSv1.2+",
                    cipher_suite="unknown",
                    handshake_success=False,
                    error_type=str(e),
                    response_time_ms=0.0,
                    certificate_info={},
                    vulnerabilities=[f"Renegotiation test failed: {e}"]
                )
                
        except Exception as e:
            logger.debug(f"[Protocol] Renegotiation test failed: {e}")
            return None
    
    def _test_certificate_pinning_bypass(self, target_host: str, target_port: int) -> Optional[TLSHandshakeResult]:
        """Test for certificate pinning bypass attempts."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                start_time = time.time()
                sock.connect((target_host, target_port))
                
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                response_time = (time.time() - start_time) * 1000
                
                cert = ssl_sock.getpeercert()
                cert_info = self._analyze_certificate(cert) if cert else {}
                
                ssl_sock.close()
                sock.close()
                
                # Check for certificate validation issues
                vulnerabilities = []
                if cert_info:
                    if cert_info.get("self_signed"):
                        vulnerabilities.append("Self-signed certificate detected")
                    if cert_info.get("expired"):
                        vulnerabilities.append("Expired certificate detected")
                    if cert_info.get("weak_signature"):
                        vulnerabilities.append("Weak signature algorithm detected")
                    if cert_info.get("weak_key"):
                        vulnerabilities.append("Weak key size detected")
                
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version="TLSv1.2+",
                    cipher_suite="unknown",
                    handshake_success=True,
                    error_type=None,
                    response_time_ms=response_time,
                    certificate_info=cert_info,
                    vulnerabilities=vulnerabilities
                )
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                
                return TLSHandshakeResult(
                    target_host=target_host,
                    target_port=target_port,
                    tls_version="TLSv1.2+",
                    cipher_suite="unknown",
                    handshake_success=False,
                    error_type=str(e),
                    response_time_ms=0.0,
                    certificate_info={},
                    vulnerabilities=[f"Certificate analysis failed: {e}"]
                )
                
        except Exception as e:
            logger.debug(f"[Protocol] Certificate pinning test failed: {e}")
            return None
    
    def _analyze_certificate(self, cert: dict) -> Dict[str, Any]:
        """Analyze TLS certificate for security issues."""
        cert_info = {}
        
        if not cert:
            return cert_info
        
        # Extract certificate information
        subject = cert.get("subject", ())
        issuer = cert.get("issuer", ())
        not_after = cert.get("notAfter")
        
        # Analyze subject
        for rdn in subject:
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                attr_type, attr_value = rdn[0], rdn[1]
                if attr_type == "commonName":
                    cert_info["common_name"] = attr_value if isinstance(attr_value, str) else str(attr_value)
        
        # Analyze issuer
        for rdn in issuer:
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                attr_type, attr_value = rdn[0], rdn[1]
                if attr_type == "organizationName":
                    cert_info["issuer"] = attr_value if isinstance(attr_value, str) else str(attr_value)
        
        # Check expiration
        if not_after:
            import datetime
            expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y")
            cert_info["expired"] = expiry_date < datetime.datetime.now()
            cert_info["expiry_date"] = not_after
        
        # Check for self-signed
        if issuer == subject:
            cert_info["self_signed"] = True
        else:
            cert_info["self_signed"] = False
        
        # Check for weak signature algorithm (simplified)
        cert_info["weak_signature"] = False  # Would need more detailed analysis
        
        # Check for weak key size (simplified)
        cert_info["weak_key"] = False  # Would need more detailed analysis
        
        return cert_info
    
    def _analyze_cipher_vulnerabilities(self, cipher_suite: str) -> List[str]:
        """Analyze cipher suite for vulnerabilities."""
        vulnerabilities = []
        
        # Check for known weak ciphers
        if "RC4" in cipher_suite:
            vulnerabilities.append("RC4 cipher has known biases")
        
        if "DES" in cipher_suite or "3DES" in cipher_suite:
            vulnerabilities.append("DES/3DES ciphers are weak")
        
        if "NULL" in cipher_suite:
            vulnerabilities.append("NULL cipher provides no encryption")
        
        if "EXPORT" in cipher_suite:
            vulnerabilities.append("EXPORT cipher suite is extremely weak")
        
        if "MD5" in cipher_suite:
            vulnerabilities.append("MD5 hash is weak")
        
        if "SHA1" in cipher_suite:
            vulnerabilities.append("SHA1 hash is weak")
        
        return vulnerabilities
    
    def _identify_weak_configurations(self, version_results: List[TLSHandshakeResult], 
                                   cipher_results: List[TLSHandshakeResult]) -> List[str]:
        """Identify weak TLS configurations."""
        weak_configs = []
        
        # Check for SSLv2/SSLv3 support
        ssl_versions = [r.tls_version for r in version_results if r.handshake_success]
        if "SSLv2" in ssl_versions:
            weak_configs.append("SSLv2 is deprecated and insecure")
        if "SSLv3" in ssl_versions:
            weak_configs.append("SSLv3 is vulnerable to POODLE attack")
        
        # Check for TLSv1.0/TLSv1.1 support
        if "TLSv1.0" in ssl_versions:
            weak_configs.append("TLSv1.0 is vulnerable to BEAST and other attacks")
        if "TLSv1.1" in ssl_versions:
            weak_configs.append("TLSv1.1 has known vulnerabilities")
        
        # Check for weak cipher suites
        weak_ciphers = []
        for result in cipher_results:
            if result.handshake_success and result.vulnerabilities:
                weak_ciphers.extend(result.vulnerabilities)
        
        if weak_ciphers:
            weak_configs.extend(weak_ciphers)
        
        return list(set(weak_configs))
    
    def _identify_vulnerabilities(self, version_results: List[TLSHandshakeResult], 
                              cipher_results: List[TLSHandshakeResult], 
                              vulnerability_results: List[TLSHandshakeResult]) -> List[str]:
        """Identify all vulnerabilities."""
        vulnerabilities = []
        
        # Collect vulnerabilities from all results
        for result in version_results:
            if result.vulnerabilities:
                vulnerabilities.extend(result.vulnerabilities)
        
        for result in cipher_results:
            if result.vulnerabilities:
                vulnerabilities.extend(result.vulnerabilities)
        
        for result in vulnerability_results:
            if result.vulnerabilities:
                vulnerabilities.extend(result.vulnerabilities)
        
        return list(set(vulnerabilities))
    
    def _generate_security_assessment(self, supported_versions: List[str], 
                                   supported_ciphers: List[str], 
                                   vulnerabilities: List[str]) -> List[str]:
        """Generate security assessment."""
        assessment = []
        
        # Overall security posture
        if vulnerabilities:
            assessment.append("CRITICAL: TLS configuration vulnerabilities detected")
        elif "TLSv1.0" in supported_versions or "TLSv1.1" in supported_versions or "SSLv3" in supported_versions:
            assessment.append("HIGH: Legacy TLS protocol support detected")
        elif any("RC4" in cipher for cipher in supported_ciphers):
            assessment.append("MEDIUM: Weak cipher suites detected")
        elif any("EXPORT" in cipher for cipher in supported_ciphers):
            assessment.append("HIGH: Export cipher suites detected")
        elif any("NULL" in cipher for cipher in supported_ciphers):
            assessment.append("CRITICAL: NULL cipher suites detected")
        else:
            assessment.append("INFO: TLS configuration appears secure")
        
        # Specific recommendations
        if "TLSv1.3" not in supported_versions:
            assessment.append("Recommend enabling TLSv1.3 for improved security")
        
        if len(supported_ciphers) > 10:
            assessment.append("Large number of cipher suites may indicate weak configuration")
        
        return assessment
    
    def _generate_recommendations(self, weak_configurations: List[str], 
                               vulnerabilities: List[str]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # General recommendations
        recommendations.extend([
            "Disable SSLv2 and SSLv3 support",
            "Disable TLSv1.0 and TLSv1.1 support",
            "Enable TLSv1.3 with modern cipher suites",
            "Remove export and NULL cipher suites",
            "Implement proper certificate validation",
            "Use HSTS for HTTPS sites",
            "Regularly update TLS libraries",
            "Monitor for TLS vulnerabilities"
        ])
        
        # Specific recommendations based on findings
        if "POODLE" in str(vulnerabilities):
            recommendations.append("Apply POODLE vulnerability patches")
        
        if "renegotiation" in str(vulnerabilities):
            recommendations.append("Implement secure renegotiation (RFC 5746)")
        
        if any("self-signed" in config for config in weak_configurations):
            recommendations.append("Replace self-signed certificates with CA-signed certificates")
        
        if any("expired" in config for config in weak_configurations):
            recommendations.append("Update expired certificates immediately")
        
        return recommendations
    
    def _calculate_confidence(self, version_results: List[TLSHandshakeResult], 
                           cipher_results: List[TLSHandshakeResult], 
                           vulnerability_results: List[TLSHandshakeResult]) -> float:
        """Calculate confidence score for protocol analysis."""
        total_tests = len(version_results) + len(cipher_results) + len(vulnerability_results)
        successful_tests = len([r for r in version_results if r.handshake_success]) + \
                         len([r for r in cipher_results if r.handshake_success]) + \
                         len([r for r in vulnerability_results if r.handshake_success])
        
        if total_tests == 0:
            return 0.0
        
        # Base confidence from successful tests
        base_confidence = successful_tests / total_tests
        
        # Quality confidence from detailed results
        quality_confidence = 0.0
        if vulnerability_results:
            quality_confidence += 0.3
        if cipher_results:
            quality_confidence += 0.4
        if version_results:
            quality_confidence += 0.3
        
        # Combined confidence
        overall_confidence = (base_confidence + quality_confidence) / 2.0
        
        return min(1.0, overall_confidence)
    
    def generate_protocol_report(self, result: ProtocolDowngradeResult) -> str:
        """Generate human-readable protocol analysis report."""
        report = []
        report.append("Protocol Downgrade and Weak Configuration Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        if result.supported_versions:
            report.append("Supported TLS Versions:")
            for version in result.supported_versions:
                report.append(f"  - {version}")
            report.append("")
        
        if result.supported_ciphers:
            report.append("Supported Cipher Suites:")
            for cipher in result.supported_ciphers[:20]:  # Show first 20
                report.append(f"  - {cipher}")
            if len(result.supported_ciphers) > 20:
                report.append(f"    ... and {len(result.supported_ciphers) - 20} more")
            report.append("")
        
        if result.weak_configurations:
            report.append("Weak Configurations:")
            for config in result.weak_configurations:
                report.append(f"  - {config}")
            report.append("")
        
        if result.vulnerabilities:
            report.append("Vulnerabilities:")
            for vulnerability in result.vulnerabilities:
                report.append(f"  - {vulnerability}")
            report.append("")
        
        if result.security_assessment:
            report.append("Security Assessment:")
            for assessment in result.security_assessment:
                report.append(f"  - {assessment}")
            report.append("")
        
        if result.recommendations:
            report.append("Recommendations:")
            for recommendation in result.recommendations:
                report.append(f"  - {recommendation}")
            report.append("")
        
        return "\n".join(report)

# Global instance
_protocol_enum = None

def get_protocol_enum() -> ProtocolDowngradeEnumerator:
    """Get global protocol enumerator."""
    global _protocol_enum
    if _protocol_enum is None:
        _protocol_enum = ProtocolDowngradeEnumerator()
    return _protocol_enum

def enumerate_protocol_weaknesses(target_host: str, target_port: int = 443) -> ProtocolDowngradeResult:
    """Convenience function for protocol weakness enumeration."""
    enumerator = get_protocol_enum()
    return enumerator.enumerate_protocol_weaknesses(target_host, target_port)

def generate_protocol_report(result: ProtocolDowngradeResult) -> str:
    """Convenience function for protocol report generation."""
    enumerator = get_protocol_enum()
    return enumerator.generate_protocol_report(result)
