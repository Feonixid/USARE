"""
USARE TLS Certificate Chain Intelligence

Analyzes TLS certificates and certificate transparency logs to extract
infrastructure intelligence, subdomain discovery, and security posture.

Features:
- Certificate chain analysis
- Certificate Transparency log querying
- Subdomain enumeration from CT logs
- Infrastructure relationship mapping
- Security posture assessment
"""

import json
import time
import hashlib
import ssl
import socket
import requests
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import quote
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ipaddress

logger = logging.getLogger("usare.cert_intelligence")

@dataclass
class CertificateInfo:
    """Information extracted from a TLS certificate."""
    subject_cn: str
    subject_san: List[str]
    issuer_cn: str
    issuer_org: str
    serial_number: str
    not_before: str
    not_after: str
    signature_algorithm: str
    key_size: int
    is_self_signed: bool
    is_wildcard: bool
    certificate_hash: str

@dataclass
class CTLogEntry:
    """Certificate Transparency log entry."""
    cert_sha256: str
    subject_cn: str
    subject_san: List[str]
    issuer_name: str
    not_before: str
    not_after: str
    log_name: str
    log_id: str

@dataclass
class CertIntelligence:
    """Complete certificate intelligence analysis."""
    leaf_certificate: CertificateInfo
    chain_certificates: List[CertificateInfo]
    ct_subdomains: Set[str]
    infrastructure_relationships: Dict[str, List[str]]
    security_posture: Dict[str, str]
    certificate_history: List[CTLogEntry]
    analysis_confidence: float

class CertificateIntelligenceAnalyzer:
    """Advanced TLS certificate intelligence analyzer."""
    
    # Certificate Transparency APIs
    CT_APIS = [
        "https://crt.sh/?q={}&output=json",
        "https://crt.sh/?q={}&output=json&exclude=expired",
        "https://google.transparencyreport.dev/api/v1/ct/v1/get-entries?domain={}"
    ]
    
    # Known certificate issuers and their characteristics
    ISSUER_PROFILES = {
        "Let's Encrypt": {"type": "free", "automation": "high", "security": "good"},
        "DigiCert": {"type": "commercial", "automation": "medium", "security": "excellent"},
        "GlobalSign": {"type": "commercial", "automation": "medium", "security": "excellent"},
        "Sectigo": {"type": "commercial", "automation": "medium", "security": "good"},
        "GoDaddy": {"type": "commercial", "automation": "low", "security": "good"},
        "Cloudflare": {"type": "free", "automation": "high", "security": "excellent"},
        "Amazon": {"type": "commercial", "automation": "high", "security": "excellent"},
        "Google": {"type": "free", "automation": "high", "security": "excellent"},
        "Microsoft": {"type": "commercial", "automation": "high", "security": "excellent"},
    }
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
        
    def analyze_certificate_chain(self, target: str, port: int = 443) -> Optional[CertificateInfo]:
        """Analyze the TLS certificate chain for a target."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssock.getpeercert()
                    
                    # Parse certificate with cryptography
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    return self._extract_certificate_info(cert, cert_pem, cert_der)
                    
        except Exception as e:
            logger.debug(f"[USARE] Certificate analysis failed for {target}:{port} - {e}")
            return None
            
    def _extract_certificate_info(self, cert, cert_pem: dict, cert_der: bytes) -> CertificateInfo:
        """Extract detailed information from a certificate."""
        # Subject information
        subject = cert.subject
        subject_cn = self._get_attribute(subject, "common_name")
        
        # SAN extraction
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            subject_san = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            subject_san = []
            
        # Issuer information
        issuer = cert.issuer
        issuer_cn = self._get_attribute(issuer, "common_name")
        issuer_org = self._get_attribute(issuer, "organization_name")
        
        # Certificate details
        serial_number = hex(cert.serial_number)[2:].upper()
        not_before = cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after.isoformat()
        signature_algorithm = cert.signature_algorithm_oid._name
        
        # Key information
        public_key = cert.public_key()
        key_size = public_key.key_size if hasattr(public_key, 'key_size') else 0
        
        # Flags
        is_self_signed = cert.issuer == cert.subject
        is_wildcard = subject_cn and subject_cn.startswith("*.")
        
        # Certificate hash
        cert_hash = hashlib.sha256(cert_der).hexdigest()
        
        return CertificateInfo(
            subject_cn=subject_cn,
            subject_san=subject_san,
            issuer_cn=issuer_cn,
            issuer_org=issuer_org,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            signature_algorithm=signature_algorithm,
            key_size=key_size,
            is_self_signed=is_self_signed,
            is_wildcard=is_wildcard,
            certificate_hash=cert_hash
        )
        
    def _get_attribute(self, name_obj, attribute_name: str) -> str:
        """Extract attribute from X.509 name object."""
        for attr in name_obj:
            if attr.oid._name == attribute_name:
                return attr.value
        return ""
        
    def query_certificate_transparency(self, domain: str) -> List[CTLogEntry]:
        """Query Certificate Transparency logs for a domain."""
        ct_entries = []
        
        for api_url in self.CT_APIS[:2]:  # Use first 2 APIs (crt.sh)
            try:
                url = api_url.format(quote(domain))
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    try:
                        entries = response.json()
                        
                        for entry in entries:
                            # Parse CRT.sh entry format
                            if isinstance(entry, dict):
                                ct_entry = self._parse_ct_entry(entry)
                                if ct_entry:
                                    ct_entries.append(ct_entry)
                                    
                    except json.JSONDecodeError:
                        logger.debug(f"[USARE] Failed to parse CT JSON from {api_url}")
                        continue
                        
                # Limit results to prevent overwhelming
                if len(ct_entries) > 1000:
                    break
                    
            except Exception as e:
                logger.debug(f"[USARE] CT query failed for {api_url} - {e}")
                continue
                
        logger.info(f"[USARE] Found {len(ct_entries)} CT entries for {domain}")
        return ct_entries
        
    def _parse_ct_entry(self, entry: dict) -> Optional[CTLogEntry]:
        """Parse a Certificate Transparency log entry."""
        try:
            # CRT.sh format
            name_value = entry.get('name_value', '')
            issuer_name = entry.get('issuer_name', '')
            not_before = entry.get('not_before', '')
            not_after = entry.get('not_after', '')
            
            # Extract domains from name_value
            domains = set()
            for line in name_value.split('\n'):
                if line.startswith('DNS:'):
                    domain = line[4:].strip()
                    if domain:
                        domains.add(domain)
                        
            # Get primary CN (first domain)
            subject_cn = list(domains)[0] if domains else ''
            subject_san = list(domains)
            
            # Calculate certificate hash
            cert_sha256 = hashlib.sha256(name_value.encode()).hexdigest()
            
            return CTLogEntry(
                cert_sha256=cert_sha256,
                subject_cn=subject_cn,
                subject_san=subject_san,
                issuer_name=issuer_name,
                not_before=not_before,
                not_after=not_after,
                log_name="crt.sh",
                log_id="unknown"
            )
            
        except Exception as e:
            logger.debug(f"[USARE] Failed to parse CT entry - {e}")
            return None
            
    def extract_subdomains_from_ct(self, ct_entries: List[CTLogEntry]) -> Set[str]:
        """Extract unique subdomains from CT log entries."""
        subdomains = set()
        
        for entry in ct_entries:
            for domain in entry.subject_san:
                # Extract subdomain (everything before the base domain)
                if '.' in domain and not domain.startswith('*.'):
                    parts = domain.split('.')
                    if len(parts) >= 2:
                        potential_subdomain = '.'.join(parts[:-2])  # Remove TLD and SLD
                        if potential_subdomain:
                            subdomains.add(potential_subdomain)
                            
        return subdomains
        
    def analyze_infrastructure_relationships(self, cert_info: CertificateInfo, 
                                          ct_entries: List[CTLogEntry]) -> Dict[str, List[str]]:
        """Analyze infrastructure relationships from certificates."""
        relationships = {
            'shared_issuers': [],
            'related_domains': [],
            'infrastructure_providers': [],
            'security_services': []
        }
        
        # Group by issuer
        issuer_groups = {}
        for entry in ct_entries:
            issuer = entry.issuer_name
            if issuer not in issuer_groups:
                issuer_groups[issuer] = []
            issuer_groups[issuer].extend(entry.subject_san)
            
        # Find shared issuers indicating related infrastructure
        for issuer, domains in issuer_groups.items():
            unique_domains = set(domains)
            if len(unique_domains) > 1:
                relationships['shared_issuers'].append({
                    'issuer': issuer,
                    'domains': list(unique_domains)[:10]  # Limit to 10
                })
                
        # Identify infrastructure providers from issuer patterns
        for issuer in issuer_groups.keys():
            if any(provider in issuer.lower() for provider in ['cloudflare', 'akamai', 'fastly', 'incapsula']):
                relationships['infrastructure_providers'].append(issuer)
            elif any(provider in issuer.lower() for provider in ['letsencrypt', 'digicert', 'globalsign']):
                relationships['security_services'].append(issuer)
                
        return relationships
        
    def assess_security_posture(self, cert_info: CertificateInfo, 
                              ct_entries: List[CTLogEntry]) -> Dict[str, str]:
        """Assess the security posture based on certificate analysis."""
        posture = {}
        
        # Certificate issuer quality
        issuer_profile = self.ISSUER_PROFILES.get(cert_info.issuer_org, {})
        posture['issuer_quality'] = issuer_profile.get('security', 'unknown')
        
        # Certificate age and rotation
        try:
            from datetime import datetime
            not_after = datetime.fromisoformat(cert_info.not_after.replace('Z', '+00:00'))
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry < 7:
                posture['expiry_status'] = 'critical'
            elif days_until_expiry < 30:
                posture['expiry_status'] = 'warning'
            else:
                posture['expiry_status'] = 'good'
        except:
            posture['expiry_status'] = 'unknown'
            
        # Key strength
        if cert_info.key_size >= 4096:
            posture['key_strength'] = 'excellent'
        elif cert_info.key_size >= 2048:
            posture['key_strength'] = 'good'
        elif cert_info.key_size >= 1024:
            posture['key_strength'] = 'weak'
        else:
            posture['key_strength'] = 'very_weak'
            
        # Certificate complexity (number of certificates in CT logs)
        cert_count = len(ct_entries)
        if cert_count > 100:
            posture['cert_complexity'] = 'high'
        elif cert_count > 20:
            posture['cert_complexity'] = 'medium'
        else:
            posture['cert_complexity'] = 'low'
            
        return posture
        
    def analyze_target(self, target: str, port: int = 443) -> CertIntelligence:
        """Perform complete certificate intelligence analysis."""
        logger.info(f"[USARE] Starting certificate intelligence analysis for {target}:{port}")
        
        # Analyze current certificate chain
        leaf_cert = self.analyze_certificate_chain(target, port)
        if not leaf_cert:
            raise ValueError(f"Could not retrieve certificate from {target}:{port}")
            
        # Query Certificate Transparency logs
        domain = leaf_cert.subject_cn.replace('*.', '')  # Remove wildcard prefix
        ct_entries = self.query_certificate_transparency(domain)
        
        # Extract subdomains
        ct_subdomains = self.extract_subdomains_from_ct(ct_entries)
        
        # Analyze infrastructure relationships
        infrastructure_relationships = self.analyze_infrastructure_relationships(leaf_cert, ct_entries)
        
        # Assess security posture
        security_posture = self.assess_security_posture(leaf_cert, ct_entries)
        
        # Calculate confidence based on data quality
        confidence_factors = []
        if leaf_cert: confidence_factors.append(0.3)
        if ct_entries: confidence_factors.append(0.4)
        if ct_subdomains: confidence_factors.append(0.2)
        if infrastructure_relationships.get('shared_issuers'): confidence_factors.append(0.1)
        
        analysis_confidence = sum(confidence_factors)
        
        logger.info(f"[USARE] Certificate analysis complete: {len(ct_entries)} CT entries, "
                   f"{len(ct_subdomains)} subdomains found")
        
        return CertIntelligence(
            leaf_certificate=leaf_cert,
            chain_certificates=[],  # TODO: Implement full chain analysis
            ct_subdomains=ct_subdomains,
            infrastructure_relationships=infrastructure_relationships,
            security_posture=security_posture,
            certificate_history=ct_entries,
            analysis_confidence=analysis_confidence
        )

# Integration function for existing scanner
def analyze_certificate_intelligence(target: str, port: int = 443) -> Optional[Dict[str, any]]:
    """Analyze certificate intelligence and return results as dict."""
    try:
        analyzer = CertificateIntelligenceAnalyzer()
        intel = analyzer.analyze_target(target, port)
        
        return {
            'leaf_certificate': intel.leaf_certificate.__dict__,
            'ct_subdomains': list(intel.ct_subdomains),
            'infrastructure_relationships': intel.infrastructure_relationships,
            'security_posture': intel.security_posture,
            'certificate_count': len(intel.certificate_history),
            'confidence': intel.analysis_confidence
        }
    except Exception as e:
        logger.error(f"[USARE] Certificate intelligence analysis failed: {e}")
        return None
