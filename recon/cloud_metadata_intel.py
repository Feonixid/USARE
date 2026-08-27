"""Cloud Provider Metadata API Fingerprinting.

Identifies cloud providers and service types through public interface analysis
without requiring SSRF vulnerabilities or internal access.

Uses TLS certificate patterns, HTTP headers, routing data, and
behavioral analysis to fingerprint cloud infrastructure.
"""

import logging
import time
import ssl
import socket
import hashlib
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from scapy.all import IP, TCP, sr1, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.cloud_metadata")

class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITAL_OCEAN = "digitalocean"
    LINODE = "linode"
    VULTR = "vultr"
    ALIBABA = "alibaba"
    ORACLE = "oracle"
    IBM = "ibm"
    RACKSPACE = "rackspace"

class CloudServiceType(Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORKING = "networking"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"
    SERVERLESS = "serverless"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"

@dataclass
class CloudFingerprint:
    """Cloud provider fingerprint."""
    provider: CloudProvider
    service_type: CloudServiceType
    confidence: float
    indicators: List[str]
    metadata_indicators: Dict[str, Any]

@dataclass
class CloudIntelResult:
    """Cloud intelligence analysis result."""
    target_ip: str
    target_host: str
    cloud_fingerprints: List[CloudFingerprint]
    primary_provider: Optional[CloudProvider]
    primary_service: Optional[CloudServiceType]
    provider_confidence: float
    service_confidence: float
    security_assessment: List[str]
    recommendations: List[str]

class CloudMetadataIntelligence:
    """Advanced cloud provider metadata intelligence gatherer."""
    
    def __init__(self):
        self.timeout = 10.0
        
        # Cloud provider signatures
        self.cloud_signatures = {
            CloudProvider.AWS: {
                "ip_ranges": [
                    "3.", "52.", "54.", "107.", "172.", "204.", "205.", "208.", "23."
                ],
                "tls_patterns": [
                    r"*.amazonaws.com",
                    r"*.compute.amazonaws.com",
                    r"*.elasticbeanstalk.com",
                    r"*.s3.amazonaws.com",
                    r"*.cloudfront.net"
                ],
                "http_headers": {
                    "server": [r"Server:.*Amazon.*", r"Server:.*aws.*"],
                    "x-amz": [r"X-Amz-.*"],
                    "x-aws": [r"X-AWS-.*"]
                },
                "certificate_patterns": [
                    r"*.amazonaws.com",
                    r"*.compute.amazonaws.com",
                    r"*.elasticbeanstalk.com"
                ],
                "service_patterns": {
                    CloudServiceType.COMPUTE: [r".*\.compute\.amazonaws\.com"],
                    CloudServiceType.STORAGE: [r".*\.s3\.amazonaws\.com"],
                    CloudServiceType.CDN: [r".*\.cloudfront\.net"],
                    CloudServiceType.LOAD_BALANCER: [r".*\.elb\.amazonaws\.com"],
                    CloudServiceType.DATABASE: [r".*\.rds\.amazonaws\.com"],
                    CloudServiceType.CONTAINER: [r".*\.ecs\.amazonaws\.com"]
                }
            },
            CloudProvider.AZURE: {
                "ip_ranges": [
                    "13.", "20.", "40.", "52.", "104.", "168.", "172.", "191.", "204."
                ],
                "tls_patterns": [
                    r"*.azureedge.net",
                    r"*.cloudapp.net",
                    r"*.azurewebsites.net",
                    r"*.blob.core.windows.net"
                ],
                "http_headers": {
                    "server": [r"Server:.*Microsoft.*", r"Server:.*Azure.*"],
                    "x-azure": [r"X-Azure-.*"],
                    "x-ms": [r"X-MS-.*"]
                },
                "certificate_patterns": [
                    r"*.azureedge.net",
                    r"*.cloudapp.net",
                    r"*.azurewebsites.net"
                ],
                "service_patterns": {
                    CloudServiceType.COMPUTE: [r".*\.cloudapp\.net"],
                    CloudServiceType.STORAGE: [r".*\.blob\.core\.windows\.net"],
                    CloudServiceType.CDN: [r".*\.azureedge\.net"],
                    CloudServiceType.LOAD_BALANCER: [r".*\.azurefd\.net"],
                    CloudServiceType.DATABASE: [r".*\.database\.windows\.net"],
                    CloudServiceType.CONTAINER: [r".*\.container\.azurewebsites\.net"]
                }
            },
            CloudProvider.GCP: {
                "ip_ranges": [
                    "8.", "23.", "34.", "35.", "64.", "66.", "70.", "74.", "104.", "108.", "142.", "146.", "172.", "199.", "216."
                ],
                "tls_patterns": [
                    r"*.googleusercontent.com",
                    r"*.gcp.gvt2.com",
                    r"*.appspot.com",
                    r"*.googleapis.com"
                ],
                "http_headers": {
                    "server": [r"Server:.*GSE.*", r"Server:.*gws.*"],
                    "x-google": [r"X-Google-.*"],
                    "x-gcp": [r"X-GCP-.*"]
                },
                "certificate_patterns": [
                    r"*.googleusercontent.com",
                    r"*.gcp.gvt2.com",
                    r"*.appspot.com"
                ],
                "service_patterns": {
                    CloudServiceType.COMPUTE: [r".*\.googleusercontent\.com"],
                    CloudServiceType.STORAGE: [r".*\.storage\.googleapis\.com"],
                    CloudServiceType.CDN: [r".*\.googleapis\.com"],
                    CloudServiceType.LOAD_BALANCER: [r".*\.googleapis\.com"],
                    CloudServiceType.DATABASE: [r".*\.sqladmin\.googleapis\.com"],
                    CloudServiceType.SERVERLESS: [r".*\.cloudfunctions\.net"],
                    CloudServiceType.CONTAINER: [r".*\.appspot\.com"]
                }
            }
        }
        
        # Metadata API endpoints (for reference)
        self.metadata_endpoints = {
            CloudProvider.AWS: "169.254.169.254",
            CloudProvider.AZURE: "169.254.169.254",
            CloudProvider.GCP: "metadata.google.internal"
        }
    
    def analyze_cloud_provider(self, target_ip: str, target_host: str = None) -> CloudIntelResult:
        """Analyze target for cloud provider and service type."""
        start_time = time.time()
        
        try:
            # Use target_host if provided, otherwise resolve from IP
            if not target_host:
                target_host = self._resolve_hostname(target_ip) or target_ip
            
            # Collect fingerprinting data
            fingerprints = []
            
            # TLS certificate analysis
            cert_fingerprint = self._analyze_tls_certificate(target_host, target_ip)
            if cert_fingerprint:
                fingerprints.append(cert_fingerprint)
            
            # HTTP header analysis
            header_fingerprint = self._analyze_http_headers(target_host, target_ip)
            if header_fingerprint:
                fingerprints.append(header_fingerprint)
            
            # IP range analysis
            ip_fingerprint = self._analyze_ip_range(target_ip)
            if ip_fingerprint:
                fingerprints.append(ip_fingerprint)
            
            # Behavioral analysis
            behavior_fingerprint = self._analyze_cloud_behavior(target_host, target_ip)
            if behavior_fingerprint:
                fingerprints.append(behavior_fingerprint)
            
            # Determine primary provider and service
            primary_provider, provider_confidence = self._determine_primary_provider(fingerprints)
            primary_service, service_confidence = self._determine_primary_service(fingerprints)
            
            # Security assessment
            security_assessment = self._assess_cloud_security(fingerprints, primary_provider)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(fingerprints, primary_provider)
            
            return CloudIntelResult(
                target_ip=target_ip,
                target_host=target_host,
                cloud_fingerprints=fingerprints,
                primary_provider=primary_provider,
                primary_service=primary_service,
                provider_confidence=provider_confidence,
                service_confidence=service_confidence,
                security_assessment=security_assessment,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"[Cloud Intel] Analysis failed: {e}")
            return CloudIntelResult(
                target_ip=target_ip,
                target_host=target_host or target_ip,
                cloud_fingerprints=[],
                primary_provider=None,
                primary_service=None,
                provider_confidence=0.0,
                service_confidence=0.0,
                security_assessment=[f"Analysis failed: {e}"],
                recommendations=[]
            )
    
    def _resolve_hostname(self, target_ip: str) -> Optional[str]:
        """Resolve hostname from IP address."""
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            return hostname
        except:
            return None
    
    def _analyze_tls_certificate(self, target_host: str, target_ip: str) -> Optional[CloudFingerprint]:
        """Analyze TLS certificate for cloud indicators."""
        try:
            # Get TLS certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target_host, 443))
                ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.do_handshake()
                
                cert = ssl_sock.getpeercert()
                
                if cert:
                    fingerprint = self._analyze_certificate_content(cert, target_host)
                    ssl_sock.close()
                    sock.close()
                    return fingerprint
                
                ssl_sock.close()
                sock.close()
                
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                logger.debug(f"[Cloud Intel] TLS analysis failed: {e}")
            
            return None
            
        except Exception as e:
            logger.debug(f"[Cloud Intel] Certificate analysis failed: {e}")
            return None
    
    def _analyze_certificate_content(self, cert: dict, target_host: str) -> CloudFingerprint:
        """Analyze certificate content for cloud indicators."""
        indicators = []
        provider_votes = {}
        
        # Extract certificate information
        subject = cert.get("subject", ())
        issuer = cert.get("issuer", ())
        sans = cert.get("subjectAltName", ())
        
        # Analyze subject common name
        for rdn in subject:
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                attr_type, attr_value = rdn[0], rdn[1]
                if attr_type == "commonName":
                    cn = attr_value if isinstance(attr_value, str) else str(attr_value)
                    
                    # Check against provider patterns
                    for provider, signature in self.cloud_signatures.items():
                        for pattern in signature["certificate_patterns"]:
                            if re.match(pattern, cn, re.IGNORECASE):
                                provider_votes[provider] = provider_votes.get(provider, 0) + 1
                                indicators.append(f"CN matches {provider.value} pattern")
        
        # Analyze subject alternative names
        for san in sans:
            if isinstance(san, tuple) and len(san) >= 2:
                san_type, san_value = san[0], san[1]
                if san_type == "DNS":
                    san_name = san_value if isinstance(san_value, str) else str(san_value)
                    
                    for provider, signature in self.cloud_signatures.items():
                        for pattern in signature["certificate_patterns"]:
                            if re.match(pattern, san_name, re.IGNORECASE):
                                provider_votes[provider] = provider_votes.get(provider, 0) + 1
                                indicators.append(f"SAN matches {provider.value} pattern")
        
        # Analyze issuer
        for rdn in issuer:
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                attr_type, attr_value = rdn[0], rdn[1]
                if attr_type == "organizationName":
                    issuer_org = attr_value if isinstance(attr_value, str) else str(attr_value)
                    
                    if "Amazon" in issuer_org:
                        provider_votes[CloudProvider.AWS] = provider_votes.get(CloudProvider.AWS, 0) + 2
                        indicators.append("Issuer: Amazon")
                    elif "Microsoft" in issuer_org:
                        provider_votes[CloudProvider.AZURE] = provider_votes.get(CloudProvider.AZURE, 0) + 2
                        indicators.append("Issuer: Microsoft")
                    elif "Google" in issuer_org:
                        provider_votes[CloudProvider.GCP] = provider_votes.get(CloudProvider.GCP, 0) + 2
                        indicators.append("Issuer: Google")
        
        # Determine provider and service type
        primary_provider = None
        max_votes = 0
        for provider, votes in provider_votes.items():
            if votes > max_votes:
                max_votes = votes
                primary_provider = provider
        
        # Determine service type
        service_type = self._determine_service_from_certificates(primary_provider, subject, sans)
        
        return CloudFingerprint(
            provider=primary_provider,
            service_type=service_type,
            confidence=min(1.0, max_votes / 5.0),
            indicators=indicators,
            metadata_indicators={
                "subject": str(subject),
                "issuer": str(issuer),
                "sans": str(sans)
            }
        )
    
    def _analyze_http_headers(self, target_host: str, target_ip: str) -> Optional[CloudFingerprint]:
        """Analyze HTTP headers for cloud indicators."""
        try:
            if not HAS_REQUESTS:
                return None
            
            # Send HTTP request
            url = f"https://{target_host}/"
            headers = {
                "User-Agent": "USARE-Cloud-Intel/1.0"
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            indicators = []
            provider_votes = {}
            
            # Analyze response headers
            response_headers = response.headers
            
            for provider, signature in self.cloud_signatures.items():
                for header_name, patterns in signature["http_headers"].items():
                    header_value = response_headers.get(header_name.lower(), "")
                    
                    if header_value:
                        for pattern in patterns:
                            if re.search(pattern, header_value, re.IGNORECASE):
                                provider_votes[provider] = provider_votes.get(provider, 0) + 1
                                indicators.append(f"{header_name} matches {provider.value}")
            
            # Analyze server header specifically
            server_header = response_headers.get("server", "")
            if server_header:
                if "Amazon" in server_header:
                    provider_votes[CloudProvider.AWS] = provider_votes.get(CloudProvider.AWS, 0) + 2
                    indicators.append("Server header indicates AWS")
                elif "Microsoft" in server_header:
                    provider_votes[CloudProvider.AZURE] = provider_votes.get(CloudProvider.AZURE, 0) + 2
                    indicators.append("Server header indicates Azure")
                elif "GSE" in server_header or "gws" in server_header:
                    provider_votes[CloudProvider.GCP] = provider_votes.get(CloudProvider.GCP, 0) + 2
                    indicators.append("Server header indicates GCP")
            
            # Determine provider and service type
            primary_provider = None
            max_votes = 0
            for provider, votes in provider_votes.items():
                if votes > max_votes:
                    max_votes = votes
                    primary_provider = provider
            
            service_type = self._determine_service_from_headers(primary_provider, response_headers)
            
            return CloudFingerprint(
                provider=primary_provider,
                service_type=service_type,
                confidence=min(1.0, max_votes / 5.0),
                indicators=indicators,
                metadata_indicators={
                    "headers": dict(response_headers),
                    "status_code": response.status_code
                }
            )
            
        except Exception as e:
            logger.debug(f"[Cloud Intel] HTTP header analysis failed: {e}")
            return None
    
    def _analyze_ip_range(self, target_ip: str) -> Optional[CloudFingerprint]:
        """Analyze IP range for cloud indicators."""
        try:
            indicators = []
            provider_votes = {}
            
            # Check IP against provider ranges
            for provider, signature in self.cloud_signatures.items():
                for ip_range in signature["ip_ranges"]:
                    if target_ip.startswith(ip_range):
                        provider_votes[provider] = provider_votes.get(provider, 0) + 1
                        indicators.append(f"IP {target_ip} in {provider.value} range")
            
            # Determine provider
            primary_provider = None
            max_votes = 0
            for provider, votes in provider_votes.items():
                if votes > max_votes:
                    max_votes = votes
                    primary_provider = provider
            
            # IP range alone doesn't determine service type
            service_type = None
            
            return CloudFingerprint(
                provider=primary_provider,
                service_type=service_type,
                confidence=min(1.0, max_votes / 3.0),
                indicators=indicators,
                metadata_indicators={
                    "ip_range": target_ip
                }
            )
            
        except Exception as e:
            logger.debug(f"[Cloud Intel] IP range analysis failed: {e}")
            return None
    
    def _analyze_cloud_behavior(self, target_host: str, target_ip: str) -> Optional[CloudFingerprint]:
        """Analyze cloud-specific behaviors."""
        try:
            indicators = []
            provider_votes = {}
            
            # Test for cloud-specific behaviors
            # This is a simplified implementation
            # Real implementation would test specific cloud APIs and behaviors
            
            # Test for AWS-specific behavior
            if self._test_aws_behavior(target_host):
                provider_votes[CloudProvider.AWS] = provider_votes.get(CloudProvider.AWS, 0) + 1
                indicators.append("AWS-specific behavior detected")
            
            # Test for Azure-specific behavior
            if self._test_azure_behavior(target_host):
                provider_votes[CloudProvider.AZURE] = provider_votes.get(CloudProvider.AZURE, 0) + 1
                indicators.append("Azure-specific behavior detected")
            
            # Test for GCP-specific behavior
            if self._test_gcp_behavior(target_host):
                provider_votes[CloudProvider.GCP] = provider_votes.get(CloudProvider.GCP, 0) + 1
                indicators.append("GCP-specific behavior detected")
            
            # Determine provider
            primary_provider = None
            max_votes = 0
            for provider, votes in provider_votes.items():
                if votes > max_votes:
                    max_votes = votes
                    primary_provider = provider
            
            service_type = None  # Behavior analysis doesn't determine service type
            
            return CloudFingerprint(
                provider=primary_provider,
                service_type=service_type,
                confidence=min(1.0, max_votes / 3.0),
                indicators=indicators,
                metadata_indicators={
                    "behavioral_analysis": True
                }
            )
            
        except Exception as e:
            logger.debug(f"[Cloud Intel] Behavior analysis failed: {e}")
            return None
    
    def _test_aws_behavior(self, target_host: str) -> bool:
        """Test for AWS-specific behavior."""
        try:
            # Test for AWS-specific endpoints
            aws_endpoints = [
                "169.254.169.254/latest/meta-data/",
                "instance-data.ec2.internal",
                "169.254.169.254/latest/user-data"
            ]
            
            for endpoint in aws_endpoints:
                if endpoint in target_host:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _test_azure_behavior(self, target_host: str) -> bool:
        """Test for Azure-specific behavior."""
        try:
            # Test for Azure-specific endpoints
            azure_endpoints = [
                "169.254.169.254/metadata/",
                "168.63.129.16",
                "169.254.169.254/waagent/"
            ]
            
            for endpoint in azure_endpoints:
                if endpoint in target_host:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _test_gcp_behavior(self, target_host: str) -> bool:
        """Test for GCP-specific behavior."""
        try:
            # Test for GCP-specific endpoints
            gcp_endpoints = [
                "metadata.google.internal",
                "169.254.169.254/computeMetadata/",
                "metadata"
            ]
            
            for endpoint in gcp_endpoints:
                if endpoint in target_host:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _determine_service_from_certificates(self, provider: Optional[CloudProvider], 
                                        subject: tuple, sans: tuple) -> Optional[CloudServiceType]:
        """Determine service type from certificate information."""
        if not provider:
            return None
        
        service_patterns = self.cloud_signatures.get(provider, {}).get("service_patterns", {})
        
        # Check subject common name
        for rdn in subject:
            if isinstance(rdn, tuple) and len(rdn) >= 2:
                attr_type, attr_value = rdn[0], rdn[1]
                if attr_type == "commonName":
                    cn = attr_value if isinstance(attr_value, str) else str(attr_value)
                    
                    for service_type, patterns in service_patterns.items():
                        for pattern in patterns:
                            if re.match(pattern, cn, re.IGNORECASE):
                                return service_type
        
        # Check subject alternative names
        for san in sans:
            if isinstance(san, tuple) and len(san) >= 2:
                san_type, san_value = san[0], san[1]
                if san_type == "DNS":
                    san_name = san_value if isinstance(san_value, str) else str(san_value)
                    
                    for service_type, patterns in service_patterns.items():
                        for pattern in patterns:
                            if re.match(pattern, san_name, re.IGNORECASE):
                                return service_type
        
        return None
    
    def _determine_service_from_headers(self, provider: Optional[CloudProvider], 
                                     headers: Dict[str, str]) -> Optional[CloudServiceType]:
        """Determine service type from HTTP headers."""
        if not provider:
            return None
        
        # This is a simplified implementation
        # Real implementation would analyze specific headers for service indicators
        
        # Check for service-specific headers
        server_header = headers.get("server", "").lower()
        
        if provider == CloudProvider.AWS:
            if "elb" in server_header:
                return CloudServiceType.LOAD_BALANCER
            elif "s3" in server_header:
                return CloudServiceType.STORAGE
            elif "api-gateway" in server_header:
                return CloudServiceType.SERVERLESS
        elif provider == CloudProvider.AZURE:
            if "app-service" in server_header:
                return CloudServiceType.COMPUTE
            elif "azure-front" in server_header:
                return CloudServiceType.CDN
        elif provider == CloudProvider.GCP:
            if "gws" in server_header:
                return CloudServiceType.COMPUTE
            elif "gcs" in server_header:
                return CloudServiceType.STORAGE
            elif "cloudfunctions" in server_header:
                return CloudServiceType.SERVERLESS
        
        return None
    
    def _determine_primary_provider(self, fingerprints: List[CloudFingerprint]) -> Tuple[Optional[CloudProvider], float]:
        """Determine primary cloud provider from fingerprints."""
        provider_votes = {}
        total_confidence = 0
        
        for fingerprint in fingerprints:
            if fingerprint.provider:
                provider_votes[fingerprint.provider] = provider_votes.get(fingerprint.provider, 0) + fingerprint.confidence
                total_confidence += fingerprint.confidence
        
        if not provider_votes:
            return None, 0.0
        
        # Find provider with highest votes
        primary_provider = None
        max_votes = 0
        for provider, votes in provider_votes.items():
            if votes > max_votes:
                max_votes = votes
                primary_provider = provider
        
        # Calculate confidence
        confidence = min(1.0, max_votes / total_confidence) if total_confidence > 0 else 0.0
        
        return primary_provider, confidence
    
    def _determine_primary_service(self, fingerprints: List[CloudFingerprint]) -> Tuple[Optional[CloudServiceType], float]:
        """Determine primary service type from fingerprints."""
        service_votes = {}
        total_confidence = 0
        
        for fingerprint in fingerprints:
            if fingerprint.service_type:
                service_votes[fingerprint.service_type] = service_votes.get(fingerprint.service_type, 0) + fingerprint.confidence
                total_confidence += fingerprint.confidence
        
        if not service_votes:
            return None, 0.0
        
        # Find service type with highest votes
        primary_service = None
        max_votes = 0
        for service_type, votes in service_votes.items():
            if votes > max_votes:
                max_votes = votes
                primary_service = service_type
        
        # Calculate confidence
        confidence = min(1.0, max_votes / total_confidence) if total_confidence > 0 else 0.0
        
        return primary_service, confidence
    
    def _assess_cloud_security(self, fingerprints: List[CloudFingerprint], 
                           provider: Optional[CloudProvider]) -> List[str]:
        """Assess cloud security configuration."""
        assessment = []
        
        if not provider:
            assessment.append("Unable to determine cloud provider")
            return assessment
        
        # Provider-specific security assessments
        if provider == CloudProvider.AWS:
            assessment.extend([
                "Check for AWS security groups configuration",
                "Verify IAM role permissions",
                "Review VPC network ACLs",
                "Monitor CloudTrail logs",
                "Check for exposed S3 buckets"
            ])
        elif provider == CloudProvider.AZURE:
            assessment.extend([
                "Check Azure Network Security Groups",
                "Verify Azure AD permissions",
                "Review Azure Monitor logs",
                "Check for exposed storage accounts",
                "Validate Azure Key Vault access"
            ])
        elif provider == CloudProvider.GCP:
            assessment.extend([
                "Check GCP firewall rules",
                "Verify IAM service account permissions",
                "Review Cloud Audit logs",
                "Check for exposed Cloud Storage buckets",
                "Validate GCP KMS access"
            ])
        
        # General cloud security recommendations
        assessment.extend([
            "Implement proper cloud access controls",
            "Use cloud-native security services",
            "Enable comprehensive logging and monitoring",
            "Regularly review cloud configurations",
            "Implement cloud security best practices"
        ])
        
        return assessment
    
    def _generate_recommendations(self, fingerprints: List[CloudFingerprint], 
                               provider: Optional[CloudProvider]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        if not provider:
            recommendations.extend([
                "Unable to determine cloud provider",
                "Consider manual verification of cloud infrastructure",
                "Review network routing and DNS configuration"
            ])
            return recommendations
        
        # Provider-specific recommendations
        if provider == CloudProvider.AWS:
            recommendations.extend([
                "Use AWS IAM roles instead of access keys when possible",
                "Implement VPC with proper subnet segmentation",
                "Enable AWS CloudTrail for comprehensive logging",
                "Use AWS WAF for web application protection",
                "Regularly rotate IAM credentials"
            ])
        elif provider == CloudProvider.AZURE:
            recommendations.extend([
                "Use Azure AD for centralized identity management",
                "Implement Azure Network Security Groups",
                "Enable Azure Monitor for comprehensive logging",
                "Use Azure Security Center for threat protection",
                "Regularly review Azure AD permissions"
            ])
        elif provider == CloudProvider.GCP:
            recommendations.extend([
                "Use GCP IAM service accounts with least privilege",
                "Implement GCP firewall rules",
                "Enable Cloud Audit logs for comprehensive logging",
                "Use GCP Security Command Center for threat protection",
                "Regularly review GCP project permissions"
            ])
        
        # General recommendations
        recommendations.extend([
            "Implement cloud security monitoring",
            "Use cloud-native security tools",
            "Regular security assessments",
            "Implement proper access controls",
            "Maintain cloud security best practices"
        ])
        
        return recommendations
    
    def generate_cloud_report(self, result: CloudIntelResult) -> str:
        """Generate human-readable cloud intelligence report."""
        report = []
        report.append("Cloud Provider Metadata Intelligence Report")
        report.append("=" * 50)
        report.append(f"Target IP: {result.target_ip}")
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Primary Provider: {result.primary_provider.value if result.primary_provider else 'Unknown'}")
        report.append(f"Primary Service: {result.primary_service.value if result.primary_service else 'Unknown'}")
        report.append(f"Provider Confidence: {result.provider_confidence:.2f}")
        report.append(f"Service Confidence: {result.service_confidence:.2f}")
        report.append("")
        
        if result.cloud_fingerprints:
            report.append("Cloud Fingerprints:")
            for i, fingerprint in enumerate(result.cloud_fingerprints):
                report.append(f"  {i+1}. Provider: {fingerprint.provider.value if fingerprint.provider else 'Unknown'}")
                report.append(f"     Service: {fingerprint.service_type.value if fingerprint.service_type else 'Unknown'}")
                report.append(f"     Confidence: {fingerprint.confidence:.2f}")
                if fingerprint.indicators:
                    report.append(f"     Indicators: {', '.join(fingerprint.indicators[:3])}")
                report.append("")
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
_cloud_intel = None

def get_cloud_intel() -> CloudMetadataIntelligence:
    """Get global cloud intelligence instance."""
    global _cloud_intel
    if _cloud_intel is None:
        _cloud_intel = CloudMetadataIntelligence()
    return _cloud_intel

def analyze_cloud_provider(target_ip: str, target_host: str = None) -> CloudIntelResult:
    """Convenience function for cloud provider analysis."""
    intel = get_cloud_intel()
    return intel.analyze_cloud_provider(target_ip, target_host)

def generate_cloud_report(result: CloudIntelResult) -> str:
    """Convenience function for cloud report generation."""
    intel = get_cloud_intel()
    return intel.generate_cloud_report(result)
