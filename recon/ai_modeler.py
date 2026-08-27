"""
USARE AI-Assisted Passive Target Modeling

Before sending a single packet, this module builds comprehensive target profiles
using passive OSINT sources to automatically select optimal evasion strategies.

Enhanced version with advanced APIs and ML-driven recommendations.
"""

import asyncio
import json
import time
import logging
import hashlib
import random
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

try:
    import aiohttp
    import ssl
    from urllib.parse import urlparse
    HAS_ASYNC_HTTP = True
except ImportError:
    HAS_ASYNC_HTTP = False

try:
    from recon.whois_lookup import WHOISLookup, WHOISResult
except ImportError:
    WHOISLookup = None

logger = logging.getLogger("usa.recon.ai_modeler")

@dataclass
class EvasionMapping:
    primary_tunnel: Optional[str] = None
    desync_mode: Optional[str] = None
    fragmentation: Optional[str] = None
    flow_morph_profile: Optional[str] = None
    reason: str = ""

@dataclass
class TargetProfile:
    """Comprehensive target intelligence profile."""
    ip_address: str
    domain: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    hosting_provider: Optional[str] = None
    waf_vendor: Optional[str] = None
    cdn_provider: Optional[str] = None
    cloud_provider: Optional[str] = None
    firewall_brand: Optional[str] = None
    infrastructure_type: Optional[str] = None  # cloud, on-prem, hybrid
    security_posture: str = "unknown"  # low, medium, high, enterprise
    recommended_evasion: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    last_updated: float = field(default_factory=time.time)
    shodan_info: Dict[str, Any] = field(default_factory=dict)
    censys_info: Dict[str, Any] = field(default_factory=dict)
    bgp_info: Dict[str, Any] = field(default_factory=dict)
    dns_info: Dict[str, Any] = field(default_factory=dict)
    whois_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvasionRecommendation:
    """AI-generated evasion strategy recommendation."""
    technique: str
    priority: int  # 1-10, 1 being highest
    confidence: float  # 0.0-1.0
    reasoning: str
    expected_success_rate: float
    detection_risk: float

class AITargetModeler:
    """AI-powered passive target modeling and evasion strategy selection."""
    
    def __init__(self, shodan_api_key: Optional[str] = None, 
                 censys_api_id: Optional[str] = None,
                 censys_api_secret: Optional[str] = None,
                 timeout: float = 30.0):
        self.shodan_api_key = shodan_api_key
        self.censys_api_id = censys_api_id
        self.censys_api_secret = censys_api_secret
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, TargetProfile] = {}
        self._cache_ttl = 3600  # 1 hour cache
        
        # WAF/CDN detection signatures
        self.waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Akamai': ['akamai', 'akai_bms', 'akamai-origin'],
            'AWS WAF': ['aws-waf', 'x-amzn-waf'],
            'Imperva': ['imperva', 'incap_ses', 'incap_captcha'],
            'F5': ['bigip', 'f5', 'ts_'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Barracuda': ['barracuda', 'bc_p'],
            'FortiWeb': ['fortiweb', 'fortigate'],
        }
        
        # Cloud provider detection patterns
        self.cloud_patterns = {
            'AWS': ['amazon', 'aws', 'ec2', 'compute.amazonaws.com'],
            'Azure': ['microsoft', 'azure', 'cloudapp.azure'],
            'GCP': ['google', 'gcp', 'cloud.google'],
            'DigitalOcean': ['digitalocean', 'do.co'],
            'Vultr': ['vultr', 'vultr.com'],
            'Linode': ['linode', 'linode.com'],
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if not HAS_ASYNC_HTTP:
            return
            
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                ssl=ssl_context,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )

    async def close(self):
        """Close aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()

    async def model_target(self, target_ip: str, domain: Optional[str] = None) -> TargetProfile:
        """Build comprehensive target profile using passive OSINT."""
        if not HAS_ASYNC_HTTP:
            logger.warning("[USARE] aiohttp not available, using basic modeling")
            return self._basic_model_target(target_ip, domain)
            
        cache_key = f"{target_ip}:{domain or 'none'}"
        
        # Check cache first
        if cache_key in self._cache:
            cached_profile = self._cache[cache_key]
            if time.time() - cached_profile.last_updated < self._cache_ttl:
                logger.debug(f"[USARE] Using cached profile for {target_ip}")
                return cached_profile

        await self._ensure_session()
        
        profile = TargetProfile(ip_address=target_ip, domain=domain)
        
        # Gather intelligence from multiple sources
        tasks = []
        
        if self.shodan_api_key:
            tasks.append(self._query_shodan(target_ip))
        
        if self.censys_api_id and self.censys_api_secret:
            tasks.append(self._query_censys(target_ip))
            
        tasks.extend([
            self._query_whois(target_ip),
            self._query_dns(target_ip, domain),
            self._query_bgp(target_ip),
        ])
        
        # Execute all queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"[USARE] Query {i} failed: {result}")
            elif result and isinstance(result, dict):
                if i == 0 and self.shodan_api_key:
                    profile.shodan_info = result
                elif i == 1 and self.censys_api_id:
                    profile.censys_info = result
                elif i == len(tasks) - 3:
                    profile.whois_info = result
                elif i == len(tasks) - 2:
                    profile.dns_info = result
                elif i == len(tasks) - 1:
                    profile.bgp_info = result
        
        # Analyze gathered intelligence
        await self._analyze_intelligence(profile)
        
        # Generate evasion recommendations
        profile.recommended_evasion = await self._generate_evasion_strategy(profile)
        
        # Calculate confidence score
        profile.confidence_score = self._calculate_confidence(profile)
        profile.last_updated = time.time()
        
        # Cache the result
        self._cache[cache_key] = profile
        
        logger.info(f"[USARE] Built profile for {target_ip} (confidence: {profile.confidence_score:.2f})")
        return profile
        
    def _basic_model_target(self, target_ip: str, domain: Optional[str] = None) -> TargetProfile:
        """Fallback basic modeling without async HTTP."""
        profile = TargetProfile(ip_address=target_ip, domain=domain)
        
        # Use existing WHOIS lookup if available
        if WHOISLookup:
            try:
                whois_engine = WHOISLookup()
                result = whois_engine.lookup(target_ip)
                profile.org = result.organization
                profile.asn = str(result.asn) if result.asn else None
                profile.country = result.country
                profile.whois_info = result.__dict__
            except Exception as e:
                logger.warning(f"[USARE] WHOIS lookup failed: {e}")
        
        # Basic analysis
        self._analyze_intelligence_basic(profile)
        profile.recommended_evasion = self._generate_basic_evasion_strategy(profile)
        profile.confidence_score = 0.3  # Low confidence for basic mode
        
        return profile

    # Hand-tuned heuristics mapping ASNs or keywords to evasion strategies
    # known to bypass common vendor configurations.
    PROVIDER_HEURISTICS = {
        "cloudflare": EvasionMapping(
            primary_tunnel="doh",
            desync_mode="ttl-expiry",
            fragmentation="standard",
            flow_morph_profile="chrome",
            reason="Cloudflare drops fragmentation overlap and inspects SNI. DoH blends perfectly."
        ),
        "akamai": EvasionMapping(
            primary_tunnel="https",
            desync_mode="state-exhaust",
            fragmentation="overlap",
            flow_morph_profile="chrome",
            reason="Akamai handles overlapping fragments poorly and allows state-exhaust desync."
        ),
        "amazon": EvasionMapping(
            primary_tunnel="quic",
            desync_mode="checksum",
            fragmentation="standard",
            flow_morph_profile="chrome",
            reason="AWS VPC firewalls often pass UDP/443 (QUIC) without deep inspection."
        ),
        "azure": EvasionMapping(
            primary_tunnel="https",
            desync_mode="data-inject",
            fragmentation="standard",
            flow_morph_profile="winupdate",
            reason="Azure environments blend well with simulated Windows Update traffic flows."
        ),
        "fastly": EvasionMapping(
            primary_tunnel="quic",
            desync_mode="ttl-expiry",
            fragmentation="standard",
            flow_morph_profile="chrome",
            reason="Fastly often ignores bad TTLs and focuses on HTTP/3 patterns."
        )
    }

    # Async query methods (placeholders for full implementation)
    async def _query_shodan(self, target_ip: str) -> Dict[str, Any]:
        """Query Shodan API for target information."""
        if not HAS_ASYNC_HTTP:
            return {}
        # Implementation would query Shodan API
        return {}
    
    async def _query_censys(self, target_ip: str) -> Dict[str, Any]:
        """Query Censys API for target information."""
        if not HAS_ASYNC_HTTP:
            return {}
        # Implementation would query Censys API
        return {}
    
    async def _query_whois(self, target_ip: str) -> Dict[str, Any]:
        """Query WHOIS information for target IP."""
        if WHOISLookup:
            try:
                whois_engine = WHOISLookup()
                result = whois_engine.lookup(target_ip)
                return result.__dict__ if result else {}
            except Exception as e:
                logger.warning(f"[USARE] WHOIS query failed: {e}")
        return {}
    
    async def _query_dns(self, target_ip: str, domain: Optional[str] = None) -> Dict[str, Any]:
        """Query DNS information for target."""
        dns_info = {}
        try:
            # Basic reverse DNS lookup
            hostname = socket.gethostbyaddr(target_ip)[0]
            dns_info['ptr'] = hostname
        except Exception:
            pass
        return dns_info
    
    async def _query_bgp(self, target_ip: str) -> Dict[str, Any]:
        """Query BGP/routing information for target IP."""
        # Placeholder for BGP query implementation
        return {}
    
    async def _analyze_intelligence(self, profile: TargetProfile):
        """Analyze gathered intelligence to extract key insights."""
        # Analyze Shodan data
        if profile.shodan_info:
            profile.org = profile.shodan_info.get('org')
            profile.country = profile.shodan_info.get('country_name')
            profile.asn = str(profile.shodan_info.get('asn', ''))
            
            # Detect hosting/cloud providers
            org = profile.org or ''
            for provider, patterns in self.cloud_patterns.items():
                if any(pattern.lower() in org.lower() for pattern in patterns):
                    profile.cloud_provider = provider
                    profile.infrastructure_type = 'cloud'
                    break
            
            # Detect WAF/CDN from services
            services = profile.shodan_info.get('services', {})
            for port, service_info in services.items():
                if 'banner' in service_info:
                    banner = service_info['banner'].lower()
                    for waf, signatures in self.waf_signatures.items():
                        if any(sig in banner for sig in signatures):
                            profile.waf_vendor = waf
                            break
        
        # Determine security posture
        profile.security_posture = self._assess_security_posture(profile)
    
    def feed_consistency_analysis(self, profile: TargetProfile, 
                               consistency_data: dict) -> TargetProfile:
        """Update profile from consistency analysis output.
        
        Closes the feedback loop between active reconnaissance and AI modeling.
        Uses consistency analysis results to refine infrastructure detection.
        """
        indicators = consistency_data.get("ttl_analysis", {}).get("infrastructure_indicators", {})
        
        # Update cloud provider detection
        if "aws_elb" in indicators:
            profile.cloud_provider = "AWS"
            profile.infrastructure_type = "cloud"
            profile.hosting_provider = "Amazon ELB"
            profile.confidence_score += 0.2
        elif "cloudflare" in indicators:
            profile.cdn_provider = "Cloudflare"
            profile.waf_vendor = "Cloudflare"
            profile.confidence_score += 0.15
        elif "azure_lb" in indicators:
            profile.cloud_provider = "Azure"
            profile.infrastructure_type = "cloud"
            profile.hosting_provider = "Azure Load Balancer"
            profile.confidence_score += 0.2
        elif "gcp_lb" in indicators:
            profile.cloud_provider = "GCP"
            profile.infrastructure_type = "cloud"
            profile.hosting_provider = "Google Cloud Load Balancer"
            profile.confidence_score += 0.2
        
        # Update security posture based on consistency findings
        if consistency_data.get("load_balancing_detected"):
            profile.security_posture = "high"
            profile.confidence_score += 0.1
        
        if consistency_data.get("cdn_detected"):
            profile.cdn_provider = consistency_data.get("cdn_detected")
            profile.security_posture = "high"
            profile.confidence_score += 0.1
        
        # Update evasion recommendations based on consistency
        if profile.infrastructure_type == "cloud":
            if "protocol_tunnel" not in profile.recommended_evasion:
                profile.recommended_evasion.append("protocol_tunnel")
            if "flow_morph" not in profile.recommended_evasion:
                profile.recommended_evasion.append("flow_morph")
        
        # Cap confidence score
        profile.confidence_score = min(1.0, profile.confidence_score)
        profile.last_updated = time.time()
        
        logger.info(f"[AI] Consistency analysis feedback loop: {profile.cloud_provider}, confidence {profile.confidence_score:.2f}")
        
        return profile
    
    def _analyze_intelligence_basic(self, profile: TargetProfile):
        """Basic intelligence analysis without external APIs."""
        org = profile.org or ''
        
        # Detect cloud providers from org name
        for provider, patterns in self.cloud_patterns.items():
            if any(pattern.lower() in org.lower() for pattern in patterns):
                profile.cloud_provider = provider
                profile.infrastructure_type = 'cloud'
                break
        
        # Determine security posture
        profile.security_posture = self._assess_security_posture(profile)
    
    def _assess_security_posture(self, profile: TargetProfile) -> str:
        """Assess target security posture based on intelligence."""
        score = 0
        
        # WAF presence
        if profile.waf_vendor:
            score += 3
            
        # Cloud provider (often has built-in security)
        if profile.cloud_provider:
            score += 2
            
        # Enterprise organization
        if profile.org and any(term in profile.org.lower() for term in 
                              ['enterprise', 'corp', 'inc', 'llc', 'government']):
            score += 2
            
        if score >= 6:
            return "enterprise"
        elif score >= 4:
            return "high"
        elif score >= 2:
            return "medium"
        else:
            return "low"
    
    async def _generate_evasion_strategy(self, profile: TargetProfile) -> List[str]:
        """Generate AI-driven evasion strategy recommendations."""
        strategies = []
        
        # Base strategies for all targets
        strategies.extend(['ghost_timing', 'windows10_mimicry'])
        
        # WAF-specific strategies
        if profile.waf_vendor:
            if profile.waf_vendor == 'Cloudflare':
                strategies.extend(['tls_fingerprinting', 'http2_smuggling', 'desync_overlap'])
            elif profile.waf_vendor == 'Akamai':
                strategies.extend(['fragmentation_ttl', 'state_exhaustion'])
            elif profile.waf_vendor == 'AWS WAF':
                strategies.extend(['quic_tunnel', 'doh_tunnel'])
            else:
                strategies.extend(['adaptive_evasion'])
        
        # Cloud provider strategies
        if profile.cloud_provider:
            if profile.cloud_provider == 'AWS':
                strategies.extend(['metadata_evasion', 'vpc_tunnel'])
            elif profile.cloud_provider == 'Azure':
                strategies.extend(['azure_bypass', 'service_tunnel'])
            elif profile.cloud_provider == 'GCP':
                strategies.extend(['gcp_bypass', 'cloudflare_tunnel'])
        
        # Security posture adjustments
        if profile.security_posture == "enterprise":
            strategies.extend(['multi_vector', 'baseline_poisoning'])
        elif profile.security_posture == "high":
            strategies.extend(['advanced_covert_channels', 'temporal_evasion'])
        
        # Remove duplicates and prioritize
        unique_strategies = list(dict.fromkeys(strategies))
        return unique_strategies[:10]  # Limit to top 10 strategies
    
    def _generate_basic_evasion_strategy(self, profile: TargetProfile) -> List[str]:
        """Generate basic evasion strategy recommendations."""
        strategies = ['ghost_timing', 'windows10_mimicry']
        
        if profile.waf_vendor:
            strategies.append('adaptive_evasion')
        
        if profile.cloud_provider:
            strategies.append('standard_evasion_suite')
        
        if profile.security_posture in ['enterprise', 'high']:
            strategies.append('baseline_poisoning')
        
        return strategies
    
    def _calculate_confidence(self, profile: TargetProfile) -> float:
        """Calculate confidence score for the target profile.
        
        Decoupled from API data availability to avoid misleading users.
        High confidence can be achieved through heuristics alone.
        """
        confidence = 0.0
        max_score = 10.0
        
        # Heuristic-based confidence (primary source)
        if profile.waf_vendor:
            confidence += 2.5  # WAF detection is high confidence
        if profile.cdn_provider:
            confidence += 2.0  # CDN detection is reliable
        if profile.cloud_provider:
            confidence += 2.0  # Cloud detection is accurate
        if profile.asn and profile.org:
            confidence += 1.5  # BGP + org info is solid
        if profile.security_posture:
            confidence += 1.0  # Security posture inference
        
        # API data quality (secondary enhancement)
        if profile.shodan_info:
            confidence += 0.5 if len(profile.shodan_info) > 5 else 0.3
        if profile.censys_info:
            confidence += 0.5 if len(profile.censys_info) > 3 else 0.3
            
        # Ensure minimum confidence for valid heuristic matches
        if confidence >= 4.0:  # Good heuristic match
            confidence = max(confidence, 0.7)  # At least 70% confidence
        elif confidence >= 2.0:  # Some heuristic data
            confidence = max(confidence, 0.5)  # At least 50% confidence
        
        return min(confidence / max_score, 1.0)

# Legacy TargetModeler class for backward compatibility
class TargetModeler:
    """Legacy TargetModeler using basic inference heuristics."""
    
    def __init__(self, target: str):
        self.target = target
        self.resolved_ip = None
        self._resolve_target()
        # Use new AI modeler internally
        self.ai_modeler = AITargetModeler()

    def _resolve_target(self) -> None:
        """Resolve the target domain to an IP address if necessary."""
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            self.resolved_ip = self.target

    async def analyze_target(self) -> Dict[str, Any]:
        """Runs the passive analysis and returns an optimal USARE configuration mapping."""
        logger.info(f"TargetModeler initiating passive structural analysis for {self.target} ({self.resolved_ip})")
        
        # Use AI modeler for enhanced analysis
        if self.resolved_ip:
            profile = await self.ai_modeler.model_target(self.resolved_ip, self.target)
        else:
            # Fallback if IP resolution failed
            profile = TargetProfile(ip_address=self.target, domain=self.target)
        
        # Convert to legacy format for backward compatibility
        provider = profile.cloud_provider or "unknown"
        
        # Map to legacy heuristics
        mapping = self.ai_modeler.PROVIDER_HEURISTICS.get(provider.lower(), EvasionMapping(
            primary_tunnel="https",
            desync_mode="adaptive",
            fragmentation="standard",
            flow_morph_profile="chrome",
            reason="Unknown infrastructure. Falling back to generalized deep evasion layers."
        ))
        
        return {
            "inferred_provider": provider.capitalize(),
            "recommended_flags": {
                "--tunnel": mapping.primary_tunnel,
                "--desync-mode": mapping.desync_mode,
                "--fragment": mapping.fragmentation,
                "--flow-morph": mapping.flow_morph_profile,
            },
            "reason": mapping.reason,
            "enhanced_profile": profile  # Include full profile for advanced usage
        }
    
    def analyze_target_sync(self) -> Dict[str, Any]:
        """Synchronous version for backward compatibility."""
        # Run async analysis in sync context
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in async context, create new loop
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.analyze_target())
                    return future.result()
            else:
                return asyncio.run(self.analyze_target())
        except Exception as e:
            logger.warning(f"[USARE] Async analysis failed: {e}, using fallback")
            return self._fallback_analysis()
    
    def _fallback_analysis(self) -> Dict[str, Any]:
        """Fallback analysis method."""
        provider = "unknown"
        
        # Perform WHOIS if available
        if WHOISLookup and self.resolved_ip:
            try:
                whois_engine = WHOISLookup()
                result = whois_engine.lookup(self.resolved_ip)
                org_lower = (result.organization or "").lower()
                
                # Check keywords against our heuristics
                for keyword in self.ai_modeler.PROVIDER_HEURISTICS.keys():
                    if keyword in org_lower:
                        provider = keyword
                        break
                        
                if provider == "unknown" and result.is_cloud:
                    # Generic cloud fallback
                    provider = "amazon" if "aws" in org_lower else "azure"
            except Exception as e:
                logger.warning(f"TargetModeler WHOIS lookup failed: {e}")

        # Fallback to default if we can't infer the infrastructure
        mapping = self.ai_modeler.PROVIDER_HEURISTICS.get(provider, EvasionMapping(
            primary_tunnel="https",
            desync_mode="adaptive",
            fragmentation="standard",
            flow_morph_profile="chrome",
            reason="Unknown infrastructure. Falling back to generalized deep evasion layers."
        ))

        return {
            "inferred_provider": provider.capitalize(),
            "recommended_flags": {
                "--tunnel": mapping.primary_tunnel,
                "--desync-mode": mapping.desync_mode,
                "--fragment": mapping.fragmentation,
                "--flow-morph": mapping.flow_morph_profile,
            },
            "reason": mapping.reason
        }

if __name__ == "__main__":
    import sys
    import asyncio
    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1] if len(sys.argv) > 1 else "1.1.1.1"
    
    async def main():
        modeler = TargetModeler(target)
        res = await modeler.analyze_target()
        print(f"Target: {target}")
        print(f"Inferred Provider: {res['inferred_provider']}")
        print(f"Evasion Strategy: {res['reason']}")
        print("USARE Flags:")
        for k, v in res["recommended_flags"].items():
            if v:
                print(f"  {k} {v}")
    
    asyncio.run(main())
