"""Passive DNS Timeline Analysis for Infrastructure Change Reconstruction.

Correlates DNS TTL changes, CNAME chain modifications, and IP transitions
over time to reconstruct infrastructure evolution and identify misconfigurations.

Uses SecurityTrails, Farsight DNSDB, VirusTotal, and other passive DNS
sources to build comprehensive infrastructure change timelines.
"""

import logging
import time
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("usare.pdns_timeline")

class DNSChangeType(Enum):
    A_RECORD_CHANGE = "a_record_change"
    CNAME_CHANGE = "cname_change"
    TTL_CHANGE = "ttl_change"
    NS_RECORD_CHANGE = "ns_record_change"
    MX_RECORD_CHANGE = "mx_record_change"
    SUBDOMAIN_ADDED = "subdomain_added"
    SUBDOMAIN_REMOVED = "subdomain_removed"
    CLOUD_MIGRATION = "cloud_migration"
    CDN_DEPLOYMENT = "cdn_deployment"
    LOAD_BALANCER_CHANGE = "load_balancer_change"

@dataclass
class DNSChangeEvent:
    """DNS change event."""
    timestamp: datetime
    change_type: DNSChangeType
    domain: str
    old_value: Optional[str]
    new_value: Optional[str]
    old_ttl: Optional[int]
    new_ttl: Optional[int]
    source: str
    confidence: float
    infrastructure_impact: str

@dataclass
class PDNSTimelineResult:
    """Passive DNS timeline analysis result."""
    target_domain: str
    analysis_period: Tuple[datetime, datetime]
    changes: List[DNSChangeEvent]
    infrastructure_events: List[Dict[str, Any]]
    migration_timeline: List[Dict[str, Any]]
    security_implications: List[str]
    confidence_score: float
    recommendations: List[str]

class PDNSTimelineAnalyzer:
    """Advanced passive DNS timeline analyzer."""
    
    def __init__(self):
        self.pdns_sources = {
            "securitytrails": {
                "url": "https://api.securitytrails.com/v1/",
                "rate_limit": 1000,  # requests/hour
                "auth_required": True
            },
            "farsight": {
                "url": "https://api.dnsdb.info/v1/",
                "rate_limit": 1000,
                "auth_required": True
            },
            "virustotal": {
                "url": "https://www.virustotal.com/vtapi/v2/",
                "rate_limit": 4,  # requests/minute
                "auth_required": True
            },
            "passivetotal": {
                "url": "https://api.passivetotal.org/v2/",
                "rate_limit": 500,
                "auth_required": True
            }
        }
        
        # Infrastructure patterns
        self.infrastructure_patterns = {
            "cloud_providers": {
                "aws": {
                    "ip_ranges": ["3.", "52.", "54.", "107.", "172.", "204.", "205.", "208.", "23."],
                    "cname_patterns": [".amazonaws.com", ".cloudfront.net", ".elb.amazonaws.com"],
                    "ns_patterns": ["ns-*.awsdns-*.", "*.awsdns-*."]
                },
                "azure": {
                    "ip_ranges": ["13.", "20.", "40.", "52.", "104.", "168.", "172.", "191.", "204."],
                    "cname_patterns": [".azureedge.net", ".cloudapp.net", ".azurewebsites.net"],
                    "ns_patterns": ["ns1-*.azure-dns.com."]
                },
                "gcp": {
                    "ip_ranges": ["8.", "23.", "34.", "35.", "64.", "66.", "70.", "74.", "104.", "108.", "142.", "146.", "172.", "199.", "216."],
                    "cname_patterns": [".googleusercontent.com", ".gcp.gvt2.com", ".appspot.com"],
                    "ns_patterns": ["ns-cloud-*.google.com."]
                }
            },
            "cdn_providers": {
                "cloudflare": {
                    "ip_ranges": ["103.", "104.", "108.", "172.", "173.", "190.", "191.", "192.", "198.", "199.", "204.", "205.", "206.", "207.", "208.", "209.", "216."],
                    "cname_patterns": [".cloudflare.net", ".cdn.cloudflare.net"],
                    "ns_patterns": ["*.ns.cloudflare.com."]
                },
                "fastly": {
                    "ip_ranges": ["23.", "52.", "69.", "151.", "172.", "185.", "199.", "207.", "208.", "209.", "216."],
                    "cname_patterns": [".fastly.net", ".fastlylb.net"],
                    "ns_patterns": ["*.ns.fastly.net."]
                },
                "akamai": {
                    "ip_ranges": ["23.", "69.", "72.", "80.", "96.", "104.", "107.", "108.", "172.", "184.", "185.", "192.", "198.", "204.", "208.", "209.", "216."],
                    "cname_patterns": [".akamaiedge.net", ".akamaitechnologies.com", ".edgekey.net"],
                    "ns_patterns": ["*.ns.akamaiedge.net."]
                }
            }
        }
    
    def analyze_domain_timeline(self, target_domain: str, days_back: int = 365) -> PDNSTimelineResult:
        """Analyze passive DNS timeline for domain."""
        start_time = time.time()
        
        try:
            # Calculate analysis period
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            # Collect passive DNS data
            pdns_data = self._collect_pdns_data(target_domain, start_date, end_date)
            
            # Extract DNS changes
            changes = self._extract_dns_changes(pdns_data, target_domain)
            
            # Analyze infrastructure events
            infrastructure_events = self._analyze_infrastructure_events(changes, target_domain)
            
            # Build migration timeline
            migration_timeline = self._build_migration_timeline(changes, infrastructure_events)
            
            # Identify security implications
            security_implications = self._identify_security_implications(changes, infrastructure_events)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(changes, infrastructure_events, security_implications)
            
            # Calculate confidence score
            confidence = self._calculate_confidence(pdns_data, changes)
            
            return PDNSTimelineResult(
                target_domain=target_domain,
                analysis_period=(start_date, end_date),
                changes=changes,
                infrastructure_events=infrastructure_events,
                migration_timeline=migration_timeline,
                security_implications=security_implications,
                confidence_score=confidence,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"[PDNS Timeline] Analysis failed: {e}")
            return PDNSTimelineResult(
                target_domain=target_domain,
                analysis_period=(datetime.now() - timedelta(days=1), datetime.now()),
                changes=[],
                infrastructure_events=[],
                migration_timeline=[],
                security_implications=[f"Analysis failed: {e}"],
                confidence_score=0.0,
                recommendations=["Unable to complete analysis"]
            )
    
    def _collect_pdns_data(self, target_domain: str, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect passive DNS data from multiple sources."""
        pdns_data = {
            "a_records": [],
            "cname_records": [],
            "ns_records": [],
            "mx_records": [],
            "subdomains": [],
            "historical_data": []
        }
        
        if not HAS_REQUESTS:
            logger.warning("[PDNS Timeline] Requests library not available")
            return pdns_data
        
        # Try SecurityTrails
        try:
            st_data = self._query_securitytrails(target_domain, start_date, end_date)
            if st_data:
                pdns_data["historical_data"].extend(st_data.get("historical", []))
                pdns_data["subdomains"].extend(st_data.get("subdomains", []))
        except Exception as e:
            logger.debug(f"[PDNS Timeline] SecurityTrails query failed: {e}")
        
        # Try Farsight DNSDB
        try:
            farsight_data = self._query_farsight(target_domain, start_date, end_date)
            if farsight_data:
                pdns_data["historical_data"].extend(farsight_data.get("historical", []))
        except Exception as e:
            logger.debug(f"[PDNS Timeline] Farsight query failed: {e}")
        
        # Try VirusTotal
        try:
            vt_data = self._query_virustotal(target_domain, start_date, end_date)
            if vt_data:
                pdns_data["historical_data"].extend(vt_data.get("historical", []))
        except Exception as e:
            logger.debug(f"[PDNS Timeline] VirusTotal query failed: {e}")
        
        return pdns_data
    
    def _query_securitytrails(self, target_domain: str, start_date: datetime, end_date: datetime) -> Optional[Dict[str, Any]]:
        """Query SecurityTrails API."""
        try:
            # This is a simplified implementation
            # Real implementation would require API key
            url = f"https://api.securitytrails.com/v1/history/{target_domain}/dns/a"
            
            headers = {
                "Accept": "application/json",
                "User-Agent": "USARE-PDNS-Timeline/1.0"
            }
            
            # Add API key if available
            # headers["apikey"] = "your-api-key"
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract historical records
            historical = []
            for record in data.get("records", []):
                historical.append({
                    "timestamp": record.get("first_seen"),
                    "ip": record.get("ip"),
                    "ttl": record.get("ttl"),
                    "source": "securitytrails"
                })
            
            return {
                "historical": historical,
                "subdomains": [],  # Would need separate API call
                "source": "securitytrails"
            }
            
        except Exception as e:
            logger.debug(f"[PDNS Timeline] SecurityTrails query error: {e}")
            return None
    
    def _query_farsight(self, target_domain: str, start_date: datetime, end_date: datetime) -> Optional[Dict[str, Any]]:
        """Query Farsight DNSDB API."""
        try:
            url = f"https://api.dnsdb.info/v1/lookup/rrset/name/{target_domain}"
            
            headers = {
                "Accept": "application/json",
                "User-Agent": "USARE-PDNS-Timeline/1.0"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract historical records
            historical = []
            for record in data.get("data", []):
                historical.append({
                    "timestamp": record.get("time_first"),
                    "ip": record.get("rdata"),
                    "ttl": record.get("ttl"),
                    "source": "farsight"
                })
            
            return {
                "historical": historical,
                "source": "farsight"
            }
            
        except Exception as e:
            logger.debug(f"[PDNS Timeline] Farsight query error: {e}")
            return None
    
    def _query_virustotal(self, target_domain: str, start_date: datetime, end_date: datetime) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API."""
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            
            headers = {
                "User-Agent": "USARE-PDNS-Timeline/1.0"
            }
            
            params = {
                "domain": target_domain,
                "apikey": "your-api-key"  # Would need real API key
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract historical records
            historical = []
            if "resolutions" in data:
                for resolution in data["resolutions"]:
                    historical.append({
                        "timestamp": resolution.get("date"),
                        "ip": resolution.get("ip_address"),
                        "source": "virustotal"
                    })
            
            return {
                "historical": historical,
                "source": "virustotal"
            }
            
        except Exception as e:
            logger.debug(f"[PDNS Timeline] VirusTotal query error: {e}")
            return None
    
    def _extract_dns_changes(self, pdns_data: Dict[str, Any], target_domain: str) -> List[DNSChangeEvent]:
        """Extract DNS changes from passive DNS data."""
        changes = []
        
        # Process historical data
        historical_records = pdns_data.get("historical_data", [])
        
        # Sort by timestamp
        historical_records.sort(key=lambda x: x.get("timestamp", ""))
        
        # Track previous values
        previous_values = {}
        
        for record in historical_records:
            timestamp_str = record.get("timestamp", "")
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            ip = record.get("ip", "")
            ttl = record.get("ttl", 0)
            source = record.get("source", "unknown")
            
            # Check for A record changes
            if ip:
                if target_domain in previous_values:
                    old_ip = previous_values[target_domain].get("ip", "")
                    if old_ip != ip:
                        changes.append(DNSChangeEvent(
                            timestamp=timestamp,
                            change_type=DNSChangeType.A_RECORD_CHANGE,
                            domain=target_domain,
                            old_value=old_ip,
                            new_value=ip,
                            old_ttl=previous_values[target_domain].get("ttl"),
                            new_ttl=ttl,
                            source=source,
                            confidence=0.8,
                            infrastructure_impact=self._assess_infrastructure_impact("a_record_change", old_ip, ip)
                        ))
                
                previous_values[target_domain] = {"ip": ip, "ttl": ttl}
            
            # Check for TTL changes
            if ttl and target_domain in previous_values:
                old_ttl = previous_values[target_domain].get("ttl", 0)
                if old_ttl != ttl:
                    changes.append(DNSChangeEvent(
                        timestamp=timestamp,
                        change_type=DNSChangeType.TTL_CHANGE,
                        domain=target_domain,
                        old_value=str(old_ttl),
                        new_value=str(ttl),
                        old_ttl=old_ttl,
                        new_ttl=ttl,
                        source=source,
                        confidence=0.7,
                        infrastructure_impact=self._assess_infrastructure_impact("ttl_change", old_ttl, ttl)
                    ))
        
        return changes
    
    def _analyze_infrastructure_events(self, changes: List[DNSChangeEvent], target_domain: str) -> List[Dict[str, Any]]:
        """Analyze infrastructure events from DNS changes."""
        events = []
        
        # Group changes by type
        a_changes = [c for c in changes if c.change_type == DNSChangeType.A_RECORD_CHANGE]
        ttl_changes = [c for c in changes if c.change_type == DNSChangeType.TTL_CHANGE]
        
        # Detect cloud migrations
        cloud_events = self._detect_cloud_migrations(a_changes)
        events.extend(cloud_events)
        
        # Detect CDN deployments
        cdn_events = self._detect_cdn_deployments(a_changes)
        events.extend(cdn_events)
        
        # Detect load balancer changes
        lb_events = self._detect_load_balancer_changes(a_changes, ttl_changes)
        events.extend(lb_events)
        
        return events
    
    def _detect_cloud_migrations(self, a_changes: List[DNSChangeEvent]) -> List[Dict[str, Any]]:
        """Detect cloud migration events."""
        events = []
        
        for i, change in enumerate(a_changes):
            old_ip = change.old_value or ""
            new_ip = change.new_value or ""
            
            if not old_ip or not new_ip:
                continue
            
            # Check if old IP was on-premises and new is cloud
            old_cloud = self._identify_cloud_provider(old_ip)
            new_cloud = self._identify_cloud_provider(new_ip)
            
            if old_cloud != new_cloud:
                if old_cloud is None and new_cloud:
                    events.append({
                        "event_type": "cloud_migration",
                        "timestamp": change.timestamp,
                        "description": f"Migrated from on-premises to {new_cloud}",
                        "old_infrastructure": "on-premises",
                        "new_infrastructure": new_cloud,
                        "confidence": 0.9
                    })
                elif old_cloud and new_cloud and old_cloud != new_cloud:
                    events.append({
                        "event_type": "cloud_migration",
                        "timestamp": change.timestamp,
                        "description": f"Migrated from {old_cloud} to {new_cloud}",
                        "old_infrastructure": old_cloud,
                        "new_infrastructure": new_cloud,
                        "confidence": 0.8
                    })
        
        return events
    
    def _detect_cdn_deployments(self, a_changes: List[DNSChangeEvent]) -> List[Dict[str, Any]]:
        """Detect CDN deployment events."""
        events = []
        
        for i, change in enumerate(a_changes):
            old_ip = change.old_value or ""
            new_ip = change.new_value or ""
            
            if not old_ip or not new_ip:
                continue
            
            # Check if new IP belongs to CDN
            old_cdn = self._identify_cdn_provider(old_ip)
            new_cdn = self._identify_cdn_provider(new_ip)
            
            if new_cdn and old_cdn != new_cdn:
                events.append({
                    "event_type": "cdn_deployment",
                    "timestamp": change.timestamp,
                    "description": f"Deployed CDN: {new_cdn}",
                    "old_cdn": old_cdn or "none",
                    "new_cdn": new_cdn,
                    "confidence": 0.8
                })
        
        return events
    
    def _detect_load_balancer_changes(self, a_changes: List[DNSChangeEvent], ttl_changes: List[DNSChangeEvent]) -> List[Dict[str, Any]]:
        """Detect load balancer configuration changes."""
        events = []
        
        # Look for rapid IP changes with low TTL
        rapid_changes = []
        for i, change in enumerate(a_changes):
            if i > 0:
                time_diff = (change.timestamp - a_changes[i-1].timestamp).total_seconds()
                if time_diff < 300:  # Less than 5 minutes
                    rapid_changes.append(change)
        
        if len(rapid_changes) >= 3:
            events.append({
                "event_type": "load_balancer_change",
                "timestamp": rapid_changes[0].timestamp,
                "description": "Load balancer reconfiguration detected",
                "change_count": len(rapid_changes),
                "time_window": (rapid_changes[-1].timestamp - rapid_changes[0].timestamp).total_seconds(),
                "confidence": 0.7
            })
        
        # Look for TTL changes indicating load balancing
        low_ttl_changes = [c for c in ttl_changes if c.new_ttl and c.new_ttl < 300]
        if len(low_ttl_changes) >= 2:
            events.append({
                "event_type": "load_balancer_change",
                "timestamp": low_ttl_changes[0].timestamp,
                "description": "Load balancer TTL optimization detected",
                "ttls": [c.new_ttl for c in low_ttl_changes],
                "confidence": 0.6
            })
        
        return events
    
    def _identify_cloud_provider(self, ip: str) -> Optional[str]:
        """Identify cloud provider from IP address."""
        if not ip:
            return None
        
        # Extract first octet
        first_octet = ip.split('.')[0] if '.' in ip else ""
        
        for provider, info in self.infrastructure_patterns["cloud_providers"].items():
            for ip_range in info["ip_ranges"]:
                if ip.startswith(ip_range):
                    return provider
        
        return None
    
    def _identify_cdn_provider(self, ip: str) -> Optional[str]:
        """Identify CDN provider from IP address."""
        if not ip:
            return None
        
        first_octet = ip.split('.')[0] if '.' in ip else ""
        
        for provider, info in self.infrastructure_patterns["cdn_providers"].items():
            for ip_range in info["ip_ranges"]:
                if ip.startswith(ip_range):
                    return provider
        
        return None
    
    def _build_migration_timeline(self, changes: List[DNSChangeEvent], infrastructure_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build migration timeline from changes and events."""
        timeline = []
        
        # Combine changes and events
        all_events = []
        
        for change in changes:
            all_events.append({
                "timestamp": change.timestamp,
                "type": "dns_change",
                "change_type": change.change_type.value,
                "description": f"{change.change_type.value}: {change.old_value} -> {change.new_value}",
                "confidence": change.confidence
            })
        
        for event in infrastructure_events:
            all_events.append({
                "timestamp": event["timestamp"],
                "type": "infrastructure_event",
                "event_type": event["event_type"],
                "description": event["description"],
                "confidence": event["confidence"]
            })
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x["timestamp"])
        
        # Build timeline
        for event in all_events:
            timeline.append({
                "timestamp": event["timestamp"],
                "event_type": event["type"],
                "description": event["description"],
                "confidence": event["confidence"],
                "impact": self._assess_event_impact(event)
            })
        
        return timeline
    
    def _assess_infrastructure_impact(self, change_type: str, old_value: str, new_value: str) -> str:
        """Assess infrastructure impact of change."""
        if change_type == "a_record_change":
            old_cloud = self._identify_cloud_provider(old_value)
            new_cloud = self._identify_cloud_provider(new_value)
            
            if old_cloud != new_cloud:
                return "Major infrastructure change detected"
            else:
                return "Standard IP address change"
        
        elif change_type == "ttl_change":
            try:
                old_ttl = int(old_value) if old_value else 0
                new_ttl = int(new_value) if new_value else 0
                
                if new_ttl < 300:
                    return "Load balancing or CDN optimization"
                elif new_ttl > 86400:
                    return "Static IP assignment"
                else:
                    return "Standard TTL configuration"
            except:
                return "TTL configuration change"
        
        return "Infrastructure change"
    
    def _identify_security_implications(self, changes: List[DNSChangeEvent], infrastructure_events: List[Dict[str, Any]]) -> List[str]:
        """Identify security implications from DNS changes."""
        implications = []
        
        # Check for rapid IP changes
        a_changes = [c for c in changes if c.change_type == DNSChangeType.A_RECORD_CHANGE]
        if len(a_changes) > 10:
            implications.append("High frequency IP changes may indicate misconfiguration or active defense")
        
        # Check for very low TTL values
        low_ttl_changes = [c for c in changes if c.new_ttl and c.new_ttl < 60]
        if len(low_ttl_changes) > 0:
            implications.append("Very low TTL values may indicate load balancing or potential DNS hijacking")
        
        # Check for cloud migrations
        cloud_migrations = [e for e in infrastructure_events if e["event_type"] == "cloud_migration"]
        if cloud_migrations:
            implications.append("Cloud migration detected - review security configurations in new environment")
        
        # Check for CDN deployments
        cdn_deployments = [e for e in infrastructure_events if e["event_type"] == "cdn_deployment"]
        if cdn_deployments:
            implications.append("CDN deployment detected - ensure proper security headers and configurations")
        
        return implications
    
    def _generate_recommendations(self, changes: List[DNSChangeEvent], infrastructure_events: List[Dict[str, Any]], security_implications: List[str]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if len(changes) > 20:
            recommendations.append("High frequency DNS changes detected - consider implementing DNS change monitoring")
        
        if security_implications:
            recommendations.extend(security_implications)
        
        # Check for recent migrations
        recent_migrations = [e for e in infrastructure_events 
                            if e["event_type"] == "cloud_migration" 
                            and (datetime.now() - e["timestamp"]).days < 30]
        
        if recent_migrations:
            recommendations.append("Recent cloud migration detected - perform security assessment of new environment")
        
        return recommendations
    
    def _assess_event_impact(self, event: Dict[str, Any]) -> str:
        """Assess impact of DNS event."""
        if event.get("event_type") == "cloud_migration":
            return "High"
        elif event.get("event_type") == "cdn_deployment":
            return "Medium"
        elif event.get("change_type") == "a_record_change":
            return "Medium"
        elif event.get("change_type") == "ttl_change":
            return "Low"
        else:
            return "Unknown"
    
    def _calculate_confidence(self, pdns_data: Dict[str, Any], changes: List[DNSChangeEvent]) -> float:
        """Calculate confidence score for analysis."""
        if not pdns_data.get("historical_data"):
            return 0.0
        
        # Base confidence from data sources
        sources = set()
        for record in pdns_data.get("historical_data", []):
            sources.add(record.get("source", "unknown"))
        
        source_confidence = min(1.0, len(sources) / 3.0)
        
        # Confidence from change detection
        change_confidence = min(1.0, len(changes) / 10.0)
        
        # Combined confidence
        overall_confidence = (source_confidence + change_confidence) / 2.0
        
        return min(1.0, overall_confidence)
    
    def generate_timeline_report(self, result: PDNSTimelineResult) -> str:
        """Generate human-readable timeline report."""
        report = []
        report.append("Passive DNS Timeline Analysis Report")
        report.append("=" * 50)
        report.append(f"Target Domain: {result.target_domain}")
        report.append(f"Analysis Period: {result.analysis_period[0].strftime('%Y-%m-%d')} to {result.analysis_period[1].strftime('%Y-%m-%d')}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        if result.infrastructure_events:
            report.append("Infrastructure Events:")
            for event in result.infrastructure_events:
                report.append(f"  - {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {event['description']}")
                report.append(f"    Confidence: {event['confidence']:.2f}")
            report.append("")
        
        if result.migration_timeline:
            report.append("Migration Timeline:")
            for event in result.migration_timeline:
                report.append(f"  - {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {event['description']}")
                report.append(f"    Impact: {event['impact']}")
            report.append("")
        
        if result.security_implications:
            report.append("Security Implications:")
            for implication in result.security_implications:
                report.append(f"  - {implication}")
            report.append("")
        
        if result.recommendations:
            report.append("Recommendations:")
            for recommendation in result.recommendations:
                report.append(f"  - {recommendation}")
            report.append("")
        
        return "\n".join(report)

# Global instance
_pdns_analyzer = None

def get_pdns_analyzer() -> PDNSTimelineAnalyzer:
    """Get global PDNS timeline analyzer."""
    global _pdns_analyzer
    if _pdns_analyzer is None:
        _pdns_analyzer = PDNSTimelineAnalyzer()
    return _pdns_analyzer

def analyze_domain_timeline(target_domain: str, days_back: int = 365) -> PDNSTimelineResult:
    """Convenience function for PDNS timeline analysis."""
    analyzer = get_pdns_analyzer()
    return analyzer.analyze_domain_timeline(target_domain, days_back)

def generate_timeline_report(result: PDNSTimelineResult) -> str:
    """Convenience function for timeline report generation."""
    analyzer = get_pdns_analyzer()
    return analyzer.generate_timeline_report(result)
