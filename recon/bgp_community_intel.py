"""BGP Community Intelligence for Passive Network Topology Mapping.

Analyzes BGP community attributes from public route collectors to extract
organizational topology, datacenter locations, and infrastructure relationships.

Uses RIPE RIS, Route Views, and other public route collectors to
passively map network infrastructure without sending any packets.
"""

import logging
import time
import json
import re
import socket
import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("usare.bgp_community")

class BGPCommunityType(Enum):
    STANDARD = "standard"           # 16-bit communities
    EXTENDED = "extended"          # 32-bit extended communities
    LARGE = "large"               # 64-bit large communities
    WELL_KNOWN = "well_known"      # Well-known communities
    PRIVATE = "private"             # Private use communities

@dataclass
class BGPCommunityInfo:
    """BGP community information."""
    community: str
    community_type: str
    description: str
    purpose: str
    geographic_hint: Optional[str]
    datacenter_hint: Optional[str]
    service_hint: Optional[str]
    confidence: float

@dataclass
class BGPTopologyResult:
    """BGP topology analysis result."""
    target_asn: int
    target_prefix: str
    communities: List[BGPCommunityInfo]
    datacenter_locations: List[str]
    service_types: List[str]
    load_balancer_pools: List[str]
    failover_relationships: List[str]
    internal_topology: Dict[str, Any]
    confidence_score: float
    collection_timestamp: float

class BGPCommunityIntelligence:
    """Advanced BGP community intelligence analyzer."""
    
    def __init__(self):
        self.route_collectors = {
            "ripe_ris": {
                "url": "https://ris-live.ripe.net/v1/",
                "endpoints": ["bgp-data", "route-views"]
            },
            "route_views": {
                "url": "http://archive.routeviews.org/",
                "endpoints": ["bgpdata"]
            },
            "bgpstream": {
                "url": "https://bgpstream.caida.org/v2/",
                "endpoints": ["data"]
            }
        }
        
        # Well-known community patterns
        self.community_patterns = {
            # Geographic communities
            r"(\d+):(\d+):(\d+)": {
                "type": "geographic",
                "description": "Geographic location community",
                "confidence": 0.8
            },
            
            # Datacenter communities
            r"(\d+):(\d+)": {
                "type": "datacenter",
                "description": "Datacenter or facility community",
                "confidence": 0.7
            },
            
            # Service communities
            r"(\d+):(\d+):(\d+)": {
                "type": "service",
                "description": "Service-specific community",
                "confidence": 0.6
            }
        }
        
        # Major cloud provider community patterns
        self.cloud_patterns = {
            "aws": {
                "asn_ranges": [16509, 14618, 7224],
                "community_patterns": [r"16509:(\d+)", r"14618:(\d+)"],
                "datacenter_regions": {
                    "1": "us-east-1",
                    "2": "us-east-2", 
                    "3": "us-west-1",
                    "4": "us-west-2",
                    "5": "eu-west-1",
                    "6": "eu-west-2",
                    "7": "eu-central-1",
                    "8": "ap-southeast-1",
                    "9": "ap-southeast-2",
                    "10": "ap-northeast-1"
                }
            },
            "azure": {
                "asn_ranges": [8075, 12076],
                "community_patterns": [r"8075:(\d+)", r"12076:(\d+)"],
                "datacenter_regions": {
                    "1": "eastus",
                    "2": "westus",
                    "3": "centralus",
                    "4": "eastasia",
                    "5": "southeastasia",
                    "6": "westeurope",
                    "7": "northeurope"
                }
            },
            "gcp": {
                "asn_ranges": [15169, 36040, 43515],
                "community_patterns": [r"15169:(\d+)", r"36040:(\d+)"],
                "datacenter_regions": {
                    "1": "us-central1",
                    "2": "us-east1",
                    "3": "us-west1",
                    "4": "europe-west1",
                    "5": "europe-west2",
                    "6": "asia-east1",
                    "7": "asia-southeast1"
                }
            }
        }
    
    def analyze_bgp_communities(self, target_prefix: str, target_asn: int) -> BGPTopologyResult:
        """Analyze BGP communities for target prefix."""
        start_time = time.time()
        
        try:
            # Collect BGP data from multiple sources
            bgp_data = self._collect_bgp_data(target_prefix, target_asn)
            
            # Extract and analyze communities
            communities = self._extract_communities(bgp_data)
            
            # Analyze topology
            topology_analysis = self._analyze_topology(communities, target_asn)
            
            # Calculate confidence score
            confidence = self._calculate_confidence(communities, bgp_data)
            
            return BGPTopologyResult(
                target_asn=target_asn,
                target_prefix=target_prefix,
                communities=communities,
                datacenter_locations=topology_analysis["datacenter_locations"],
                service_types=topology_analysis["service_types"],
                load_balancer_pools=topology_analysis["load_balancer_pools"],
                failover_relationships=topology_analysis["failover_relationships"],
                internal_topology=topology_analysis["internal_topology"],
                confidence_score=confidence,
                collection_timestamp=time.time()
            )
            
        except Exception as e:
            logger.error(f"[BGP Intel] Analysis failed: {e}")
            return BGPTopologyResult(
                target_asn=target_asn,
                target_prefix=target_prefix,
                communities=[],
                datacenter_locations=[],
                service_types=[],
                load_balancer_pools=[],
                failover_relationships=[],
                internal_topology={},
                confidence_score=0.0,
                collection_timestamp=time.time()
            )
    
    def _collect_bgp_data(self, target_prefix: str, target_asn: int) -> Dict[str, Any]:
        """Collect BGP data from route collectors."""
        bgp_data = {
            "routes": [],
            "communities": [],
            "as_path": [],
            "nexthops": []
        }
        
        if not HAS_REQUESTS:
            logger.warning("[BGP Intel] Requests library not available")
            return bgp_data
        
        # Try RIPE RIS first
        try:
            ris_data = self._query_ripe_ris(target_prefix, target_asn)
            if ris_data:
                bgp_data["routes"].extend(ris_data.get("routes", []))
                bgp_data["communities"].extend(ris_data.get("communities", []))
        except Exception as e:
            logger.debug(f"[BGP Intel] RIPE RIS query failed: {e}")
        
        # Try Route Views
        try:
            rv_data = self._query_route_views(target_prefix, target_asn)
            if rv_data:
                bgp_data["routes"].extend(rv_data.get("routes", []))
                bgp_data["communities"].extend(rv_data.get("communities", []))
        except Exception as e:
            logger.debug(f"[BGP Intel] Route Views query failed: {e}")
        
        return bgp_data
    
    def _query_ripe_ris(self, target_prefix: str, target_asn: int) -> Optional[Dict[str, Any]]:
        """Query RIPE RIS for BGP data."""
        try:
            # RIPE RIS Live API
            url = f"https://ris-live.ripe.net/v1/lookup/?prefix={target_prefix}"
            
            headers = {
                "Accept": "application/json",
                "User-Agent": "USARE-BGP-Intel/1.0"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract communities from response
            communities = []
            for route in data.get("data", {}).get("announcements", []):
                for announcement in route.get("announcements", []):
                    for community in announcement.get("communities", []):
                        communities.append({
                            "community": community,
                            "source": "ripe_ris",
                            "timestamp": time.time()
                        })
            
            return {
                "routes": data.get("data", {}).get("announcements", []),
                "communities": communities,
                "source": "ripe_ris"
            }
            
        except Exception as e:
            logger.debug(f"[BGP Intel] RIPE RIS query error: {e}")
            return None
    
    def _query_route_views(self, target_prefix: str, target_asn: int) -> Optional[Dict[str, Any]]:
        """Query Route Views for BGP data."""
        try:
            # Route Views archive (simplified)
            url = f"http://archive.routeviews.org/bgpdata/2023.10/RIBS/"
            
            headers = {
                "User-Agent": "USARE-BGP-Intel/1.0"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            # This is a simplified implementation
            # Real implementation would parse MRT files
            return {
                "routes": [],
                "communities": [],
                "source": "route_views"
            }
            
        except Exception as e:
            logger.debug(f"[BGP Intel] Route Views query error: {e}")
            return None
    
    def _extract_communities(self, bgp_data: Dict[str, Any]) -> List[BGPCommunityInfo]:
        """Extract and analyze BGP communities."""
        communities = []
        
        for community_data in bgp_data.get("communities", []):
            community_str = community_data.get("community", "")
            
            # Parse community string
            community_info = self._parse_community_string(community_str)
            if community_info:
                communities.append(community_info)
        
        # Remove duplicates and sort by confidence
        unique_communities = {}
        for community in communities:
            key = community.community
            if key not in unique_communities or community.confidence > unique_communities[key].confidence:
                unique_communities[key] = community
        
        return list(unique_communities.values())
    
    def _parse_community_string(self, community_str: str) -> Optional[BGPCommunityInfo]:
        """Parse BGP community string."""
        try:
            # Standard community format: ASN:Value
            if ":" in community_str and community_str.count(":") == 1:
                asn, value = community_str.split(":")
                return self._analyze_standard_community(community_str, int(asn), int(value))
            
            # Extended community format: Type:ASN:Value
            elif ":" in community_str and community_str.count(":") == 2:
                type_part, asn, value = community_str.split(":")
                return self._analyze_extended_community(community_str, int(type_part), int(asn), int(value))
            
            # Large community format: Type:ASN:Value:Value2
            elif ":" in community_str and community_str.count(":") == 3:
                type_part, asn, value, value2 = community_str.split(":")
                return self._analyze_large_community(community_str, int(type_part), int(asn), int(value), int(value2))
            
            return None
            
        except (ValueError, AttributeError):
            return None
    
    def _analyze_standard_community(self, community_str: str, asn: int, value: int) -> BGPCommunityInfo:
        """Analyze standard 16-bit community."""
        description = f"Standard community {asn}:{value}"
        purpose = "Unknown"
        geographic_hint = None
        datacenter_hint = None
        service_hint = None
        
        # Check for well-known communities
        if asn == 0:
            if value == 0:
                description = "No export"
                purpose = "Do not export to any peer"
            elif value == 1:
                description = "No advertise"
                purpose = "Do not advertise to any peer"
            elif value == 2:
                description = "No export to peer AS"
                purpose = "Do not export to peer AS"
        
        # Check cloud provider patterns
        for cloud_name, cloud_info in self.cloud_patterns.items():
            if asn in cloud_info["asn_ranges"]:
                datacenter_hint = cloud_info["datacenter_regions"].get(str(value), f"region-{value}")
                description = f"{cloud_name.upper()} {datacenter_hint}"
                purpose = f"{cloud_name.upper()} datacenter region"
                break
        
        return BGPCommunityInfo(
            community=community_str,
            community_type="standard",
            description=description,
            purpose=purpose,
            geographic_hint=geographic_hint,
            datacenter_hint=datacenter_hint,
            service_hint=service_hint,
            confidence=0.8
        )
    
    def _analyze_extended_community(self, community_str: str, type_part: int, asn: int, value: int) -> BGPCommunityInfo:
        """Analyze extended community."""
        description = f"Extended community {type_part}:{asn}:{value}"
        purpose = "Extended community attribute"
        geographic_hint = None
        datacenter_hint = None
        service_hint = None
        
        # Extended community type analysis
        if type_part == 0x00:  # Route target
            description = f"Route target {asn}:{value}"
            purpose = "VPN route target"
        elif type_part == 0x01:  # Route origin
            description = f"Route origin {asn}:{value}"
            purpose = "VPN route origin"
        elif type_part == 0x02:  # OSPF domain ID
            description = f"OSPF domain {asn}:{value}"
            purpose = "OSPF domain identifier"
        elif type_part == 0x03:  # BGP flow spec
            description = f"Flow spec {asn}:{value}"
            purpose = "BGP flow specification"
        
        return BGPCommunityInfo(
            community=community_str,
            community_type="extended",
            description=description,
            purpose=purpose,
            geographic_hint=geographic_hint,
            datacenter_hint=datacenter_hint,
            service_hint=service_hint,
            confidence=0.7
        )
    
    def _analyze_large_community(self, community_str: str, type_part: int, asn: int, value: int, value2: int) -> BGPCommunityInfo:
        """Analyze large community."""
        description = f"Large community {type_part}:{asn}:{value}:{value2}"
        purpose = "Large community attribute"
        geographic_hint = None
        datacenter_hint = None
        service_hint = None
        
        # Large community type analysis
        if type_part == 0x00:  # Generic large community
            description = f"Generic large community {asn}:{value}:{value2}"
            purpose = "Generic large community"
        elif type_part == 0x01:  # OSPF route type
            description = f"OSPF route type {asn}:{value}:{value2}"
            purpose = "OSPF route type"
        
        return BGPCommunityInfo(
            community=community_str,
            community_type="large",
            description=description,
            purpose=purpose,
            geographic_hint=geographic_hint,
            datacenter_hint=datacenter_hint,
            service_hint=service_hint,
            confidence=0.6
        )
    
    def _analyze_topology(self, communities: List[BGPCommunityInfo], target_asn: int) -> Dict[str, Any]:
        """Analyze network topology from communities."""
        analysis = {
            "datacenter_locations": [],
            "service_types": [],
            "load_balancer_pools": [],
            "failover_relationships": [],
            "internal_topology": {}
        }
        
        # Extract datacenter locations
        datacenters = set()
        for community in communities:
            if community.datacenter_hint:
                datacenters.add(community.datacenter_hint)
        
        analysis["datacenter_locations"] = list(datacenters)
        
        # Extract service types
        service_types = set()
        for community in communities:
            if community.service_hint:
                service_types.add(community.service_hint)
        
        analysis["service_types"] = list(service_types)
        
        # Analyze load balancer pools
        lb_pools = self._identify_load_balancer_pools(communities)
        analysis["load_balancer_pools"] = lb_pools
        
        # Identify failover relationships
        failover = self._identify_failover_relationships(communities)
        analysis["failover_relationships"] = failover
        
        # Build internal topology
        internal_topology = self._build_internal_topology(communities, target_asn)
        analysis["internal_topology"] = internal_topology
        
        return analysis
    
    def _identify_load_balancer_pools(self, communities: List[BGPCommunityInfo]) -> List[str]:
        """Identify load balancer pools from communities."""
        pools = []
        
        # Look for patterns indicating load balancer pools
        for community in communities:
            if "pool" in community.description.lower() or "lb" in community.description.lower():
                pools.append(community.description)
            elif "anycast" in community.description.lower():
                pools.append(f"Anycast pool: {community.community}")
            elif community.datacenter_hint and community.service_hint:
                pools.append(f"{community.datacenter_hint}-{community.service_hint}")
        
        return list(set(pools))
    
    def _identify_failover_relationships(self, communities: List[BGPCommunityInfo]) -> List[str]:
        """Identify failover relationships from communities."""
        relationships = []
        
        # Look for communities indicating failover
        for community in communities:
            if "backup" in community.description.lower() or "secondary" in community.description.lower():
                relationships.append(f"Backup: {community.description}")
            elif "primary" in community.description.lower() or "active" in community.description.lower():
                relationships.append(f"Primary: {community.description}")
            elif "failover" in community.description.lower():
                relationships.append(f"Failover: {community.description}")
        
        return list(set(relationships))
    
    def _build_internal_topology(self, communities: List[BGPCommunityInfo], target_asn: int) -> Dict[str, Any]:
        """Build internal topology from communities."""
        topology = {
            "target_asn": target_asn,
            "datacenters": {},
            "services": {},
            "relationships": []
        }
        
        # Group communities by datacenter
        for community in communities:
            if community.datacenter_hint:
                dc = community.datacenter_hint
                if dc not in topology["datacenters"]:
                    topology["datacenters"][dc] = []
                topology["datacenters"][dc].append(community.description)
            
            if community.service_hint:
                service = community.service_hint
                if service not in topology["services"]:
                    topology["services"][service] = []
                topology["services"][service].append(community.description)
        
        return topology
    
    def _calculate_confidence(self, communities: List[BGPCommunityInfo], bgp_data: Dict[str, Any]) -> float:
        """Calculate confidence score for analysis."""
        if not communities:
            return 0.0
        
        # Base confidence from number of communities
        base_confidence = min(1.0, len(communities) / 10.0)
        
        # Adjust for data quality
        data_sources = set(bgp_data.get("source", []))
        source_confidence = min(1.0, len(data_sources) / 3.0)
        
        # Average community confidence
        avg_community_confidence = sum(c.confidence for c in communities) / len(communities)
        
        # Combined confidence
        overall_confidence = (base_confidence + source_confidence + avg_community_confidence) / 3.0
        
        return min(1.0, overall_confidence)
    
    def generate_topology_report(self, result: BGPTopologyResult) -> str:
        """Generate human-readable topology report."""
        report = []
        report.append(f"BGP Community Intelligence Report")
        report.append(f"=" * 50)
        report.append(f"Target ASN: {result.target_asn}")
        report.append(f"Target Prefix: {result.target_prefix}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append(f"Collection Time: {time.ctime(result.collection_timestamp)}")
        report.append("")
        
        if result.datacenter_locations:
            report.append("Datacenter Locations:")
            for location in result.datacenter_locations:
                report.append(f"  - {location}")
            report.append("")
        
        if result.service_types:
            report.append("Service Types:")
            for service in result.service_types:
                report.append(f"  - {service}")
            report.append("")
        
        if result.load_balancer_pools:
            report.append("Load Balancer Pools:")
            for pool in result.load_balancer_pools:
                report.append(f"  - {pool}")
            report.append("")
        
        if result.failover_relationships:
            report.append("Failover Relationships:")
            for relationship in result.failover_relationships:
                report.append(f"  - {relationship}")
            report.append("")
        
        if result.communities:
            report.append("BGP Communities:")
            for community in result.communities:
                report.append(f"  - {community.community}: {community.description}")
                report.append(f"    Purpose: {community.purpose}")
                if community.datacenter_hint:
                    report.append(f"    Datacenter: {community.datacenter_hint}")
                if community.service_hint:
                    report.append(f"    Service: {community.service_hint}")
                report.append(f"    Confidence: {community.confidence:.2f}")
                report.append("")
        
        return "\n".join(report)

# Global instance
_bgp_intel = None

def get_bgp_intel() -> BGPCommunityIntelligence:
    """Get global BGP intelligence instance."""
    global _bgp_intel
    if _bgp_intel is None:
        _bgp_intel = BGPCommunityIntelligence()
    return _bgp_intel

def analyze_bgp_communities(target_prefix: str, target_asn: int) -> BGPTopologyResult:
    """Convenience function for BGP community analysis."""
    intel = get_bgp_intel()
    return intel.analyze_bgp_communities(target_prefix, target_asn)

def generate_topology_report(result: BGPTopologyResult) -> str:
    """Convenience function for topology report generation."""
    intel = get_bgp_intel()
    return intel.generate_topology_report(result)
