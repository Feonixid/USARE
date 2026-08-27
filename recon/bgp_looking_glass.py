"""BGP Looking Glass Passive Topology Mapping.

Public BGP looking glass servers let you query the global routing table without
touching the target. You can map the exact AS path to the target, identify
transit providers, find anycast nodes, and determine CDN presence — all from
public infrastructure with zero packets to the target.

Looking glass servers:
- route-views.oregon-ix.net
- rrc00.ripe.net
- lg.he.net
- bgp.he.net
"""

import logging
import socket
import telnetlib
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger("usare.bgp_looking_glass")

@dataclass
class BGPPrefixInfo:
    prefix: str
    as_path: List[int]
    origin_as: int
    next_hop: Optional[str]
    local_pref: Optional[int]
    med: Optional[int]
    community: Optional[List[str]]

@dataclass
class LookingGlassServer:
    name: str
    host: str
    port: int
    type: str  # "telnet", "whois", "http"
    commands: Dict[str, str]

class BGPLookingGlass:
    """BGP Looking Glass topology mapper."""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        
        # Known looking glass servers
        self.servers = {
            "route-views": LookingGlassServer(
                name="Route Views",
                host="route-views.oregon-ix.net",
                port=23,
                type="telnet",
                commands={
                    "bgp": "show ip bgp {}",
                    "aspath": "show ip bgp regexp ^{}$",
                    "prefix": "show ip bgp {}"
                }
            ),
            "ripe-rrc00": LookingGlassServer(
                name="RIPE RRC00",
                host="rrc00.ripe.net",
                port=23,
                type="telnet",
                commands={
                    "bgp": "show bgp ipv4 unicast {}",
                    "aspath": "show bgp ipv4 unicast regexp ^{}$",
                    "prefix": "show bgp ipv4 unicast {}"
                }
            ),
            "hurricane-electric": LookingGlassServer(
                name="Hurricane Electric",
                host="lg.he.net",
                port=23,
                type="telnet",
                commands={
                    "bgp": "show ip bgp {}",
                    "aspath": "show ip bgp regexp ^{}$",
                    "prefix": "show ip bgp {}"
                }
            ),
            "bgp-tools": LookingGlassServer(
                name="BGP.Tools",
                host="bgp.he.net",
                port=43,
                type="whois",
                commands={
                    "bgp": "-t route -l {}",
                    "aspath": "-t origin -l {}",
                    "prefix": "-t route -l {}"
                }
            )
        }
    
    def _query_telnet_server(self, server: LookingGlassServer, 
                          query: str) -> Optional[str]:
        """Query telnet-based looking glass server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((server.host, server.port))
            
            # Wait for prompt
            sock.recv(1024)  # Read initial prompt
            
            # Send command
            sock.send(query.encode() + b"\n")
            
            # Read response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            sock.close()
            return response
            
        except Exception as e:
            logger.debug(f"Socket query failed for {server.name}: {e}")
            return None
    
    def _query_whois_server(self, server: LookingGlassServer, 
                          query: str) -> Optional[str]:
        """Query whois-based looking glass server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((server.host, server.port))
            sock.send(query.encode() + b"\n")
            
            response = sock.recv(4096).decode('utf-8')
            sock.close()
            
            return response
            
        except Exception as e:
            logger.debug(f"Whois query failed for {server.name}: {e}")
            return None
    
    def _parse_bgp_output(self, output: str) -> List[BGPPrefixInfo]:
        """Parse BGP output into structured data."""
        prefixes = []
        
        try:
            lines = output.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith('%') or line.startswith('BGP'):
                    continue
                
                # Parse typical BGP table entry format
                # Example: "*> 192.0.2.0/24    10.0.0.1              0    100     0 64512 i"
                parts = line.split()
                
                if len(parts) >= 6:
                    prefix = parts[1] if '/' in parts[1] else parts[1] + '/32'
                    next_hop = parts[2] if parts[2] != '0.0.0.0' else None
                    
                    # Extract AS path (everything between next_hop and community)
                    as_path = []
                    for i in range(5, len(parts)):
                        part = parts[i]
                        if part.isdigit() and len(part) <= 6:  # ASN format
                            as_path.append(int(part))
                        elif part == 'i':  # Origin IGP
                            break
                    
                    if as_path:
                        origin_as = as_path[0] if as_path else 0
                        
                        prefixes.append(BGPPrefixInfo(
                            prefix=prefix,
                            as_path=as_path,
                            origin_as=origin_as,
                            next_hop=next_hop,
                            local_pref=None,
                            med=None,
                            community=None
                        ))
        
        except Exception as e:
            logger.debug(f"BGP parsing failed: {e}")
        
        return prefixes
    
    def query_target_prefix(self, target_ip: str, 
                          server_name: str = "route-views") -> Optional[List[BGPPrefixInfo]]:
        """Query BGP information for target IP prefix."""
        if server_name not in self.servers:
            logger.error(f"Unknown server: {server_name}")
            return None
        
        server = self.servers[server_name]
        
        # Build query for IP address
        command = server.commands["bgp"].format(target_ip)
        
        # Query server
        if server.type == "telnet":
            response = self._query_telnet_server(server, command)
        elif server.type == "whois":
            response = self._query_whois_server(server, command)
        else:
            logger.error(f"Unsupported server type: {server.type}")
            return None
        
        if response:
            return self._parse_bgp_output(response)
        
        return None
    
    def query_as_path(self, target_as: int, 
                     server_name: str = "route-views") -> Optional[List[BGPPrefixInfo]]:
        """Query BGP information for specific AS path."""
        if server_name not in self.servers:
            logger.error(f"Unknown server: {server_name}")
            return None
        
        server = self.servers[server_name]
        
        # Build query for AS path
        command = server.commands["aspath"].format(f"^{target_as}$")
        
        # Query server
        if server.type == "telnet":
            response = self._query_telnet_server(server, command)
        elif server.type == "whois":
            response = self._query_whois_server(server, command)
        else:
            logger.error(f"Unsupported server type: {server.type}")
            return None
        
        if response:
            return self._parse_bgp_output(response)
        
        return None
    
    def analyze_target_topology(self, target_ip: str) -> Dict[str, Any]:
        """Comprehensive topology analysis using multiple looking glasses."""
        analysis = {
            "target": target_ip,
            "servers_queried": [],
            "bgp_info": {},
            "topology": {},
            "transit_providers": [],
            "anycast_detected": False,
            "cdn_indicators": []
        }
        
        # Query multiple servers for redundancy
        for server_name in ["route-views", "ripe-rrc00", "hurricane-electric"]:
            prefixes = self.query_target_prefix(target_ip, server_name)
            
            if prefixes:
                analysis["servers_queried"].append(server_name)
                analysis["bgp_info"][server_name] = prefixes
                
                # Analyze first (most specific) prefix
                if prefixes:
                    prefix_info = prefixes[0]
                    
                    # Extract transit providers (ASNs in path except origin)
                    transit_asns = prefix_info.as_path[1:] if len(prefix_info.as_path) > 1 else []
                    analysis["transit_providers"].extend(transit_asns)
                    
                    # Check for anycast (multiple next hops from different servers)
                    if prefix_info.next_hop:
                        analysis["topology"]["next_hop"] = prefix_info.next_hop
                    
                    analysis["topology"]["origin_as"] = prefix_info.origin_as
                    analysis["topology"]["as_path"] = prefix_info.as_path
        
        # Remove duplicate transit providers
        analysis["transit_providers"] = list(set(analysis["transit_providers"]))
        
        # Detect anycast (different next hops from different servers)
        next_hops = []
        for server_info in analysis["bgp_info"].values():
            if server_info and server_info[0].next_hop:
                next_hops.append(server_info[0].next_hop)
        
        analysis["anycast_detected"] = len(set(next_hops)) > 1
        
        # CDN detection based on known ASNs
        cdn_asns = {
            13335: "Cloudflare",
            20940: "Akamai", 
            15133: "Edgecast",
            16509: "Amazon",
            8075: "Microsoft",
            15169: "Google"
        }
        
        for asn in analysis["transit_providers"] + [analysis["topology"].get("origin_as", 0)]:
            if asn in cdn_asns:
                analysis["cdn_indicators"].append({
                    "asn": asn,
                    "provider": cdn_asns[asn]
                })
        
        return analysis
    
    def identify_infrastructure(self, target_ip: str) -> Dict[str, Any]:
        """Identify infrastructure type and providers from BGP data."""
        topology = self.analyze_target_topology(target_ip)
        
        infrastructure = {
            "target": target_ip,
            "infrastructure_type": "unknown",
            "hosting_provider": None,
            "cdn_provider": None,
            "cloud_provider": None,
            "transit_networks": topology["transit_providers"],
            "confidence": 0.0
        }
        
        # Cloud provider detection
        cloud_asns = {
            16509: "AWS",
            8075: "Azure", 
            15169: "Google Cloud",
            64512: "Aliyun",
            37971: "Oracle Cloud"
        }
        
        origin_as = topology["topology"].get("origin_as", 0)
        if origin_as in cloud_asns:
            infrastructure["cloud_provider"] = cloud_asns[origin_as]
            infrastructure["infrastructure_type"] = "cloud"
            infrastructure["confidence"] = 0.8
        
        # CDN detection
        if topology["cdn_indicators"]:
            infrastructure["cdn_provider"] = topology["cdn_indicators"][0]["provider"]
            infrastructure["infrastructure_type"] = "cdn"
            infrastructure["confidence"] = max(infrastructure["confidence"], 0.7)
        
        # Hosting provider detection
        hosting_asns = {
            16276: "OVH",
            47869: "Nobis",
            197695: "Hetzner",
            24940: "Hetzner",
            3216: "Soqueti"
        }
        
        if origin_as in hosting_asns:
            infrastructure["hosting_provider"] = hosting_asns[origin_as]
            if infrastructure["infrastructure_type"] == "unknown":
                infrastructure["infrastructure_type"] = "hosting"
                infrastructure["confidence"] = 0.6
        
        # Anycast detection
        if topology["anycast_detected"]:
            infrastructure["anycast"] = True
            infrastructure["confidence"] += 0.1
        
        infrastructure["confidence"] = min(1.0, infrastructure["confidence"])
        
        return infrastructure

# Example usage
if __name__ == "__main__":
    bgp = BGPLookingGlass()
    
    # Analyze target topology
    target = "8.8.8.8"
    topology = bgp.analyze_target_topology(target)
    print(f"Topology for {target}: {topology}")
    
    # Identify infrastructure
    infrastructure = bgp.identify_infrastructure(target)
    print(f"Infrastructure: {infrastructure}")
