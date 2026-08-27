"""DNS Cache Snooping - Passive intelligence gathering."""

import socket
import struct
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger("usare.dns_cache_snoop")

@dataclass
class CacheSnoopResult:
    domain: str
    is_cached: bool
    response_time_ms: float
    ttl: Optional[int]

class DNSCacheSnooper:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    def _build_dns_query_no_recurse(self, domain: str) -> bytes:
        """Build DNS query with RD=0 (no recursion desired)."""
        # DNS header: ID=0x1234, flags=0x0100 (standard query, no recursion)
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        
        # Encode domain name
        qname = b""
        for part in domain.split('.'):
            if part:
                qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"  # End of domain name
        
        # Question section: QTYPE=1 (A), QCLASS=1 (IN)
        question = qname + struct.pack("!HH", 1, 1)
        
        return header + question
    
    def cache_snoop(self, resolver_ip: str, domains: List[str]) -> Dict[str, CacheSnoopResult]:
        """Query resolver non-recursively to detect cached entries."""
        results = {}
        
        for domain in domains:
            try:
                start_time = time.time()
                
                # Create UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Build and send query
                query = self._build_dns_query_no_recurse(domain)
                sock.sendto(query, (resolver_ip, 53))
                
                try:
                    response, _ = sock.recvfrom(512)
                    response_time = (time.time() - start_time) * 1000
                    
                    # Parse response
                    if len(response) >= 12:
                        flags = struct.unpack("!H", response[2:4])[0]
                        qr = (flags >> 15) & 1  # Query/Response bit
                        aa = (flags >> 10) & 1  # Authoritative Answer bit
                        ancount = struct.unpack("!H", response[6:8])[0]  # Answer count
                        
                        # If we got answers and AA=0, it's from cache
                        is_cached = (qr == 1 and aa == 0 and ancount > 0)
                        
                        # Extract TTL from first answer if available
                        ttl = None
                        if is_cached and len(response) > 12:
                            # Find end of question section by scanning for null terminator
                            offset = 12
                            while offset < len(response) and response[offset] != 0:
                                label_len = response[offset]
                                offset += label_len + 1
                            offset += 5  # null byte + QTYPE(2) + QCLASS(2)
                            # Now at answer section — TTL is at bytes +4 to +8
                            if offset + 10 < len(response):
                                ttl = struct.unpack("!I", response[offset+4:offset+8])[0]
                        
                        results[domain] = CacheSnoopResult(
                            domain=domain,
                            is_cached=is_cached,
                            response_time_ms=response_time,
                            ttl=ttl
                        )
                        
                except socket.timeout:
                    results[domain] = CacheSnoopResult(
                        domain=domain,
                        is_cached=False,
                        response_time_ms=self.timeout * 1000,
                        ttl=None
                    )
                
                sock.close()
                
            except Exception as e:
                logger.debug(f"DNS cache snoop failed for {domain}: {e}")
                results[domain] = CacheSnoopResult(
                    domain=domain,
                    is_cached=False,
                    response_time_ms=0,
                    ttl=None
                )
        
        return results

def analyze_dns_cache(target_ip: str) -> Optional[Dict[str, any]]:
    """Analyze DNS cache for intelligence."""
    try:
        snooper = DNSCacheSnooper()
        
        # Common domains to check
        test_domains = [
            "windows.update.microsoft.com",  # Windows systems
            "github.com",                     # Developers
            "docker.io",                     # Container environments
            "aws.amazon.com",                # AWS infrastructure
            "google.com",                    # General web access
            "cloudflare.com",                # CDN usage
            "letsencrypt.org",               # Certificate automation
            "shodan.io",                     # Security scanning
        ]
        
        results = snooper.cache_snoop(target_ip, test_domains)
        
        return {
            "resolver_ip": target_ip,
            "cached_domains": [d for d, r in results.items() if r.is_cached],
            "intelligence": {
                "windows_detected": any("microsoft" in d.lower() for d, r in results.items() if r.is_cached),
                "developers_present": any("github" in d.lower() for d, r in results.items() if r.is_cached),
                "cloud_infrastructure": any("aws" in d.lower() or "docker" in d.lower() for d, r in results.items() if r.is_cached),
                "security_tools": any("shodan" in d.lower() for d, r in results.items() if r.is_cached),
            },
            "results": {d: {"cached": r.is_cached, "ttl": r.ttl} for d, r in results.items()}
        }
        
    except Exception as e:
        logger.error(f"DNS cache analysis failed: {e}")
        return None
