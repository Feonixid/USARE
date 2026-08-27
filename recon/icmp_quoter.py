import time
import logging
from typing import Dict, Optional, Any
from scapy.all import IP, UDP, ICMP, TCP, sr1, conf

logger = logging.getLogger("usare.icmp_quoter")

class ICMPQuoter:
    """
    Intentionally triggers ICMP Time Exceeded or Destination Unreachable errors.
    Parses the ICMP payload (the "quoted" packet) which often leaks:
    - Internal NAT IPs
    - Hidden router interfaces
    - Unfiltered internal IP/Port translations
    """
    def __init__(self, target_ip: str, timeout: float = 3.0):
        self.target_ip = target_ip
        self.timeout = timeout
        if not conf.verb:
            conf.verb = 0

    def extract_leakage(self, dport: int = 33434, ttl: int = 1) -> Dict[str, Optional[str]]:
        """
        Sends a low-TTL UDP probe to trigger an ICMP Time Exceeded in Transit.
        Analyzes the quoted IP layer inside the ICMP frame.
        """
        logger.debug(f"[ICMP-Quoter] Firing probe at {self.target_ip}:{dport} with TTL {ttl}")
        
        probe = IP(dst=self.target_ip, ttl=ttl) / UDP(dport=dport, sport=54321)
        
        reply = sr1(probe, timeout=self.timeout, verbose=0)
        
        result: Dict[str, Any] = {
            "trigger_ttl": str(ttl),
            "responding_router": None,
            "error_type": None,
            "original_dst_quoted": None,
            "original_src_quoted": None,
            "nat_detected": "False"
        }
        
        if reply and reply.haslayer(ICMP):
            result["responding_router"] = reply[IP].src
            result["error_type"] = f"Type {reply[ICMP].type} Code {reply[ICMP].code}"
            
            # The quoted packet lives inside the ICMP payload
            if reply[ICMP].payload and reply[ICMP].payload.haslayer(IP):
                quoted_ip = reply[ICMP].payload[IP]
                result["original_src_quoted"] = quoted_ip.src
                result["original_dst_quoted"] = quoted_ip.dst
                
                # If the quoted destination doesn't match our original target IP, NAT is rewriting it
                if quoted_ip.dst != self.target_ip:
                    result["nat_detected"] = "True (Destination NAT Translation)"
                # If the quoted source doesn't match our local IP, a proxy/NAT altered it
                elif quoted_ip.src != probe[IP].src:
                    result["nat_detected"] = "True (Source IP Spoofed back)"
                    
        return result
        
    def probe_path_leaks(self, dport: int = 33434, max_hops: int = 15) -> Dict[int, Dict]:
        """
        Perform a targeted traceroute-style sweep specifically hunting for NAT translation leaks.
        """
        path_leaks = {}
        for ttl in range(1, max_hops + 1):
            leak = self.extract_leakage(dport=dport, ttl=ttl)
            if leak["responding_router"]:
                path_leaks[ttl] = leak
                
                # Stop if we hit the actual target
                if leak["responding_router"] == self.target_ip:
                    break
            else:
                path_leaks[ttl] = {"status": "timeout/dropped"}
                
        return path_leaks
