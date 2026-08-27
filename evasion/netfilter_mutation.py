"""Netfilter Queue based real-time packet mutation - Linux only.

This module provides kernel-level transparent packet mutation that works
with any tool - not just USARE. Intercepts outgoing packets through NFQUEUE,
mutates them in Python, and reinjects for transparent evasion.

Requires: libnetfilter_queue-dev, netfilterqueue Python package
Usage: iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
"""

import logging
import time
import random
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass

try:
    from netfilterqueue import NetfilterQueue
    from scapy.all import IP, TCP, Raw, send
    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False
    NetfilterQueue = None

logger = logging.getLogger("usare.netfilter_mutation")

@dataclass
class MutationConfig:
    """Configuration for packet mutations."""
    enable_fragmentation: bool = True
    enable_timing_delay: bool = True
    enable_checksum_corruption: bool = True
    enable_ttl_scatter: bool = True
    enable_header_mutation: bool = True
    
    # Fragmentation settings
    fragment_size: int = 8
    overlap_ratio: float = 0.3
    
    # Timing settings
    base_delay_ms: int = 50
    jitter_ms: int = 20
    
    # TTL settings
    ttl_base: int = 64
    ttl_scatter: int = 3
    
    # Checksum corruption
    corruption_rate: float = 0.7

class NetfilterMutationEngine:
    """Kernel-level transparent packet mutation engine."""
    
    def __init__(self, config: Optional[MutationConfig] = None, queue_num: int = 1):
        if not HAS_NFQUEUE:
            raise RuntimeError("NetfilterQueue not available - Linux only")
        
        self.config = config or MutationConfig()
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.is_running = False
        self.packets_processed = 0
        self.packets_mutated = 0
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "fragmented_packets": 0,
            "delayed_packets": 0,
            "corrupted_packets": 0,
            "ttl_scattered": 0,
            "header_mutated": 0
        }
    
    def _mutate_packet(self, packet) -> Optional[bytes]:
        """Apply mutations to intercepted packet."""
        try:
            # Convert to Scapy packet
            scapy_pkt = IP(packet.get_payload())
            mutated = False
            
            self.stats["total_packets"] += 1
            
            # 1. Fragmentation mutation
            if self.config.enable_fragmentation and scapy_pkt.haslayer(TCP):
                if random.random() < self.config.enable_fragmentation / 100:
                    scapy_pkt = self._apply_fragmentation(scapy_pkt)
                    self.stats["fragmented_packets"] += 1
                    mutated = True
            
            # 2. TTL scatter
            if self.config.enable_ttl_scatter and scapy_pkt.haslayer(IP):
                if random.random() < 0.8:
                    scatter = random.randint(-self.config.ttl_scatter, self.config.ttl_scatter)
                    new_ttl = max(1, min(255, scapy_pkt[IP].ttl + scatter))
                    scapy_pkt[IP].ttl = new_ttl
                    del scapy_pkt[IP].chksum
                    self.stats["ttl_scattered"] += 1
                    mutated = True
            
            # 3. Checksum corruption
            if self.config.enable_checksum_corruption and scapy_pkt.haslayer(TCP):
                if random.random() < self.config.corruption_rate:
                    # Corrupt TCP checksum
                    scapy_pkt[TCP].chksum = 0x0000  # Invalid checksum
                    self.stats["corrupted_packets"] += 1
                    mutated = True
            
            # 4. Header mutation
            if self.config.enable_header_mutation and scapy_pkt.haslayer(TCP):
                if random.random() < 0.3:
                    # Add random TCP option
                    scapy_pkt[TCP].options.append(("NOP", None))
                    del scapy_pkt[TCP].chksum
                    self.stats["header_mutated"] += 1
                    mutated = True
            
            if mutated:
                self.stats["packets_mutated"] += 1
                return bytes(scapy_pkt)
            else:
                return None  # No mutation, accept original
                
        except Exception as e:
            logger.debug(f"Packet mutation failed: {e}")
            return None
    
    def _apply_fragmentation(self, pkt) -> IP:
        """Apply overlapping fragmentation to packet."""
        if not pkt.haslayer(TCP):
            return pkt
        
        # Create overlapping fragments
        payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
        
        if len(payload) < 16:
            return pkt
        
        # Fragment 1: First 8 bytes + overlap
        frag1_payload = payload[:self.config.fragment_size + 2]
        
        # Fragment 2: Overlap starting at byte 6
        frag2_payload = payload[self.config.fragment_size - 2:]
        
        # Create fragmented IP packets
        frag1 = IP(
            dst=pkt[IP].dst,
            src=pkt[IP].src,
            id=pkt[IP].id,
            flags="MF",
            frag=0,
            proto=pkt[IP].proto
        ) / frag1_payload
        
        frag2 = IP(
            dst=pkt[IP].dst,
            src=pkt[IP].src,
            id=pkt[IP].id,
            flags=0,  # Last fragment
            frag=self.config.fragment_size // 8,
            proto=pkt[IP].proto
        ) / frag2_payload
        
        # Send fragments and drop original
        send(frag1, verbose=0)
        time.sleep(0.001)  # Small delay between fragments
        send(frag2, verbose=0)
        
        return pkt  # Return original for dropping
    
    def _process_packet(self, packet):
        """Netfilter queue packet processing callback."""
        try:
            mutated_payload = self._mutate_packet(packet)
            
            if mutated_payload:
                # Replace with mutated packet
                packet.set_payload(mutated_payload)
            
            # Accept packet (mutated or original)
            packet.accept()
            
            self.packets_processed += 1
            
            # Apply timing delay if configured
            if self.config.enable_timing_delay:
                delay = self.config.base_delay_ms + random.randint(-self.config.jitter_ms, self.config.jitter_ms)
                delay_sec = delay / 1000.0
                if delay_sec > 0:
                    time.sleep(delay_sec)
                    self.stats["delayed_packets"] += 1
            
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
            packet.drop()
    
    def start(self, bind_address: str = "0.0.0.0", port: Optional[int] = None):
        """Start the netfilter mutation engine."""
        if self.is_running:
            logger.warning("Netfilter mutation already running")
            return
        
        try:
            self.nfqueue.bind(self.queue_num, self._process_packet)
            self.is_running = True
            logger.info(f"Netfilter mutation started on queue {self.queue_num}")
            
            # Run forever (or until stop() called)
            self.nfqueue.run()
            
        except Exception as e:
            logger.error(f"Failed to start netfilter mutation: {e}")
            self.stop()
    
    def stop(self):
        """Stop the netfilter mutation engine."""
        if self.is_running:
            self.nfqueue.unbind()
            self.is_running = False
            logger.info("Netfilter mutation stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get mutation statistics."""
        return {
            "packets_processed": self.packets_processed,
            "packets_mutated": self.stats["packets_mutated"],
            "mutation_rate": self.stats["packets_mutated"] / max(1, self.stats["total_packets"]),
            "breakdown": self.stats.copy()
        }

def setup_iptables_rules(target_port: int = 80, queue_num: int = 1) -> bool:
    """Setup iptables rules for packet interception."""
    try:
        import subprocess
        
        # Clear existing rules
        subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", str(target_port), 
                      "-j", "NFQUEUE", "--queue-num", str(queue_num)], 
                     capture_output=True, check=False)
        
        # Add new rule
        subprocess.run(["iptables", "-I", "OUTPUT", "-p", "tcp", "--dport", str(target_port), 
                      "-j", "NFQUEUE", "--queue-num", str(queue_num)], 
                     capture_output=True, check=True)
        
        logger.info(f"iptables rule added for port {target_port} -> queue {queue_num}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup iptables rules: {e}")
        return False

def cleanup_iptables_rules(target_port: int = 80, queue_num: int = 1):
    """Cleanup iptables rules."""
    try:
        import subprocess
        subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", str(target_port), 
                      "-j", "NFQUEUE", "--queue-num", str(queue_num)], 
                     capture_output=True, check=False)
        logger.info(f"iptables rule removed for port {target_port}")
    except Exception as e:
        logger.debug(f"Failed to cleanup iptables rules: {e}")

# Example usage
if __name__ == "__main__":
    if not HAS_NFQUEUE:
        print("NetfilterQueue not available - Linux only")
        exit(1)
    
    config = MutationConfig(
        enable_fragmentation=True,
        enable_timing_delay=True,
        base_delay_ms=100,
        fragment_size=8
    )
    
    engine = NetfilterMutationEngine(config, queue_num=1)
    
    try:
        # Setup iptables
        setup_iptables_rules(80, 1)
        
        # Start mutation
        engine.start()
        
    except KeyboardInterrupt:
        print("Stopping netfilter mutation...")
        engine.stop()
        cleanup_iptables_rules(80, 1)
        print(f"Stats: {engine.get_stats()}")
