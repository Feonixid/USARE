import ipaddress
import time
import os
import concurrent.futures
from typing import List
from scapy.all import IP, ICMP, sr1, conf

class TargetParser:
    """
    Parses and expands target specifications (CIDR, ranges, lists).
    Includes a fast host discovery (ping sweep) engine.
    """
    def __init__(self, target_string: str, use_ping_sweep: bool = True):
        self.target_string = target_string
        self.use_ping_sweep = use_ping_sweep
        conf.verb = 0

    def get_targets(self) -> List[str]:
        expanded = self._expand_targets()
        
        if len(expanded) == 1 or not self.use_ping_sweep:
            return expanded
            
        return self._ping_sweep(expanded)

    def _expand_targets(self) -> List[str]:
        targets = []
        # Check if it's a file
        if os.path.isfile(self.target_string):
            with open(self.target_string, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]
            for line in lines:
                targets.extend(self._parse_single(line))
        else:
            # Comma separated
            for part in self.target_string.split(","):
                part = part.strip()
                if part:
                    targets.extend(self._parse_single(part))
        # Deduplicate while preserving order
        return list(dict.fromkeys(targets))

    def _parse_single(self, target: str) -> List[str]:
        try:
            # Check for CIDR
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            
            # Check for hyphenated range (e.g. 192.168.1.1-50)
            if '-' in target:
                base, end = target.rsplit('.', 1)
                if '-' in end:
                    start_num, end_num = end.split('-', 1)
                    return [f"{base}.{i}" for i in range(int(start_num), int(end_num) + 1)]
                
            # Assume single IP or hostname
            return [target]
        except Exception:
            return [target] # Return verbatim if parsing fails (could be hostname)

    def _ping_sweep(self, targets: List[str]) -> List[str]:
        active_hosts = []
        
        def ping_host(ip: str) -> str | None:
            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=1.0, verbose=0)
            if resp is not None:
                return ip
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in targets}  # type: ignore[arg-type]
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future.result()
                if ip:
                    active_hosts.append(ip)
                    
        def _sort_key(host: str) -> tuple:
            # Normalise so both IPs and hostnames sort as strings without TypeError
            parts = host.split('.')
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return (0, tuple(int(p) for p in parts))
            return (1, (host,))
        return sorted(active_hosts, key=_sort_key)
