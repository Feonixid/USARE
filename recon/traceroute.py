import time
import logging
from typing import Optional, List, Callable
from dataclasses import dataclass, field
from scapy.all import IP, TCP, ICMP, sr1, conf
from core.packet_engine import PacketEngine, PacketConfig
logger = logging.getLogger("usare.traceroute")
@dataclass
class Hop:
    ttl: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    is_target: bool = False
    is_filtered: bool = False       
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}
@dataclass
class TracerouteResult:
    target: str
    hops: List[Hop] = field(default_factory=list)
    total_hops: int = 0
    target_reached: bool = False
    firewall_position: Optional[int] = None  
    path_complete: bool = False
    timestamp: float = field(default_factory=time.time)
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_hops": self.total_hops,
            "target_reached": self.target_reached,
            "firewall_position": self.firewall_position,
            "path_complete": self.path_complete,
            "hops": [h.to_dict() for h in self.hops],
        }
class StealthTraceroute:
    def __init__(
        self,
        packet_engine: Optional[PacketEngine] = None,
        max_ttl: int = 30,
        timeout: float = 3.0,
        retries: int = 2,
        target_port: int = 80,
        inter_hop_delay: Optional[float] = None,
        hop_callback: Optional[Callable[[int], None]] = None,
    ):
        self.engine = packet_engine or PacketEngine()
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.retries = retries
        self.target_port = target_port
        self.inter_hop_delay = inter_hop_delay
        self.hop_callback = hop_callback or (lambda _: None)

    def trace(self, target_ip: str) -> TracerouteResult:
        result = TracerouteResult(target=target_ip)
        consecutive_filtered = 0
        for ttl in range(1, self.max_ttl + 1):
            if self.inter_hop_delay is not None and ttl > 1:
                import time
                time.sleep(self.inter_hop_delay)
            self.hop_callback(ttl)
            hop = self._probe_hop(target_ip, ttl)
            result.hops.append(hop)
            result.total_hops = ttl
            if hop.is_target:
                result.target_reached = True
                result.path_complete = True
                logger.info(f"[TRACE] Target reached at hop {ttl}")
                break
            if hop.is_filtered:
                consecutive_filtered += 1
                if consecutive_filtered >= 5:
                    result.firewall_position = ttl - 4
                    logger.info(
                        f"[TRACE] Firewall detected at hop {result.firewall_position}"
                    )
                    break
            else:
                consecutive_filtered = 0
            if hop.ip:
                logger.debug(f"[TRACE] Hop {ttl}: {hop.ip} ({hop.latency_ms:.1f}ms)")
        if result.firewall_position is None:
            for i, hop in enumerate(result.hops):
                if hop.is_filtered and i > 0:
                    result.firewall_position = hop.ttl
                    break
        return result
    def _probe_hop(self, target_ip: str, ttl: int) -> Hop:
        hop = Hop(ttl=ttl)
        for attempt in range(self.retries):
            try:
                from core.packet_engine import PacketConfig
                custom_engine = PacketEngine(PacketConfig(custom_ttl=ttl))
                syn = custom_engine.craft_syn(target_ip, self.target_port)
                t0 = time.time()
                resp = sr1(syn, timeout=self.timeout, verbose=0)
                latency = (time.time() - t0) * 1000
                if resp is None:
                    continue  
                if resp.haslayer(ICMP):
                    if resp[ICMP].type == 11:  
                        hop.ip = resp[IP].src
                        hop.latency_ms = latency
                        hop.icmp_type = resp[ICMP].type
                        hop.icmp_code = resp[ICMP].code
                        hop.hostname = self._reverse_dns(resp[IP].src)
                        return hop
                    elif resp[ICMP].type == 3:  
                        hop.ip = resp[IP].src
                        hop.latency_ms = latency
                        hop.is_filtered = True
                        hop.icmp_type = resp[ICMP].type
                        hop.icmp_code = resp[ICMP].code
                        return hop
                if resp.haslayer(TCP):
                    hop.ip = resp[IP].src
                    hop.latency_ms = latency
                    hop.is_target = True
                    hop.hostname = self._reverse_dns(resp[IP].src)
                    return hop
            except Exception as e:
                logger.debug(f"Probe failed for TTL {ttl}: {e}")
        hop.is_filtered = True
        return hop
    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        import socket
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None