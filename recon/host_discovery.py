import time
import logging
import ipaddress
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from scapy.all import ( # type: ignore
    IP, TCP, ICMP, ARP, Ether, sr1, srp1, send, conf,
)
from core.packet_engine import PacketEngine, PacketConfig # type: ignore
logger = logging.getLogger("usare.host_discovery")
@dataclass
class HostStatus:
    ip: str
    is_alive: bool = False
    method: Optional[str] = None
    latency_ms: Optional[float] = None
    mac_address: Optional[str] = None
    ttl: Optional[int] = None
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}
DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 21, 25, 8080, 8443, 3306]
class HostDiscovery:
    def __init__(
        self,
        packet_engine: Optional[PacketEngine] = None,
        timeout: float = 3.0,
    ):
        self.engine = packet_engine or PacketEngine()
        self.timeout = timeout
    def is_alive(self, target_ip: str) -> HostStatus:
        status = HostStatus(ip=target_ip)
        if self._is_local(target_ip):
            arp_result = self._arp_ping(target_ip)
            if arp_result:
                return arp_result
        syn_result = self._tcp_syn_ping(target_ip)
        if syn_result and syn_result.is_alive:
            return syn_result
        icmp_result = self._icmp_echo(target_ip)
        if icmp_result and icmp_result.is_alive:
            return icmp_result
        ts_result = self._icmp_timestamp(target_ip)
        if ts_result and ts_result.is_alive:
            return ts_result
        ack_result = self._tcp_ack_ping(target_ip)
        if ack_result and ack_result.is_alive:
            return ack_result
        udp_result = self._udp_ping(target_ip)
        if udp_result and udp_result.is_alive:
            return udp_result
        status.reason = "No response from any discovery method"
        return status
    def discover_subnet(
        self,
        network: str,
        delay: float = 0.1,
    ) -> List[HostStatus]:
        net = ipaddress.ip_network(network, strict=False)
        import typing; net = typing.cast(typing.Any, net)
        alive_hosts = []
        for host in net.hosts():
            ip = str(host)
            result = self.is_alive(ip)
            if result.is_alive:
                alive_hosts.append(result)
                logger.info(f"[ALIVE] {ip} via {result.method}")
            time.sleep(delay)
        return alive_hosts
    def _arp_ping(self, target_ip: str) -> Optional[HostStatus]:
        try:
            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
            t0 = time.time()
            resp = srp1(arp, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            if resp and resp.haslayer(ARP):
                return HostStatus(
                    ip=target_ip,
                    is_alive=True,
                    method="arp",
                    latency_ms=latency,
                    mac_address=resp[ARP].hwsrc,
                    reason="ARP reply received",
                )
        except Exception as e:
            logger.debug(f"ARP ping failed for {target_ip}: {e}")
        return None
    def _tcp_syn_ping(self, target_ip: str) -> Optional[HostStatus]:
        import typing; dp = typing.cast(typing.Any, DISCOVERY_PORTS)
        for port in dp[:3]:
            try:
                syn = self.engine.craft_syn(target_ip, port)
                t0 = time.time()
                resp = sr1(syn, timeout=self.timeout, verbose=0)
                latency = (time.time() - t0) * 1000
                if resp and resp.haslayer(TCP):
                    flags = resp[TCP].flags
                    if flags & 0x12 == 0x12:
                        rst = self.engine.craft_syn_ack_response_rst(resp)
                        send(rst, verbose=0)
                        return HostStatus(
                            ip=target_ip, is_alive=True,
                            method=f"tcp-syn:{port}",
                            latency_ms=latency,
                            ttl=resp[IP].ttl,
                            reason=f"SYN-ACK from port {port}",
                        )
                    elif flags & 0x04:
                        return HostStatus(
                            ip=target_ip, is_alive=True,
                            method=f"tcp-syn:{port}",
                            latency_ms=latency,
                            ttl=resp[IP].ttl,
                            reason=f"RST from port {port} (port closed but host alive)",
                        )
            except Exception:
                continue
        return None
    def _icmp_echo(self, target_ip: str) -> Optional[HostStatus]:
        try:
            pkt = self.engine.craft_icmp_echo(target_ip)
            t0 = time.time()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
                return HostStatus(
                    ip=target_ip, is_alive=True,
                    method="icmp-echo",
                    latency_ms=latency,
                    ttl=resp[IP].ttl,
                    reason="ICMP Echo Reply received",
                )
        except Exception:
            pass
        return None
    def _icmp_timestamp(self, target_ip: str) -> Optional[HostStatus]:
        try:
            pkt = self.engine.craft_icmp_timestamp(target_ip)
            t0 = time.time()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            if resp and resp.haslayer(ICMP) and resp[ICMP].type == 14:
                return HostStatus(
                    ip=target_ip, is_alive=True,
                    method="icmp-timestamp",
                    latency_ms=latency,
                    ttl=resp[IP].ttl,
                    reason="ICMP Timestamp Reply received",
                )
        except Exception:
            pass
        return None
    def _tcp_ack_ping(self, target_ip: str) -> Optional[HostStatus]:
        try:
            ack = self.engine.craft_ack(target_ip, 80)
            t0 = time.time()
            resp = sr1(ack, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                return HostStatus(
                    ip=target_ip, is_alive=True,
                    method="tcp-ack:80",
                    latency_ms=latency,
                    ttl=resp[IP].ttl,
                    reason="RST to ACK on port 80",
                )
        except Exception:
            pass
        return None
    def _udp_ping(self, target_ip: str) -> Optional[HostStatus]:
        try:
            pkt = self.engine.craft_udp_service_probe(target_ip, 53)
            t0 = time.time()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            latency = (time.time() - t0) * 1000
            if resp:
                if resp.haslayer(ICMP):
                    return HostStatus(
                        ip=target_ip, is_alive=True,
                        method="udp:53",
                        latency_ms=latency,
                        reason="ICMP unreachable (host alive, port closed)",
                    )
                else:
                    return HostStatus(
                        ip=target_ip, is_alive=True,
                        method="udp:53",
                        latency_ms=latency,
                        reason="UDP response from DNS",
                    )
        except Exception:
            pass
        return None
    @staticmethod
    def _is_local(target_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(target_ip)
            return addr.is_private
        except ValueError:
            return False