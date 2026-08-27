import random
import ipaddress
from typing import List, Optional, Tuple
from scapy.all import IP, TCP, UDP, Raw
from core.packet_engine import PacketEngine, WIN10_BUILD_19045_TTL, WIN10_BUILD_19045_WINDOW, WIN10_TCP_OPTION_ORDER
MASQUERADE_PORTS = [53, 123, 443, 80, 8080]
HIGH_REP_IP_RANGES = [
    # Google
    "8.8.8.0/24", "8.8.4.0/24", "34.0.0.0/15", "35.192.0.0/14",
    # Cloudflare
    "1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/13", "162.158.0.0/15",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Apple
    "17.0.0.0/8",
    # AWS (us-east-1 examples)
    "52.0.0.0/15", "54.144.0.0/15", "3.80.0.0/12",
    # Azure
    "40.74.0.0/15", "52.239.0.0/16",
    # OpenDNS / Cisco
    "208.67.222.0/24", "208.67.220.0/24",
    # Quad9
    "9.9.9.0/24",
]
class DecoyEngine:
    def __init__(self, packet_engine: Optional[PacketEngine] = None):
        self._engine = packet_engine or PacketEngine()
        self._rng = random.SystemRandom()
        self._decoys_generated = 0
    def generate_decoys(
        self,
        target_ip: str,
        target_port: int,
        count: int = 5,
        subnet_mask: int = 24,
        bgp_trusted: bool = False,
    ) -> List[IP]:
        decoys: List[IP] = []
        subnet = ipaddress.ip_network(
            f"{target_ip}/{subnet_mask}", strict=False
        )
        hosts = [h for h in subnet.hosts()]
        target_addr = ipaddress.ip_address(target_ip)
        hosts = [h for h in hosts if h != target_addr]
        if not hosts and not bgp_trusted:
            return decoys
        for _ in range(count):
            if bgp_trusted:
                fake_src = self.get_high_rep_ip()
            else:
                fake_src = str(self._rng.choice(hosts))
            src_port = self.get_masquerade_port()
            pkt = self._engine.craft_syn(
                target_ip=target_ip,
                target_port=target_port,
                src_port=src_port,
                src_ip=fake_src,
            )
            decoys.append(pkt)
            self._decoys_generated += 1
        return decoys
    def generate_multi_port_decoys(
        self,
        target_ip: str,
        port_range: Tuple[int, int] = (1, 1024),
        count: int = 5,
    ) -> List[IP]:
        decoys: List[IP] = []
        subnet = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        hosts = [
            h for h in subnet.hosts()
            if h != ipaddress.ip_address(target_ip)
        ]
        if not hosts:
            return decoys
        for _ in range(count):
            fake_src = str(self._rng.choice(hosts))
            fake_port = self._rng.randint(port_range[0], port_range[1])
            src_port = self.get_masquerade_port()
            pkt = self._engine.craft_syn(
                target_ip=target_ip,
                target_port=fake_port,
                src_port=src_port,
                src_ip=fake_src,
            )
            decoys.append(pkt)
            self._decoys_generated += 1
        return decoys
    def generate_protocol_noise(
        self,
        target_ip: str,
    ) -> List[IP]:
        noise: List[IP] = []
        subnet = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        hosts = [h for h in subnet.hosts()]
        for _ in range(2):
            src = str(self._rng.choice(hosts))
            pkt = self._engine.craft_udp_probe(
                target_ip=target_ip,
                target_port=53,
                src_port=self._rng.randint(49152, 65535),
            )
            pkt[IP].src = src
            del pkt[IP].chksum
            noise.append(pkt)
        for _ in range(2):
            src = str(self._rng.choice(hosts))
            pkt = self._engine.craft_udp_probe(
                target_ip=target_ip,
                target_port=123,
                src_port=123,
            )
            pkt[IP].src = src
            del pkt[IP].chksum
            noise.append(pkt)
        src = str(self._rng.choice(hosts))
        pkt = self._engine.craft_syn(
            target_ip=target_ip,
            target_port=80,
            src_port=self._rng.randint(49152, 65535),
            src_ip=src,
        )
        noise.append(pkt)
        self._decoys_generated += len(noise)
        return noise
    def interleave_decoys(
        self,
        real_pkt: IP,
        target_ip: str,
        count: Optional[int] = None,
    ) -> List[IP]:
        """Interleave decoy packets around the real packet at a random position."""
        n = count or 5
        target_port = real_pkt[TCP].dport if real_pkt.haslayer(TCP) else 80
        decoys = self.generate_decoys(target_ip, target_port, count=n)
        if not decoys:
            return [real_pkt]
        insert_pos = self._rng.randint(0, len(decoys))
        result = decoys[:insert_pos] + [real_pkt] + decoys[insert_pos:]
        return result

    @staticmethod
    def get_masquerade_port() -> int:
        return random.SystemRandom().choice(MASQUERADE_PORTS)
    @staticmethod
    def get_high_rep_ip() -> str:
        rng = random.SystemRandom()
        network = ipaddress.ip_network(rng.choice(HIGH_REP_IP_RANGES))
        hosts = [h for h in network.hosts()]
        return str(rng.choice(hosts))
    @property
    def total_decoys_generated(self) -> int:
        return self._decoys_generated