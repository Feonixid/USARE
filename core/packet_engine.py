import threading
import struct
import time
import random
import collections
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from enum import Enum
from scapy.all import (
    IP, TCP, Raw, Ether, conf, RandShort,
    send, sr1, srp1, IPv6
)


class DesyncMode(Enum):
    """Desync attack variant selection."""
    CHECKSUM = "checksum"       # Original: corrupted checksum RST
    TTL_EXPIRY = "ttl-expiry"   # RST with short TTL expires before target
    STATE_EXHAUST = "state-exhaust"  # Flood firewall state table
    DATA_INJECT = "data-inject"      # Overlapping TCP segments
    ADAPTIVE = "adaptive"       # Auto-select best variant

# Windows 10 Pro Build 19045 Network Stack Constants
WIN10_BUILD_19045_TTL = 128
WIN10_BUILD_19045_WINDOW = 64240
WIN10_BUILD_19045_WSCALE = 8  # Updated for build 19045
WIN10_BUILD_19045_MSS = 1460
WIN10_BUILD_19045_TOS = 0x00
WIN10_BUILD_19045_DF_FLAG = True

# Windows 10 TCP Option Order (verified against build 19045)
WIN10_TCP_OPTION_ORDER = [
    ("MSS", WIN10_BUILD_19045_MSS),
    ("NOP", None),
    ("WScale", WIN10_BUILD_19045_WSCALE),
    ("NOP", None),
    ("NOP", None),
    ("Timestamp", (0, 0)),  # Will be updated dynamically
    ("SAckOK", b""),
    ("EOL", None),  # End of Option List
]

# Windows 10 TCP Timestamp Behavior
WIN10_TS_FREQUENCY = 100  # 100Hz timestamp clock
WIN10_TS_EPOCH_OFFSET = random.randint(1000000, 50000000)

class TCPTimestampClock:
    """Windows 10 Build 19045 TCP Timestamp Clock Emulator."""
    def __init__(self):
        self._boot_offset = WIN10_TS_EPOCH_OFFSET
        self._start_time = time.time()
        self._last_ts = 0
        
    def current_tsval(self) -> int:
        """Generate Windows 10 compliant timestamp value."""
        elapsed = time.time() - self._start_time
        ticks = int(elapsed * WIN10_TS_FREQUENCY)
        ts = (self._boot_offset + ticks) & 0xFFFFFFFF
        
        # Ensure monotonic increasing (Windows behavior)
        if ts <= self._last_ts:
            ts = self._last_ts + 1
        self._last_ts = ts
        return ts
        
    def get_tsecr(self, received_ts: int) -> int:
        """Generate TSecr value for received timestamp."""
        return received_ts & 0xFFFFFFFF

_ts_clock = TCPTimestampClock()

def _build_win10_tcp_options(tsval: int = 0, tsecr: int = 0) -> List[tuple]:
    """Build Windows 10 Build 19045 compliant TCP options."""
    options = WIN10_TCP_OPTION_ORDER.copy()
    
    # Update timestamp with current values
    for i, (opt_type, opt_val) in enumerate(options):
        if opt_type == "Timestamp":
            options[i] = ("Timestamp", (tsval, tsecr))
            break
    
    return options

@dataclass
class PacketConfig:
    interface: Optional[str] = None
    spoof_src_ip: Optional[str] = None
    custom_ttl: int = WIN10_BUILD_19045_TTL
    custom_window: int = WIN10_BUILD_19045_WINDOW
    df_flag: bool = WIN10_BUILD_19045_DF_FLAG
    tos: int = WIN10_BUILD_19045_TOS
    verbose: bool = False
    ttl_scatter: bool = False
    pad_to_mtu: bool = False
    source_port_masq: bool = False
    masq_strategy: Optional[str] = "dns"

class IPIDGenerator:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {}
        self._global_fallback = random.randint(256, 8192)
    def next_id(self, dst_ip: str = "") -> int:
        with self._lock:
            if dst_ip:
                if dst_ip not in self._counters:
                    self._counters[dst_ip] = random.randint(256, 8192)
                jitter = random.randint(0, 2)
                self._counters[dst_ip] = (self._counters[dst_ip] + 1 + jitter) & 0xFFFF
                return self._counters[dst_ip]
            else:
                jitter = random.randint(0, 2)
                self._global_fallback = (self._global_fallback + 1 + jitter) & 0xFFFF
                return self._global_fallback
    def peek(self, dst_ip: str = "") -> int:
        with self._lock:
            if dst_ip and dst_ip in self._counters:
                return self._counters[dst_ip]
            return self._global_fallback
class TCPSeqGenerator:
    @staticmethod
    def generate_isn() -> int:
        time_component = int(time.time() * 1_000_000) & 0x00FFFFFF
        random_component = random.randint(0, 0xFF) << 24
        return (random_component | time_component) & 0xFFFFFFFF
class PacketEngine:
    def __init__(self, config: Optional[PacketConfig] = None):
        self.config = config or PacketConfig()
        self._ip_id = IPIDGenerator()
        self._seq_gen = TCPSeqGenerator()
        self._packet_count = 0
        self._lock = threading.Lock()
        self._masquerader = None
        
        # Initialize source port masquerader if enabled
        if self.config.source_port_masq:
            from evasion.source_port_masq import SourcePortMasquerader, MasqueradeStrategy
            strategy_map = {
                "dns": MasqueradeStrategy.DNS,
                "https": MasqueradeStrategy.HTTPS,
                "ntp": MasqueradeStrategy.NTP,
                "http": MasqueradeStrategy.HTTP,
                "random_high": MasqueradeStrategy.RANDOM_HIGH
            }
            strategy = strategy_map.get(self.config.masq_strategy or "dns", MasqueradeStrategy.DNS)
            self._masquerader = SourcePortMasquerader(strategy)
        
        if not self.config.verbose:
            conf.verb = 0
    def craft_syn(
        self,
        target_ip: str,
        target_port: int,
        src_port: Optional[int] = None,
        src_ip: Optional[str] = None,
        use_ipv6: bool = False
    ):
        seq = self._seq_gen.generate_isn()
        if use_ipv6 or ":" in target_ip:
            ip_layer = IPv6(
                dst=target_ip,
                hlim=self.config.custom_ttl,
                tc=self.config.tos
            )
            if src_ip or self.config.spoof_src_ip:
                ip_layer.src = src_ip or self.config.spoof_src_ip
        else:
            ip_layer = IP(
                dst=target_ip,
                ttl=self.config.custom_ttl,
                id=self._ip_id.next_id(target_ip),
                tos=self.config.tos,
                flags="DF" if self.config.df_flag else 0,
            )
            if src_ip or self.config.spoof_src_ip:
                ip_layer.src = src_ip or self.config.spoof_src_ip
        tcp_opts = _build_win10_tcp_options(
            tsval=_ts_clock.current_tsval(),
            tsecr=0,
        )
        tcp_layer = TCP(
            sport=src_port or self._default_sport(target_port),
            dport=target_port,
            flags="S",
            seq=seq,
            window=self.config.custom_window,
            options=tcp_opts,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_syn_ack_response_rst(self, syn_ack_pkt, src_port: Optional[int] = None) -> IP:
        dst = syn_ack_pkt[IP].src
        ip_layer = IP(
            dst=dst,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(dst),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port or syn_ack_pkt[TCP].dport,
            dport=syn_ack_pkt[TCP].sport,
            flags="R",
            seq=syn_ack_pkt[TCP].ack,
            ack=0,
            window=0,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_rst(self, target_ip: str, target_port: int, src_port: int, seq: int) -> IP:
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port, dport=target_port,
            flags="R", seq=seq, ack=0, window=0,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt

    def craft_desync_burst(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> list[IP]:
        syn_seq = self._seq_gen.generate_isn()
        sp = src_port or self._default_sport(target_port)

        ip_layer = IP(
            dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        tcp_syn = TCP(sport=sp, dport=target_port, flags="S", seq=syn_seq, window=self.config.custom_window)
        pkt1 = ip_layer / tcp_syn

        ip_layer2 = IP(
            dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        tcp_rst = TCP(sport=sp, dport=target_port, flags="R", seq=syn_seq + 1, window=0, chksum=0x3afb)
        pkt2 = ip_layer2 / tcp_rst

        ip_layer3 = IP(
            dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        tcp_real = TCP(sport=sp, dport=target_port, flags="S", seq=syn_seq, window=self.config.custom_window)
        pkt3 = ip_layer3 / tcp_real

        with self._lock:
            self._packet_count += 3

        return [pkt1, pkt2, pkt3]

    def craft_desync_ttl_expiry(self, target_ip: str, target_port: int,
                                firewall_hops: int = 5, src_port: Optional[int] = None) -> list[IP]:
        syn_seq = self._seq_gen.generate_isn()
        sp = src_port or self._default_sport(target_port)
        ip_syn = IP(
            dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        tcp_syn = TCP(sport=sp, dport=target_port, flags="S", seq=syn_seq, window=self.config.custom_window)
        pkt_syn = ip_syn / tcp_syn
        ip_rst = IP(
            dst=target_ip, ttl=max(1, firewall_hops - 1), id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        tcp_rst = TCP(sport=sp, dport=target_port, flags="R", seq=syn_seq + 1, window=0)
        pkt_rst = ip_rst / tcp_rst
        ip_real = IP(
            dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        tcp_real = TCP(sport=sp, dport=target_port, flags="S", seq=syn_seq, window=self.config.custom_window)
        pkt_real = ip_real / tcp_real
        with self._lock:
            self._packet_count += 3
        return [pkt_syn, pkt_rst, pkt_real]

    def craft_state_exhaustion(self, target_ip: str, count: int = 50,
                               port_range: tuple = (10000, 60000)) -> list[IP]:
        pkts = []
        for _ in range(count):
            dummy_port = random.randint(port_range[0], port_range[1])
            ip_layer = IP(
                dst=target_ip, ttl=self.config.custom_ttl,
                id=self._ip_id.next_id(target_ip),
                tos=self.config.tos, flags="DF" if self.config.df_flag else 0
            )
            tcp_layer = TCP(
                sport=self._default_sport(dummy_port), dport=dummy_port,
                flags="S", seq=self._seq_gen.generate_isn(),
                window=self.config.custom_window,
            )
            pkts.append(ip_layer / tcp_layer)
        with self._lock:
            self._packet_count += count
        return pkts

    def craft_data_desync(self, target_ip: str, target_port: int,
                          src_port: Optional[int] = None) -> list[IP]:
        seq = self._seq_gen.generate_isn()
        sp = src_port or self._default_sport(target_port)
        ip1 = IP(dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
                 tos=self.config.tos, flags="DF" if self.config.df_flag else 0)
        tcp1 = TCP(sport=sp, dport=target_port, flags="PA", seq=seq,
                   ack=random.randint(1, 0xFFFFFFFF), window=self.config.custom_window)
        payload_a = Raw(load=b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        pkt1 = ip1 / tcp1 / payload_a
        ip2 = IP(dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
                 tos=self.config.tos, flags="DF" if self.config.df_flag else 0)
        tcp2 = TCP(sport=sp, dport=target_port, flags="PA", seq=seq,
                   ack=random.randint(1, 0xFFFFFFFF), window=self.config.custom_window)
        payload_b = Raw(load=random.randbytes(len(payload_a.load)))
        pkt2 = ip2 / tcp2 / payload_b
        with self._lock:
            self._packet_count += 2
        return [pkt1, pkt2]

    def craft_fin(self, target_ip: str, target_port: int, src_port: int, seq: int, ack: int) -> IP:
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port, dport=target_port,
            flags="FA", seq=seq, ack=ack,
            window=self.config.custom_window,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_xmas(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> IP:
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port or self._default_sport(),
            dport=target_port,
            flags="FPU",
            seq=self._seq_gen.generate_isn(),
            window=self.config.custom_window,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_null(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> IP:
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port or self._default_sport(),
            dport=target_port,
            flags="",
            seq=self._seq_gen.generate_isn(),
            window=self.config.custom_window,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_ack(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> IP:
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port or self._default_sport(),
            dport=target_port,
            flags="A",
            seq=self._seq_gen.generate_isn(),
            ack=random.randint(1, 0xFFFFFFFF),
            window=self.config.custom_window,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_window(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> IP:
        return self.craft_ack(target_ip, target_port, src_port)
    def craft_maimon(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> IP:
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        tcp_layer = TCP(
            sport=src_port or self._default_sport(),
            dport=target_port,
            flags="FA",
            seq=self._seq_gen.generate_isn(),
            ack=random.randint(1, 0xFFFFFFFF),
            window=self.config.custom_window,
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt
    def craft_udp_probe(
        self, target_ip: str, target_port: int,
        src_port: Optional[int] = None, payload: bytes = b"",
    ) -> IP:
        from scapy.all import UDP as ScapyUDP
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
        )
        udp_layer = ScapyUDP(
            sport=src_port or self._default_sport(),
            dport=target_port,
        )
        pkt = ip_layer / udp_layer
        if payload:
            pkt = pkt / Raw(load=payload)
        self._increment_count()
        return pkt
    UDP_SERVICE_PAYLOADS = {
        53: bytes.fromhex(   
            "0000" "0010" "0001" "0000" "0000" "0000"
            "0776657273696f6e" "0462696e64" "0000" "0010" "0003"
        ),
        67: bytes.fromhex(
            "0101060000003d1d0000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000"
        ),
        69: b"\x00\x01netascii\x00",
        123: bytes.fromhex(
            "e30006ec" "0000000000000000" "0000000000000000"
            "0000000000000000" "0000000000000000" "0000000000000000"
        ),
        137: bytes.fromhex(  
            "80f0" "0010" "0001" "0000" "0000" "0000"
            "20434b4141414141414141414141414141414141414141414141414141414141"
            "00" "0021" "0001"
        ),
        161: bytes.fromhex(  
            "302602010004067075626c6963"
            "a01902044bcc3743020100020100"
            "300b300906052b060102010500"
        ),
        500: bytes.fromhex(  
            "0000000000000000" "0000000000000000"
            "01100200000000000000005c0000003c"
            "00000001000000010000002400010001"
            "00000018010100007001000080010005"
            "80020002800400028003000180050002"
        ),
        514: b"<14>usare: test\n",  
        520: bytes.fromhex(  
            "0101000000000000000000000000000000000000000000100000"
        ),
        623: bytes.fromhex(  
            "0600ff07000000000000000000092018c88100388e04b5"
        ),
        1434: bytes.fromhex("02"),  
        1604: bytes.fromhex(  
            "1e00013002fda8e300000000000000000000000000000000000000000000"
        ),
        1900: (  
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n"
        ),
        5353: bytes.fromhex(  
            "0000" "0000" "0001" "0000" "0000" "0000"
            "095f7365727669636573" "07"
            "5f646e732d7364" "045f756470" "056c6f63616c" "00"
            "000c" "0001"
        ),
        5632: bytes.fromhex("0100"),  
        11211: b"stats\r\n",  
    }
    def craft_udp_service_probe(
        self, target_ip: str, target_port: int,
        src_port: Optional[int] = None,
    ) -> IP:
        payload = self.UDP_SERVICE_PAYLOADS.get(target_port, b"\x00" * 8)
        return self.craft_udp_probe(target_ip, target_port, src_port, payload)
    def craft_ecn_syn(self, target_ip: str, target_port: int, src_port: Optional[int] = None) -> IP:
        """Craft SYN packet with ECN bits set for probing.
        
        ECN (Explicit Congestion Notification) probing:
        - Linux supports ECN by default
        - Windows varies by version
        - Network equipment often strips ECN bits
        - Completely invisible in logs as ECN is valid protocol behavior
        """
        sp = src_port or self._default_sport(target_port)
        
        ip_layer = IP(
            dst=target_ip, ttl=self.config.custom_ttl, id=self._ip_id.next_id(target_ip),
            tos=self.config.tos, flags="DF" if self.config.df_flag else 0
        )
        
        # TCP flags: SYN (0x02) + ECE (0x40) + CWR (0x80) = 0xC2
        tcp_layer = TCP(
            sport=sp, dport=target_port, flags=0xC2,  # SYN+ECE+CWR
            seq=self._seq_gen.generate_isn(), window=self.config.custom_window,
            options=_build_win10_tcp_options()
        )
        pkt = ip_layer / tcp_layer
        self._increment_count()
        return pkt

    def craft_icmp_echo(self, target_ip: str) -> IP:
        """Alias for craft_win10_ping — maintains backward compatibility."""
        return self.craft_win10_ping(target_ip)

    def craft_win10_ping(self, target_ip: str) -> IP:
        from scapy.all import ICMP
        win10_ping_data = b"abcdefghijklmnopqrstuvwabcdefghi"
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
            tos=self.config.tos,
            flags="DF" if self.config.df_flag else 0,
        )
        icmp_layer = ICMP(type=8, code=0, id=1, seq=1)
        pkt = ip_layer / icmp_layer / Raw(load=win10_ping_data)
        self._increment_count()
        return pkt
    def craft_icmp_timestamp(self, target_ip: str) -> IP:
        from scapy.all import ICMP
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
        )
        icmp_layer = ICMP(type=13, code=0, id=1, seq=1)
        pkt = ip_layer / icmp_layer
        self._increment_count()
        return pkt
    def craft_icmp_address_mask(self, target_ip: str) -> IP:
        from scapy.all import ICMP
        ip_layer = IP(
            dst=target_ip,
            ttl=self.config.custom_ttl,
            id=self._ip_id.next_id(target_ip),
        )
        icmp_layer = ICMP(type=17, code=0, id=1, seq=1)
        pkt = ip_layer / icmp_layer
        self._increment_count()
        return pkt
    @property
    def packets_crafted(self) -> int:
        with self._lock:
            return self._packet_count
    @property
    def current_ip_id(self) -> int:
        return self._ip_id.peek()
    def get_fingerprint_summary(self) -> dict:
        return {
            "os_mimic": "Windows 10 Pro Build 19045 (Dynamic)",
            "ttl": self.config.custom_ttl,
            "window_size": self.config.custom_window,
            "mss": "Dynamic (1200-1460)",
            "wscale": WIN10_BUILD_19045_WSCALE,
            "tcp_timestamps": True,
            "timestamp_clock_hz": 100,
            "df_flag": self.config.df_flag,
            "tos": self.config.tos,
            "ip_id_strategy": "per_destination_incremental",
            "current_ip_id": self.current_ip_id,
            "packets_crafted": self.packets_crafted,
        }
    def _default_sport(self, target_port: Optional[int] = None) -> int:
        """Get default source port, with optional masquerading."""
        if self._masquerader is not None and target_port:
            return self._masquerader.get_source_port(target_port)
        return random.randint(49152, 65535)
    def _increment_count(self):
        with self._lock:
            self._packet_count += 1

    def _scatter_ttl(self, base_ttl: int) -> int:
        jitter = random.choice([-2, -1, 0, 0, 0, 1, 2])
        return max(1, min(255, base_ttl + jitter))

    def pad_packet(self, pkt, target_size: int = 1500):
        current_size = len(bytes(pkt))
        if current_size < target_size:
            pad_len = target_size - current_size
            pkt = pkt / Raw(load=random.randbytes(pad_len))
        return pkt

    def apply_evasion(self, pkt):
        if self.config.ttl_scatter and pkt.haslayer(IP):
            pkt[IP].ttl = self._scatter_ttl(pkt[IP].ttl)
            del pkt[IP].chksum
        if self.config.pad_to_mtu:
            pkt = self.pad_packet(pkt, target_size=random.choice([576, 1480, 1500]))
        return pkt

    def craft_desync_adaptive(
        self,
        target_ip: str,
        target_port: int,
        src_port: Optional[int] = None,
        mode: str = "adaptive",
        firewall_hops: Optional[int] = None,
        state_exhaust_count: int = 30,
    ) -> List[IP]:
        """Adaptive desync dispatcher — selects best variant from available intel.

        Priority:
        1. If firewall_hops known → TTL-expiry (best evasion)
        2. If mode is state-exhaust → flood firewall state table + checksum burst
        3. If mode is data-inject → overlapping TCP segments
        4. Default → checksum corruption (safe fallback)
        """
        pkts: List[IP] = []

        if mode == "adaptive":
            if firewall_hops and firewall_hops > 1:
                mode = "ttl-expiry"
            else:
                mode = "checksum"

        if mode == "ttl-expiry" and firewall_hops:
            pkts = self.craft_desync_ttl_expiry(
                target_ip, target_port,
                firewall_hops=firewall_hops,
                src_port=src_port,
            )
        elif mode == "state-exhaust":
            exhaust_pkts = self.craft_state_exhaustion(
                target_ip, count=state_exhaust_count,
            )
            pkts.extend(exhaust_pkts)
            # Follow up with normal desync burst on target port
            pkts.extend(self.craft_desync_burst(
                target_ip, target_port, src_port=src_port,
            ))
        elif mode == "data-inject":
            pkts = self.craft_data_desync(
                target_ip, target_port, src_port=src_port,
            )
        else:
            # Default: checksum corruption
            pkts = self.craft_desync_burst(
                target_ip, target_port, src_port=src_port,
            )

        return pkts