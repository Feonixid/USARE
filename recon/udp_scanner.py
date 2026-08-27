import time
import logging
from typing import List, Optional
from scapy.all import IP, UDP, ICMP, sr1, conf

from recon.syn_scanner import ScanResult, PortState, ScanConfig, chunk_ports, SERVICE_MAP
from core.packet_engine import PacketEngine, PacketConfig
from evasion.session import SessionTracker
from ops.heat_meter import HeatMeter
from evasion.timing import GhostTimer, TimingConfig, TimingProfile

logger = logging.getLogger("usare.udp_scanner")

class UDPScanner:
    """
    UDP Scanner for USARE.
    UDP Response -> OPEN
    ICMP Type 3, Code 3 -> CLOSED
    ICMP Type 3, Code 1, 2, 9, 10, 13 -> FILTERED
    No Response / Timeout -> OPEN|FILTERED
    """
    def __init__(self, config: ScanConfig, heat_meter: Optional[HeatMeter] = None):
        self.config = config
        self.heat_meter = heat_meter or HeatMeter()
        
        pkt_config = PacketConfig(interface=config.interface, verbose=config.verbose)
        self.packet_engine = PacketEngine(pkt_config)
        
        timing_config = TimingConfig.from_profile(config.timing_profile)
        if config.timing_profile == TimingProfile.ADAPTIVE:
            timing_config.heat_callback = self.heat_meter.detection_probability
        self.timer = GhostTimer(timing_config)
        
        self.session = SessionTracker(max_retries=config.max_retries)
        self.results: List[ScanResult] = []
        self._start_time: Optional[float] = None
        
        if not config.verbose:
            conf.verb = 0

    def execute(self) -> List[ScanResult]:
        self._start_time = time.time()
        logger.info(f"[USARE] Starting UDP scan against {self.config.target_ip}")
        ports = self._resolve_ports()
        
        chunks = chunk_ports(ports, self.config.chunk_size)
        for chunk_idx, port_chunk in enumerate(chunks):
            logger.info(f"[USARE] UDP Phase — chunk {chunk_idx + 1}/{len(chunks)} ({len(port_chunk)} ports)")
            
            for port in port_chunk:
                if not self.session.check_rate_limit():
                    time.sleep(self.session.time_until_next_allowed())
                
                result = self._probe_port_udp_with_retries(port)
                self.results.append(result)
                self.session.set_state(self.config.target_ip, port, result.state.value)
                
                if self.config.ghost_mode:
                    self.timer.sync_ghost_wait()
                    
        elapsed = time.time() - (self._start_time or time.time())
        logger.info(f"[USARE] UDP Scan complete. {len(self.results)} results in {elapsed:.1f}s.")
        return self.results

    def _probe_port_udp_with_retries(self, port: int) -> ScanResult:
        src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
        timeout = self.config.timeout
        if self.config.adaptive_timeout:
            timeout = self.session.get_adaptive_timeout(self.config.target_ip)
            
        last_result = None
        for attempt in range(self.config.max_retries):
            result = self._probe_port_udp(port, src_port, timeout)
            result.retries = attempt
            
            self.session.record_probe(
                target=self.config.target_ip,
                port=port,
                method="udp",
                src_port=src_port,
                response=result.state.value,
                latency_ms=result.latency_ms,
                is_retry=(attempt > 0)
            )
            
            if result.latency_ms:
                self.session.record_rtt(self.config.target_ip, result.latency_ms)
                
            # If not an ambiguous Open|Filtered, accept the definitive state
            if result.state != PortState.OPEN_FILTERED:
                return result
                
            last_result = result
            # Exponential backoff for retries to handle rate-limited ICMP error generation
            time.sleep((1.5 ** attempt) * 0.5)
            timeout *= 1.5
            
        return last_result or ScanResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp", scan_method="udp")

    def _probe_port_udp(self, port: int, src_port: int, timeout: float) -> ScanResult:
        pkt = self.packet_engine.craft_udp_service_probe(self.config.target_ip, port, src_port)
        
        t0 = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        latency = (time.time() - t0) * 1000
        
        self.heat_meter.record_packet()
        self.session.record_send()
        
        service_guess = SERVICE_MAP.get(port, None)
        
        if resp is None:
            # Silence generally means Open|Filtered for UDP
            return ScanResult(
                port=port, state=PortState.OPEN_FILTERED, protocol="udp",
                latency_ms=latency, scan_method="udp", service_guess=service_guess, confidence=0.3
            )
            
        if resp.haslayer(UDP):
            # UDP response indicates the port is open and actively talking
            return ScanResult(
                port=port, state=PortState.OPEN, protocol="udp",
                ttl_received=resp[IP].ttl, latency_ms=latency,
                scan_method="udp", service_guess=service_guess, confidence=0.95
            )
            
        if resp.haslayer(ICMP):
            icmp_type = resp.getlayer(ICMP).type
            icmp_code = resp.getlayer(ICMP).code
            
            # Type 3 = Destination Unreachable
            if icmp_type == 3:
                if icmp_code == 3: # Port Unreachable -> Closed
                    return ScanResult(
                        port=port, state=PortState.CLOSED, protocol="udp",
                        ttl_received=resp[IP].ttl, latency_ms=latency,
                        scan_method="udp", service_guess=service_guess, confidence=0.95
                    )
                # Network/Host/Admin Unreachable etc. -> Filtered
                elif icmp_code in (0, 1, 2, 9, 10, 13):
                    return ScanResult(
                        port=port, state=PortState.FILTERED, protocol="udp",
                        ttl_received=resp[IP].ttl, latency_ms=latency,
                        scan_method="udp", service_guess=service_guess, confidence=0.8
                    )
                    
        # Catch-all
        return ScanResult(
            port=port, state=PortState.FILTERED, protocol="udp",
            latency_ms=latency, scan_method="udp", service_guess=service_guess, confidence=0.4
        )

    def _resolve_ports(self) -> List[int]:
        if self.config.ports:
            return list(self.config.ports)
        ports = []
        for part in self.config.port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
