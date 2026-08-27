import time
import logging
import asyncio
from typing import List, Optional, Dict, Any
from scapy.all import IP, sr1, send, conf
from scapy.layers.sctp import SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkAbort
from recon.syn_scanner import ScanResult, PortState, ScanConfig, chunk_ports
from core.packet_engine import PacketEngine, PacketConfig
from evasion.session import SessionTracker
from ops.heat_meter import HeatMeter
from evasion.timing import GhostTimer, TimingConfig, TimingProfile

logger = logging.getLogger("usare.sctp_scanner")

class SCTPScanner:
    """
    SCTP INIT Scanner for USARE.
    Sends SCTP INIT chunks. 
    INIT-ACK -> OPEN
    ABORT -> CLOSED
    Timeout / No Response -> FILTERED
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
        logger.info(f"[USARE] Starting SCTP INIT scan against {self.config.target_ip}")
        ports = self._resolve_ports()
        
        chunks = chunk_ports(ports, self.config.chunk_size)
        for chunk_idx, port_chunk in enumerate(chunks):
            logger.info(f"[USARE] SCTP Phase — chunk {chunk_idx + 1}/{len(chunks)} ({len(port_chunk)} ports)")
            
            for port in port_chunk:
                if not self.session.check_rate_limit():
                    time.sleep(self.session.time_until_next_allowed())
                
                result = self._probe_port_sctp_with_retries(port)
                self.results.append(result)
                self.session.set_state(self.config.target_ip, port, result.state.value)
                
                if self.config.ghost_mode:
                    self.timer.sync_ghost_wait()
                    
        elapsed = time.time() - (self._start_time or time.time())
        logger.info(f"[USARE] SCTP Scan complete. {len(self.results)} results in {elapsed:.1f}s.")
        return self.results

    def _probe_port_sctp_with_retries(self, port: int) -> ScanResult:
        src_port = self.session.get_pinned_src_port(self.config.target_ip, port)
        timeout = self.config.timeout
        if self.config.adaptive_timeout:
            timeout = self.session.get_adaptive_timeout(self.config.target_ip)
            
        last_result = None
        for attempt in range(self.config.max_retries):
            result = self._probe_port_sctp(port, src_port, timeout)
            result.retries = attempt
            
            self.session.record_probe(
                target=self.config.target_ip,
                port=port,
                method="sctp",
                src_port=src_port,
                response=result.state.value,
                latency_ms=result.latency_ms,
                is_retry=(attempt > 0)
            )
            
            if result.latency_ms:
                self.session.record_rtt(self.config.target_ip, result.latency_ms)
                
            if result.state != PortState.FILTERED:
                return result
                
            last_result = result
            time.sleep((1.5 ** attempt) * 0.5)
            timeout *= 1.5
            
        return last_result or ScanResult(port=port, state=PortState.FILTERED, protocol="sctp")

    def _probe_port_sctp(self, port: int, src_port: int, timeout: float) -> ScanResult:
        ip_layer = IP(dst=self.config.target_ip)
        sctp_layer = SCTP(sport=src_port, dport=port)
        init_chunk = SCTPChunkInit()
        
        pkt = ip_layer / sctp_layer / init_chunk
        
        t0 = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        latency = (time.time() - t0) * 1000
        
        self.heat_meter.record_packet()
        self.session.record_send()
        
        if resp is None:
            return ScanResult(
                port=port, state=PortState.FILTERED, protocol="sctp",
                latency_ms=latency, scan_method="sctp_init", confidence=0.4
            )
            
        if resp.haslayer(SCTPChunkInitAck):
            return ScanResult(
                port=port, state=PortState.OPEN, protocol="sctp",
                ttl_received=resp[IP].ttl, latency_ms=latency,
                scan_method="sctp_init", confidence=0.95
            )
            
        if resp.haslayer(SCTPChunkAbort):
            return ScanResult(
                port=port, state=PortState.CLOSED, protocol="sctp",
                ttl_received=resp[IP].ttl, latency_ms=latency,
                scan_method="sctp_init", confidence=0.95
            )
            
        # Any other ICMP unreachables, etc.
        return ScanResult(
            port=port, state=PortState.FILTERED, protocol="sctp",
            latency_ms=latency, scan_method="sctp_init", confidence=0.7
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
