"""
USARE TCP Timestamp Clock Skew Fingerprinting

Analyzes TCP timestamp values across multiple responses to calculate
clock frequency and determine exact OS, uptime, and VM detection.

Linux: 250Hz (4ms increments)
Windows: 100Hz (10ms increments) 
BSD: varying rates (often 1000Hz)
VMs: inconsistent clock rates
"""

import time
import math
import statistics
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from scapy.all import TCP, Raw
import logging

logger = logging.getLogger("usare.timestamp_analysis")

@dataclass
class TimestampObservation:
    """Single TCP timestamp observation."""
    tsval: int          # Timestamp value from target
    tsecr: int          # Timestamp echo reply
    latency_ms: float   # Round-trip time
    observation_time: float  # When we observed this

@dataclass
class ClockAnalysis:
    """Results of TCP timestamp clock analysis."""
    clock_frequency_hz: float
    estimated_uptime_hours: float
    os_confidence: Dict[str, float]
    is_virtual_machine: bool
    clock_consistency: float  # 0-1, higher = more consistent
    observations_count: int
    analysis_confidence: float

class TCPClockAnalyzer:
    """Advanced TCP timestamp clock skew analysis."""
    
    # Known clock frequencies by OS
    OS_CLOCK_RATES = {
        'Linux': 250.0,      # 4ms increments
        'Windows': 100.0,    # 10ms increments  
        'FreeBSD': 1000.0,   # 1ms increments
        'OpenBSD': 1000.0,   # 1ms increments
        'macOS': 1000.0,     # 1ms increments
        'Cisco IOS': 1000.0, # 1ms increments
        'Juniper': 1000.0,   # 1ms increments
    }
    
    # VM detection thresholds
    VM_INCONSISTENCY_THRESHOLD = 0.15  # 15% variance suggests VM
    MIN_OBSERVATIONS = 8  # Need at least 8 observations for analysis
    
    def __init__(self):
        self.observations: List[TimestampObservation] = []
        self.start_time = time.time()
        
    def add_observation(self, tsval: int, tsecr: int, latency_ms: float) -> None:
        """Add a TCP timestamp observation."""
        obs = TimestampObservation(
            tsval=tsval,
            tsecr=tsecr, 
            latency_ms=latency_ms,
            observation_time=time.time()
        )
        self.observations.append(obs)
        logger.debug(f"[USARE] Added timestamp observation: tsval={tsval}, tsecr={tsecr}")
        
    def calculate_clock_frequency(self) -> Optional[float]:
        """Calculate the target's TCP timestamp clock frequency in Hz."""
        if len(self.observations) < self.MIN_OBSERVATIONS:
            return None
            
        # Extract timestamps and times
        timestamps = [obs.tsval for obs in self.observations]
        times = [obs.observation_time for obs in self.observations]
        
        # Calculate deltas
        ts_deltas = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        time_deltas = [times[i] - times[i-1] for i in range(1, len(times))]
        
        # Filter out zero or negative deltas (clock wraps, reordering)
        valid_deltas = []
        for ts_delta, time_delta in zip(ts_deltas, time_deltas):
            if ts_delta > 0 and time_delta > 0:
                frequency = ts_delta / time_delta
                if 50 < frequency < 20000:  # Reasonable clock rate range
                    valid_deltas.append(frequency)
        
        if len(valid_deltas) < 3:
            return None
            
        # Use median to reduce impact of outliers
        return statistics.median(valid_deltas)
        
    def estimate_uptime(self, clock_frequency: float) -> Optional[float]:
        """Estimate target uptime in hours from current timestamp."""
        if not self.observations or clock_frequency <= 0:
            return None
            
        # Get the most recent timestamp
        latest_obs = max(self.observations, key=lambda x: x.observation_time)
        current_ts = latest_obs.tsval
        
        # Estimate seconds since boot (32-bit timestamp wraps every ~13 hours at 250Hz)
        # Assume current timestamp is close to current time * frequency
        seconds_since_boot = current_ts / clock_frequency
        
        # Convert to hours
        uptime_hours = seconds_since_boot / 3600
        
        # Apply some sanity checks
        if uptime_hours < 0 or uptime_hours > 8760:  # Max 1 year
            return None
            
        return uptime_hours
        
    def detect_virtual_machine(self, clock_frequency: float) -> Tuple[bool, float]:
        """Detect if target is likely a virtual machine."""
        if len(self.observations) < self.MIN_OBSERVATIONS:
            return False, 0.0
            
        # Calculate clock consistency
        timestamps = [obs.tsval for obs in self.observations]
        times = [obs.observation_time for obs in self.observations]
        
        # Expected vs actual timestamp progression
        expected_frequency = clock_frequency
        actual_frequencies = []
        
        for i in range(1, len(timestamps)):
            ts_delta = timestamps[i] - timestamps[i-1]
            time_delta = times[i] - times[i-1]
            
            if ts_delta > 0 and time_delta > 0:
                actual_freq = ts_delta / time_delta
                actual_frequencies.append(actual_freq)
        
        if len(actual_frequencies) < 3:
            return False, 0.0
            
        # Calculate coefficient of variation
        mean_freq = statistics.mean(actual_frequencies)
        std_freq = statistics.stdev(actual_frequencies) if len(actual_frequencies) > 1 else 0
        
        if mean_freq > 0:
            cv = std_freq / mean_freq  # Coefficient of variation
        else:
            cv = 1.0
            
        # VMs often have inconsistent clock rates
        is_vm = cv > self.VM_INCONSISTENCY_THRESHOLD
        
        return is_vm, cv
        
    def match_os_frequency(self, clock_frequency: float) -> Dict[str, float]:
        """Match clock frequency to known OS frequencies."""
        os_confidence = {}
        
        for os_name, os_freq in self.OS_CLOCK_RATES.items():
            # Calculate how close the observed frequency is to expected
            if os_freq > 0:
                error_percent = abs(clock_frequency - os_freq) / os_freq
                confidence = max(0, 1 - error_percent * 2)  # Penalize errors
                os_confidence[os_name] = confidence
                
        # Normalize confidences
        total_confidence = sum(os_confidence.values())
        if total_confidence > 0:
            for os_name in os_confidence:
                os_confidence[os_name] /= total_confidence
                
        return os_confidence
        
    def analyze(self) -> ClockAnalysis:
        """Perform complete TCP timestamp clock analysis."""
        logger.info(f"[USARE] Analyzing {len(self.observations)} timestamp observations")
        
        if len(self.observations) < self.MIN_OBSERVATIONS:
            return ClockAnalysis(
                clock_frequency_hz=0.0,
                estimated_uptime_hours=0.0,
                os_confidence={},
                is_virtual_machine=False,
                clock_consistency=0.0,
                observations_count=len(self.observations),
                analysis_confidence=0.0
            )
            
        # Calculate clock frequency
        clock_frequency = self.calculate_clock_frequency()
        if not clock_frequency:
            logger.warning("[USARE] Could not determine clock frequency")
            return ClockAnalysis(
                clock_frequency_hz=0.0,
                estimated_uptime_hours=0.0,
                os_confidence={},
                is_virtual_machine=False,
                clock_consistency=0.0,
                observations_count=len(self.observations),
                analysis_confidence=0.0
            )
            
        # Estimate uptime
        uptime = self.estimate_uptime(clock_frequency) or 0.0
        
        # OS detection
        os_confidence = self.match_os_frequency(clock_frequency)
        
        # VM detection
        is_vm, consistency = self.detect_virtual_machine(clock_frequency)
        
        # Overall confidence based on observation count and consistency
        obs_confidence = min(1.0, len(self.observations) / 20.0)  # More obs = higher confidence
        consistency_confidence = 1.0 - consistency  # More consistent = higher confidence
        analysis_confidence = (obs_confidence + consistency_confidence) / 2.0
        
        logger.info(f"[USARE] Clock analysis complete: {clock_frequency:.1f}Hz, "
                   f"uptime: {uptime:.1f}h, VM: {is_vm}")
        
        return ClockAnalysis(
            clock_frequency_hz=clock_frequency,
            estimated_uptime_hours=uptime,
            os_confidence=os_confidence,
            is_virtual_machine=is_vm,
            clock_consistency=1.0 - consistency,
            observations_count=len(self.observations),
            analysis_confidence=analysis_confidence
        )
        
    def extract_timestamp_from_packet(self, packet) -> Optional[Tuple[int, int]]:
        """Extract TCP timestamp options from packet."""
        if not packet.haslayer(TCP):
            return None
            
        tcp = packet[TCP]
        
        # TCP timestamp option format: Kind(1), Length(1), Timestamp Value(4), Timestamp Echo(4)
        # Option kind 8 = Timestamp
        for option in tcp.options:
            if isinstance(option, tuple) and len(option) >= 2:
                opt_kind, opt_data = option[0], option[1]
                if opt_kind == 8 and len(opt_data) >= 8:  # Timestamp option
                    tsval = int.from_bytes(opt_data[:4], byteorder='big')
                    tsecr = int.from_bytes(opt_data[4:8], byteorder='big')
                    return tsval, tsecr
                    
        return None

# Integration function for existing scanner
def analyze_timestamps_from_scan_results(scan_results: List) -> ClockAnalysis:
    """Analyze TCP timestamps from existing scan results."""
    analyzer = TCPClockAnalyzer()
    
    for result in scan_results:
        if hasattr(result, 'raw_packet') and result.raw_packet:
            ts_data = analyzer.extract_timestamp_from_packet(result.raw_packet)
            if ts_data and result.latency_ms:
                tsval, tsecr = ts_data
                analyzer.add_observation(tsval, tsecr, result.latency_ms)
                
    return analyzer.analyze()
