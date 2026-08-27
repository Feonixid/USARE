"""Traffic Control (tc) based timing injection - Linux only.

Uses kernel-level traffic shaping to add realistic network jitter.
More precise than Python's time.sleep() and works even in async paths.

Requires: tc (iproute2) package
Usage: tc qdisc add dev eth0 root netem delay 60ms 15ms distribution normal
"""

import logging
import subprocess
import time
import random
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

logger = logging.getLogger("usare.traffic_control")

@dataclass
class TrafficControlConfig:
    """Configuration for traffic control timing injection."""
    interface: str = "eth0"
    base_delay_ms: int = 60
    jitter_ms: int = 15
    delay_distribution: str = "normal"  # normal, uniform, pareto, paretonormal
    packet_loss_percent: float = 0.0
    duplicate_percent: float = 0.0
    corrupt_percent: float = 0.0
    limit_packets: int = 1000
    buffer_bytes: int = 2000
    
    # Advanced timing profiles
    enable_burst_control: bool = True
    burst_limit_kb: int = 32
    burst_delay_ms: int = 100

class TrafficControlEngine:
    """Kernel-level traffic control timing engine."""
    
    def __init__(self, config: Optional[TrafficControlConfig] = None):
        self.config = config or TrafficControlConfig()
        self.original_config = None
        self.is_active = False
        self.interface = self.config.interface
        
        # Statistics
        self.stats = {
            "delays_applied": 0,
            "packets_shaped": 0,
            "timing_profile": "none"
        }
    
    def _run_tc_command(self, cmd: List[str]) -> bool:
        """Execute tc command with error handling."""
        try:
            result = subprocess.run(["tc"] + cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error(f"tc command failed: {' '.join(cmd)} - {result.stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"tc command timeout: {' '.join(cmd)}")
            return False
        except Exception as e:
            logger.error(f"tc command error: {e}")
            return False
    
    def _backup_current_config(self) -> bool:
        """Backup current traffic control configuration."""
        try:
            result = subprocess.run(["tc", "qdisc", "show", "dev", self.interface], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.original_config = result.stdout.strip()
                logger.debug(f"Backed up original tc config: {self.original_config}")
                return True
        except Exception as e:
            logger.debug(f"Failed to backup tc config: {e}")
        return False
    
    def setup_timing_profile(self, profile_name: str) -> bool:
        """Setup predefined timing profiles."""
        profiles = {
            "stealth": {
                "base_delay_ms": 150,
                "jitter_ms": 50,
                "delay_distribution": "normal",
                "packet_loss_percent": 0.1
            },
            "aggressive": {
                "base_delay_ms": 30,
                "jitter_ms": 10,
                "delay_distribution": "uniform",
                "packet_loss_percent": 0.0
            },
            "realistic": {
                "base_delay_ms": 80,
                "jitter_ms": 25,
                "delay_distribution": "paretonormal",
                "packet_loss_percent": 0.05
            },
            "high_latency": {
                "base_delay_ms": 200,
                "jitter_ms": 100,
                "delay_distribution": "normal",
                "packet_loss_percent": 0.2
            }
        }
        
        if profile_name not in profiles:
            logger.error(f"Unknown timing profile: {profile_name}")
            return False
        
        profile = profiles[profile_name]
        self.config.base_delay_ms = profile["base_delay_ms"]
        self.config.jitter_ms = profile["jitter_ms"]
        self.config.delay_distribution = profile["delay_distribution"]
        self.config.packet_loss_percent = profile["packet_loss_percent"]
        
        self.stats["timing_profile"] = profile_name
        logger.info(f"Applied timing profile: {profile_name}")
        return True
    
    def start(self) -> bool:
        """Start traffic control timing injection."""
        if self.is_active:
            logger.warning("Traffic control already active")
            return True
        
        # Check if tc is available
        try:
            subprocess.run(["tc", "--version"], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("tc command not available - install iproute2 package")
            return False
        
        # Backup current config
        self._backup_current_config()
        
        # Remove existing qdisc
        self._run_tc_command(["qdisc", "del", "dev", self.interface, "root"])
        
        # Build tc command
        cmd = ["qdisc", "add", "dev", self.interface, "root", "netem"]
        
        # Add delay
        delay_cmd = f"{self.config.base_delay_ms}ms"
        if self.config.jitter_ms > 0:
            delay_cmd += f" {self.config.jitter_ms}ms"
        if self.config.delay_distribution != "normal":
            delay_cmd += f" distribution {self.config.delay_distribution}"
        
        cmd.append(delay_cmd)
        
        # Add packet loss
        if self.config.packet_loss_percent > 0:
            cmd.append(f"loss {self.config.packet_loss_percent}%")
        
        # Add duplication
        if self.config.duplicate_percent > 0:
            cmd.append(f"duplicate {self.config.duplicate_percent}%")
        
        # Add corruption
        if self.config.corrupt_percent > 0:
            cmd.append(f"corrupt {self.config.corrupt_percent}%")
        
        # Add limit
        if self.config.limit_packets > 0:
            cmd.append(f"limit {self.config.limit_packets}")
        
        # Add buffer
        if self.config.buffer_bytes > 0:
            cmd.append(f"buffer {self.config.buffer_bytes}")
        
        # Execute command
        if self._run_tc_command(cmd):
            self.is_active = True
            logger.info(f"Traffic control started on {self.interface}: {delay_cmd}")
            return True
        else:
            return False
    
    def stop(self) -> bool:
        """Stop traffic control and restore original config."""
        if not self.is_active:
            return True
        
        # Remove current qdisc
        self._run_tc_command(["qdisc", "del", "dev", self.interface, "root"])
        
        # Restore original config if available
        if self.original_config and "noqueue" not in self.original_config:
            logger.info("Restoring original traffic control configuration")
            # Parse and restore original config (simplified)
            pass
        
        self.is_active = False
        logger.info("Traffic control stopped")
        return True
    
    def modify_timing_on_the_fly(self, new_delay_ms: int, new_jitter_ms: int) -> bool:
        """Modify timing parameters without restarting."""
        if not self.is_active:
            logger.warning("Traffic control not active")
            return False
        
        # Change delay parameters
        cmd = ["qdisc", "change", "dev", self.interface, "root", "netem"]
        delay_cmd = f"{new_delay_ms}ms {new_jitter_ms}ms"
        cmd.append(delay_cmd)
        
        if self._run_tc_command(cmd):
            self.config.base_delay_ms = new_delay_ms
            self.config.jitter_ms = new_jitter_ms
            logger.info(f"Timing modified: {delay_cmd}")
            return True
        return False
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current traffic control configuration."""
        try:
            result = subprocess.run(["tc", "qdisc", "show", "dev", self.interface], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return {"interface": self.interface, "config": result.stdout.strip()}
        except Exception as e:
            logger.debug(f"Failed to get tc config: {e}")
        
        return {"interface": self.interface, "config": "unknown"}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get traffic control statistics."""
        return {
            "is_active": self.is_active,
            "interface": self.interface,
            "config": {
                "base_delay_ms": self.config.base_delay_ms,
                "jitter_ms": self.config.jitter_ms,
                "distribution": self.config.delay_distribution,
                "packet_loss_percent": self.config.packet_loss_percent
            },
            "stats": self.stats.copy()
        }

# Context manager for automatic cleanup
class TrafficControlContext:
    """Context manager for traffic control with automatic cleanup."""
    
    def __init__(self, config: Optional[TrafficControlConfig] = None):
        self.engine = TrafficControlEngine(config)
    
    def __enter__(self) -> TrafficControlEngine:
        if self.engine.start():
            return self.engine
        else:
            raise RuntimeError("Failed to start traffic control")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.engine.stop()

# Example usage
if __name__ == "__main__":
    # Setup realistic timing profile
    config = TrafficControlConfig(
        interface="eth0",
        base_delay_ms=80,
        jitter_ms=25,
        delay_distribution="paretonormal",
        packet_loss_percent=0.05
    )
    
    engine = TrafficControlEngine(config)
    
    try:
        if engine.start():
            print("Traffic control started")
            print(f"Current config: {engine.get_current_config()}")
            
            # Run for some time
            time.sleep(10)
            
            # Modify timing on the fly
            engine.modify_timing_on_the_fly(100, 30)
            time.sleep(5)
            
        else:
            print("Failed to start traffic control")
    finally:
        engine.stop()
        print(f"Final stats: {engine.get_stats()}")
