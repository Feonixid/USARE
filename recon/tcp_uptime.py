"""
USARE TCP Timestamp Uptime Estimator

Extracts TCP Timestamps from SYN-ACK responses (RFC 7323) to estimate
the host's uptime. This leaks information about patching cycles and
can distinguish between rebooted hosts vs long-running legacy systems.

Since most OS kernels increment the timestamp clock at a fixed frequency
(usually 100Hz, 250Hz, or 1000Hz), we can estimate uptime based on the
raw TSval.
"""

import socket
import logging
import time
import struct
from typing import Dict, Optional, Tuple

logger = logging.getLogger("usare.tcp_timestamp")

def estimate_uptime(host: str, port: int, timeout: float = 3.0) -> Optional[Dict]:
    """
    Connect to a TCP port, extract TSval from the SYN-ACK (if using raw sockets)
    or from established connection (using socket options if supported).
    
    Python's standard socket API doesn't easily expose TCP options like TSval 
    from the raw SYN-ACK without packet sniffing. As a fallback/approximation,
    some platforms support TCP_INFO to get timestamp data on established sockets.
    
    For full accuracy, this should be wired into the raw packet sniffer
    (like syn_scanner or passive_listener).
    """
    
    # In Linux, TCP_INFO provides tcpi_rcv_tsval and tcpi_snd_tsval
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try to read TCP_INFO (Linux specific)
        # TCP_INFO is optname 11 in SOL_TCP
        try:
            # struct tcp_info size is roughly 104-192 bytes depending on kernel
            info = sock.getsockopt(socket.IPPROTO_TCP, 11, 256)
            
            # tcpi_options is generally field 3 (1 byte)
            # rc_tsval/snd_tsval are further down. 
            # Given struct variations, unpacking reliably in pure python is hard.
            # Instead, we define a simpler Raw packet analyzer function for use
            # with Scapy later.
            sock.close()
        except OSError:
            sock.close()
            
    except Exception as e:
        logger.debug(f"[Uptime] Failed to connect: {e}")

    return None

def analyze_raw_tcp_timestamp(ts_val: int) -> Dict:
    """
    Given a raw TSval from a packet, estimate uptime.
    Most Linux/Windows systems use 1000Hz (1ms/tick).
    Some older systems use 100Hz (10ms/tick) or 250Hz.
    We return estimates for common frequencies.
    """
    
    if ts_val == 0:
        return {"uptime_supported": False}
        
    # Convert ticks to seconds based on common frequencies
    uptime_1000hz = ts_val / 1000.0
    uptime_250hz = ts_val / 250.0
    uptime_100hz = ts_val / 100.0
    
    def format_uptime(secs: float) -> str:
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        return f"{days} days, {hours} hours"
        
    return {
        "uptime_supported": True,
        "raw_tsval": ts_val,
        "estimates": {
            "1000Hz (Modern Linux/Windows)": format_uptime(uptime_1000hz),
            "250Hz (Some BSD/Linux)": format_uptime(uptime_250hz),
            "100Hz (Legacy)": format_uptime(uptime_100hz)
        },
        "likely_uptime_days": round(uptime_1000hz / 86400, 1) # Assume 1000Hz as default
    }
