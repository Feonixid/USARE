"""ECN (Explicit Congestion Notification) Probing Analysis."""

import logging
from typing import Dict, Optional
from scapy.all import TCP

logger = logging.getLogger("usare.ecn_probe")

def analyze_ecn_response(response) -> Dict[str, any]:
    """Analyze ECN probe response for OS fingerprinting and firewall detection.
    
    ECN probing provides intelligence about:
    - OS support for ECN (Linux full, Windows partial/none)
    - Firewall behavior (many RST ECN packets)
    - Network equipment ECN stripping
    
    Args:
        response: Scapy packet from ECN SYN probe
        
    Returns:
        Dictionary with ECN analysis results
    """
    if not response or not response.haslayer(TCP):
        return {"ecn_support": "filtered", "analysis": "no_response"}
    
    flags = response[TCP].flags
    
    # SYN-ACK response (port open)
    if flags & 0x12 == 0x12:  # SYN+ACK
        ece = bool(flags & 0x40)  # ECE flag set
        cwr = bool(flags & 0x80)  # CWR flag set
        
        os_hint = "Linux" if ece else "Windows/other"
        
        return {
            "ecn_support": "full" if ece and cwr else "partial",
            "ece_flag": ece,
            "cwr_flag": cwr,
            "os_hint": os_hint,
            "analysis": "port_open_with_ecn_response",
            "confidence": 0.8 if ece else 0.6
        }
    
    # RST response (port closed or filtered)
    elif flags & 0x04 == 0x04:  # RST
        return {
            "ecn_support": "rejected_by_firewall",
            "ecn_stripped": True,
            "os_hint": "firewall_present",
            "analysis": "ecn_packet_blocked_or_reset",
            "confidence": 0.7
        }
    
    # Other responses
    else:
        return {
            "ecn_support": "unknown",
            "flags_hex": hex(flags),
            "analysis": "unexpected_response",
            "confidence": 0.3
        }

def correlate_ecn_with_os_fingerprint(ecn_result: Dict[str, any], 
                                   os_fingerprint: Optional[Dict[str, any]] = None) -> Dict[str, any]:
    """Correlate ECN analysis with OS fingerprint for enhanced detection.
    
    Combines ECN probe results with traditional OS fingerprinting
    to improve confidence and detect inconsistencies.
    """
    if not ecn_result:
        return {"correlation": "no_ecn_data"}
    
    correlation = {
        "ecn_result": ecn_result,
        "correlation_confidence": ecn_result.get("confidence", 0.0)
    }
    
    if os_fingerprint:
        os_family = os_fingerprint.get("os_family", "Unknown")
        ecn_os_hint = ecn_result.get("os_hint", "")
        
        # Check for consistency
        if os_family.lower() in ecn_os_hint.lower():
            correlation["consistency"] = "high"
            correlation["correlation_confidence"] += 0.15
        elif "linux" in os_family.lower() and "linux" in ecn_os_hint.lower():
            correlation["consistency"] = "high"
            correlation["correlation_confidence"] += 0.15
        elif "windows" in os_family.lower() and "windows" in ecn_os_hint.lower():
            correlation["consistency"] = "high"
            correlation["correlation_confidence"] += 0.15
        else:
            correlation["consistency"] = "low"
            correlation["inconsistency"] = f"OS says {os_family} but ECN suggests {ecn_os_hint}"
            correlation["correlation_confidence"] -= 0.1
    
    # Cap confidence at 1.0
    correlation["correlation_confidence"] = min(1.0, correlation["correlation_confidence"])
    
    return correlation

def detect_ecn_middlebox(ecn_result: Dict[str, any]) -> Dict[str, any]:
    """Detect presence of middlebox equipment based on ECN behavior.
    
    Many network devices (load balancers, firewalls, routers) strip
    or modify ECN bits, which can be used for infrastructure detection.
    """
    if not ecn_result:
        return {"middlebox_detected": False}
    
    middlebox_analysis = {
        "middlebox_detected": False,
        "device_type": None,
        "confidence": 0.0
    }
    
    ecn_support = ecn_result.get("ecn_support", "")
    
    if ecn_support == "rejected_by_firewall":
        middlebox_analysis["middlebox_detected"] = True
        middlebox_analysis["device_type"] = "firewall"
        middlebox_analysis["confidence"] = 0.8
    elif ecn_support == "filtered":
        middlebox_analysis["middlebox_detected"] = True
        middlebox_analysis["device_type"] = "router_or_nat"
        middlebox_analysis["confidence"] = 0.6
    elif ecn_result.get("ecn_stripped", False):
        middlebox_analysis["middlebox_detected"] = True
        middlebox_analysis["device_type"] = "load_balancer_or_proxy"
        middlebox_analysis["confidence"] = 0.7
    
    return middlebox_analysis
