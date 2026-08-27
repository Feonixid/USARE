import time
import logging
from typing import Optional, Dict, Any
from scapy.all import sniff, IP, TCP
from recon.os_fingerprint import OSFingerprintEngine
logger = logging.getLogger("usare.coldstart")
class ColdStartSniffer:
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
    def sniff_profile(self, target_ip: str, timeout: int = 120) -> Optional[Dict[str, Any]]:
        logger.info(f"[USARE] Cold Start: Listening passively on interface for organic traffic to {target_ip} for {timeout}s...")
        bpf_filter = f"tcp and src host {target_ip} and tcp[tcpflags] & (tcp-syn) != 0"
        captured = sniff(
            iface=self.interface,
            filter=bpf_filter,
            count=1,
            timeout=timeout,
            store=True
        )
        if not captured:
            logger.warning("[USARE] Cold Start: No organic traffic detected. Falling back to default Windows 10 profile.")
            return None
        pkt = captured[0]
        ttl = pkt[IP].ttl
        window = pkt[TCP].window
        df_flag = bool(pkt[IP].flags & 0x02)
        dummy_response = {
            "ttl": ttl,
            "window": window,
            "df": df_flag,
            "ip_id": pkt[IP].id
        }
        os_engine = OSFingerprintEngine()
        os_guess = os_engine.fingerprint_from_multiple_responses([dummy_response])
        profile = {
            "ttl": ttl,
            "window": window,
            "df_flag": df_flag,
            "os_guess": os_guess.os_name if os_guess else "Unknown"
        }
        logger.info(
            f"[USARE] Cold Start Success! Intercepted organic packet. "
            f"Cloning Profile: TTL={ttl}, Win={window}, DF={df_flag}. "
            f"OS appears to be: {profile['os_guess']}"
        )
        return profile