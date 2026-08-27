import socket
import ssl
import time
import logging
import struct
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("usare.sni_smuggler")

class SNISmuggler:
    """
    Implements Domain Fronting and SNI Smuggling.
    Bypasses DPI/Firewalls looking at plaintext ClientHello.
    
    Front Domain (SNI): Allowed domain (e.g. google.com, cloudflare.com)
    Backend Target: Actual IP / Host Header you want to hit
    """
    def __init__(self, front_domain: str = "www.google.com", timeout: float = 5.0):
        self.front_domain = front_domain
        self.timeout = timeout

    def craft_smuggled_request(self, 
                              target_ip: str, 
                              target_port: int, 
                              smuggled_host_header: str, 
                              path: str = "/") -> Tuple[bool, str, Optional[str]]:
        """
        Create a raw socket, wrap it in SSL/TLS with the 'front_domain' SNI,
        then inject a manually crafted HTTP request specifically asking for
        the 'smuggled_host_header' to the actual 'target_ip'.
        """
        try:
            # 1. Establish raw TCP connection to the destination (bypassing normal DNS)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target_ip, target_port))
            
            # 2. Wrap the socket with TLS, injecting the decoy SNI
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Important for hitting direct IPs
            
            secure_sock = context.wrap_socket(sock, server_hostname=self.front_domain)
            
            # 3. Craft raw HTTP request pointing to the hidden target
            http_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {smuggled_host_header}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            # 4. Fire the payload
            secure_sock.sendall(http_req.encode())
            
            # 5. Read response
            response = b""
            while True:
                chunk = secure_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                
            secure_sock.close()
            
            return True, "Smuggled successfully", response.decode(errors="ignore")
            
        except ssl.SSLError as e:
            logger.debug(f"[SNI] Failed SSL Handshake for {target_ip}: {e}")
            return False, f"SSL Handshake Error: {e}", None
        except Exception as e:
            logger.debug(f"[SNI] Smuggling failed against {target_ip}: {e}")
            return False, f"Connection Error: {e}", None

    def probe_front_domains(self, target_ip: str, target_port: int, real_host: str, front_list: list[str]) -> dict:
        """
        Execute parallel probes across a list of potential front domains to see
        if the backend infrastructure routes any of the allowed SNI's.
        """
        results = {}
        
        def _probe(front: str) -> Tuple[str, bool, Optional[str]]:
            smuggler = SNISmuggler(front_domain=front, timeout=self.timeout)
            success, msg, resp = smuggler.craft_smuggled_request(target_ip, target_port, real_host)
            return front, success, resp

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_probe, f) for f in front_list]
            for future in futures:
                front, success, resp = future.result()
                if success and resp is not None:
                    # Basic heuristic to check if we bypassed generic WAF blocks
                    if "403 Forbidden" not in resp and "Cloudflare" not in resp[:150]:  # type: ignore[index]
                        results[front] = "Susceptible (Bypassed block page)"
                    else:
                        results[front] = "Connected but blocked by backend logic"
                else:
                    results[front] = "Failed connection / Handshake rejection"
        
        return results
