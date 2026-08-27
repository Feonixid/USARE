"""
USARE Script: http-methods
Discovers allowed HTTP methods via OPTIONS and tests for dangerous ones.
Identifies PUT (file upload), DELETE, TRACE (XST), and CONNECT.
Nmap equivalent: http-methods NSE script.
"""
import socket, ssl, re
from typing import List, Dict, Any

DESCRIPTION = "Discover dangerous HTTP methods (PUT/DELETE/TRACE) via OPTIONS"
CATEGORIES  = ["safe", "discovery"]
WEB_PORTS   = {80, 443, 8080, 8443, 8888, 3000, 5000, 8000, 9090}
DANGEROUS   = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

def _request(target, port, method, path, tls, timeout, extra_headers=""):
    sock = socket.create_connection((target, port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=target)
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: Mozilla/5.0 USARE/2.0\r\n"
        f"Content-Length: 0\r\n"
        f"{extra_headers}"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    while len(resp) < 8192:
        chunk = sock.recv(2048)
        if not chunk: break
        resp += chunk
    sock.close()
    return resp.decode("utf-8", errors="replace")

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout = float(script_args.get("http.timeout", 6))
    path    = script_args.get("http.path", "/")
    results = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in WEB_PORTS and "http" not in service:
            continue

        tls = port in (443, 8443, 4443, 9443)
        info: Dict[str, Any] = {
            "allowed_methods": [],
            "dangerous_methods": [],
            "trace_enabled": False,
            "put_enabled": False,
            "notes": [],
        }

        try:
            # OPTIONS request
            resp = _request(target_ip, port, "OPTIONS", path, tls, timeout)
            allow_hdr = re.search(r"\nAllow:\s*(.+?)[\r\n]", resp, re.I)
            if allow_hdr:
                methods = [m.strip() for m in allow_hdr.group(1).split(",")]
                info["allowed_methods"] = methods
                info["dangerous_methods"] = [m for m in methods if m in DANGEROUS]
                if "TRACE" in methods:
                    info["trace_enabled"] = True
                    info["notes"].append("WARNING: TRACE enabled — Cross-Site Tracing (XST) possible")
                if "PUT" in methods:
                    info["put_enabled"] = True
                    info["notes"].append("WARNING: PUT enabled — file upload may be possible")
                if "DELETE" in methods:
                    info["notes"].append("WARNING: DELETE enabled — resource deletion possible")
                if any(m in methods for m in ("PROPFIND", "PROPPATCH", "MKCOL")):
                    info["notes"].append("INFO: WebDAV methods detected")

            # Confirm TRACE with actual request
            if info["trace_enabled"]:
                trace_resp = _request(target_ip, port, "TRACE", path, tls, timeout,
                                      extra_headers="X-Test-Header: usare\r\n")
                if "X-Test-Header" in trace_resp:
                    info["trace_reflection_confirmed"] = True
                    info["notes"].append("CONFIRMED: TRACE reflects headers (XST confirmed)")

        except Exception as e:
            info["error"] = str(e)[:100]

        results[port] = info

    return results if results else {"note": "No HTTP ports found"}
