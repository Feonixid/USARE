"""
USARE Script: http-title
Grabs HTTP/S title, server header, redirect chain, and cookies from web ports.
Nmap equivalent: http-title + http-headers + http-server-header
"""
import socket, ssl, re
from typing import List, Dict, Any

DESCRIPTION = "Grab HTTP title, server, redirect chain, and cookies from web ports"
CATEGORIES  = ["discovery", "safe"]
WEB_PORTS   = {80, 443, 8080, 8443, 8888, 3000, 5000, 8000, 9090, 4443, 7443, 8008}

def _fetch(target, port, tls, ua, timeout):
    sock = socket.create_connection((target, port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=target)
    req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {ua}\r\nConnection: close\r\n\r\n"
    sock.sendall(req.encode())
    resp = b""
    while len(resp) < 65536:
        chunk = sock.recv(4096)
        if not chunk: break
        resp += chunk
    sock.close()
    return resp.decode("utf-8", errors="replace")

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout = float(script_args.get("http.timeout", 6))
    ua      = script_args.get("http.ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) USARE/2.0")
    results = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in WEB_PORTS and service not in ("http", "https", "http-alt", "http-proxy"):
            continue

        tls_options = [True, False] if port in (443, 8443, 4443, 7443, 9443) else [False, True]
        for tls in tls_options:
            try:
                text   = _fetch(target_ip, port, tls, ua, timeout)
                status = re.search(r"HTTP/\S+ (\d{3})", text)
                server = re.search(r"\nServer:\s*(.+?)[\r\n]", text, re.I)
                title  = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                loc    = re.search(r"\nLocation:\s*(.+?)[\r\n]", text, re.I)
                cookies = re.findall(r"\nSet-Cookie:\s*([^;\r\n]+)", text, re.I)
                pw_hint = re.search(r"WWW-Authenticate:\s*(.+?)[\r\n]", text, re.I)

                results[port] = {
                    "status":        int(status.group(1)) if status else None,
                    "server":        server.group(1).strip() if server else None,
                    "title":         re.sub(r"\s+", " ", title.group(1).strip())[:200] if title else None,
                    "redirect":      loc.group(1).strip() if loc else None,
                    "cookies":       cookies[:5] if cookies else [],
                    "auth_required": pw_hint.group(1).strip() if pw_hint else None,
                    "tls":           tls,
                }
                break
            except Exception:
                pass

    return results if results else {"note": "No web ports responded"}
