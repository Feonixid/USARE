"""
USARE Script: smtp-enum
Enumerates valid users via SMTP VRFY, EXPN, and RCPT TO commands.
Also checks for open relay and extracts server capabilities.
Nmap equivalent: smtp-enum-users + smtp-commands + smtp-open-relay
"""
import socket
from typing import List, Dict, Any

DESCRIPTION = "Enumerate SMTP commands, test user enumeration, and check for open relay"
CATEGORIES  = ["auth", "discovery", "safe"]
SMTP_PORTS  = {25, 465, 587, 2525}
TEST_USERS  = ["admin", "root", "postmaster", "webmaster", "info", "abuse",
               "test", "mail", "support", "hostmaster", "security"]

def _smtp_cmd(sock, cmd: str) -> str:
    sock.sendall((cmd + "\r\n").encode())
    resp = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        resp += chunk
        lines = resp.decode("utf-8", errors="replace").strip().splitlines()
        if lines:
            last = lines[-1]
            # Multi-line responses: code followed by space (not dash) = final line
            if len(last) >= 4 and last[3] == " ":
                break
        if len(resp) > 32768:
            break
    return resp.decode("utf-8", errors="replace").strip()

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout     = float(script_args.get("smtp.timeout", 8))
    test_users  = script_args.get("smtp.users", ",".join(TEST_USERS)).split(",")
    test_domain = script_args.get("smtp.domain", "example.com")
    results     = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in SMTP_PORTS and "smtp" not in service:
            continue

        info: Dict[str, Any] = {
            "banner":         None,
            "capabilities":   [],
            "vrfy_users":     [],
            "expn_lists":     [],
            "open_relay":     False,
            "starttls":       False,
            "auth_methods":   [],
        }

        try:
            sock = socket.create_connection((target_ip, port), timeout=timeout)

            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            info["banner"] = banner[:200]

            # EHLO
            ehlo_resp = _smtp_cmd(sock, f"EHLO usare.scan.local")
            for line in ehlo_resp.splitlines():
                cap = line[4:].strip() if len(line) > 4 else ""
                if cap:
                    info["capabilities"].append(cap)
                    if cap.upper().startswith("AUTH"):
                        info["auth_methods"] = cap.split()[1:]
                    if "STARTTLS" in cap.upper():
                        info["starttls"] = True

            # VRFY enumeration
            for user in test_users[:10]:
                vrfy = _smtp_cmd(sock, f"VRFY {user}")
                code = vrfy[:3]
                if code in ("250", "251", "252"):
                    info["vrfy_users"].append({"user": user, "response": vrfy[:100]})

            # EXPN
            for lst in ["all", "staff", "users"]:
                expn = _smtp_cmd(sock, f"EXPN {lst}")
                if expn.startswith("250"):
                    info["expn_lists"].append({"list": lst, "response": expn[:200]})

            # Open relay test: try to relay external→external
            _smtp_cmd(sock, f"MAIL FROM:<test@{test_domain}>")
            rcpt = _smtp_cmd(sock, f"RCPT TO:<probe@relay-test.{test_domain}>")
            if rcpt.startswith("250"):
                info["open_relay"] = True
                info["open_relay_note"] = "CRITICAL: Server accepted relay to external domain"

            _smtp_cmd(sock, "RSET")
            _smtp_cmd(sock, "QUIT")
            sock.close()

        except Exception as e:
            info["error"] = str(e)[:100]

        results[port] = info

    return results if results else {"note": "No SMTP ports found"}
