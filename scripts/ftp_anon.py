"""
USARE Script: ftp-anon
Tests FTP anonymous login and lists accessible files/directories.
Nmap equivalent: ftp-anon NSE script.
"""
import socket, ftplib
from typing import List, Dict, Any

DESCRIPTION = "Test FTP anonymous login and enumerate accessible files"
CATEGORIES  = ["auth", "discovery", "safe"]
FTP_PORTS   = {21, 990, 2121}

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout  = float(script_args.get("ftp.timeout", 8))
    max_list = int(script_args.get("ftp.maxlist", 20))
    results  = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in FTP_PORTS and "ftp" not in service:
            continue

        info: Dict[str, Any] = {"anonymous_login": False, "files": [], "banner": None}

        try:
            # Grab banner first
            sock = socket.create_connection((target_ip, port), timeout=timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            info["banner"] = banner[:200]
        except Exception:
            pass

        try:
            ftp = ftplib.FTP()
            ftp.connect(target_ip, port, timeout=timeout)
            ftp.login("anonymous", "usare@scan.local")
            info["anonymous_login"] = True

            # Try to list root
            files = []
            try:
                ftp.dir(".", lambda line: files.append(line))
            except Exception:
                try:
                    files = ftp.nlst()
                except Exception:
                    pass

            info["files"] = files[:max_list]

            # Try to read system info
            try:
                info["system"] = ftp.sendcmd("SYST")
            except Exception:
                pass
            try:
                info["pwd"] = ftp.pwd()
            except Exception:
                pass

            ftp.quit()

        except ftplib.error_perm as e:
            info["anonymous_login"] = False
            info["error"] = str(e)[:100]
        except Exception as e:
            info["error"] = str(e)[:100]

        results[port] = info

    return results if results else {"note": "No FTP ports found"}
