"""
USARE Script: redis-unauth
Tests Redis for unauthenticated access and enumerates server info.
Nmap equivalent: redis-info NSE script.
"""
import socket
from typing import List, Dict, Any

DESCRIPTION = "Test Redis for unauthenticated access and enumerate server configuration"
CATEGORIES  = ["auth", "discovery", "safe"]
REDIS_PORTS = {6379, 6380, 6381, 16379}

def _redis_cmd(sock, *args):
    """Send a Redis RESP command and read response."""
    cmd  = f"*{len(args)}\r\n"
    cmd += "".join(f"${len(str(a))}\r\n{a}\r\n" for a in args)
    sock.sendall(cmd.encode())
    resp = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        resp += chunk
        if resp.endswith(b"\r\n") and not resp.startswith(b"*"):
            break
        if b"\r\n" in resp and resp.startswith(b"-"):
            break
        if len(resp) > 65536:
            break
    return resp.decode("utf-8", errors="replace").strip()

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout  = float(script_args.get("redis.timeout", 5))
    password = script_args.get("redis.pass", "")
    results  = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in REDIS_PORTS and "redis" not in service:
            continue

        info: Dict[str, Any] = {
            "unauthenticated_access": False,
            "auth_required":          False,
            "version":                None,
            "databases":              [],
            "config_exposure":        [],
            "keyspace_count":         None,
        }

        try:
            sock = socket.create_connection((target_ip, port), timeout=timeout)

            # Try AUTH if password provided
            if password:
                _redis_cmd(sock, "AUTH", password)

            # Ping test
            ping_resp = _redis_cmd(sock, "PING")
            if "+PONG" in ping_resp:
                info["unauthenticated_access"] = True
            elif "NOAUTH" in ping_resp or "ERR" in ping_resp:
                info["auth_required"] = True
                sock.close()
                results[port] = info
                continue

            # INFO server
            info_resp = _redis_cmd(sock, "INFO", "server")
            for line in info_resp.splitlines():
                if ":" in line and not line.startswith("#"):
                    k, _, v = line.partition(":")
                    k = k.strip(); v = v.strip()
                    if k == "redis_version":
                        info["version"] = v
                    elif k == "os":
                        info["os"] = v
                    elif k == "executable":
                        info["executable"] = v
                    elif k == "config_file":
                        info["config_file"] = v

            # INFO keyspace
            ks_resp = _redis_cmd(sock, "INFO", "keyspace")
            for line in ks_resp.splitlines():
                if line.startswith("db"):
                    info["databases"].append(line.strip())
                    keys_match = line.split(",")[0]
                    if "keys=" in keys_match:
                        n = int(keys_match.split("keys=")[1])
                        info["keyspace_count"] = (info.get("keyspace_count") or 0) + n

            # Try to read CONFIG GET (leaks sensitive settings)
            cfg_resp = _redis_cmd(sock, "CONFIG", "GET", "bind")
            if not cfg_resp.startswith("-"):
                info["config_exposure"].append(f"CONFIG GET allowed — bind: {cfg_resp[:80]}")

            # Try DBSIZE
            dbsize = _redis_cmd(sock, "DBSIZE")
            if dbsize.startswith(":"):
                info["total_keys"] = int(dbsize[1:])

            sock.close()

        except Exception as e:
            info["error"] = str(e)[:100]

        results[port] = info

    return results if results else {"note": "No Redis ports found"}
