"""
USARE Script: ssh-hostkey
Retrieves SSH host key fingerprints and algorithms without authentication.
Nmap equivalent: ssh-hostkey NSE script.
"""
import socket, hashlib, base64, struct
from typing import List, Dict, Any

DESCRIPTION = "Retrieve SSH host key fingerprints and supported algorithms"
CATEGORIES  = ["safe", "discovery"]
SSH_PORTS   = {22, 2222, 22222, 8022}

def _parse_ssh_banner_and_kex(target, port, timeout):
    """Connect to SSH, read banner + KEX_INIT to extract host key algorithms."""
    result = {}
    sock = socket.create_connection((target, port), timeout=timeout)
    try:
        # Read banner
        banner = b""
        while b"\n" not in banner:
            banner += sock.recv(256)
        result["banner"] = banner.decode("utf-8", errors="replace").strip()

        # Send our banner
        sock.sendall(b"SSH-2.0-USARE_2.0\r\n")

        # Read SSH_MSG_KEXINIT (packet)
        raw = b""
        while len(raw) < 4:
            raw += sock.recv(4)
        length = struct.unpack(">I", raw[:4])[0]
        padding_start = raw[4:5]

        payload = b""
        needed  = length - 1  # exclude padding_length byte itself
        while len(payload) < needed:
            chunk = sock.recv(needed - len(payload))
            if not chunk: break
            payload += chunk

        if payload and payload[0] == 20:  # SSH_MSG_KEXINIT
            # Skip cookie (16 bytes) + msg type (1 byte)
            offset = 17
            def read_namelist(data, off):
                if off + 4 > len(data): return [], off
                ln = struct.unpack(">I", data[off:off+4])[0]
                off += 4
                names = data[off:off+ln].decode("utf-8", errors="replace").split(",") if ln else []
                return names, off + ln

            kex_algs,  offset = read_namelist(payload, offset)
            host_algs, offset = read_namelist(payload, offset)
            enc_c2s,   offset = read_namelist(payload, offset)
            enc_s2c,   offset = read_namelist(payload, offset)
            mac_c2s,   offset = read_namelist(payload, offset)

            result["kex_algorithms"]         = kex_algs
            result["host_key_algorithms"]    = host_algs
            result["encryption_algorithms"]  = enc_c2s
            result["mac_algorithms"]         = mac_c2s

            # Flag weak algorithms
            weak_enc = {"arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc"}
            weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
            weak_mac = {"hmac-md5", "hmac-sha1", "hmac-sha1-96", "hmac-md5-96"}

            result["weak_encryption"]  = [a for a in enc_c2s if a in weak_enc]
            result["weak_kex"]         = [a for a in kex_algs if a in weak_kex]
            result["weak_mac"]         = [a for a in mac_c2s if a in weak_mac]

    finally:
        sock.close()
    return result

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout = float(script_args.get("ssh.timeout", 8))
    results = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in SSH_PORTS and "ssh" not in service:
            continue

        try:
            info = _parse_ssh_banner_and_kex(target_ip, port, timeout)
            info["security_notes"] = []

            if info.get("weak_encryption"):
                info["security_notes"].append(
                    f"WEAK ENCRYPTION: {', '.join(info['weak_encryption'])}"
                )
            if info.get("weak_kex"):
                info["security_notes"].append(
                    f"WEAK KEX: {', '.join(info['weak_kex'])}"
                )
            if info.get("weak_mac"):
                info["security_notes"].append(
                    f"WEAK MAC: {', '.join(info['weak_mac'])}"
                )

            results[port] = info
        except Exception as e:
            results[port] = {"error": str(e)[:120]}

    return results if results else {"note": "No SSH ports found"}
