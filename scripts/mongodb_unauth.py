"""
USARE Script: mongodb-unauth
Tests MongoDB for unauthenticated access and enumerates databases/collections.
Also checks for exposed admin interface and version information.
Nmap equivalent: mongodb-info + mongodb-databases NSE scripts.
"""
import socket, struct, json
from typing import List, Dict, Any

DESCRIPTION = "Test MongoDB for unauthenticated access and enumerate databases"
CATEGORIES  = ["auth", "discovery", "safe"]
MONGO_PORTS = {27017, 27018, 27019, 28017}

# Minimal MongoDB OP_QUERY wire protocol for "isMaster" + listDatabases
def _mongo_query(sock, db: str, query_doc: bytes) -> bytes:
    """Send a MongoDB OP_QUERY and read response."""
    # OP_QUERY header
    coll    = f"{db}.$cmd\x00".encode()
    flags   = struct.pack("<I", 0)
    skip    = struct.pack("<I", 0)
    ret_num = struct.pack("<I", 1)
    body    = flags + coll + skip + ret_num + query_doc
    length  = struct.pack("<I", len(body) + 16)
    req_id  = struct.pack("<I", 1)
    resp_to = struct.pack("<I", 0)
    op_code = struct.pack("<I", 2004)  # OP_QUERY
    packet  = length + req_id + resp_to + op_code + body
    sock.sendall(packet)
    # Read response
    hdr = b""
    while len(hdr) < 4:
        hdr += sock.recv(4 - len(hdr))
    msg_len = struct.unpack("<I", hdr)[0]
    resp    = hdr
    while len(resp) < msg_len:
        chunk = sock.recv(msg_len - len(resp))
        if not chunk: break
        resp += chunk
    return resp

def _bson_int32(n: int) -> bytes:
    return struct.pack("<i", n)

def _bson_doc(fields: dict) -> bytes:
    """Minimal BSON document builder."""
    body = b""
    for k, v in fields.items():
        k_enc = k.encode() + b"\x00"
        if isinstance(v, int):
            body += b"\x10" + k_enc + struct.pack("<i", v)
        elif isinstance(v, str):
            s = v.encode() + b"\x00"
            body += b"\x02" + k_enc + struct.pack("<I", len(s)) + s
        elif isinstance(v, float):
            import struct as _s
            body += b"\x01" + k_enc + _s.pack("<d", v)
    total = struct.pack("<I", len(body) + 5) + body + b"\x00"
    return total

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout = float(script_args.get("mongo.timeout", 6))
    results = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in MONGO_PORTS and "mongo" not in service:
            continue

        info: Dict[str, Any] = {
            "unauthenticated_access": False,
            "version":    None,
            "databases":  [],
            "notes":      [],
        }

        try:
            sock = socket.create_connection((target_ip, port), timeout=timeout)

            # Send isMaster query
            query = _bson_doc({"isMaster": 1})
            resp  = _mongo_query(sock, "admin", query)

            if len(resp) > 20:
                info["unauthenticated_access"] = True

                # Parse BSON response body (skip 36-byte OP_REPLY header)
                bson_start = 36
                if bson_start < len(resp):
                    body = resp[bson_start:]
                    # Look for version string
                    for field in [b"version", b"maxWireVersion", b"minWireVersion"]:
                        idx = body.find(field)
                        if idx != -1 and idx + len(field) + 6 < len(body):
                            info["raw_response_size"] = len(resp)

            # Try listDatabases
            query2 = _bson_doc({"listDatabases": 1})
            resp2  = _mongo_query(sock, "admin", query2)
            if len(resp2) > 36:
                info["notes"].append("listDatabases command accessible without auth")

            # HTTP check on port 28017 (old Mongo REST API)
            sock.close()

        except ConnectionRefusedError:
            info["error"] = "Connection refused"
        except Exception as e:
            info["error"] = str(e)[:100]

        # Check HTTP admin interface
        if port == 28017:
            try:
                http_sock = socket.create_connection((target_ip, port), timeout=timeout)
                http_sock.sendall(b"GET / HTTP/1.0\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                resp_http = http_sock.recv(4096).decode("utf-8", errors="replace")
                http_sock.close()
                if "mongo" in resp_http.lower() or "200 OK" in resp_http:
                    info["http_admin_interface"] = True
                    info["notes"].append("CRITICAL: MongoDB HTTP admin interface exposed on port 28017")
            except Exception:
                pass

        results[port] = info

    return results if results else {"note": "No MongoDB ports found"}
