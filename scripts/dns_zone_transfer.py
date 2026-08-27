"""
USARE Script: dns-zone-transfer
Attempts DNS zone transfer (AXFR) against discovered DNS servers.
A successful transfer leaks all hostnames, IPs, and MX/SPF records.
Nmap equivalent: dns-zone-transfer NSE script.
"""
import socket, struct
from typing import List, Dict, Any

DESCRIPTION = "Attempt DNS AXFR zone transfer against DNS servers"
CATEGORIES  = ["discovery", "safe"]
DNS_PORTS   = {53, 5353}

def _build_axfr_query(domain: str) -> bytes:
    """Build a raw DNS AXFR (TCP) query packet."""
    tx_id  = struct.pack(">H", 0x1337)
    flags  = struct.pack(">H", 0x0000)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    qname  = b""
    for label in domain.rstrip(".").split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    qtype  = struct.pack(">H", 252)  # AXFR
    qclass = struct.pack(">H", 1)    # IN
    body   = tx_id + flags + counts + qname + qtype + qclass
    # TCP DNS: 2-byte length prefix
    return struct.pack(">H", len(body)) + body

def _parse_name(data: bytes, offset: int) -> tuple:
    """Parse a compressed DNS name, return (name, new_offset)."""
    labels = []
    jumped = False
    orig_offset = offset
    max_jumps = 20
    while offset < len(data) and max_jumps > 0:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data): break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = ptr
            jumped = True
            max_jumps -= 1
        else:
            offset += 1
            if offset + length > len(data): break
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    if jumped:
        return ".".join(labels), orig_offset
    return ".".join(labels), offset

def _parse_axfr_response(data: bytes) -> List[Dict]:
    """Parse DNS AXFR TCP response into records."""
    records = []
    offset  = 12  # skip DNS header
    ancount = struct.unpack(">H", data[6:8])[0]

    for _ in range(min(ancount, 500)):
        if offset >= len(data): break
        try:
            name, offset = _parse_name(data, offset)
            if offset + 10 > len(data): break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen

            record: Dict = {"name": name, "type": rtype, "ttl": ttl}

            if rtype == 1 and rdlen == 4:   # A
                record["value"] = ".".join(str(b) for b in rdata)
                record["type_name"] = "A"
            elif rtype == 28 and rdlen == 16:  # AAAA
                record["value"] = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
                record["type_name"] = "AAAA"
            elif rtype in (2, 5, 12, 15):  # NS, CNAME, PTR, MX
                names = {2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}
                skip  = 2 if rtype == 15 else 0  # MX has 2-byte preference
                val, _ = _parse_name(data, offset - rdlen + skip)
                record["value"]     = val
                record["type_name"] = names[rtype]
            elif rtype == 16:  # TXT
                txt_parts = []
                p = 0
                while p < len(rdata):
                    ln = rdata[p]; p += 1
                    txt_parts.append(rdata[p:p+ln].decode("utf-8", errors="replace"))
                    p += ln
                record["value"]     = " ".join(txt_parts)
                record["type_name"] = "TXT"
            else:
                record["value"]     = rdata.hex()
                record["type_name"] = f"TYPE{rtype}"

            records.append(record)
        except Exception:
            break

    return records

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout  = float(script_args.get("dns.timeout", 8))
    domains  = script_args.get("dns.domains", "").split(",")
    if not domains or not domains[0]:
        # Try to auto-discover from PTR record
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            parts = hostname.split(".")
            domains = [".".join(parts[-2:])] if len(parts) >= 2 else []
        except Exception:
            domains = []

    results: Dict[str, Any] = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        if port not in DNS_PORTS and "dns" not in service:
            continue

        port_result: Dict[str, Any] = {"transfer_successful": False, "records": [], "domains_tried": []}

        for domain in domains[:5]:
            domain = domain.strip()
            if not domain:
                continue
            port_result["domains_tried"].append(domain)
            try:
                # DNS zone transfers MUST use TCP
                sock = socket.create_connection((target_ip, port), timeout=timeout)
                query = _build_axfr_query(domain)
                sock.sendall(query)

                # Read TCP DNS response (may be multi-packet)
                raw = b""
                while len(raw) < 65536:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    raw += chunk
                sock.close()

                if len(raw) > 6:
                    # Strip the 2-byte TCP length prefix
                    data = raw[2:] if len(raw) > 2 else raw
                    rcode = data[3] & 0x0F if len(data) > 3 else 5
                    ancount = struct.unpack(">H", data[6:8])[0] if len(data) > 7 else 0

                    if rcode == 0 and ancount > 1:
                        records = _parse_axfr_response(data)
                        if records:
                            port_result["transfer_successful"] = True
                            port_result["domain"]  = domain
                            port_result["records"] = records[:200]
                            port_result["total_records"] = ancount
                            port_result["note"] = f"CRITICAL: Zone transfer succeeded for {domain} — {len(records)} records leaked"
                            break
                    elif rcode == 9:
                        port_result[f"{domain}_error"] = "NOTAUTH — not authoritative for this zone"
                    elif rcode == 5:
                        port_result[f"{domain}_error"] = "REFUSED — zone transfer denied"

            except Exception as e:
                port_result[f"{domain}_error"] = str(e)[:80]

        results[port] = port_result

    return results if results else {"note": "No DNS ports found"}
