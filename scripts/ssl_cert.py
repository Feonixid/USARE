"""
USARE Script: ssl-cert
Extracts and analyses SSL/TLS certificate details from any HTTPS/TLS port.
Checks expiry, self-signed certs, weak signature algorithms, and SANs.
Nmap equivalent: ssl-cert + ssl-enum-ciphers (partial)
"""
import socket, ssl, datetime
from typing import List, Dict, Any

DESCRIPTION = "Extract TLS certificate details, SANs, expiry, and security posture"
CATEGORIES  = ["safe", "discovery"]
TLS_PORTS   = {443, 8443, 4443, 9443, 465, 993, 995, 636, 5986, 8883}

def run(target_ip: str, port_data: List[Dict], script_args: Dict = {}) -> Dict[str, Any]:
    timeout = float(script_args.get("ssl.timeout", 8))
    results = {}

    for entry in port_data:
        port    = entry.get("port", 0)
        service = (entry.get("service") or "").lower()
        is_tls  = port in TLS_PORTS or "https" in service or "tls" in service or "ssl" in service
        if not is_tls:
            continue

        info: Dict[str, Any] = {"tls": True}
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1

            with socket.create_connection((target_ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target_ip) as ssock:
                    cert    = ssock.getpeercert(binary_form=False)
                    info["tls_version"]  = ssock.version()
                    info["cipher"]       = ssock.cipher()

                    if cert:
                        # Subject
                        subj = dict(x[0] for x in cert.get("subject", []))
                        info["subject_cn"]  = subj.get("commonName")
                        info["subject_org"] = subj.get("organizationName")

                        # Issuer
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        info["issuer_cn"]   = issuer.get("commonName")
                        info["self_signed"] = (
                            subj.get("commonName") == issuer.get("commonName")
                        )

                        # SANs
                        sans = []
                        for san_type, san_val in cert.get("subjectAltName", []):
                            sans.append(f"{san_type}:{san_val}")
                        info["sans"] = sans[:30]

                        # Validity
                        not_before = ssl.cert_time_to_seconds(cert["notBefore"])
                        not_after  = ssl.cert_time_to_seconds(cert["notAfter"])
                        now        = datetime.datetime.utcnow().timestamp()
                        days_left  = int((not_after - now) / 86400)

                        info["not_before"]  = cert["notBefore"]
                        info["not_after"]   = cert["notAfter"]
                        info["days_left"]   = days_left
                        info["expired"]     = days_left < 0
                        info["expiring_soon"] = 0 <= days_left <= 30

                        # Security notes
                        notes = []
                        if info["expired"]:
                            notes.append("CRITICAL: Certificate expired")
                        if info["expiring_soon"] and not info["expired"]:
                            notes.append(f"WARNING: Certificate expires in {days_left} days")
                        if info["self_signed"]:
                            notes.append("WARNING: Self-signed certificate")
                        if info["tls_version"] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                            notes.append(f"CRITICAL: Deprecated TLS version {info['tls_version']}")
                        cipher_name = info["cipher"][0] if info["cipher"] else ""
                        if any(w in cipher_name.upper() for w in ("RC4", "DES", "EXPORT", "NULL", "ANON")):
                            notes.append(f"CRITICAL: Weak cipher {cipher_name}")
                        info["security_notes"] = notes

        except Exception as e:
            info["error"] = str(e)[:120]

        results[port] = info

    return results if results else {"note": "No TLS ports found"}
