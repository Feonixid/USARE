import socket
import ssl
import hashlib
import time
import logging
from typing import List, Optional
logger = logging.getLogger("usare.jarm")
JARM_PROBES = [
    ({"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2, "alpn": ["http/1.1"], "ciphers": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"}),
    ({"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2, "alpn": ["http/1.1"], "ciphers": "AES256-SHA:AES128-SHA"}),
    ({"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2, "alpn": ["h2", "http/1.1"], "ciphers": "DEFAULT"}),
    ({"min_version": ssl.TLSVersion.TLSv1_3, "max_version": ssl.TLSVersion.TLSv1_3, "alpn": ["h2"], "ciphers": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"}),
    ({"min_version": ssl.TLSVersion.TLSv1_3, "max_version": ssl.TLSVersion.TLSv1_3, "alpn": ["h2", "http/1.1"], "ciphers": "DEFAULT"}),
    ({"min_version": ssl.TLSVersion.TLSv1_1, "max_version": ssl.TLSVersion.TLSv1_1, "alpn": [], "ciphers": "DEFAULT"}),
    ({"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2, "alpn": ["hq"], "ciphers": "AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384"}),
    ({"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2, "alpn": ["h2"], "ciphers": "ECDHE-RSA-AES256-GCM-SHA384"}),
    ({"min_version": ssl.TLSVersion.TLSv1_3, "max_version": ssl.TLSVersion.TLSv1_3, "alpn": ["http/1.1"], "ciphers": "TLS_AES_128_GCM_SHA256"}),
    ({"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2, "alpn": [], "ciphers": "ECDHE-RSA-AES128-GCM-SHA256"}),
]
class JARMFingerprinter:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    def build_hash(self, target_ip: str, port: int) -> Optional[str]:
        cipher_version = ""
        extensions_list = []
        logger.info(f"[USARE] Executing 10-packet JARM sequence against {target_ip}:{port}")
        for i, probe in enumerate(JARM_PROBES):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = probe["min_version"]
                ctx.maximum_version = probe["max_version"]
                ctx.set_ciphers(probe["ciphers"])
                if probe["alpn"]:
                    ctx.set_alpn_protocols(probe["alpn"])
            except Exception:
                pass
            try:
                sock = socket.create_connection((target_ip, port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=target_ip)
                ver = ssock.version() or "0000"
                ciph = ssock.cipher()
                selected_cipher = ciph[0] if ciph else "0000"
                alpn = ssock.selected_alpn_protocol() or "0000"
                v_char = str(ver.replace("TLSv", ""))[0] if "TLSv" in ver else "0"
                import typing; hdig = typing.cast(typing.Any, hashlib.md5(selected_cipher.encode()).hexdigest())
                c_hash = hdig[:2]
                cipher_version += f"{v_char}{c_hash}"
                extensions_list.append(f"{alpn}_{selected_cipher}")
                ssock.close()
            except Exception as e:
                cipher_version += "000"
                extensions_list.append("failed")
        if cipher_version == "000" * 10:
            return None
        ext_str = "|".join(extensions_list)
        import typing; hdig2 = typing.cast(typing.Any, str(hashlib.sha256(ext_str.encode()).hexdigest()))
        ext_hash = hdig2[:32]
        jarm_hash = f"{cipher_version}{ext_hash}"
        logger.info(f"[USARE] JARM Hash acquired: {jarm_hash}")
        return jarm_hash