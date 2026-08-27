import socket
import ssl
import os
import base64
import time
import struct
import logging

logger = logging.getLogger("usare.wss_tunnel")

class WebSocketTunnel:
    """
    L7 Persistent Evasion Tunnel. Upgrades a generic HTTPS session to a WebSocket,
    submerging reconnaissance payloads inside binary/text frames.
    """
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _generate_ws_key(self) -> str:
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    def construct_frame(self, data: bytes, is_text: bool = True) -> bytes:
        opcode = 0x1 if is_text else 0x2
        b1 = 0x80 | opcode
        length = len(data)
        
        if length <= 125:
            b2 = 0x80 | length
            header = struct.pack('!BB', b1, b2)
        elif length <= 65535:
            b2 = 0x80 | 126
            header = struct.pack('!BBH', b1, b2, length)
        else:
            b2 = 0x80 | 127
            header = struct.pack('!BBQ', b1, b2, length)
            
        mask = os.urandom(4)
        masked_data = bytearray(data)
        for i in range(len(data)):
            masked_data[i] ^= mask[i % 4]
            
        return header + mask + masked_data

    def connect_and_smuggle(self, target_ip: str, port: int, payload: bytes) -> dict:
        results = {"success": False, "ws_upgraded": False, "data_delivered": False, "latency_ms": 0.0, "response": b""}
        start = time.time()
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if port in (443, 8443):
                conn = ctx.wrap_socket(sock, server_hostname=target_ip)
            else:
                conn = sock
                
            conn.connect((target_ip, port))
            
            ws_key = self._generate_ws_key()
            upgrade_req = (
                f"GET /ws HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n"
            ).encode()
            
            conn.sendall(upgrade_req)
            resp = conn.recv(4096)
            
            if b"101 Switching Protocols" in resp or b"Upgrade: websocket" in resp:
                results["ws_upgraded"] = True
                
            frame = self.construct_frame(payload, is_text=True)
            conn.sendall(frame)
            results["data_delivered"] = True
            
            try:
                msg = conn.recv(4096)
                results["response"] = msg
                results["success"] = True
            except socket.timeout:
                pass
                
            conn.close()
            
        except Exception as e:
            results["response"] = str(e).encode()
            
        results["latency_ms"] = (time.time() - start) * 1000
        return results
