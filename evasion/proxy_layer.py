import socket
import logging
from typing import Optional, Tuple
import socks 
logger = logging.getLogger("usare.proxy")
class ProxyManager:
    def __init__(self, proxy_str: str):
        self.proxy_ip, self.proxy_port = self._parse_proxy(proxy_str)
        self._enabled = False
    def _parse_proxy(self, proxy_str: str) -> Tuple[str, int]:
        clean = proxy_str.replace("socks5://", "").replace("socks4://", "").replace("http://", "")
        parts = clean.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid proxy format: {proxy_str}. Expected IP:PORT")
        return parts[0], int(parts[1])
    def enable(self) -> bool:
        try:
            logger.info(f"[USARE] Enabling SOCKS5 routing through {self.proxy_ip}:{self.proxy_port}")
            socks.set_default_proxy(socks.SOCKS5, self.proxy_ip, self.proxy_port)
            socket.socket = socks.socksocket 
            self._enabled = True
            return True
        except Exception as e:
            logger.error(f"[USARE] Failed to enable SOCKS5 proxy: {e}")
            return False
    def disable(self) -> None:
        if self._enabled:
            logger.info("[USARE] Disabling SOCKS5 routing")
            socks.set_default_proxy() 
            self._enabled = False
    def get_proxy_ip(self) -> str:
        return self.proxy_ip