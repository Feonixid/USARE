import random
from typing import Optional, List
from enum import Enum

class MasqueradeStrategy(Enum):
    DNS = "dns"
    HTTPS = "https"
    NTP = "ntp"
    HTTP = "http"
    RANDOM_HIGH = "random_high"

MASQ_PORTS = {
    MasqueradeStrategy.DNS: [53],
    MasqueradeStrategy.HTTPS: [443, 8443],
    MasqueradeStrategy.NTP: [123],
    MasqueradeStrategy.HTTP: [80, 8080],
    MasqueradeStrategy.RANDOM_HIGH: list(range(49152, 49200)),
}

FIREWALL_BYPASS_PORTS = [53, 80, 123, 443, 8080, 8443]

class SourcePortMasquerader:
    def __init__(self, strategy: MasqueradeStrategy = MasqueradeStrategy.DNS):
        self.strategy = strategy
        self._rng = random.SystemRandom()
        self._used_ports: set = set()

    def get_source_port(self, target_port: Optional[int] = None) -> int:
        if target_port and target_port in (443, 8443):
            return self._pick_from(MasqueradeStrategy.HTTPS)
        if target_port and target_port in (80, 8080):
            return self._pick_from(MasqueradeStrategy.HTTP)
        return self._pick_from(self.strategy)

    def get_bypass_port(self) -> int:
        return self._rng.choice(FIREWALL_BYPASS_PORTS)

    def get_rotating_port(self) -> int:
        candidates = FIREWALL_BYPASS_PORTS + list(range(49152, 49200))
        port = self._rng.choice(candidates)
        while port in self._used_ports and len(self._used_ports) < len(candidates):
            port = self._rng.choice(candidates)
        self._used_ports.add(port)
        return port

    def _pick_from(self, strategy: MasqueradeStrategy) -> int:
        pool = MASQ_PORTS.get(strategy, MASQ_PORTS[MasqueradeStrategy.DNS])
        return self._rng.choice(pool)

    def reset(self):
        self._used_ports.clear()
