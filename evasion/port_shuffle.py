import secrets
import random
from typing import List, Optional, Set
PRIORITY_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    5985, 5986, 6379, 8080, 8443, 8888, 9090, 27017,
}
def shuffle_ports(
    port_list: List[int],
    seed: Optional[int] = None,
) -> List[int]:
    ports = list(port_list)  
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = secrets.SystemRandom()
    rng.shuffle(ports)
    return ports
def shuffle_ports_prioritized(
    port_list: List[int],
    priority_ports: Optional[Set[int]] = None,
    priority_ratio: float = 0.3,
    seed: Optional[int] = None,
) -> List[int]:
    if priority_ports is None:
        priority_ports = PRIORITY_PORTS
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = secrets.SystemRandom()
    priority = [p for p in port_list if p in priority_ports]
    regular = [p for p in port_list if p not in priority_ports]
    rng.shuffle(priority)
    rng.shuffle(regular)
    result = priority + regular
    return result
def generate_port_ranges(
    start: int = 1,
    end: int = 65535,
    common_only: bool = False,
) -> List[int]:
    if common_only:
        return sorted([p for p in PRIORITY_PORTS if start <= p <= end])
    return list(range(start, end + 1))
def chunk_ports(
    ports: List[int],
    chunk_size: int = 50,
) -> List[List[int]]:
    return [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]  # type: ignore[index]
def anti_sequential_verify(ports: List[int], max_run: int = 3) -> bool:
    if len(ports) < 2:
        return True
    current_run = 1
    for i in range(1, len(ports)):
        if ports[i] == ports[i - 1] + 1:
            current_run += 1
            if current_run > max_run:
                return False
        else:
            current_run = 1
    return True