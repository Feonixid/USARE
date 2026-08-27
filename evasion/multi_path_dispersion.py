"""Multi-Path Source Dispersion for Heat Distribution.

Distributes scanning across multiple source IPs and exit nodes to prevent
any single IP from hitting detection thresholds. Supports VPNs, proxies,
and TOR exit nodes with intelligent load balancing.

Features:
- VPN/Proxy rotation with health checking
- Heat-based load balancing
- Automatic failover
- Geographic distribution
- Rate limiting per source
"""

import logging
import time
import random
import json
import socket
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

logger = logging.getLogger("usare.multi_path")

class SourceType(Enum):
    DIRECT = "direct"
    VPN = "vpn"
    PROXY = "proxy"
    TOR = "tor"
    RESIDENTIAL = "residential"
    CLOUD = "cloud"

@dataclass
class SourceNode:
    """Represents a source node for packet sending."""
    id: str
    source_type: SourceType
    ip_address: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    provider: Optional[str] = None
    active: bool = True
    health_score: float = 1.0  # 0-1, higher = better
    current_heat: float = 0.0  # 0-1, higher = more suspicious
    max_heat_threshold: float = 0.8
    packets_sent: int = 0
    last_used: float = field(default_factory=time.time)
    response_time_ms: float = 0.0
    error_count: int = 0
    consecutive_failures: int = 0

@dataclass
class DispersionConfig:
    """Configuration for multi-path dispersion."""
    max_concurrent_sources: int = 5
    heat_decay_rate: float = 0.1  # Heat decay per minute
    health_check_interval: float = 300.0  # 5 minutes
    max_failures_before_disable: int = 3
    geographic_diversity: bool = True
    provider_diversity: bool = True
    rate_limit_per_source: int = 100  # Packets per minute
    load_balance_strategy: str = "heat_aware"  # heat_aware, round_robin, random

class ProxyChainManager:
    """Manages proxy/VPN connections for packet routing."""
    
    def __init__(self, config: DispersionConfig):
        self.config = config
        self.source_nodes: List[SourceNode] = []
        self.current_node_index = 0
        self.health_check_thread = None
        self.heat_decay_thread = None
        self.lock = threading.Lock()
        self.running = False
        
    def add_source_node(self, node: SourceNode):
        """Add a source node to the pool."""
        with self.lock:
            self.source_nodes.append(node)
            logger.info(f"[MultiPath] Added source node: {node.id} ({node.source_type.value})")
    
    def load_source_nodes_from_file(self, filename: str):
        """Load source nodes from configuration file."""
        try:
            with open(filename, 'r') as f:
                config_data = json.load(f)
            
            for node_data in config_data.get('source_nodes', []):
                node = SourceNode(
                    id=node_data['id'],
                    source_type=SourceType(node_data['type']),
                    ip_address=node_data['ip'],
                    port=node_data['port'],
                    username=node_data.get('username'),
                    password=node_data.get('password'),
                    country=node_data.get('country'),
                    city=node_data.get('city'),
                    provider=node_data.get('provider')
                )
                self.add_source_node(node)
                
        except Exception as e:
            logger.error(f"[MultiPath] Failed to load source nodes: {e}")
    
    def start_health_monitoring(self):
        """Start health monitoring and heat decay threads."""
        if self.running:
            return
        
        self.running = True
        
        # Health check thread
        self.health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True
        )
        self.health_check_thread.start()
        
        # Heat decay thread
        self.heat_decay_thread = threading.Thread(
            target=self._heat_decay_loop,
            daemon=True
        )
        self.heat_decay_thread.start()
        
        logger.info("[MultiPath] Started health monitoring")
    
    def stop_health_monitoring(self):
        """Stop health monitoring threads."""
        self.running = False
        logger.info("[MultiPath] Stopped health monitoring")
    
    def select_source_node(self, target_ip: str, target_port: int) -> Optional[SourceNode]:
        """Select optimal source node for probe."""
        with self.lock:
            active_nodes = [n for n in self.source_nodes if n.active and n.health_score > 0.3]
            
            if not active_nodes:
                logger.warning("[MultiPath] No active source nodes available")
                return None
            
            if self.config.load_balance_strategy == "heat_aware":
                return self._select_heat_aware_node(active_nodes, target_ip)
            elif self.config.load_balance_strategy == "round_robin":
                return self._select_round_robin_node(active_nodes)
            elif self.config.load_balance_strategy == "random":
                return self._select_random_node(active_nodes)
            else:
                return self._select_heat_aware_node(active_nodes, target_ip)
    
    def _select_heat_aware_node(self, nodes: List[SourceNode], target_ip: str) -> SourceNode:
        """Select node based on heat awareness and geographic diversity."""
        # Filter nodes with acceptable heat
        cool_nodes = [n for n in nodes if n.current_heat < n.max_heat_threshold]
        
        if not cool_nodes:
            # All nodes are hot, select the coolest
            cool_nodes = sorted(nodes, key=lambda n: n.current_heat)[:3]
        
        # Apply geographic diversity if enabled
        if self.config.geographic_diversity and len(cool_nodes) > 1:
            # Prefer nodes from different countries/regions
            countries = {}
            for node in cool_nodes:
                country = node.country or "Unknown"
                if country not in countries:
                    countries[country] = []
                countries[country].append(node)
            
            # Select from most diverse countries
            if len(countries) > 1:
                cool_nodes = random.choice(list(countries.values()))
        
        # Apply provider diversity if enabled
        if self.config.provider_diversity and len(cool_nodes) > 1:
            providers = {}
            for node in cool_nodes:
                provider = node.provider or "Unknown"
                if provider not in providers:
                    providers[provider] = []
                providers[provider].append(node)
            
            if len(providers) > 1:
                cool_nodes = random.choice(list(providers.values()))
        
        # Select based on combined score (health - heat + response time)
        def node_score(node):
            return (node.health_score * 0.4 - 
                   node.current_heat * 0.4 - 
                   node.response_time_ms / 1000 * 0.2)
        
        selected_node = max(cool_nodes, key=node_score)
        
        # Update node heat
        selected_node.current_heat = min(1.0, selected_node.current_heat + 0.1)
        selected_node.last_used = time.time()
        
        return selected_node
    
    def _select_round_robin_node(self, nodes: List[SourceNode]) -> SourceNode:
        """Select node using round-robin strategy."""
        node = nodes[self.current_node_index % len(nodes)]
        self.current_node_index += 1
        
        node.current_heat = min(1.0, node.current_heat + 0.05)
        node.last_used = time.time()
        
        return node
    
    def _select_random_node(self, nodes: List[SourceNode]) -> SourceNode:
        """Select node randomly."""
        node = random.choice(nodes)
        
        node.current_heat = min(1.0, node.current_heat + 0.05)
        node.last_used = time.time()
        
        return node
    
    def send_packet_through_node(self, node: SourceNode, packet_data: bytes,
                               target_ip: str, target_port: int) -> bool:
        """Send packet through specific source node."""
        try:
            if node.source_type == SourceType.DIRECT:
                return self._send_direct(packet_data, target_ip, target_port)
            elif node.source_type == SourceType.PROXY:
                return self._send_through_proxy(node, packet_data, target_ip, target_port)
            elif node.source_type == SourceType.VPN:
                return self._send_through_vpn(node, packet_data, target_ip, target_port)
            elif node.source_type == SourceType.TOR:
                return self._send_through_tor(node, packet_data, target_ip, target_port)
            else:
                logger.warning(f"[MultiPath] Unsupported source type: {node.source_type}")
                return False
                
        except Exception as e:
            logger.error(f"[MultiPath] Failed to send through node {node.id}: {e}")
            self._handle_node_failure(node)
            return False
    
    def _send_direct(self, packet_data: bytes, target_ip: str, target_port: int) -> bool:
        """Send packet directly (no proxy)."""
        try:
            # This would integrate with packet_engine.py
            # For now, simulate sending
            time.sleep(0.01)  # Simulate network delay
            return True
        except Exception:
            return False
    
    def _send_through_proxy(self, node: SourceNode, packet_data: bytes,
                           target_ip: str, target_port: int) -> bool:
        """Send packet through HTTP/SOCKS proxy."""
        try:
            # Implement proxy connection logic
            # This is a simplified version
            proxies = {
                'http': f"http://{node.ip_address}:{node.port}",
                'https': f"http://{node.ip_address}:{node.port}"
            }
            
            if node.username and node.password:
                proxies['http'] = f"http://{node.username}:{node.password}@{node.ip_address}:{node.port}"
                proxies['https'] = f"http://{node.username}:{node.password}@{node.ip_address}:{node.port}"
            
            # Test connectivity
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
            
            if response.status_code == 200:
                node.response_time_ms = response.elapsed.total_seconds() * 1000
                node.packets_sent += 1
                return True
            else:
                return False
                
        except Exception as e:
            logger.debug(f"[MultiPath] Proxy {node.id} failed: {e}")
            return False
    
    def _send_through_vpn(self, node: SourceNode, packet_data: bytes,
                         target_ip: str, target_port: int) -> bool:
        """Send packet through VPN tunnel."""
        # VPN integration would require system-level configuration
        # For now, simulate VPN behavior
        time.sleep(random.uniform(0.02, 0.05))  # Simulate VPN overhead
        node.packets_sent += 1
        return True
    
    def _send_through_tor(self, node: SourceNode, packet_data: bytes,
                         target_ip: str, target_port: int) -> bool:
        """Send packet through TOR exit node."""
        try:
            # TOR typically uses SOCKS5 on port 9050
            import socks
            
            # Set up SOCKS proxy
            socks.set_default_proxy(socks.SOCKS5, node.ip_address, node.port)
            socket.socket = socks.socksocket
            
            # Test connectivity
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(5)
            
            start_time = time.time()
            result = test_sock.connect_ex((target_ip, target_port))
            response_time = (time.time() - start_time) * 1000
            
            test_sock.close()
            
            if result == 0:
                node.response_time_ms = response_time
                node.packets_sent += 1
                return True
            else:
                return False
                
        except Exception as e:
            logger.debug(f"[MultiPath] TOR node {node.id} failed: {e}")
            return False
    
    def _handle_node_failure(self, node: SourceNode):
        """Handle node failure and update health."""
        node.error_count += 1
        node.consecutive_failures += 1
        node.health_score = max(0.0, node.health_score - 0.2)
        
        # Disable node if too many failures
        if node.consecutive_failures >= self.config.max_failures_before_disable:
            node.active = False
            logger.warning(f"[MultiPath] Disabled node {node.id} due to failures")
    
    def _health_check_loop(self):
        """Periodic health check of all nodes."""
        while self.running:
            try:
                with self.lock:
                    for node in self.source_nodes:
                        if not node.active:
                            continue
                        
                        # Perform health check
                        start_time = time.time()
                        is_healthy = self._check_node_health(node)
                        response_time = (time.time() - start_time) * 1000
                        
                        if is_healthy:
                            node.health_score = min(1.0, node.health_score + 0.1)
                            node.consecutive_failures = 0
                            node.response_time_ms = response_time
                        else:
                            self._handle_node_failure(node)
                
                time.sleep(self.config.health_check_interval)
                
            except Exception as e:
                logger.error(f"[MultiPath] Health check error: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _check_node_health(self, node: SourceNode) -> bool:
        """Check health of individual node."""
        try:
            if node.source_type == SourceType.PROXY:
                return self._check_proxy_health(node)
            elif node.source_type == SourceType.TOR:
                return self._check_tor_health(node)
            else:
                # For other types, assume healthy if recently used
                return (time.time() - node.last_used) < 300  # 5 minutes
                
        except Exception:
            return False
    
    def _check_proxy_health(self, node: SourceNode) -> bool:
        """Check proxy node health."""
        try:
            proxies = {
                'http': f"http://{node.ip_address}:{node.port}",
                'https': f"http://{node.ip_address}:{node.port}"
            }
            
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
            return response.status_code == 200
            
        except Exception:
            return False
    
    def _check_tor_health(self, node: SourceNode) -> bool:
        """Check TOR node health."""
        try:
            # Check if TOR SOCKS port is responsive
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((node.ip_address, node.port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def _heat_decay_loop(self):
        """Periodic heat decay for all nodes."""
        while self.running:
            try:
                with self.lock:
                    for node in self.source_nodes:
                        # Decay heat based on time since last use
                        time_since_use = time.time() - node.last_used
                        decay_amount = (time_since_use / 60.0) * self.config.heat_decay_rate
                        
                        node.current_heat = max(0.0, node.current_heat - decay_amount)
                
                time.sleep(60)  # Decay every minute
                
            except Exception as e:
                logger.error(f"[MultiPath] Heat decay error: {e}")
                time.sleep(60)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dispersion statistics."""
        with self.lock:
            active_nodes = [n for n in self.source_nodes if n.active]
            
            return {
                "total_nodes": len(self.source_nodes),
                "active_nodes": len(active_nodes),
                "nodes_by_type": {
                    source_type.value: len([n for n in active_nodes if n.source_type == source_type])
                    for source_type in SourceType
                },
                "average_health": sum(n.health_score for n in active_nodes) / len(active_nodes) if active_nodes else 0,
                "average_heat": sum(n.current_heat for n in active_nodes) / len(active_nodes) if active_nodes else 0,
                "total_packets_sent": sum(n.packets_sent for n in self.source_nodes),
                "geographic_diversity": len(set(n.country for n in active_nodes if n.country)),
                "provider_diversity": len(set(n.provider for n in active_nodes if n.provider))
            }

# Global instance
_proxy_manager = None

def get_proxy_manager(config: Optional[DispersionConfig] = None) -> ProxyChainManager:
    """Get global proxy chain manager."""
    global _proxy_manager
    if _proxy_manager is None:
        _proxy_manager = ProxyChainManager(config or DispersionConfig())
        _proxy_manager.start_health_monitoring()
    return _proxy_manager

def send_with_dispersion(packet_data: bytes, target_ip: str, target_port: int,
                         preferred_type: Optional[str] = None) -> bool:
    """Send packet with multi-path dispersion."""
    manager = get_proxy_manager()
    
    node = manager.select_source_node(target_ip, target_port)
    if not node:
        return False
    
    return manager.send_packet_through_node(node, packet_data, target_ip, target_port)

def get_dispersion_stats() -> Dict[str, Any]:
    """Get current dispersion statistics."""
    manager = get_proxy_manager()
    return manager.get_statistics()

def load_proxy_config(filename: str):
    """Load proxy configuration from file."""
    manager = get_proxy_manager()
    manager.load_source_nodes_from_file(filename)
