"""
USARE Unified Intelligence Graph

Links all intelligence sources into a directed graph that enables
pivot-chain discovery across related infrastructure.

Graph structure:
  IP ← ASN → Org
  IP ← Cert (SANs) → Domain
  Domain → IP (DNS A/AAAA)
  IP ← WHOIS → Org
  IP ← Shodan → Service
  IP ← Traceroute → Hop → Gateway
  IP ← PDNS → Historical DNS

Enables:
  1. Given IP → find all related IPs via shared certs/ASN/org
  2. Given domain → find all IPs and associated infrastructure
  3. Infrastructure mapping → group IPs by owner/provider
  4. Pivot chain discovery → shortest path between two entities
"""

import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger("usare.intel_graph")


@dataclass
class GraphNode:
    """A node in the intelligence graph."""
    node_id: str          # Unique ID (e.g., "ip:1.2.3.4")
    node_type: str        # "ip", "domain", "asn", "org", "cert", "service", "hop"
    label: str            # Display label
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.node_id,
            "type": self.node_type,
            "label": self.label,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    """A directed edge between two nodes."""
    source_id: str
    target_id: str
    edge_type: str        # "resolves_to", "belongs_to", "has_cert", etc.
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class PivotChain:
    """A chain of related entities discovered through pivoting."""
    path: List[str]          # Node IDs in order
    relationships: List[str]  # Edge types in order
    confidence: float

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "relationships": self.relationships,
            "confidence": round(self.confidence, 3),
        }


class IntelGraph:
    """
    Unified intelligence graph that connects all USARE data sources.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[Tuple[str, str]]] = defaultdict(list)  # node_id → [(target_id, edge_type)]
        self._reverse_adj: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    # ═══════════════════════
    #  Core Graph Operations
    # ═══════════════════════

    def add_node(self, node_id: str, node_type: str, label: str,
                 **properties: Any) -> GraphNode:
        """Add or update a node."""
        if node_id in self._nodes:
            self._nodes[node_id].properties.update(properties)
            return self._nodes[node_id]

        node = GraphNode(node_id=node_id, node_type=node_type,
                         label=label, properties=properties)
        self._nodes[node_id] = node
        return node

    def add_edge(self, source_id: str, target_id: str, edge_type: str,
                 confidence: float = 1.0, **properties: Any) -> GraphEdge:
        """Add a directed edge."""
        edge = GraphEdge(source_id=source_id, target_id=target_id,
                         edge_type=edge_type, confidence=confidence,
                         properties=properties)
        self._edges.append(edge)
        self._adjacency[source_id].append((target_id, edge_type))
        self._reverse_adj[target_id].append((source_id, edge_type))
        return edge

    # ═══════════════════════
    #  Data Ingestion
    # ═══════════════════════

    def ingest_scan_results(self, target: str, scan_data: Dict[str, Any]):
        """Ingest all scan data into the graph."""
        # Core target node
        target_ip = target
        self.add_node(f"ip:{target_ip}", "ip", target_ip)

        self._ingest_ports(target_ip, scan_data)
        self._ingest_whois(target_ip, scan_data)
        self._ingest_dns(target_ip, scan_data)
        self._ingest_certs(target_ip, scan_data)
        self._ingest_traceroute(target_ip, scan_data)
        self._ingest_correlation(target_ip, scan_data)
        self._ingest_shodan(target_ip, scan_data)
        self._ingest_bgp(target_ip, scan_data)

    def _ingest_ports(self, target_ip: str, data: Dict):
        """Add service nodes from scan results."""
        results = data.get("scan_results", data.get("results", []))
        if isinstance(results, list):
            for r in results:
                port = r.get("port", 0) if isinstance(r, dict) else getattr(r, "port", 0)
                state = r.get("state", "") if isinstance(r, dict) else str(getattr(r, "state", ""))
                svc = r.get("service_guess", "") if isinstance(r, dict) else getattr(r, "service_guess", "")

                if "open" in str(state).lower():
                    svc_id = f"service:{target_ip}:{port}"
                    self.add_node(svc_id, "service", f"{svc or 'unknown'}:{port}",
                                  port=port, service=svc)
                    self.add_edge(f"ip:{target_ip}", svc_id, "has_service")

    def _ingest_whois(self, target_ip: str, data: Dict):
        """Add WHOIS-derived nodes."""
        whois = data.get("whois_info", {})
        if not whois:
            return

        org = whois.get("organization", whois.get("org", ""))
        if org:
            org_id = f"org:{org.lower().replace(' ', '_')}"
            self.add_node(org_id, "org", org)
            self.add_edge(f"ip:{target_ip}", org_id, "owned_by")

        asn = whois.get("asn", "")
        if asn:
            asn_id = f"asn:{asn}"
            self.add_node(asn_id, "asn", f"AS{asn}")
            self.add_edge(f"ip:{target_ip}", asn_id, "belongs_to_asn")
            if org:
                self.add_edge(asn_id, org_id, "operated_by")

        country = whois.get("country", "")
        if country:
            self._nodes.get(f"ip:{target_ip}", GraphNode(
                f"ip:{target_ip}", "ip", target_ip
            )).properties["country"] = country

    def _ingest_dns(self, target_ip: str, data: Dict):
        """Add DNS-derived nodes."""
        dns_info = data.get("dns_info", {})
        if not dns_info:
            return

        # PTR record
        ptr = dns_info.get("ptr", "")
        if ptr:
            domain_id = f"domain:{ptr}"
            self.add_node(domain_id, "domain", ptr)
            self.add_edge(f"ip:{target_ip}", domain_id, "reverse_dns")
            self.add_edge(domain_id, f"ip:{target_ip}", "resolves_to")

    def _ingest_certs(self, target_ip: str, data: Dict):
        """Add certificate-derived nodes and pivot links."""
        crypto = data.get("crypto_fingerprint", {})
        tls_data = crypto.get("tls", {})

        for port_str, cert_info in tls_data.items():
            if not isinstance(cert_info, dict):
                continue

            subject = cert_info.get("cert_subject", "")
            issuer = cert_info.get("cert_issuer", "")
            sans = cert_info.get("cert_sans", [])

            if subject:
                cert_id = f"cert:{subject.lower()}"
                self.add_node(cert_id, "cert", subject,
                              issuer=issuer, port=int(port_str) if str(port_str).isdigit() else 0)
                self.add_edge(f"ip:{target_ip}", cert_id, "has_cert")

                # SANs create domain links
                for san in sans:
                    san_clean = san.lstrip("*.")
                    domain_id = f"domain:{san_clean}"
                    self.add_node(domain_id, "domain", san_clean)
                    self.add_edge(cert_id, domain_id, "covers_domain")
                    self.add_edge(domain_id, f"ip:{target_ip}", "resolves_to",
                                  confidence=0.8)

    def _ingest_traceroute(self, target_ip: str, data: Dict):
        """Add traceroute-derived nodes."""
        traceroute = data.get("traceroute", data.get("Traceroute", {}))
        hops = traceroute.get("hops", [])

        prev_id = f"ip:{target_ip}"
        for hop in hops:
            if isinstance(hop, dict):
                hop_ip = hop.get("ip", "")
                hop_num = hop.get("hop", 0)
                if hop_ip and hop_ip != "*":
                    hop_id = f"hop:{hop_ip}"
                    self.add_node(hop_id, "hop", f"Hop {hop_num}: {hop_ip}",
                                  hop_number=hop_num,
                                  rtt=hop.get("rtt", 0))
                    self.add_edge(prev_id, hop_id, "routes_through")
                    prev_id = hop_id

    def _ingest_correlation(self, target_ip: str, data: Dict):
        """Add correlation-derived data."""
        corr = data.get("correlation", {})
        if not corr:
            return

        os_guess = corr.get("best_os", "")
        if os_guess:
            node = self._nodes.get(f"ip:{target_ip}")
            if node:
                node.properties["os"] = os_guess
                node.properties["os_confidence"] = corr.get("best_os_confidence", 0)

        # Infrastructure nodes
        for infra in corr.get("infrastructure", []):
            if isinstance(infra, dict):
                role = infra.get("role", "")
                if role:
                    infra_id = f"infra:{role.lower().replace(' ', '_')}"
                    self.add_node(infra_id, "infrastructure", role)
                    self.add_edge(f"ip:{target_ip}", infra_id, "behind")

    def _ingest_shodan(self, target_ip: str, data: Dict):
        """Add Shodan-derived data."""
        shodan = data.get("shodan_info", {})
        if not shodan:
            return

        ports = shodan.get("ports", [])
        for port in ports:
            svc_id = f"service:{target_ip}:{port}"
            if svc_id not in self._nodes:
                self.add_node(svc_id, "service", f"shodan:{port}", port=port)
                self.add_edge(f"ip:{target_ip}", svc_id, "has_service",
                              confidence=0.9)

    def _ingest_bgp(self, target_ip: str, data: Dict):
        """Add BGP-derived data."""
        bgp = data.get("bgp_info", {})
        if not bgp:
            return

        prefix = bgp.get("prefix", "")
        if prefix:
            prefix_id = f"prefix:{prefix}"
            self.add_node(prefix_id, "prefix", prefix)
            self.add_edge(f"ip:{target_ip}", prefix_id, "in_prefix")

        peers = bgp.get("peers", [])
        for peer_asn in peers[:10]:
            peer_id = f"asn:{peer_asn}"
            self.add_node(peer_id, "asn", f"AS{peer_asn}")
            main_asn_id = f"asn:{bgp.get('asn', '')}"
            if main_asn_id in self._nodes:
                self.add_edge(main_asn_id, peer_id, "peers_with",
                              confidence=0.7)

    # ═══════════════════════
    #  Query Operations
    # ═══════════════════════

    def find_related_ips(self, seed_ip: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """Find all IPs related to seed_ip through shared certs/ASN/org."""
        seed_id = f"ip:{seed_ip}"
        related = []
        visited: Set[str] = set()

        queue: deque = deque([(seed_id, 0, [])])
        visited.add(seed_id)

        while queue:
            current_id, depth, path = queue.popleft()

            if depth > max_depth:
                continue

            # Check all neighbors (both directions)
            neighbors = (
                self._adjacency.get(current_id, []) +
                self._reverse_adj.get(current_id, [])
            )

            for neighbor_id, edge_type in neighbors:
                if neighbor_id in visited:
                    continue
                visited.add(neighbor_id)

                new_path = path + [edge_type]

                # If this is an IP node, record it
                node = self._nodes.get(neighbor_id)
                if node and node.node_type == "ip" and neighbor_id != seed_id:
                    related.append({
                        "ip": node.label,
                        "distance": depth + 1,
                        "path": new_path,
                    })

                queue.append((neighbor_id, depth + 1, new_path))

        return related

    def find_pivot_chains(self, source_id: str, target_id: str,
                          max_depth: int = 5) -> List[PivotChain]:
        """Find all paths between two entities."""
        chains = []
        queue: deque = deque([(source_id, [source_id], [], 1.0)])
        visited: Set[str] = set()

        while queue:
            current, path, rels, conf = queue.popleft()

            if current == target_id:
                chains.append(PivotChain(
                    path=path, relationships=rels, confidence=conf
                ))
                continue

            if len(path) > max_depth:
                continue

            visited.add(current)

            for neighbor_id, edge_type in self._adjacency.get(current, []):
                if neighbor_id not in visited:
                    edge_conf = 1.0
                    for e in self._edges:
                        if e.source_id == current and e.target_id == neighbor_id:
                            edge_conf = e.confidence
                            break
                    queue.append((
                        neighbor_id,
                        path + [neighbor_id],
                        rels + [edge_type],
                        conf * edge_conf,
                    ))

        chains.sort(key=lambda c: (-c.confidence, len(c.path)))
        return chains[:10]

    def get_infrastructure_summary(self) -> Dict[str, Any]:
        """Get a summary of the entire intelligence graph."""
        type_counts: Dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type] += 1

        edge_type_counts: Dict[str, int] = defaultdict(int)
        for edge in self._edges:
            edge_type_counts[edge.edge_type] += 1

        # Find all unique IPs
        ips = [n for n in self._nodes.values() if n.node_type == "ip"]
        domains = [n for n in self._nodes.values() if n.node_type == "domain"]
        orgs = [n for n in self._nodes.values() if n.node_type == "org"]
        certs = [n for n in self._nodes.values() if n.node_type == "cert"]

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_types": dict(type_counts),
            "edge_types": dict(edge_type_counts),
            "ips": [n.label for n in ips],
            "domains": [n.label for n in domains],
            "organizations": [n.label for n in orgs],
            "certificates": len(certs),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export the full graph as a dictionary."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "summary": self.get_infrastructure_summary(),
        }
