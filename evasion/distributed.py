"""
Gap 3 — Distributed Source Architecture

Multi-node scanning across different ASNs. Each node is a separate
genuine IP, making correlation-based detection nearly impossible.
Supports SSH and REST API dispatch modes.
"""

import json
import time
import hashlib
import threading
import subprocess
import logging
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

logger = logging.getLogger("usare.distributed")


class DispatchMode(Enum):
    SSH = "ssh"
    REST = "rest"


@dataclass
class ScanNode:
    """Remote scanning node with connectivity details."""
    host: str
    port: int = 22
    ssh_key: Optional[str] = None
    username: str = "root"
    asn: Optional[str] = None
    provider: Optional[str] = None
    label: Optional[str] = None
    status: str = "idle"
    dispatch_mode: str = "ssh"
    rest_port: int = 8443
    rest_token: Optional[str] = None
    latency_ms: Optional[float] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class DistributedJob:
    """A scanning job assigned to a specific node."""
    node: ScanNode
    target: str
    ports: List[int]
    flags: str = ""
    status: str = "pending"
    results: Optional[Dict] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error: Optional[str] = None

    @property
    def elapsed(self) -> float:
        if self.start_time is not None and self.end_time is not None:
            return self.end_time - self.start_time
        return 0.0


class DistributedCoordinator:
    """Coordinates scanning across multiple nodes."""

    def __init__(self, nodes_file: Optional[str] = None, encryption_password: Optional[str] = None):
        self.nodes: List[ScanNode] = []
        self.jobs: List[DistributedJob] = []
        self._lock = threading.Lock()
        self._encryption_password = encryption_password
        if nodes_file:
            self.load_nodes(nodes_file)

    def load_nodes(self, filepath: str):
        """Load node configuration from JSON file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            for entry in data.get("nodes", []):
                node = ScanNode(
                    host=entry["host"],
                    port=entry.get("port", 22),
                    ssh_key=entry.get("ssh_key"),
                    username=entry.get("username", "root"),
                    asn=entry.get("asn"),
                    provider=entry.get("provider"),
                    label=entry.get("label"),
                    dispatch_mode=entry.get("dispatch_mode", "ssh"),
                    rest_port=entry.get("rest_port", 8443),
                    rest_token=entry.get("rest_token"),
                )
                self.nodes.append(node)
            logger.info(f"Loaded {len(self.nodes)} nodes from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load nodes from {filepath}: {e}")

    def health_check(self, timeout: float = 5.0) -> Dict[str, Any]:
        """Check connectivity and latency to all nodes."""
        results = {}
        threads = []

        def _check_node(node: ScanNode):
            start = time.time()
            try:
                if node.dispatch_mode == "rest":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((node.host, node.rest_port))
                    sock.close()
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((node.host, node.port))
                    sock.close()

                latency = (time.time() - start) * 1000
                node.latency_ms = latency
                node.status = "ready"
                results[node.host] = {
                    "status": "ready", "latency_ms": round(latency, 1),
                    "asn": node.asn, "provider": node.provider,
                }
            except Exception as e:
                node.status = "unreachable"
                results[node.host] = {
                    "status": "unreachable", "error": str(e),
                }

        for node in self.nodes:
            t = threading.Thread(target=_check_node, args=(node,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=timeout + 2)

        return results

    def partition_ports(self, ports: List[int]) -> Dict[int, List[int]]:
        """Distribute ports across nodes using round-robin."""
        available = [i for i, n in enumerate(self.nodes) if n.status != "unreachable"]
        if not available:
            return {0: ports}

        partitions: Dict[int, List[int]] = {i: [] for i in available}
        for idx, port in enumerate(ports):
            node_idx = available[idx % len(available)]
            partitions[node_idx].append(port)
        return partitions

    def dispatch_all(self, target: str, ports: List[int], flags: str = "") -> List[DistributedJob]:
        """Dispatch scanning jobs to all nodes in parallel."""
        partitions = self.partition_ports(ports)
        threads = []

        for node_idx, port_subset in partitions.items():
            if node_idx >= len(self.nodes) or not port_subset:
                continue

            node = self.nodes[node_idx]
            job = DistributedJob(
                node=node,
                target=target,
                ports=port_subset,
                flags=flags,
            )
            with self._lock:
                self.jobs.append(job)

            if node.dispatch_mode == "rest":
                t = threading.Thread(target=self._execute_job_rest, args=(job,), daemon=True)
            else:
                t = threading.Thread(target=self._execute_job_ssh, args=(job,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=600)

        return self.jobs

    def _execute_job_ssh(self, job: DistributedJob):
        """Execute a scan job via SSH."""
        job.status = "running"
        job.start_time = time.time()
        job.node.status = "scanning"

        port_spec = ",".join(str(p) for p in job.ports)
        cmd = (
            f"ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 "
            f"-o BatchMode=yes "
        )
        if job.node.ssh_key:
            cmd += f"-i {job.node.ssh_key} "
        cmd += (
            f"{job.node.username}@{job.node.host} -p {job.node.port} "
            f"'cd /opt/usare && python3 usare.py -t {job.target} "
            f"-p {port_spec} {job.flags} --json --quiet -o /tmp/usare_result.json "
            f"&& cat /tmp/usare_result.json'"
        )

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=600
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    job.results = json.loads(result.stdout.strip())
                except json.JSONDecodeError:
                    job.results = {"raw_output": result.stdout[:2000]}
            else:
                job.results = {"error": result.stderr[:500]}
                job.error = result.stderr[:200]
            job.status = "done"
        except subprocess.TimeoutExpired:
            job.status = "timeout"
            job.error = "SSH execution timed out"
            job.results = {"error": "SSH execution timed out"}
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.results = {"error": str(e)}
        finally:
            job.end_time = time.time()
            job.node.status = "idle"

    def _execute_job_rest(self, job: DistributedJob):
        """Execute a scan job via REST API (HTTPS POST)."""
        job.status = "running"
        job.start_time = time.time()
        job.node.status = "scanning"

        try:
            import urllib.request
            import ssl

            payload = json.dumps({
                "target": job.target,
                "ports": job.ports,
                "flags": job.flags,
            }).encode()

            url = f"https://{job.node.host}:{job.node.rest_port}/api/scan"
            req = urllib.request.Request(
                url,
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {job.node.rest_token or ''}",
                    "User-Agent": "USARE-Coordinator/2.0",
                },
            )

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=600, context=ctx) as resp:
                response_data = resp.read().decode()
                try:
                    job.results = json.loads(response_data)
                except json.JSONDecodeError:
                    job.results = {"raw_output": response_data[:2000]}

            job.status = "done"
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.results = {"error": str(e)}
        finally:
            job.end_time = time.time()
            job.node.status = "idle"

    def merge_results(self) -> Dict[str, Any]:
        """Merge results from all completed jobs."""
        merged: Dict[str, Any] = {
            "nodes_used": len([n for n in self.nodes if n.status != "unreachable"]),
            "total_jobs": len(self.jobs),
            "completed": sum(1 for j in self.jobs if j.status == "done"),
            "failed": sum(1 for j in self.jobs if j.status in ("failed", "timeout")),
            "total_elapsed": sum(j.elapsed for j in self.jobs),
            "ports": {},
            "node_details": [],
        }

        for job in self.jobs:
            if job.results and "ports" in job.results:
                merged["ports"].update(job.results["ports"])

            # Also merge scan_results arrays if present
            if job.results and "scan_results" in job.results:
                merged.setdefault("scan_results", []).extend(
                    job.results["scan_results"]
                )

            merged["node_details"].append({
                "node": job.node.host,
                "asn": job.node.asn,
                "provider": job.node.provider,
                "status": job.status,
                "ports_assigned": len(job.ports),
                "elapsed": round(job.elapsed, 2),
                "error": job.error,
                "dispatch_mode": job.node.dispatch_mode,
            })

        return merged

    @property
    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "nodes_ready": sum(1 for n in self.nodes if n.status == "ready"),
            "jobs": len(self.jobs),
            "active": sum(1 for j in self.jobs if j.status == "running"),
            "done": sum(1 for j in self.jobs if j.status == "done"),
            "failed": sum(1 for j in self.jobs if j.status in ("failed", "timeout")),
            "asns": list(set(n.asn for n in self.nodes if n.asn)),
        }


class NodeProvisioner:
    """Skeleton for cloud API node provisioning.

    Implementations would call cloud provider APIs to spin up
    ephemeral instances, deploy USARE, run scans, and destroy.

    Supported providers (skeleton):
    - AWS EC2 (boto3)
    - DigitalOcean Droplets
    - Linode Instances
    - Vultr Instances
    """

    def __init__(self, provider: str = "manual", api_key: Optional[str] = None):
        self.provider = provider
        self.api_key = api_key
        self._provisioned_nodes: List[ScanNode] = []

    def provision(self, count: int = 3, regions: Optional[List[str]] = None) -> List[ScanNode]:
        """Provision ephemeral scan nodes.

        This is a skeleton — real implementations would call
        the cloud provider API. For now, logs what would happen.
        """
        if regions is None:
            regions = ["us-east-1", "eu-west-1", "ap-southeast-1"]

        logger.info(
            f"[NodeProvisioner] Would provision {count} nodes via {self.provider} "
            f"in regions: {regions}"
        )

        # Skeleton: real impl would create instances here
        for i in range(count):
            region = regions[i % len(regions)]
            node = ScanNode(
                host=f"pending-{self.provider}-{region}-{i}",
                port=22,
                provider=self.provider,
                label=f"ephemeral-{region}-{i}",
                status="provisioning",
            )
            self._provisioned_nodes.append(node)

        return self._provisioned_nodes

    def destroy_all(self):
        """Destroy all provisioned nodes."""
        logger.info(
            f"[NodeProvisioner] Would destroy {len(self._provisioned_nodes)} "
            f"ephemeral nodes via {self.provider}"
        )
        for node in self._provisioned_nodes:
            node.status = "destroyed"
        self._provisioned_nodes.clear()

    @property
    def stats(self) -> dict:
        return {
            "provider": self.provider,
            "provisioned": len(self._provisioned_nodes),
            "statuses": [n.status for n in self._provisioned_nodes],
        }
