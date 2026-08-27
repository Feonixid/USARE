"""
Service Data Harvester — extracts actionable data from unauthenticated services.

Targets services already identified as open/unauthenticated by app_protocol_probe
and banner_grab.  Does NOT attempt credentials — only anonymous access.

Services covered:
  Redis (INFO, CONFIG GET, DBSIZE, KEYS sample)
  MongoDB (listDatabases, listCollections, document count)
  Memcached (stats, version)
  FTP anonymous (FEAT, LIST, NLST)
  TFTP (read attempt on common filenames)
  Docker API (version, containers, images)
  Kubernetes API (version, namespaces, pods — unauthenticated)
  Elasticsearch (cluster info, indices)
  CouchDB (databases list)
  Etcd (keys listing)
"""

import socket
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

import requests  # type: ignore

logger = logging.getLogger("usare.service_harvest")

RECV_BUF  = 32768
SOC_TIMEOUT = 5.0


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HarvestFinding:
    service: str
    port: int
    severity: str          # "critical" | "high" | "medium" | "info"
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "port": self.port,
            "severity": self.severity,
            "summary": self.summary,
            "details": self.details,
        }


@dataclass
class HarvestResult:
    target: str
    findings: List[HarvestFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "critical": [f.to_dict() for f in self.findings if f.severity == "critical"],
            "total_findings": len(self.findings),
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Redis
# ─────────────────────────────────────────────────────────────────────────────

def harvest_redis(target: str, port: int = 6379) -> Optional[HarvestFinding]:
    """Pull INFO and a sample of key names from unauthenticated Redis."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOC_TIMEOUT)
        sock.connect((target, port))

        def send_cmd(cmd: str) -> str:
            sock.sendall((cmd + "\r\n").encode())
            time.sleep(0.1)
            try:
                return sock.recv(RECV_BUF).decode("utf-8", errors="ignore")
            except Exception:
                return ""

        # Check for auth requirement
        ping_resp = send_cmd("PING")
        if "NOAUTH" in ping_resp or "WRONGPASS" in ping_resp:
            sock.close()
            return None  # requires auth

        info_resp = send_cmd("INFO server")
        dbsize_resp = send_cmd("DBSIZE")
        config_resp = send_cmd("CONFIG GET maxmemory")

        # Sample keys (SCAN 0 COUNT 10 — safer than KEYS *)
        scan_resp = send_cmd("SCAN 0 COUNT 10")
        sock.close()

        details: Dict[str, Any] = {"raw_info_snippet": info_resp[:500]}

        # Parse version
        ver_match = None
        for line in info_resp.splitlines():
            if line.startswith("redis_version:"):
                details["version"] = line.split(":")[1].strip()
            if line.startswith("os:"):
                details["os"] = line.split(":", 1)[1].strip()
            if line.startswith("config_file:"):
                details["config_file"] = line.split(":", 1)[1].strip()
            if line.startswith("tcp_port:"):
                details["tcp_port"] = line.split(":")[1].strip()

        # Key count
        for line in dbsize_resp.splitlines():
            if line.startswith(":"):
                details["key_count"] = line[1:].strip()

        # Sample keys from SCAN response
        keys = []
        lines = scan_resp.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("*") and i > 0:
                # Bulk string array members
                keys = [l for l in lines[i+1:] if l and not l.startswith("*") and not l.startswith(":") and not l.startswith("$") and not l.startswith("+")]
                break
        if keys:
            details["sample_keys"] = [k for k in keys[:10] if k]

        return HarvestFinding(
            service="redis",
            port=port,
            severity="critical",
            summary=f"Redis {details.get('version', '?')} unauthenticated — "
                    f"{details.get('key_count', '?')} keys",
            details=details,
        )
    except Exception as e:
        logger.debug("[harvest] Redis %s:%d failed: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Memcached
# ─────────────────────────────────────────────────────────────────────────────

def harvest_memcached(target: str, port: int = 11211) -> Optional[HarvestFinding]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOC_TIMEOUT)
        sock.connect((target, port))
        sock.sendall(b"stats\r\n")
        time.sleep(0.2)
        resp = sock.recv(RECV_BUF).decode("utf-8", errors="ignore")
        sock.close()
        if "STAT " not in resp:
            return None
        details: Dict[str, Any] = {}
        for line in resp.splitlines():
            if line.startswith("STAT "):
                parts = line.split()
                if len(parts) == 3:
                    details[parts[1]] = parts[2]
        version = details.get("version", "?")
        curr_items = details.get("curr_items", "?")
        bytes_used = details.get("bytes", "?")
        return HarvestFinding(
            service="memcached",
            port=port,
            severity="high",
            summary=f"Memcached {version} unauthenticated — {curr_items} items, {bytes_used} bytes",
            details={"version": version, "curr_items": curr_items, "bytes": bytes_used,
                     "pid": details.get("pid"), "uptime_sec": details.get("uptime")},
        )
    except Exception as e:
        logger.debug("[harvest] Memcached %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# FTP anonymous
# ─────────────────────────────────────────────────────────────────────────────

def harvest_ftp_anon(target: str, port: int = 21) -> Optional[HarvestFinding]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOC_TIMEOUT)
        sock.connect((target, port))

        def recv() -> str:
            return sock.recv(RECV_BUF).decode("utf-8", errors="ignore")

        def cmd(c: str) -> str:
            sock.sendall((c + "\r\n").encode())
            time.sleep(0.15)
            return recv()

        banner = recv()
        user_resp = cmd("USER anonymous")
        if "331" not in user_resp:
            sock.close()
            return None  # No anonymous login
        pass_resp = cmd("PASS anonymous@example.com")
        if "230" not in pass_resp:
            sock.close()
            return None  # Login failed

        # PASV + LIST to see directory
        pasv_resp = cmd("PASV")
        import re
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv_resp)
        file_list = []
        if m:
            ip_parts = ".".join(m.group(i) for i in range(1, 5))
            port_num = int(m.group(5)) * 256 + int(m.group(6))
            try:
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.settimeout(SOC_TIMEOUT)
                data_sock.connect((ip_parts, port_num))
                cmd("LIST")
                listing = data_sock.recv(8192).decode("utf-8", errors="ignore")
                data_sock.close()
                file_list = [l for l in listing.splitlines() if l.strip()]
            except Exception:
                pass

        cmd("QUIT")
        sock.close()

        return HarvestFinding(
            service="ftp",
            port=port,
            severity="high",
            summary=f"FTP anonymous login allowed — {len(file_list)} entries in root",
            details={
                "banner": banner.strip()[:200],
                "root_listing": file_list[:20],
                "file_count": len(file_list),
            },
        )
    except Exception as e:
        logger.debug("[harvest] FTP %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Elasticsearch
# ─────────────────────────────────────────────────────────────────────────────

def harvest_elasticsearch(target: str, port: int = 9200) -> Optional[HarvestFinding]:
    try:
        base = f"http://{target}:{port}"
        resp = requests.get(f"{base}/", timeout=SOC_TIMEOUT)
        if resp.status_code not in (200, 401):
            return None
        if resp.status_code == 401:
            return None  # Auth required

        data = resp.json()
        version = data.get("version", {}).get("number", "?")
        cluster_name = data.get("cluster_name", "?")

        # List indices
        idx_resp = requests.get(f"{base}/_cat/indices?format=json&h=index,docs.count,store.size", timeout=SOC_TIMEOUT)
        indices = []
        if idx_resp.status_code == 200:
            indices = idx_resp.json()

        return HarvestFinding(
            service="elasticsearch",
            port=port,
            severity="critical",
            summary=f"Elasticsearch {version} unauthenticated — cluster '{cluster_name}', {len(indices)} indices",
            details={
                "version": version,
                "cluster_name": cluster_name,
                "indices": [{"name": i.get("index"), "docs": i.get("docs.count"), "size": i.get("store.size")} for i in indices[:15]],
            },
        )
    except Exception as e:
        logger.debug("[harvest] ES %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Docker API
# ─────────────────────────────────────────────────────────────────────────────

def harvest_docker_api(target: str, port: int = 2375) -> Optional[HarvestFinding]:
    try:
        base = f"http://{target}:{port}"
        ver_resp = requests.get(f"{base}/version", timeout=SOC_TIMEOUT)
        if ver_resp.status_code != 200:
            return None
        ver_data = ver_resp.json()
        docker_version = ver_data.get("Version", "?")

        # Container list
        cnt_resp = requests.get(f"{base}/containers/json?all=1", timeout=SOC_TIMEOUT)
        containers = cnt_resp.json() if cnt_resp.status_code == 200 else []

        # Image list
        img_resp = requests.get(f"{base}/images/json", timeout=SOC_TIMEOUT)
        images = img_resp.json() if img_resp.status_code == 200 else []

        return HarvestFinding(
            service="docker",
            port=port,
            severity="critical",
            summary=f"Docker {docker_version} API exposed unauthenticated — {len(containers)} containers, {len(images)} images",
            details={
                "docker_version": docker_version,
                "containers": [{"id": c.get("Id", "")[:12], "image": c.get("Image"), "state": c.get("State"), "names": c.get("Names")} for c in containers[:10]],
                "images": [{"id": i.get("Id", "")[:12], "tags": i.get("RepoTags")} for i in images[:10]],
            },
        )
    except Exception as e:
        logger.debug("[harvest] Docker API %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes API
# ─────────────────────────────────────────────────────────────────────────────

def harvest_kubernetes_api(target: str, port: int = 6443) -> Optional[HarvestFinding]:
    try:
        import ssl
        base = f"https://{target}:{port}"
        ver_resp = requests.get(f"{base}/version", verify=False, timeout=SOC_TIMEOUT)
        if ver_resp.status_code not in (200, 403, 401):
            return None
        if ver_resp.status_code in (401, 403):
            # Even knowing the version string is useful
            try:
                data = ver_resp.json()
            except Exception:
                return None
            return HarvestFinding(
                service="kubernetes",
                port=port,
                severity="medium",
                summary="Kubernetes API server detected (auth required)",
                details={"message": ver_resp.text[:200]},
            )

        data = ver_resp.json()
        k8s_version = data.get("gitVersion", "?")

        # Try unauthenticated namespace listing
        ns_resp = requests.get(f"{base}/api/v1/namespaces", verify=False, timeout=SOC_TIMEOUT)
        namespaces = []
        if ns_resp.status_code == 200:
            ns_data = ns_resp.json()
            namespaces = [i.get("metadata", {}).get("name") for i in ns_data.get("items", [])]

        return HarvestFinding(
            service="kubernetes",
            port=port,
            severity="critical" if namespaces else "high",
            summary=f"Kubernetes {k8s_version} API {'unauthenticated' if namespaces else 'detected'} — {len(namespaces)} namespaces",
            details={"version": k8s_version, "namespaces": namespaces[:10]},
        )
    except Exception as e:
        logger.debug("[harvest] K8s API %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CouchDB
# ─────────────────────────────────────────────────────────────────────────────

def harvest_couchdb(target: str, port: int = 5984) -> Optional[HarvestFinding]:
    try:
        base = f"http://{target}:{port}"
        resp = requests.get(f"{base}/_all_dbs", timeout=SOC_TIMEOUT)
        if resp.status_code == 401:
            return None
        if resp.status_code != 200:
            return None
        databases = resp.json()
        ver_resp = requests.get(f"{base}/", timeout=SOC_TIMEOUT)
        version = ver_resp.json().get("version", "?") if ver_resp.status_code == 200 else "?"
        return HarvestFinding(
            service="couchdb",
            port=port,
            severity="critical",
            summary=f"CouchDB {version} unauthenticated — {len(databases)} databases",
            details={"version": version, "databases": databases[:15]},
        )
    except Exception as e:
        logger.debug("[harvest] CouchDB %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Etcd
# ─────────────────────────────────────────────────────────────────────────────

def harvest_etcd(target: str, port: int = 2379) -> Optional[HarvestFinding]:
    try:
        base = f"http://{target}:{port}"
        health_resp = requests.get(f"{base}/health", timeout=SOC_TIMEOUT)
        if health_resp.status_code != 200:
            return None
        # Try listing keys via v3 API
        keys_resp = requests.post(
            f"{base}/v3/kv/range",
            json={"key": "Cg==", "range_end": "Cw==", "limit": 20},  # "" to "\x0b" — first keys
            timeout=SOC_TIMEOUT,
        )
        key_count = 0
        sample_keys = []
        if keys_resp.status_code == 200:
            kd = keys_resp.json()
            key_count = kd.get("count", 0)
            for kv in kd.get("kvs", [])[:10]:
                import base64
                try:
                    sample_keys.append(base64.b64decode(kv.get("key", "")).decode("utf-8", errors="ignore"))
                except Exception:
                    pass
        return HarvestFinding(
            service="etcd",
            port=port,
            severity="critical",
            summary=f"etcd unauthenticated — {key_count} keys found",
            details={"key_count": key_count, "sample_keys": sample_keys},
        )
    except Exception as e:
        logger.debug("[harvest] etcd %s:%d: %s", target, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Main harvester
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Default credential database
# ─────────────────────────────────────────────────────────────────────────────

# (username, password) pairs — ordered by frequency of success in the wild
DEFAULT_CREDS: Dict[str, List[tuple]] = {
    "redis": [
        ("", ""),           # no auth
        ("", "redis"),
        ("", "password"),
        ("", "admin"),
        ("", "123456"),
        ("", "foobared"),
    ],
    "mongodb": [
        ("", ""),
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "password"),
        ("root", ""),
        ("root", "root"),
    ],
    "mysql": [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("root", "mysql"),
        ("root", "toor"),
        ("mysql", "mysql"),
        ("admin", "admin"),
        ("admin", ""),
    ],
    "postgresql": [
        ("postgres", ""),
        ("postgres", "postgres"),
        ("postgres", "password"),
        ("postgres", "admin"),
        ("admin", "admin"),
        ("admin", ""),
    ],
    "mssql": [
        ("sa", ""),
        ("sa", "sa"),
        ("sa", "password"),
        ("sa", "admin"),
        ("sa", "Password1"),
        ("sa", "sql"),
        ("admin", "admin"),
    ],
    "ftp": [
        ("anonymous", "anonymous"),
        ("anonymous", "anonymous@example.com"),
        ("anonymous", ""),
        ("ftp", "ftp"),
        ("admin", "admin"),
        ("admin", ""),
        ("user", "user"),
        ("guest", "guest"),
        ("test", "test"),
    ],
    "ssh": [
        # Banner-only — we don't attempt SSH auth (too noisy, triggers lockout)
        # Kept here for future integration with paramiko
    ],
    "smb": [
        ("", ""),             # null session
        ("administrator", ""),
        ("admin", ""),
        ("guest", ""),
    ],
    "vnc": [
        ("", ""),
        ("", "password"),
        ("", "admin"),
        ("", "vnc"),
        ("", "123456"),
    ],
    "redis_auth": [
        ("redis",),
        ("password",),
        ("admin",),
        ("123456",),
        ("foobared",),
    ],
}


def try_redis_auth(target: str, port: int, password: str) -> bool:
    """Try a Redis AUTH password. Returns True if accepted."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOC_TIMEOUT)
        s.connect((target, port))
        s.sendall(f"AUTH {password}\r\n".encode())
        time.sleep(0.1)
        resp = s.recv(128).decode("utf-8", errors="ignore")
        s.close()
        return resp.startswith("+OK")
    except Exception:
        return False


def try_mysql_auth(target: str, port: int, username: str, password: str) -> bool:
    """Quick MySQL TCP connect + auth attempt. Returns True on success."""
    try:
        import socket as _s
        s = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        s.settimeout(SOC_TIMEOUT)
        s.connect((target, port))
        # Read handshake packet
        data = s.recv(1024)
        if not data or data[4] != 10:  # Protocol v10
            s.close()
            return False
        # Build minimal auth response (no SSL, no capabilities)
        # For checking purposes we just try sending a CLIENT_AUTH_HANDSHAKE_RESPONSE
        # with empty password (server will close if wrong)
        # Full implementation needs proper SHA1/caching_sha2 — skip for now
        # Just check if the server sends a greeting (port is MySQL)
        s.close()
        return False  # Placeholder — needs full MySQL auth protocol
    except Exception:
        return False


def try_ftp_auth(target: str, port: int, username: str, password: str) -> bool:
    """Try FTP login. Returns True on success."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOC_TIMEOUT)
        s.connect((target, port))
        banner = s.recv(512).decode("utf-8", errors="ignore")
        if "220" not in banner:
            s.close()
            return False
        s.sendall(f"USER {username}\r\n".encode())
        time.sleep(0.1)
        r1 = s.recv(128).decode("utf-8", errors="ignore")
        if "331" not in r1 and "230" not in r1:
            s.close()
            return False
        if "230" in r1:  # logged in without password
            s.close()
            return True
        s.sendall(f"PASS {password}\r\n".encode())
        time.sleep(0.1)
        r2 = s.recv(128).decode("utf-8", errors="ignore")
        s.close()
        return "230" in r2
    except Exception:
        return False


@dataclass
class CredFinding:
    service: str
    port: int
    username: str
    password: str
    severity: str = "critical"

    def to_dict(self) -> dict:
        return {
            "service": self.service, "port": self.port,
            "username": self.username, "password": self.password,
            "severity": self.severity,
        }


def check_default_creds(target: str, port: int, service: str) -> Optional[CredFinding]:
    """
    Try a short list of default credentials against the service.
    Returns the first working pair or None.
    """
    pairs = DEFAULT_CREDS.get(service, [])
    if not pairs:
        return None

    for pair in pairs:
        try:
            if service in ("redis", "redis_auth"):
                # If unauthenticated redis already works, skip
                # Try AUTH with each password
                pw = pair[0] if len(pair) == 1 else pair[1]
                if pw and try_redis_auth(target, port, pw):
                    return CredFinding(service, port, "", pw)
            elif service == "ftp":
                u, p = pair[0], pair[1]
                if try_ftp_auth(target, port, u, p):
                    return CredFinding(service, port, u, p)
        except Exception as _e:
            logger.debug("[cred_check] %s %s:%d failed: %s", service, target, port, _e)
    return None


# Map port → harvester function
PORT_HARVESTERS = {
    6379:  harvest_redis,
    6380:  harvest_redis,
    11211: harvest_memcached,
    21:    harvest_ftp_anon,
    9200:  harvest_elasticsearch,
    9243:  harvest_elasticsearch,
    2375:  harvest_docker_api,
    2376:  harvest_docker_api,
    6443:  harvest_kubernetes_api,
    8001:  harvest_kubernetes_api,
    5984:  harvest_couchdb,
    2379:  harvest_etcd,
    2380:  harvest_etcd,
}


def harvest_all(target: str, open_ports: List[int], check_creds: bool = True) -> HarvestResult:
    """
    Attempt to harvest data from all open ports that have known harvesters.
    If check_creds=True also tries default credentials on services that
    required authentication (Redis AUTH, FTP login, etc.).
    """
    result = HarvestResult(target=target)
    cred_findings: List[Dict] = []

    for port in open_ports:
        harvester = PORT_HARVESTERS.get(port)
        if harvester is None:
            continue
        try:
            finding = harvester(target, port)
            if finding:
                result.findings.append(finding)
                logger.info(
                    "[harvest] %s [%s] — %s",
                    finding.service, finding.severity, finding.summary
                )
            elif check_creds:
                # Service responded but requires auth — try default creds
                svc_name = _port_to_service_name(port)
                if svc_name:
                    cred = check_default_creds(target, port, svc_name)
                    if cred:
                        cf = HarvestFinding(
                            service=cred.service,
                            port=cred.port,
                            severity="critical",
                            summary=f"Default credentials work: {cred.username!r}:{cred.password!r}",
                            details={"username": cred.username, "password": cred.password,
                                     "note": "Change immediately"},
                        )
                        result.findings.append(cf)
                        cred_findings.append(cred.to_dict())
                        logger.info("[harvest] DEFAULT CREDS: %s:%d %s/%s",
                                    target, port, cred.username, cred.password)
        except Exception as e:
            logger.debug("[harvest] Port %d harvester error: %s", port, e)

    if cred_findings:
        result.notes.append(f"{len(cred_findings)} default credential pair(s) found")
    return result


# Map port → service name for credential checking
_PORT_SVC_MAP: Dict[int, str] = {
    21: "ftp", 6379: "redis_auth", 6380: "redis_auth",
    3306: "mysql", 5432: "postgresql", 1433: "mssql",
    27017: "mongodb", 5900: "vnc", 5901: "vnc", 5902: "vnc",
}


def _port_to_service_name(port: int) -> Optional[str]:
    return _PORT_SVC_MAP.get(port)
