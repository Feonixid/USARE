"""
HTTP Path Discovery — Stealth wordlist probe against discovered web ports.

Probes a curated set of high-value paths that commonly expose sensitive
configuration, debug endpoints, admin interfaces, and frameworks.
No brute-force — all paths are hand-selected for maximum signal/noise.
"""

import socket
import ssl
import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("usare.path_scan")

# High-value paths — ordered by priority (first confirmed finding wins)
HIGH_VALUE_PATHS: List[Tuple[str, str]] = [
    # Secret / credential leaks
    ("/.env",                    "Environment config (credentials)"),
    ("/.env.local",              "Local env override"),
    ("/.env.production",         "Production env"),
    ("/.env.backup",             "Backup env file"),
    ("/.git/config",             "Git repository config"),
    ("/.git/HEAD",               "Git HEAD ref"),
    ("/.svn/entries",            "Subversion repo"),
    ("/.DS_Store",               "macOS metadata leak"),
    ("/web.config",              "IIS config file"),
    ("/app.config",              "Application config"),
    ("/config.php",              "PHP config"),
    ("/config.yml",              "YAML config"),
    ("/config.json",             "JSON config"),
    ("/configuration.php",       "CMS config"),
    ("/settings.py",             "Django/Python settings"),
    ("/wp-config.php",           "WordPress config"),
    ("/wp-config.php.bak",       "WordPress config backup"),
    # Debug / admin interfaces
    ("/robots.txt",              "robots.txt (path disclosure)"),
    ("/sitemap.xml",             "Sitemap (path disclosure)"),
    ("/admin",                   "Admin panel"),
    ("/admin/",                  "Admin panel (trailing slash)"),
    ("/administrator",           "Joomla admin"),
    ("/wp-admin/",               "WordPress admin"),
    ("/wp-login.php",            "WordPress login"),
    ("/phpmyadmin/",             "phpMyAdmin"),
    ("/pma/",                    "phpMyAdmin alias"),
    ("/adminer.php",             "Adminer DB tool"),
    ("/manager/html",            "Tomcat manager"),
    ("/jmx-console/",           "JBoss JMX console"),
    ("/web-console/",           "JBoss web console"),
    # Framework / API discovery
    ("/actuator",                "Spring Boot Actuator"),
    ("/actuator/env",            "Spring Boot: env vars"),
    ("/actuator/beans",          "Spring Boot: bean list"),
    ("/actuator/health",         "Spring Boot: health"),
    ("/actuator/httptrace",      "Spring Boot: HTTP trace"),
    ("/actuator/dump",           "Spring Boot: thread dump"),
    ("/api",                     "API root"),
    ("/api/v1",                  "API v1"),
    ("/api/v2",                  "API v2"),
    ("/swagger",                 "Swagger UI"),
    ("/swagger-ui.html",         "Swagger UI (Spring)"),
    ("/swagger-ui/",             "Swagger UI (OpenAPI 3)"),
    ("/swagger.json",            "OpenAPI spec"),
    ("/openapi.json",            "OpenAPI 3 spec"),
    ("/v2/api-docs",             "Springfox API docs"),
    ("/graphql",                 "GraphQL endpoint"),
    ("/graphiql",                "GraphiQL explorer"),
    ("/__graphql",               "GraphQL alt path"),
    ("/console",                 "H2/Grails console"),
    ("/.well-known/security.txt","Security contact"),
    ("/.well-known/acme-challenge/","ACME challenge exposure"),
    # Monitoring / logs
    ("/server-status",           "Apache mod_status"),
    ("/server-info",             "Apache mod_info"),
    ("/status",                  "Generic status page"),
    ("/health",                  "Health check"),
    ("/metrics",                 "Prometheus metrics"),
    ("/debug",                   "Debug endpoint"),
    ("/debug/pprof/",            "Go pprof profiler"),
    ("/trace",                   "Trace endpoint"),
    ("/logs",                    "Logs endpoint"),
    ("/info",                    "Info endpoint"),
    # Backup / source code
    ("/index.php~",              "PHP backup file"),
    ("/index.php.bak",           "PHP backup"),
    ("/index.html.bak",          "HTML backup"),
    ("/backup.zip",              "Backup archive"),
    ("/backup.tar.gz",           "Backup tarball"),
    ("/dump.sql",                "SQL dump"),
    ("/db.sql",                  "SQL dump"),
    # Cloud / containers
    ("/latest/meta-data/",       "AWS IMDS v1"),
    ("/computeMetadata/v1/",     "GCP metadata"),
    ("/metadata/instance",       "Azure IMDS"),
    ("/.kube/config",            "Kubernetes config"),
    ("/version",                 "Version disclosure"),
]

# HTTP status codes that indicate a real finding (not 404/default)
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500}
POSITIVE_CODES    = {200, 201, 204, 301, 302, 307, 308}
AUTH_CODES        = {401, 403}


@dataclass
class PathFinding:
    path: str
    description: str
    status_code: int
    content_length: int
    server_header: Optional[str]
    content_type: Optional[str]
    redirect_location: Optional[str]
    is_positive: bool
    requires_auth: bool
    port: int
    scheme: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "description": self.description,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "server": self.server_header,
            "content_type": self.content_type,
            "redirect": self.redirect_location,
            "auth_required": self.requires_auth,
            "port": self.port,
            "scheme": self.scheme,
        }


@dataclass
class PathScanResult:
    target: str
    port: int
    scheme: str
    total_probed: int = 0
    findings: List[PathFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "scheme": self.scheme,
            "total_probed": self.total_probed,
            "findings": [f.to_dict() for f in self.findings],
            "positive": [f.to_dict() for f in self.findings if f.is_positive],
            "auth_required": [f.path for f in self.findings if f.requires_auth],
            "notes": self.notes,
        }


def _probe_path(
    host: str,
    port: int,
    use_tls: bool,
    path: str,
    timeout: float,
    ua: str = "Mozilla/5.0 (compatible; USARE/2.0)",
) -> Optional[Tuple[int, int, Optional[str], Optional[str], Optional[str]]]:
    """
    Make a minimal GET request.
    Returns (status_code, content_length, server, content_type, location) or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Connection: close\r\n"
            f"Accept: */*\r\n\r\n"
        )
        sock.sendall(request.encode())
        response = b""
        while True:
            chunk = sock.recv(2048)
            if not chunk:
                break
            response += chunk
            if len(response) > 16384:
                break
        sock.close()
        if not response:
            return None
        header_end = response.find(b"\r\n\r\n")
        headers_raw = response[:header_end].decode("utf-8", errors="ignore") if header_end > 0 else response[:512].decode("utf-8", errors="ignore")
        lines = headers_raw.split("\r\n")
        if not lines:
            return None
        # Status line
        status_line = lines[0]
        m = None
        import re
        m = re.match(r"HTTP/[\d.]+ (\d+)", status_line)
        if not m:
            return None
        status_code = int(m.group(1))
        # Parse headers
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        content_length = int(headers.get("content-length", "0") or "0")
        server = headers.get("server")
        content_type = headers.get("content-type")
        location = headers.get("location")
        return status_code, content_length, server, content_type, location
    except Exception:
        return None


def scan_paths(
    target: str,
    port: int,
    use_tls: bool,
    timeout: float = 5.0,
    delay_between: float = 0.2,
    paths: Optional[List[Tuple[str, str]]] = None,
) -> PathScanResult:
    """
    Probe a list of paths against a target web port.
    Returns a PathScanResult with all findings.
    """
    result = PathScanResult(
        target=target,
        port=port,
        scheme="https" if use_tls else "http",
    )
    path_list = paths or HIGH_VALUE_PATHS

    for path, description in path_list:
        result.total_probed += 1
        resp = _probe_path(target, port, use_tls, path, timeout)
        if resp is None:
            continue
        status_code, content_length, server, content_type, location = resp
        if status_code not in INTERESTING_CODES:
            continue
        finding = PathFinding(
            path=path,
            description=description,
            status_code=status_code,
            content_length=content_length,
            server_header=server,
            content_type=content_type,
            redirect_location=location,
            is_positive=status_code in POSITIVE_CODES,
            requires_auth=status_code in AUTH_CODES,
            port=port,
            scheme="https" if use_tls else "http",
        )
        result.findings.append(finding)
        logger.debug(
            "[path_scan] %s:%d%s → %d (%s)",
            target, port, path, status_code, description
        )
        if delay_between > 0:
            time.sleep(delay_between)

    return result


def scan_all_web_ports(
    target: str,
    open_ports: List[int],
    timeout: float = 5.0,
    delay_between: float = 0.2,
) -> Dict[int, PathScanResult]:
    """
    Run path scan against all known web ports from the open port list.
    """
    results: Dict[int, PathScanResult] = {}
    web_ports_tls = {443, 8443, 9443, 4443}
    web_ports_plain = {80, 8080, 8000, 8888, 3000, 5000, 9090, 7080}
    for port in open_ports:
        if port in web_ports_tls:
            results[port] = scan_paths(target, port, use_tls=True, timeout=timeout, delay_between=delay_between)
        elif port in web_ports_plain:
            results[port] = scan_paths(target, port, use_tls=False, timeout=timeout, delay_between=delay_between)
    return results
