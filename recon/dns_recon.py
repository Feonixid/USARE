import socket
import struct
import time
import random
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
logger = logging.getLogger("usare.dns")
@dataclass
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: Optional[int] = None
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}
@dataclass
class DNSReconResult:
    target: str
    hostname: Optional[str] = None
    reverse_dns: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[str] = field(default_factory=list)
    has_wildcard: bool = False
    zone_transfer_possible: bool = False
    timestamp: float = field(default_factory=time.time)
    def to_dict(self) -> dict:
        result = {
            "target": self.target,
            "hostname": self.hostname,
            "reverse_dns": self.reverse_dns,
            "ip_addresses": self.ip_addresses,
            "subdomains": self.subdomains,
            "nameservers": self.nameservers,
            "mail_servers": self.mail_servers,
            "has_wildcard": self.has_wildcard,
            "zone_transfer_possible": self.zone_transfer_possible,
            "records": [r.to_dict() for r in self.records],
        }
        return {k: v for k, v in result.items() if v}
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "cpanel", "whm", "ns1", "ns2", "ns3",
    "api", "dev", "staging", "test", "beta", "alpha",
    "app", "mobile", "m", "cdn", "static", "assets", "media",
    "blog", "shop", "store", "portal", "vpn", "remote",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "elk", "kibana", "grafana", "prometheus", "monitor",
    "backup", "old", "legacy", "new", "www2", "www3",
    "internal", "intranet", "extranet", "exchange",
    "owa", "autodiscover", "sip", "lyncdiscover",
    "proxy", "gateway", "firewall", "router", "switch",
    "dns", "dns1", "dns2", "ntp", "time", "log", "syslog",
    "cloud", "aws", "azure", "gcp", "k8s", "docker",
    "status", "health", "metrics", "docs", "wiki",
    "support", "help", "ticket", "crm", "erp",
    "auth", "sso", "login", "identity", "oauth",
    "s3", "storage", "files", "upload", "download",
    "analytics", "tracking", "ads", "marketing",
    "direct", "origin", "backend", "frontend",
]
class DNSReconEngine:
    def __init__(
        self,
        timeout: float = 5.0,
        inter_query_delay: float = 0.5,
    ):
        self.timeout = timeout
        self.inter_query_delay = inter_query_delay
    def full_recon(self, target: str) -> DNSReconResult:
        result = DNSReconResult(target=target)
        is_ip = self._is_ip(target)
        if is_ip:
            result.reverse_dns = self.reverse_lookup(target)
            result.ip_addresses = [target]
            if result.reverse_dns:
                result.hostname = result.reverse_dns
                self._enumerate_records(str(result.reverse_dns), result)
        else:
            result.hostname = target
            ips = self.forward_lookup(target)
            result.ip_addresses = ips
            self._enumerate_records(target, result)
            result.subdomains = self.subdomain_bruteforce(target)
            result.has_wildcard = self.detect_wildcard(target)
        return result
    def reverse_lookup(self, ip: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None
    def forward_lookup(self, hostname: str) -> List[str]:
        try:
            results = socket.getaddrinfo(hostname, 0)
            ips = list(set(str(r[4][0]) for r in results))
            return ips
        except (socket.gaierror, OSError):
            return []
    def _enumerate_records(self, hostname: str, result: DNSReconResult):
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for info in infos:
                ip = str(info[4][0])
                result.records.append(DNSRecord(
                    name=hostname, record_type="A", value=ip
                ))
        except (socket.gaierror, OSError):
            pass
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for info in infos:
                ip = str(info[4][0])
                result.records.append(DNSRecord(
                    name=hostname, record_type="AAAA", value=ip
                ))
        except (socket.gaierror, OSError):
            pass
        mx_records = self._query_mx(hostname)
        for mx in mx_records:
            result.records.append(DNSRecord(
                name=hostname, record_type="MX", value=mx
            ))
            result.mail_servers.append(mx)
        ns_records = self._query_ns(hostname)
        for ns in ns_records:
            result.records.append(DNSRecord(
                name=hostname, record_type="NS", value=ns
            ))
            result.nameservers.append(ns)
    def _query_mx(self, hostname: str) -> List[str]:
        try:
            return self._dns_query(hostname, qtype=15)
        except Exception:
            return []
    def _query_ns(self, hostname: str) -> List[str]:
        try:
            return self._dns_query(hostname, qtype=2)
        except Exception:
            return []
    def _dns_query(self, hostname: str, qtype: int = 1, server: str = "8.8.8.8") -> List[str]:
        tx_id = random.randint(0, 65535)
        flags = 0x0100
        questions = 1
        query = struct.pack(">HHHHHH", tx_id, flags, questions, 0, 0, 0)
        for part in hostname.split("."):
            query += struct.pack("B", len(part)) + part.encode()
        query += b"\x00"
        query += struct.pack(">HH", qtype, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        sock.sendto(query, (server, 53))
        response, _ = sock.recvfrom(4096)
        import typing; response = typing.cast(typing.Any, response)
        sock.close()
        results = []
        try:
            answer_count = struct.unpack(">H", response[6:8])[0]
            # Walk past the 12-byte DNS header and then skip the question section
            # (which mirrors our query name + qtype + qclass) to reach the answer section.
            # Using len(query) was WRONG — response and query are completely separate buffers.
            offset = 12  # fixed-size DNS header
            # Skip question name (same encoding we sent)
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:   # pointer — shouldn't appear in question but guard anyway
                    offset += 2
                    break
                offset += response[offset] + 1
            offset += 1   # null terminator
            offset += 4   # qtype (2) + qclass (2)
            for _ in range(answer_count):
                if offset >= len(response):
                    break
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1
                if offset + 10 > len(response):
                    break
                rtype, rclass, rttl, rdlength = struct.unpack(
                    ">HHIH", response[offset:offset + 10]
                )
                offset += 10
                rdata = response[offset:offset + rdlength]
                offset += rdlength
                if rtype == 1 and rdlength == 4:
                    ip = ".".join(str(b) for b in rdata)
                    results.append(ip)
                elif rtype in (2, 5, 15):
                    name = self._decode_dns_name(response, offset - int(rdlength))
                    if name:
                        results.append(name)
        except Exception:
            pass
        return results
    def _decode_dns_name(self, data: bytes, offset: int) -> Optional[str]:
        import typing; data = typing.cast(typing.Any, data)
        parts = []
        seen = set()
        max_jumps = 20
        if offset + 2 < len(data):
            pass
        while offset < len(data) and max_jumps > 0:
            if offset in seen:
                break
            seen.add(offset)
            length = data[offset]
            if length == 0:
                break
            elif length & 0xC0 == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                offset = pointer
                max_jumps = max_jumps - 1
            else:
                offset += 1
                if offset + length > len(data):
                    break
                parts.append(data[offset:offset + length].decode("ascii", errors="replace"))
                offset += length
                max_jumps = max_jumps - 1
        return ".".join(parts) if parts else None
    def subdomain_bruteforce(
        self, domain: str,
        wordlist: Optional[List[str]] = None,
        max_results: int = 100,
    ) -> List[str]:
        words = wordlist or SUBDOMAIN_WORDLIST
        discovered = []
        for word in words:
            if len(discovered) >= max_results:
                break
            fqdn = f"{word}.{domain}"
            try:
                ips = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                if ips:
                    discovered.append(fqdn)
                    logger.info(f"[DNS] Discovered: {fqdn} → {ips[0][4][0]}")
            except (socket.gaierror, OSError):
                pass
            time.sleep(self.inter_query_delay)
        return discovered
    def detect_wildcard(self, domain: str) -> bool:
        random_sub = f"usare-{random.randint(100000, 999999)}-check"
        fqdn = f"{random_sub}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            return True
        except (socket.gaierror, OSError):
            return False
    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False