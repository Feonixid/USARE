import json
import time
import os
import csv
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
@dataclass
class PortIntelligence:
    port: int
    state: str
    protocol: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    os_hint: Optional[str] = None
    banner: Optional[str] = None
    ttl: Optional[int] = None
    window: Optional[int] = None
    latency_ms: Optional[float] = None
    confidence: float = 0.0
    risk_level: str = "info"       
    notes: List[str] = field(default_factory=list)
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}
@dataclass
class ScanIntelligence:
    target: str
    scan_start: float = field(default_factory=time.time)
    scan_end: Optional[float] = None
    os_detection: Optional[Dict] = None
    ports: List[PortIntelligence] = field(default_factory=list)
    dns_intel: Optional[Dict] = None
    traceroute: Optional[Dict] = None
    waf_detection: Optional[Dict] = None
    host_status: Optional[Dict] = None
    heat_level: float = 0.0
    attack_surface_score: float = 0.0
    total_packets_sent: int = 0
    recommendations: List[str] = field(default_factory=list)
    def to_dict(self) -> dict:
        self.scan_end = self.scan_end or time.time()
        return {
            "target": self.target,
            "scan_start": datetime.fromtimestamp(self.scan_start).isoformat(),
            "scan_end": datetime.fromtimestamp(float(self.scan_end)).isoformat(),
            "elapsed_seconds": round(float(self.scan_end - self.scan_start), 1),
            "os_detection": self.os_detection,
            "ports": [p.to_dict() for p in self.ports],
            "dns_intel": self.dns_intel,
            "traceroute": self.traceroute,
            "waf_detection": self.waf_detection,
            "host_status": self.host_status,
            "heat_level": round(float(self.heat_level), 4),
            "attack_surface_score": round(float(self.attack_surface_score), 2),
            "total_packets_sent": self.total_packets_sent,
            "recommendations": self.recommendations,
        }
SERVICE_RISK = {
    "telnet": "critical",
    "ftp": "high",
    "ms-sql": "high",
    "mysql": "high",
    "postgresql": "medium",
    "redis": "critical",
    "mongodb": "critical",
    "memcached": "critical",
    "vnc": "high",
    "smb": "high",
    "microsoft-ds": "high",
    "ms-wbt-server": "medium",
    "ssh": "low",
    "http": "low",
    "https": "info",
    "smtp": "medium",
    "dns": "low",
}
class ReportEngine:
    def build_intelligence(
        self,
        target: str,
        scan_results: List[Dict],
        os_fingerprint: Optional[Dict] = None,
        banners: Optional[Dict] = None,
        service_info: Optional[Dict[int, Dict]] = None,
        dns_intel: Optional[Dict] = None,
        traceroute_data: Optional[Dict] = None,
        waf_data: Optional[Dict] = None,
        host_status: Optional[Dict] = None,
        heat_level: float = 0.0,
        total_packets: int = 0,
    ) -> ScanIntelligence:
        intel = ScanIntelligence(
            target=target,
            os_detection=os_fingerprint,
            dns_intel=dns_intel,
            traceroute=traceroute_data,
            waf_detection=waf_data,
            host_status=host_status,
            heat_level=heat_level,
            total_packets_sent=total_packets,
        )
        for result in scan_results:
            port_num = result.get("port", 0)
            port_intel = PortIntelligence(
                port=port_num,
                state=result.get("state", "unknown"),
                protocol=result.get("protocol", "tcp"),
                service=result.get("service"),
                ttl=result.get("ttl"),
                window=result.get("window"),
                latency_ms=result.get("latency_ms"),
            )
            if banners and port_num in banners:
                b = banners[port_num]
                port_intel.banner = b.get("banner_raw")
                if not port_intel.service:
                    port_intel.service = b.get("service")
            if service_info and port_num in service_info:
                s = service_info[port_num]
                port_intel.product = s.get("product")
                port_intel.version = s.get("version")
                port_intel.cpe = s.get("cpe")
                port_intel.os_hint = s.get("os_hint")
                port_intel.confidence = s.get("confidence", 0.0)
            service_key = (port_intel.service or "").lower()
            port_intel.risk_level = SERVICE_RISK.get(service_key, "info")
            if port_intel.state == "open":
                base = 0.5
                if port_intel.service:
                    base += 0.1
                if port_intel.product:
                    base += 0.1
                if port_intel.version:
                    base += 0.2
                if port_intel.cpe:
                    base += 0.1
                port_intel.confidence = max(port_intel.confidence, base)
            if port_intel.risk_level == "critical":
                port_intel.notes.append(
                    f"CRITICAL: {port_intel.service} exposed — high exploitation risk"
                )
            if port_intel.version:
                port_intel.notes.append(f"Version: {port_intel.version}")
            intel.ports.append(port_intel)
        intel.attack_surface_score = self._calculate_attack_surface(intel)
        intel.recommendations = self._generate_recommendations(intel)
        intel.scan_end = time.time()
        return intel
    def _calculate_attack_surface(self, intel: ScanIntelligence) -> float:
        open_ports = [p for p in intel.ports if p.state == "open"]
        if not open_ports:
            return 0.0
        score = 0.0
        risk_weights = {
            "critical": 25.0, "high": 15.0, "medium": 8.0,
            "low": 3.0, "info": 1.0,
        }
        for port in open_ports:
            score += risk_weights.get(port.risk_level, 1.0)
        return min(100.0, score)
    def _generate_recommendations(self, intel: ScanIntelligence) -> List[str]:
        recs = []
        open_ports = [p for p in intel.ports if p.state == "open"]
        critical = [p for p in open_ports if p.risk_level == "critical"]
        if critical:
            services = ", ".join(set(p.service or str(p.port) for p in critical))
            recs.append(
                f"CRITICAL: Close or firewall these services immediately: {services}"
            )
        high = [p for p in open_ports if p.risk_level == "high"]
        if high:
            services = ", ".join(set(p.service or str(p.port) for p in high))
            recs.append(f"HIGH: Review access controls for: {services}")
        for port in open_ports:
            if port.product and port.version:
                recs.append(
                    f"Port {port.port}: Verify {port.product} {port.version} "
                    f"is patched against known CVEs"
                )
        if not intel.waf_detection or not intel.waf_detection.get("waf_detected"):
            has_http = any(
                p.service in ("http", "https") for p in open_ports
            )
            if has_http:
                recs.append("No WAF detected on HTTP services — consider deploying one")
        if len(open_ports) > 20:
            recs.append(
                f"Large attack surface: {len(open_ports)} open ports. "
                f"Review and close unnecessary services."
            )
        return recs
    def display_report(self, intel: ScanIntelligence, console: Optional[Console] = None):
        con = console or Console()
        con.print(Panel(
            f"[bold]Target: {intel.target}[/bold]\n"
            f"Elapsed: {intel.scan_end - intel.scan_start:.1f}s | "
            f"Packets: {intel.total_packets_sent} | "
            f"Heat: {intel.heat_level:.2%}",
            title="[bold cyan]📊 USARE Intelligence Report[/bold cyan]",
            border_style="cyan",
        ))
        if intel.os_detection:
            os_name = intel.os_detection.get("os_name", "Unknown")
            os_conf = intel.os_detection.get("confidence", 0)
            con.print(f"\n[bold]🖥️  OS Detection:[/bold] {os_name} "
                      f"(confidence: {os_conf:.0%})")
        open_ports = [p for p in intel.ports if p.state == "open"]
        if open_ports:
            table = Table(
                title="🔓 Open Ports",
                box=box.ROUNDED, show_lines=True, border_style="green",
            )
            table.add_column("Port", style="bold green", justify="right")
            table.add_column("Service", style="cyan")
            table.add_column("Product", style="white")
            table.add_column("Version", style="yellow")
            table.add_column("Risk", justify="center")
            table.add_column("Confidence", justify="center")
            table.add_column("CPE", style="dim")
            risk_colors = {
                "critical": "bold red", "high": "red", "medium": "yellow",
                "low": "green", "info": "dim",
            }
            for p in sorted(open_ports, key=lambda x: x.port):
                risk_style = risk_colors.get(p.risk_level, "dim")
                table.add_row(
                    str(p.port),
                    p.service or "-",
                    p.product or "-",
                    p.version or "-",
                    f"[{risk_style}]{p.risk_level.upper()}[/{risk_style}]",
                    f"{p.confidence:.0%}",
                    p.cpe or "-",
                )
            con.print(table)
        score = intel.attack_surface_score
        if score >= 50:
            color = "red"
        elif score >= 25:
            color = "yellow"
        else:
            color = "green"
        con.print(f"\n[bold]🎯 Attack Surface Score:[/bold] "
                  f"[{color}]{score:.0f}/100[/{color}]")
        if intel.recommendations:
            rec_text = "\n".join(f"  • {r}" for r in intel.recommendations)
            con.print(Panel(
                rec_text,
                title="[bold]💡 Recommendations[/bold]",
                border_style="yellow",
            ))

    def export_json(self, intel: ScanIntelligence, console: Optional[Console] = None, out_dir: str = "logs"):
        import os
        con = console or Console()
        os.makedirs(out_dir, exist_ok=True)
        filename = os.path.join(out_dir, f"usare_{intel.target.replace('.', '_')}_{int(intel.scan_start)}.json")
        try:
            with open(filename, "w") as f:
                json.dump(intel.to_dict(), f, indent=4)
            con.print(f"\n[bold green]✓ Report exported to JSON:[/bold green] {filename}")
        except Exception as e:
            con.print(f"\n[bold red]✗ Failed to export JSON:[/bold red] {e}")

    def export_csv(self, intel: ScanIntelligence, console: Optional[Console] = None, out_dir: str = "logs"):
        import os
        import csv
        con = console or Console()
        os.makedirs(out_dir, exist_ok=True)
        filename = os.path.join(out_dir, f"usare_{intel.target.replace('.', '_')}_{int(intel.scan_start)}.csv")
        try:
            with open(filename, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Port", "State", "Protocol", "Service", "Product", "Version", "Risk", "Confidence", "CPE"
                ])
                for p in sorted(intel.ports, key=lambda x: x.port):
                    writer.writerow([
                        p.port, p.state, p.protocol, p.service or "", p.product or "",
                        p.version or "", p.risk_level, f"{p.confidence:.2f}", p.cpe or ""
                    ])
            con.print(f"\n[bold green]✓ Report exported to CSV:[/bold green] {filename}")
        except Exception as e:
            con.print(f"\n[bold red]✗ Failed to export CSV:[/bold red] {e}")

    def export_xml(self, intel: ScanIntelligence, console: Optional[Console] = None):
        import os
        import xml.etree.ElementTree as ET
        from xml.dom import minidom
        con = console or Console()
        os.makedirs("logs", exist_ok=True)
        filename = f"logs/usare_{intel.target.replace('.', '_')}_{int(intel.scan_start)}.xml"
        try:
            root = ET.Element("nmaprun")
            root.set("scanner", "usare")
            root.set("args", "usare stealth scan")
            root.set("start", str(int(intel.scan_start)))
            root.set("startstr", datetime.fromtimestamp(intel.scan_start).strftime("%a %b %d %H:%M:%S %Y"))
            root.set("version", "2.0")
            root.set("xmloutputversion", "1.04")

            host = ET.SubElement(root, "host")
            status = ET.SubElement(host, "status")
            status.set("state", "up")
            status.set("reason", "syn-ack")
            
            address = ET.SubElement(host, "address")
            address.set("addr", intel.target)
            address.set("addrtype", "ipv4")
            
            ports_elem = ET.SubElement(host, "ports")
            for p in sorted(intel.ports, key=lambda x: x.port):
                port_elem = ET.SubElement(ports_elem, "port")
                port_elem.set("protocol", p.protocol)
                port_elem.set("portid", str(p.port))
                
                state_elem = ET.SubElement(port_elem, "state")
                state_elem.set("state", p.state)
                state_elem.set("reason", "syn-ack" if p.state == "open" else "no-response")
                
                if p.service:
                    service_elem = ET.SubElement(port_elem, "service")
                    service_elem.set("name", str(p.service))
                    service_elem.set("method", "probed")
                    service_elem.set("conf", "10")
                    if p.product:
                        service_elem.set("product", str(p.product))
                    if p.version:
                        service_elem.set("version", str(p.version))
                    if p.cpe:
                        cpe_elem = ET.SubElement(service_elem, "cpe")
                        cpe_elem.text = p.cpe
                        
            runstats = ET.SubElement(root, "runstats")
            finished = ET.SubElement(runstats, "finished")
            end_time = intel.scan_end or intel.scan_start
            finished.set("time", str(int(end_time)))
            finished.set("timestr", datetime.fromtimestamp(end_time).strftime("%a %b %d %H:%M:%S %Y"))
            finished.set("elapsed", f"{end_time - intel.scan_start:.2f}")
            finished.set("summary", f"USARE done: 1 IP address (1 host up) scanned in {end_time - intel.scan_start:.2f} seconds")

            xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="    ")
            # Replace the generic XML declaration to include the Nmap DTD stylesheet if needed
            xmlstr = xmlstr.replace('<?xml version="1.0" ?>', '<?xml version="1.0" ?>\n<!DOCTYPE nmaprun>\n<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>')
            with open(filename, "w") as f:
                f.write(xmlstr)
                
            con.print(f"\n[bold green]✓ Report exported to XML:[/bold green] {filename}")
        except Exception as e:
            con.print(f"\n[bold red]✗ Failed to export XML:[/bold red] {e}")