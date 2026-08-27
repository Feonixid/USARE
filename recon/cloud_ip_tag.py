"""
USARE Cloud IP Range Tagger

Tags target IP addresses with their corresponding cloud provider
(AWS, Azure, GCP, Cloudflare, etc.) by checking against known public IP ranges.
This helps in contextualizing targets for specific attack/evasion paths
(e.g., SSRF against AWS metadata service if target is on AWS).
"""

import ipaddress
import urllib.request
import json
import os
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger("usare.cloud_tagger")

@dataclass
class CloudTag:
    provider: str
    service: str
    region: str


class CloudIPTagger:
    """Tags IP addresses with their cloud provider origin."""

    def __init__(self, cache_dir: str = "/tmp/usare_cache"):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        # Network -> CloudTag
        self.aws_ranges: Dict[ipaddress.IPv4Network, CloudTag] = {}
        self.azure_ranges: Dict[ipaddress.IPv4Network, CloudTag] = {}
        self.gcp_ranges: Dict[ipaddress.IPv4Network, CloudTag] = {}
        self.cloudflare_ranges: List[ipaddress.IPv4Network] = []

    def _download_if_old(self, url: str, filename: str, max_age_days: int = 7) -> str:
        """Download file if it doesn't exist or is too old."""
        filepath = os.path.join(self.cache_dir, filename)
        
        needs_download = True
        if os.path.exists(filepath):
            mtime = os.path.getmtime(filepath)
            if (time.time() - mtime) < (max_age_days * 86400):
                needs_download = False
                
        if needs_download:
            try:
                logger.debug(f"Downloading {filename} from {url}")
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    with open(filepath, 'wb') as f:
                        f.write(response.read())
            except Exception as e:
                logger.warning(f"Failed to download {url}: {e}")
                
        return filepath

    def load_ranges(self):
        """Load IP ranges for major providers."""
        # AWS
        aws_file = self._download_if_old(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", "aws_ips.json"
        )
        if os.path.exists(aws_file):
            try:
                with open(aws_file, 'r') as f:
                    data = json.load(f)
                    for prefix in data.get('prefixes', []):
                        try:
                            net = ipaddress.IPv4Network(prefix['ip_prefix'])
                            tag = CloudTag(
                                provider="AWS",
                                service=prefix.get('service', 'AMAZON'),
                                region=prefix.get('region', 'GLOBAL')
                            )
                            self.aws_ranges[net] = tag
                        except ValueError:
                            pass
            except Exception as e:
                logger.warning(f"Error parsing AWS ranges: {e}")

        # GCP
        gcp_file = self._download_if_old(
            "https://www.gstatic.com/ipranges/cloud.json", "gcp_ips.json"
        )
        if os.path.exists(gcp_file):
            try:
                with open(gcp_file, 'r') as f:
                    data = json.load(f)
                    for prefix in data.get('prefixes', []):
                        if 'ipv4Prefix' in prefix:
                            try:
                                net = ipaddress.IPv4Network(prefix['ipv4Prefix'])
                                tag = CloudTag(
                                    provider="GCP",
                                    service=prefix.get('service', 'Google_Cloud'),
                                    region=prefix.get('scope', 'global')
                                )
                                self.gcp_ranges[net] = tag
                            except ValueError:
                                pass
            except Exception as e:
                logger.warning(f"Error parsing GCP ranges: {e}")

        # Azure (public cloud XML → JSON download tags)
        azure_file = self._download_if_old(
            "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240101.json",
            "azure_ips.json"
        )
        if os.path.exists(azure_file):
            try:
                with open(azure_file, 'r') as f:
                    data = json.load(f)
                    for entry in data.get('values', []):
                        props = entry.get('properties', {})
                        for prefix in props.get('addressPrefixes', []):
                            if ':' not in prefix:  # IPv4 only
                                try:
                                    net = ipaddress.IPv4Network(prefix)
                                    tag = CloudTag(
                                        provider="Azure",
                                        service=entry.get('name', 'AzureCloud'),
                                        region=props.get('region', 'global') or 'global'
                                    )
                                    self.azure_ranges[net] = tag
                                except ValueError:
                                    pass
            except Exception as e:
                logger.warning(f"Error parsing Azure ranges: {e}")

        # Cloudflare
        cf_file = self._download_if_old(
            "https://www.cloudflare.com/ips-v4", "cloudflare_ips.txt"
        )
        if os.path.exists(cf_file):
            try:
                with open(cf_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                self.cloudflare_ranges.append(ipaddress.IPv4Network(line))
                            except ValueError:
                                pass
            except Exception as e:
                logger.warning(f"Error parsing Cloudflare ranges: {e}")

    def tag_ip(self, ip_str: str) -> Optional[CloudTag]:
        """Tag an IP address with its cloud provider."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return None

        # Check AWS
        for net, tag in self.aws_ranges.items():
            if ip in net:
                return tag

        # Check GCP
        for net, tag in self.gcp_ranges.items():
            if ip in net:
                return tag

        # Check Azure
        for net, tag in self.azure_ranges.items():
            if ip in net:
                return tag

        # Check Cloudflare
        for net in self.cloudflare_ranges:
            if ip in net:
                return CloudTag(provider="Cloudflare", service="CDN/WAF", region="Global")

        return None
