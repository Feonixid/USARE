"""
HTTP Header Rotation — Evade L7 Fingerprinting.

Rotates User-Agent, Accept, Accept-Language, and header order to defeat
HTTP fingerprinting and correlation. Mimics CDN health checks, monitoring
agents, and varied browser profiles.
"""

import random
from typing import Dict, Any, List, Optional

# CDN / monitoring / health-check style — low suspicion
HEALTH_CHECK_AGENTS = [
    "Amazon CloudWatch-HealthAgent/1.0",
    "UptimeRobot/2.0 (https://uptimerobot.com/)",
    "Pingdom/1.0 (https://pingdom.com)",
    "Datadog Agent/7.0",
    "NewRelic-HealthCheck/1.0",
    "Google-Cloud-Health-Check/1.0",
    "Azure-Health-Check/1.0",
    "Fastly-Health-Check/1.0",
    "Cloudflare-Health-Check/1.0",
    "StatusCake/1.0",
]

# Common browser profiles — rotate to avoid single fingerprint
BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Edg/121.0.0.0",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
]

ACCEPT_LANGUAGE = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "",
]


def get_rotated_headers(
    profile: str = "browser",
    seed: Optional[int] = None,
) -> Dict[str, str]:
    """
    Return a randomized HTTP header set for the given profile.
    profile: "browser" | "health" | "mixed"
    """
    rng = random.Random(seed)
    headers: Dict[str, str] = {}
    if profile == "health":
        headers["User-Agent"] = rng.choice(HEALTH_CHECK_AGENTS)
        headers["Accept"] = "*/*"
    elif profile == "mixed" and rng.random() < 0.3:
        headers["User-Agent"] = rng.choice(HEALTH_CHECK_AGENTS)
        headers["Accept"] = "*/*"
    else:
        headers["User-Agent"] = rng.choice(BROWSER_AGENTS)
        headers["Accept"] = rng.choice(ACCEPT_HEADERS)
    al = rng.choice(ACCEPT_LANGUAGE)
    if al:
        headers["Accept-Language"] = al
    return headers
