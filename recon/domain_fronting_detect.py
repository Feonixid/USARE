"""
Domain Fronting / CDN Abuse Detection.

Analyzes HTTP responses for CDN/edge headers that may enable domain fronting
or SNI/certificate mismatches. Passive L7 intel from security header probe.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger("usare.domain_fronting_detect")


def analyze_fronting_hints(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract CDN/edge hints that suggest domain fronting may be possible.
    Input: headers dict from http_security_intel probe.

    Coverage:
        CloudFront, Cloudflare, Fastly, Akamai, Azure CDN,
        Google Cloud CDN, BunnyCDN, Sucuri, generic Via/X-Cache
    """
    out: Dict[str, Any] = {
        "fronting_likely": False,
        "cdn_hints": [],
        "edge_hints": [],
        "sni_smuggle_candidates": [],
        "notes": [],
    }
    h = headers if isinstance(headers, dict) else {}
    hl = {k.lower(): v for k, v in h.items() if isinstance(k, str)}

    # ── AWS CloudFront ────────────────────────────────────────────────────────
    if "x-amz-cf-id" in hl or "x-amz-cf-pop" in hl:
        out["cdn_hints"].append("cloudfront")
        out["fronting_likely"] = True

    # ── Cloudflare ────────────────────────────────────────────────────────────
    if "cf-ray" in hl or "cf-cache-status" in hl:
        out["cdn_hints"].append("cloudflare")
        out["fronting_likely"] = True

    # ── Fastly ────────────────────────────────────────────────────────────────
    if "x-served-by" in hl and "fastly" in str(hl.get("x-served-by", "")).lower():
        out["cdn_hints"].append("fastly")
        out["fronting_likely"] = True
    if "fastly-restarts" in hl or "x-fastly-request-id" in hl:
        if "fastly" not in out["cdn_hints"]:
            out["cdn_hints"].append("fastly")
        out["fronting_likely"] = True

    # ── Akamai ────────────────────────────────────────────────────────────────
    if "x-akamai-request-id" in hl or "x-check-cacheable" in hl:
        out["cdn_hints"].append("akamai")
        out["fronting_likely"] = True
    if "akamai-cache-status" in hl or "x-akamai-transformed" in hl:
        if "akamai" not in out["cdn_hints"]:
            out["cdn_hints"].append("akamai")
        out["fronting_likely"] = True

    # ── Azure CDN / Front Door ────────────────────────────────────────────────
    if "x-ms-routing-request-id" in hl or "x-azure-ref" in hl:
        out["cdn_hints"].append("azure_cdn")
        out["fronting_likely"] = True
    if "x-fd-healthprobe" in hl or "x-ms-ref" in hl:
        if "azure_cdn" not in out["cdn_hints"]:
            out["cdn_hints"].append("azure_cdn")
        out["fronting_likely"] = True

    # ── Google Cloud CDN / Load Balancer ──────────────────────────────────────
    if "x-cloud-trace-context" in hl or "x-goog-request-id" in hl:
        out["cdn_hints"].append("gcp_cdn")
        out["fronting_likely"] = True
    if "via" in hl and "google" in str(hl.get("via", "")).lower():
        if "gcp_cdn" not in out["cdn_hints"]:
            out["cdn_hints"].append("gcp_cdn")
        out["fronting_likely"] = True

    # ── BunnyCDN ──────────────────────────────────────────────────────────────
    if "bunny-request-id" in hl or "cdn-requestid" in hl:
        out["cdn_hints"].append("bunnycdn")
        out["fronting_likely"] = True
    if "cdn-requestcountrycode" in hl:
        if "bunnycdn" not in out["cdn_hints"]:
            out["cdn_hints"].append("bunnycdn")
        out["fronting_likely"] = True

    # ── Sucuri ────────────────────────────────────────────────────────────────
    if "x-sucuri-id" in hl or "x-sucuri-cache" in hl:
        out["cdn_hints"].append("sucuri")
        out["fronting_likely"] = True

    # ── Generic Via / X-Cache ─────────────────────────────────────────────────
    if "via" in hl:
        via = str(hl["via"]).lower()
        known_cdns = ("cloudflare", "fastly", "akamai", "google", "varnish",
                      "squid", "nginx", "apache")
        if any(cdn in via for cdn in known_cdns):
            out["edge_hints"].append(hl["via"][:80])
    if "x-cache" in hl:
        out["edge_hints"].append(f"cache: {hl['x-cache'][:60]}")

    if out["cdn_hints"]:
        out["sni_smuggle_candidates"] = list(out["cdn_hints"])
        out["notes"].append(
            "CDN present — SNI smuggling / domain fronting may be possible"
        )
    return out
