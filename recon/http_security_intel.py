"""
HTTP Security Header Intelligence.

Single GET/HEAD to collect HSTS, CSP, security headers, and redirect chain hints —
passive-ish L7 fingerprinting without aggressive crawling.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin

logger = logging.getLogger("usare.http_security_intel")

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "server",
    "x-powered-by",
    "via",
    "x-xss-protection",
    "x-dns-prefetch-control",
    "expect-ct",
    "nel",
    "report-to",
    "x-request-id",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "cf-ray",
    "x-served-by",
    "x-cache",
    "x-timer",
)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _extract_headers(resp, max_len: int = 500) -> Dict[str, str]:
    headers = {}
    hdr_obj = getattr(resp, "headers", None) or (resp if hasattr(resp, "get") else None)
    if not hdr_obj:
        return headers
    for h in SECURITY_HEADERS:
        v = hdr_obj.get(h) if hasattr(hdr_obj, "get") else None
        if v:
            sv = str(v)
            headers[h] = sv[:max_len] if len(sv) > max_len else sv
    return headers


def _follow_redirect_chain(
    target: str, port: int, use_https: bool, timeout: float, path: str,
    max_hops: int = 5,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Follow redirect chain and collect headers at each hop."""
    https = use_https or port in (443, 8443, 9443)
    scheme = "https" if https else "http"
    base = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"
    url = f"{base}{path}"
    chain = []
    seen = set()
    for _ in range(max_hops):
        if url in seen:
            break
        seen.add(url)
        try:
            base_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:122.0) Gecko/20100101 Firefox/122.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            try:
                from evasion.http_header_rotation import get_rotated_headers
                base_headers = get_rotated_headers(profile="mixed")
            except ImportError:
                pass
            req = Request(url, method="GET", headers=base_headers)
            opener = build_opener(_NoRedirectHandler())
            with opener.open(req, timeout=timeout) as resp:
                chain.append({
                    "url": url,
                    "status": getattr(resp, "status", 200),
                    "headers": _extract_headers(resp),
                })
                loc = resp.headers.get("Location") or resp.headers.get("location")
                if loc and getattr(resp, "status", 200) in (301, 302, 303, 307, 308):
                    url = urljoin(url, loc)
                else:
                    return chain, None
        except HTTPError as e:
            chain.append({
                "url": url,
                "status": e.code,
                "headers": _extract_headers(e) if e.headers else {},
            })
            loc = e.headers.get("Location") or e.headers.get("location") if e.headers else None
            if loc and e.code in (301, 302, 303, 307, 308):
                url = urljoin(url, loc)
            else:
                return chain, None
        except Exception:
            return chain, None
    return chain, None


def probe_http_security(
    target: str,
    port: int = 80,
    use_https: bool = False,
    timeout: float = 8.0,
    path: str = "/",
    follow_redirects: bool = True,
    max_redirect_hops: int = 5,
    rotate_headers: bool = True,
) -> Dict[str, Any]:
    https = use_https or port in (443, 8443, 9443)
    scheme = "https" if https else "http"
    if (https and port == 443) or (not https and port == 80):
        url = f"{scheme}://{target}{path}"
    else:
        url = f"{scheme}://{target}:{port}{path}"

    out: Dict[str, Any] = {
        "url": url,
        "status": None,
        "headers": {},
        "redirect_url": None,
        "redirect_chain": [],
        "hsts_preload": False,
        "infra_hints": [],
        "notes": [],
    }
    try:
        if follow_redirects and max_redirect_hops > 0:
            chain, final_redirect = _follow_redirect_chain(
                target, port, use_https, timeout, path, max_redirect_hops
            )
            if chain:
                last = chain[-1]
                out["status"] = last.get("status")
                out["headers"] = last.get("headers", {})
                out["redirect_chain"] = [
                    {"url": c["url"], "status": c["status"], "header_count": len(c.get("headers", {}))}
                    for c in chain
                ]
                out["redirect_url"] = final_redirect
        else:
            base_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:122.0) Gecko/20100101 Firefox/122.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            }
            try:
                from evasion.http_header_rotation import get_rotated_headers
                base_headers = get_rotated_headers(profile="mixed")
            except ImportError:
                pass
            req = Request(url, method="GET", headers=base_headers)
            with urlopen(req, timeout=timeout) as resp:
                out["status"] = resp.status
                out["headers"] = _extract_headers(resp)
                loc = resp.headers.get("Location") or resp.headers.get("location")
                if loc:
                    out["redirect_url"] = loc
    except HTTPError as e:
        out["status"] = e.code
        if e.headers:
            out["headers"] = _extract_headers(e)
    except URLError as e:
        out["notes"].append(str(e.reason) if hasattr(e, "reason") else str(e))
    except Exception as e:
        out["notes"].append(str(e))
        logger.debug("HTTP security probe: %s", e)

    hsts = out.get("headers", {}).get("strict-transport-security", "")
    if hsts and "preload" in hsts.lower():
        out["hsts_preload"] = True
    for hint in ("x-amz-cf-id", "cf-ray", "x-served-by", "x-cache"):
        if out.get("headers", {}).get(hint):
            out["infra_hints"].append(f"{hint}: present")

    if out.get("headers"):
        try:
            from recon.domain_fronting_detect import analyze_fronting_hints
            out["fronting_analysis"] = analyze_fronting_hints(out["headers"])
        except ImportError:
            pass
        out["security_grade"] = grade_http_security_headers(out["headers"])
    return out


def grade_http_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Evaluate HTTP security headers against OWASP guidelines and return
    a compliance score (0-100), letter grade (A+ through F), and specific findings.
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    score = 0
    max_score = 100
    missing = []
    present = []
    warnings = []

    # 1. HSTS (20 pts)
    hsts = normalized.get("strict-transport-security")
    if hsts:
        score += 20
        present.append("Strict-Transport-Security")
        if "preload" in hsts.lower():
            score += 5
    else:
        missing.append("Strict-Transport-Security (HSTS)")

    # 2. CSP (25 pts)
    csp = normalized.get("content-security-policy")
    if csp:
        score += 25
        present.append("Content-Security-Policy")
    else:
        missing.append("Content-Security-Policy (CSP)")

    # 3. X-Frame-Options (15 pts)
    xfo = normalized.get("x-frame-options")
    if xfo:
        score += 15
        present.append("X-Frame-Options")
    else:
        missing.append("X-Frame-Options (Clickjacking defense)")

    # 4. X-Content-Type-Options (15 pts)
    xcto = normalized.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        score += 15
        present.append("X-Content-Type-Options")
    else:
        missing.append("X-Content-Type-Options: nosniff (MIME sniffing defense)")

    # 5. Referrer-Policy (15 pts)
    ref = normalized.get("referrer-policy")
    if ref:
        score += 15
        present.append("Referrer-Policy")
    else:
        missing.append("Referrer-Policy")

    # 6. Permissions-Policy (10 pts)
    perm = normalized.get("permissions-policy")
    if perm:
        score += 10
        present.append("Permissions-Policy")
    else:
        missing.append("Permissions-Policy (Browser feature restrictions)")

    # Information leakage penalties
    if "x-powered-by" in normalized:
        score = max(0, score - 10)
        warnings.append(f"Information disclosure: X-Powered-By header revealed ({normalized['x-powered-by']})")
    if "server" in normalized and any(c.isdigit() for c in normalized["server"]):
        score = max(0, score - 5)
        warnings.append(f"Server header exposes exact software version ({normalized['server']})")

    # Clamp score to 0..100
    score = min(100, max(0, score))

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "present_headers": present,
        "missing_headers": missing,
        "warnings": warnings,
    }
