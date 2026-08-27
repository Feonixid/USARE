"""
USARE TLS CAA Record Checker

DNS CAA (Certification Authority Authorization, RFC 8659) records declare
which CAs are authorised to issue certificates for a domain.

A mismatch between CAA policy and what's actually in use is a real finding:
  - If CAA restricts issuance to "letsencrypt.org" but the cert was issued
    by DigiCert, someone bypassed CAA controls or records are misconfigured.
  - Missing CAA records allow any CA to issue — no issuance control at all.
  - Incorrect issuance in CT logs + mismatched CAA = certificate misdirection
    or a compromised CA trust chain.

Requires: dnspython (pip install dnspython) for reliable DNS resolution.
Falls back to raw socket DNS if dnspython unavailable.
"""

import ssl
import socket
import logging
import struct
import random
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple

logger = logging.getLogger("usare.tls_caa")

try:
    import dns.resolver          # type: ignore
    import dns.name              # type: ignore
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# Known CA tag→organisation mappings for display
CA_DISPLAY: Dict[str, str] = {
    "letsencrypt.org":      "Let's Encrypt",
    "pki.goog":             "Google Trust Services",
    "digicert.com":         "DigiCert",
    "comodoca.com":         "Comodo/Sectigo",
    "sectigo.com":          "Sectigo",
    "usertrust.com":        "Comodo/Sectigo (UserTrust)",
    "globalsign.com":       "GlobalSign",
    "godaddy.com":          "GoDaddy",
    "entrust.net":          "Entrust",
    "geotrust.com":         "GeoTrust",
    "thawte.com":           "Thawte",
    "verisign.com":         "VeriSign (legacy)",
    "certum.pl":            "Certum",
    "buypass.com":          "Buypass",
    "ssl.com":              "SSL.com",
    "amazon.com":           "Amazon Trust Services",
    "microsoft.com":        "Microsoft (Azure)",
    "apple.com":            "Apple",
    "zerossl.com":          "ZeroSSL",
    "actalis.it":           "Actalis",
}


@dataclass
class CAARecord:
    tag: str        # "issue", "issuewild", "iodef"
    value: str      # CA domain or iodef URI
    flags: int = 0

    def ca_display(self) -> str:
        for key, name in CA_DISPLAY.items():
            if key in self.value.lower():
                return name
        return self.value


@dataclass
class CertIssuer:
    """Issuer extracted from the live TLS certificate."""
    common_name: str = ""
    organization: str = ""
    raw_issuer: str = ""


@dataclass
class CAARecheckResult:
    domain: str
    has_caa: bool = False
    caa_records: List[CAARecord] = field(default_factory=list)
    cert_issuer: Optional[CertIssuer] = None
    issuer_authorised: bool = True    # True = issuer matches CAA, False = MISMATCH
    no_caa_risk: bool = False         # True = no CAA records (any CA can issue)
    findings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "has_caa": self.has_caa,
            "caa_records": [
                {"tag": r.tag, "value": r.value, "flags": r.flags}
                for r in self.caa_records
            ],
            "cert_issuer": {
                "cn": self.cert_issuer.common_name,
                "org": self.cert_issuer.organization,
            } if self.cert_issuer else None,
            "issuer_authorised": self.issuer_authorised,
            "no_caa_risk": self.no_caa_risk,
            "findings": self.findings,
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# CAA DNS lookup
# ─────────────────────────────────────────────────────────────────────────────

def _query_caa_dnspython(domain: str) -> List[CAARecord]:
    records: List[CAARecord] = []
    try:
        # Walk up the DNS tree: domain → parent → grandparent
        names_to_try = []
        parts = domain.rstrip(".").split(".")
        for i in range(len(parts)):
            names_to_try.append(".".join(parts[i:]))

        for name in names_to_try:
            try:
                answers = dns.resolver.resolve(name, "CAA", raise_on_no_answer=True)
                for rr in answers:
                    tag   = rr.tag.decode("ascii", errors="ignore").lower()
                    value = rr.value.decode("ascii", errors="ignore").strip('"')
                    records.append(CAARecord(tag=tag, value=value, flags=rr.flags))
                if records:
                    break   # found at this level, stop walking up
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
    except Exception as e:
        logger.debug("[caa] dnspython query error: %s", e)
    return records


def _query_caa_raw(domain: str, nameserver: str = "8.8.8.8") -> List[CAARecord]:
    """
    Minimal raw DNS query for CAA records (QTYPE=257) without dnspython.
    """
    records: List[CAARecord] = []
    try:
        txid = random.randint(1, 65535)
        # Build DNS query packet
        header  = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        # Encode domain name
        labels = b""
        for part in domain.rstrip(".").split("."):
            labels += bytes([len(part)]) + part.encode()
        labels += b"\x00"
        question = labels + struct.pack(">HH", 257, 1)  # QTYPE=CAA, QCLASS=IN
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(packet, (nameserver, 53))
        resp, _ = sock.recvfrom(512)
        sock.close()

        if len(resp) < 12:
            return records

        # Parse answer count
        ancount = struct.unpack(">H", resp[6:8])[0]
        if ancount == 0:
            return records

        # Skip question section
        idx = 12
        while idx < len(resp) and resp[idx] != 0:
            idx += resp[idx] + 1
        idx += 5  # skip null label + QTYPE + QCLASS

        # Parse answer RRs
        for _ in range(ancount):
            if idx + 10 > len(resp):
                break
            # Skip name (might be a pointer)
            if resp[idx] == 0xC0:
                idx += 2
            else:
                while idx < len(resp) and resp[idx] != 0:
                    idx += resp[idx] + 1
                idx += 1
            if idx + 10 > len(resp):
                break
            rtype, rclass, _, rdlen = struct.unpack(">HHIH", resp[idx:idx+10])
            idx += 10
            if rtype == 257 and rdlen >= 2:  # CAA
                rdata = resp[idx:idx+rdlen]
                flags   = rdata[0]
                tag_len = rdata[1]
                tag     = rdata[2:2+tag_len].decode("ascii", errors="ignore").lower()
                value   = rdata[2+tag_len:rdlen].decode("ascii", errors="ignore").strip('"')
                records.append(CAARecord(tag=tag, value=value, flags=flags))
            idx += rdlen

    except Exception as e:
        logger.debug("[caa] raw DNS query error: %s", e)
    return records


def query_caa(domain: str) -> List[CAARecord]:
    """Query CAA records for a domain, using dnspython if available."""
    if HAS_DNSPYTHON:
        return _query_caa_dnspython(domain)
    return _query_caa_raw(domain)


# ─────────────────────────────────────────────────────────────────────────────
# Cert issuer extraction
# ─────────────────────────────────────────────────────────────────────────────

def get_cert_issuer(host: str, port: int = 443, timeout: float = 5.0) -> Optional[CertIssuer]:
    """Extract the issuing CA from the live TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                issuer: Dict[str, str] = {}
                for rdn in cert.get("issuer", []):
                    for attr_type, attr_value in rdn:
                        issuer[attr_type] = attr_value
                return CertIssuer(
                    common_name=issuer.get("commonName", ""),
                    organization=issuer.get("organizationName", ""),
                    raw_issuer=str(cert.get("issuer", "")),
                )
    except Exception as e:
        logger.debug("[caa] cert fetch error %s:%d: %s", host, port, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Mismatch analysis
# ─────────────────────────────────────────────────────────────────────────────

def _issuer_matches_caa(issuer: CertIssuer, caa_records: List[CAARecord]) -> Tuple[bool, str]:
    """
    Check whether the certificate's issuer is authorised by CAA.
    Returns (is_authorised, explanation).
    """
    issue_records = [r for r in caa_records if r.tag in ("issue", "issuewild")]
    if not issue_records:
        return True, "No CAA issue records (any CA permitted)"

    # Extract issuer domain tokens to match against CAA values
    issuer_tokens = set()
    for field_val in [issuer.common_name.lower(), issuer.organization.lower()]:
        # Pull the root domain from the CA's CN (e.g. "R3" from Let's Encrypt → "letsencrypt.org")
        for known_key in CA_DISPLAY:
            if known_key in field_val:
                issuer_tokens.add(known_key)
        issuer_tokens.add(field_val)

    for rec in issue_records:
        caa_val = rec.value.lower().strip(";").split(";")[0].strip()
        if not caa_val or caa_val == "":
            # Semicolon-only = explicitly deny all issuance
            continue
        for token in issuer_tokens:
            if token and (token in caa_val or caa_val in token):
                return True, f"Issuer matches CAA: {rec.value}"

    authorised_cas = [r.value for r in issue_records]
    return False, (
        f"Issuer '{issuer.common_name}' NOT in CAA-authorised list: "
        + ", ".join(authorised_cas)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main check
# ─────────────────────────────────────────────────────────────────────────────

def check_caa(
    domain: str,
    tls_port: int = 443,
    timeout: float = 5.0,
) -> CAARecheckResult:
    """
    Full CAA check pipeline:
      1. Query DNS CAA records for the domain
      2. Fetch the live TLS certificate issuer
      3. Compare — report mismatches as findings
    """
    result = CAARecheckResult(domain=domain)

    # Step 1: CAA DNS records
    caa_recs = query_caa(domain)
    result.caa_records = caa_recs
    result.has_caa = bool(caa_recs)

    if not caa_recs:
        result.no_caa_risk = True
        result.findings.append(
            "No CAA records — any CA may issue certificates for this domain. "
            "Recommended: add CAA records to restrict issuance."
        )

    iodef = [r for r in caa_recs if r.tag == "iodef"]
    if iodef:
        result.notes.append(f"Violation reporting (iodef): {iodef[0].value}")

    # Step 2: Live cert issuer
    issuer = get_cert_issuer(domain, tls_port, timeout)
    result.cert_issuer = issuer

    if issuer is None:
        result.notes.append(f"Could not fetch TLS cert from {domain}:{tls_port}")
        return result

    result.notes.append(
        f"Live cert issuer: {issuer.common_name or issuer.organization}"
    )

    # Step 3: Mismatch check
    if caa_recs:
        authorised, explanation = _issuer_matches_caa(issuer, caa_recs)
        result.issuer_authorised = authorised
        if not authorised:
            result.findings.append(
                f"CAA MISMATCH: {explanation}. "
                "Possible causes: misrouted issuance, stale CAA records, "
                "or certificate obtained before CAA was set."
            )
        else:
            result.notes.append(f"CAA OK: {explanation}")

    return result
