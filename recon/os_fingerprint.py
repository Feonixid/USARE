import json
import os
import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.os_fingerprint")

@dataclass
class OSFingerprint:
    os_name: str = "Unknown"
    os_family: str = "Unknown"
    os_version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    ttl_initial: Optional[int] = None
    window_size: Optional[int] = None
    df_flag: Optional[bool] = None
    tcp_options_seen: Optional[List[str]] = None
    ip_id_behavior: Optional[str] = None
    wscale_value: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}

def load_os_db() -> List[Dict[str, Any]]:
    db_path = os.path.join(os.path.dirname(__file__), "..", "data", "os_fingerprints.json")
    if not os.path.exists(db_path):
        logger.info("[OS Fingerprint] OS database missing. Attempting auto-conversion...")
        try:
            from recon.nmap_os_db_converter import parse_nmap_os_db
            parse_nmap_os_db()  # no args → writes built-in defaults
        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Auto-conversion failed: {e}")

    try:
        with open(db_path, "r") as f:
            raw_db = json.load(f)
            
        parsed_db = []
        for family, versions in raw_db.items():
            for version, specs in versions.items():
                parsed_db.append({
                    "ttl": (specs["ttl"]-5, specs["ttl"]+5),
                    "windows": [specs["window_size"]],
                    "wscale": [8] if "wscale" in specs.get("tcp_options", []) else [0],
                    "df": specs["df_flag"],
                    "os": f"{family.title()} {version.title()}",
                    "family": family.title(),
                    "version": version.title(),
                    "tcp_options": specs.get("tcp_options", [])
                })
        return parsed_db
    except Exception as e:
        logger.error(f"Failed to load OS fingerprints database: {e}")
        return []

OS_DB = load_os_db()
def _initial_ttl(observed_ttl: int) -> int:
    if observed_ttl <= 32:
        return 32
    elif observed_ttl <= 64:
        return 64
    elif observed_ttl <= 128:
        return 128
    else:
        return 255

def _hop_count(observed_ttl: int) -> int:
    return _initial_ttl(observed_ttl) - observed_ttl

class OSFingerprintEngine:
    def fingerprint_from_response(
        self,
        ttl: int,
        window: int,
        df: bool = True,
        tcp_options: Optional[List[str]] = None,
        ip_id: Optional[int] = None,
        wscale: Optional[int] = None,
    ) -> OSFingerprint:
        initial_ttl = _initial_ttl(ttl)
        result = OSFingerprint(
            ttl_initial=initial_ttl,
            window_size=window,
            df_flag=df,
            tcp_options_seen=tcp_options,
        )
        best_score = 0.0
        best_match = None
        evidence = []
        for entry in OS_DB:
            score = 0.0
            entry_evidence = []
            ttl_low, ttl_high = entry["ttl"]
            if ttl_low <= initial_ttl <= ttl_high:
                score += 0.35
                entry_evidence.append(f"TTL {initial_ttl} matches {entry['os']}")
            if window in entry["windows"]:
                score += 0.35
                entry_evidence.append(f"Window {window} matches {entry['os']}")
            elif any(abs(window - w) < 100 for w in entry["windows"]):
                score += 0.15
                entry_evidence.append(f"Window {window} near {entry['os']}")
            if df == entry["df"]:
                score += 0.15
                entry_evidence.append(f"DF={df} matches {entry['os']}")
            # Enhanced wscale scoring
            if wscale is not None and "wscale" in entry:
                if wscale in entry["wscale"]:
                    score += 0.20  # High weight for wscale match
                    entry_evidence.append(f"WScale {wscale} matches {entry['os']}")
                elif any(abs(wscale - w) <= 1 for w in entry["wscale"]):
                    score += 0.10  # Partial match
                    entry_evidence.append(f"WScale {wscale} near {entry['os']}")
            if tcp_options:
                if "timestamp" in tcp_options or "Timestamp" in tcp_options:  # type: ignore[operator]
                    if entry["family"] in ("Linux", "BSD"):
                        score += 0.10
                        entry_evidence.append("Timestamps present (Linux/BSD typical)")
                elif entry["family"] == "Windows":
                    score += 0.05
                    entry_evidence.append("No timestamps (older Windows typical)")
                if "sackok" in tcp_options or "SAckOK" in tcp_options:  # type: ignore[operator]
                    score += 0.05
            if ip_id is not None:
                if ip_id == 0 and entry["family"] == "Linux":
                    score += 0.10
                    entry_evidence.append("IP ID=0 (Linux DF packets)")
                elif ip_id > 0 and entry["family"] == "Windows":
                    score += 0.05
                    entry_evidence.append("IP ID incremental (Windows)")
            if score > best_score:
                best_score = score
                best_match = entry
                evidence = entry_evidence
        if best_match:
            result.os_name = best_match["os"]  # type: ignore[index]
            result.os_family = best_match["family"]  # type: ignore[index]
            result.os_version = best_match.get("version")  # type: ignore[attr-defined]
            result.confidence = min(1.0, best_score)
            result.evidence = evidence
            result.ip_id_behavior = (
                "zero" if ip_id is not None and ip_id == 0
                else "incremental" if ip_id is not None and ip_id > 0
                else "unknown"
            )
            result.wscale_value = wscale
        return result

    def fingerprint_fuzzy(
        self,
        ttl: int,
        window: int,
        df: bool = True,
        tcp_options=None,
        ip_id=None,
        wscale=None,
        top_n: int = 3,
    ):
        """
        Fuzzy OS matching -- returns top_n candidates even with low confidence.
        Equivalent to Nmap's --osscan-guess mode.

        Returns:
            List of (score, entry) tuples sorted by score descending.
            Always returns results even if confidence is very low.
        """
        initial_ttl = _initial_ttl(ttl)
        scored = []
        for entry in OS_DB:
            score = 0.0
            ttl_low, ttl_high = entry["ttl"]
            if ttl_low <= initial_ttl <= ttl_high:
                score += 0.35
            if window in entry["windows"]:
                score += 0.35
            elif any(abs(window - w) < 100 for w in entry["windows"]):
                score += 0.15
            if df == entry["df"]:
                score += 0.15
            if wscale is not None and "wscale" in entry:
                if wscale in entry["wscale"]:
                    score += 0.20
                elif any(abs(wscale - w) <= 1 for w in entry["wscale"]):
                    score += 0.10
            scored.append((score, entry))
        scored.sort(key=lambda x: -x[0])
        return [
            {
                "os": e["os"],
                "family": e["family"],
                "confidence": round(s, 3),
                "guess": True,
            }
            for s, e in scored[:top_n]
        ]

    def fingerprint_from_tcp_options(
        self,
        options_list: List[Any],
        observed_ttl: int = 64,
        observed_window: int = 64240,
    ) -> Dict[str, Any]:
        """
        Extract structured TCP options (MSS, WScale, SACKOK, Timestamps, NOP padding)
        and match against known TCP stack characteristics to classify OS through firewalls.
        """
        parsed_opts: Dict[str, Any] = {}
        opt_names: List[str] = []
        for item in options_list:
            if isinstance(item, tuple):
                name, val = item
                opt_names.append(str(name))
                parsed_opts[str(name)] = val
            elif isinstance(item, str):
                opt_names.append(item)
                parsed_opts[item] = True

        mss = parsed_opts.get("MSS") or parsed_opts.get("mss")
        wscale = parsed_opts.get("WScale") or parsed_opts.get("wscale")
        has_sack = "SAckOK" in parsed_opts or "sackok" in parsed_opts or "SAck" in parsed_opts
        has_ts = "Timestamp" in parsed_opts or "timestamp" in parsed_opts

        os_candidates: List[Dict[str, Any]] = []
        if wscale == 8 and observed_ttl > 64:
            os_candidates.append({"os": "Windows 10/11 / Windows Server", "confidence": 0.85})
        elif wscale in (7, 8, 9) and observed_ttl <= 64 and has_ts:
            os_candidates.append({"os": "Linux Kernel 5.x / 6.x", "confidence": 0.88})
        elif wscale == 6 and observed_ttl <= 64:
            os_candidates.append({"os": "macOS / iOS / Darwin", "confidence": 0.80})
        elif observed_ttl <= 64:
            os_candidates.append({"os": "Linux/Unix Generic", "confidence": 0.70})
        elif observed_ttl <= 128:
            os_candidates.append({"os": "Windows Generic", "confidence": 0.70})
        else:
            os_candidates.append({"os": "Cisco IOS / Network Appliance", "confidence": 0.65})

        best = os_candidates[0]
        return {
            "parsed_options": parsed_opts,
            "option_sequence": opt_names,
            "mss": mss,
            "wscale": wscale,
            "has_sack": has_sack,
            "has_timestamps": has_ts,
            "best_match": best["os"],
            "confidence": best["confidence"],
            "candidates": os_candidates,
        }


    def fingerprint_from_multiple_responses(
        self,
        responses: List[Dict[str, Any]],
    ) -> OSFingerprint:
        if not responses:
            return OSFingerprint()
        fingerprints = []
        for resp in responses:
            fp = self.fingerprint_from_response(
                ttl=resp.get("ttl", 64),
                window=resp.get("window", 0),
                df=resp.get("df", True),
                tcp_options=resp.get("tcp_options"),
                ip_id=resp.get("ip_id"),
                wscale=resp.get("wscale"),
            )
            fingerprints.append(fp)
        family_votes: Dict[str, float] = {}
        for fp in fingerprints:
            family_votes[fp.os_family] = (
                family_votes.get(fp.os_family, 0.0) + fp.confidence
            )
        if not family_votes:
            return fingerprints[0] if fingerprints else OSFingerprint()
            
        best_family = max(list(family_votes.keys()), key=lambda k: family_votes[k])
        best_fp = max(
            [f for f in fingerprints if f.os_family == best_family],
            key=lambda f: f.confidence,
        )
        vote_count = sum(1 for f in fingerprints if f.os_family == best_family)
        consensus_boost = min(0.15, 0.05 * vote_count)
        best_fp.confidence = min(1.0, best_fp.confidence + consensus_boost)
        best_fp.evidence.append(
            f"Consensus: {vote_count}/{len(fingerprints)} responses agree on {best_family}"
        )
        return best_fp
    @staticmethod
    def estimate_hop_count(observed_ttl: int) -> int:
        return _hop_count(observed_ttl)