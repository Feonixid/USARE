"""
USARE Ollama AI Inference Backend

Connects to a local Ollama instance to provide real LLM-powered
evasion strategy generation. Ingests all gathered intelligence
(Shodan, Censys, BGP, WHOIS, scan results, crypto fingerprints)
and outputs ranked evasion strategies with confidence scores.

Falls back to heuristic mode if Ollama is unavailable.
"""

import json
import socket
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("usare.ollama_backend")


@dataclass
class AIEvasionStrategy:
    """A single AI-generated evasion strategy."""
    technique: str
    priority: int          # 1 = highest
    confidence: float      # 0.0-1.0
    reasoning: str
    expected_success: float
    detection_risk: float  # 0.0 = invisible, 1.0 = certain detection

    def to_dict(self) -> Dict:
        return {
            "technique": self.technique,
            "priority": self.priority,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "expected_success": round(self.expected_success, 3),
            "detection_risk": round(self.detection_risk, 3),
        }


@dataclass
class AIInferenceResult:
    """Complete AI inference output."""
    strategies: List[AIEvasionStrategy] = field(default_factory=list)
    target_assessment: str = ""
    security_posture: str = "unknown"
    recommended_profile: str = "ghost"  # ghost/phantom/shadow
    model_used: str = ""
    inference_time_ms: float = 0.0
    fallback_used: bool = False

    def to_dict(self) -> Dict:
        return {
            "strategies": [s.to_dict() for s in self.strategies],
            "target_assessment": self.target_assessment,
            "security_posture": self.security_posture,
            "recommended_profile": self.recommended_profile,
            "model_used": self.model_used,
            "inference_time_ms": round(self.inference_time_ms, 1),
            "fallback_used": self.fallback_used,
        }


# System prompt template for the LLM
SYSTEM_PROMPT = """You are a network security analyst specializing in evasion technique selection.

Given intelligence about a target, you must output a JSON object with:
- "assessment": 1-2 sentence target assessment
- "security_posture": one of "low", "medium", "high", "enterprise"
- "timing_profile": one of "ghost", "phantom", "shadow"
- "strategies": array of objects with:
  - "technique": name of the USARE evasion technique
  - "priority": 1 (highest) to 10 (lowest)
  - "confidence": 0.0 to 1.0
  - "reasoning": why this technique fits
  - "expected_success": 0.0 to 1.0
  - "detection_risk": 0.0 to 1.0

Available USARE techniques:
- ghost_timing: Gaussian jitter timing with ML-adaptive delays
- https_tunnel: Probes inside TLS 1.3 connections
- doh_tunnel: DNS-over-HTTPS through Cloudflare/Google resolvers
- quic_tunnel: QUIC/H3 encapsulation on UDP/443
- dns_tunnel: DNS subdomain encoding
- icmp_tunnel: Probes inside ICMP echo
- flow_morph: Statistical traffic morphing (chrome/firefox/winupdate profiles)
- ttl_masquerade: TTL hop-count camouflage
- ja3_rotation: JA3 fingerprint randomization
- entropy_balance: Payload entropy normalization
- sni_smuggle: SNI mismatch / domain fronting
- fragment_overlap: Overlapping TCP fragments for IDS confusion
- multi_path: Traffic dispersion across multiple source IPs
- decoy_swarm: Decoy packet flooding
- idle_scan: Zero-attribution via zombie hosts
- ipv6_tunnel: IPv4-in-IPv6 encapsulation

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


class OllamaBackend:
    """
    LLM inference backend using a local Ollama instance.
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 11434
    PREFERRED_MODELS = [
        "deepseek-r1:8b",
        "llama3.1:8b",
        "llama3:8b", 
        "mistral:7b",
        "qwen2.5:7b",
        "phi3:mini",
        "gemma2:9b",
    ]

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 model: Optional[str] = None, timeout: float = 180.0):
        self.host = host
        self.port = port
        self.model = model
        self.timeout = timeout
        self._available = False
        self._available_models: List[str] = []

    def check_availability(self) -> bool:
        """Check if Ollama is running and accessible."""
        try:
            resp = self._http_request("GET", "/api/tags")
            if resp:
                data = json.loads(resp)
                self._available_models = [
                    m["name"] for m in data.get("models", [])
                ]
                self._available = True

                # Auto-select best model if not specified
                if not self.model:
                    self.model = self._select_best_model()

                logger.info(
                    f"[Ollama] Connected. Models: {len(self._available_models)}, "
                    f"Selected: {self.model}"
                )
                return True
        except Exception as e:
            logger.debug(f"[Ollama] Not available: {e}")

        self._available = False
        return False

    def _select_best_model(self) -> Optional[str]:
        """Select the best available model from preferences."""
        for preferred in self.PREFERRED_MODELS:
            for available in self._available_models:
                if preferred.split(":")[0] in available:
                    return available
        # Fall back to first available
        return self._available_models[0] if self._available_models else None

    def infer_evasion_strategy(self, intel: Dict[str, Any]) -> AIInferenceResult:
        """
        Run LLM inference to generate evasion strategies.

        Args:
            intel: Dict containing all gathered intelligence about the target.
                   Can include: shodan_info, censys_info, bgp_info, whois_info,
                   scan_results, crypto_fingerprint, acl_map, os_fingerprint, etc.
        """
        result = AIInferenceResult()
        start = time.time()

        if not self._available or not self.model:
            if not self.check_availability():
                logger.info("[Ollama] Unavailable, using heuristic fallback")
                return self._heuristic_fallback(intel)

        # Build the prompt with sanitized intel
        user_prompt = self._build_prompt(intel)

        try:
            response = self._generate(user_prompt)
            if response:
                result = self._parse_response(response)
                result.model_used = self.model or "unknown"
                result.inference_time_ms = (time.time() - start) * 1000
                return result
        except Exception as e:
            logger.warning(f"[Ollama] Inference failed: {e}")

        # Fallback
        result = self._heuristic_fallback(intel)
        result.inference_time_ms = (time.time() - start) * 1000
        return result

    def _build_prompt(self, intel: Dict[str, Any]) -> str:
        """Build a structured prompt from intelligence data."""
        sections = []

        # Target basics
        target = intel.get("target", "unknown")
        sections.append(f"TARGET: {target}")

        # OS info
        os_fp = intel.get("os_fingerprint", {})
        if os_fp:
            sections.append(f"OS: {os_fp.get('os_guess', 'unknown')} "
                          f"(confidence: {os_fp.get('confidence', 0):.0%})")

        # Open ports
        scan = intel.get("scan_results", [])
        if isinstance(scan, list) and scan:
            open_ports = []
            for r in scan[:20]:
                if hasattr(r, "state") and getattr(r.state, "value", None) == "open":
                    open_ports.append(str(r.port))
                elif isinstance(r, dict) and r.get("state") == "open":
                    open_ports.append(str(r.get("port", "")))
            if open_ports:
                sections.append(f"OPEN PORTS: {', '.join(open_ports[:20])}")
        
        # Deception Detection
        deception = intel.get("deception", {})
        if deception:
            if deception.get("is_honeypot"):
                sections.append(f"DECEPTION: Honeypot detected (Confidence: {deception.get('confidence', 0):.0%})")
                if deception.get("reasoning"):
                    sections.append(f"REASONING: {deception['reasoning']}")

        # WAF/CDN
        waf = intel.get("waf_detection", {})
        if waf:
            sections.append(f"WAF: {json.dumps(waf, default=str)[:200]}")

        # ACL mapping
        acl = intel.get("acl_map", {})
        if acl:
            sections.append(f"FIREWALL: {acl.get('firewall_summary', 'unknown')}")

        # Crypto fingerprints
        crypto = intel.get("crypto_fingerprint", {})
        if crypto:
            ssh_info = crypto.get("ssh", {})
            tls_info = crypto.get("tls", {})
            if ssh_info:
                for port, fp in list(ssh_info.items())[:3]:
                    sections.append(
                        f"SSH/{port}: {fp.get('implementation', 'unknown')} "
                        f"({fp.get('confidence', 0):.0%})"
                    )
            if tls_info:
                for port, fp in list(tls_info.items())[:3]:
                    sections.append(
                        f"TLS/{port}: {fp.get('tls_version', '')} "
                        f"{fp.get('cipher', '')} → {fp.get('server_impl', 'unknown')}"
                    )

        # Correlation
        corr = intel.get("correlation", {})
        if corr:
            sections.append(f"CORRELATED OS: {corr.get('best_os', 'unknown')} "
                          f"({corr.get('best_os_confidence', 0):.0%})")
            if corr.get("anomalies"):
                sections.append(f"ANOMALIES: {'; '.join(corr['anomalies'][:3])}")

        # WHOIS / BGP
        whois = intel.get("whois_info", {})
        if whois:
            org = whois.get("organization", whois.get("org", ""))
            if org:
                sections.append(f"ORG: {org}")

        # Heat level
        heat = intel.get("heat_level")
        if heat is not None:
            sections.append(f"CURRENT HEAT: {heat}")

        return "\n".join(sections)

    def _generate(self, prompt: str) -> Optional[str]:
        """Call Ollama generate API."""
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 1024,
            }
        })

        resp = self._http_request("POST", "/api/generate", payload)
        if resp:
            data = json.loads(resp)
            return data.get("response", "")
        return None

    def _parse_response(self, response: str) -> AIInferenceResult:
        """Parse LLM JSON response into structured result."""
        result = AIInferenceResult()

        # Extract JSON from response (handle markdown wrapping)
        json_str = response.strip()
        if "```" in json_str:
            start = json_str.find("{")
            end = json_str.rfind("}") + 1
            json_str = json_str[start:end]
        elif json_str.startswith("{"):
            pass
        else:
            start = json_str.find("{")
            if start >= 0:
                end = json_str.rfind("}") + 1
                json_str = json_str[start:end]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("[Ollama] Failed to parse LLM response as JSON")
            result.fallback_used = True
            return result

        result.target_assessment = data.get("assessment", "")
        result.security_posture = data.get("security_posture", "unknown")
        result.recommended_profile = data.get("timing_profile", "ghost")

        for s in data.get("strategies", []):
            result.strategies.append(AIEvasionStrategy(
                technique=s.get("technique", ""),
                priority=s.get("priority", 10),
                confidence=float(s.get("confidence", 0.5)),
                reasoning=s.get("reasoning", ""),
                expected_success=float(s.get("expected_success", 0.5)),
                detection_risk=float(s.get("detection_risk", 0.5)),
            ))

        # Sort by priority
        result.strategies.sort(key=lambda s: s.priority)

        return result

    def _http_request(self, method: str, path: str,
                      body: Optional[str] = None) -> Optional[str]:
        """Send raw HTTP request to Ollama."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            if method == "GET":
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.host}:{self.port}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
            else:
                body_bytes = (body or "").encode()
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {self.host}:{self.port}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + body_bytes

            sock.sendall(request)

            # Read response
            response = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk

            sock.close()

            # Extract body
            body_start = response.find(b"\r\n\r\n")
            if body_start >= 0:
                headers = response[:body_start].lower()
                body = response[body_start + 4:]
                
                if b"transfer-encoding: chunked" in headers:
                    processed_bytes = bytearray()
                    idx = 0
                    while idx < len(body):
                        end_hex = body.find(b"\r\n", idx)
                        if end_hex == -1:
                            break
                        hex_str = body[idx:end_hex].split(b";")[0].strip()
                        try:
                            chunk_size = int(hex_str, 16)
                        except ValueError:
                            break
                        if chunk_size == 0:
                            break
                        chunk_start = end_hex + 2
                        processed_bytes.extend(body[chunk_start:chunk_start+chunk_size])
                        idx = chunk_start + chunk_size + 2
                    return processed_bytes.decode("utf-8", errors="replace")
                
                return body.decode("utf-8", errors="replace")
                
            return response.decode("utf-8", errors="replace")

        except Exception as e:
            logger.debug(f"[Ollama] HTTP request failed: {e}")
            return None

    def _heuristic_fallback(self, intel: Dict[str, Any]) -> AIInferenceResult:
        """Rule-based fallback when Ollama is unavailable."""
        result = AIInferenceResult(fallback_used=True, model_used="heuristic")

        # Determine security posture from available data
        acl = intel.get("acl_map", {})
        waf = intel.get("waf_detection", {})
        corr = intel.get("correlation", {})

        has_waf = bool(waf)
        has_stateful_fw = "stateful" in str(acl.get("firewall_summary", "")).lower()
        anomalies = corr.get("anomalies", [])

        if has_waf and has_stateful_fw:
            result.security_posture = "enterprise"
            result.recommended_profile = "ghost"
        elif has_waf or has_stateful_fw:
            result.security_posture = "high"
            result.recommended_profile = "phantom"
        else:
            result.security_posture = "medium"
            result.recommended_profile = "shadow"

        # Generate strategies based on posture
        strategies = []

        # Always recommend timing
        strategies.append(AIEvasionStrategy(
            technique="ghost_timing", priority=1, confidence=0.9,
            reasoning="Adaptive timing is always beneficial",
            expected_success=0.85, detection_risk=0.1,
        ))

        if has_waf:
            strategies.append(AIEvasionStrategy(
                technique="doh_tunnel", priority=2, confidence=0.8,
                reasoning="WAF detected — DoH bypasses L7 inspection",
                expected_success=0.75, detection_risk=0.15,
            ))
            strategies.append(AIEvasionStrategy(
                technique="sni_smuggle", priority=3, confidence=0.7,
                reasoning="WAF may rely on SNI for routing decisions",
                expected_success=0.65, detection_risk=0.25,
            ))

        if has_stateful_fw:
            strategies.append(AIEvasionStrategy(
                technique="fragment_overlap", priority=2, confidence=0.75,
                reasoning="Stateful firewall — overlapping fragments confuse reassembly",
                expected_success=0.70, detection_risk=0.20,
            ))

        strategies.append(AIEvasionStrategy(
            technique="ja3_rotation", priority=4, confidence=0.85,
            reasoning="JA3 rotation prevents fingerprint-based blocking",
            expected_success=0.80, detection_risk=0.05,
        ))

        strategies.append(AIEvasionStrategy(
            technique="flow_morph", priority=5, confidence=0.75,
            reasoning="Traffic morphing blends with legitimate patterns",
            expected_success=0.70, detection_risk=0.10,
        ))

        if any("honeypot" in a.lower() for a in anomalies):
            strategies.append(AIEvasionStrategy(
                technique="idle_scan", priority=1, confidence=0.90,
                reasoning="Possible honeypot detected — zero-attribution critical",
                expected_success=0.60, detection_risk=0.05,
            ))

        strategies.sort(key=lambda s: s.priority)
        result.strategies = strategies
        result.target_assessment = (
            f"Security posture: {result.security_posture}. "
            f"{'WAF present. ' if has_waf else ''}"
            f"{'Stateful firewall. ' if has_stateful_fw else ''}"
            f"Recommended profile: {result.recommended_profile}."
        )

        return result

    @property
    def available_models(self) -> List[str]:
        return self._available_models

    @property
    def is_available(self) -> bool:
        return self._available
