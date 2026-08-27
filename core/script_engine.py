"""
USARE Script Engine — NSE-equivalent dynamic script loader.

Discovers and executes Python scripts from the scripts/ directory against
open ports discovered during the scan.  Each script follows a standard
interface:

    DESCRIPTION: str
    CATEGORIES:  list[str]          # e.g. ["discovery", "safe"]
    def run(target_ip, port_data, script_args={}) -> dict

The engine loads every .py file in scripts/, matches each script to the
relevant open ports, and runs them with a configurable timeout.
"""

import os
import sys
import time
import importlib
import importlib.util
import logging
import concurrent.futures
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("usare.script_engine")

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
)


@dataclass
class ScriptInfo:
    """Metadata about a loaded script."""
    name: str
    path: str
    description: str = ""
    categories: List[str] = field(default_factory=list)
    module: Any = None  # the imported module


@dataclass
class ScriptResult:
    """Result from running a single script."""
    script_name: str
    success: bool
    output: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "script": self.script_name,
            "success": self.success,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }
        if self.output:
            d["output"] = self.output
        if self.error:
            d["error"] = self.error
        return d


class ScriptEngine:
    """Lightweight NSE-equivalent engine for USARE."""

    def __init__(
        self,
        scripts_dir: str = SCRIPTS_DIR,
        timeout: float = 30.0,
        max_workers: int = 4,
    ):
        self.scripts_dir = scripts_dir
        self.timeout = timeout
        self.max_workers = max_workers
        self._scripts: List[ScriptInfo] = []

    # ── Discovery ──────────────────────────────────────────────────────
    def discover(self) -> List[ScriptInfo]:
        """Scan scripts/ directory and load every .py file."""
        self._scripts = []
        if not os.path.isdir(self.scripts_dir):
            logger.warning(f"Scripts directory not found: {self.scripts_dir}")
            return self._scripts

        for fname in sorted(os.listdir(self.scripts_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            fpath = os.path.join(self.scripts_dir, fname)
            try:
                spec = importlib.util.spec_from_file_location(
                    f"usare_script.{fname[:-3]}", fpath,
                )
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                info = ScriptInfo(
                    name=fname[:-3],  # strip .py
                    path=fpath,
                    description=getattr(mod, "DESCRIPTION", ""),
                    categories=getattr(mod, "CATEGORIES", []),
                    module=mod,
                )

                # Sanity check: script must expose a run() callable
                if not callable(getattr(mod, "run", None)):
                    logger.warning(f"Script {fname} has no run() — skipping")
                    continue

                self._scripts.append(info)
            except Exception as exc:
                logger.warning(f"Failed to load script {fname}: {exc}")
        return self._scripts

    @property
    def loaded_scripts(self) -> List[ScriptInfo]:
        return list(self._scripts)

    # ── Execution ──────────────────────────────────────────────────────
    def run_all(
        self,
        target_ip: str,
        open_ports: List[Dict[str, Any]],
        script_args: Optional[Dict[str, str]] = None,
    ) -> List[ScriptResult]:
        """Run every loaded script against the target.

        Args:
            target_ip:  Target IP or hostname.
            open_ports: List of dicts with at least {"port": int, "service": str}.
            script_args: Parsed --script-args key=value pairs.

        Returns:
            List of ScriptResult objects.
        """
        if not self._scripts:
            self.discover()

        args = script_args or {}
        results: List[ScriptResult] = []

        # Run scripts in parallel (each script gets wrapped in a timeout)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
        ) as pool:
            futures = {}
            for script in self._scripts:
                fut = pool.submit(
                    self._run_one, script, target_ip, open_ports, args,
                )
                futures[fut] = script

            for fut in concurrent.futures.as_completed(futures):
                script = futures[fut]
                try:
                    result = fut.result(timeout=self.timeout)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    results.append(ScriptResult(
                        script_name=script.name,
                        success=False,
                        error=f"Timeout after {self.timeout}s",
                    ))
                except Exception as exc:
                    results.append(ScriptResult(
                        script_name=script.name,
                        success=False,
                        error=str(exc),
                    ))

        return results

    def _run_one(
        self,
        script: ScriptInfo,
        target_ip: str,
        open_ports: List[Dict[str, Any]],
        script_args: Dict[str, str],
    ) -> ScriptResult:
        """Execute a single script with timing."""
        t0 = time.time()
        try:
            output = script.module.run(target_ip, open_ports, script_args)
            elapsed = (time.time() - t0) * 1000
            return ScriptResult(
                script_name=script.name,
                success=True,
                output=output if isinstance(output, dict) else {"raw": output},
                elapsed_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.time() - t0) * 1000
            return ScriptResult(
                script_name=script.name,
                success=False,
                elapsed_ms=elapsed,
                error=str(exc),
            )

    # ── Helpers ────────────────────────────────────────────────────────
    @staticmethod
    def parse_script_args(raw: Optional[str]) -> Dict[str, str]:
        """Parse 'key=val,key2=val2' format from --script-args."""
        if not raw:
            return {}
        out: Dict[str, str] = {}
        for pair in raw.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                out[k.strip()] = v.strip()
        return out
