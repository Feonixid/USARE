"""
USARE Persistent Scan Database — SQLite storage for scan history.

Stores every scan result so you can:
  - Query historical scans per target
  - Auto-diff against the last scan of the same target
  - Track port state changes over time
  - Export filtered result sets
"""

import os
import json
import time
import sqlite3
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("usare.scan_db")

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "usare_scans.db",
)


class ScanDB:
    """SQLite persistent scan database."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        c = self._conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp REAL NOT NULL,
                profile TEXT,
                total_ports INTEGER DEFAULT 0,
                open_ports INTEGER DEFAULT 0,
                closed_ports INTEGER DEFAULT 0,
                filtered_ports INTEGER DEFAULT 0,
                elapsed_s REAL DEFAULT 0,
                flags TEXT DEFAULT '',
                data_json TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS port_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                state TEXT NOT NULL,
                service TEXT,
                banner TEXT,
                latency_ms REAL,
                confidence REAL DEFAULT 0,
                reason TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ports_scan ON port_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_ports_port ON port_results(port);
        """)
        self._conn.commit()

    def save_scan(
        self,
        target: str,
        results: list,
        profile: str = "ghost",
        elapsed_s: float = 0.0,
        flags: str = "",
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Save a complete scan to the database. Returns scan_id."""
        open_count = sum(1 for r in results if getattr(r, "state", None) and r.state.value == "open")
        closed_count = sum(1 for r in results if getattr(r, "state", None) and r.state.value == "closed")
        filtered_count = sum(1 for r in results if getattr(r, "state", None) and r.state.value == "filtered")

        c = self._conn.cursor()
        c.execute(
            """INSERT INTO scans (target, timestamp, profile, total_ports,
               open_ports, closed_ports, filtered_ports, elapsed_s, flags, data_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target,
                time.time(),
                profile,
                len(results),
                open_count,
                closed_count,
                filtered_count,
                elapsed_s,
                flags,
                json.dumps(extra_data or {}, default=str),
            ),
        )
        scan_id = c.lastrowid

        for r in results:
            state_val = r.state.value if hasattr(r.state, "value") else str(r.state)
            reason = _build_reason(r)
            c.execute(
                """INSERT INTO port_results
                   (scan_id, port, protocol, state, service, banner, latency_ms, confidence, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    r.port,
                    getattr(r, "protocol", "tcp"),
                    state_val,
                    getattr(r, "service_guess", None),
                    getattr(r, "banner", None),
                    getattr(r, "latency_ms", None),
                    getattr(r, "confidence", 0.0),
                    reason,
                ),
            )

        self._conn.commit()
        logger.info(f"[ScanDB] Saved scan #{scan_id} for {target} ({len(results)} ports)")
        return scan_id

    def get_last_scan(self, target: str) -> Optional[Dict]:
        """Get the most recent scan for a target."""
        c = self._conn.cursor()
        c.execute(
            "SELECT * FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
            (target,),
        )
        row = c.fetchone()
        if not row:
            return None
        return dict(row)

    def get_scan_ports(self, scan_id: int) -> List[Dict]:
        """Get all port results for a scan."""
        c = self._conn.cursor()
        c.execute("SELECT * FROM port_results WHERE scan_id = ? ORDER BY port", (scan_id,))
        return [dict(r) for r in c.fetchall()]

    def get_scan_history(self, target: str, limit: int = 10) -> List[Dict]:
        """Get scan history for a target."""
        c = self._conn.cursor()
        c.execute(
            "SELECT * FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
            (target, limit),
        )
        return [dict(r) for r in c.fetchall()]

    def query(self, sql: str, params: tuple = ()) -> List[Dict]:
        """Run arbitrary SQL query."""
        c = self._conn.cursor()
        c.execute(sql, params)
        return [dict(r) for r in c.fetchall()]

    def close(self):
        self._conn.close()


def _build_reason(result) -> str:
    """Build human-readable reason string for a port state."""
    state = result.state.value if hasattr(result.state, "value") else str(result.state)
    flags = getattr(result, "raw_flags", None)
    ttl = getattr(result, "ttl_received", None)
    method = getattr(result, "scan_method", "syn")
    retries = getattr(result, "retries", 0)

    if state == "open":
        ttl_str = f" ttl={ttl}" if ttl else ""
        return f"syn-ack{ttl_str}"
    elif state == "closed":
        ttl_str = f" ttl={ttl}" if ttl else ""
        return f"rst{ttl_str}"
    elif state == "filtered":
        if retries > 0:
            return f"no-response ({retries + 1} probes)"
        return "no-response"
    elif state == "open|filtered":
        return f"no-response ({method})"
    elif state == "unfiltered":
        return f"rst (ack-scan)"
    return state
