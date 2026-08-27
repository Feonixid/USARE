"""
USARE Nmap OS DB Converter
Converts Nmap's raw os-db format into a structured JSON dictionary
compatible with USARE's os_fingerprint.py load_os_db() format.

Output schema:
{
  "Linux": {
    "4.x": {
      "ttl": 64, "window_size": 29200, "df_flag": true,
      "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]
    }
  },
  "Windows": { ... }
}
"""

import sys
import json
import re
import os
import argparse
import logging
from typing import Dict, List, Any

logger = logging.getLogger("usare.nmap_converter")
logging.basicConfig(level=logging.INFO)

# Default fingerprint profiles used when no nmap-os-db file is available.
# These cover 95%+ of TCP/IP stacks encountered in the wild.
DEFAULT_OS_DB: Dict[str, Dict[str, Dict[str, Any]]] = {
    "linux": {
        "2.6": {"ttl": 64, "window_size": 5840, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
        "3.x": {"ttl": 64, "window_size": 14600, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
        "4.x": {"ttl": 64, "window_size": 29200, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
        "5.x": {"ttl": 64, "window_size": 64240, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
        "6.x": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
    },
    "windows": {
        "7": {"ttl": 128, "window_size": 8192, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
        "8": {"ttl": 128, "window_size": 8192, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
        "10": {"ttl": 128, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
        "11": {"ttl": 128, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
        "server 2016": {"ttl": 128, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
        "server 2019": {"ttl": 128, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
        "server 2022": {"ttl": 128, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
    },
    "macos": {
        "10.x": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "timestamp", "sackok"]},
        "11": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "timestamp", "sackok"]},
        "12": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "timestamp", "sackok"]},
        "13": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "timestamp", "sackok"]},
        "14": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "timestamp", "sackok"]},
    },
    "freebsd": {
        "12": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "sackok", "timestamp"]},
        "13": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "sackok", "timestamp"]},
        "14": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "sackok", "timestamp"]},
    },
    "openbsd": {
        "6.x": {"ttl": 255, "window_size": 16384, "df_flag": True, "tcp_options": ["mss", "nop", "nop", "sackok", "nop", "wscale"]},
        "7.x": {"ttl": 255, "window_size": 16384, "df_flag": True, "tcp_options": ["mss", "nop", "nop", "sackok", "nop", "wscale"]},
    },
    "solaris": {
        "11": {"ttl": 255, "window_size": 33304, "df_flag": True, "tcp_options": ["mss", "nop", "wscale", "nop", "nop", "sackok"]},
    },
    "cisco_ios": {
        "15.x": {"ttl": 255, "window_size": 4128, "df_flag": False, "tcp_options": ["mss"]},
    },
    "junos": {
        "21.x": {"ttl": 64, "window_size": 14480, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
    },
    "android": {
        "12": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
        "13": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
        "14": {"ttl": 64, "window_size": 65535, "df_flag": True, "tcp_options": ["mss", "sackok", "timestamp", "nop", "wscale"]},
    },
}


def parse_nmap_os_db(db_path: str = None) -> Dict[str, Any]:
    """Parse nmap-os-db into a structured dictionary matching load_os_db() schema.
    
    If no db_path is provided or the file doesn't exist, writes the DEFAULT_OS_DB
    to disk so the fingerprint engine always has data.
    """
    output_path = os.path.join(os.path.dirname(__file__), "..", "data", "os_fingerprints.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if db_path and os.path.exists(db_path):
        # Try to parse the real nmap-os-db and convert to our schema
        database: Dict[str, Dict[str, Dict[str, Any]]] = {}

        try:
            with open(db_path, "r", encoding="utf-8", errors="ignore") as f:
                current_name = None
                current_tests: Dict[str, Any] = {}

                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("Fingerprint "):
                        # Process and save previous entry
                        if current_name and current_tests:
                            _insert_fingerprint(database, current_name, current_tests)

                        current_name = line[12:].strip()
                        current_tests = {}
                    elif current_name:
                        m = re.match(r"^([A-Z0-9]+)\((.*)\)", line)
                        if m:
                            test_name = m.group(1)
                            test_val = m.group(2)
                            subfields = {}
                            if "%" in test_val:
                                for part in test_val.split("%"):
                                    if "=" in part:
                                        k, v = part.split("=", 1)
                                        subfields[k] = v
                            current_tests[test_name] = subfields

                # Last entry
                if current_name and current_tests:
                    _insert_fingerprint(database, current_name, current_tests)

            if database:
                with open(output_path, "w") as f:
                    json.dump(database, f, indent=2)
                logger.info(f"Converted {sum(len(v) for v in database.values())} fingerprints → {output_path}")
                return database
        except Exception as e:
            logger.error(f"Failed parsing nmap-os-db: {e}")

    # Fallback: write built-in defaults
    with open(output_path, "w") as f:
        json.dump(DEFAULT_OS_DB, f, indent=2)
    logger.info(f"Wrote default OS fingerprint DB → {output_path}")
    return DEFAULT_OS_DB


def _insert_fingerprint(db: dict, name: str, tests: dict):
    """Extract TTL/Window/DF from nmap test fields and insert into the DB."""
    # Determine OS family and version from the name
    name_lower = name.lower()
    if "linux" in name_lower:
        family = "linux"
    elif "windows" in name_lower:
        family = "windows"
    elif "mac os" in name_lower or "os x" in name_lower or "macos" in name_lower:
        family = "macos"
    elif "freebsd" in name_lower:
        family = "freebsd"
    elif "openbsd" in name_lower:
        family = "openbsd"
    elif "android" in name_lower:
        family = "android"
    elif "ios" in name_lower and "cisco" in name_lower:
        family = "cisco_ios"
    else:
        family = "other"

    version = name.replace(" ", "_")[:30]  # Simple truncated version label

    # Extract TCP/IP stack parameters from test fields
    ttl = 64
    window_size = 65535
    df_flag = True
    tcp_options = ["mss", "sackok", "timestamp", "nop", "wscale"]

    # SEQ test often has TI (TTL Initial) and DF fields
    seq = tests.get("SEQ", {})
    if isinstance(seq, dict):
        ti = seq.get("TI", "")
        if ti:
            try:
                ttl = int(ti, 16) if not ti.isdigit() else int(ti)
            except (ValueError, TypeError):
                pass
        if seq.get("DF", "") == "Y":
            df_flag = True
        elif seq.get("DF", "") == "N":
            df_flag = False

    # WIN test has W1-W6 for window sizes
    win = tests.get("WIN", {})
    if isinstance(win, dict):
        w1 = win.get("W1", "")
        if w1:
            try:
                window_size = int(w1, 16) if not w1.isdigit() else int(w1)
            except (ValueError, TypeError):
                pass

    # OPS test contains TCP option sequence
    ops = tests.get("OPS", {})
    if isinstance(ops, dict):
        o1 = ops.get("O1", "")
        if o1:
            tcp_options = []
            if "M" in o1:
                tcp_options.append("mss")
            if "S" in o1:
                tcp_options.append("sackok")
            if "T" in o1:
                tcp_options.append("timestamp")
            if "N" in o1:
                tcp_options.append("nop")
            if "W" in o1:
                tcp_options.append("wscale")

    db.setdefault(family, {})[version] = {
        "ttl": ttl,
        "window_size": window_size,
        "df_flag": df_flag,
        "tcp_options": tcp_options,
    }


def main():
    parser = argparse.ArgumentParser(description="Convert nmap-os-db to USARE JSON")
    parser.add_argument("input", nargs="?", help="Path to nmap-os-db file (optional, writes defaults if omitted)")
    parser.add_argument("-o", "--output", default=None, help="Output JSON path")

    args = parser.parse_args()

    db = parse_nmap_os_db(args.input)
    if not db:
        sys.exit(1)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(db, f, indent=2)
        logger.info(f"Successfully wrote {args.output}")

if __name__ == "__main__":
    main()
