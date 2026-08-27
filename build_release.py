#!/usr/bin/env python3
"""
USARE Release Builder

Compiles usare.py into a standalone binary using Nuitka (preferred) or
PyInstaller (fallback) so it doesn't appear as a Python interpreter
process to EDR/AV systems.

Nuitka is preferred because:
  - It compiles Python to genuine C code, then to a native binary
  - The result is a real ELF/PE binary — no python.exe in process list
  - Better obfuscation than PyInstaller (which just zips .pyc)
  - Supports --obfuscate and --disable-console for stealth builds

PyInstaller fallback because:
  - Nuitka requires a C compiler; PyInstaller does not
  - PyInstaller is far more common in most environments

Usage:
    python build_release.py                  # auto-selects best available
    python build_release.py --nuitka         # force Nuitka
    python build_release.py --pyinstaller    # force PyInstaller
    python build_release.py --strip          # strip symbols from binary
    python build_release.py --target linux   # linux | windows | macos
    python build_release.py --obfuscate      # rename symbols (Nuitka only)

Output: dist/usare  (Linux/macOS) or dist/usare.exe (Windows)
"""

import os
import sys
import shutil
import argparse
import subprocess
import platform
from pathlib import Path

BASE_DIR   = Path(__file__).parent.resolve()
ENTRY      = BASE_DIR / "usare.py"
DIST_DIR   = BASE_DIR / "dist"
BUILD_DIR  = BASE_DIR / "build"

# Packages that must be included explicitly (Nuitka/PyInstaller miss them)
HIDDEN_IMPORTS = [
    "scapy",
    "scapy.all",
    "scapy.layers.inet",
    "scapy.layers.inet6",
    "scapy.layers.l2",
    "rich",
    "rich.console",
    "rich.table",
    "rich.panel",
    "rich.progress",
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    "requests",
    "urllib3",
    "dns",
    "dns.resolver",
    "bcc",
    "sklearn",
    "numpy",
]

# Data files to bundle (relative to BASE_DIR)
DATA_FILES = [
    "data/os_fingerprints.json",
    "data/nmap-service-probes",
]


# ─────────────────────────────────────────────────────────────────────────────
# Nuitka build
# ─────────────────────────────────────────────────────────────────────────────

def build_nuitka(strip: bool = False, obfuscate: bool = False, target_os: str = "linux") -> int:
    print("[USARE Build] Building with Nuitka (native binary)")

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--onefile",
        f"--output-dir={DIST_DIR}",
        f"--output-filename=usare",
        # Remove the Python company branding from the binary
        "--company-name=USARE",
        "--product-name=USARE",
        "--product-version=2.0.0",
        # Disable console window on Windows (silent operation)
        "--windows-disable-console" if target_os == "windows" else "",
        # Obfuscate internal module names (makes reverse engineering harder)
        "--obfuscation" if obfuscate else "",
        # Follow all imports
        "--follow-imports",
        # Include data files
    ]

    for data_path in DATA_FILES:
        full = BASE_DIR / data_path
        if full.exists():
            dest_dir = str(Path(data_path).parent)
            cmd.append(f"--include-data-file={full}={dest_dir}/")

    # Hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.append(f"--include-package={imp}")

    # Compiler flags for size optimization
    cmd += [
        "--python-flag=no_docstrings",   # strip docstrings
        "--python-flag=no_asserts",      # strip assertions
    ]

    cmd.append(str(ENTRY))

    # Remove empty strings from arglist
    cmd = [c for c in cmd if c]

    print(f"[USARE Build] Command: {' '.join(cmd[:6])} ...")
    result = subprocess.run(cmd, cwd=BASE_DIR)

    if result.returncode != 0:
        print("[USARE Build] Nuitka failed.")
        return result.returncode

    binary = DIST_DIR / "usare"
    if target_os == "windows":
        binary = DIST_DIR / "usare.exe"

    if strip and binary.exists() and platform.system() != "Windows":
        print(f"[USARE Build] Stripping symbols from {binary}")
        subprocess.run(["strip", "--strip-all", str(binary)])

    if binary.exists():
        size_mb = binary.stat().st_size / (1024 * 1024)
        print(f"[USARE Build] ✓ Binary: {binary} ({size_mb:.1f} MB)")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# PyInstaller build
# ─────────────────────────────────────────────────────────────────────────────

def build_pyinstaller(strip: bool = False, target_os: str = "linux") -> int:
    print("[USARE Build] Building with PyInstaller")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--clean",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        "--name=usare",
        "--strip" if strip else "",
        # Suppress the bootloader console splash on Windows
        "--noconsole" if target_os == "windows" else "",
    ]

    for imp in HIDDEN_IMPORTS:
        cmd += ["--hidden-import", imp]

    for data_path in DATA_FILES:
        full = BASE_DIR / data_path
        if full.exists():
            dest_dir = str(Path(data_path).parent)
            sep = ";" if target_os == "windows" else ":"
            cmd += ["--add-data", f"{full}{sep}{dest_dir}"]

    cmd.append(str(ENTRY))
    cmd = [c for c in cmd if c]

    print(f"[USARE Build] Command: {' '.join(cmd[:6])} ...")
    result = subprocess.run(cmd, cwd=BASE_DIR)

    if result.returncode == 0:
        binary = DIST_DIR / ("usare.exe" if target_os == "windows" else "usare")
        if binary.exists():
            size_mb = binary.stat().st_size / (1024 * 1024)
            print(f"[USARE Build] ✓ Binary: {binary} ({size_mb:.1f} MB)")

    return result.returncode


# ─────────────────────────────────────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────────────────────────────────────

def check_deps():
    print("[USARE Build] Checking dependencies...")
    missing = []
    for pkg in ["rich", "scapy", "requests", "cryptography"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[USARE Build] Missing: {missing}")
        print("[USARE Build] Run: pip install -r requirements.txt")
        return False
    print("[USARE Build] Core dependencies OK")
    return True


def detect_builder() -> str:
    """Return 'nuitka', 'pyinstaller', or 'none'."""
    try:
        r = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            return "nuitka"
    except Exception:
        pass
    try:
        r = subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            return "pyinstaller"
    except Exception:
        pass
    return "none"


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="USARE Release Builder")
    parser.add_argument("--nuitka",       action="store_true", help="Force Nuitka")
    parser.add_argument("--pyinstaller",  action="store_true", help="Force PyInstaller")
    parser.add_argument("--strip",        action="store_true", help="Strip debug symbols")
    parser.add_argument("--obfuscate",    action="store_true", help="Obfuscate symbol names (Nuitka only)")
    parser.add_argument("--target",       default=platform.system().lower(),
                        choices=["linux", "windows", "macos"],
                        help="Target OS (default: current platform)")
    args = parser.parse_args()

    if not check_deps():
        sys.exit(1)

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # Select builder
    if args.nuitka:
        builder = "nuitka"
    elif args.pyinstaller:
        builder = "pyinstaller"
    else:
        builder = detect_builder()
        if builder == "none":
            print("[USARE Build] Neither Nuitka nor PyInstaller found.")
            print("  Install Nuitka:      pip install nuitka")
            print("  Install PyInstaller: pip install pyinstaller")
            sys.exit(1)

    print(f"[USARE Build] Using: {builder} | target: {args.target} | strip: {args.strip}")

    if builder == "nuitka":
        rc = build_nuitka(strip=args.strip, obfuscate=args.obfuscate, target_os=args.target)
    else:
        rc = build_pyinstaller(strip=args.strip, target_os=args.target)

    if rc == 0:
        print("\n[USARE Build] Build complete.")
        print(f"[USARE Build] Binary in: {DIST_DIR}/")
        print("\nNotes:")
        print("  - Run as root/Administrator for raw socket and eBPF support")
        print("  - The compiled binary will not show as 'python' in process lists")
        print("  - Nuitka builds are genuine native binaries; PyInstaller builds")
        print("    still contain a Python interpreter (just zipped)")
    else:
        print(f"\n[USARE Build] Build FAILED (exit code {rc})")
        sys.exit(rc)


if __name__ == "__main__":
    main()
