"""
USARE — Ultra-Stealth Adaptive Reconnaissance Engine
Entry point module for the `usare` console command.

This module provides:
  - __version__: the single source of truth for the version string
  - main(): the entry point registered in pyproject.toml

Usage after `pip install .`:
    usare -t 192.168.1.1 -p 22,80,443 --ghost --full
    usare --version
    usare --cheatsheet
"""

import sys
import os

__version__ = "2.1.0"


def _check_privileges():
    """Check for root/admin privileges required for raw sockets."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                from core.cli import console
                console.print(
                    "[bold yellow]⚠️  Running without Administrator privileges "
                    "— raw socket scans may fail.[/bold yellow]"
                )
                console.print(
                    "[dim]Tip: Right-click terminal → Run as Administrator[/dim]\n"
                )
        except Exception:
            pass
    else:
        if os.geteuid() != 0:
            from core.cli import console
            console.print(
                "[bold red]❌ USARE requires root privileges for raw socket access.[/bold red]"
            )
            console.print("[dim]Run: sudo usare ...[/dim]")
            sys.exit(1)


def _handle_standalone_flags():
    """Handle flags that exit immediately without starting a scan."""
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"USARE v{__version__}")
        sys.exit(0)
    if "--cheatsheet" in sys.argv:
        from core.cli import console
        from core.cheatsheet import print_cheatsheet
        print_cheatsheet(console)
        sys.exit(0)


def main():
    """Main entry point for the `usare` console command."""
    _handle_standalone_flags()
    _check_privileges()

    from core.engine import main as engine_main
    try:
        engine_main()
    except KeyboardInterrupt:
        from core.cli import console
        console.print("\n[yellow]Scan aborted by user.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
