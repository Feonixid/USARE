import subprocess
import logging
import sys

logger = logging.getLogger("usare.rst_blocker")

class RSTBlocker:
    """
    Safely utilizes OS-level firewall rules (iptables on Linux, netsh on Windows)
    to prevent the local OS from leaking TCP RST packets in response to SYN-ACKs
    during raw socket scans.
    """
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.active = False
        self.is_linux = sys.platform.startswith("linux")
        self.is_windows = sys.platform.startswith("win")
        self.rule_name = f"USARE_RST_BLOCK_{self.target_ip.replace('.', '_').replace(':', '_')}"

    def __enter__(self):
        if self.is_linux:
            try:
                # Rule: iptables -A OUTPUT -p tcp --tcp-flags RST RST -d <target> -j DROP
                cmd = [
                    "iptables", "-A", "OUTPUT", 
                    "-p", "tcp", 
                    "--tcp-flags", "RST", "RST", 
                    "-d", self.target_ip, 
                    "-j", "DROP"
                ]
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.active = True
                logger.info(f"[RST-Blocker] Engaged: Dropping local RST packets to {self.target_ip} via iptables")
            except subprocess.CalledProcessError:
                logger.warning("[RST-Blocker] Failed to add iptables rule (Requires root/iptables installed).")
            except FileNotFoundError:
                logger.warning("[RST-Blocker] iptables binary not found. Skipping.")
        elif self.is_windows:
            try:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={self.rule_name}",
                    "dir=out", "action=block", "protocol=TCP",
                    f"remoteip={self.target_ip}"
                ]
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.active = True
                logger.info(f"[RST-Blocker] Engaged: Dropping local RST packets to {self.target_ip} via Windows Firewall")
            except (subprocess.CalledProcessError, FileNotFoundError, PermissionError) as e:
                logger.warning(f"[RST-Blocker] Windows Firewall rule failed (Run as Administrator for RST block): {e}")

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.active:
            if self.is_linux:
                try:
                    cmd = [
                        "iptables", "-D", "OUTPUT", 
                        "-p", "tcp", 
                        "--tcp-flags", "RST", "RST", 
                        "-d", self.target_ip, 
                        "-j", "DROP"
                    ]
                    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.active = False
                    logger.debug(f"[RST-Blocker] Disengaged: IPTables rule removed.")
                except Exception as e:
                    logger.error(f"[RST-Blocker] Cleanup failed! You may need to manually flush iptables: {e}")
            elif self.is_windows:
                try:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={self.rule_name}"
                    ]
                    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.active = False
                    logger.debug(f"[RST-Blocker] Disengaged: Windows Firewall rule removed.")
                except Exception as e:
                    logger.error(f"[RST-Blocker] Windows Firewall cleanup failed: {e}")
