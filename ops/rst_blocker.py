import subprocess
import logging
import sys

logger = logging.getLogger("usare.rst_blocker")

class RSTBlocker:
    """
    Safely utilizes OS-level firewall rules (iptables) to prevent the local OS 
    from leaking TCP RST packets in response to SYN-ACKs during raw socket scans.
    Requires root. Only natively supports Linux via iptables.
    """
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.active = False
        self.is_linux = sys.platform.startswith("linux")

    def __enter__(self):
        if not self.is_linux:
            logger.debug("[RST-Blocker] Not on Linux. Skipping iptables rule.")
            return self

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
            logger.info(f"[RST-Blocker] Engaged: Dropping local RST packets to {self.target_ip}")
        except subprocess.CalledProcessError:
            logger.warning("[RST-Blocker] Failed to add iptables rule (Requires root/iptables installed).")
        except FileNotFoundError:
            logger.warning("[RST-Blocker] iptables binary not found. Skipping.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.active and self.is_linux:
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
                logger.error(f"[RST-Blocker] Cleanup failed! You may need to manually flush iptables. {e}")
