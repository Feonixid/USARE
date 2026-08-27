"""
USARE MAC Address Spoofing Engine

Spoofs the Ethernet source MAC address on all outgoing frames.
This matters on local network segments where:
  - ARP caches record your real MAC even when your IP is spoofed
  - 802.1X port authentication is based on MAC
  - Network access control (NAC) appliances allow/deny by MAC
  - Logging infrastructure records MAC alongside IP for attribution

Three spoofing modes:
  1. RANDOM  — completely random 48-bit MAC (may trigger OUI-unknown alerts)
  2. VENDOR  — random MAC within a specific vendor OUI (realistic, blends in)
  3. CLONE   — clone MAC from a seen-in-the-wild packet (best camouflage)

Technical implementation:
  On Linux, MAC spoofing at the kernel level requires either:
    a) ip link set dev <iface> address <mac>  — changes the NIC's reported MAC
       (affects ALL traffic on that interface, persists until reset)
    b) Scapy Ether(src=<mac>)  — spoofs the MAC only in raw crafted frames
       without changing the interface MAC (safer, per-packet control)

  USARE uses approach (b) — per-packet Scapy spoofing — for surgical control.
  Approach (a) is offered as --mac-persist for when you want all traffic spoofed.

Important: MAC spoofing only affects Layer 2. Once frames are routed through
a gateway (any hop beyond your local subnet), the MAC is replaced by the
gateway's MAC and your spoofed MAC is irrelevant. This module is primarily
useful for local network reconnaissance.
"""

import os
import re
import random
import subprocess
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("usare.mac_spoof")

# ─── Common vendor OUI prefixes ──────────────────────────────────────────────
# These are real OUIs from hardware manufacturers. Using one makes the MAC
# look like it belongs to a real device rather than triggering "unknown vendor" alerts.

VENDOR_OUIS: Dict[str, str] = {
    # Workstations / laptops (blend in on office networks)
    "dell":         "F8:DB:88",
    "lenovo":       "00:1A:6B",
    "apple":        "AC:DE:48",
    "apple_wifi":   "A4:83:E7",
    "hp":           "00:1E:4F",
    "asus":         "00:1A:92",
    "acer":         "00:26:9E",
    # Network gear (blend in on infrastructure scans)
    "cisco":        "00:1A:A1",
    "cisco_wifi":   "00:0C:CE",
    "juniper":      "00:05:85",
    "aruba":        "00:0B:86",
    "ubiquiti":     "DC:9F:DB",
    "netgear":      "00:09:5B",
    "tplink":       "50:C7:BF",
    # VM hypervisors (useful for evading VM-detection by MAC)
    "vmware":       "00:0C:29",
    "virtualbox":   "08:00:27",
    "hyper_v":      "00:15:5D",
    # Mobile devices
    "samsung":      "00:1D:25",
    "huawei":       "00:18:82",
    "xiaomi":       "0C:1D:AF",
    # Cloud/server
    "amazon_aws":   "0A:58:A9",
    "google":       "42:01:0A",
}


def generate_random_mac() -> str:
    """Generate a fully random unicast MAC address."""
    # Ensure bit 0 of byte 0 = 0 (unicast) and bit 1 = 0 (globally unique)
    byte0 = random.randint(0, 255) & 0xFC
    rest  = [random.randint(0, 255) for _ in range(5)]
    octets = [byte0] + rest
    return ":".join(f"{b:02x}" for b in octets)


def generate_vendor_mac(vendor: str = "dell") -> str:
    """Generate a random MAC within a specific vendor's OUI."""
    vendor_lower = vendor.lower().replace(" ", "_")
    oui = VENDOR_OUIS.get(vendor_lower, VENDOR_OUIS.get("dell"))
    if not oui:
        return generate_random_mac()
    # Keep the OUI, randomise the remaining 3 bytes
    suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    return f"{oui}:{suffix}"


def validate_mac(mac: str) -> bool:
    """Check if a MAC address string is well-formed."""
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
    return bool(pattern.match(mac))


def normalise_mac(mac: str) -> str:
    """Normalise MAC to lowercase colon-separated format."""
    return mac.replace("-", ":").lower()


class MACSpoofer:
    """
    Per-packet MAC address spoofer for Scapy raw frames.

    Injects a spoofed Ethernet source MAC into every crafted Ether() packet
    without changing the interface's actual hardware MAC.
    """

    def __init__(
        self,
        mode: str = "vendor",
        mac: Optional[str] = None,
        vendor: str = "dell",
        interface: Optional[str] = None,
    ):
        """
        Args:
            mode: "random" | "vendor" | "fixed"
                  random = new random MAC each call
                  vendor = random within vendor OUI (consistent per session)
                  fixed  = use the exact `mac` value provided
            mac:      Explicit MAC for mode="fixed" (e.g. "de:ad:be:ef:ca:fe")
            vendor:   Vendor name for mode="vendor" (see VENDOR_OUIS keys)
            interface: Network interface (only needed for --mac-persist)
        """
        self.mode      = mode.lower()
        self.vendor    = vendor.lower()
        self.interface = interface
        self._session_mac: Optional[str] = None

        if self.mode == "fixed":
            if mac and validate_mac(mac):
                self._session_mac = normalise_mac(mac)
            else:
                raise ValueError(f"Invalid MAC address: {mac!r}")
        elif self.mode == "vendor":
            # Generate once per session for consistency
            self._session_mac = generate_vendor_mac(vendor)
            logger.info(f"[MACSpoof] Session MAC ({vendor}): {self._session_mac}")
        elif self.mode == "random":
            # Will regenerate on each call
            self._session_mac = None
        else:
            raise ValueError(f"Unknown mode: {mode!r}. Use random|vendor|fixed")

    def get_mac(self) -> str:
        """Get the MAC to use for the next packet."""
        if self.mode == "random":
            return generate_random_mac()
        return self._session_mac or generate_random_mac()

    def inject(self, pkt):
        """
        Inject the spoofed MAC into a Scapy Ether layer packet.
        Returns the modified packet.
        """
        try:
            from scapy.all import Ether
            if pkt.haslayer(Ether):
                pkt[Ether].src = self.get_mac()
            else:
                # Wrap bare IP packets in an Ether layer
                pkt = Ether(src=self.get_mac()) / pkt
        except ImportError:
            pass
        return pkt

    def get_info(self) -> Dict[str, Any]:
        return {
            "mode":        self.mode,
            "vendor":      self.vendor if self.mode == "vendor" else None,
            "session_mac": self._session_mac,
            "random":      self.mode == "random",
        }

    # ─── Persistent interface-level spoofing (optional, affects all traffic) ──

    def apply_to_interface(self) -> bool:
        """
        Change the interface's hardware MAC at the OS level.
        This affects ALL traffic from this interface, not just Scapy packets.
        Requires root. Reverts on interface down/up or explicit revert().

        WARNING: This changes your interface's MAC system-wide.
        Only use if you understand the implications.
        """
        if not self.interface:
            logger.error("[MACSpoof] No interface specified for persistent MAC change")
            return False

        new_mac = self.get_mac()
        try:
            # Bring interface down, change MAC, bring back up
            subprocess.run(["ip", "link", "set", self.interface, "down"],
                           check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "address", new_mac],
                           check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"],
                           check=True, capture_output=True)
            logger.info(f"[MACSpoof] Interface {self.interface} MAC changed to {new_mac}")
            self._persistent_mac = new_mac
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"[MACSpoof] Failed to change interface MAC: {e}")
            return False

    def revert_interface(self, original_mac: str) -> bool:
        """Restore the original MAC address on the interface."""
        if not self.interface:
            return False
        try:
            subprocess.run(["ip", "link", "set", self.interface, "down"],
                           check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "address", original_mac],
                           check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"],
                           check=True, capture_output=True)
            logger.info(f"[MACSpoof] Interface {self.interface} MAC restored to {original_mac}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"[MACSpoof] Failed to restore MAC: {e}")
            return False

    @staticmethod
    def get_interface_mac(interface: str) -> Optional[str]:
        """Get the current MAC address of a network interface."""
        try:
            path = f"/sys/class/net/{interface}/address"
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return None

    @staticmethod
    def list_vendors() -> Dict[str, str]:
        """Return all available vendor OUI profiles."""
        return dict(VENDOR_OUIS)
