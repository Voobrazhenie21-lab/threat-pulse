"""Network enricher: DNS PTR resolution, Tor exit node detection, and scanner identification."""

import socket
from typing import Dict, Any, Set
from threat_pulse.enrichers.base import BaseEnricher
from threat_pulse.models import IOCType

# Known active Tor exit nodes (sample curated offline seed list for instant high-confidence matching)
KNOWN_TOR_EXIT_NODES: Set[str] = {
    "185.220.101.5", "185.220.101.6", "185.220.101.7",
    "185.220.100.241", "185.220.100.242", "185.220.100.252",
    "195.176.3.23", "51.15.43.205", "185.107.56.210",
    "109.70.100.25", "185.14.29.178", "198.96.155.3"
}

# Known security research / port scanner subnets & IPs
KNOWN_SCANNERS: Dict[str, str] = {
    "198.20.69.74": "Shadowserver Foundation Scanner",
    "198.20.69.98": "Shadowserver Foundation Scanner",
    "162.142.125.0": "Censys Research Scanner",
    "167.248.133.0": "Censys Research Scanner",
    "71.6.232.0": "Shodan Internet Scanner",
    "71.6.165.200": "Shodan Internet Scanner",
    "185.180.143.0": "LeakIX Security Scanner",
}


class NetworkEnricher(BaseEnricher):
    """Enriches network indicators with reverse DNS, Tor status, and scanner attribution."""

    def __init__(self, timeout: float = 2.0):
        super().__init__(name="network_enricher")
        self.timeout = timeout

    def can_enrich(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN)

    def enrich(self, ioc: str, ioc_type: IOCType) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "ptr": None,
            "resolved_ips": [],
            "is_tor_exit": False,
            "is_known_scanner": False,
            "scanner_name": None,
        }

        # IP Specific Network Checks
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            # Check Tor
            if ioc in KNOWN_TOR_EXIT_NODES:
                data["is_tor_exit"] = True

            # Check Known Scanners
            for scanner_ip, scanner_name in KNOWN_SCANNERS.items():
                if ioc == scanner_ip or ioc.startswith(scanner_ip.rsplit(".", 1)[0]):
                    data["is_known_scanner"] = True
                    data["scanner_name"] = scanner_name
                    break

            # Reverse DNS (PTR)
            try:
                socket.setdefaulttimeout(self.timeout)
                host_info = socket.gethostbyaddr(ioc)
                data["ptr"] = host_info[0]
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                data["ptr"] = None

        # Domain Specific Network Checks
        elif ioc_type == IOCType.DOMAIN:
            try:
                socket.setdefaulttimeout(self.timeout)
                _, _, ip_list = socket.gethostbyname_ex(ioc)
                data["resolved_ips"] = ip_list
                # Check if domain resolves to a Tor node or scanner
                for ip in ip_list:
                    if ip in KNOWN_TOR_EXIT_NODES:
                        data["is_tor_exit"] = True
            except (socket.gaierror, socket.timeout, OSError):
                data["resolved_ips"] = []

        return data
