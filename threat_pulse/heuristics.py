"""Offline heuristic analyzers for IP addresses, domains, and URLs."""

import ipaddress
import math
import re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse

# Suspicious TLDs frequently abused in malware campaigns / phishing
HIGH_ABUSE_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "icu", "work",
    "click", "link", "rest", "surf", "monster", "casa", "country", "kim"
}

# Bogon / Reserved network ranges (IPv4)
BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / APIPA
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),     # Network Interconnect Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string to evaluate randomness (DGA detection)."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_ip_heuristics(ip_str: str) -> Dict[str, Any]:
    """Inspect IP against RFC1918, Bogon, Loopback, and Reserved spaces."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"valid": False}

    is_private = ip.is_private
    is_loopback = ip.is_loopback
    is_link_local = ip.is_link_local
    is_multicast = ip.is_multicast
    is_reserved = ip.is_reserved

    is_bogon = False
    bogon_reason = ""
    if ip.version == 4:
        for net in BOGON_NETWORKS:
            if ip in net:
                is_bogon = True
                bogon_reason = str(net)
                break

    rfc1918 = False
    if ip.version == 4:
        rfc_nets = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        rfc1918 = any(ip in net for net in rfc_nets)

    return {
        "valid": True,
        "version": ip.version,
        "is_private": is_private,
        "is_rfc1918": rfc1918,
        "is_bogon": is_bogon,
        "bogon_network": bogon_reason,
        "is_loopback": is_loopback,
        "is_link_local": is_link_local,
        "is_multicast": is_multicast,
        "is_reserved": is_reserved,
    }


def analyze_domain_heuristics(domain: str) -> Dict[str, Any]:
    """Inspect domain for DGA entropy, suspicious TLDs, and IDN homograph punycode."""
    clean_domain = domain.lower().strip()
    parts = clean_domain.split(".")

    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else parts[0]

    # Calculate entropy on Second-Level Domain (the main name)
    sld_entropy = calculate_shannon_entropy(sld)

    is_high_entropy = (sld_entropy >= 3.6 and len(sld) >= 8) or (sld_entropy >= 3.3 and len(sld) >= 14)
    has_suspicious_tld = tld in HIGH_ABUSE_TLDS
    is_punycode = "xn--" in clean_domain
    has_subdomain_abuse = len(parts) >= 4

    # Count digits in main domain name (common in botnets / DGA)
    digit_count = sum(c.isdigit() for c in sld)
    digit_ratio = digit_count / len(sld) if sld else 0.0

    return {
        "domain": clean_domain,
        "sld": sld,
        "tld": tld,
        "sld_entropy": sld_entropy,
        "is_dga_candidate": is_high_entropy or (digit_ratio >= 0.4 and len(sld) >= 8),
        "suspicious_tld": has_suspicious_tld,
        "is_punycode": is_punycode,
        "subdomain_depth": len(parts),
        "excessive_subdomains": has_subdomain_abuse,
        "digit_ratio": round(digit_ratio, 2),
    }


def analyze_url_heuristics(url_str: str) -> Dict[str, Any]:
    """Inspect URL structure for raw IP hosts, suspicious paths, or credentials in URI."""
    try:
        parsed = urlparse(url_str)
    except Exception:
        return {"valid": False}

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    is_raw_ip = False
    try:
        if hostname:
            ipaddress.ip_address(hostname)
            is_raw_ip = True
    except ValueError:
        is_raw_ip = False

    has_credentials = bool(parsed.username or parsed.password)
    has_executable_extension = any(
        path.lower().endswith(ext)
        for ext in [".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".iso", ".hta", ".apk"]
    )
    uncommon_port = parsed.port not in [None, 80, 443, 8080]

    domain_data = analyze_domain_heuristics(hostname) if not is_raw_ip else {}

    return {
        "valid": True,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": parsed.port,
        "uncommon_port": uncommon_port,
        "is_raw_ip_host": is_raw_ip,
        "has_credentials": has_credentials,
        "has_executable_extension": has_executable_extension,
        "domain_heuristics": domain_data,
    }
