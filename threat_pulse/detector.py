"""Indicator of Compromise (IOC) type detection and extraction engine."""

import ipaddress
import re
from typing import List, Tuple
from threat_pulse.models import IOCType

# Regular expressions for IOC detection
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Matches standard domains (2+ labels, valid TLD length)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Matches URLs (http, https, ftp, or defanged hxxp/hxxps)
URL_REGEX = re.compile(
    r"\b(?:https?|hxxps?|ftp)://[^\s/$.?#].[^\s]*", re.IGNORECASE
)


def refang(ioc: str) -> str:
    """Normalize defanged indicators back into canonical format."""
    cleaned = ioc.strip()
    # Replace bracketed dots: [.] or (.) or {.} -> .
    cleaned = re.sub(r"[\[\(\{]\.[\]\)\}]", ".", cleaned)
    # Replace hxxp/hxxps -> http/https
    cleaned = re.sub(r"^hxxp(s?):", r"http\1:", cleaned, flags=re.IGNORECASE)
    # Replace [:] -> :
    cleaned = re.sub(r"\[:\]", ":", cleaned)
    return cleaned


def defang(ioc: str) -> str:
    """Defang an indicator to prevent accidental clicks or resolutions."""
    cleaned = ioc.strip()
    # Defang http/https
    cleaned = re.sub(r"^http:", "hxxp:", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^https:", "hxxps:", cleaned, flags=re.IGNORECASE)
    # Defang dots
    return cleaned.replace(".", "[.]")


def detect_ioc_type(raw_ioc: str) -> IOCType:
    """Classify an IOC string into a specific IOCType."""
    target = refang(raw_ioc).strip()

    # 1. URL Check
    if URL_REGEX.match(target) or target.startswith(("http://", "https://", "ftp://")):
        return IOCType.URL

    # 2. IP Checks
    try:
        ip = ipaddress.ip_address(target)
        if ip.version == 4:
            return IOCType.IPV4
        elif ip.version == 6:
            return IOCType.IPV6
    except ValueError:
        pass

    # 3. Hash Checks
    if SHA256_REGEX.fullmatch(target):
        return IOCType.SHA256
    if SHA1_REGEX.fullmatch(target):
        return IOCType.SHA1
    if MD5_REGEX.fullmatch(target):
        return IOCType.MD5

    # 4. Domain Check
    if DOMAIN_REGEX.fullmatch(target):
        # Exclude common file extensions that match domain regex by accident (e.g. script.sh, tool.py)
        excluded_suffixes = {
            "py", "sh", "exe", "dll", "bat", "ps1", "json", "xml", "csv", "log",
            "txt", "md", "yml", "yaml", "tar", "gz", "zip", "rar", "7z", "conf"
        }
        parts = target.lower().split(".")
        if len(parts) == 2 and parts[-1] in excluded_suffixes:
            return IOCType.UNKNOWN
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def extract_iocs_from_text(text: str) -> List[Tuple[str, IOCType]]:
    """Scan raw text/logs and extract all recognized indicators."""
    results: List[Tuple[str, IOCType]] = []
    seen = set()

    # 1. URLs
    for match in URL_REGEX.finditer(text):
        val = refang(match.group(0))
        if val not in seen:
            seen.add(val)
            results.append((val, IOCType.URL))

    # 2. IP Addresses (v4)
    for match in IPV4_REGEX.finditer(text):
        val = match.group(0)
        try:
            ipaddress.IPv4Address(val)
            if val not in seen:
                seen.add(val)
                results.append((val, IOCType.IPV4))
        except ValueError:
            continue

    # 3. Hashes
    for match in SHA256_REGEX.finditer(text):
        val = match.group(0)
        if val not in seen:
            seen.add(val)
            results.append((val, IOCType.SHA256))

    for match in MD5_REGEX.finditer(text):
        val = match.group(0)
        if val not in seen:
            seen.add(val)
            results.append((val, IOCType.MD5))

    # 4. Domains (avoid matching substrings of already extracted URLs or IPs)
    for match in DOMAIN_REGEX.finditer(text):
        val = match.group(0)
        if detect_ioc_type(val) == IOCType.DOMAIN:
            if val not in seen:
                seen.add(val)
                results.append((val, IOCType.DOMAIN))

    return results
