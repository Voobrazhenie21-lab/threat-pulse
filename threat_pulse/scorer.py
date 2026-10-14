"""Risk scoring engine and MITRE ATT&CK correlation for ThreatPulse."""

from typing import Dict, Any, List, Tuple
from threat_pulse.models import IOCType, RiskLevel


def calculate_risk_score(
    ioc: str,
    ioc_type: IOCType,
    heuristics: Dict[str, Any],
    network_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    malware_data: Dict[str, Any]
) -> Tuple[int, RiskLevel, str, List[str], List[str], str]:
    """
    Calculate an aggregate threat score (0 to 100), assign RiskLevel, verdict, tags,
    MITRE ATT&CK techniques, and actionable recommendation for SOC analysts.
    """
    score = 0
    tags: List[str] = []
    mitre: List[str] = []

    # 1. Check Private / Bogon IPs
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        if heuristics.get("is_rfc1918"):
            tags.append("RFC1918-Private")
            return (
                0,
                RiskLevel.CLEAN,
                "Internal Private IP (RFC 1918)",
                tags,
                [],
                "Internal corporate asset. Verify hostname via internal Active Directory / DHCP. Do not block at border."
            )
        if heuristics.get("is_loopback"):
            tags.append("Loopback")
            return (0, RiskLevel.CLEAN, "Localhost / Loopback", tags, [], "Local loopback address. No external threat.")
        if heuristics.get("is_bogon"):
            tags.append("Bogon-Reserved")
            return (
                15,
                RiskLevel.LOW,
                f"Bogon / Reserved Space ({heuristics.get('bogon_network', '')})",
                tags,
                ["T1590: Gather Victim Network Information"],
                "Unallocated or reserved address. If seen in external traffic, verify possible spoofing."
            )

    # 2. Known Malware Hashes
    if malware_data.get("is_known_malware"):
        score = 100
        family = malware_data.get("family", "Malware")
        m_type = malware_data.get("type", "Malicious")
        tags.extend(["Known-Malware", family, m_type])

        if "Mimikatz" in family:
            mitre.append("T1003.001: OS Credential Dumping: LSASS Memory")
        elif "WannaCry" in family or "Ransomware" in m_type:
            mitre.append("T1486: Data Encrypted for Impact")
            mitre.append("T1210: Exploitation of Remote Services")
        elif "Cobalt Strike" in family:
            mitre.append("T1071: Application Layer Protocol")
            mitre.append("T1059: Command and Scripting Interpreter")
        elif "WebShell" in family or "Web Shell" in m_type:
            mitre.append("T1505.003: Server Software Component: Web Shell")
        else:
            mitre.append("T1204: User Execution")

        return (
            score,
            RiskLevel.CRITICAL,
            f"Confirmed Malicious: {family}",
            tags,
            mitre,
            "CRITICAL THREAT: Isolate host immediately, capture memory dump, kill parent process, and reset credentials."
        )

    # 3. Tor Exit Node
    if network_data.get("is_tor_exit"):
        score = max(score, 85)
        tags.append("Tor-Exit-Node")
        tags.append("Anonymizer")
        mitre.append("T1090.003: Multi-hop Proxy: Tor")

    # 4. Known Internet Scanners (Censys, Shodan, Shadowserver)
    if network_data.get("is_known_scanner"):
        scanner_name = network_data.get("scanner_name", "Internet Scanner")
        tags.append("Known-Scanner")
        tags.append(scanner_name)
        mitre.append("T1595: Active Scanning")
        # If it's a known benign research scanner, cap risk at LOW/MEDIUM to prevent false positive panic
        score = 25
        return (
            score,
            RiskLevel.LOW,
            f"Benign Security Research Scanner ({scanner_name})",
            tags,
            mitre,
            "Known research scanner. Do not escalate to P1; monitor for aggressive credential brute force."
        )

    # 5. AbuseIPDB Scoring
    if abuse_data.get("queried"):
        abuse_score = abuse_data.get("abuse_score", 0)
        reports = abuse_data.get("total_reports", 0)
        if abuse_score > 0:
            score = max(score, abuse_score)
            tags.append(f"AbuseIPDB-Score-{abuse_score}%")
            if reports >= 5:
                tags.append("Frequent-Attacker")
                mitre.append("T1110: Brute Force")
                mitre.append("T1190: Exploit Public-Facing Application")

    # 6. Domain Heuristics
    if ioc_type == IOCType.DOMAIN:
        if heuristics.get("is_dga_candidate"):
            score = max(score, 75)
            tags.append("DGA-Candidate")
            tags.append(f"Entropy-{heuristics.get('sld_entropy', 0)}")
            mitre.append("T1568.002: Dynamic Resolution: Domain Generation Algorithms")

        if heuristics.get("suspicious_tld"):
            score = max(score, 50)
            tags.append(f"Suspicious-TLD-.{heuristics.get('tld')}")
            mitre.append("T1583.001: Acquire Infrastructure: Domains")

        if heuristics.get("is_punycode"):
            score = max(score, 65)
            tags.append("IDN-Homograph-Punycode")
            mitre.append("T1036.007: Masquerading: Double File Extension or IDN Spoofing")

    # 7. URL Heuristics
    if ioc_type == IOCType.URL:
        if heuristics.get("is_raw_ip_host"):
            score = max(score, 55)
            tags.append("Raw-IP-Host")
            mitre.append("T1071.001: Web Protocols")

        if heuristics.get("has_executable_extension"):
            score = max(score, 80)
            tags.append("Direct-Executable-Download")
            mitre.append("T1204.002: Malicious File")

        if heuristics.get("has_credentials"):
            score = max(score, 60)
            tags.append("Embedded-Credentials")

    # Final Risk Level Determination
    if score >= 90:
        level = RiskLevel.CRITICAL
        verdict = "Critical Malicious Threat"
        recom = "Block at perimeter firewall/EDR immediately. Check SIEM for lateral movement or data exfiltration."
    elif score >= 70:
        level = RiskLevel.HIGH
        verdict = "High Risk Indicator"
        recom = "Isolate traffic, block domain/IP at proxy, verify if any endpoint established persistent C2 connection."
    elif score >= 40:
        level = RiskLevel.MEDIUM
        verdict = "Suspicious Indicator"
        recom = "Add to SIEM watchlist. Correlate with authentication failures or uncommon outbound traffic."
    elif score >= 16:
        level = RiskLevel.LOW
        verdict = "Low Risk / Informational"
        recom = "Low threat probability. Standard monitoring applies."
    else:
        level = RiskLevel.CLEAN
        verdict = "Clean / No Malicious Indicators"
        recom = "No threat indicators detected. Whitelist or close alert as benign."

    return score, level, verdict, tags, mitre, recom
