"""Terminal card, table, JSON, Markdown, and Wazuh CDB list output formatters."""

import json
from typing import List
from threat_pulse.models import EnrichmentResult, RiskLevel

# ANSI Color codes for clean, zero-dependency colored terminal rendering
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_GREEN = "\033[42m"


def _risk_color(level: RiskLevel) -> str:
    if level == RiskLevel.CRITICAL:
        return f"{BG_RED}{WHITE}{BOLD}"
    elif level == RiskLevel.HIGH:
        return f"{RED}{BOLD}"
    elif level == RiskLevel.MEDIUM:
        return f"{YELLOW}{BOLD}"
    elif level == RiskLevel.LOW:
        return f"{BLUE}"
    else:
        return f"{GREEN}{BOLD}"


def render_terminal_card(res: EnrichmentResult) -> str:
    """Render a standalone, highly detailed threat intelligence card for a single IOC."""
    color = _risk_color(res.risk_level)
    lines = []
    lines.append(f"{CYAN}┌────────────────────────────────────────────────────────────────────────┐{RESET}")
    lines.append(f"{CYAN}│{RESET} {BOLD}ThreatPulse IOC Report{RESET}  {DIM}[{res.ioc_type.value.upper()}]{RESET}")
    lines.append(f"{CYAN}├────────────────────────────────────────────────────────────────────────┤{RESET}")
    lines.append(f"{CYAN}│{RESET} {BOLD}Indicator:{RESET}    {res.defanged} {DIM}(raw: {res.ioc}){RESET}")
    lines.append(f"{CYAN}│{RESET} {BOLD}Risk Level:{RESET}   {color} {res.risk_level.value} ({res.risk_score}/100) {RESET}")
    lines.append(f"{CYAN}│{RESET} {BOLD}Verdict:{RESET}      {res.verdict}")

    if res.tags:
        tag_str = " ".join([f"{MAGENTA}#{t}{RESET}" for t in res.tags])
        lines.append(f"{CYAN}│{RESET} {BOLD}Tags:{RESET}         {tag_str}")

    if res.mitre_attack:
        lines.append(f"{CYAN}│{RESET} {BOLD}MITRE ATT&CK:{RESET}")
        for m in res.mitre_attack:
            lines.append(f"{CYAN}│{RESET}   • {YELLOW}{m}{RESET}")

    # Specific details section
    details = res.details
    if details:
        lines.append(f"{CYAN}│{RESET} {BOLD}Intelligence Details:{RESET}")
        if "ptr" in details and details["ptr"]:
            lines.append(f"{CYAN}│{RESET}   • Reverse DNS: {details['ptr']}")
        if "country_code" in details and details["country_code"] != "UNKNOWN":
            lines.append(f"{CYAN}│{RESET}   • Country / ISP: {details['country_code']} ({details.get('isp', 'N/A')})")
        if "abuse_score" in details and details["abuse_score"] > 0:
            lines.append(f"{CYAN}│{RESET}   • AbuseIPDB Score: {details['abuse_score']}% ({details.get('total_reports', 0)} reports)")
        if "family" in details and details["family"]:
            lines.append(f"{CYAN}│{RESET}   • Malware Family: {details['family']} ({details.get('description', '')})")
        if "sld_entropy" in details:
            lines.append(f"{CYAN}│{RESET}   • Domain Entropy: {details['sld_entropy']} (DGA Candidate: {details.get('is_dga_candidate')})")
        if "is_known_scanner" in details and details["is_known_scanner"]:
            lines.append(f"{CYAN}│{RESET}   • Scanner: {details.get('scanner_name')}")

    lines.append(f"{CYAN}│{RESET} {BOLD}SOC Action:{RESET}   {WHITE}{res.recommendation}{RESET}")
    cache_badge = f"{DIM}(from local cache){RESET}" if res.cached else f"{DIM}(live analysis){RESET}"
    lines.append(f"{CYAN}│{RESET} {DIM}Timestamp: {res.timestamp} {cache_badge}{RESET}")
    lines.append(f"{CYAN}└────────────────────────────────────────────────────────────────────────┘{RESET}")
    return "\n".join(lines)


def render_terminal_summary_table(results: List[EnrichmentResult]) -> str:
    """Render a clean summary table for batch IOC enrichment."""
    if not results:
        return "No IOCs analyzed."

    headers = f"{'INDICATOR':<35} {'TYPE':<8} {'RISK':<12} {'SCORE':<7} {'VERDICT':<30}"
    separator = "-" * 95
    lines = [f"{BOLD}{headers}{RESET}", separator]

    for r in results:
        color = _risk_color(r.risk_level)
        short_verdict = (r.verdict[:27] + "...") if len(r.verdict) > 30 else r.verdict
        line = (
            f"{r.defanged[:33]:<35} "
            f"{r.ioc_type.value:<8} "
            f"{color}{r.risk_level.value:<12}{RESET} "
            f"{r.risk_score:<7} "
            f"{short_verdict:<30}"
        )
        lines.append(line)

    return "\n".join(lines)


def render_json(results: List[EnrichmentResult], pretty: bool = True) -> str:
    """Serialize results list to JSON."""
    data = [r.to_dict() for r in results]
    indent = 2 if pretty else None
    return json.dumps({"count": len(results), "indicators": data}, indent=indent)


def render_markdown(results: List[EnrichmentResult]) -> str:
    """Format results into a Markdown table for ticketing / GitHub / reporting."""
    lines = [
        "# ThreatPulse Threat Intelligence Report",
        "",
        f"**Total Indicators Analyzed:** {len(results)}",
        "",
        "| Indicator (Defanged) | Type | Risk Level | Score | Verdict | Tags |",
        "| --------------------- | ---- | ---------- | ----- | ------- | ---- |"
    ]
    for r in results:
        tags_str = ", ".join(r.tags) if r.tags else "-"
        lines.append(
            f"| `{r.defanged}` | {r.ioc_type.value} | **{r.risk_level.value}** | {r.risk_score}/100 | {r.verdict} | {tags_str} |"
        )
    return "\n".join(lines)


def render_wazuh_cdb_list(results: List[EnrichmentResult]) -> str:
    """
    Format malicious/suspicious indicators into Wazuh CDB list syntax.
    Syntax: <key>:<value>
    Usage: save to /var/ossec/etc/lists/threat_pulse.cdb
    """
    lines = ["# ThreatPulse exported CDB List for Wazuh SIEM"]
    for r in results:
        if r.risk_score >= 40:  # Medium, High, or Critical
            tag_summary = ",".join(r.tags[:2]) if r.tags else "malicious"
            lines.append(f"{r.ioc}:{r.risk_level.value}_{r.risk_score}:{tag_summary}")
    return "\n".join(lines)
