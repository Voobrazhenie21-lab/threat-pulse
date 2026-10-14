"""Command Line Interface (CLI) entry point for ThreatPulse."""

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from threat_pulse import __version__
from threat_pulse.cache import ThreatCache
from threat_pulse.detector import detect_ioc_type, defang, refang, extract_iocs_from_text
from threat_pulse.enrichers.abuseipdb import AbuseIPDBEnricher
from threat_pulse.enrichers.malware import MalwareHashEnricher
from threat_pulse.enrichers.network import NetworkEnricher
from threat_pulse.formatters import (
    render_terminal_card,
    render_terminal_summary_table,
    render_json,
    render_markdown,
    render_wazuh_cdb_list,
)
from threat_pulse.heuristics import (
    analyze_ip_heuristics,
    analyze_domain_heuristics,
    analyze_url_heuristics,
)
from threat_pulse.models import EnrichmentResult, IOCType, RiskLevel
from threat_pulse.scorer import calculate_risk_score


def enrich_single_ioc(
    raw_ioc: str,
    cache: Optional[ThreatCache] = None,
    abuse_api_key: Optional[str] = None,
    use_cache: bool = True
) -> EnrichmentResult:
    """Enrich a single IOC across all heuristic, network, and intelligence engines."""
    clean_target = refang(raw_ioc).strip()
    ioc_type = detect_ioc_type(clean_target)

    # 1. Check Cache
    if use_cache and cache:
        cached_result = cache.get(clean_target)
        if cached_result:
            return cached_result

    # 2. Run Heuristics
    heuristics = {}
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        heuristics = analyze_ip_heuristics(clean_target)
    elif ioc_type == IOCType.DOMAIN:
        heuristics = analyze_domain_heuristics(clean_target)
    elif ioc_type == IOCType.URL:
        heuristics = analyze_url_heuristics(clean_target)

    # 3. Run Enrichers
    network_enricher = NetworkEnricher()
    abuse_enricher = AbuseIPDBEnricher(api_key=abuse_api_key)
    malware_enricher = MalwareHashEnricher()

    net_data = network_enricher.enrich(clean_target, ioc_type) if network_enricher.can_enrich(ioc_type) else {}
    abuse_data = abuse_enricher.enrich(clean_target, ioc_type) if abuse_enricher.can_enrich(ioc_type) else {}
    malware_data = malware_enricher.enrich(clean_target, ioc_type) if malware_enricher.can_enrich(ioc_type) else {}

    # 4. Score and Classify
    score, level, verdict, tags, mitre, recom = calculate_risk_score(
        clean_target, ioc_type, heuristics, net_data, abuse_data, malware_data
    )

    # Combine all details
    combined_details = {**heuristics, **net_data, **abuse_data, **malware_data}

    result = EnrichmentResult(
        ioc=clean_target,
        ioc_type=ioc_type,
        defanged=defang(clean_target),
        risk_score=score,
        risk_level=level,
        verdict=verdict,
        is_private=heuristics.get("is_rfc1918", False),
        is_bogon=heuristics.get("is_bogon", False),
        tags=tags,
        mitre_attack=mitre,
        details=combined_details,
        recommendation=recom,
        cached=False,
    )

    # Save to Cache
    if use_cache and cache:
        cache.set(result)

    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with comprehensive options."""
    parser = argparse.ArgumentParser(
        prog="threat-pulse",
        description="ThreatPulse - Fast Threat Intelligence & IOC Enrichment CLI for SOC Analysts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  threat-pulse 185.220.101.5
  threat-pulse 84c82835a5d21bbcf75a61706d8ab549
  threat-pulse evil-dga-domain192837.top --format json
  threat-pulse --file access.log --format table
  threat-pulse --file suspicious_iocs.txt --format wazuh-cdb --out threat_pulse.cdb
  threat-pulse --defang http://malicious.com/payload.exe
        """
    )
    parser.add_argument(
        "ioc",
        nargs="?",
        help="Target IOC to inspect (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256)"
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to file (log, alert export, text) containing IOCs to extract and analyze"
    )
    parser.add_argument(
        "--format",
        choices=["card", "table", "json", "markdown", "wazuh-cdb"],
        default="card",
        help="Output visualization format (default: card for single, table for batch)"
    )
    parser.add_argument(
        "-o", "--out",
        help="Write report to an output file instead of stdout"
    )
    parser.add_argument(
        "--api-key",
        help="AbuseIPDB API key (defaults to ABUSEIPDB_API_KEY environment variable)"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass local SQLite cache and force fresh enrichment"
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Wipe the local ThreatPulse SQLite cache and exit"
    )
    parser.add_argument(
        "--defang",
        help="Quickly defang an indicator and print the result"
    )
    parser.add_argument(
        "--refang",
        help="Quickly refang an indicator and print the canonical form"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"ThreatPulse v{__version__}"
    )
    return parser


def main() -> int:
    # Ensure Windows console supports UTF-8 Unicode characters (borders, bullets, emoji)
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args()

    cache = ThreatCache()

    # Clear cache action
    if args.clear_cache:
        deleted = cache.clear()
        print(f"[*] ThreatPulse cache cleared successfully ({deleted} entries removed).")
        return 0

    # Quick defang / refang helpers
    if args.defang:
        print(defang(args.defang))
        return 0

    if args.refang:
        print(refang(args.refang))
        return 0

    use_cache = not args.no_cache
    iocs_to_check: List[str] = []

    # Single IOC from positional argument
    if args.ioc:
        iocs_to_check.append(args.ioc)

    # Batch IOCs from file
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[!] Error: File '{args.file}' not found.", file=sys.stderr)
            return 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            extracted = extract_iocs_from_text(content)
            for val, _ in extracted:
                if val not in iocs_to_check:
                    iocs_to_check.append(val)
        except Exception as e:
            print(f"[!] Error reading file: {e}", file=sys.stderr)
            return 1

    if not iocs_to_check:
        parser.print_help()
        return 1

    # Enrich all targets
    results: List[EnrichmentResult] = []
    for target in iocs_to_check:
        res = enrich_single_ioc(
            target,
            cache=cache,
            abuse_api_key=args.api_key,
            use_cache=use_cache
        )
        results.append(res)

    # Determine default format
    selected_format = args.format
    if len(results) > 1 and selected_format == "card" and not args.out:
        selected_format = "table"

    output_text = ""
    if selected_format == "card":
        output_text = "\n\n".join(render_terminal_card(r) for r in results)
    elif selected_format == "table":
        output_text = render_terminal_summary_table(results)
    elif selected_format == "json":
        output_text = render_json(results, pretty=True)
    elif selected_format == "markdown":
        output_text = render_markdown(results)
    elif selected_format == "wazuh-cdb":
        output_text = render_wazuh_cdb_list(results)

    # Write output or print to console
    if args.out:
        try:
            Path(args.out).write_text(output_text, encoding="utf-8")
            print(f"[+] Threat report successfully written to {args.out}")
        except Exception as e:
            print(f"[!] Error writing to {args.out}: {e}", file=sys.stderr)
            return 1
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
