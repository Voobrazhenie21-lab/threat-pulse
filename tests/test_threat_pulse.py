"""Comprehensive test suite for ThreatPulse."""

import os
import tempfile
import pytest
from pathlib import Path

from threat_pulse.cache import ThreatCache
from threat_pulse.detector import (
    detect_ioc_type,
    defang,
    refang,
    extract_iocs_from_text,
)
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
    calculate_shannon_entropy,
    analyze_ip_heuristics,
    analyze_domain_heuristics,
    analyze_url_heuristics,
)
from threat_pulse.models import IOCType, RiskLevel, EnrichmentResult
from threat_pulse.cli import enrich_single_ioc, build_parser


# ==========================================
# 1. Detector & Defanging Tests
# ==========================================

def test_detect_ioc_type_ipv4():
    assert detect_ioc_type("192.168.1.1") == IOCType.IPV4
    assert detect_ioc_type("8.8.8.8") == IOCType.IPV4
    assert detect_ioc_type("185[.]220[.]101[.]5") == IOCType.IPV4


def test_detect_ioc_type_ipv6():
    assert detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == IOCType.IPV6
    assert detect_ioc_type("::1") == IOCType.IPV6


def test_detect_ioc_type_hashes():
    assert detect_ioc_type("84c82835a5d21bbcf75a61706d8ab549") == IOCType.MD5
    assert detect_ioc_type("49b788647055a40bbd21b79313ea5fa2e6ff3f1b") == IOCType.SHA1
    assert detect_ioc_type("ed01ebf83334a19373140c0df0ddb638ec6d7e99f8788f5b8978cb8c4cb5ffce") == IOCType.SHA256


def test_detect_ioc_type_domains_and_urls():
    assert detect_ioc_type("evil-domain.top") == IOCType.DOMAIN
    assert detect_ioc_type("sub.bank-login.xyz") == IOCType.DOMAIN
    assert detect_ioc_type("https://evil.com/payload.exe") == IOCType.URL
    assert detect_ioc_type("hxxps://evil[.]com/drop.sh") == IOCType.URL


def test_defang_and_refang():
    raw_url = "https://malicious.com/test"
    defanged = defang(raw_url)
    assert defanged == "hxxps://malicious[.]com/test"
    assert refang(defanged) == raw_url

    ip = "1.1.1.1"
    assert defang(ip) == "1[.]1[.]1[.]1"
    assert refang("1[.]1[.]1[.]1") == "1.1.1.1"
    assert refang("1(.)1(.)1(.)1") == "1.1.1.1"


def test_extract_iocs_from_text():
    sample_text = """
    Found connection from 192.168.1.50 to 185.220.101.5 on port 443.
    Downloaded file from https://c2-server.top/loader.exe with hash:
    ed01ebf83334a19373140c0df0ddb638ec6d7e99f8788f5b8978cb8c4cb5ffce
    """
    extracted = extract_iocs_from_text(sample_text)
    values = [val for val, _ in extracted]

    assert "192.168.1.50" in values
    assert "185.220.101.5" in values
    assert "https://c2-server.top/loader.exe" in values
    assert "ed01ebf83334a19373140c0df0ddb638ec6d7e99f8788f5b8978cb8c4cb5ffce" in values


# ==========================================
# 2. Heuristics Tests
# ==========================================

def test_shannon_entropy():
    # Low entropy (repetitive)
    low_entropy = calculate_shannon_entropy("aaaaaaaa")
    assert low_entropy == 0.0

    # High entropy (random DGA-like string)
    high_entropy = calculate_shannon_entropy("q9w8e7r6t5y4u3i2o1p0")
    assert high_entropy > 4.0


def test_analyze_ip_heuristics():
    # Private RFC 1918
    res_private = analyze_ip_heuristics("10.50.2.1")
    assert res_private["is_rfc1918"] is True
    assert res_private["is_private"] is True

    res_192 = analyze_ip_heuristics("192.168.1.1")
    assert res_192["is_rfc1918"] is True

    # Loopback
    res_loopback = analyze_ip_heuristics("127.0.0.1")
    assert res_loopback["is_loopback"] is True
    assert res_loopback["is_bogon"] is True

    # Public IP
    res_public = analyze_ip_heuristics("8.8.8.8")
    assert res_public["is_rfc1918"] is False
    assert res_public["is_private"] is False
    assert res_public["is_bogon"] is False


def test_analyze_domain_heuristics():
    # DGA Domain
    dga_res = analyze_domain_heuristics("xjq87hsdkjhwq987123.top")
    assert dga_res["is_dga_candidate"] is True
    assert dga_res["suspicious_tld"] is True

    # Normal Domain
    clean_res = analyze_domain_heuristics("google.com")
    assert clean_res["is_dga_candidate"] is False
    assert clean_res["suspicious_tld"] is False


def test_analyze_url_heuristics():
    # Raw IP in URL
    raw_ip_url = analyze_url_heuristics("http://185.220.101.5:8080/malware.exe")
    assert raw_ip_url["is_raw_ip_host"] is True
    assert raw_ip_url["has_executable_extension"] is True
    assert raw_ip_url["uncommon_port"] is False  # 8080 is standard web alt


# ==========================================
# 3. Enricher Tests
# ==========================================

def test_network_enricher_tor_and_scanners():
    enricher = NetworkEnricher(timeout=1.0)

    # Tor Exit Node
    tor_res = enricher.enrich("185.220.101.5", IOCType.IPV4)
    assert tor_res["is_tor_exit"] is True

    # Known Scanner
    scanner_res = enricher.enrich("198.20.69.74", IOCType.IPV4)
    assert scanner_res["is_known_scanner"] is True
    assert "Shadowserver" in scanner_res["scanner_name"]


def test_malware_hash_enricher():
    enricher = MalwareHashEnricher()

    # WannaCry SHA256
    wannacry = enricher.enrich("ed01ebf83334a19373140c0df0ddb638ec6d7e99f8788f5b8978cb8c4cb5ffce", IOCType.SHA256)
    assert wannacry["is_known_malware"] is True
    assert "WannaCry" in wannacry["family"]

    # Mimikatz SHA256
    mimikatz = enricher.enrich("a60c52bb53a5c0b89cf53dc5bb7c2c129219b16e4ee7d9c6e3b5e43a9b1c9d2f", IOCType.SHA256)
    assert mimikatz["is_known_malware"] is True
    assert "Mimikatz" in mimikatz["family"]

    # Clean unknown hash
    unknown = enricher.enrich("1111111111111111111111111111111111111111111111111111111111111111", IOCType.SHA256)
    assert unknown["is_known_malware"] is False


def test_abuseipdb_offline_graceful_fallback():
    # Without API key, should gracefully return error without raising exception
    enricher = AbuseIPDBEnricher(api_key=None)
    res = enricher.enrich("8.8.8.8", IOCType.IPV4)
    assert res["queried"] is False
    assert "No API key" in res["error"]


# ==========================================
# 4. End-to-End Scoring & Integration Tests
# ==========================================

def test_enrich_single_ioc_private_ip():
    res = enrich_single_ioc("192.168.1.100", use_cache=False)
    assert res.risk_level == RiskLevel.CLEAN
    assert res.risk_score == 0
    assert "RFC1918-Private" in res.tags


def test_enrich_single_ioc_tor_node():
    res = enrich_single_ioc("185.220.101.5", use_cache=False)
    assert res.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert res.risk_score >= 85
    assert "Tor-Exit-Node" in res.tags
    assert any("T1090.003" in m for m in res.mitre_attack)


def test_enrich_single_ioc_wannacry():
    res = enrich_single_ioc("84c82835a5d21bbcf75a61706d8ab549", use_cache=False)
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.risk_score == 100
    assert "WannaCry" in res.verdict
    assert any("T1486" in m for m in res.mitre_attack)


# ==========================================
# 5. Local Cache Tests
# ==========================================

def test_threat_cache():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        cache = ThreatCache(db_path=db_path, ttl_seconds=3600)
        assert cache.get("1.2.3.4") is None

        # Create dummy result
        result = EnrichmentResult(
            ioc="1.2.3.4",
            ioc_type=IOCType.IPV4,
            defanged="1[.]2[.]3[.]4",
            risk_score=75,
            risk_level=RiskLevel.HIGH,
            verdict="Test Threat",
            tags=["TestTag"],
            mitre_attack=["T1110"]
        )
        cache.set(result)

        cached_entry = cache.get("1.2.3.4")
        assert cached_entry is not None
        assert cached_entry.risk_score == 75
        assert cached_entry.cached is True

        # Test clear
        count = cache.clear()
        assert count == 1
        assert cache.get("1.2.3.4") is None
    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except OSError:
            pass


# ==========================================
# 6. Formatters Tests
# ==========================================

def test_formatters():
    result = EnrichmentResult(
        ioc="185.220.101.5",
        ioc_type=IOCType.IPV4,
        defanged="185[.]220[.]101[.]5",
        risk_score=85,
        risk_level=RiskLevel.HIGH,
        verdict="Tor Exit Node",
        tags=["Tor-Exit-Node"],
        mitre_attack=["T1090.003: Multi-hop Proxy"],
        recommendation="Block at firewall"
    )

    card = render_terminal_card(result)
    assert "185[.]220[.]101[.]5" in card
    assert "HIGH" in card
    assert "T1090.003" in card

    table = render_terminal_summary_table([result])
    assert "185[.]220[.]101[.]5" in table

    json_str = render_json([result])
    assert '"risk_score": 85' in json_str

    md_str = render_markdown([result])
    assert "| `185[.]220[.]101[.]5` |" in md_str

    cdb_str = render_wazuh_cdb_list([result])
    assert "185.220.101.5:HIGH_85:Tor-Exit-Node" in cdb_str
