"""AbuseIPDB Threat Intelligence API client with graceful offline fallback."""

import json
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from threat_pulse.enrichers.base import BaseEnricher
from threat_pulse.models import IOCType


class AbuseIPDBEnricher(BaseEnricher):
    """Enriches IP addresses using AbuseIPDB APIv2 or fallback heuristics."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 3.0):
        super().__init__(name="abuseipdb")
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.timeout = timeout

    def can_enrich(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6)

    def enrich(self, ioc: str, ioc_type: IOCType) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "queried": False,
            "abuse_score": 0,
            "total_reports": 0,
            "country_code": "UNKNOWN",
            "usage_type": "Unknown",
            "isp": "Unknown",
            "is_whitelisted": False,
            "last_reported_at": None,
            "categories": [],
            "error": None,
        }

        if not self.api_key:
            data["error"] = "No API key configured (using local heuristics). Set ABUSEIPDB_API_KEY to enable live checks."
            return data

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90&verbose"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatPulse-SOC-CLI/1.0"
        }

        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    report = payload.get("data", {})
                    data["queried"] = True
                    data["abuse_score"] = report.get("abuseConfidenceScore", 0)
                    data["total_reports"] = report.get("totalReports", 0)
                    data["country_code"] = report.get("countryCode", "UNKNOWN")
                    data["usage_type"] = report.get("usageType", "Unknown")
                    data["isp"] = report.get("isp", "Unknown")
                    data["is_whitelisted"] = report.get("isWhitelisted", False)
                    data["last_reported_at"] = report.get("lastReportedAt")
        except urllib.error.HTTPError as e:
            data["error"] = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            data["error"] = f"Network error: {e.reason}"
        except Exception as e:
            data["error"] = str(e)

        return data
