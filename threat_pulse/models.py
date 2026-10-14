"""Data models and enums for ThreatPulse."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import datetime


class IOCType(str, Enum):
    """Supported indicator of compromise types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Categorized threat risk level based on aggregated score."""
    CLEAN = "CLEAN"          # 0 - 15
    LOW = "LOW"              # 16 - 39
    MEDIUM = "MEDIUM"        # 40 - 69
    HIGH = "HIGH"            # 70 - 89
    CRITICAL = "CRITICAL"    # 90 - 100


@dataclass
class EnrichmentResult:
    """Consolidated threat intelligence report for a single IOC."""
    ioc: str
    ioc_type: IOCType
    defanged: str
    risk_score: int
    risk_level: RiskLevel
    verdict: str
    is_private: bool = False
    is_bogon: bool = False
    tags: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    cached: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a serializable dictionary."""
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type.value,
            "defanged": self.defanged,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "verdict": self.verdict,
            "is_private": self.is_private,
            "is_bogon": self.is_bogon,
            "tags": self.tags,
            "mitre_attack": self.mitre_attack,
            "details": self.details,
            "recommendation": self.recommendation,
            "cached": self.cached,
            "timestamp": self.timestamp,
        }
