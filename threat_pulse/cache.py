"""Local SQLite caching layer for threat intelligence queries."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional, Dict, Any
from threat_pulse.models import EnrichmentResult, IOCType, RiskLevel


class ThreatCache:
    """Persistent local cache for IOC enrichment results to respect API rate limits."""

    def __init__(self, db_path: Optional[str] = None, ttl_seconds: int = 86400):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path.home() / ".threatpulse_cache.db"
        self.ttl = ttl_seconds
        self._init_db()

    def _init_db(self) -> None:
        """Create cache table if not already existing."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ioc_cache (
                        ioc TEXT PRIMARY KEY,
                        ioc_type TEXT,
                        data_json TEXT,
                        cached_at INTEGER
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

    def get(self, ioc: str) -> Optional[EnrichmentResult]:
        """Retrieve cached result if within TTL."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ioc_type, data_json, cached_at FROM ioc_cache WHERE ioc = ?",
                    (ioc.lower().strip(),)
                )
                row = cursor.fetchone()
                if not row:
                    return None

                ioc_type_str, data_json, cached_at = row
                if time.time() - cached_at > self.ttl:
                    return None  # Expired

                payload = json.loads(data_json)
                payload["cached"] = True
                return EnrichmentResult(
                    ioc=payload["ioc"],
                    ioc_type=IOCType(payload["ioc_type"]),
                    defanged=payload["defanged"],
                    risk_score=payload["risk_score"],
                    risk_level=RiskLevel(payload["risk_level"]),
                    verdict=payload["verdict"],
                    is_private=payload.get("is_private", False),
                    is_bogon=payload.get("is_bogon", False),
                    tags=payload.get("tags", []),
                    mitre_attack=payload.get("mitre_attack", []),
                    details=payload.get("details", {}),
                    recommendation=payload.get("recommendation", ""),
                    cached=True,
                    timestamp=payload.get("timestamp", "")
                )
            finally:
                conn.close()
        except Exception:
            return None

    def set(self, result: EnrichmentResult) -> None:
        """Save enrichment result into local SQLite cache."""
        try:
            payload_json = json.dumps(result.to_dict())
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO ioc_cache (ioc, ioc_type, data_json, cached_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (result.ioc.lower().strip(), result.ioc_type.value, payload_json, int(time.time()))
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

    def clear(self) -> int:
        """Clear all entries from cache and return count of deleted records."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT count(*) FROM ioc_cache")
                count = cursor.fetchone()[0]
                cursor.execute("DELETE FROM ioc_cache")
                conn.commit()
                return count
            finally:
                conn.close()
        except Exception:
            return 0
