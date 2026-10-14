"""Base classes for threat intelligence enrichers."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from threat_pulse.models import IOCType


class BaseEnricher(ABC):
    """Abstract interface for all threat intelligence and metadata enrichers."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def can_enrich(self, ioc_type: IOCType) -> bool:
        """Determine if this enricher supports the given IOC type."""
        pass

    @abstractmethod
    def enrich(self, ioc: str, ioc_type: IOCType) -> Dict[str, Any]:
        """Perform enrichment and return structured metadata dictionary."""
        pass
