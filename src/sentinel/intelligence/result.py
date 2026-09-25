"""Enriched security alert model."""

from pydantic import BaseModel, ConfigDict, Field

from sentinel.intelligence.enricher import AlertEnrichment
from sentinel.models import Alert


class EnrichedAlert(BaseModel):
    """Security alert combined with threat intelligence enrichment."""

    model_config = ConfigDict(extra="forbid")

    alert: Alert
    enrichment: AlertEnrichment
    adjusted_risk_score: int = Field(ge=0, le=100)

    @property
    def has_threat_intelligence(self) -> bool:
        """Return whether threat intelligence matched the alert."""

        return self.enrichment.has_matches
