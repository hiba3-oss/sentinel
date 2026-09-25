"""Threat intelligence analysis orchestration."""

from sentinel.intelligence.enricher import AlertEnricher
from sentinel.intelligence.result import EnrichedAlert
from sentinel.models import Alert, Event


class ThreatIntelAnalyzer:
    """Combine alerts with threat intelligence enrichment."""

    def __init__(self, enricher: AlertEnricher) -> None:
        self.enricher = enricher

    def analyze(
        self,
        alert: Alert,
        events: list[Event],
    ) -> EnrichedAlert:
        """Enrich an alert and calculate its adjusted risk score."""

        enrichment = self.enricher.enrich(alert, events)

        adjusted_risk = alert.risk_score

        for match in enrichment.matches:
            indicator = match.indicator

            if indicator.severity == "critical":
                adjusted_risk += 20
            elif indicator.severity == "high":
                adjusted_risk += 15
            elif indicator.severity == "medium":
                adjusted_risk += 10
            elif indicator.severity == "low":
                adjusted_risk += 5

            if indicator.confidence >= 90:
                adjusted_risk += 10
            elif indicator.confidence >= 75:
                adjusted_risk += 5

        adjusted_risk = min(adjusted_risk, 100)

        return EnrichedAlert(
            alert=alert,
            enrichment=enrichment,
            adjusted_risk_score=adjusted_risk,
        )
