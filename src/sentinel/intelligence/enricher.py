"""Threat intelligence enrichment models and services."""

from pydantic import BaseModel, ConfigDict, Field

from sentinel.intelligence.matcher import IOCMatcher
from sentinel.models import Alert, Event, Indicator


class IOCMatch(BaseModel):
    """A threat intelligence match associated with an alert."""

    model_config = ConfigDict(extra="forbid")

    indicator: Indicator
    matched_value: str = Field(min_length=1)
    observable_type: str = Field(min_length=1)


class AlertEnrichment(BaseModel):
    """Threat intelligence enrichment attached to an alert."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1)
    matches: list[IOCMatch] = Field(default_factory=list)

    @property
    def has_matches(self) -> bool:
        """Return whether at least one IOC matched."""

        return bool(self.matches)


class AlertEnricher:
    """Enrich generated alerts with threat intelligence indicators."""

    def __init__(self, matcher: IOCMatcher) -> None:
        self.matcher = matcher

    def enrich(
        self,
        alert: Alert,
        events: list[Event],
    ) -> AlertEnrichment:
        """Find threat intelligence indicators related to an alert."""

        matches: list[IOCMatch] = []
        seen: set[tuple[str, str]] = set()

        for event in events:
            for observable_type, value, indicator in (
                self.matcher.match_observables(event)
            ):
                key = (
                    indicator.indicator_type.value,
                    indicator.value.lower(),
                )

                if key in seen:
                    continue

                seen.add(key)

                matches.append(
                    IOCMatch(
                        indicator=indicator,
                        matched_value=value,
                        observable_type=observable_type,
                    )
                )

        return AlertEnrichment(
            alert_id=alert.id,
            matches=matches,
        )
