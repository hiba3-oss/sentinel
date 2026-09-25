"""Threat intelligence matching and event enrichment."""

from sentinel.intelligence.store import IndicatorStore
from sentinel.models import Event, Indicator


class IOCMatcher:
    """Match event observables against known threat intelligence."""

    def __init__(self, store: IndicatorStore) -> None:
        self.store = store

    def match_event(self, event: Event) -> list[Indicator]:
        """Return all indicators matching the event observables."""

        matches: list[Indicator] = []
        seen: set[tuple[str, str]] = set()

        observables = [
            event.source_ip,
            event.destination_ip,
        ]

        for observable in observables:
            if not observable:
                continue

            indicator = self.store.lookup(observable)

            if indicator is None:
                continue

            key = (
                indicator.indicator_type.value,
                indicator.value.lower(),
            )

            if key in seen:
                continue

            seen.add(key)
            matches.append(indicator)

        return matches

    def match_observables(
        self,
        event: Event,
    ) -> list[tuple[str, str, Indicator]]:
        """Return matched indicators with their observable type and value."""

        matches: list[tuple[str, str, Indicator]] = []

        observables = [
            ("source_ip", event.source_ip),
            ("destination_ip", event.destination_ip),
        ]

        seen: set[tuple[str, str]] = set()

        for observable_type, value in observables:
            if not value:
                continue

            indicator = self.store.lookup(value)

            if indicator is None:
                continue

            key = (
                indicator.indicator_type.value,
                indicator.value.lower(),
            )

            if key in seen:
                continue

            seen.add(key)

            matches.append(
                (
                    observable_type,
                    value,
                    indicator,
                )
            )

        return matches
