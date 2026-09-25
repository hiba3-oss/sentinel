"""Threat intelligence indicator store."""

import json
from pathlib import Path

from sentinel.models import Indicator


class IndicatorStore:
    """Load and query threat intelligence indicators."""

    def __init__(self, feed_path: Path) -> None:
        self.feed_path = feed_path
        self._indicators: dict[tuple[str, str], Indicator] = {}
        self._load()

    def _load(self) -> None:
        """Load indicators from the configured JSON feed."""

        with self.feed_path.open("r", encoding="utf-8-sig") as file:
            raw_indicators = json.load(file)

        for raw_indicator in raw_indicators:
            indicator = Indicator.model_validate(raw_indicator)
            key = (indicator.indicator_type.value, indicator.value.lower())
            self._indicators[key] = indicator

    def lookup(
        self,
        value: str,
        indicator_type: str | None = None,
    ) -> Indicator | None:
        """Find an indicator by value and optionally by type."""

        normalized_value = value.strip().lower()

        if indicator_type is not None:
            key = (indicator_type.lower(), normalized_value)
            return self._indicators.get(key)

        for (_stored_type, stored_value), indicator in self._indicators.items():
            if stored_value == normalized_value:
                return indicator

        return None

    def all_indicators(self) -> list[Indicator]:
        """Return all loaded indicators."""

        return list(self._indicators.values())

    def count(self) -> int:
        """Return the number of loaded indicators."""

        return len(self._indicators)

