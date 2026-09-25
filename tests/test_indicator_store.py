"""Tests for the threat intelligence indicator store."""

import json

import pytest
from pydantic import ValidationError

from sentinel.intelligence.store import IndicatorStore
from sentinel.models import IndicatorType


@pytest.fixture
def feed_path(tmp_path):
    """Create a temporary IOC feed."""

    path = tmp_path / "indicators.json"

    indicators = [
        {
            "value": "10.10.10.50",
            "indicator_type": "ipv4",
            "confidence": 90,
            "severity": "high",
            "source": "test-feed",
            "description": "Synthetic test indicator.",
        },
        {
            "value": "evil.example.test",
            "indicator_type": "domain",
            "confidence": 80,
            "severity": "medium",
            "source": "test-feed",
            "description": "Synthetic test domain.",
        },
    ]

    path.write_text(json.dumps(indicators), encoding="utf-8")

    return path


def test_store_loads_indicators(feed_path) -> None:
    """The store should load all indicators."""

    store = IndicatorStore(feed_path)

    assert store.count() == 2


def test_store_lookup_by_value(feed_path) -> None:
    """An indicator should be found by its value."""

    store = IndicatorStore(feed_path)

    indicator = store.lookup("10.10.10.50")

    assert indicator is not None
    assert indicator.value == "10.10.10.50"
    assert indicator.indicator_type == IndicatorType.IPV4


def test_store_lookup_is_case_insensitive(feed_path) -> None:
    """Lookup should normalize indicator values."""

    store = IndicatorStore(feed_path)

    indicator = store.lookup("EVIL.EXAMPLE.TEST")

    assert indicator is not None
    assert indicator.value == "evil.example.test"


def test_store_lookup_by_type(feed_path) -> None:
    """Lookup can be restricted to an indicator type."""

    store = IndicatorStore(feed_path)

    indicator = store.lookup(
        "10.10.10.50",
        indicator_type="ipv4",
    )

    assert indicator is not None
    assert indicator.indicator_type == IndicatorType.IPV4


def test_store_returns_none_for_unknown_indicator(feed_path) -> None:
    """Unknown indicators should return None."""

    store = IndicatorStore(feed_path)

    assert store.lookup("8.8.8.8") is None


def test_store_returns_all_indicators(feed_path) -> None:
    """The store should return all loaded indicators."""

    store = IndicatorStore(feed_path)

    indicators = store.all_indicators()

    assert len(indicators) == 2
    assert {indicator.value for indicator in indicators} == {
        "10.10.10.50",
        "evil.example.test",
    }


def test_store_rejects_invalid_feed(tmp_path) -> None:
    """Invalid indicator data should fail validation."""

    path = tmp_path / "invalid.json"

    path.write_text(
        json.dumps(
            [
                {
                    "value": "",
                    "indicator_type": "ipv4",
                    "confidence": 90,
                    "severity": "high",
                    "source": "test-feed",
                    "description": "Invalid indicator.",
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        IndicatorStore(path)


