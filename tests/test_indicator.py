"""Tests for threat intelligence indicators."""

import pytest
from pydantic import ValidationError

from sentinel.models import Indicator, IndicatorType


def make_indicator(**overrides) -> Indicator:
    """Build a valid indicator with optional overrides."""

    data = {
        "value": "10.10.10.50",
        "indicator_type": IndicatorType.IPV4,
        "confidence": 80,
        "severity": "high",
        "source": "local-test-feed",
        "description": "Known malicious test indicator",
    }
    data.update(overrides)
    return Indicator(**data)


def test_indicator_creation() -> None:
    """A valid indicator should be created correctly."""

    indicator = make_indicator()

    assert indicator.value == "10.10.10.50"
    assert indicator.indicator_type == IndicatorType.IPV4
    assert indicator.confidence == 80
    assert indicator.severity == "high"
    assert indicator.source == "local-test-feed"


@pytest.mark.parametrize(
    "indicator_type",
    [
        IndicatorType.IPV4,
        IndicatorType.IPV6,
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.SHA256,
    ],
)
def test_supported_indicator_types(indicator_type: IndicatorType) -> None:
    """All supported IOC types should be accepted."""

    indicator = make_indicator(indicator_type=indicator_type)

    assert indicator.indicator_type == indicator_type


@pytest.mark.parametrize("confidence", [0, 50, 100])
def test_confidence_boundary_values(confidence: int) -> None:
    """Confidence should accept the valid boundaries."""

    indicator = make_indicator(confidence=confidence)

    assert indicator.confidence == confidence


@pytest.mark.parametrize("confidence", [-1, 101])
def test_confidence_out_of_range(confidence: int) -> None:
    """Confidence outside 0-100 should be rejected."""

    with pytest.raises(ValidationError):
        make_indicator(confidence=confidence)


def test_empty_value_is_rejected() -> None:
    """An empty indicator value should be rejected."""

    with pytest.raises(ValidationError):
        make_indicator(value="")


def test_empty_source_is_rejected() -> None:
    """An empty source should be rejected."""

    with pytest.raises(ValidationError):
        make_indicator(source="")


def test_extra_fields_are_rejected() -> None:
    """Unexpected fields should be rejected."""

    with pytest.raises(ValidationError):
        make_indicator(unexpected_field="should fail")
