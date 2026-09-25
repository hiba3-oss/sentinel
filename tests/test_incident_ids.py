"""Tests for Sentinel incident identifier generation."""

from sentinel.incidents.ids import IncidentIdGenerator


def test_generator_creates_expected_format() -> None:
    """Generated identifiers use the Sentinel incident format."""

    generator = IncidentIdGenerator()

    incident_id = generator.generate()

    assert incident_id.startswith("INC-")
    assert len(incident_id) == 19


def test_generator_creates_unique_ids() -> None:
    """Generated identifiers are unique within one generator."""

    generator = IncidentIdGenerator()

    first = generator.generate()
    second = generator.generate()

    assert first != second


def test_generator_increments_sequence() -> None:
    """The numeric sequence increments for each generated ID."""

    generator = IncidentIdGenerator()

    first = generator.generate()
    second = generator.generate()

    assert first.endswith("000001")
    assert second.endswith("000002")
