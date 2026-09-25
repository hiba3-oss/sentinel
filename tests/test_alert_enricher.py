"""Tests for threat intelligence alert enrichment."""

from pathlib import Path

from sentinel.intelligence import AlertEnricher, IndicatorStore, IOCMatcher
from sentinel.models import Alert, AlertSeverity, Event

FEED_PATH = Path("data/threat_intel/indicators.json")


def make_alert() -> Alert:
    """Create a representative alert for enrichment tests."""

    return Alert(
        id="ALT-TEST-001",
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute-force detected",
        description="Repeated SSH authentication failures detected.",
        severity=AlertSeverity.HIGH,
        risk_score=90,
        source_ip="10.10.10.50",
        username="root",
        event_ids=[],
    )


def make_enricher() -> AlertEnricher:
    """Create an alert enricher using the local synthetic feed."""

    store = IndicatorStore(FEED_PATH)
    matcher = IOCMatcher(store)

    return AlertEnricher(matcher)


def test_enrich_matches_source_ip() -> None:
    """An indicator matching the source IP should be returned."""

    event = Event(
        source="test",
        event_type="authentication_failure",
        username="root",
        source_ip="10.10.10.50",
        message="Failed password for root",
    )

    enrichment = make_enricher().enrich(make_alert(), [event])

    assert enrichment.alert_id == "ALT-TEST-001"
    assert enrichment.has_matches is True
    assert len(enrichment.matches) == 1

    match = enrichment.matches[0]

    assert match.matched_value == "10.10.10.50"
    assert match.observable_type == "source_ip"
    assert match.indicator.confidence == 90
    assert match.indicator.severity == "high"


def test_enrich_matches_destination_ip() -> None:
    """An indicator matching the destination IP should be returned."""

    event = Event(
        source="test",
        event_type="network_connection",
        source_ip="10.10.10.99",
        destination_ip="192.168.1.50",
        message="Connection attempt",
    )

    enrichment = make_enricher().enrich(make_alert(), [event])

    assert enrichment.has_matches is True
    assert len(enrichment.matches) == 1

    match = enrichment.matches[0]

    assert match.matched_value == "192.168.1.50"
    assert match.observable_type == "destination_ip"
    assert match.indicator.confidence == 70
    assert match.indicator.severity == "medium"


def test_enrich_returns_no_match_for_unknown_ip() -> None:
    """Unknown observables should produce an empty enrichment."""

    event = Event(
        source="test",
        event_type="network_connection",
        source_ip="172.16.50.25",
        destination_ip="172.16.50.30",
        message="Normal connection",
    )

    enrichment = make_enricher().enrich(make_alert(), [event])

    assert enrichment.has_matches is False
    assert enrichment.matches == []


def test_enrich_can_match_multiple_iocs() -> None:
    """Multiple events can produce multiple distinct IOC matches."""

    events = [
        Event(
            source="test",
            event_type="authentication_failure",
            source_ip="10.10.10.50",
            message="Failed SSH authentication",
        ),
        Event(
            source="test",
            event_type="network_connection",
            destination_ip="192.168.1.50",
            message="Connection attempt",
        ),
    ]

    enrichment = make_enricher().enrich(make_alert(), events)

    assert enrichment.has_matches is True
    assert len(enrichment.matches) == 2

    matched_values = {
        match.matched_value
        for match in enrichment.matches
    }

    assert matched_values == {
        "10.10.10.50",
        "192.168.1.50",
    }


def test_enrich_deduplicates_same_indicator() -> None:
    """The same IOC appearing in multiple events should be returned once."""

    events = [
        Event(
            source="test",
            event_type="authentication_failure",
            source_ip="10.10.10.50",
            message="Failed SSH authentication",
        ),
        Event(
            source="test",
            event_type="authentication_failure",
            source_ip="10.10.10.50",
            message="Failed SSH authentication",
        ),
    ]

    enrichment = make_enricher().enrich(make_alert(), events)

    assert len(enrichment.matches) == 1
    assert enrichment.matches[0].matched_value == "10.10.10.50"


def test_enrich_preserves_observable_type() -> None:
    """The enrichment must identify which observable produced the match."""

    event = Event(
        source="test",
        event_type="network_connection",
        source_ip="172.16.10.10",
        destination_ip="10.10.10.50",
        message="Connection attempt",
    )

    enrichment = make_enricher().enrich(make_alert(), [event])

    assert len(enrichment.matches) == 1

    match = enrichment.matches[0]

    assert match.observable_type == "destination_ip"
    assert match.matched_value == "10.10.10.50"


