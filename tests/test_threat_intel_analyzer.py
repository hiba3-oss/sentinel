"""Tests for threat intelligence analysis."""

from pathlib import Path

from sentinel.intelligence import (
    AlertEnricher,
    IndicatorStore,
    IOCMatcher,
    ThreatIntelAnalyzer,
)
from sentinel.models import Alert, AlertSeverity, Event

FEED_PATH = Path("data/threat_intel/indicators.json")


def make_analyzer() -> ThreatIntelAnalyzer:
    """Create an analyzer using the local synthetic threat feed."""

    store = IndicatorStore(FEED_PATH)
    matcher = IOCMatcher(store)
    enricher = AlertEnricher(matcher)

    return ThreatIntelAnalyzer(enricher)


def make_alert(risk_score: int = 70) -> Alert:
    """Create a representative alert."""

    return Alert(
        id="ALT-ANALYZER-001",
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute-force detected",
        description="Repeated authentication failures detected.",
        severity=AlertSeverity.HIGH,
        risk_score=risk_score,
        source_ip="10.10.10.50",
        username="root",
    )


def test_analyzer_without_ioc_preserves_risk() -> None:
    """An alert without IOC matches keeps its original risk score."""

    event = Event(
        source="test",
        event_type="authentication_failure",
        source_ip="172.16.50.25",
        message="Failed authentication",
    )

    result = make_analyzer().analyze(make_alert(70), [event])

    assert result.has_threat_intelligence is False
    assert result.adjusted_risk_score == 70


def test_high_confidence_high_ioc_increases_risk() -> None:
    """A high-confidence high-severity IOC increases the risk."""

    event = Event(
        source="test",
        event_type="authentication_failure",
        source_ip="10.10.10.50",
        message="Failed authentication",
    )

    result = make_analyzer().analyze(make_alert(70), [event])

    assert result.has_threat_intelligence is True
    assert result.adjusted_risk_score == 95


def test_medium_ioc_increases_risk() -> None:
    """A medium-confidence medium-severity IOC increases the risk."""

    event = Event(
        source="test",
        event_type="network_connection",
        destination_ip="192.168.1.50",
        message="Connection attempt",
    )

    result = make_analyzer().analyze(make_alert(50), [event])

    assert result.has_threat_intelligence is True
    assert result.adjusted_risk_score == 60


def test_risk_score_is_capped_at_100() -> None:
    """Threat intelligence enrichment cannot push risk above 100."""

    event = Event(
        source="test",
        event_type="authentication_failure",
        source_ip="10.10.10.50",
        message="Failed authentication",
    )

    result = make_analyzer().analyze(make_alert(95), [event])

    assert result.adjusted_risk_score == 100


def test_result_keeps_original_alert() -> None:
    """The enriched result retains the original Alert object."""

    alert = make_alert(70)

    event = Event(
        source="test",
        event_type="authentication_failure",
        source_ip="10.10.10.50",
        message="Failed authentication",
    )

    result = make_analyzer().analyze(alert, [event])

    assert result.alert.id == alert.id
    assert result.alert.rule_id == alert.rule_id
    assert result.alert.risk_score == 70

