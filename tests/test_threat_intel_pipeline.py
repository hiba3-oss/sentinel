"""End-to-end tests for Sentinel threat intelligence analysis."""

from pathlib import Path

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.detection.rules.port_scan import PortScanRule
from sentinel.detection.rules.suspicious_login import SuspiciousLoginRule
from sentinel.ingestion.parser import parse_lines
from sentinel.intelligence import (
    AlertEnricher,
    IndicatorStore,
    IOCMatcher,
    ThreatIntelAnalyzer,
)

LOG_PATH = Path("data/sample_logs/incident.log")
FEED_PATH = Path("data/threat_intel/indicators.json")


def build_detection_engine() -> DetectionEngine:
    """Build the production detection engine used by the integration test."""

    return DetectionEngine(
        rules=[
            SSHBruteForceRule(),
            PortScanRule(),
            SuspiciousLoginRule(),
        ]
    )


def build_threat_intel_analyzer() -> ThreatIntelAnalyzer:
    """Build the threat intelligence analysis pipeline."""

    store = IndicatorStore(FEED_PATH)
    matcher = IOCMatcher(store)
    enricher = AlertEnricher(matcher)

    return ThreatIntelAnalyzer(enricher)


def test_incident_log_flows_through_detection_and_threat_intelligence() -> None:
    """The incident sample should produce IOC-enriched alerts."""

    lines = LOG_PATH.read_text(encoding="utf-8-sig").splitlines()
    events = parse_lines(lines)

    assert len(events) == 6

    alerts = build_detection_engine().analyze(events)

    assert len(alerts) == 2

    analyzer = build_threat_intel_analyzer()

    enriched_alerts = [
        analyzer.analyze(alert, events)
        for alert in alerts
    ]

    assert len(enriched_alerts) == 2

    for result in enriched_alerts:
        assert result.has_threat_intelligence is True
        assert len(result.enrichment.matches) == 1

        match = result.enrichment.matches[0]

        assert match.matched_value == "10.10.10.50"
        assert match.observable_type == "source_ip"
        assert match.indicator.confidence == 90
        assert match.indicator.severity == "high"
        assert result.adjusted_risk_score >= result.alert.risk_score
        assert result.adjusted_risk_score <= 100


def test_threat_intelligence_does_not_change_original_alert() -> None:
    """Enrichment must preserve the original detection alert."""

    lines = LOG_PATH.read_text(encoding="utf-8-sig").splitlines()
    events = parse_lines(lines)

    alerts = build_detection_engine().analyze(events)

    analyzer = build_threat_intel_analyzer()
    result = analyzer.analyze(alerts[0], events)

    assert result.alert is alerts[0]
    assert result.alert.risk_score < result.adjusted_risk_score


