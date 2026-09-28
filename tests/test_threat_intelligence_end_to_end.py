from pathlib import Path

from sentinel.incidents.ids import IncidentIdGenerator
from sentinel.intelligence.analyzer import ThreatIntelAnalyzer
from sentinel.intelligence.enricher import AlertEnricher
from sentinel.intelligence.matcher import IOCMatcher
from sentinel.intelligence.store import IndicatorStore
from sentinel.models import Alert, AlertSeverity, Event, Incident, IncidentStatus
from sentinel.storage.database import SentinelDatabase


def test_threat_intelligence_end_to_end(tmp_path):
    feed_path = Path("data/threat_intel/indicators.json")

    store = IndicatorStore(feed_path)
    matcher = IOCMatcher(store)
    enricher = AlertEnricher(matcher)
    analyzer = ThreatIntelAnalyzer(enricher)

    event = Event(
        source="test",
        event_type="authentication_failure",
        source_ip="10.10.10.50",
        username="admin",
        message="Failed SSH login",
    )

    alert = Alert(
        id="ALT-E2E-001",
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute force detected",
        description="Multiple failed SSH authentication attempts.",
        severity=AlertSeverity.HIGH,
        risk_score=70,
        source_ip="10.10.10.50",
        username="admin",
        event_ids=["EVT-E2E-001"],
    )

    enriched = analyzer.analyze(
        alert=alert,
        events=[event],
    )

    assert enriched.alert.id == "ALT-E2E-001"
    assert enriched.enrichment.has_matches is True
    assert len(enriched.enrichment.matches) == 1

    match = enriched.enrichment.matches[0]

    assert match.indicator.value == "10.10.10.50"
    assert match.indicator.confidence == 90
    assert match.indicator.severity == "high"
    assert match.indicator.source == "sentinel-test-feed"
    assert match.matched_value == "10.10.10.50"
    assert match.observable_type == "source_ip"

    assert enriched.adjusted_risk_score == 95

    database_path = tmp_path / "sentinel_e2e.db"
    database = SentinelDatabase(database_path)

    database.save_enriched_alert(enriched)

    incident = Incident(
        incident_id=IncidentIdGenerator().generate(),
        title="SSH brute force incident",
        description="Incident generated from a threat-intelligence-enriched alert.",
        status=IncidentStatus.OPEN,
        severity="high",
        risk_score=enriched.adjusted_risk_score,
        source_ip="10.10.10.50",
        alert_ids=[alert.id],
    )

    database.save_incident(incident)

    alert_matches = database.get_threat_intelligence_matches(
        alert.id,
    )

    assert len(alert_matches) == 1

    stored_match = alert_matches[0]

    assert stored_match["indicator_value"] == "10.10.10.50"
    assert stored_match["indicator_type"] == "ipv4"
    assert stored_match["matched_value"] == "10.10.10.50"
    assert stored_match["observable_type"] == "source_ip"
    assert stored_match["confidence"] == 90
    assert stored_match["severity"] == "high"
    assert stored_match["source"] == "sentinel-test-feed"
    assert stored_match["adjusted_risk_score"] == 95

    incident_matches = database.get_incident_threat_intelligence(
        incident.incident_id,
    )

    assert len(incident_matches) == 1

    incident_match = incident_matches[0]

    assert incident_match["alert_id"] == alert.id
    assert incident_match["indicator_value"] == "10.10.10.50"
    assert incident_match["confidence"] == 90
    assert incident_match["adjusted_risk_score"] == 95
