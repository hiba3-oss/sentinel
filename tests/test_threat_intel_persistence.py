"""Tests for Sentinel SQLite threat intelligence persistence."""

from datetime import UTC, datetime

from sentinel.intelligence.enricher import AlertEnrichment, IOCMatch
from sentinel.intelligence.result import EnrichedAlert
from sentinel.models import Alert, AlertSeverity, Indicator
from sentinel.storage import SentinelDatabase


def _build_enriched_alert() -> EnrichedAlert:
    """Build a deterministic enriched alert for testing."""

    alert = Alert(
        id="ALT-TI-001",
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute force detected",
        description="Repeated failed SSH authentication.",
        severity=AlertSeverity.HIGH,
        risk_score=70,
        source_ip="10.10.10.50",
        username="admin",
        created_at=datetime(
            2026,
            9,
            25,
            12,
            0,
            tzinfo=UTC,
        ),
    )

    indicator = Indicator(
        value="10.10.10.50",
        indicator_type="ipv4",
        confidence=90,
        severity="high",
        source="sentinel-test-feed",
        description=(
            "Synthetic malicious SSH source used "
            "for Sentinel detection testing."
        ),
    )

    match = IOCMatch(
        indicator=indicator,
        matched_value="10.10.10.50",
        observable_type="source_ip",
    )

    enrichment = AlertEnrichment(
        alert_id=alert.id,
        matches=[match],
    )

    return EnrichedAlert(
        alert=alert,
        enrichment=enrichment,
        adjusted_risk_score=95,
    )


def test_save_enriched_alert_persists_threat_intelligence(
    tmp_path,
) -> None:
    """An enriched alert stores its threat intelligence match."""

    database = SentinelDatabase(
        tmp_path / "sentinel.db"
    )

    enriched_alert = _build_enriched_alert()

    database.save_enriched_alert(
        enriched_alert
    )

    matches = database.get_threat_intelligence_matches(
        enriched_alert.alert.id
    )

    assert len(matches) == 1

    match = matches[0]

    assert match["alert_id"] == "ALT-TI-001"
    assert match["indicator_value"] == "10.10.10.50"
    assert match["indicator_type"] == "ipv4"
    assert match["matched_value"] == "10.10.10.50"
    assert match["observable_type"] == "source_ip"
    assert match["confidence"] == 90
    assert match["severity"] == "high"
    assert match["source"] == "sentinel-test-feed"
    assert match["adjusted_risk_score"] == 95


def test_get_incident_threat_intelligence_returns_related_matches(
    tmp_path,
) -> None:
    """An incident returns threat intelligence from its alerts."""

    database = SentinelDatabase(
        tmp_path / "sentinel.db"
    )

    enriched_alert = _build_enriched_alert()

    database.save_enriched_alert(
        enriched_alert
    )

    from sentinel.models import Incident, IncidentStatus

    incident = Incident(
        incident_id="INC-TI-001",
        title="Threat intelligence incident",
        description="Incident created for TI persistence testing.",
        status=IncidentStatus.OPEN,
        severity="high",
        risk_score=95,
        source_ip="10.10.10.50",
        alert_ids=[
            enriched_alert.alert.id
        ],
    )

    database.save_incident(
        incident
    )

    matches = database.get_incident_threat_intelligence(
        incident.incident_id
    )

    assert len(matches) == 1

    match = matches[0]

    assert match["alert_id"] == "ALT-TI-001"
    assert match["indicator_value"] == "10.10.10.50"
    assert match["confidence"] == 90
    assert match["source"] == "sentinel-test-feed"
    assert match["adjusted_risk_score"] == 95
