"""Tests for Sentinel incidents."""

from sentinel.incidents import IncidentCorrelator
from sentinel.models import Alert, AlertSeverity, IncidentStatus


def make_alert(
    alert_id: str,
    rule_id: str,
    severity: AlertSeverity,
    risk_score: int,
    source_ip: str | None,
) -> Alert:
    """Create a test alert."""

    return Alert(
        id=alert_id,
        rule_id=rule_id,
        title="Test alert",
        description="Test security alert",
        severity=severity,
        risk_score=risk_score,
        source_ip=source_ip,
    )


def test_alerts_from_same_ip_are_correlated() -> None:
    alerts = [
        make_alert(
            "ALT-001",
            "SSH-BRUTE-FORCE",
            AlertSeverity.HIGH,
            90,
            "192.168.1.50",
        ),
        make_alert(
            "ALT-002",
            "SUSPICIOUS-LOGIN",
            AlertSeverity.CRITICAL,
            100,
            "192.168.1.50",
        ),
    ]

    incidents = IncidentCorrelator().correlate(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.source_ip == "192.168.1.50"
    assert incident.status == IncidentStatus.OPEN
    assert incident.severity == "critical"
    assert incident.risk_score == 100
    assert incident.alert_ids == [
        "ALT-001",
        "ALT-002",
    ]


def test_alerts_from_different_ips_create_different_incidents() -> None:
    alerts = [
        make_alert(
            "ALT-001",
            "SSH-BRUTE-FORCE",
            AlertSeverity.HIGH,
            90,
            "192.168.1.50",
        ),
        make_alert(
            "ALT-002",
            "PORT-SCAN",
            AlertSeverity.HIGH,
            95,
            "10.0.0.20",
        ),
    ]

    incidents = IncidentCorrelator().correlate(alerts)

    assert len(incidents) == 2

    assert incidents[0].source_ip == "192.168.1.50"
    assert incidents[1].source_ip == "10.0.0.20"


def test_empty_alert_list_creates_no_incidents() -> None:
    incidents = IncidentCorrelator().correlate([])

    assert incidents == []


def test_single_alert_creates_incident() -> None:
    alerts = [
        make_alert(
            "ALT-001",
            "PORT-SCAN",
            AlertSeverity.HIGH,
            95,
            "10.0.0.20",
        )
    ]

    incidents = IncidentCorrelator().correlate(alerts)

    assert len(incidents) == 1
    assert incidents[0].incident_id.startswith("INC-")
    assert incidents[0].alert_ids == ["ALT-001"]


def test_risk_score_increases_when_multiple_alerts_are_correlated() -> None:
    alerts = [
        make_alert(
            "ALT-001",
            "SSH-BRUTE-FORCE",
            AlertSeverity.HIGH,
            70,
            "192.168.1.50",
        ),
        make_alert(
            "ALT-002",
            "PORT-SCAN",
            AlertSeverity.HIGH,
            80,
            "192.168.1.50",
        ),
    ]

    incidents = IncidentCorrelator().correlate(alerts)

    assert incidents[0].risk_score == 85
