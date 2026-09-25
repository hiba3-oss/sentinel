"""Tests for the Alert model."""

import pytest
from pydantic import ValidationError

from sentinel.models import Alert, AlertSeverity


def test_alert_creation() -> None:
    alert = Alert(
        id="ALT-0001",
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute-force detected",
        description="Multiple failed SSH authentication attempts detected.",
        severity=AlertSeverity.HIGH,
        risk_score=85,
        source_ip="192.168.1.50",
        username="root",
        event_ids=["EVT-0001", "EVT-0002"],
    )

    assert alert.id == "ALT-0001"
    assert alert.rule_id == "SSH-BRUTE-FORCE"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.risk_score == 85
    assert len(alert.event_ids) == 2


def test_alert_default_event_ids() -> None:
    alert = Alert(
        id="ALT-0002",
        rule_id="TEST-RULE",
        title="Test alert",
        description="Test description.",
        severity=AlertSeverity.LOW,
        risk_score=10,
    )

    assert alert.event_ids == []
    assert alert.created_at is not None


def test_alert_rejects_invalid_risk_score() -> None:
    with pytest.raises(ValidationError):
        Alert(
            id="ALT-0003",
            rule_id="TEST-RULE",
            title="Invalid alert",
            description="Invalid risk score.",
            severity=AlertSeverity.MEDIUM,
            risk_score=101,
        )


def test_alert_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Alert(
            id="ALT-0004",
            rule_id="TEST-RULE",
            title="Test alert",
            description="Test description.",
            severity=AlertSeverity.LOW,
            risk_score=10,
            unknown_field="unexpected",
        )
