"""Tests for Sentinel risk scoring."""

from sentinel.models import Alert, AlertSeverity
from sentinel.risk import RiskFactors, RiskScorer


def make_alert(
    severity: AlertSeverity = AlertSeverity.HIGH,
    risk_score: int = 70,
) -> Alert:
    """Create a test alert."""
    return Alert(
        id="ALT-0001",
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute-force detected",
        description="Repeated authentication failures.",
        severity=severity,
        risk_score=risk_score,
        source_ip="192.168.1.50",
    )


def test_risk_score_includes_severity_bonus() -> None:
    scorer = RiskScorer()
    alert = make_alert()

    score = scorer.calculate(alert)

    assert score == 90


def test_risk_score_is_capped_at_100() -> None:
    scorer = RiskScorer()
    alert = make_alert()

    factors = RiskFactors(
        base_score=90,
        repetition_bonus=20,
        privileged_account_bonus=20,
        known_malicious_ip_bonus=20,
    )

    score = scorer.calculate(alert, factors)

    assert score == 100


def test_risk_score_cannot_be_negative() -> None:
    scorer = RiskScorer()
    alert = make_alert()

    factors = RiskFactors(base_score=-50)

    score = scorer.calculate(alert, factors)

    assert score == 0


def test_risk_explanation_is_deterministic() -> None:
    scorer = RiskScorer()
    alert = make_alert()

    factors = RiskFactors(
        base_score=70,
        repetition_bonus=10,
        privileged_account_bonus=15,
        known_malicious_ip_bonus=5,
    )

    explanation = scorer.explain(alert, factors)

    assert explanation == {
        "base_score": 70,
        "repetition_bonus": 10,
        "privileged_account_bonus": 15,
        "known_malicious_ip_bonus": 5,
        "severity_bonus": 20,
    }
