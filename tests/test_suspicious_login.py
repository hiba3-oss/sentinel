"""Tests for suspicious login detection."""

from datetime import datetime, timedelta

from sentinel.detection.rules.suspicious_login import SuspiciousLoginRule
from sentinel.models import Event

BASE_TIME = datetime(2026, 9, 25, 12, 0, 0)


def make_event(
    seconds: int,
    event_type: str,
    source_ip: str = "192.168.1.50",
) -> Event:
    """Create an authentication event."""

    message = "Failed password" if event_type == "authentication_failure" else "Accepted password"

    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="ssh",
        event_type=event_type,
        username="root",
        source_ip=source_ip,
        message=message,
    )


def test_suspicious_login_detected() -> None:
    events = [
        make_event(0, "authentication_failure"),
        make_event(5, "authentication_failure"),
        make_event(10, "authentication_failure"),
        make_event(15, "authentication_success"),
    ]

    rule = SuspiciousLoginRule(
        failure_threshold=3,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is not None
    assert alert.rule_id == "SUSPICIOUS-LOGIN"
    assert alert.severity.value == "critical"
    assert alert.risk_score == 85
    assert alert.source_ip == "192.168.1.50"


def test_successful_login_without_failures_is_not_suspicious() -> None:
    events = [
        make_event(0, "authentication_success"),
    ]

    rule = SuspiciousLoginRule(
        failure_threshold=3,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None


def test_below_failure_threshold_is_not_suspicious() -> None:
    events = [
        make_event(0, "authentication_failure"),
        make_event(5, "authentication_failure"),
        make_event(10, "authentication_success"),
    ]

    rule = SuspiciousLoginRule(
        failure_threshold=3,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None


def test_failures_outside_window_are_not_counted() -> None:
    events = [
        make_event(0, "authentication_failure"),
        make_event(20, "authentication_failure"),
        make_event(40, "authentication_failure"),
        make_event(100, "authentication_success"),
    ]

    rule = SuspiciousLoginRule(
        failure_threshold=3,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None


def test_different_ips_are_not_combined() -> None:
    events = [
        make_event(0, "authentication_failure", "192.168.1.50"),
        make_event(5, "authentication_failure", "192.168.1.51"),
        make_event(10, "authentication_failure", "192.168.1.50"),
        make_event(15, "authentication_failure", "192.168.1.51"),
        make_event(20, "authentication_success", "192.168.1.50"),
    ]

    rule = SuspiciousLoginRule(
        failure_threshold=3,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None
