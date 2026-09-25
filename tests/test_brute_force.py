"""Tests for SSH brute-force detection."""

from datetime import datetime, timedelta

from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.models import Event

BASE_TIME = datetime(2026, 9, 25, 10, 0, 0)


def make_failure(
    seconds: int,
    source_ip: str = "192.168.1.50",
    username: str = "root",
) -> Event:
    """Create a failed SSH authentication event."""
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="ssh",
        event_type="authentication_failure",
        username=username,
        source_ip=source_ip,
        message=f"Failed password for {username}",
    )


def test_brute_force_detected() -> None:
    events = [
        make_failure(0),
        make_failure(5),
        make_failure(10),
        make_failure(15),
        make_failure(20),
    ]

    rule = SSHBruteForceRule(threshold=5, window_seconds=60)

    alert = rule.evaluate(events)

    assert alert is not None
    assert alert.rule_id == "SSH-BRUTE-FORCE"
    assert alert.severity.value == "high"
    assert alert.risk_score == 70
    assert alert.source_ip == "192.168.1.50"


def test_brute_force_not_detected_below_threshold() -> None:
    events = [
        make_failure(0),
        make_failure(5),
        make_failure(10),
        make_failure(15),
    ]

    rule = SSHBruteForceRule(threshold=5, window_seconds=60)

    alert = rule.evaluate(events)

    assert alert is None


def test_brute_force_not_detected_outside_time_window() -> None:
    events = [
        make_failure(0),
        make_failure(20),
        make_failure(40),
        make_failure(80),
        make_failure(100),
    ]

    rule = SSHBruteForceRule(threshold=5, window_seconds=60)

    alert = rule.evaluate(events)

    assert alert is None


def test_different_ips_are_not_combined() -> None:
    events = [
        make_failure(0, "192.168.1.50"),
        make_failure(5, "192.168.1.51"),
        make_failure(10, "192.168.1.50"),
        make_failure(15, "192.168.1.51"),
        make_failure(20, "192.168.1.50"),
        make_failure(25, "192.168.1.51"),
        make_failure(30, "192.168.1.50"),
        make_failure(35, "192.168.1.51"),
    ]

    rule = SSHBruteForceRule(threshold=5, window_seconds=60)

    alert = rule.evaluate(events)

    assert alert is None


def test_successful_login_is_not_counted() -> None:
    events = [
        make_failure(0),
        make_failure(5),
        make_failure(10),
        Event(
            timestamp=BASE_TIME + timedelta(seconds=15),
            source="ssh",
            event_type="authentication_success",
            username="root",
            source_ip="192.168.1.50",
            message="Accepted password for root",
        ),
        make_failure(20),
    ]

    rule = SSHBruteForceRule(threshold=4, window_seconds=60)

    alert = rule.evaluate(events)

    assert alert is not None
    assert alert.rule_id == "SSH-BRUTE-FORCE"
