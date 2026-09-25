"""Tests for the Sentinel detection engine."""

from datetime import datetime, timedelta

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.models import Event

BASE_TIME = datetime(2026, 9, 25, 10, 0, 0)


def make_failure(seconds: int) -> Event:
    """Create a failed SSH authentication event."""
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="ssh",
        event_type="authentication_failure",
        username="root",
        source_ip="192.168.1.50",
        message="Failed password for root",
    )


def test_engine_generates_alert() -> None:
    events = [
        make_failure(0),
        make_failure(5),
        make_failure(10),
        make_failure(15),
        make_failure(20),
    ]

    engine = DetectionEngine(
        rules=[
            SSHBruteForceRule(
                threshold=5,
                window_seconds=60,
            )
        ]
    )

    alerts = engine.analyze(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SSH-BRUTE-FORCE"


def test_engine_returns_no_alert_when_nothing_matches() -> None:
    events = [
        make_failure(0),
        make_failure(5),
        make_failure(10),
    ]

    engine = DetectionEngine(
        rules=[
            SSHBruteForceRule(
                threshold=5,
                window_seconds=60,
            )
        ]
    )

    alerts = engine.analyze(events)

    assert alerts == []
