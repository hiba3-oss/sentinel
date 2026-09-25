"""Tests for port scan detection."""

from datetime import datetime, timedelta

from sentinel.detection.rules.port_scan import PortScanRule
from sentinel.models import Event

BASE_TIME = datetime(2026, 9, 25, 10, 0, 0)


def make_connection(
    seconds: int,
    port: int,
    source_ip: str = "192.168.1.50",
) -> Event:
    """Create a network connection event."""

    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source="network",
        event_type="connection",
        source_ip=source_ip,
        destination_ip="192.168.1.10",
        destination_port=port,
        message=f"TCP connection to port {port}",
    )


def test_port_scan_detected() -> None:
    events = [
        make_connection(0, 22),
        make_connection(5, 80),
        make_connection(10, 443),
        make_connection(15, 445),
        make_connection(20, 8080),
    ]

    rule = PortScanRule(
        threshold=5,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is not None
    assert alert.rule_id == "PORT-SCAN"
    assert alert.severity.value == "high"
    assert alert.source_ip == "192.168.1.50"
    assert alert.risk_score == 75


def test_port_scan_not_detected_below_threshold() -> None:
    events = [
        make_connection(0, 22),
        make_connection(5, 80),
        make_connection(10, 443),
        make_connection(15, 445),
    ]

    rule = PortScanRule(
        threshold=5,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None


def test_repeated_same_port_is_not_port_scan() -> None:
    events = [
        make_connection(0, 22),
        make_connection(5, 22),
        make_connection(10, 22),
        make_connection(15, 22),
        make_connection(20, 22),
        make_connection(25, 22),
    ]

    rule = PortScanRule(
        threshold=5,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None


def test_port_scan_outside_time_window() -> None:
    events = [
        make_connection(0, 22),
        make_connection(20, 80),
        make_connection(40, 443),
        make_connection(80, 445),
        make_connection(100, 8080),
    ]

    rule = PortScanRule(
        threshold=5,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None


def test_different_ips_are_not_combined() -> None:
    events = [
        make_connection(0, 22, "192.168.1.50"),
        make_connection(5, 80, "192.168.1.51"),
        make_connection(10, 443, "192.168.1.50"),
        make_connection(15, 445, "192.168.1.51"),
        make_connection(20, 8080, "192.168.1.50"),
        make_connection(25, 8443, "192.168.1.51"),
    ]

    rule = PortScanRule(
        threshold=4,
        window_seconds=60,
    )

    alert = rule.evaluate(events)

    assert alert is None
