"""Tests for IOC matching."""

import json

from sentinel.intelligence import IOCMatcher
from sentinel.intelligence.store import IndicatorStore
from sentinel.models import Event, IndicatorType


def create_store(tmp_path):
    """Create a temporary IOC store for tests."""

    feed = tmp_path / "indicators.json"

    feed.write_text(
        json.dumps(
            [
                {
                    "value": "10.10.10.50",
                    "indicator_type": "ipv4",
                    "confidence": 90,
                    "severity": "high",
                    "source": "test-feed",
                    "description": "Synthetic malicious source.",
                },
                {
                    "value": "192.168.1.100",
                    "indicator_type": "ipv4",
                    "confidence": 80,
                    "severity": "medium",
                    "source": "test-feed",
                    "description": "Synthetic suspicious destination.",
                },
            ]
        ),
        encoding="utf-8",
    )

    return IndicatorStore(feed)


def test_match_source_ip(tmp_path) -> None:
    """A matching source IP should produce an IOC match."""

    matcher = IOCMatcher(create_store(tmp_path))

    event = Event(
        source="test",
        event_type="network_connection",
        source_ip="10.10.10.50",
        message="Connection observed",
    )

    matches = matcher.match_event(event)

    assert len(matches) == 1
    assert matches[0].value == "10.10.10.50"
    assert matches[0].indicator_type == IndicatorType.IPV4


def test_match_destination_ip(tmp_path) -> None:
    """A matching destination IP should produce an IOC match."""

    matcher = IOCMatcher(create_store(tmp_path))

    event = Event(
        source="test",
        event_type="network_connection",
        destination_ip="192.168.1.100",
        message="Connection observed",
    )

    matches = matcher.match_event(event)

    assert len(matches) == 1
    assert matches[0].value == "192.168.1.100"


def test_match_source_and_destination(tmp_path) -> None:
    """Both matching IPs should be returned."""

    matcher = IOCMatcher(create_store(tmp_path))

    event = Event(
        source="test",
        event_type="network_connection",
        source_ip="10.10.10.50",
        destination_ip="192.168.1.100",
        message="Connection observed",
    )

    matches = matcher.match_event(event)

    assert len(matches) == 2
    assert {match.value for match in matches} == {
        "10.10.10.50",
        "192.168.1.100",
    }


def test_no_match_returns_empty_list(tmp_path) -> None:
    """An event with unknown IPs should produce no matches."""

    matcher = IOCMatcher(create_store(tmp_path))

    event = Event(
        source="test",
        event_type="network_connection",
        source_ip="8.8.8.8",
        message="Connection observed",
    )

    matches = matcher.match_event(event)

    assert matches == []


def test_event_without_ip_returns_empty_list(tmp_path) -> None:
    """An event without IP observables should produce no matches."""

    matcher = IOCMatcher(create_store(tmp_path))

    event = Event(
        source="test",
        event_type="authentication_failure",
        username="alice",
        message="Authentication failed",
    )

    matches = matcher.match_event(event)

    assert matches == []

