"""Tests for the Event model."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from sentinel.models import Event


def test_event_creation() -> None:
    event = Event(
        timestamp=datetime(2026, 9, 25, 10, 15, 0),
        source="ssh",
        event_type="authentication_failure",
        username="root",
        source_ip="192.168.1.50",
        message="Failed password for root",
    )

    assert event.source == "ssh"
    assert event.event_type == "authentication_failure"
    assert event.username == "root"
    assert event.source_ip == "192.168.1.50"


def test_event_default_metadata() -> None:
    event = Event(
        source="system",
        event_type="test",
        message="Test event",
    )

    assert event.metadata == {}
    assert event.timestamp is not None


def test_event_rejects_invalid_port() -> None:
    with pytest.raises(ValidationError):
        Event(
            source="network",
            event_type="connection",
            message="Invalid port",
            destination_port=70000,
        )


def test_event_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Event(
            source="ssh",
            event_type="authentication_failure",
            message="Unknown field",
            unknown_field="malicious",
        )
