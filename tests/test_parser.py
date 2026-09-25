"""Tests for Sentinel log parsing."""

from pathlib import Path

from sentinel.ingestion.parser import parse_line, parse_lines
from sentinel.ingestion.reader import read_log_file


def test_parse_ssh_failure() -> None:
    line = (
        "2026-09-25T10:00:01Z ssh authentication_failure "
        "user=root src=192.168.1.50 "
        'msg="Failed password for root"'
    )

    event = parse_line(line)

    assert event.source == "ssh"
    assert event.event_type == "authentication_failure"
    assert event.username == "root"
    assert event.source_ip == "192.168.1.50"
    assert event.message == "Failed password for root"


def test_parse_ssh_success() -> None:
    line = (
        "2026-09-25T10:00:25Z ssh authentication_success "
        "user=root src=192.168.1.50 "
        'msg="Accepted password for root"'
    )

    event = parse_line(line)

    assert event.source == "ssh"
    assert event.event_type == "authentication_success"
    assert event.username == "root"
    assert event.source_ip == "192.168.1.50"
    assert event.message == "Accepted password for root"


def test_parse_network_event() -> None:
    line = (
        "2026-09-25T10:00:01Z network connection "
        "src=192.168.1.50 dst=192.168.1.10 port=22 "
        'msg="TCP connection"'
    )

    event = parse_line(line)

    assert event.source == "network"
    assert event.event_type == "connection"
    assert event.source_ip == "192.168.1.50"
    assert event.destination_ip == "192.168.1.10"
    assert event.destination_port == 22
    assert event.message == "TCP connection"


def test_parse_lines_skips_invalid_lines() -> None:
    lines = [
        (
            "2026-09-25T10:00:01Z ssh authentication_failure "
            "user=root src=192.168.1.50 "
            'msg="Failed password for root"'
        ),
        "invalid log line",
    ]

    events = parse_lines(lines)

    assert len(events) == 1
    assert events[0].source_ip == "192.168.1.50"


def test_parse_lines_preserves_all_valid_events() -> None:
    lines = [
        (
            "2026-09-25T10:00:01Z ssh authentication_failure "
            "user=root src=192.168.1.50 "
            'msg="Failed password for root"'
        ),
        (
            "2026-09-25T10:00:05Z ssh authentication_failure "
            "user=root src=192.168.1.50 "
            'msg="Failed password for root"'
        ),
        (
            "2026-09-25T10:00:09Z ssh authentication_success "
            "user=root src=192.168.1.50 "
            'msg="Accepted password for root"'
        ),
    ]

    events = parse_lines(lines)

    assert len(events) == 3
    assert events[0].event_type == "authentication_failure"
    assert events[1].event_type == "authentication_failure"
    assert events[2].event_type == "authentication_success"


def test_read_log_file_handles_utf8_bom(tmp_path: Path) -> None:
    log_file = tmp_path / "bom.log"

    content = (
        "\ufeff"
        "2026-09-25T10:00:01Z ssh authentication_failure "
        "user=root src=192.168.1.50 "
        'msg="Failed password for root"\n'
        "2026-09-25T10:00:05Z ssh authentication_failure "
        "user=root src=192.168.1.50 "
        'msg="Failed password for root"\n'
    )

    log_file.write_text(content, encoding="utf-8")

    lines = read_log_file(log_file)

    assert len(lines) == 2
    assert not lines[0].startswith("\ufeff")
    assert lines[0].startswith("2026-09-25T10:00:01Z")
