"""Security log parser."""

import re
from datetime import UTC, datetime

from sentinel.models import Event

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<event_type>\S+)"
    r"(?P<fields>.*)$"
)


FIELD_PATTERN = re.compile(
    r"(?P<key>user|src|dst|port|msg)="
    r'(?:"(?P<quoted>[^"]*)"|(?P<value>\S+))'
)


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp."""

    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    return timestamp


def parse_line(line: str) -> Event:
    """Parse one Sentinel log line."""

    line = line.strip()

    match = LOG_PATTERN.match(line)

    if not match:
        raise ValueError(f"Unsupported log format: {line}")

    data = match.groupdict()

    fields: dict[str, str] = {}

    for field_match in FIELD_PATTERN.finditer(data["fields"]):
        key = field_match.group("key")
        value = field_match.group("quoted")

        if value is None:
            value = field_match.group("value")

        fields[key] = value

    destination_port = None

    if fields.get("port"):
        destination_port = int(fields["port"])

    message = fields.get("msg") or line

    return Event(
        timestamp=parse_timestamp(data["timestamp"]),
        source=data["source"],
        event_type=data["event_type"],
        username=fields.get("user"),
        source_ip=fields.get("src"),
        destination_ip=fields.get("dst"),
        destination_port=destination_port,
        message=message,
    )


def parse_lines(lines: list[str]) -> list[Event]:
    """Parse multiple log lines.

    Invalid lines are skipped so that one malformed log entry
    does not prevent analysis of the entire file.
    """

    events: list[Event] = []

    for line in lines:
        try:
            events.append(parse_line(line))
        except (ValueError, TypeError):
            continue

    return events
