"""Incident identifier generation."""

from datetime import UTC, datetime


class IncidentIdGenerator:
    """Generate unique Sentinel incident identifiers."""

    def __init__(self) -> None:
        """Initialize the incident identifier generator."""

        self._counter = 0

    def generate(self) -> str:
        """Generate a unique incident identifier."""

        self._counter += 1

        timestamp = datetime.now(UTC).strftime("%Y%m%d")

        return f"INC-{timestamp}-{self._counter:06d}"
