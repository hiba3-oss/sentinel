"""Suspicious login detection rule."""

from collections import defaultdict
from datetime import timedelta

from sentinel.detection.base import DetectionRule
from sentinel.models import Alert, AlertSeverity, Event


class SuspiciousLoginRule(DetectionRule):
    """Detect successful logins after repeated authentication failures."""

    rule_id = "SUSPICIOUS-LOGIN"
    name = "Suspicious Login Detection"

    def __init__(
        self,
        failure_threshold: int = 3,
        window_seconds: int = 60,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.failure_threshold = failure_threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events: list[Event]) -> Alert | None:
        """Detect successful authentication following repeated failures."""

        authentication_events = [
            event
            for event in events
            if event.source.lower() == "ssh"
            and event.source_ip
            and event.event_type.lower()
            in {
                "authentication_failure",
                "authentication_success",
            }
        ]

        if not authentication_events:
            return None

        authentication_events.sort(key=lambda event: event.timestamp)

        events_by_ip: dict[str, list[Event]] = defaultdict(list)

        for event in authentication_events:
            events_by_ip[event.source_ip].append(event)

        for source_ip, ip_events in events_by_ip.items():
            for index, event in enumerate(ip_events):
                if event.event_type.lower() != "authentication_success":
                    continue

                previous_events = [
                    previous
                    for previous in ip_events[:index]
                    if event.timestamp - previous.timestamp <= self.window
                ]

                failures = [
                    previous
                    for previous in previous_events
                    if previous.event_type.lower() == "authentication_failure"
                ]

                if len(failures) < self.failure_threshold:
                    continue

                event_ids = [
                    f"EVT-{position + 1:04d}" for position, _ in enumerate(failures + [event])
                ]

                return Alert(
                    id=f"ALT-SUSPICIOUS-LOGIN-{source_ip.replace('.', '-')}",
                    rule_id=self.rule_id,
                    title="Suspicious login detected",
                    description=(
                        f"A successful SSH login from {source_ip} occurred "
                        f"after {len(failures)} failed authentication "
                        f"attempts within "
                        f"{self.window.total_seconds():.0f} seconds."
                    ),
                    severity=AlertSeverity.CRITICAL,
                    risk_score=min(
                        100,
                        85 + (len(failures) - self.failure_threshold) * 5,
                    ),
                    source_ip=source_ip,
                    username=event.username,
                    event_ids=event_ids,
                )

        return None
