"""SSH brute-force detection rule."""

from datetime import timedelta

from sentinel.detection.base import DetectionRule
from sentinel.models import Alert, AlertSeverity, Event


class SSHBruteForceRule(DetectionRule):
    """Detect repeated SSH authentication failures from one IP."""

    rule_id = "SSH-BRUTE-FORCE"
    name = "SSH Brute-Force Detection"

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events: list[Event]) -> Alert | None:
        """Detect repeated failed SSH authentications."""

        failures = [
            event
            for event in events
            if event.source.lower() == "ssh"
            and event.event_type.lower() == "authentication_failure"
            and event.source_ip
        ]

        if not failures:
            return None

        failures.sort(key=lambda event: event.timestamp)

        for start_index, start_event in enumerate(failures):
            source_ip = start_event.source_ip

            window_events = [
                event
                for event in failures[start_index:]
                if event.source_ip == source_ip
                and event.timestamp - start_event.timestamp <= self.window
            ]

            if len(window_events) < self.threshold:
                continue

            event_ids = [f"EVT-{index + 1:04d}" for index, _ in enumerate(window_events)]

            return Alert(
                id=f"ALT-{source_ip.replace('.', '-')}",
                rule_id=self.rule_id,
                title="SSH brute-force detected",
                description=(
                    f"{len(window_events)} failed SSH authentication attempts "
                    f"were detected from {source_ip} within "
                    f"{self.window.total_seconds():.0f} seconds."
                ),
                severity=AlertSeverity.HIGH,
                risk_score=min(100, 70 + (len(window_events) - self.threshold) * 5),
                source_ip=source_ip,
                username=window_events[-1].username,
                event_ids=event_ids,
            )

        return None
