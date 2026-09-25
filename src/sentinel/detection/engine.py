"""Sentinel detection engine."""

from sentinel.detection.base import DetectionRule
from sentinel.models import Alert, Event


class DetectionEngine:
    """Run all registered detection rules against security events."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    def analyze(self, events: list[Event]) -> list[Alert]:
        """Run every detection rule and return generated alerts."""

        alerts: list[Alert] = []

        for rule in self.rules:
            alert = rule.evaluate(events)

            if alert is not None:
                alerts.append(alert)

        return alerts
