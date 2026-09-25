"""Base interface for Sentinel detection rules."""

from abc import ABC, abstractmethod

from sentinel.models import Alert, Event


class DetectionRule(ABC):
    """Base class for all Sentinel detection rules."""

    rule_id: str
    name: str

    @abstractmethod
    def evaluate(self, events: list[Event]) -> Alert | None:
        """Evaluate events and return an alert when the rule triggers."""
        raise NotImplementedError
