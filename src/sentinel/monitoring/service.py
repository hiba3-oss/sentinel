"""Live monitoring service for Sentinel."""

from sentinel.detection.engine import DetectionEngine
from sentinel.ingestion.parser import parse_lines
from sentinel.models import Alert, Event
from sentinel.monitoring.watcher import LogWatcher


class MonitoringService:
    """Connect live log ingestion to Sentinel detection."""

    def __init__(
        self,
        watcher: LogWatcher,
        detection_engine: DetectionEngine,
    ) -> None:
        """Initialize the monitoring service."""

        self.watcher = watcher
        self.detection_engine = detection_engine

    def start(self) -> None:
        """Initialize the underlying log watcher."""

        self.watcher.start()

    def process_new_lines(self) -> tuple[list[Event], list[Alert]]:
        """Process newly appended log lines."""

        lines = self.watcher.read_new_lines()

        if not lines:
            return [], []

        events = parse_lines(lines)

        if not events:
            return [], []

        alerts = self.detection_engine.analyze(events)

        return events, alerts
