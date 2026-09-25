"""Live monitoring service for Sentinel."""

from sentinel.detection.engine import DetectionEngine
from sentinel.incidents.correlator import IncidentCorrelator
from sentinel.ingestion.parser import parse_lines
from sentinel.intelligence.analyzer import ThreatIntelAnalyzer
from sentinel.intelligence.result import EnrichedAlert
from sentinel.models import Alert, Event, Incident
from sentinel.monitoring.watcher import LogWatcher
from sentinel.storage.database import SentinelDatabase


class MonitoringService:
    """Connect live log ingestion to the Sentinel security pipeline."""

    def __init__(
        self,
        watcher: LogWatcher,
        detection_engine: DetectionEngine,
        threat_intel_analyzer: ThreatIntelAnalyzer,
        incident_correlator: IncidentCorrelator,
        database: SentinelDatabase,
    ) -> None:
        """Initialize the monitoring service."""

        self.watcher = watcher
        self.detection_engine = detection_engine
        self.threat_intel_analyzer = threat_intel_analyzer
        self.incident_correlator = incident_correlator
        self.database = database

    def start(self) -> None:
        """Initialize the underlying log watcher."""

        self.watcher.start()

    def process_new_lines(
        self,
    ) -> tuple[list[Event], list[Alert], list[EnrichedAlert], list[Incident]]:
        """Process, enrich, correlate, and persist newly appended log lines."""

        lines = self.watcher.read_new_lines()

        if not lines:
            return [], [], [], []

        events = parse_lines(lines)

        if not events:
            return [], [], [], []

        alerts = self.detection_engine.analyze(events)

        enriched_alerts = [
            self.threat_intel_analyzer.analyze(
                alert=alert,
                events=events,
            )
            for alert in alerts
        ]

        incidents = self.incident_correlator.correlate(alerts)

        for alert in alerts:
            self.database.save_alert(alert)

        for incident in incidents:
            self.database.save_incident(incident)

        return events, alerts, enriched_alerts, incidents
