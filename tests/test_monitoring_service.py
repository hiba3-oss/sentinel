"""Tests for the Sentinel live monitoring service."""

from pathlib import Path

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.incidents.correlator import IncidentCorrelator
from sentinel.intelligence.analyzer import ThreatIntelAnalyzer
from sentinel.intelligence.enricher import AlertEnricher
from sentinel.intelligence.matcher import IOCMatcher
from sentinel.intelligence.store import IndicatorStore
from sentinel.monitoring.service import MonitoringService
from sentinel.monitoring.watcher import LogWatcher
from sentinel.storage.database import SentinelDatabase

FEED_PATH = Path("data/threat_intel/indicators.json")


def build_detection_engine() -> DetectionEngine:
    """Build the detection engine used by the monitoring service."""

    return DetectionEngine(
        rules=[
            SSHBruteForceRule(),
        ]
    )


def build_threat_intel_analyzer() -> ThreatIntelAnalyzer:
    """Build the threat intelligence analyzer used by the service."""

    store = IndicatorStore(FEED_PATH)
    matcher = IOCMatcher(store)
    enricher = AlertEnricher(matcher)

    return ThreatIntelAnalyzer(enricher)


def build_service(
    log_path: Path,
    database_path: Path,
) -> MonitoringService:
    """Build a fully configured monitoring service."""

    watcher = LogWatcher(log_path, start_at_end=True)
    database = SentinelDatabase(database_path)

    return MonitoringService(
        watcher=watcher,
        detection_engine=build_detection_engine(),
        threat_intel_analyzer=build_threat_intel_analyzer(),
        incident_correlator=IncidentCorrelator(),
        database=database,
    )


def test_service_processes_and_persists_security_pipeline(
    tmp_path: Path,
) -> None:
    """The service detects, enriches, correlates, and persists alerts."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    service.start()

    with log_path.open("a", encoding="utf-8") as file:
        for index in range(5):
            file.write(
                f"2026-09-25T10:00:0{index}Z "
                "ssh authentication_failure "
                "user=root "
                "src=10.10.10.50 "
                'msg="Failed password for root"\n'
            )

    events, alerts, enriched_alerts, incidents = (
        service.process_new_lines()
    )

    assert len(events) == 5
    assert len(alerts) == 1
    assert len(enriched_alerts) == 1
    assert len(incidents) == 1

    assert enriched_alerts[0].has_threat_intelligence
    assert enriched_alerts[0].adjusted_risk_score == 95

    assert incidents[0].source_ip == "10.10.10.50"
    assert incidents[0].risk_score == 70

    stored_alerts = service.database.get_alerts()
    stored_incidents = service.database.get_incidents()

    assert len(stored_alerts) == 1
    assert len(stored_incidents) == 1

    assert stored_alerts[0]["id"] == alerts[0].id
    assert stored_incidents[0]["incident_id"] == incidents[0].incident_id

    stored_alert_ids = service.database.get_incident_alert_ids(
        incidents[0].incident_id
    )

    assert stored_alert_ids == [alerts[0].id]


def test_service_returns_empty_result_when_no_new_lines(
    tmp_path: Path,
) -> None:
    """The service returns empty collections when nothing changed."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    service.start()

    events, alerts, enriched_alerts, incidents = (
        service.process_new_lines()
    )

    assert events == []
    assert alerts == []
    assert enriched_alerts == []
    assert incidents == []


def test_service_does_not_process_invalid_lines_as_events(
    tmp_path: Path,
) -> None:
    """Invalid log lines are ignored by the parser."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    service.start()

    with log_path.open("a", encoding="utf-8") as file:
        file.write("this is not a valid Sentinel event\n")

    events, alerts, enriched_alerts, incidents = (
        service.process_new_lines()
    )

    assert events == []
    assert alerts == []
    assert enriched_alerts == []
    assert incidents == []


def test_service_processes_only_new_lines(
    tmp_path: Path,
) -> None:
    """Previously consumed lines are not processed again."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    service.start()

    with log_path.open("a", encoding="utf-8") as file:
        file.write(
            "2026-09-25T10:00:01Z "
            "ssh authentication_failure "
            "user=root "
            "src=10.10.10.50 "
            'msg="Failed password for root"\n'
        )

    first_events, first_alerts, first_enriched, first_incidents = (
        service.process_new_lines()
    )

    assert len(first_events) == 1
    assert first_alerts == []
    assert first_enriched == []
    assert first_incidents == []

    second_events, second_alerts, second_enriched, second_incidents = (
        service.process_new_lines()
    )

    assert second_events == []
    assert second_alerts == []
    assert second_enriched == []
    assert second_incidents == []
