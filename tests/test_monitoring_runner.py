"""Tests for the Sentinel monitoring runner."""

from pathlib import Path
from time import sleep

import pytest

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.incidents.correlator import IncidentCorrelator
from sentinel.intelligence.analyzer import ThreatIntelAnalyzer
from sentinel.intelligence.enricher import AlertEnricher
from sentinel.intelligence.matcher import IOCMatcher
from sentinel.intelligence.store import IndicatorStore
from sentinel.monitoring.runner import MonitoringRunner
from sentinel.monitoring.service import MonitoringService
from sentinel.monitoring.watcher import LogWatcher
from sentinel.storage.database import SentinelDatabase

FEED_PATH = Path("data/threat_intel/indicators.json")


def build_service(
    log_path: Path,
    database_path: Path,
) -> MonitoringService:
    """Build a fully configured monitoring service."""

    store = IndicatorStore(FEED_PATH)
    matcher = IOCMatcher(store)
    enricher = AlertEnricher(matcher)
    threat_intel_analyzer = ThreatIntelAnalyzer(enricher)

    return MonitoringService(
        watcher=LogWatcher(log_path, start_at_end=True),
        detection_engine=DetectionEngine(
            rules=[
                SSHBruteForceRule(),
            ]
        ),
        threat_intel_analyzer=threat_intel_analyzer,
        incident_correlator=IncidentCorrelator(),
        database=SentinelDatabase(database_path),
    )


def test_runner_starts_and_stops(
    tmp_path: Path,
) -> None:
    """The monitoring runner starts and stops cleanly."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    runner = MonitoringRunner(
        service=service,
        interval=0.01,
    )

    assert not runner.is_running

    runner.start()

    try:
        assert runner.is_running
    finally:
        runner.stop()

    assert not runner.is_running


def test_runner_processes_appended_log_lines(
    tmp_path: Path,
) -> None:
    """The runner continuously processes appended security logs."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    runner = MonitoringRunner(
        service=service,
        interval=0.01,
    )

    runner.start()

    try:
        with log_path.open("a", encoding="utf-8") as file:
            for index in range(5):
                file.write(
                    f"2026-09-25T10:00:0{index}Z "
                    "ssh authentication_failure "
                    "user=root "
                    "src=10.10.10.50 "
                    'msg="Failed password for root"\n'
                )

        for _ in range(100):
            if service.database.get_alerts():
                break
            sleep(0.01)

        alerts = service.database.get_alerts()
        incidents = service.database.get_incidents()

        assert len(alerts) == 1
        assert len(incidents) == 1

        assert alerts[0]["rule_id"] == "SSH-BRUTE-FORCE"
        assert alerts[0]["source_ip"] == "10.10.10.50"
        assert incidents[0]["source_ip"] == "10.10.10.50"

    finally:
        runner.stop()


def test_runner_rejects_invalid_interval(
    tmp_path: Path,
) -> None:
    """The runner rejects a non-positive polling interval."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    with pytest.raises(ValueError, match="interval"):
        MonitoringRunner(
            service=service,
            interval=0,
        )


def test_runner_cannot_start_twice(
    tmp_path: Path,
) -> None:
    """The runner prevents starting the same worker twice."""

    log_path = tmp_path / "auth.log"
    database_path = tmp_path / "sentinel.db"

    log_path.write_text("", encoding="utf-8")

    service = build_service(
        log_path=log_path,
        database_path=database_path,
    )

    runner = MonitoringRunner(
        service=service,
        interval=0.01,
    )

    runner.start()

    try:
        with pytest.raises(
            RuntimeError,
            match="already running",
        ):
            runner.start()
    finally:
        runner.stop()
