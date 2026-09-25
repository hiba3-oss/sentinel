"""Tests for the Sentinel live monitoring service."""

from pathlib import Path

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.monitoring.service import MonitoringService
from sentinel.monitoring.watcher import LogWatcher


def build_detection_engine() -> DetectionEngine:
    """Build the detection engine used by the monitoring service."""

    return DetectionEngine(
        rules=[
            SSHBruteForceRule(),
        ]
    )


def test_service_processes_new_log_lines(tmp_path: Path) -> None:
    """The service parses new lines and generates alerts."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)

    service = MonitoringService(
        watcher=watcher,
        detection_engine=build_detection_engine(),
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

    events, alerts = service.process_new_lines()

    assert len(events) == 5
    assert len(alerts) == 1

    assert alerts[0].rule_id == "SSH-BRUTE-FORCE"
    assert alerts[0].source_ip == "10.10.10.50"


def test_service_returns_empty_result_when_no_new_lines(
    tmp_path: Path,
) -> None:
    """The service returns empty collections when nothing changed."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)

    service = MonitoringService(
        watcher=watcher,
        detection_engine=build_detection_engine(),
    )

    service.start()

    events, alerts = service.process_new_lines()

    assert events == []
    assert alerts == []


def test_service_does_not_process_invalid_lines_as_events(
    tmp_path: Path,
) -> None:
    """Invalid log lines are ignored by the parser."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)

    service = MonitoringService(
        watcher=watcher,
        detection_engine=build_detection_engine(),
    )

    service.start()

    with log_path.open("a", encoding="utf-8") as file:
        file.write("this is not a valid Sentinel event\n")

    events, alerts = service.process_new_lines()

    assert events == []
    assert alerts == []


def test_service_processes_only_new_lines(
    tmp_path: Path,
) -> None:
    """Previously consumed lines are not processed again."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)

    service = MonitoringService(
        watcher=watcher,
        detection_engine=build_detection_engine(),
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

    first_events, first_alerts = service.process_new_lines()

    assert len(first_events) == 1
    assert first_alerts == []

    second_events, second_alerts = service.process_new_lines()

    assert second_events == []
    assert second_alerts == []
