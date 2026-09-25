"""Tests for Sentinel live log watching."""

from pathlib import Path

import pytest

from sentinel.monitoring.watcher import LogWatcher


def test_watcher_starts_at_end(tmp_path: Path) -> None:
    """A watcher configured for live mode ignores existing lines."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "old line 1\nold line 2\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)

    watcher.start()

    assert watcher.read_new_lines() == []


def test_watcher_reads_new_lines(tmp_path: Path) -> None:
    """The watcher returns lines appended after startup."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "old line\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)
    watcher.start()

    with log_path.open("a", encoding="utf-8") as file:
        file.write("new line 1\n")
        file.write("new line 2\n")

    assert watcher.read_new_lines() == [
        "new line 1",
        "new line 2",
    ]


def test_watcher_does_not_duplicate_lines(tmp_path: Path) -> None:
    """Already consumed lines are not returned twice."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "initial\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)
    watcher.start()

    with log_path.open("a", encoding="utf-8") as file:
        file.write("event 1\n")

    assert watcher.read_new_lines() == ["event 1"]
    assert watcher.read_new_lines() == []


def test_watcher_can_start_from_beginning(tmp_path: Path) -> None:
    """The watcher can optionally process the existing file."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "line 1\nline 2\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=False)

    watcher.start()

    assert watcher.read_new_lines() == [
        "line 1",
        "line 2",
    ]


def test_watcher_detects_file_truncation(tmp_path: Path) -> None:
    """The watcher resets when the monitored file becomes smaller."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "old line 1\nold line 2\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=False)
    watcher.start()

    assert watcher.read_new_lines() == [
        "old line 1",
        "old line 2",
    ]

    log_path.write_text(
        "new line\n",
        encoding="utf-8",
    )

    assert watcher.read_new_lines() == ["new line"]


def test_watcher_requires_existing_file(tmp_path: Path) -> None:
    """Starting a watcher for a missing file raises FileNotFoundError."""

    log_path = tmp_path / "missing.log"

    watcher = LogWatcher(log_path)

    with pytest.raises(FileNotFoundError):
        watcher.start()


def test_watcher_position_advances(tmp_path: Path) -> None:
    """The tracked position advances after reading new data."""

    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "initial\n",
        encoding="utf-8",
    )

    watcher = LogWatcher(log_path, start_at_end=True)
    watcher.start()

    initial_position = watcher.position

    with log_path.open("a", encoding="utf-8") as file:
        file.write("new event\n")

    watcher.read_new_lines()

    assert watcher.position > initial_position