"""Tests for Sentinel dashboard data access."""

import sqlite3
from pathlib import Path

import pandas as pd

from sentinel.dashboard import data


def _create_test_database(
    database_path: Path,
) -> None:
    """Create a temporary Sentinel database for dashboard tests."""

    connection = sqlite3.connect(database_path)

    connection.executescript(
        """
        CREATE TABLE alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            source_ip TEXT,
            username TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            source_ip TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE incident_alerts (
            incident_id TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            PRIMARY KEY (incident_id, alert_id)
        );

        CREATE TABLE threat_intelligence_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            matched_value TEXT NOT NULL,
            observable_type TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT NOT NULL,
            adjusted_risk_score INTEGER NOT NULL
        );

        INSERT INTO alerts (
            id,
            rule_id,
            title,
            description,
            severity,
            risk_score,
            source_ip,
            username,
            created_at
        )
        VALUES
        (
            'ALT-001',
            'SSH-BRUTE-FORCE',
            'SSH brute force detected',
            'Repeated failed SSH authentication.',
            'high',
            95,
            '10.10.10.50',
            'admin',
            '2026-09-25T12:00:00+00:00'
        ),
        (
            'ALT-002',
            'SUSPICIOUS-LOGIN',
            'Suspicious login detected',
            'Multiple failed login attempts.',
            'critical',
            100,
            '10.10.10.50',
            'admin',
            '2026-09-25T12:01:00+00:00'
        );

        INSERT INTO incidents (
            incident_id,
            title,
            description,
            status,
            severity,
            risk_score,
            source_ip,
            created_at,
            updated_at
        )
        VALUES (
            'INC-20260925-000001',
            'Correlated security incident',
            'Two related security alerts.',
            'open',
            'high',
            95,
            '10.10.10.50',
            '2026-09-25T12:02:00+00:00',
            '2026-09-25T12:02:00+00:00'
        );

        INSERT INTO incident_alerts (
            incident_id,
            alert_id
        )
        VALUES
        (
            'INC-20260925-000001',
            'ALT-001'
        ),
        (
            'INC-20260925-000001',
            'ALT-002'
        );
        """
    )

    connection.commit()
    connection.close()


def test_get_incident_returns_requested_incident(
    tmp_path,
    monkeypatch,
) -> None:
    """Dashboard data access returns the requested incident."""

    database_path = tmp_path / "sentinel.db"

    _create_test_database(database_path)

    monkeypatch.setattr(
        data,
        "DB_PATH",
        database_path,
    )

    data.get_incident.clear()

    result = data.get_incident(
        "INC-20260925-000001"
    )

    assert isinstance(result, pd.DataFrame)
    assert len(result) == 1

    row = result.iloc[0]

    assert row["incident_id"] == "INC-20260925-000001"
    assert row["severity"] == "high"
    assert row["risk_score"] == 95


def test_get_incident_alerts_returns_related_alerts(
    tmp_path,
    monkeypatch,
) -> None:
    """Dashboard data access returns alerts related to an incident."""

    database_path = tmp_path / "sentinel.db"

    _create_test_database(database_path)

    monkeypatch.setattr(
        data,
        "DB_PATH",
        database_path,
    )

    data.get_incident_alerts.clear()

    result = data.get_incident_alerts(
        "INC-20260925-000001"
    )

    assert isinstance(result, pd.DataFrame)
    assert len(result) == 2

    assert result["id"].tolist() == [
        "ALT-001",
        "ALT-002",
    ]

    assert result["source_ip"].tolist() == [
        "10.10.10.50",
        "10.10.10.50",
    ]


def test_get_incident_alerts_returns_empty_for_unknown_incident(
    tmp_path,
    monkeypatch,
) -> None:
    """Dashboard data access returns no alerts for an unknown incident."""

    database_path = tmp_path / "sentinel.db"

    _create_test_database(database_path)

    monkeypatch.setattr(
        data,
        "DB_PATH",
        database_path,
    )

    data.get_incident_alerts.clear()

    result = data.get_incident_alerts(
        "INC-DOES-NOT-EXIST"
    )

    assert isinstance(result, pd.DataFrame)
    assert result.empty


def test_get_incident_threat_intelligence(
    tmp_path,
    monkeypatch,
) -> None:
    """Dashboard data access returns TI matches for an incident."""

    database_path = tmp_path / "sentinel.db"

    connection = sqlite3.connect(database_path)

    connection.executescript(
        """
        CREATE TABLE alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            source_ip TEXT,
            username TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            source_ip TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE incident_alerts (
            incident_id TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            PRIMARY KEY (incident_id, alert_id)
        );

        CREATE TABLE threat_intelligence_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            matched_value TEXT NOT NULL,
            observable_type TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT NOT NULL,
            adjusted_risk_score INTEGER NOT NULL
        );

        INSERT INTO alerts (
            id,
            rule_id,
            title,
            description,
            severity,
            risk_score,
            source_ip,
            username,
            created_at
        )
        VALUES (
            'ALT-TI-001',
            'SSH-BRUTE-FORCE',
            'SSH brute force detected',
            'Repeated failed SSH authentication.',
            'high',
            95,
            '10.10.10.50',
            'admin',
            '2026-09-25T12:00:00+00:00'
        );

        INSERT INTO incidents (
            incident_id,
            title,
            description,
            status,
            severity,
            risk_score,
            source_ip,
            created_at,
            updated_at
        )
        VALUES (
            'INC-TI-001',
            'Threat intelligence incident',
            'Incident created for dashboard testing.',
            'open',
            'high',
            95,
            '10.10.10.50',
            '2026-09-25T12:00:00+00:00',
            '2026-09-25T12:00:00+00:00'
        );

        INSERT INTO incident_alerts (
            incident_id,
            alert_id
        )
        VALUES (
            'INC-TI-001',
            'ALT-TI-001'
        );

        INSERT INTO threat_intelligence_matches (
            alert_id,
            indicator_value,
            indicator_type,
            matched_value,
            observable_type,
            confidence,
            severity,
            source,
            description,
            adjusted_risk_score
        )
        VALUES (
            'ALT-TI-001',
            '10.10.10.50',
            'ipv4',
            '10.10.10.50',
            'source_ip',
            90,
            'high',
            'sentinel-test-feed',
            'Synthetic malicious SSH source used for testing.',
            95
        );
        """
    )

    connection.commit()
    connection.close()

    monkeypatch.setattr(
        data,
        "DB_PATH",
        database_path,
    )

    data.get_incident_threat_intelligence.clear()

    result = data.get_incident_threat_intelligence(
        "INC-TI-001"
    )

    assert isinstance(result, pd.DataFrame)
    assert len(result) == 1

    row = result.iloc[0]

    assert row["alert_id"] == "ALT-TI-001"
    assert row["indicator_value"] == "10.10.10.50"
    assert row["indicator_type"] == "ipv4"
    assert row["matched_value"] == "10.10.10.50"
    assert row["observable_type"] == "source_ip"
    assert row["confidence"] == 90
    assert row["severity"] == "high"
    assert row["source"] == "sentinel-test-feed"
    assert row["adjusted_risk_score"] == 95
