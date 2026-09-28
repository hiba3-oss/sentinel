import sqlite3

from sentinel.storage.database import SentinelDatabase


def test_existing_database_gets_threat_intelligence_table(tmp_path):
    database_path = tmp_path / "legacy.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
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
            )
            """
        )

        connection.execute(
            """
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
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE incident_alerts (
                incident_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, alert_id)
            )
            """
        )

        connection.commit()

    SentinelDatabase(database_path)

    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

    assert "alerts" in tables
    assert "incidents" in tables
    assert "incident_alerts" in tables
    assert "threat_intelligence_matches" in tables
