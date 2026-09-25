"""SQLite persistence layer for Sentinel."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sentinel.models import Alert, Incident

DEFAULT_DB_PATH = Path("data/sentinel.db")


class SentinelDatabase:
    """Persist Sentinel alerts and incidents in SQLite."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)

        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)

        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open, commit, rollback, and safely close a SQLite connection."""

        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row

        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        """Create database tables when they do not exist."""

        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
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

                CREATE TABLE IF NOT EXISTS incidents (
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

                CREATE TABLE IF NOT EXISTS incident_alerts (
                    incident_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    PRIMARY KEY (incident_id, alert_id),
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents(incident_id),
                    FOREIGN KEY (alert_id)
                        REFERENCES alerts(id)
                );
                """
            )

    def save_alert(self, alert: Alert) -> None:
        """Persist one security alert."""

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO alerts (
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.rule_id,
                    alert.title,
                    alert.description,
                    alert.severity.value,
                    alert.risk_score,
                    alert.source_ip,
                    alert.username,
                    alert.created_at.isoformat(),
                ),
            )

    def save_incident(self, incident: Incident) -> None:
        """Persist one incident and its alert relationships."""

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.title,
                    incident.description,
                    incident.status.value,
                    incident.severity,
                    incident.risk_score,
                    incident.source_ip,
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                ),
            )

            for alert_id in incident.alert_ids:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO incident_alerts (
                        incident_id,
                        alert_id
                    )
                    VALUES (?, ?)
                    """,
                    (
                        incident.incident_id,
                        alert_id,
                    ),
                )

    def get_alerts(self) -> list[sqlite3.Row]:
        """Return all stored alerts."""

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY created_at DESC
                """
            ).fetchall()

    def get_incidents(self) -> list[sqlite3.Row]:
        """Return all stored incidents."""

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM incidents
                ORDER BY created_at DESC
                """
            ).fetchall()

    def get_incident_alert_ids(
        self,
        incident_id: str,
    ) -> list[str]:
        """Return alert IDs associated with an incident."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_id
                FROM incident_alerts
                WHERE incident_id = ?
                ORDER BY alert_id
                """,
                (incident_id,),
            ).fetchall()

        return [row["alert_id"] for row in rows]
