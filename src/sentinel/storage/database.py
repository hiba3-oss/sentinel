"""SQLite persistence layer for Sentinel."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sentinel.intelligence.result import EnrichedAlert
from sentinel.models import Alert, Incident

DEFAULT_DB_PATH = Path("data/sentinel.db")


class SentinelDatabase:
    """Persist Sentinel alerts, threat intelligence, and incidents."""

    def __init__(
        self,
        path: str | Path = DEFAULT_DB_PATH,
    ) -> None:
        """Initialize the Sentinel database."""

        self.path = Path(path)

        if self.path.parent != Path("."):
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

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

                CREATE TABLE IF NOT EXISTS threat_intelligence_matches (
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
                    adjusted_risk_score INTEGER NOT NULL,
                    FOREIGN KEY (alert_id)
                        REFERENCES alerts(id)
                );
                """
            )

    def save_alert(
        self,
        alert: Alert,
    ) -> None:
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

    def save_enriched_alert(
        self,
        enriched_alert: EnrichedAlert,
    ) -> None:
        """Persist an alert together with its threat intelligence matches."""

        alert = enriched_alert.alert

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
                    enriched_alert.adjusted_risk_score,
                    alert.source_ip,
                    alert.username,
                    alert.created_at.isoformat(),
                ),
            )

            connection.execute(
                """
                DELETE FROM threat_intelligence_matches
                WHERE alert_id = ?
                """,
                (alert.id,),
            )

            for match in enriched_alert.enrichment.matches:
                indicator = match.indicator

                connection.execute(
                    """
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.id,
                        indicator.value,
                        indicator.indicator_type.value,
                        match.matched_value,
                        match.observable_type,
                        indicator.confidence,
                        indicator.severity,
                        indicator.source,
                        indicator.description,
                        enriched_alert.adjusted_risk_score,
                    ),
                )

    def save_incident(
        self,
        incident: Incident,
    ) -> None:
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

    def get_alerts(
        self,
    ) -> list[sqlite3.Row]:
        """Return all stored alerts."""

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY created_at DESC
                """
            ).fetchall()

    def get_incidents(
        self,
    ) -> list[sqlite3.Row]:
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

        return [
            row["alert_id"]
            for row in rows
        ]

    def get_threat_intelligence_matches(
        self,
        alert_id: str,
    ) -> list[sqlite3.Row]:
        """Return threat intelligence matches for one alert."""

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM threat_intelligence_matches
                WHERE alert_id = ?
                ORDER BY id
                """,
                (alert_id,),
            ).fetchall()

    def get_incident_threat_intelligence(
        self,
        incident_id: str,
    ) -> list[sqlite3.Row]:
        """Return threat intelligence matches for an incident."""

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT
                    ti.*
                FROM threat_intelligence_matches AS ti
                INNER JOIN incident_alerts AS ia
                    ON ia.alert_id = ti.alert_id
                WHERE ia.incident_id = ?
                ORDER BY ti.id
                """,
                (incident_id,),
            ).fetchall()
