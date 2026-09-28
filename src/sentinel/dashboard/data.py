"""Read-only data access layer for the Sentinel Streamlit dashboard."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

# ============================================================================
# DATABASE
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DB_PATH = PROJECT_ROOT / "data" / "sentinel.db"


def _get_connection() -> sqlite3.Connection:
    """Open a read-only SQLite connection."""

    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Sentinel database not found: {DB_PATH}"
        )

    database_uri = (
        f"file:{DB_PATH.as_posix()}?mode=ro"
    )

    connection = sqlite3.connect(
        database_uri,
        uri=True,
    )

    return connection


# ============================================================================
# DASHBOARD STATISTICS
# ============================================================================


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_dashboard_stats() -> dict[str, int]:
    """Return high-level dashboard statistics."""

    query = """
        SELECT
            (SELECT COUNT(*) FROM alerts) AS total_alerts,

            (
                SELECT COUNT(*)
                FROM incidents
                WHERE status = 'open'
            ) AS open_incidents,

            (
                SELECT COUNT(*)
                FROM incidents
                WHERE status = 'investigating'
            ) AS investigating_incidents,

            (
                SELECT COUNT(*)
                FROM incidents
                WHERE status = 'resolved'
            ) AS resolved_incidents,

            (
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'critical'
            ) AS critical_alerts,

            (
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'high'
            ) AS high_alerts
    """

    with _get_connection() as connection:
        row = connection.execute(query).fetchone()

    return {
        "total_alerts": int(row[0]),
        "open_incidents": int(row[1]),
        "investigating_incidents": int(row[2]),
        "resolved_incidents": int(row[3]),
        "critical_alerts": int(row[4]),
        "high_alerts": int(row[5]),
    }


# ============================================================================
# ALERTS
# ============================================================================


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_alerts(
    limit: int = 100,
) -> pd.DataFrame:
    """Return recent alerts."""

    query = """
        SELECT
            id,
            rule_id,
            title,
            description,
            severity,
            risk_score,
            source_ip,
            username,
            created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(limit,),
        )


# ============================================================================
# INCIDENTS
# ============================================================================


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_incidents(
    limit: int = 100,
) -> pd.DataFrame:
    """Return recent incidents."""

    query = """
        SELECT
            incident_id,
            title,
            description,
            status,
            severity,
            risk_score,
            source_ip,
            created_at,
            updated_at
        FROM incidents
        ORDER BY created_at DESC
        LIMIT ?
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(limit,),
        )


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_incident(
    incident_id: str,
) -> pd.DataFrame:
    """Return one incident by its identifier."""

    query = """
        SELECT
            incident_id,
            title,
            description,
            status,
            severity,
            risk_score,
            source_ip,
            created_at,
            updated_at
        FROM incidents
        WHERE incident_id = ?
        LIMIT 1
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(incident_id,),
        )


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_incident_alerts(
    incident_id: str,
) -> pd.DataFrame:
    """Return alerts associated with one incident."""

    query = """
        SELECT
            a.id,
            a.rule_id,
            a.title,
            a.description,
            a.severity,
            a.risk_score,
            a.source_ip,
            a.username,
            a.created_at
        FROM alerts AS a
        INNER JOIN incident_alerts AS ia
            ON ia.alert_id = a.id
        WHERE ia.incident_id = ?
        ORDER BY a.created_at ASC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(incident_id,),
        )


# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_incident_threat_intelligence(
    incident_id: str,
) -> pd.DataFrame:
    """Return threat intelligence matches associated with an incident."""

    query = """
        SELECT
            ti.alert_id,
            ti.indicator_value,
            ti.indicator_type,
            ti.matched_value,
            ti.observable_type,
            ti.confidence,
            ti.severity,
            ti.source,
            ti.description,
            ti.adjusted_risk_score
        FROM threat_intelligence_matches AS ti
        INNER JOIN incident_alerts AS ia
            ON ia.alert_id = ti.alert_id
        WHERE ia.incident_id = ?
        ORDER BY ti.id ASC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(incident_id,),
        )


# ============================================================================
# ALERT ANALYTICS
# ============================================================================


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_alerts_by_severity() -> pd.DataFrame:
    """Return alert counts grouped by severity."""

    query = """
        SELECT
            severity,
            COUNT(*) AS count
        FROM alerts
        GROUP BY severity
        ORDER BY count DESC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
        )


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_alerts_by_rule() -> pd.DataFrame:
    """Return alert counts grouped by detection rule."""

    query = """
        SELECT
            rule_id,
            COUNT(*) AS count
        FROM alerts
        GROUP BY rule_id
        ORDER BY count DESC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
        )


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_alerts_by_source_ip() -> pd.DataFrame:
    """Return alert activity grouped by source IP."""

    query = """
        SELECT
            COALESCE(source_ip, 'unknown') AS source_ip,
            COUNT(*) AS count,
            MAX(risk_score) AS max_risk_score
        FROM alerts
        GROUP BY source_ip
        ORDER BY count DESC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
        )


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_alert_timeline() -> pd.DataFrame:
    """Return alert counts grouped by creation timestamp."""

    query = """
        SELECT
            substr(created_at, 1, 16) AS timestamp,
            COUNT(*) AS count
        FROM alerts
        GROUP BY substr(created_at, 1, 16)
        ORDER BY timestamp
    """

    with _get_connection() as connection:
        dataframe = pd.read_sql_query(
            query,
            connection,
        )

    if dataframe.empty:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "count",
            ]
        )

    dataframe["timestamp"] = (
        dataframe["timestamp"]
        .astype(str)
    )

    dataframe["count"] = (
        dataframe["count"]
        .astype(int)
    )

    return dataframe[
        [
            "timestamp",
            "count",
        ]
    ]


# ============================================================================
# INCIDENT ANALYTICS
# ============================================================================


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_incidents_by_severity() -> pd.DataFrame:
    """Return incident counts grouped by severity."""

    query = """
        SELECT
            severity,
            COUNT(*) AS count
        FROM incidents
        GROUP BY severity
        ORDER BY count DESC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
        )


@st.cache_data(
    ttl=5,
    show_spinner=False,
)
def get_incidents_by_status() -> pd.DataFrame:
    """Return incident counts grouped by status."""

    query = """
        SELECT
            status,
            COUNT(*) AS count
        FROM incidents
        GROUP BY status
        ORDER BY count DESC
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
        )


# ============================================================================
# CACHE
# ============================================================================


def clear_dashboard_cache() -> None:
    """Clear Streamlit dashboard data cache."""

    st.cache_data.clear()

