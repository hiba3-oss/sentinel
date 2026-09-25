"""Read-only data access layer for the Sentinel Streamlit dashboard."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

# Project root:
# C:\Users\net\Desktop\sentinel
PROJECT_ROOT = Path(__file__).resolve().parents[3]

DB_PATH = PROJECT_ROOT / "data" / "sentinel.db"


def _get_connection() -> sqlite3.Connection:
    """Open the Sentinel database in read-only mode."""
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Sentinel database not found: {DB_PATH}"
        )

    database_uri = f"file:{DB_PATH.as_posix()}?mode=ro"

    return sqlite3.connect(
        database_uri,
        uri=True,
    )


@st.cache_data(ttl=5, show_spinner=False)
def get_dashboard_stats() -> dict[str, int]:
    """Return high-level dashboard statistics."""

    with _get_connection() as connection:
        alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]

        critical_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'critical'"
        ).fetchone()[0]

        high_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'high'"
        ).fetchone()[0]

        open_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
        ).fetchone()[0]

        investigating_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents "
            "WHERE status = 'investigating'"
        ).fetchone()[0]

        resolved_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'resolved'"
        ).fetchone()[0]

    return {
        "total_alerts": alerts,
        "total_incidents": incidents,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "open_incidents": open_incidents,
        "investigating_incidents": investigating_incidents,
        "resolved_incidents": resolved_incidents,
    }


@st.cache_data(ttl=5, show_spinner=False)
def get_alerts(limit: int = 100) -> pd.DataFrame:
    """Return recent alerts."""

    limit = max(1, min(limit, 1000))

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


@st.cache_data(ttl=5, show_spinner=False)
def get_incidents(limit: int = 100) -> pd.DataFrame:
    """Return recent incidents."""

    limit = max(1, min(limit, 1000))

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
        ORDER BY updated_at DESC
        LIMIT ?
    """

    with _get_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(limit,),
        )


@st.cache_data(ttl=5, show_spinner=False)
def get_alerts_by_severity() -> pd.DataFrame:
    """Return alert counts grouped by severity."""

    query = """
        SELECT
            severity,
            COUNT(*) AS count
        FROM alerts
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """

    with _get_connection() as connection:
        return pd.read_sql_query(query, connection)


@st.cache_data(ttl=5, show_spinner=False)
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
        return pd.read_sql_query(query, connection)


@st.cache_data(ttl=5, show_spinner=False)
def get_alerts_by_source_ip() -> pd.DataFrame:
    """Return alert counts grouped by source IP."""

    query = """
        SELECT
            COALESCE(source_ip, 'Unknown') AS source_ip,
            COUNT(*) AS count,
            MAX(risk_score) AS max_risk_score
        FROM alerts
        GROUP BY source_ip
        ORDER BY count DESC, max_risk_score DESC
        LIMIT 20
    """

    with _get_connection() as connection:
        return pd.read_sql_query(query, connection)


@st.cache_data(ttl=5, show_spinner=False)
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
        return pd.read_sql_query(query, connection)


@st.cache_data(ttl=5, show_spinner=False)
def get_incidents_by_severity() -> pd.DataFrame:
    """Return incident counts grouped by severity."""

    query = """
        SELECT
            severity,
            COUNT(*) AS count
        FROM incidents
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """

    with _get_connection() as connection:
        return pd.read_sql_query(query, connection)


@st.cache_data(ttl=5, show_spinner=False)
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
        return pd.read_sql_query(query, connection)


def clear_dashboard_cache() -> None:
    """Clear cached dashboard data."""

    st.cache_data.clear()


