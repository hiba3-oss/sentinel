"""Sentinel REST API routes."""

from fastapi import APIRouter, Depends, HTTPException
from pathlib import Path
from typing import Any

from sentinel.api.security import get_api_key
from fastapi import APIRouter, HTTPException

from sentinel.api.schemas import (
    AlertResponse,
    IncidentResponse,
    ThreatIntelligenceResponse,
)
from sentinel.storage.database import SentinelDatabase

router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(get_api_key)],
)

DATABASE_PATH = Path("data/sentinel.db")


def get_database() -> SentinelDatabase:
    """Return the Sentinel database instance."""

    return SentinelDatabase(DATABASE_PATH)


def row_to_dict(row: Any) -> dict[str, Any]:
    """Convert a SQLite row to a JSON-compatible dictionary."""

    return dict(row)


@router.get(
    "/alerts",
    response_model=list[AlertResponse],
)
def get_alerts() -> list[dict[str, Any]]:
    """Return persisted Sentinel alerts."""

    database = get_database()

    alerts = database.get_alerts()

    return [
        row_to_dict(alert)
        for alert in alerts
    ]


@router.get(
    "/incidents",
    response_model=list[IncidentResponse],
)
def get_incidents() -> list[dict[str, Any]]:
    """Return persisted Sentinel incidents."""

    database = get_database()

    incidents = database.get_incidents()

    return [
        row_to_dict(incident)
        for incident in incidents
    ]


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
)
def get_incident(incident_id: str) -> dict[str, Any]:
    """Return one Sentinel incident."""

    database = get_database()

    incident = database.get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return row_to_dict(incident)


@router.get(
    "/incidents/{incident_id}/alerts",
    response_model=list[AlertResponse],
)
def get_incident_alerts(
    incident_id: str,
) -> list[dict[str, Any]]:
    """Return alerts associated with one incident."""

    database = get_database()

    incident = database.get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    alert_ids = database.get_incident_alert_ids(incident_id)

    alerts = database.get_alerts()

    alerts_by_id = {
        alert["id"]: row_to_dict(alert)
        for alert in alerts
    }

    return [
        alerts_by_id[alert_id]
        for alert_id in alert_ids
        if alert_id in alerts_by_id
    ]


@router.get(
    "/incidents/{incident_id}/threat-intelligence",
    response_model=list[ThreatIntelligenceResponse],
)
def get_incident_threat_intelligence(
    incident_id: str,
) -> list[dict[str, Any]]:
    """Return threat intelligence matches for one incident."""

    database = get_database()

    incident = database.get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    matches = database.get_incident_threat_intelligence(
        incident_id,
    )

    return [
        row_to_dict(match)
        for match in matches
    ]

