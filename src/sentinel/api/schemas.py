"""Pydantic schemas for the Sentinel REST API."""

from pydantic import BaseModel


class AlertResponse(BaseModel):
    """API representation of a persisted security alert."""

    id: str
    rule_id: str
    title: str
    description: str
    severity: str
    risk_score: int
    source_ip: str | None
    username: str | None
    created_at: str


class IncidentResponse(BaseModel):
    """API representation of a persisted security incident."""

    incident_id: str
    title: str
    description: str
    status: str
    severity: str
    risk_score: int
    source_ip: str | None
    created_at: str
    updated_at: str


class ThreatIntelligenceResponse(BaseModel):
    """API representation of a threat intelligence match."""

    id: int
    alert_id: str
    indicator_value: str
    indicator_type: str
    matched_value: str
    observable_type: str
    confidence: int
    severity: str
    source: str
    description: str
    adjusted_risk_score: int

