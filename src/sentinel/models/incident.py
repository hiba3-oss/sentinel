"""Security incident model."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(StrEnum):
    """Lifecycle status of a security incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class Incident(BaseModel):
    """A correlated security incident."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    title: str
    description: str

    status: IncidentStatus = IncidentStatus.OPEN

    severity: str
    risk_score: int = Field(ge=0, le=100)

    source_ip: str | None = None

    alert_ids: list[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
