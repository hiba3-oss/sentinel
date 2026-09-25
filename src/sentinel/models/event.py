"""Core security event model."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Event(BaseModel):
    """Normalized security event."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str
    event_type: str

    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
    )

    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
