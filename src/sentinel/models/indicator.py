"""Threat intelligence indicator model."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(StrEnum):
    """Supported IOC types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"


class Indicator(BaseModel):
    """Threat intelligence indicator."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    indicator_type: IndicatorType
    confidence: int = Field(ge=0, le=100)
    severity: str = Field(min_length=1)
    source: str = Field(min_length=1)
    description: str = Field(min_length=1)
