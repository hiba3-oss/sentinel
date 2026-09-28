"""Tests for the Sentinel REST API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.api import routes
from sentinel.api.app import app
from sentinel.models import Alert, AlertSeverity, Incident, IncidentStatus
from sentinel.storage import SentinelDatabase

client = TestClient(app)

TEST_API_KEY = "sentinel-test-api-key"


@pytest.fixture(autouse=True)
def configure_api_key(monkeypatch) -> None:
    """Configure the API key for API tests."""

    monkeypatch.setenv(
        "SENTINEL_API_KEY",
        TEST_API_KEY,
    )


def make_alert(
    alert_id: str = "ALT-API-001",
) -> Alert:
    """Create a test alert."""

    return Alert(
        id=alert_id,
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute-force detected",
        description="Repeated SSH authentication failures.",
        severity=AlertSeverity.HIGH,
        risk_score=100,
        source_ip="10.10.10.50",
        username="root",
    )


def make_incident() -> Incident:
    """Create a test incident."""

    return Incident(
        incident_id="INC-API-0001",
        title="API investigation incident",
        description="Incident used for API integration testing.",
        status=IncidentStatus.OPEN,
        severity="critical",
        risk_score=100,
        source_ip="10.10.10.50",
        alert_ids=["ALT-API-001"],
    )


def auth_headers() -> dict[str, str]:
    """Return authentication headers for API requests."""

    return {
        "X-API-Key": TEST_API_KEY,
    }


def test_root() -> None:
    """The API root is publicly accessible."""

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "Sentinel Security API"
    assert data["version"]
    assert data["status"] == "online"


def test_health() -> None:
    """The health endpoint is publicly accessible."""

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_get_alerts() -> None:
    """Return persisted alerts."""

    response = client.get(
        "/api/v1/alerts",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


def test_get_incidents() -> None:
    """Return persisted incidents."""

    response = client.get(
        "/api/v1/incidents",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


def test_get_unknown_incident() -> None:
    """Unknown incidents return HTTP 404."""

    response = client.get(
        "/api/v1/incidents/INC-DOES-NOT-EXIST",
        headers=auth_headers(),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


def test_get_incident_alerts_for_unknown_incident() -> None:
    """Unknown incidents return HTTP 404 for alert investigation."""

    response = client.get(
        "/api/v1/incidents/INC-DOES-NOT-EXIST/alerts",
        headers=auth_headers(),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


def test_get_incident_threat_intelligence_for_unknown_incident() -> None:
    """Unknown incidents return HTTP 404 for threat intelligence."""

    response = client.get(
        "/api/v1/incidents/INC-DOES-NOT-EXIST/threat-intelligence",
        headers=auth_headers(),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


def test_get_incident_alerts_integration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Return the alerts associated with an incident."""

    database_path = tmp_path / "sentinel.db"
    database = SentinelDatabase(database_path)

    alert = make_alert()
    incident = make_incident()

    database.save_alert(alert)
    database.save_incident(incident)

    monkeypatch.setattr(
        routes,
        "DATABASE_PATH",
        database_path,
    )

    response = client.get(
        "/api/v1/incidents/INC-API-0001/alerts",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == "ALT-API-001"
    assert data[0]["rule_id"] == "SSH-BRUTE-FORCE"
    assert data[0]["severity"] == "high"
    assert data[0]["risk_score"] == 100
    assert data[0]["source_ip"] == "10.10.10.50"


def test_get_incident_integration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Return the requested incident."""

    database_path = tmp_path / "sentinel.db"
    database = SentinelDatabase(database_path)

    incident = make_incident()

    database.save_incident(incident)

    monkeypatch.setattr(
        routes,
        "DATABASE_PATH",
        database_path,
    )

    response = client.get(
        "/api/v1/incidents/INC-API-0001",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == "INC-API-0001"
    assert data["status"] == "open"
    assert data["severity"] == "critical"
    assert data["risk_score"] == 100
    assert data["source_ip"] == "10.10.10.50"


def test_get_incident_threat_intelligence_integration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Return threat intelligence matches for an incident."""

    database_path = tmp_path / "sentinel.db"
    database = SentinelDatabase(database_path)

    alert = make_alert()
    incident = make_incident()

    database.save_alert(alert)
    database.save_incident(incident)

    monkeypatch.setattr(
        routes,
        "DATABASE_PATH",
        database_path,
    )

    response = client.get(
        "/api/v1/incidents/INC-API-0001/threat-intelligence",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)
    assert data == []


def test_api_requires_authentication(
    monkeypatch,
) -> None:
    """Protected API endpoints require an API key."""

    monkeypatch.setenv(
        "SENTINEL_API_KEY",
        TEST_API_KEY,
    )

    response = client.get("/api/v1/alerts")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key"


def test_api_rejects_invalid_api_key(
    monkeypatch,
) -> None:
    """Invalid API keys are rejected."""

    monkeypatch.setenv(
        "SENTINEL_API_KEY",
        TEST_API_KEY,
    )

    response = client.get(
        "/api/v1/alerts",
        headers={
            "X-API-Key": "wrong-key",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key"


def test_api_accepts_valid_api_key(
    monkeypatch,
) -> None:
    """A valid API key grants access."""

    monkeypatch.setenv(
        "SENTINEL_API_KEY",
        TEST_API_KEY,
    )

    response = client.get(
        "/api/v1/alerts",
        headers={
            "X-API-Key": TEST_API_KEY,
        },
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_health_does_not_require_authentication() -> None:
    """Health checks remain publicly accessible."""

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

