"""Tests for Sentinel SQLite persistence."""

from sentinel.models import Alert, AlertSeverity, Incident, IncidentStatus
from sentinel.storage import SentinelDatabase


def make_alert(
    alert_id: str = "ALT-001",
) -> Alert:
    """Create a test alert."""

    return Alert(
        id=alert_id,
        rule_id="SSH-BRUTE-FORCE",
        title="SSH brute-force detected",
        description="Repeated SSH authentication failures.",
        severity=AlertSeverity.HIGH,
        risk_score=90,
        source_ip="192.168.1.50",
        username="root",
    )


def make_incident(
    incident_id: str = "INC-0001",
) -> Incident:
    """Create a test incident."""

    return Incident(
        incident_id=incident_id,
        title="Correlated security incident",
        description="Multiple alerts from the same source.",
        status=IncidentStatus.OPEN,
        severity="critical",
        risk_score=100,
        source_ip="192.168.1.50",
        alert_ids=["ALT-001"],
    )


def test_database_creates_tables(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    assert database.path.exists()

    with database._connect() as connection:
        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()

    table_names = {row["name"] for row in tables}

    assert "alerts" in table_names
    assert "incidents" in table_names
    assert "incident_alerts" in table_names


def test_save_and_get_alert(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    alert = make_alert()

    database.save_alert(alert)

    alerts = database.get_alerts()

    assert len(alerts) == 1
    assert alerts[0]["id"] == "ALT-001"
    assert alerts[0]["rule_id"] == "SSH-BRUTE-FORCE"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["risk_score"] == 90
    assert alerts[0]["source_ip"] == "192.168.1.50"


def test_save_alert_is_idempotent(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    alert = make_alert()

    database.save_alert(alert)
    database.save_alert(alert)

    alerts = database.get_alerts()

    assert len(alerts) == 1


def test_save_and_get_incident(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    alert = make_alert()
    incident = make_incident()

    database.save_alert(alert)
    database.save_incident(incident)

    incidents = database.get_incidents()

    assert len(incidents) == 1
    assert incidents[0]["incident_id"] == "INC-0001"
    assert incidents[0]["status"] == "open"
    assert incidents[0]["severity"] == "critical"
    assert incidents[0]["risk_score"] == 100


def test_incident_alert_relationship_is_saved(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    alert = make_alert()
    incident = make_incident()

    database.save_alert(alert)
    database.save_incident(incident)

    alert_ids = database.get_incident_alert_ids("INC-0001")

    assert alert_ids == ["ALT-001"]


def test_unknown_incident_has_no_alerts(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    alert_ids = database.get_incident_alert_ids("INC-9999")

    assert alert_ids == []


def test_empty_database_returns_no_alerts_or_incidents(tmp_path) -> None:
    database = SentinelDatabase(tmp_path / "sentinel.db")

    assert database.get_alerts() == []
    assert database.get_incidents() == []
