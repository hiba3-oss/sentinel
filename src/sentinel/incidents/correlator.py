"""Security incident correlation."""

from collections import defaultdict
from datetime import UTC, datetime

from sentinel.incidents.ids import IncidentIdGenerator
from sentinel.models import Alert, Incident, IncidentStatus


class IncidentCorrelator:
    """Correlate related security alerts into incidents."""

    def __init__(
        self,
        id_generator: IncidentIdGenerator | None = None,
    ) -> None:
        """Initialize the incident correlator."""

        self.id_generator = id_generator or IncidentIdGenerator()

    def correlate(self, alerts: list[Alert]) -> list[Incident]:
        """Group related security alerts into security incidents."""

        if not alerts:
            return []

        alerts_by_ip: dict[str, list[Alert]] = defaultdict(list)
        alerts_without_ip: list[Alert] = []

        for alert in alerts:
            if alert.source_ip:
                alerts_by_ip[alert.source_ip].append(alert)
            else:
                alerts_without_ip.append(alert)

        incidents: list[Incident] = []

        for source_ip, ip_alerts in alerts_by_ip.items():
            incidents.append(
                self._build_incident(
                    alerts=ip_alerts,
                    source_ip=source_ip,
                )
            )

        for alert in alerts_without_ip:
            incidents.append(
                self._build_incident(
                    alerts=[alert],
                    source_ip=None,
                )
            )

        return incidents

    def _build_incident(
        self,
        alerts: list[Alert],
        source_ip: str | None,
    ) -> Incident:
        """Build one incident from correlated alerts."""

        severity_order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        highest_severity = max(
            alerts,
            key=lambda alert: severity_order[alert.severity.value],
        )

        risk_score = min(
            100,
            max(alert.risk_score for alert in alerts)
            + (len(alerts) - 1) * 5,
        )

        rule_names = ", ".join(alert.rule_id for alert in alerts)
        alert_ids = [alert.id for alert in alerts]

        now = datetime.now(UTC)

        return Incident(
            incident_id=self.id_generator.generate(),
            title="Correlated security incident",
            description=(
                f"{len(alerts)} security alert(s) were correlated "
                f"for source {source_ip or 'unknown'}. "
                f"Detected rules: {rule_names}."
            ),
            status=IncidentStatus.OPEN,
            severity=highest_severity.severity.value,
            risk_score=risk_score,
            source_ip=source_ip,
            alert_ids=alert_ids,
            created_at=now,
            updated_at=now,
        )
