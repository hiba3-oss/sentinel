"""Command-line interface for Sentinel."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules import (
    PortScanRule,
    SSHBruteForceRule,
    SuspiciousLoginRule,
)
from sentinel.incidents import IncidentCorrelator
from sentinel.ingestion.parser import parse_lines
from sentinel.ingestion.reader import read_log_file
from sentinel.risk import RiskScorer
from sentinel.storage import SentinelDatabase

app = typer.Typer(
    name="sentinel",
    help="Defensive cybersecurity monitoring and threat detection platform.",
)

console = Console()

info_app = typer.Typer(help="Sentinel information and version commands.")

app.add_typer(info_app, name="info")


@info_app.command("version")
def version_command() -> None:
    """Display the Sentinel version."""

    from sentinel import __version__

    console.print(f"Sentinel v{__version__}")


def build_detection_engine() -> DetectionEngine:
    """Build the Sentinel detection engine."""

    return DetectionEngine(
        rules=[
            SSHBruteForceRule(
                threshold=5,
                window_seconds=60,
            ),
            PortScanRule(
                threshold=5,
                window_seconds=60,
            ),
            SuspiciousLoginRule(
                failure_threshold=3,
                window_seconds=60,
            ),
        ]
    )


def display_alerts(
    alerts: list,
    scorer: RiskScorer,
) -> None:
    """Display generated security alerts."""

    if not alerts:
        console.print("[green]No security alerts detected.[/green]")
        return

    table = Table(title="Security Alerts")

    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Risk")
    table.add_column("Source IP")
    table.add_column("Description")

    for alert in alerts:
        risk_score = scorer.calculate(alert)

        severity_style = {
            "low": "green",
            "medium": "yellow",
            "high": "orange1",
            "critical": "red",
        }.get(alert.severity.value, "white")

        table.add_row(
            alert.rule_id,
            f"[{severity_style}]{alert.severity.value.upper()}[/{severity_style}]",
            str(risk_score),
            alert.source_ip or "-",
            alert.description,
        )

    console.print(table)
    console.print()

    console.print(f"[bold red]{len(alerts)} security alert(s) detected.[/bold red]")


def display_incidents(incidents: list) -> None:
    """Display correlated security incidents."""

    if not incidents:
        console.print("[green]No security incidents created.[/green]")
        return

    console.print()

    table = Table(title="Security Incidents")

    table.add_column("Incident")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Risk")
    table.add_column("Source IP")
    table.add_column("Alerts")

    for incident in incidents:
        severity_style = {
            "low": "green",
            "medium": "yellow",
            "high": "orange1",
            "critical": "red",
        }.get(incident.severity, "white")

        table.add_row(
            incident.incident_id,
            incident.status.value.upper(),
            f"[{severity_style}]{incident.severity.upper()}[/{severity_style}]",
            str(incident.risk_score),
            incident.source_ip or "-",
            str(len(incident.alert_ids)),
        )

    console.print(table)
    console.print()

    console.print(f"[bold red]{len(incidents)} security incident(s) created.[/bold red]")


@app.command()
def analyze(
    log_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the security log file to analyze.",
    ),
) -> None:
    """Analyze a security log file and persist alerts and incidents."""

    console.print()
    console.print("[bold cyan]Sentinel Security Analysis[/bold cyan]")
    console.print("─" * 70)

    try:
        lines = read_log_file(log_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    events = parse_lines(lines)

    console.print(f"Log file : {log_file}")
    console.print(f"Lines    : {len(lines)}")
    console.print(f"Events   : {len(events)}")
    console.print()

    engine = build_detection_engine()

    alerts = engine.analyze(events)

    database = SentinelDatabase()

    for alert in alerts:
        database.save_alert(alert)

    scorer = RiskScorer()

    display_alerts(alerts, scorer)

    if not alerts:
        return

    correlator = IncidentCorrelator()

    incidents = correlator.correlate(alerts)

    for incident in incidents:
        database.save_incident(incident)

    display_incidents(incidents)


@app.command()
def alerts() -> None:
    """Display stored security alerts."""

    database = SentinelDatabase()

    stored_alerts = database.get_alerts()

    if not stored_alerts:
        console.print("[green]No stored alerts.[/green]")
        return

    table = Table(title="Stored Security Alerts")

    table.add_column("ID")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Risk")
    table.add_column("Source IP")
    table.add_column("Created")

    for alert in stored_alerts:
        severity_style = {
            "low": "green",
            "medium": "yellow",
            "high": "orange1",
            "critical": "red",
        }.get(alert["severity"], "white")

        table.add_row(
            alert["id"],
            alert["rule_id"],
            f"[{severity_style}]{alert['severity'].upper()}[/{severity_style}]",
            str(alert["risk_score"]),
            alert["source_ip"] or "-",
            alert["created_at"],
        )

    console.print(table)
    console.print()

    console.print(f"[bold]{len(stored_alerts)} stored alert(s).[/bold]")


@app.command()
def incidents() -> None:
    """Display stored security incidents."""

    database = SentinelDatabase()

    stored_incidents = database.get_incidents()

    if not stored_incidents:
        console.print("[green]No stored incidents.[/green]")
        return

    table = Table(title="Stored Security Incidents")

    table.add_column("ID")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Risk")
    table.add_column("Source IP")
    table.add_column("Alerts")
    table.add_column("Created")

    for incident in stored_incidents:
        alert_ids = database.get_incident_alert_ids(incident["incident_id"])

        severity_style = {
            "low": "green",
            "medium": "yellow",
            "high": "orange1",
            "critical": "red",
        }.get(incident["severity"], "white")

        table.add_row(
            incident["incident_id"],
            incident["status"].upper(),
            f"[{severity_style}]{incident['severity'].upper()}[/{severity_style}]",
            str(incident["risk_score"]),
            incident["source_ip"] or "-",
            str(len(alert_ids)),
            incident["created_at"],
        )

    console.print(table)
    console.print()

    console.print(f"[bold]{len(stored_incidents)} stored incident(s).[/bold]")


if __name__ == "__main__":
    app()
