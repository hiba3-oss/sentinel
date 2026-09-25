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
from sentinel.intelligence.analyzer import ThreatIntelAnalyzer
from sentinel.intelligence.enricher import AlertEnricher
from sentinel.intelligence.matcher import IOCMatcher
from sentinel.intelligence.store import IndicatorStore
from sentinel.monitoring.runner import MonitoringRunner
from sentinel.monitoring.service import MonitoringService
from sentinel.monitoring.watcher import LogWatcher
from sentinel.risk import RiskScorer
from sentinel.storage import SentinelDatabase

app = typer.Typer(
    name="sentinel",
    help="Defensive cybersecurity monitoring and threat detection platform.",
)

console = Console()

info_app = typer.Typer(
    help="Sentinel information and version commands.",
)

app.add_typer(info_app, name="info")

DEFAULT_DATABASE_PATH = Path("data/sentinel.db")
DEFAULT_THREAT_INTEL_PATH = Path(
    "data/threat_intel/indicators.json"
)


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


def build_threat_intel_analyzer(
    feed_path: Path = DEFAULT_THREAT_INTEL_PATH,
) -> ThreatIntelAnalyzer:
    """Build the Sentinel threat intelligence analyzer."""

    store = IndicatorStore(feed_path)
    matcher = IOCMatcher(store)
    enricher = AlertEnricher(matcher)

    return ThreatIntelAnalyzer(enricher)


def display_alerts(
    alerts: list,
    scorer: RiskScorer,
) -> None:
    """Display generated security alerts."""

    if not alerts:
        console.print(
            "[green]No security alerts detected.[/green]"
        )
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
            (
                f"[{severity_style}]"
                f"{alert.severity.value.upper()}"
                f"[/{severity_style}]"
            ),
            str(risk_score),
            alert.source_ip or "-",
            alert.description,
        )

    console.print(table)
    console.print()

    console.print(
        f"[bold red]{len(alerts)} "
        "security alert(s) detected.[/bold red]"
    )


def display_incidents(incidents: list) -> None:
    """Display correlated security incidents."""

    if not incidents:
        console.print(
            "[green]No security incidents created.[/green]"
        )
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
            (
                f"[{severity_style}]"
                f"{incident.severity.upper()}"
                f"[/{severity_style}]"
            ),
            str(incident.risk_score),
            incident.source_ip or "-",
            str(len(incident.alert_ids)),
        )

    console.print(table)
    console.print()

    console.print(
        f"[bold red]{len(incidents)} "
        "security incident(s) created.[/bold red]"
    )


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
    console.print(
        "[bold cyan]Sentinel Security Analysis[/bold cyan]"
    )
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
def monitor(
    log_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the log file to monitor continuously.",
    ),
    interval: float = typer.Option(
        1.0,
        "--interval",
        "-i",
        min=0.01,
        help="Polling interval in seconds.",
    ),
    database_path: Path = typer.Option(  # noqa: B008
        DEFAULT_DATABASE_PATH,
        "--database",
        "-d",
        help="Path to the Sentinel SQLite database.",
    ),
    threat_intel_path: Path = typer.Option(  # noqa: B008
        DEFAULT_THREAT_INTEL_PATH,
        "--threat-intel",
        help="Path to the threat intelligence feed.",
    ),
) -> None:
    """Monitor a security log continuously."""

    if not threat_intel_path.is_file():
        console.print(
            "[red]Error:[/red] "
            f"Threat intelligence feed not found: "
            f"{threat_intel_path}"
        )
        raise typer.Exit(code=1)

    console.print()
    console.print(
        "[bold cyan]Sentinel Live Monitoring[/bold cyan]"
    )
    console.print("─" * 70)
    console.print(f"Log file       : {log_file}")
    console.print(f"Database       : {database_path}")
    console.print(f"Threat Intel   : {threat_intel_path}")
    console.print(f"Interval       : {interval:.2f}s")
    console.print()
    console.print(
        "[green]Monitoring started.[/green] "
        "Press [bold]Ctrl+C[/bold] to stop."
    )
    console.print()

    runner: MonitoringRunner | None = None

    try:
        watcher = LogWatcher(
            log_file,
            start_at_end=True,
        )

        database = SentinelDatabase(database_path)

        service = MonitoringService(
            watcher=watcher,
            detection_engine=build_detection_engine(),
            threat_intel_analyzer=build_threat_intel_analyzer(
                threat_intel_path
            ),
            incident_correlator=IncidentCorrelator(),
            database=database,
        )

        runner = MonitoringRunner(
            service=service,
            interval=interval,
        )

        runner.start()

        try:
            runner.wait()
        except KeyboardInterrupt:
            console.print()
            console.print(
                "[yellow]Stopping Sentinel monitoring...[/yellow]"
            )

    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    finally:
        if runner is not None:
            runner.stop()

    console.print(
        "[green]Monitoring stopped cleanly.[/green]"
    )


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
            (
                f"[{severity_style}]"
                f"{alert['severity'].upper()}"
                f"[/{severity_style}]"
            ),
            str(alert["risk_score"]),
            alert["source_ip"] or "-",
            alert["created_at"],
        )

    console.print(table)
    console.print()

    console.print(
        f"[bold]{len(stored_alerts)} stored alert(s).[/bold]"
    )


@app.command()
def incidents() -> None:
    """Display stored security incidents."""

    database = SentinelDatabase()
    stored_incidents = database.get_incidents()

    if not stored_incidents:
        console.print(
            "[green]No stored incidents.[/green]"
        )
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
        alert_ids = database.get_incident_alert_ids(
            incident["incident_id"]
        )

        severity_style = {
            "low": "green",
            "medium": "yellow",
            "high": "orange1",
            "critical": "red",
        }.get(incident["severity"], "white")

        table.add_row(
            incident["incident_id"],
            incident["status"].upper(),
            (
                f"[{severity_style}]"
                f"{incident['severity'].upper()}"
                f"[/{severity_style}]"
            ),
            str(incident["risk_score"]),
            incident["source_ip"] or "-",
            str(len(alert_ids)),
            incident["created_at"],
        )

    console.print(table)
    console.print()

    console.print(
        f"[bold]{len(stored_incidents)} "
        "stored incident(s).[/bold]"
    )


if __name__ == "__main__":
    app()
