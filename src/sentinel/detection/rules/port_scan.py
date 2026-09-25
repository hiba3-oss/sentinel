"""Port scan detection rule."""

from collections import defaultdict
from datetime import timedelta

from sentinel.detection.base import DetectionRule
from sentinel.models import Alert, AlertSeverity, Event


class PortScanRule(DetectionRule):
    """Detect a source IP connecting to many destination ports."""

    rule_id = "PORT-SCAN"
    name = "Port Scan Detection"

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events: list[Event]) -> Alert | None:
        """Detect multiple destination ports targeted by one source IP."""

        network_events = [
            event
            for event in events
            if event.source.lower() == "network"
            and event.event_type.lower() == "connection"
            and event.source_ip
            and event.destination_port
        ]

        if not network_events:
            return None

        network_events.sort(key=lambda event: event.timestamp)

        events_by_ip: dict[str, list[Event]] = defaultdict(list)

        for event in network_events:
            events_by_ip[event.source_ip].append(event)

        for source_ip, ip_events in events_by_ip.items():
            for start_index, start_event in enumerate(ip_events):
                window_events = [
                    event
                    for event in ip_events[start_index:]
                    if event.timestamp - start_event.timestamp <= self.window
                ]

                unique_ports = {event.destination_port for event in window_events}

                if len(unique_ports) < self.threshold:
                    continue

                ports = sorted(port for port in unique_ports if port is not None)

                event_ids = [f"EVT-{index + 1:04d}" for index, _ in enumerate(window_events)]

                return Alert(
                    id=f"ALT-PORTSCAN-{source_ip.replace('.', '-')}",
                    rule_id=self.rule_id,
                    title="Port scan detected",
                    description=(
                        f"{source_ip} targeted {len(ports)} different "
                        f"destination ports within "
                        f"{self.window.total_seconds():.0f} seconds."
                    ),
                    severity=AlertSeverity.HIGH,
                    risk_score=min(
                        100,
                        75 + (len(ports) - self.threshold) * 5,
                    ),
                    source_ip=source_ip,
                    event_ids=event_ids,
                )

        return None
