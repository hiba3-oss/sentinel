"""Continuous monitoring runner for Sentinel."""

from threading import Event, Thread

from sentinel.monitoring.service import MonitoringService


class MonitoringRunner:
    """Run the Sentinel monitoring service continuously."""

    def __init__(
        self,
        service: MonitoringService,
        interval: float = 1.0,
    ) -> None:
        """Initialize the monitoring runner."""

        if interval <= 0:
            raise ValueError("interval must be greater than 0")

        self.service = service
        self.interval = interval

        self._stop_event = Event()
        self._thread: Thread | None = None

    @property
    def is_running(self) -> bool:
        """Return whether the monitoring thread is currently running."""

        return (
            self._thread is not None
            and self._thread.is_alive()
        )

    def start(self) -> None:
        """Start continuous monitoring."""

        if self.is_running:
            raise RuntimeError(
                "Monitoring runner is already running"
            )

        self.service.start()

        self._stop_event.clear()

        self._thread = Thread(
            target=self._run,
            name="sentinel-monitoring",
            daemon=False,
        )

        self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        """Request monitoring shutdown and wait for the worker to stop."""

        if self._thread is None:
            return

        self._stop_event.set()
        self._thread.join(timeout=timeout)

        if not self._thread.is_alive():
            self._thread = None

    def wait(self, timeout: float | None = None) -> None:
        """Wait for the monitoring worker to finish."""

        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        """Continuously process newly appended log lines."""

        while not self._stop_event.is_set():
            self.service.process_new_lines()

            if self._stop_event.wait(self.interval):
                break
