"""Live log file watcher for Sentinel."""

from pathlib import Path


class LogWatcher:
    """Track a log file and return only newly appended lines."""

    def __init__(
        self,
        log_path: Path,
        *,
        encoding: str = "utf-8-sig",
        start_at_end: bool = True,
    ) -> None:
        """Initialize a watcher for a log file."""

        self.log_path = log_path
        self.encoding = encoding
        self.start_at_end = start_at_end
        self._position = 0

    @property
    def position(self) -> int:
        """Return the current byte position in the watched file."""

        return self._position

    def start(self) -> None:
        """Initialize the reading position."""

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.log_path}"
            )

        if self.start_at_end:
            self._position = self.log_path.stat().st_size
        else:
            self._position = 0

    def read_new_lines(self) -> list[str]:
        """Read lines appended since the previous read."""

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.log_path}"
            )

        current_size = self.log_path.stat().st_size

        if current_size < self._position:
            self._position = 0

        if current_size == self._position:
            return []

        lines: list[str] = []

        with self.log_path.open("rb") as file:
            file.seek(self._position)

            data = file.read()

            self._position = file.tell()

        if not data:
            return []

        text = data.decode(
            self.encoding,
            errors="replace",
        )

        lines.extend(text.splitlines())

        return lines
