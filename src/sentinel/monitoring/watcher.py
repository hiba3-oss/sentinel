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

        with self.log_path.open(
            "r",
            encoding=self.encoding,
            newline="",
        ) as file:
            if self.start_at_end:
                file.seek(0, 2)
            else:
                file.seek(0)

            self._position = file.tell()

    def read_new_lines(self) -> list[str]:
        """Read lines appended since the previous read."""

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.log_path}"
            )

        current_size = self.log_path.stat().st_size

        if current_size < self._position:
            self._position = 0

        lines: list[str] = []

        with self.log_path.open(
            "r",
            encoding=self.encoding,
            newline="",
        ) as file:
            file.seek(self._position)

            for line in file:
                lines.append(line.rstrip("\r\n"))

            self._position = file.tell()

        return lines