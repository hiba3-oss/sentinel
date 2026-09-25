"""Log file reader."""

from pathlib import Path


def read_log_file(path: str | Path) -> list[str]:
    """Read a text log file and return non-empty lines."""

    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    if not log_path.is_file():
        raise ValueError(f"Path is not a file: {log_path}")

    return [
        line.strip()
        for line in log_path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]
