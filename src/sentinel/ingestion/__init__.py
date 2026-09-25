"""Sentinel log ingestion."""

from sentinel.ingestion.parser import parse_line, parse_lines
from sentinel.ingestion.reader import read_log_file

__all__ = [
    "parse_line",
    "parse_lines",
    "read_log_file",
]
