"""Sentinel detection rules."""

from sentinel.detection.rules.brute_force import SSHBruteForceRule
from sentinel.detection.rules.port_scan import PortScanRule
from sentinel.detection.rules.suspicious_login import SuspiciousLoginRule

__all__ = [
    "SSHBruteForceRule",
    "PortScanRule",
    "SuspiciousLoginRule",
]
