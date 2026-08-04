"""Output directory management for RACON.

Creates and tracks the canonical directory layout::

    output/
        reports/
        logs/
        scans/
"""

from __future__ import annotations

from pathlib import Path


class OutputManager:
    """Manages the output directory structure for a single scan run."""

    def __init__(self, base_dir: str) -> None:
        self.base = Path(base_dir)
        self.reports_dir = self.base / "reports"
        self.logs_dir = self.base / "logs"
        self.scans_dir = self.base / "scans"

    def ensure_dirs(self) -> None:
        """Create the required sub-directories if they do not exist."""
        for path in (self.base, self.reports_dir, self.logs_dir, self.scans_dir):
            path.mkdir(parents=True, exist_ok=True)

    def report_path(self, filename: str) -> Path:
        """Return a resolved path under ``reports``."""
        return self.reports_dir / filename

    def log_path(self, filename: str) -> Path:
        """Return a resolved path under ``logs``."""
        return self.logs_dir / filename

    def scan_path(self, filename: str) -> Path:
        """Return a resolved path under ``scans``."""
        return self.scans_dir / filename

    def summary(self) -> str:
        """Return a human-readable summary of the output tree."""
        return (
            f"Reports : {self.reports_dir}\n"
            f"Logs    : {self.logs_dir}\n"
            f"Scans   : {self.scans_dir}"
        )
