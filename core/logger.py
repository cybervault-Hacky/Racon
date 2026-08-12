"""Logging setup for RACON.

Provides a process-wide logger with optional file output and a per-scan
history tracker that records scan metadata (target, timestamp, duration,
status) to ``output/scans/history.jsonl``.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

# Module-level state --------------------------------------------------------

_LOGGER: logging.Logger | None = None
_RICH_CONSOLE: Console | None = None

LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class ScanHistory:
    """Append-only JSONL scan history persisted under ``output/scans``."""

    def __init__(self, history_dir: str, enabled: bool = True) -> None:
        self.enabled = enabled
        self.path = Path(history_dir) / "history.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._current: dict[str, Any] | None = None

    def start(self, target: str, modules: list[str]) -> None:
        """Record the beginning of a scan."""
        if not self.enabled:
            return
        self._current = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "modules": modules,
            "status": "running",
            "start_time": time.time(),
            "duration_s": None,
            "elapsed_time": None,
        }

    def finish(self, status: str, elapsed_time: str) -> None:
        """Record the completion (or abort) of a scan."""
        if not self.enabled or self._current is None:
            return
        self._current["status"] = status
        self._current["elapsed_time"] = elapsed_time
        if self._current.get("start_time") is not None:
            self._current["duration_s"] = round(
                time.time() - self._current["start_time"], 2
            )
        self._current.pop("start_time", None)
        self._append(self._current)
        self._current = None

    def _append(self, record: dict[str, Any]) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass


def get_console() -> Console:
    """Return the shared Rich console instance."""
    global _RICH_CONSOLE
    if _RICH_CONSOLE is None:
        _RICH_CONSOLE = Console()
    return _RICH_CONSOLE


def get_logger() -> logging.Logger:
    """Return the configured process-wide logger."""
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    _LOGGER = _build_logger("RACON", level="INFO", to_file=False, log_dir="output/logs")
    return _LOGGER


def _build_logger(
    name: str,
    level: str,
    to_file: bool,
    log_dir: str | Path,
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(LEVELS.get(level.upper(), logging.INFO))
    logger.propagate = False

    console = get_console()
    handler = RichHandler(
        console=console,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
        level=LEVELS.get(level.upper(), logging.INFO),
    )
    handler.setLevel(LEVELS.get(level.upper(), logging.INFO))
    formatter = logging.Formatter("%(name)s - %(message)s")
    handler.setFormatter(formatter)
    logger.handlers.clear()
    logger.addHandler(handler)

    if to_file:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "racon.log", encoding="utf-8")
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh.setFormatter(file_fmt)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

    return logger


def setup_logging(
    level: str = "INFO",
    to_file: bool = True,
    log_dir: str | Path = "output/logs",
) -> logging.Logger:
    """Initialize the global logger (idempotent reconfiguration)."""
    global _LOGGER
    _LOGGER = _build_logger("RACON", level, to_file, log_dir)
    return _LOGGER


def reset_logging() -> None:
    """Remove all handlers (used primarily by tests)."""
    global _LOGGER
    if _LOGGER is not None:
        for handler in list(_LOGGER.handlers):
            _LOGGER.removeHandler(handler)
        _LOGGER = None
