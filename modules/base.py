"""Module base classes and data structures.

Every scan module subclasses :class:`BaseModule` and implements ``run``,
returning a :class:`ModuleResult` containing a dictionary of findings plus
structured ``Finding`` records for the report generator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# Severity is deliberately limited to *informational* labels only, in line
# with RACON's defensive/auditing scope.
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    """A single reportable finding within a module result.

    Attributes:
        title: Short human-readable title.
        severity: One of :data:`SEVERITIES` (informational labeling).
        description: Detailed explanation of the observation.
        evidence: Optional raw evidence (headers, config lines, URLs).
        recommendation: Optional defensive remediation guidance.
    """

    title: str
    severity: str = "info"
    description: str = ""
    evidence: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class ModuleResult:
    """Outcome of a single module execution.

    Attributes:
        module: Name of the module (class name).
        status: ``success``, ``skipped``, ``error`` or ``not_applicable``.
        data: Free-form dict of findings consumed by report templates.
        findings: Structured list of :class:`Finding` records.
        error: Error message when ``status == "error"``.
        started: Unix timestamp of module start.
        elapsed: Seconds the module ran.
    """

    module: str
    status: str = "success"
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    started: float = 0.0
    elapsed: float = 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "elapsed": round(self.elapsed, 2),
            "finding_count": len(self.findings),
            "error": self.error,
        }


class BaseModule(ABC):
    """Abstract base class for all RACON scan modules."""

    #: Human-readable display name used in the CLI dashboard.
    name = "Module"
    #: Unique identifier / configuration key.
    key = "module"

    def __init__(self, config: Any, http: Any, context: dict[str, Any]) -> None:
        """Initialize a module.

        Args:
            config: The runtime :class:`~core.config.Config`.
            http: The shared :class:`~core.http.HTTPClient`.
            context: Shared scan context (target, hostname, resolution info).
        """
        self.config = config
        self.http = http
        self.context = context

    @property
    def target(self) -> str:
        """The normalized target hostname from the shared context."""
        return str(self.context.get("target", ""))

    @property
    def base_url(self) -> str:
        """The scheme://hostname base URL from the shared context."""
        return str(self.context.get("base_url", ""))

    def enabled(self) -> bool:
        """Whether this module is enabled by configuration."""
        return self.config.module_enabled(self.key)

    def run(self) -> ModuleResult:
        """Execute the module and return a :class:`ModuleResult`."""
        import time

        started = time.time()
        result = ModuleResult(module=self.__class__.__name__)
        if not self.enabled():
            result.status = "skipped"
            result.elapsed = time.time() - started
            return result
        try:
            self.execute(result)
        except Exception as exc:  # noqa: BLE001
            result.status = "error"
            result.error = f"{type(exc).__name__}: {exc}"
            self.log_error("Module %s failed: %s", self.name, result.error)
        finally:
            result.elapsed = time.time() - started
        return result

    @abstractmethod
    def execute(self, result: ModuleResult) -> None:
        """Implement the module logic, populating ``result``.

        Subclasses should set ``result.data`` and append to
        ``result.findings``, or set ``result.status``.
        """
        raise NotImplementedError

    # -- convenience logging helpers ---------------------------------------
    def log_debug(self, msg: str, *args: Any) -> None:
        from core.logger import get_logger

        get_logger().debug(f"[{self.name}] " + msg, *args)

    def log_info(self, msg: str, *args: Any) -> None:
        from core.logger import get_logger

        get_logger().info(f"[{self.name}] " + msg, *args)

    def log_warn(self, msg: str, *args: Any) -> None:
        from core.logger import get_logger

        get_logger().warning(f"[{self.name}] " + msg, *args)

    def log_error(self, msg: str, *args: Any) -> None:
        from core.logger import get_logger

        get_logger().error(f"[{self.name}] " + msg, *args)
