"""Scan orchestrator.

Validates the target, builds a shared execution context, runs the enabled
modules in order (reporting progress), collects results and delegates report
generation and scan-history persistence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core import utils
from core.config import Config
from core.http import HTTPClient
from core.output import OutputManager
from core.reporting import ReportGenerator
from core.logger import ScanHistory, get_logger

log = get_logger()


@dataclass
class ScanResult:
    """Aggregated outcome of a full scan run."""

    target: str
    domain: str
    metadata: dict[str, Any] = field(default_factory=dict)
    module_results: list[Any] = field(default_factory=list)
    started: float = 0.0
    elapsed: float = 0.0
    report_paths: list[str] = field(default_factory=list)
    status: str = "success"

    def summary(self) -> dict[str, Any]:
        completed = sum(1 for m in self.module_results if m.status == "success")
        return {
            "target": self.target,
            "domain": self.domain,
            "status": self.status,
            "modules_completed": completed,
            "modules_total": len(self.module_results),
            "elapsed": round(self.elapsed, 2),
            "reports": self.report_paths,
        }


class Scanner:
    """Coordinates a full RACON assessment run."""

    def __init__(self, config: Config, target: str) -> None:
        self.config = config
        self.raw_target = target
        self.output = OutputManager(config.output_dir)
        self.output.ensure_dirs()
        self.http = HTTPClient(config)
        self.history = ScanHistory(str(self.output.scans_dir), config.history_enabled)
        # Optional UI hook for live progress updates.
        self.progress_callback: Callable[[int, int, str], None] | None = None

        # Validate & normalize the target up front.
        self.scheme, self.host, self.port = utils.parse_target(target)
        self.target = utils.normalize_target(target)
        if not utils.is_valid_target(self.target):
            from core.exceptions import InvalidTargetError

            raise InvalidTargetError(f"Invalid target: {target!r}")

        self.domain = utils.extract_root_domain(self.target)
        self.base_url = self._resolve_base_url()

        self._context: dict[str, Any] = {
            "target": self.target,
            "domain": self.domain,
            "base_url": self.base_url,
            "ips": utils.resolve_hostname(self.target),
        }

    # ------------------------------------------------------------------ setup
    def _resolve_base_url(self) -> str:
        """Determine the base URL for the target.

        Honors an explicit scheme/port from the target string. Otherwise
        prefers https, falling back to http when TLS is unavailable.
        """
        if self.scheme and self.port:
            return f"{self.scheme}://{self.host}:{self.port}"
        if self.port:
            # No scheme but explicit port: assume http.
            return f"http://{self.host}:{self.port}"
        if utils.is_ip(self.target):
            return f"https://{self.target}"
        if self.scheme:
            return f"{self.scheme}://{self.target}"
        # Quick reachability check.
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            resp = self.http.request("HEAD", url, use_cache=False)
            if resp.ok:
                return url
            if resp.status_code and 400 <= resp.status_code < 500:
                # Server is up but rejected HEAD; still prefer https.
                return f"https://{self.target}"
        return f"https://{self.target}"

    # ------------------------------------------------------------------ build
    def build_modules(self) -> list[Any]:
        """Instantiate the ordered list of enabled modules."""
        from modules import MODULES

        modules = []
        for cls in MODULES:
            if self.config.module_enabled(cls.key):
                modules.append(cls(self.config, self.http, self._context))
        return modules

    # ------------------------------------------------------------------ run
    def run(self, formats: str | None = None, modules: list[str] | None = None) -> ScanResult:
        """Execute the full scan and generate reports.

        Args:
            formats: Override the output report format(s).
            modules: Optional list of module keys to restrict to.

        Returns:
            A populated :class:`ScanResult`.
        """
        started = time.time()
        result = ScanResult(target=self.target, domain=self.domain, started=started)
        module_keys = modules if modules else None

        selected = self.build_modules()
        if module_keys:
            selected = [m for m in selected if m.key in module_keys]

        enabled_keys = [m.key for m in selected]
        self.history.start(self.target, enabled_keys)
        self.metadata = self._make_metadata()

        total = len(selected)
        log.info("Starting RACON scan against %s (%d module(s))", self.target, total)

        for index, module in enumerate(selected, start=1):
            if self.progress_callback:
                self.progress_callback(index - 1, total, module.name)
            log.info("[%d/%d] Running module: %s", index, total, module.name)
            module_result = module.run()
            result.module_results.append(module_result)
            if module_result.status == "error":
                log.error("Module %s finished with error: %s",
                          module.name, module_result.error)

        if self.progress_callback:
            self.progress_callback(total, total, "Reporting")

        # Report generation.
        fmt = formats or self.config.report_format
        report_dir = self.output.reports_dir
        generator = ReportGenerator(
            config=self.config,
            results=result.module_results,
            target=self.target,
            metadata=self.metadata,
            templates_dir=Path(__file__).resolve().parent.parent / "templates",
        )
        paths = generator.generate(fmt, report_dir)
        result.report_paths = [str(p) for p in paths]

        result.elapsed = time.time() - started
        result.metadata = self.metadata
        result.status = "success"

        self.history.finish("success", f"{result.elapsed:.1f}s")
        self.http.clear_cache()
        return result

    def _make_metadata(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "domain": self.domain,
            "timestamp": utils.iso_now(),
            "tool": "RACON Reconnaissance & Analysis Console",
            "classification": self.config.classification,
            "author": self.config.author,
            "company_name": self.config.company_name,
        }

    def abort(self) -> None:
        """Gracefully mark a scan as aborted (KeyboardInterrupt path)."""
        log.warning("Scan aborted by user")
        self.history.finish("aborted", "0.0s")
