"""Configuration management for RACON.

Loads ``config.yaml`` (or an alternate path) and exposes a typed,
attribute-style view over the merged settings. CLI overrides are applied
on top of the file defaults.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from ruamel.yaml import YAML
    _yaml = YAML(typ="safe")
except Exception:  # noqa: BLE001
    # Graceful fallback for environments without ruamel.yaml
    _yaml = None

from core.exceptions import ConfigurationError

DEFAULT_CONFIG = {
    "scan": {
        "threads": 10,
        "request_timeout": 15,
        "max_retries": 3,
        "verify_ssl": True,
        "follow_redirects": True,
        "crawl_depth": 2,
        "max_pages": 50,
        "subdomain_limit": 100,
    },
    "user_agents": [],
    "output": {
        "directory": "output",
        "report_format": "html",
        "theme": "auto",
    },
    "logging": {
        "level": "INFO",
        "file": True,
        "history": True,
    },
    "reporting": {
        "company_name": "RACON",
        "author": "Security Assessment Team",
        "classification": "Confidential",
        "include_screenshots_placeholder": True,
    },
    "modules": {
        "basic_info": True,
        "dns_intelligence": True,
        "domain_intelligence": True,
        "network": True,
        "web_enumeration": True,
        "wordpress": True,
        "subdomains": True,
        "ssl_analysis": True,
    },
    "network": {
        "nmap_enabled": True,
        "nmap_binary": "nmap",
        "port_range": "80,443,8080,8443",
        "scan_speed": "T3",
    },
    "passive_sources": {
        "crt_sh": True,
        "hackertarget": True,
    },
}

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into a copy of ``base``."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class Config:
    """Typed, merged runtime configuration."""

    raw: dict[str, Any] = field(default_factory=dict)

    # -- scan ---------------------------------------------------------------
    @property
    def threads(self) -> int:
        return int(self.raw.get("scan", {}).get("threads", 10))

    @property
    def request_timeout(self) -> int:
        return int(self.raw.get("scan", {}).get("request_timeout", 15))

    @property
    def max_retries(self) -> int:
        return int(self.raw.get("scan", {}).get("max_retries", 3))

    @property
    def verify_ssl(self) -> bool:
        return bool(self.raw.get("scan", {}).get("verify_ssl", True))

    @property
    def follow_redirects(self) -> bool:
        return bool(self.raw.get("scan", {}).get("follow_redirects", True))

    @property
    def crawl_depth(self) -> int:
        return int(self.raw.get("scan", {}).get("crawl_depth", 2))

    @property
    def max_pages(self) -> int:
        return int(self.raw.get("scan", {}).get("max_pages", 50))

    @property
    def subdomain_limit(self) -> int:
        return int(self.raw.get("scan", {}).get("subdomain_limit", 100))

    # -- user agents --------------------------------------------------------
    @property
    def user_agents(self) -> list[str]:
        agents = self.raw.get("user_agents") or []
        if not agents:
            agents = DEFAULT_USER_AGENTS
        return [str(a) for a in agents if a]

    # -- output -------------------------------------------------------------
    @property
    def output_dir(self) -> str:
        return str(self.raw.get("output", {}).get("directory", "output"))

    @property
    def report_format(self) -> str:
        return str(self.raw.get("output", {}).get("report_format", "html"))

    @property
    def theme(self) -> str:
        return str(self.raw.get("output", {}).get("theme", "auto"))

    # -- logging ------------------------------------------------------------
    @property
    def log_level(self) -> str:
        return str(self.raw.get("logging", {}).get("level", "INFO")).upper()

    @property
    def log_to_file(self) -> bool:
        return bool(self.raw.get("logging", {}).get("file", True))

    @property
    def history_enabled(self) -> bool:
        return bool(self.raw.get("logging", {}).get("history", True))

    # -- reporting ----------------------------------------------------------
    @property
    def company_name(self) -> str:
        return str(self.raw.get("reporting", {}).get("company_name", "RACON"))

    @property
    def author(self) -> str:
        return str(self.raw.get("reporting", {}).get("author", "Security Assessment Team"))

    @property
    def classification(self) -> str:
        return str(self.raw.get("reporting", {}).get("classification", "Confidential"))

    @property
    def screenshots_placeholder(self) -> bool:
        return bool(self.raw.get("reporting", {}).get("include_screenshots_placeholder", True))

    # -- modules ------------------------------------------------------------
    def module_enabled(self, name: str) -> bool:
        return bool(self.raw.get("modules", {}).get(name, True))

    # -- network ------------------------------------------------------------
    @property
    def nmap_enabled(self) -> bool:
        return bool(self.raw.get("network", {}).get("nmap_enabled", True))

    @property
    def nmap_binary(self) -> str:
        return str(self.raw.get("network", {}).get("nmap_binary", "nmap"))

    @property
    def port_range(self) -> str:
        return str(self.raw.get("network", {}).get("port_range", "80,443,8080,8443"))

    @property
    def scan_speed(self) -> str:
        return str(self.raw.get("network", {}).get("scan_speed", "T3"))

    # -- passive ------------------------------------------------------------
    def source_enabled(self, name: str) -> bool:
        return bool(self.raw.get("passive_sources", {}).get(name, True))

    # -- helpers ------------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        """Fetch a nested value using dot notation, e.g. ``scan.threads``."""
        node: Any = self.raw
        for part in dotted.split("."):
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return default
            if node is None:
                return default
        return node

    def set(self, dotted: str, value: Any) -> None:
        """Set a nested value using dot notation, creating dicts as needed."""
        parts = dotted.split(".")
        node = self.raw
        for part in parts[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                node[part] = nxt
            node = nxt
        node[parts[-1]] = value


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from ``path`` (or the project default ``config.yaml``).

    Args:
        path: Optional explicit path to a YAML config file.

    Returns:
        A merged, typed :class:`Config` instance.

    Raises:
        ConfigurationError: If the YAML file exists but is invalid.
    """
    merged = copy.deepcopy(DEFAULT_CONFIG)

    if path is None:
        default_path = Path(__file__).resolve().parent.parent / "config.yaml"
        path = default_path

    path = Path(path)
    if path.exists():
        try:
            with path.open("r", encoding="utf-8") as fh:
                if _yaml is not None:
                    loaded = _yaml.load(fh) or {}
                else:
                    # Fallback: treat as empty config if YAML parser missing
                    loaded = {}
        except Exception as exc:  # noqa: BLE001
            from ruamel.yaml.error import YAMLError
            if isinstance(exc, YAMLError):
                raise ConfigurationError(f"Invalid YAML in {path}: {exc}") from exc
            raise ConfigurationError(f"Failed to load config {path}: {exc}") from exc
        merged = _deep_merge(merged, loaded)
    elif str(path) != "config.yaml":
        raise ConfigurationError(f"Config file not found: {path}")

    # Resolve relative output dir against the project root.
    project_root = Path(__file__).resolve().parent.parent
    out_dir = merged["output"]["directory"]
    if not os.path.isabs(out_dir):
        out_dir = str(project_root / out_dir)
    merged["output"]["directory"] = out_dir

    return Config(raw=merged)
