"""Tests for configuration loading and overrides."""

from __future__ import annotations

import yaml

from core.config import load_config
from core.exceptions import ConfigurationError


def test_defaults_loaded():
    cfg = load_config()
    assert cfg.threads == 10
    assert cfg.request_timeout == 15
    assert cfg.max_retries == 3
    assert cfg.module_enabled("basic_info") is True
    assert cfg.user_agents  # has at least one UA


def test_output_dir_resolved_absolute():
    cfg = load_config()
    import os

    assert os.path.isabs(cfg.output_dir)


def test_module_toggle():
    cfg = load_config()
    cfg.set("modules.wordpress", False)
    assert cfg.module_enabled("wordpress") is False
    assert cfg.module_enabled("basic_info") is True


def test_cli_style_override():
    cfg = load_config()
    cfg.set("scan.threads", 20)
    cfg.set("output.report_format", "json")
    assert cfg.threads == 20
    assert cfg.report_format == "json"


def test_invalid_config_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("scan: [unclosed", encoding="utf-8")
    try:
        load_config(bad)
    except ConfigurationError:
        pass
    else:
        raise AssertionError("Expected ConfigurationError")


def test_custom_config_file(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.safe_dump({"scan": {"threads": 3}, "output": {"report_format": "csv"}}),
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.threads == 3
    assert cfg.report_format == "csv"
