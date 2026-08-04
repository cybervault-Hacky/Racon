"""End-to-end tests for the scan orchestrator against a local server."""

from __future__ import annotations

import json
from pathlib import Path

from core.scanner import Scanner
from core.exceptions import InvalidTargetError
from core.config import load_config
from core.logger import reset_logging


def test_invalid_target_raises():
    try:
        Scanner(load_config(), "bad host !")
    except InvalidTargetError:
        pass
    else:
        raise AssertionError("Expected InvalidTargetError")


def _load_config(tmp_path):
    from core.config import load_config

    cfg = load_config()
    cfg.set("output.directory", str(tmp_path))
    cfg.set("modules.network", False)
    cfg.set("modules.domain_intelligence", False)
    cfg.set("modules.subdomains", False)
    cfg.set("modules.ssl_analysis", False)
    return cfg


def test_full_scan_local(http_server, tmp_path):
    reset_logging()
    cfg = _load_config(tmp_path)
    scanner = Scanner(cfg, http_server)
    result = scanner.run(formats="html,json")

    assert result.status == "success"
    assert len(result.report_paths) == 2

    json_path = Path(result.report_paths[1])
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    modules = payload["modules"]
    assert "BasicInfoModule" in modules
    assert modules["BasicInfoModule"]["basic_info"]["http_status"] == 200


def test_scan_restricted_modules(http_server, tmp_path):
    reset_logging()
    cfg = _load_config(tmp_path)
    scanner = Scanner(cfg, http_server)
    result = scanner.run(formats="json", modules=["basic_info"])
    assert result.status == "success"
    json_path = Path(result.report_paths[0])
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert set(payload["modules"].keys()) == {"BasicInfoModule"}
