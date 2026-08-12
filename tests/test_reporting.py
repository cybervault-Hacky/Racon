"""Tests for report generation across all supported formats."""

from __future__ import annotations

import json
from pathlib import Path

from modules.base import Finding, ModuleResult
from core.config import load_config
from core.reporting import ReportGenerator


def _sample_results():
    r1 = ModuleResult(module="BasicInfoModule", status="success", elapsed=1.2)
    r1.data["basic_info"] = {"http_status": 200}
    r1.findings.append(Finding(
        title="Web Server Detected", severity="info",
        description="Server header exposed.", evidence="nginx",
        recommendation="Obfuscate version.",
    ))
    r2 = ModuleResult(module="NetworkModule", status="success", elapsed=0.3)
    r2.data["network"] = {"ip": "127.0.0.1"}
    return [r1, r2]


def _generator(tmp_path):
    cfg = load_config()
    cfg.set("output.directory", str(tmp_path))
    return ReportGenerator(
        config=cfg,
        results=_sample_results(),
        target="example.com",
        metadata={"target": "example.com", "timestamp": "2026-01-01T00:00:00Z",
                  "classification": "Confidential", "author": "Tester",
                  "company_name": "RACON"},
        templates_dir=Path(__file__).resolve().parent.parent / "templates",
    )


def test_generate_html(tmp_path):
    paths = _generator(tmp_path).generate("html", tmp_path)
    assert len(paths) == 1
    html = paths[0].read_text(encoding="utf-8")
    assert "<html" in html
    assert "Executive Summary" in html
    assert "example.com" in html


def test_generate_json(tmp_path):
    paths = _generator(tmp_path).generate("json", tmp_path)
    payload = json.loads(paths[0].read_text(encoding="utf-8"))
    assert "summary" in payload
    assert "findings" in payload
    assert payload["findings"][0]["title"] == "Web Server Detected"


def test_generate_csv(tmp_path):
    paths = _generator(tmp_path).generate("csv", tmp_path)
    content = paths[0].read_text(encoding="utf-8")
    assert "module,title,severity" in content
    assert "Web Server Detected" in content


def test_generate_pdf(tmp_path):
    paths = _generator(tmp_path).generate("pdf", tmp_path)
    data = paths[0].read_bytes()
    assert data.startswith(b"%PDF")


def test_generate_all(tmp_path):
    paths = _generator(tmp_path).generate("all", tmp_path)
    ext = {p.suffix for p in paths}
    assert {".html", ".json", ".csv", ".pdf"} <= ext


def test_all_formats_include_severity_and_metadata(tmp_path):
    paths = _generator(tmp_path).generate("all", tmp_path)
    html = next(p for p in paths if p.suffix == ".html").read_text()
    assert "info" in html.lower()
    assert "Classification" in html
