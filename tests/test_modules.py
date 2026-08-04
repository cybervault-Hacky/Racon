"""Tests for individual scan modules using the local HTTP server."""

from __future__ import annotations

from core.http import HTTPClient
from modules.basic_info import BasicInfoModule
from modules.web_enumeration import WebEnumerationModule
from modules.wordpress import WordPressModule


def _run_module(config, http, context, cls):
    module = cls(config, http, context)
    result = module.run()
    return result


def _context(base_url):
    from urllib.parse import urlparse

    host = urlparse(base_url).netloc
    return {"target": host, "domain": "localhost",
            "base_url": base_url, "ips": ["127.0.0.1"]}


def test_basic_info_module(http_server, config):
    ctx = _context(http_server)
    result = _run_module(config, HTTPClient(config), ctx, BasicInfoModule)
    assert result.status == "success"
    data = result.data["basic_info"]
    assert data["http_status"] == 200
    assert data["site_title"] == "Acme Test Site"


def test_basic_info_detects_wordpress(http_server, config):
    ctx = _context(http_server)
    result = _run_module(config, HTTPClient(config), ctx, BasicInfoModule)
    data = result.data["basic_info"]
    assert data["cms"] == "WordPress"


def test_web_enumeration_module(http_server, config):
    ctx = _context(http_server)
    result = _run_module(config, HTTPClient(config), ctx, WebEnumerationModule)
    assert result.status == "success"
    data = result.data["web"]
    assert data["robots_txt"] is not None
    assert "contact@acme.example" in data["emails"]
    assert any("/js/app.min.js" in u for u in data["js_files"])
    assert data["crawl"]["total"] >= 1


def test_wordpress_module(http_server, config):
    ctx = _context(http_server)
    result = _run_module(config, HTTPClient(config), ctx, WordPressModule)
    assert result.status == "success"
    data = result.data["wordpress"]
    assert data["detected"] is True
    assert data["version"] == "6.5.3"
    assert data["theme"] == "twentytwentyfour"


def test_disabled_module_is_skipped(http_server, config):
    config.set("modules.wordpress", False)
    ctx = _context(http_server)
    result = _run_module(config, HTTPClient(config), ctx, WordPressModule)
    assert result.status == "skipped"
