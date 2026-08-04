"""Tests for the HTTP client."""

from __future__ import annotations

from core.config import load_config
from core.http import HTTPClient


def test_get_success(http_server):
    cfg = load_config()
    client = HTTPClient(cfg)
    resp = client.get(http_server)
    assert resp.ok is True
    assert resp.status_code == 200
    assert "Acme Test Site" in resp.text


def test_http_client_caching(http_server):
    cfg = load_config()
    client = HTTPClient(cfg)
    r1 = client.get(http_server)
    r2 = client.get(http_server)
    assert r1.text == r2.text
    client.clear_cache()


def test_request_404(http_server):
    cfg = load_config()
    client = HTTPClient(cfg)
    resp = client.get(f"{http_server}/missing")
    assert resp.status_code == 404
    assert resp.ok is False


def test_user_agent_headers():
    cfg = load_config()
    client = HTTPClient(cfg)
    headers = client.headers()
    assert "User-Agent" in headers
    assert headers["User-Agent"].startswith("Mozilla")
