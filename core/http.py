"""HTTP client abstraction for RACON.

Provides connection pooling, user-agent rotation, retry with exponential
backoff, and smart caching. All modules use this client so behaviour
(timeouts, retries, headers) is consistent across the framework.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.config import Config
from core.logger import get_logger

log = get_logger()


@dataclass
class HttpResponse:
    """Thin wrapper around a ``requests.Response`` we care about."""

    ok: bool
    status_code: int | None
    url: str | None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    elapsed: float = 0.0
    error: str | None = None

    def header(self, name: str, default: str | None = None) -> str | None:
        """Case-insensitive header lookup."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


class HTTPClient:
    """A configured HTTP client with retries, caching and UA rotation."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.timeout = config.request_timeout
        self.verify = config.verify_ssl
        self.allow_redirects = config.follow_redirects
        self.max_retries = config.max_retries
        self.user_agents = config.user_agents

        self._cache: dict[str, HttpResponse] = {}
        self._cache_ttl = 120.0

        retry = Retry(
            total=config.max_retries,
            connect=config.max_retries,
            read=config.max_retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
        )
        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=config.threads * 2,
            max_retries=retry,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    # ------------------------------------------------------------------ UA
    def user_agent(self) -> str:
        """Return a (possibly random) User-Agent from the configured pool."""
        if len(self.user_agents) == 1:
            return self.user_agents[0]
        return random.choice(self.user_agents)

    def headers(self, **extra: str) -> dict[str, str]:
        """Return default request headers merged with ``extra``."""
        base = {
            "User-Agent": self.user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Connection": "keep-alive",
        }
        base.update(extra)
        return base

    # ------------------------------------------------------------- requests
    def _cache_key(self, method: str, url: str, **kwargs: Any) -> str:
        return f"{method}|{url}|{kwargs.get('params', '')}"

    def request(
        self,
        method: str,
        url: str,
        use_cache: bool = True,
        **kwargs: Any,
    ) -> HttpResponse:
        """Perform an HTTP request with caching, retry and error handling."""
        cache_key = self._cache_key(method, url, **kwargs)
        if use_cache and method.upper() in ("GET", "HEAD") and cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - getattr(cached, "_ts", 0) < self._cache_ttl:
                return cached

        headers = kwargs.pop("headers", {})
        default_headers = self.headers()
        default_headers.update(headers)

        started = time.time()
        resp = HttpResponse(ok=False, status_code=None, url=url)
        try:
            r = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=self.allow_redirects,
                headers=default_headers,
                **kwargs,
            )
            resp.ok = r.ok
            resp.status_code = r.status_code
            resp.url = r.url
            resp.headers = dict(r.headers)
            resp.elapsed = time.time() - started
            if "html" in (r.headers.get("Content-Type", "")).lower() or method in (
                "GET",
                "HEAD",
            ):
                try:
                    resp.text = r.text
                except Exception:
                    resp.text = ""
                resp.content = r.content
        except requests.exceptions.RequestException as exc:
            resp.error = str(exc)
            log.debug("HTTP %s %s failed: %s", method, url, exc)
        except Exception as exc:  # noqa: BLE001
            resp.error = f"{type(exc).__name__}: {exc}"
            log.debug("HTTP %s %s unexpected error: %s", method, url, exc)

        if use_cache and method.upper() in ("GET", "HEAD"):
            resp._ts = time.time()  # type: ignore[attr-defined]
            self._cache[cache_key] = resp
        return resp

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        """Perform a GET request."""
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpResponse:
        """Perform a HEAD request."""
        return self.request("HEAD", url, **kwargs)

    def get_text(self, url: str, **kwargs: Any) -> str:
        """GET and return response text (empty on failure)."""
        return self.get(url, **kwargs).text

    def clear_cache(self) -> None:
        """Drop all cached responses."""
        self._cache.clear()
