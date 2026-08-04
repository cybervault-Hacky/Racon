"""Pytest fixtures for RACON tests.

Provides a local HTTP server fixture so HTTP-based modules can be tested
without internet access.
"""

from __future__ import annotations

import functools
import http.server
import threading
from pathlib import Path

import pytest

from core.config import load_config

INDEX_HTML = """<!DOCTYPE html>
<html><head>
<title>Acme Test Site</title>
<meta name="generator" content="WordPress 6.5.3">
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<script src="/wp-includes/js/jquery.js"></script>
<script src="/js/app.min.js"></script>
</head><body>
<a href="/about">About</a>
<a href="https://twitter.com/acme">Twitter</a>
<a href="mailto:contact@acme.example">Contact</a>
</body></html>"""

ROBOTS_TXT = "User-agent: *\nDisallow: /admin\n"


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # silence request logging
        pass

    def do_GET(self):
        if self.path == "/":
            self._respond(200, "text/html", INDEX_HTML.encode())
        elif self.path == "/robots.txt":
            self._respond(200, "text/plain", ROBOTS_TXT.encode())
        elif self.path == "/sitemap.xml":
            self._respond(200, "text/xml",
                          b'<urlset><url><loc>/</loc></url></urlset>')
        elif self.path == "/about":
            self._respond(200, "text/html",
                          b"<html><head><title>About</title></head><body>"
                          b"hr@acme.example</body></html>")
        else:
            self._respond(404, "text/html", b"not found")

    def _respond(self, status: int, ctype: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="session")
def http_server():
    """Start a single local HTTP server for the whole test session."""
    handler = functools.partial(_Handler, directory=str(Path(__file__).parent))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="function")
def config(tmp_path):
    """Return a Config with a temp output directory."""
    cfg = load_config()
    cfg.set("output.directory", str(tmp_path))
    cfg.set("modules.network", False)  # no ping/nmap in tests
    return cfg
