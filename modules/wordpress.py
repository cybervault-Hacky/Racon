"""WordPress module.

Performs fingerprinting when a WordPress installation is detected: core
version, theme detection, plugin enumeration and REST API detection. All
checks are passive/based on public endpoints and response headers.
"""

from __future__ import annotations

import re

from modules.base import BaseModule, Finding, ModuleResult


class WordPressModule(BaseModule):
    """WordPress-specific information gathering."""

    name = "WordPress"
    key = "wordpress"

    def execute(self, result: ModuleResult) -> None:
        base = self.base_url.rstrip("/")
        home = self.http.get(base)
        html = home.text if home.ok else ""

        is_wp = self._detect_wordpress(html, home.headers)
        if not is_wp:
            result.status = "not_applicable"
            result.data["wordpress"] = {"detected": False}
            result.findings.append(Finding(
                title="WordPress Not Detected",
                severity="info",
                description="No WordPress fingerprint was found on the target.",
            ))
            return

        version = self._version(html, home.headers)
        theme = self._theme(html)
        plugins = self._plugins(html)
        rest_api = self._rest_api(base)

        result.data["wordpress"] = {
            "detected": True,
            "version": version,
            "theme": theme,
            "plugins": plugins,
            "rest_api": rest_api,
        }

        result.findings.append(Finding(
            title="WordPress Detected",
            severity="info",
            description="The target runs WordPress.",
            evidence=", ".join(filter(None, [version, theme])) or "fingerprint only",
        ))
        if version:
            result.findings.append(Finding(
                title="WordPress Version: " + version,
                severity="info",
                description="The WordPress core version was disclosed.",
                evidence=version,
                recommendation=(
                    "Verify the version is current and patched against known "
                    "advisories."
                ),
            ))
        if theme:
            result.findings.append(Finding(
                title="Active Theme: " + theme,
                severity="info",
                description="The active WordPress theme was identified.",
                evidence=theme,
                recommendation="Keep the theme and any child themes updated.",
            ))
        if plugins:
            result.findings.append(Finding(
                title="WordPress Plugins Detected",
                severity="info",
                description=f"{len(plugins)} plugin(s) were identified.",
                evidence=", ".join(plugins),
                recommendation=(
                    "Inventory plugins and verify each is current and actively "
                    "maintained."
                ),
            ))
        if rest_api:
            result.findings.append(Finding(
                title="WordPress REST API Accessible",
                severity="info",
                description="The WordPress REST API is publicly reachable.",
                evidence=rest_api,
                recommendation="Restrict API access if public exposure is unnecessary.",
            ))
        else:
            result.findings.append(Finding(
                title="WordPress REST API Not Detected",
                severity="info",
                description="The REST API endpoint was not reachable at the expected path.",
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _detect_wordpress(html: str, headers: dict) -> bool:
        if not html:
            return False
        lowered = html[:500000].lower()
        hints = [
            "wp-content", "wp-includes", "wp-json", "wordpress",
            "wp-emoji", "wp-embed",
        ]
        for hint in hints:
            if hint in lowered:
                return True
        # Header-based hint.
        for key, value in headers.items():
            if key.lower() == "x-powered-by" and "wordpress" in value.lower():
                return True
        return False

    @staticmethod
    def _version(html: str, headers: dict) -> str | None:
        # Generator meta tag.
        match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']'
            r'WordPress\s*([0-9][^"\']*)["\']',
            html, re.IGNORECASE,
        )
        if match:
            return match.group(1).strip()
        # Comment-based version.
        match = re.search(
            r'<!--\s*Site built with WordPress\s+([0-9][^ ]*)\s*-->',
            html, re.IGNORECASE,
        )
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _theme(html: str) -> str | None:
        # Theme assets in /wp-content/themes/<name>/
        match = re.search(r'wp-content/themes/([^/]+)/', html)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _plugins(html: str) -> list[str]:
        plugins: list[str] = []
        matches = re.findall(r'wp-content/plugins/([^/"\'?]+)', html)
        for slug in matches:
            slug = slug.strip()
            if slug and slug not in plugins:
                plugins.append(slug)
        return plugins

    def _rest_api(self, base: str) -> str | None:
        resp = self.http.get(f"{base}/wp-json/", use_cache=True)
        if resp.ok:
            return f"{base}/wp-json/"
        resp2 = self.http.get(f"{base}/?rest_route=/", use_cache=True)
        if resp2.ok:
            return f"{base}/?rest_route=/"
        return None
