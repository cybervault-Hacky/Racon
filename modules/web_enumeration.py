"""Web Enumeration module.

Discovers and analyzes publicly accessible web resources: robots.txt,
sitemap.xml, page links, emails, social media links, JavaScript files,
cookies, security headers and a set of common sensitive public files.
Also runs a lightweight website crawler.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup

from core import utils
from modules.base import BaseModule, Finding, ModuleResult

#: Common sensitive/disclosure files worth probing (informational only).
SENSITIVE_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/admin",
]

#: Social media domain hints.
SOCIAL_DOMAINS = {
    "twitter.com": "Twitter/X",
    "x.com": "Twitter/X",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "youtube.com": "YouTube",
    "github.com": "GitHub",
    "tiktok.com": "TikTok",
    "pinterest.com": "Pinterest",
    "reddit.com": "Reddit",
    "medium.com": "Medium",
}


class WebEnumerationModule(BaseModule):
    """Web resource discovery and analysis."""

    name = "Web Enumeration"
    key = "web_enumeration"

    def execute(self, result: ModuleResult) -> None:
        base = self.base_url.rstrip("/")
        home = self.http.get(base)
        html = home.text if home.ok else ""

        robots = self._fetch_text(f"{base}/robots.txt")
        sitemap = self._fetch_text(f"{base}/sitemap.xml")

        links = utils.extract_links(html)
        abs_links = [u for u in (utils.build_absolute_url(base, l) for l in links) if u]
        same_domain = self._same_domain_links(abs_links)
        external_links = [u for u in abs_links if not self._same_domain_url(u, base)]

        emails = utils.extract_emails(html)
        social = self._social_links(abs_links)
        js_files = self._js_files(abs_links)

        cookies = self._cookie_analysis(home.headers.get("Set-Cookie", ""))

        # Sensitive file probing (HEAD/GET on a curated list).
        sensitive = self._probe_sensitive_files(base)

        # Security header analysis already covered by BasicInfo; summarize here.
        security_headers_present = [
            h for h in (
                "content-security-policy", "strict-transport-security",
                "x-content-type-options", "x-frame-options",
            ) if home.header(h)
        ]

        # Lightweight crawler.
        crawl = self._crawl(base)

        result.data["web"] = {
            "robots_txt": robots,
            "sitemap_xml": sitemap,
            "internal_links": same_domain,
            "external_links": external_links,
            "emails": emails,
            "social_links": social,
            "js_files": js_files,
            "cookies": cookies,
            "sensitive_files": sensitive,
            "security_headers": security_headers_present,
            "crawl": crawl,
        }

        # Findings -------------------------------------------------------------
        if robots is not None:
            result.findings.append(Finding(
                title="robots.txt Found",
                severity="info",
                description="The site exposes a robots.txt file.",
                evidence=robots[:500],
                recommendation="Review disallowed paths for unintended exposure.",
            ))
        else:
            result.findings.append(Finding(
                title="robots.txt Not Found",
                severity="info",
                description="No robots.txt was returned by the server.",
            ))

        if emails:
            result.findings.append(Finding(
                title="Email Addresses Discovered",
                severity="info",
                description=f"{len(emails)} unique email address(es) found on public pages.",
                evidence=", ".join(emails[:20]),
                recommendation="Verify emails are intended to be public.",
            ))

        if social:
            result.findings.append(Finding(
                title="Social Media Presence",
                severity="info",
                description="Social media profiles referenced from the site.",
                evidence=", ".join(f"{k} -> {v}" for k, v in social.items()),
            ))

        if js_files:
            result.findings.append(Finding(
                title="JavaScript Files Discovered",
                severity="info",
                description=f"{len(js_files)} JavaScript asset(s) found.",
                evidence="; ".join(js_files[:15]),
                recommendation="Minify and review JS assets for exposed keys.",
            ))

        if sensitive:
            exposed = [s for s in sensitive if s["status"] in (200, 301, 302)]
            if exposed:
                result.findings.append(Finding(
                    title="Sensitive Files Potentially Exposed",
                    severity="medium",
                    description=(
                        "The following common sensitive paths returned a "
                        "non-error status code and may be publicly accessible."
                    ),
                    evidence="; ".join(
                        f"{s['path']} ({s['status']})" for s in exposed
                    ),
                    recommendation=(
                        "Confirm whether these resources should be public and "
                        "restrict them if not."
                    ),
                ))
            else:
                result.findings.append(Finding(
                    title="No Sensitive Files Exposed",
                    severity="info",
                    description="Probed common sensitive paths; none returned content.",
                ))

        if cookies:
            result.findings.append(Finding(
                title="Cookies Analyzed",
                severity="info",
                description="Cookies set by the application were reviewed.",
                evidence="; ".join(
                    f"{c['name']}({'HttpOnly' if c['httponly'] else 'no-HttpOnly'},"
                    f"{'Secure' if c['secure'] else 'no-Secure'})" for c in cookies
                ),
                recommendation=(
                    "Set HttpOnly and Secure flags on session cookies where "
                    "applicable."
                ),
            ))

        if security_headers_present:
            result.findings.append(Finding(
                title="Key Security Headers Present",
                severity="info",
                description="Core security headers observed on the homepage.",
                evidence=", ".join(security_headers_present),
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    def _fetch_text(self, url: str) -> str | None:
        resp = self.http.get(url)
        if resp.ok:
            return resp.text
        return None

    @staticmethod
    def _same_domain_url(url: str, base: str) -> bool:
        from urllib.parse import urlparse

        try:
            u = urlparse(url)
            b = urlparse(base)
        except Exception:  # noqa: BLE001
            return False
        return u.netloc.lower() == b.netloc.lower()

    def _same_domain_links(self, links: list[str]) -> list[str]:
        base = self.base_url
        return [u for u in links if self._same_domain_url(u, base)]

    @staticmethod
    def _social_links(links: list[str]) -> dict[str, str]:
        social: dict[str, str] = {}
        for url in links:
            try:
                from urllib.parse import urlparse

                host = urlparse(url).netloc.lower()
                for domain, name in SOCIAL_DOMAINS.items():
                    if domain in host and name not in social:
                        social[name] = url
            except Exception:  # noqa: BLE001
                continue
        return social

    @staticmethod
    def _js_files(links: list[str]) -> list[str]:
        return [u for u in links if u.lower().endswith(".js")]

    @staticmethod
    def _cookie_analysis(set_cookie_header: str) -> list[dict]:
        if not set_cookie_header:
            return []
        parts = [p.strip() for p in set_cookie_header.split(";") if p.strip()]
        # Group by cookie name.
        cookies: list[dict] = []
        for part in parts:
            if "=" in part:
                name = part.split("=", 1)[0].strip()
                cookie = {"name": name, "httponly": False, "secure": False}
                cookies.append(cookie)
        # Apply flags to all (approximation when multiple Set-Cookie).
        for part in parts:
            low = part.lower()
            if low == "httponly":
                for c in cookies:
                    c["httponly"] = True
            elif low == "secure":
                for c in cookies:
                    c["secure"] = True
        return cookies

    def _probe_sensitive_files(self, base: str) -> list[dict]:
        results: list[dict] = []
        tasks = [f"{base}{path}" for path in SENSITIVE_FILES]

        def probe(url: str) -> dict | None:
            resp = self.http.get(url, use_cache=True)
            if resp.status_code is None:
                return None
            return {
                "path": url.replace(base, ""),
                "url": url,
                "status": resp.status_code,
                "length": len(resp.content),
            }

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(probe, u): u for u in tasks}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
        results.sort(key=lambda x: x["path"])
        return results

    def _crawl(self, base: str) -> dict:
        """Bounded BFS crawl of same-origin pages."""
        from collections import deque

        visited: set[str] = set()
        queue: deque = deque([base])
        max_pages = self.config.max_pages
        max_depth = self.config.crawl_depth
        pages: list[dict] = []
        depth_map = {base: 0}

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            depth = depth_map.get(url, 0)
            visited.add(url)
            resp = self.http.get(url, use_cache=True)
            page = {
                "url": url,
                "status": resp.status_code,
                "depth": depth,
                "title": self._title(resp.text),
            }
            pages.append(page)
            if depth >= max_depth:
                continue
            for link in utils.extract_links(resp.text):
                abs_url = utils.build_absolute_url(base, link)
                if abs_url and self._same_domain_url(abs_url, base) and \
                        abs_url not in visited and len(visited) < max_pages:
                    if abs_url not in depth_map:
                        depth_map[abs_url] = depth + 1
                        queue.append(abs_url)

        return {"pages": pages, "total": len(pages)}

    @staticmethod
    def _title(html: str) -> str | None:
        if not html:
            return None
        try:
            soup = BeautifulSoup(html, "lxml")
            title = soup.title
            if title and title.string:
                return " ".join(title.string.split())
        except Exception:  # noqa: BLE001
            pass
        return None
