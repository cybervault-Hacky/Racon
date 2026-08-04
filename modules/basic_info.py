"""Basic Information module.

Gathers high-level information about a target web host: page title, HTTP
status, resolved IPs, reverse DNS, server & technology fingerprinting, CMS
detection, WAF/proxy detection, TLS certificate metadata, HTTP headers and
security header posture.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from modules.base import BaseModule, Finding, ModuleResult
from core import utils

#: Map well-known server header tokens to (vendor, confidence).
SERVER_HINTS = {
    "cloudflare": "Cloudflare (CDN/WAF)",
    "akamai": "Akamai (CDN)",
    "fastly": "Fastly (CDN)",
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "cloudfront": "AWS CloudFront",
    "openresty": "OpenResty",
    "caddy": "Caddy",
    "gunicorn": "Gunicorn",
    "uwsgi": "uWSGI",
    "tengine": "Tengine",
    "litespeed": "LiteSpeed",
}

#: Map security header names to a human description.
SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "HTTP Strict Transport Security (HSTS)",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
}

@dataclass
class Tech:
    """A detected technology with confidence."""

    name: str
    category: str = "Other"
    evidence: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "category": self.category,
                "evidence": self.evidence}


@dataclass
class BasicInfoData:
    """Aggregated basic info findings."""

    site_title: str | None = None
    http_status: int | None = None
    final_url: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    hostname: str = ""
    reverse_dns: list[dict] = field(default_factory=list)
    server: str | None = None
    server_detailed: str | None = None
    technologies: list[Tech] = field(default_factory=list)
    cms: str | None = None
    waf: str | None = None
    ssl: dict | None = None
    http_headers: dict = field(default_factory=dict)
    security_headers: dict = field(default_factory=dict)
    geoip: list[dict] | None = None


class BasicInfoModule(BaseModule):
    """Collects fundamental information about the target."""

    name = "Basic Information"
    key = "basic_info"

    def execute(self, result: ModuleResult) -> None:
        data = BasicInfoData()
        data.hostname = self.target

        # --- fetch homepage -------------------------------------------------
        response = self.http.get(self.base_url)
        data.http_status = response.status_code
        data.final_url = response.url
        data.http_headers = response.headers

        if response.ok:
            data.site_title = self._extract_title(response.text)

        # --- IP resolution & reverse DNS ------------------------------------
        data.ip_addresses = utils.resolve_hostname(self.target)
        for ip in data.ip_addresses:
            ptr = utils.reverse_dns(ip)
            if ptr:
                data.reverse_dns.append({"ip": ip, "ptr": ptr})

        # --- GeoIP enrichment (optional, needs a GeoLite2 mmdb in data/) ----
        geo = self._geoip_lookup(data.ip_addresses)
        if geo:
            data.geoip = geo

        # --- server detection ------------------------------------------------
        data.server = response.header("server")
        data.server_detailed = self._fingerprint_server(data.server, response.headers)

        # --- WAF / CDN detection --------------------------------------------
        data.waf = self._detect_waf(response.headers)

        # --- technology & CMS detection -------------------------------------
        data.technologies = self._detect_technologies(response.text, response.headers)
        data.cms = self._detect_cms(response.text, response.headers)

        # --- TLS / SSL certificate ------------------------------------------
        data.ssl = self._ssl_info(self.target)

        # --- security headers -------------------------------------------------
        data.security_headers = self._security_header_report(response.headers)

        # Build findings -------------------------------------------------------
        payload = data.__dict__
        payload["technologies"] = [t.to_dict() for t in data.technologies]
        result.data["basic_info"] = payload

        # Information gathering summary findings.
        if data.http_status:
            result.findings.append(Finding(
                title=f"HTTP Status {data.http_status}",
                severity="info",
                description=(
                    f"The target returned HTTP {data.http_status} for "
                    f"{self.base_url}."
                ),
                evidence=self.base_url,
                recommendation="No action required; recorded for inventory.",
            ))
        if data.server:
            result.findings.append(Finding(
                title=f"Web Server: {data.server}",
                severity="info",
                description=(
                    "The target discloses its web server software in the "
                    "`Server` response header."
                ),
                evidence=data.server,
                recommendation=(
                    "Consider obfuscating server version strings to reduce "
                    "attack-surface disclosure."
                ),
            ))
        if data.waf:
            result.findings.append(Finding(
                title=f"Reverse Proxy / WAF Detected: {data.waf}",
                severity="info",
                description=(
                    "A CDN, reverse proxy or WAF appears to front the origin "
                    "server, based on response headers."
                ),
                evidence=data.waf,
                recommendation="Confirm the proxy is properly configured.",
            ))
        if data.cms:
            result.findings.append(Finding(
                title=f"Content Management System: {data.cms}",
                severity="info",
                description=(
                    f"Detected CMS fingerprint: {data.cms}."
                ),
                evidence=data.cms,
                recommendation="Keep the CMS and its plugins up to date.",
            ))

        # Security header posture ---------------------------------------------
        missing = [
            h for h, _ in SECURITY_HEADERS.items() if h not in
            {k.lower() for k in response.headers}
        ]
        present = data.security_headers
        result.data["security_headers_missing"] = [SECURITY_HEADERS[h] for h in missing]

        if present:
            result.findings.append(Finding(
                title="Security Headers Present",
                severity="info",
                description=(
                    f"{len(present)} of {len(SECURITY_HEADERS)} recommended "
                    "security headers were detected."
                ),
                evidence=", ".join(present.values()),
                recommendation="Review header values for correctness.",
            ))
        if missing:
            result.findings.append(Finding(
                title="Security Headers Missing",
                severity="low",
                description=(
                    f"{len(missing)} recommended security headers were not "
                    "returned by the target."
                ),
                evidence=", ".join(SECURITY_HEADERS[h] for h in missing),
                recommendation=(
                    "Add the missing security headers to the web server / "
                    "application configuration."
                ),
            ))

        if data.ip_addresses:
            result.findings.append(Finding(
                title="Resolved IP Addresses",
                severity="info",
                description="IP addresses the target hostname resolved to.",
                evidence=", ".join(data.ip_addresses),
                recommendation="Verify these belong to the assessed asset.",
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _geoip_lookup(ips: list[str]) -> list[dict] | None:
        """Optional GeoIP lookup using a bundled GeoLite2 mmdb.

        No-op when ``geoip2`` is unavailable or no database file exists under
        ``data/GeoLite2-City.mmdb``.
        """
        from pathlib import Path

        db_path = Path(__file__).resolve().parent.parent / "data" / "GeoLite2-City.mmdb"
        if not db_path.exists():
            return None
        try:
            import geoip2.database
        except ImportError:
            return None
        results: list[dict] = []
        try:
            reader = geoip2.database.Reader(str(db_path))
        except Exception:  # noqa: BLE001
            return None
        try:
            for ip in ips:
                if not utils.is_ip(ip):
                    continue
                try:
                    loc = reader.city(ip)
                    results.append({
                        "ip": ip,
                        "country": loc.country.iso_code,
                        "country_name": loc.country.name,
                        "city": loc.city.name,
                        "latitude": loc.location.latitude,
                        "longitude": loc.location.longitude,
                    })
                except Exception:  # noqa: BLE001
                    continue
        finally:
            reader.close()
        return results or None

    @staticmethod
    def _extract_title(html: str) -> str | None:
        import re

        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        title = re.sub(r"\s+", " ", match.group(1)).strip()
        return title or None

    @staticmethod
    def _fingerprint_server(server: str | None, headers: dict) -> str | None:
        if not server:
            return None
        lowered = server.lower()
        for token, vendor in SERVER_HINTS.items():
            if token in lowered:
                return vendor
        return server

    @staticmethod
    def _detect_waf(headers: dict) -> str | None:
        lowered = {k.lower(): v for k, v in headers.items()}
        # Cloudflare
        if "cf-ray" in lowered or "cf-cache-status" in lowered:
            return "Cloudflare"
        if "x-amz-cf-id" in lowered or "via" in lowered and "cloudfront" in lowered["via"].lower():
            return "AWS CloudFront"
        if "x-sucuri-id" in lowered or "x-sucuri-cache" in lowered:
            return "Sucuri WAF"
        if "x-akamai-transformed" in lowered or "akamai-x-ser" in lowered:
            return "Akamai"
        return None

    @staticmethod
    def _detect_technologies(html: str, headers: dict) -> list[Tech]:
        import re

        techs: list[Tech] = []
        lowered_headers = {k.lower(): v for k, v in headers.items()}

        generator_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            html, re.IGNORECASE,
        )
        if generator_match:
            techs.append(Tech(
                name=generator_match.group(1).strip(),
                category="Generator",
                evidence="<meta generator> tag",
            ))

        # Framework fingerprints from headers / cookies
        frameworks = [
            ("x-powered-by", "X-Powered-By", None),
            ("x-aspnet-version", "ASP.NET", "Header"),
            ("x-drupal-cache", "Drupal", "Header"),
            ("x-generator", None, None),
        ]
        for header, name, _ in frameworks:
            value = lowered_headers.get(header)
            if value:
                techs.append(Tech(name=name or value.title(), category="Framework",
                                  evidence=f"{header}: {value}"))

        # Library / JS framework detection from scripts
        script_frameworks = {
            "jquery": "jQuery",
            "react": "React",
            "vue": "Vue.js",
            "angular": "AngularJS",
            "next/": "Next.js",
            "bootstrap": "Bootstrap",
        }
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.IGNORECASE)
        for script in scripts:
            sl = script.lower()
            for token, name in script_frameworks.items():
                if token in sl and not any(t.name == name for t in techs):
                    techs.append(Tech(name=name, category="JavaScript",
                                      evidence=script))

        return techs

    @staticmethod
    def _detect_cms(html: str, headers: dict) -> str | None:
        import re

        lowered_headers = {k.lower(): v for k, v in headers.items()}
        text = html[:200000]
        lowered_text = text.lower()

        if "wp-content" in lowered_text or "wp-includes" in lowered_text or \
                "x-powered-by" in lowered_headers and "wordpress" in lowered_headers["x-powered-by"]:
            return "WordPress"
        if 'name="generator"' in lowered_text and "joomla" in lowered_text:
            return "Joomla"
        if "drupal" in lowered_text and "x-generator" in lowered_headers or \
                "x-drupal-cache" in lowered_headers:
            return "Drupal"
        if "squarespace" in lowered_text:
            return "Squarespace"
        if "wix.com" in lowered_text or "wixstatic" in lowered_text:
            return "Wix"
        if "shopify" in lowered_text or "cdn.shopify" in lowered_text:
            return "Shopify"
        if "ghost" in lowered_text and 'name="generator"' in lowered_text:
            return "Ghost"

        # Generator meta tag is a strong CMS signal.
        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            html, re.IGNORECASE,
        )
        if gen_match:
            gen = gen_match.group(1).lower()
            for cms in ("wordpress", "joomla", "drupal", "squarespace", "wix",
                        "shopify", "ghost", "typo3", "prestashop", "magento"):
                if cms in gen:
                    return gen_match.group(1).strip()
        return None

    @staticmethod
    def _ssl_info(hostname: str) -> dict | None:
        """Grab TLS certificate metadata from the target's 443 port."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    if not cert:
                        return None
                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                        "cipher": f"{cipher[0]} {cipher[1]}",
                        "version": tls.version(),
                        "sans": cert.get("subjectAltName"),
                    }
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _security_header_report(headers: dict) -> dict:
        lowered = {k.lower(): v for k, v in headers.items()}
        report: dict = {}
        for header, display in SECURITY_HEADERS.items():
            if header in lowered:
                report[display] = lowered[header]
        return report
