"""Reusable utility functions shared across RACON modules.

These helpers are intentionally dependency-light (beyond the framework's own
dependencies) so they can be unit-tested in isolation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import tldextract

# ---------------------------------------------------------------------------
# URL / hostname helpers
# ---------------------------------------------------------------------------

#: A lazy, offline-aware tldextract instance. We avoid network fetches so the
#: framework works even without internet access to the PSL mirror.
_TLD = None


def _tldextract() -> tldextract.TLDExtract:
    """Return a shared tldextract instance that never hits the network."""
    global _TLD
    if _TLD is None:
        _TLD = tldextract.TLDExtract(
            suffix_list_urls=(),  # never download the PSL
            cache_dir=None,
            fallback_to_snapshot=False,
        )
    return _TLD

URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def parse_target(target: str) -> tuple[str | None, str, int | None]:
    """Parse a raw target into ``(scheme, host, port)``.

    Recognizes ``http://`` / ``https://`` schemes and ``:port`` suffixes.
    Returns the hostname/IP without path, and ``None`` for unspecified parts.

    Examples:
        ``https://example.com``  -> ``("https", "example.com", None)``
        ``http://192.168.1.5:8080`` -> ``("http", "192.168.1.5", 8080)``
        ``example.com``          -> ``(None, "example.com", None)``
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    scheme: str | None = None
    if URL_RE.match(target):
        parsed = urlparse(target)
        scheme = parsed.scheme.lower()
        target = parsed.netloc or parsed.path
    else:
        target = target.split("/")[0]

    host = target
    port: int | None = None
    # IPv6 bracket form [::1]:8080
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            rest = host[end + 1:]
            if rest.startswith(":"):
                port = safe_int(rest[1:], None)
            host = host[: end + 1]
    elif host.count(":") == 1:
        host, _, port_str = host.rpartition(":")
        if port_str.isdigit():
            port = int(port_str)
        else:
            host = target

    host = host.rstrip("/").strip()
    return scheme, host, port


def normalize_target(target: str) -> str:
    """Normalize a user-supplied target into a bare hostname/IP.

    Strips schemes, paths and ports (see :func:`parse_target` for the full
    parse). Returns the bare host without scheme, port or trailing slash.
    """
    _, host, _ = parse_target(target)
    return host


def is_valid_target(target: str) -> bool:
    """Return ``True`` if ``target`` looks like a hostname or IP address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return is_valid_hostname(target)


def is_valid_hostname(hostname: str) -> bool:
    """Return ``True`` if ``hostname`` is a syntactically valid DNS name."""
    if not hostname or len(hostname) > 253:
        return False
    # Permit a trailing dot for FQDNs.
    hostname = hostname.rstrip(".")
    labels = hostname.split(".")
    if not labels:
        return False
    label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|^[a-zA-Z0-9]$")
    for label in labels:
        if not label or not label_re.match(label):
            return False
    return True


#: A small built-in map of public suffixes to fall back on when the full PSL
#: is unavailable (e.g. fully offline environments).
COMMON_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "mil", "io", "co", "info", "biz",
    "me", "tv", "app", "dev", "ai", "cloud", "tech", "online", "site",
    "store", "xyz", "uk", "co.uk", "org.uk", "gov.uk", "ac.uk", "us",
    "ca", "de", "fr", "au", "com.au", "net.au", "nz", "co.nz", "jp",
    "co.jp", "in", "co.in", "br", "com.br", "ru", "cn", "com.cn", "it",
    "es", "nl", "se", "no", "fi", "pl", "za", "co.za", "mx", "com.mx",
    "kr", "co.kr", "sg", "com.sg", "hk", "com.hk", "tw", "com.tw",
}


def extract_root_domain(hostname: str) -> str:
    """Return the registrable root domain for ``hostname``.

    Uses ``tldextract`` (offline-safe) to identify the registrable domain.
    Example: ``sub.example.co.uk`` -> ``example.co.uk``. Falls back to a
    simple heuristic when the public-suffix list is unavailable.
    """
    hostname = (hostname or "").strip().lower().rstrip(".")
    try:
        ext = _tldextract().extract(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:  # noqa: BLE001
        pass

    # Heuristic fallback: find the longest suffix that matches a known public
    # suffix, then take the label immediately before it.
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    for i in range(1, len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in COMMON_SUFFIXES:
            return ".".join(labels[i - 1:])
    return hostname


def scheme_for(hostname: str) -> str:
    """Return a sensible default URL scheme for a hostname."""
    return "https"


# ---------------------------------------------------------------------------
# IP / resolution helpers
# ---------------------------------------------------------------------------

def is_ip(target: str) -> bool:
    """Return ``True`` if ``target`` parses as an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve ``hostname`` to a list of IP addresses (deduplicated)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    results: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            results.append(addr)
    return results


def reverse_dns(ip: str) -> str | None:
    """Perform a reverse DNS lookup for ``ip``."""
    try:
        host = socket.gethostbyaddr(ip)
        return host[0] if host and host[0] else None
    except (socket.herror, socket.gaierror):
        return None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return utc_now().isoformat()


def domain_age_days(created: datetime | None) -> int | None:
    """Return the number of days since a domain's creation date."""
    if not created:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    delta = utc_now() - created
    return max(0, delta.days)


# ---------------------------------------------------------------------------
# HTTP / text helpers
# ---------------------------------------------------------------------------

def build_absolute_url(base: str, href: str) -> str | None:
    """Resolve ``href`` against ``base``; return ``None`` if not http(s)."""
    url = urljoin(base, href.strip())
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    return url


EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)


def extract_emails(text: str) -> list[str]:
    """Extract unique email addresses from ``text`` (case-normalized)."""
    if not text:
        return []
    found = EMAIL_RE.findall(text)
    # Skip common placeholder domains.
    banned = {"example.com", "example.org", "domain.com", "yourdomain.com",
              "sentry.io", "wixpress.com"}
    unique: list[str] = []
    seen: set[str] = set()
    for email in found:
        low = email.lower()
        local = low.split("@")[1]
        if low in seen or local in banned:
            continue
        seen.add(low)
        unique.append(low)
    return unique


def extract_links(html: str) -> list[str]:
    """Extract unique absolute http(s) URLs from raw HTML via regex.

    A lightweight fallback for callers that do not have BeautifulSoup handy.
    """
    if not html:
        return []
    urls = re.findall(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', html)
    return list(dict.fromkeys(urls))


def safe_int(value: Any, default: int = 0) -> int:
    """Cast ``value`` to ``int``, returning ``default`` on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sha1(s: str) -> str:
    """Return the SHA-1 hex digest of ``s`` (used for cache keys)."""
    return hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()
