"""Unit tests for core.utils helpers."""

from __future__ import annotations

from core import utils


def test_normalize_target_scheme_and_path():
    assert utils.normalize_target("https://example.com") == "example.com"
    assert utils.normalize_target("http://example.com/path") == "example.com"
    assert utils.normalize_target("  EXAMPLE.com  ") == "EXAMPLE.com"


def test_parse_target():
    assert utils.parse_target("https://example.com") == ("https", "example.com", None)
    assert utils.parse_target("http://192.168.1.5:8080") == ("http", "192.168.1.5", 8080)
    assert utils.parse_target("example.com") == (None, "example.com", None)
    assert utils.parse_target("https://[::1]:8443") == ("https", "[::1]", 8443)


def test_is_valid_target():
    assert utils.is_valid_target("example.com") is True
    assert utils.is_valid_target("sub.example.co.uk") is True
    assert utils.is_valid_target("127.0.0.1") is True
    assert utils.is_valid_target("2001:db8::1") is True
    assert utils.is_valid_target("bad host name") is False
    assert utils.is_valid_target("") is False
    assert utils.is_valid_target("-bad.com") is False


def test_extract_root_domain():
    assert utils.extract_root_domain("www.example.com") == "example.com"
    assert utils.extract_root_domain("sub.example.co.uk") == "example.co.uk"
    assert utils.extract_root_domain("example.com") == "example.com"


def test_extract_emails():
    text = ("contact@widgetworks.io, other@widgetworks.io, bad@, "
            "foo@widgetworks.io")
    emails = utils.extract_emails(text)
    assert "contact@widgetworks.io" in emails
    assert "other@widgetworks.io" in emails
    # Deduplicated.
    assert emails.count("foo@widgetworks.io") == 1


def test_extract_emails_filters_placeholder_domains():
    text = "a@example.com b@sentry.io c@real-company.io"
    emails = utils.extract_emails(text)
    assert "c@real-company.io" in emails
    assert "a@example.com" not in emails


def test_extract_links():
    html = '<a href="/a">x</a><a href="https://example.com/b">y</a>'
    links = utils.extract_links(html)
    assert "/a" in links
    assert "https://example.com/b" in links


def test_resolve_localhost():
    ips = utils.resolve_hostname("localhost")
    assert "127.0.0.1" in ips


def test_reverse_dns_localhost():
    assert utils.reverse_dns("127.0.0.1") is not None


def test_domain_age_days():
    from datetime import datetime, timedelta, timezone

    created = datetime.now(timezone.utc) - timedelta(days=100)
    assert utils.domain_age_days(created) == 100
    assert utils.domain_age_days(None) is None


def test_is_ip():
    assert utils.is_ip("127.0.0.1") is True
    assert utils.is_ip("example.com") is False


def test_safe_int():
    assert utils.safe_int("42") == 42
    assert utils.safe_int("abc", 7) == 7
    assert utils.safe_int(None) == 0
