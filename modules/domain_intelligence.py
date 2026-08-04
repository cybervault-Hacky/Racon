"""Domain Intelligence module.

Performs a WHOIS lookup and surfaces registrar, registration dates, domain
age, expiry and name servers. Missing data is gracefully tolerated (WHOIS
servers are often rate-limited or non-responsive).
"""

from __future__ import annotations

from typing import Any

from modules.base import BaseModule, Finding, ModuleResult
from core import utils


def _try_whois(domain: str, timeout: float = 12.0) -> Any | None:
    """Attempt a WHOIS lookup, importing python-whois lazily."""
    try:
        import whois
    except ImportError:
        return None
    try:
        return whois.whois(domain)
    except Exception:  # noqa: BLE001
        return None


class DomainIntelligenceModule(BaseModule):
    """Collects WHOIS and registration metadata for the target domain."""

    name = "Domain Intelligence"
    key = "domain_intelligence"

    def execute(self, result: ModuleResult) -> None:
        domain = self.context.get("domain") or utils.extract_root_domain(self.target)
        self.log_info("Running WHOIS lookup for %s", domain)

        who = _try_whois(domain)
        if who is None:
            result.status = "success"
            result.data["whois"] = {"domain": domain, "error": "WHOIS lookup unavailable"}
            result.findings.append(Finding(
                title="WHOIS Lookup Unavailable",
                severity="info",
                description="The WHOIS server did not respond in time or the lookup failed.",
                evidence=domain,
                recommendation="Retry later or query the WHOIS registry manually.",
            ))
            return

        created = getattr(who, "creation_date", None)
        updated = getattr(who, "updated_date", None)
        expires = getattr(who, "expiration_date", None)

        created_str = self._dates_to_str(created)
        updated_str = self._dates_to_str(updated)
        expires_str = self._dates_to_str(expires)

        created_dt = self._first_datetime(created)
        age_days = utils.domain_age_days(created_dt)

        data = {
            "domain": domain,
            "registrar": getattr(who, "registrar", None),
            "creation_date": created_str,
            "updated_date": updated_str,
            "expiry_date": expires_str,
            "domain_age_days": age_days,
            "name_servers": self._listify(getattr(who, "name_servers", None)),
            "status": self._listify(getattr(who, "status", None)),
            "emails": self._listify(getattr(who, "emails", None)),
            "org": getattr(who, "org", None),
            "country": getattr(who, "country", None),
        }
        result.data["whois"] = data

        # Findings --------------------------------------------------------------
        if data["registrar"]:
            result.findings.append(Finding(
                title="Domain Registrar",
                severity="info",
                description="The registrant registered the domain through this registrar.",
                evidence=str(data["registrar"]),
                recommendation="Ensure registrar contact details are current.",
            ))
        if created_str:
            result.findings.append(Finding(
                title="Domain Registration Date",
                severity="info",
                description=f"Domain created on {created_str}.",
                evidence=str(created_str),
            ))
        if age_days is not None:
            result.findings.append(Finding(
                title="Domain Age",
                severity="info",
                description=f"The domain is approximately {age_days} days old.",
                evidence=str(age_days),
                recommendation="Young domains may warrant additional scrutiny.",
            ))
        if expires_str:
            result.findings.append(Finding(
                title="Domain Expiry",
                severity="info",
                description=f"The domain registration expires on {expires_str}.",
                evidence=str(expires_str),
                recommendation="Renew before expiry to avoid lapse.",
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _listify(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return [str(v) for v in value if v]
        return [str(value)]

    @staticmethod
    def _first_datetime(value: Any):
        import datetime as _dt

        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if isinstance(value, _dt.datetime):
            return value
        if isinstance(value, _dt.date):
            return _dt.datetime(value.year, value.month, value.day)
        return None

    @classmethod
    def _dates_to_str(cls, value: Any) -> str | None:
        dt = cls._first_datetime(value)
        if dt is None:
            return None
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
