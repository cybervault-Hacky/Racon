"""DNS Intelligence module.

Enumerates standard DNS record types (A, AAAA, MX, TXT, CNAME, NS), performs
reverse DNS lookups and inspects security-oriented records: SPF, DMARC and
DNSSEC (DS/DNSKEY) presence.
"""

from __future__ import annotations

from typing import Any

import dns.resolver
import dns.rdatatype

from core import utils
from modules.base import BaseModule, Finding, ModuleResult

# Map record type name -> rdatatype.
RECORD_TYPES = {
    "A": dns.rdatatype.A,
    "AAAA": dns.rdatatype.AAAA,
    "MX": dns.rdatatype.MX,
    "TXT": dns.rdatatype.TXT,
    "CNAME": dns.rdatatype.CNAME,
    "NS": dns.rdatatype.NS,
    "SOA": dns.rdatatype.SOA,
    "DS": dns.rdatatype.DS,
    "DNSKEY": dns.rdatatype.DNSKEY,
}

TXT_PREFIXES = {
    "v=spf1": "SPF",
    "_dmarc": "DMARC",
}


class DNSIntelligenceModule(BaseModule):
    """Resolves and inspects DNS records for the target domain."""

    name = "DNS Intelligence"
    key = "dns_intelligence"

    def __init__(self, config: Any, http: Any, context: dict[str, Any]) -> None:
        super().__init__(config, http, context)
        # Prefer the registrable domain for domain-scoped records.
        self.domain = context.get("domain") or utils.extract_root_domain(self.target)

    def execute(self, result: ModuleResult) -> None:
        records: dict[str, list[Any]] = {}
        records["A"] = self._query(self.target, "A")
        records["AAAA"] = self._query(self.target, "AAAA")
        records["CNAME"] = self._query(self.target, "CNAME")

        # Domain-scoped records.
        records["MX"] = self._query(self.domain, "MX")
        records["NS"] = self._query(self.domain, "NS")
        records["SOA"] = self._query(self.domain, "SOA")
        records["TXT"] = self._query(self.domain, "TXT")
        records["DNSKEY"] = self._query(self.domain, "DNSKEY")

        # Reverse DNS for each resolved A/AAAA address.
        reverse: list[dict] = []
        for ip in records.get("A", []):
            if utils.is_ip(str(ip)):
                ptr = utils.reverse_dns(str(ip))
                reverse.append({"ip": str(ip), "ptr": ptr})

        # SPF / DMARC analysis from TXT records.
        dmarc_records = self._query(f"_dmarc.{self.domain}", "TXT")
        spf, dmarc = self._security_records(records["TXT"], dmarc_records)

        # DNSSEC detection.
        dnssec = self._dnssec_status(records)

        result.data["dns"] = {
            "domain": self.domain,
            "records": {k: [str(v) for v in vals] for k, vals in records.items()},
            "reverse_dns": reverse,
            "spf": spf,
            "dmarc": dmarc,
            "dnssec": dnssec,
        }

        # Findings ---------------------------------------------------------------
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            if records.get(rtype):
                result.findings.append(Finding(
                    title=f"{rtype} Record Present",
                    severity="info",
                    description=f"{len(records[rtype])} {rtype} record(s) found for {self.domain}.",
                    evidence="; ".join(str(v) for v in records[rtype][:5]),
                    recommendation="Recorded for asset inventory.",
                ))

        if not records.get("A"):
            result.findings.append(Finding(
                title="No A Record Resolved",
                severity="info",
                description="The target did not resolve an IPv4 A record.",
                recommendation="Verify DNS configuration for the host.",
            ))

        if spf:
            result.findings.append(Finding(
                title="SPF Record Present",
                severity="info",
                description="Sender Policy Framework record found.",
                evidence=spf,
                recommendation="Ensure SPF alignment covers all legitimate senders.",
            ))
        else:
            result.findings.append(Finding(
                title="No SPF Record",
                severity="low",
                description="No SPF record found for the domain.",
                recommendation="Add an SPF record to prevent email spoofing.",
            ))

        if dmarc:
            result.findings.append(Finding(
                title="DMARC Record Present",
                severity="info",
                description="DMARC policy record found.",
                evidence=dmarc,
                recommendation="Review DMARC policy enforcement level.",
            ))
        else:
            result.findings.append(Finding(
                title="No DMARC Record",
                severity="low",
                description="No DMARC record found for the domain.",
                recommendation="Add a DMARC record to authenticate email.",
            ))

        if dnssec:
            result.findings.append(Finding(
                title="DNSSEC Enabled",
                severity="info",
                description="DNSSEC (DS/DNSKEY) records are present.",
                recommendation="Maintain DNSSEC key hygiene.",
            ))
        else:
            result.findings.append(Finding(
                title="DNSSEC Not Detected",
                severity="info",
                description="No DNSSEC DS/DNSKEY records observed.",
                recommendation="Consider enabling DNSSEC to prevent spoofing.",
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    def _query(self, hostname: str, rtype: str) -> list[str]:
        """Query a single record type, returning string values or []."""
        values: list[str] = []
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=8)
            for answer in answers:
                values.append(str(answer))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            self.log_debug("DNS %s lookup for %s failed/timed out", rtype, hostname)
        except dns.exception.DNSException:
            pass
        # Deduplicate while preserving order.
        return list(dict.fromkeys(values))

    @staticmethod
    def _security_records(txt_values: list[str],
                          dmarc_values: list[str] | None = None) -> tuple[str | None, str | None]:
        spf = None
        dmarc = None
        for value in txt_values:
            if value.lower().startswith("v=spf1"):
                spf = value
        for value in (dmarc_values or []):
            if value.lower().startswith("v=dmarc1"):
                dmarc = value
        return spf, dmarc

    def _dnssec_status(self, records: dict[str, list[Any]]) -> bool:
        # Re-query DS for the domain to be authoritative.
        try:
            dns.resolver.resolve(self.domain, "DS", lifetime=8)
            return True
        except Exception:  # noqa: BLE001
            pass
        return bool(records.get("DNSKEY"))
