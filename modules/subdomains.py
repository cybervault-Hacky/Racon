"""Subdomain Intelligence module.

Performs *passive* subdomain enumeration using public data sources
(certificate transparency via crt.sh, HackerTarget) plus a bundled wordlist
brute-force against DNS. Only passive/defensive enumeration is implemented —
no active exploitation.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from pathlib import Path

import dns.resolver

from core import utils
from modules.base import BaseModule, Finding, ModuleResult

DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns1",
    "dns2", "mx", "ftp", "ssh", "dev", "staging", "test", "qa", "beta",
    "api", "app", "portal", "vpn", "remote", "vpn2", "jira", "git", "gitlab",
    "gitlab-ci", "jenkins", "ci", "dashboard", "admin", "cms", "blog",
    "shop", "store", "cdn", "static", "assets", "media", "img", "images",
    "download", "files", "status", "monitor", "grafana", "kibana", "metrics",
    "status", "support", "help", "forum", "community", "docs", "wiki",
]


class SubdomainModule(BaseModule):
    """Enumerates and validates subdomains for the target domain."""

    name = "Subdomain Intelligence"
    key = "subdomains"

    def __init__(self, config: Any, http: Any, context: dict[str, Any]) -> None:
        super().__init__(config, http, context)
        self.domain = context.get("domain") or utils.extract_root_domain(self.target)

    def execute(self, result: ModuleResult) -> None:
        candidates = self._load_wordlist() + self._passive_crt() + self._passive_hackertarget()
        # Deduplicate and drop the bare domain from the brute force.
        candidates = list(dict.fromkeys(c for c in candidates if c and c != self.domain))

        wildcard = self._wildcard_detected()
        resolved: list[dict] = []
        seen: set[str] = set()

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(self._resolve, f"{c}.{self.domain}"): f"{c}.{self.domain}"
                       for c in candidates}
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    ips = future.result()
                except Exception:  # noqa: BLE001
                    continue
                if ips and subdomain not in seen:
                    seen.add(subdomain)
                    resolved.append({
                        "subdomain": subdomain,
                        "ips": ips,
                        "live": True,
                    })
                if len(seen) >= self.config.subdomain_limit:
                    break

        resolved.sort(key=lambda x: x["subdomain"])
        result.data["subdomains"] = {
            "domain": self.domain,
            "wildcard": wildcard,
            "candidates_tested": len(candidates),
            "resolved": resolved,
            "count": len(resolved),
        }

        if wildcard:
            result.findings.append(Finding(
                title="Wildcard DNS Detected",
                severity="info",
                description=(
                    "The domain returns DNS answers for arbitrary subdomains, "
                    "which can complicate enumeration."
                ),
                recommendation="Review wildcard DNS configuration for hygiene.",
            ))

        if resolved:
            result.findings.append(Finding(
                title="Live Subdomains Discovered",
                severity="info",
                description=(
                    f"{len(resolved)} subdomain(s) resolved to live hosts via "
                    "passive enumeration."
                ),
                evidence="; ".join(r["subdomain"] for r in resolved[:30]),
                recommendation="Include discovered subdomains in the asset inventory.",
            ))
        else:
            result.findings.append(Finding(
                title="No Live Subdomains Resolved",
                severity="info",
                description="No additional live subdomains were found.",
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    def _load_wordlist(self) -> list[str]:
        path = Path(__file__).resolve().parent.parent / "data" / "subdomains.txt"
        words: list[str] = []
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line)
        return words or list(DEFAULT_WORDLIST)

    def _resolve(self, hostname: str) -> list[str]:
        return utils.resolve_hostname(hostname)

    def _wildcard_detected(self) -> bool:
        probe = f"racon-probe-{utils.sha1(self.domain)[:10]}.{self.domain}"
        try:
            answers = dns.resolver.resolve(probe, "A", lifetime=6)
            return len(list(answers)) > 0
        except Exception:  # noqa: BLE001
            return False

    def _passive_crt(self) -> list[str]:
        """Passive certificate-transparency enumeration via crt.sh."""
        if not self.config.source_enabled("crt_sh"):
            return []
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            resp = self.http.get(url, use_cache=False)
            if not resp.ok:
                return []
            import json

            data = resp.content.decode("utf-8", errors="replace")
            try:
                entries = json.loads(data)
            except Exception:  # noqa: BLE001
                return []
            names: list[str] = []
            for entry in entries:
                name = entry.get("name_value", "")
                for n in name.splitlines():
                    n = n.strip().lower()
                    if n and n.endswith(self.domain) and n not in names:
                        names.append(n)
            return names
        except Exception:  # noqa: BLE001
            return []

    def _passive_hackertarget(self) -> list[str]:
        """Passive subdomain enumeration via the HackerTarget free API."""
        if not self.config.source_enabled("hackertarget"):
            return []
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            resp = self.http.get(url, use_cache=False)
            if not resp.ok:
                return []
            lines = resp.text.splitlines()
            names: list[str] = []
            for line in lines:
                host = line.split(",")[0].strip().lower()
                if host and host.endswith(self.domain) and host not in names:
                    names.append(host)
            return names
        except Exception:  # noqa: BLE001
            return []
