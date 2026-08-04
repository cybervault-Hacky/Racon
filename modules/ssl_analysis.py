"""SSL/TLS Analysis module.

Connects to the target's TLS port and inspects the presented certificate:
issuer, subject, validity period, remaining validity, signature algorithm,
protocol version and Subject Alternative Name (SAN) entries.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from modules.base import BaseModule, Finding, ModuleResult


class SSLAnalysisModule(BaseModule):
    """Detailed TLS certificate inspection."""

    name = "SSL Analysis"
    key = "ssl_analysis"

    def execute(self, result: ModuleResult) -> None:
        info = self._fetch_certificate(self.target)
        if info is None:
            result.status = "not_applicable"
            result.data["ssl"] = {
                "available": False,
                "error": "No TLS certificate retrieved from port 443.",
            }
            result.findings.append(Finding(
                title="TLS Certificate Unavailable",
                severity="info",
                description="Could not retrieve a TLS certificate from the target.",
                evidence=self.target,
            ))
            return

        result.data["ssl"] = info

        # Findings ------------------------------------------------------------
        subject = info.get("subject") or {}
        cn = subject.get("CN", "unknown")
        issuer = info.get("issuer") or {}
        issuer_cn = issuer.get("O") or issuer.get("CN", "unknown")

        result.findings.append(Finding(
            title="Certificate Issued To",
            severity="info",
            description=f"The certificate is issued to {cn}.",
            evidence=cn,
        ))
        result.findings.append(Finding(
            title="Certificate Issuer",
            severity="info",
            description=f"Issued by {issuer_cn}.",
            evidence=issuer_cn,
        ))
        if info.get("not_after"):
            result.findings.append(Finding(
                title="Certificate Expiration",
                severity="info",
                description=f"The certificate expires on {info['not_after']}.",
                evidence=info["not_after"],
                recommendation="Renew before expiry to avoid service disruption.",
            ))
        if info.get("remaining_days") is not None:
            severity = "info" if info["remaining_days"] > 30 else "low"
            result.findings.append(Finding(
                title="Certificate Remaining Validity",
                severity=severity,
                description=(
                    f"The certificate has ~{info['remaining_days']} day(s) of "
                    "validity remaining."
                ),
                evidence=str(info["remaining_days"]),
                recommendation=(
                    "Renew certificates well before expiration; consider "
                    "automated renewal."
                ),
            ))
        if info.get("signature_algorithm"):
            result.findings.append(Finding(
                title="Signature Algorithm",
                severity="info",
                description="The certificate's signature algorithm.",
                evidence=info["signature_algorithm"],
            ))
        sans = info.get("sans", [])
        if sans:
            result.findings.append(Finding(
                title="Subject Alternative Names",
                severity="info",
                description=f"{len(sans)} SAN entry/entries on the certificate.",
                evidence="; ".join(f"{t}:{n}" for t, n in sans[:20]),
            ))
        if info.get("tls_version"):
            result.findings.append(Finding(
                title="TLS Version Negotiated",
                severity="info",
                description="The highest TLS version negotiated during the handshake.",
                evidence=info["tls_version"],
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    def _fetch_certificate(self, hostname: str) -> dict | None:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    der = tls.getpeercert(binary_form=True)
                    if not der:
                        return None
                    try:
                        from cryptography import x509

                        cert = x509.load_der_x509_certificate(der)
                        return self._cert_fields(cert, tls)
                    except Exception:  # noqa: BLE001
                        # Fall back to dict-based certificate.
                        return self._cert_fields_dict(tls)
        except (OSError, ssl.SSLError, socket.timeout):
            return None
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _cert_fields(cert: Any, tls: Any) -> dict:
        """Extract fields using the ``cryptography`` library."""
        issuer = cert.issuer
        subject = cert.subject

        def rdn(entry: Any, oid_attr: str) -> dict[str, str]:
            d: dict[str, str] = {}
            for attribute in entry:
                if attribute.oid._name == oid_attr:
                    d[oid_attr.upper()] = attribute.value
                # Generic fallback using common OID names.
                name = attribute.oid._name
                if name in ("commonName", "organizationName", "countryName",
                            "localityName", "stateOrProvinceName",
                            "organizationName"):
                    key = {"commonName": "CN", "organizationName": "O",
                           "countryName": "C", "localityName": "L",
                           "stateOrProvinceName": "ST",
                           "organizationName": "O"}.get(name, name.upper())
                    d[key] = attribute.value
            return d

        subject_map = rdn(subject, "commonName")
        issuer_map = rdn(issuer, "commonName")

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        remaining = max(0, (not_after - datetime.now(timezone.utc)).days)

        san_names: list[tuple[str, str]] = []
        try:
            san = cert.extensions.get_extension_for_class(
                __import__("cryptography").x509.SubjectAlternativeName
            )
            for name in san.value:
                if isinstance(name, __import__("cryptography").x509.DNSName):
                    san_names.append(("DNS", name.value))
                elif isinstance(name, __import__("cryptography").x509.IPAddress):
                    san_names.append(("IP", str(name.value)))
        except Exception:  # noqa: BLE001
            pass

        return {
            "available": True,
            "subject": subject_map,
            "issuer": issuer_map,
            "serial_number": format(cert.serial_number, "x"),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "remaining_days": remaining,
            "signature_algorithm": cert.signature_algorithm_oid._name
            if hasattr(cert.signature_algorithm_oid, "_name")
            else str(cert.signature_algorithm_oid),
            "public_key": cert.public_key().__class__.__name__,
            "sans": san_names,
            "tls_version": tls.version(),
            "cipher": tls.cipher()[0] if tls.cipher() else None,
        }

    @staticmethod
    def _cert_fields_dict(tls: Any) -> dict | None:
        """Fallback using ``getpeercert`` when cryptography is unavailable."""
        cert = tls.getpeercert()
        if not cert:
            return None
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "available": True,
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": cert.get("subjectAltName", []),
            "tls_version": tls.version(),
            "cipher": tls.cipher()[0] if tls.cipher() else None,
        }
