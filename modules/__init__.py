"""Scan module registry for RACON.

Importing this package registers all available modules. The order here
defines execution order.
"""

from __future__ import annotations

from modules.base import BaseModule, Finding, ModuleResult
from modules.basic_info import BasicInfoModule
from modules.dns_intelligence import DNSIntelligenceModule
from modules.domain_intelligence import DomainIntelligenceModule
from modules.network import NetworkModule
from modules.web_enumeration import WebEnumerationModule
from modules.wordpress import WordPressModule
from modules.subdomains import SubdomainModule
from modules.ssl_analysis import SSLAnalysisModule

#: Ordered registry of module classes.
MODULES: list[type[BaseModule]] = [
    BasicInfoModule,
    DNSIntelligenceModule,
    DomainIntelligenceModule,
    NetworkModule,
    WebEnumerationModule,
    WordPressModule,
    SubdomainModule,
    SSLAnalysisModule,
]

#: Mapping of module key -> class for lookup / toggling.
MODULE_MAP: dict[str, type[BaseModule]] = {cls.key: cls for cls in MODULES}


def list_modules() -> list[str]:
    """Return the ordered list of module keys."""
    return [cls.key for cls in MODULES]


__all__ = [
    "BaseModule",
    "Finding",
    "ModuleResult",
    "MODULES",
    "MODULE_MAP",
    "list_modules",
    "BasicInfoModule",
    "DNSIntelligenceModule",
    "DomainIntelligenceModule",
    "NetworkModule",
    "WebEnumerationModule",
    "WordPressModule",
    "SubdomainModule",
    "SSLAnalysisModule",
]
