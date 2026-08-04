"""RACON exception hierarchy.

All framework-specific errors derive from :class:`RaconError`, allowing
callers to catch a single base type while still distinguishing between
distinct failure modes.
"""

from __future__ import annotations


class RaconError(Exception):
    """Base class for all RACON exceptions."""


class ConfigurationError(RaconError):
    """Raised when the configuration is malformed or missing required keys."""


class InvalidTargetError(RaconError):
    """Raised when a user-supplied target is not a valid hostname/IP."""


class NetworkError(RaconError):
    """Raised on unrecoverable network failures (DNS, TCP, HTTP)."""


class TimeoutError_(RaconError):
    """Raised when a network operation exceeds its configured timeout."""


class ModuleError(RaconError):
    """Raised when a scan module fails during execution."""


class ReportGenerationError(RaconError):
    """Raised when a report cannot be generated or written."""


class NmapUnavailableError(ModuleError):
    """Raised when the optional Nmap binary is required but missing."""
