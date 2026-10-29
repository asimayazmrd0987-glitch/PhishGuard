"""Exception hierarchy for PhishGuard.

The domain exceptions deliberately subclass the built-in exception types that
the original implementation raised (``RuntimeError``/``ValueError``).  Existing
callers that catch those built-ins keep working, while new callers can catch the
more precise PhishGuard types.
"""
from __future__ import annotations


class PhishGuardError(Exception):
    """Base class for every expected PhishGuard failure."""


class ConfigurationError(PhishGuardError, RuntimeError):
    """A configuration file is missing, malformed or internally inconsistent."""


class DataError(PhishGuardError, RuntimeError):
    """A detection data file is missing, malformed or inconsistent."""


class HistoryError(PhishGuardError, RuntimeError):
    """The scan-history file cannot be read or written safely."""


class ValidationError(PhishGuardError, ValueError):
    """User input failed validation."""


class UsageError(PhishGuardError, ValueError):
    """The command-line invocation is contradictory or incomplete."""


class ScanError(PhishGuardError, ValueError):
    """A scan could not be completed for the supplied input."""


__all__ = [
    'PhishGuardError',
    'ConfigurationError',
    'DataError',
    'HistoryError',
    'ValidationError',
    'UsageError',
    'ScanError',
]
