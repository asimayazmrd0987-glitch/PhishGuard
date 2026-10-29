"""PhishGuard: explainable heuristic phishing and scam-message analyser.

The package is intentionally dependency-free and performs no network access.
The public API mirrors the documented command-line behaviour::

    from phishguard import DetectionData, ScanService

    data = DetectionData.load_from_directory('data')
    result = ScanService(data).scan_url('https://paypa1.com/signin')
    print(result.score, result.level.name)

Library code never configures the root logger.  Importing PhishGuard only adds
a :class:`logging.NullHandler` so embedders stay silent unless they opt in.
"""

from __future__ import annotations

import logging

from .detection_data import (
    DataSummary,
    DetectionData,
    Phrase,
    RiskConfig,
    ThreatDatabase,
    ThreatEntry,
    TrustedDomainStore,
    TrustedEntry,
)
from .engine import RiskEngine, ScanService
from .errors import (
    ConfigurationError,
    DataError,
    HistoryError,
    PhishGuardError,
    ScanError,
    UsageError,
    ValidationError,
)
from .types import (
    AnalysisResult,
    Indicator,
    IndicatorCategory,
    InputType,
    RiskLevel,
    ScanFindings,
)
from .version import __version__

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    '__version__',
    'DetectionData',
    'DataSummary',
    'RiskConfig',
    'ThreatDatabase',
    'ThreatEntry',
    'TrustedDomainStore',
    'TrustedEntry',
    'Phrase',
    'ScanService',
    'RiskEngine',
    'AnalysisResult',
    'ScanFindings',
    'InputType',
    'RiskLevel',
    'Indicator',
    'IndicatorCategory',
    'PhishGuardError',
    'ConfigurationError',
    'DataError',
    'HistoryError',
    'ValidationError',
    'UsageError',
    'ScanError',
]
