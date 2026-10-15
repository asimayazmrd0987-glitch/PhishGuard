"""Shared data structures for scan input, explanations, and results."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum, Enum
from typing import Optional

class RiskLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

class InputType(str, Enum):
    URL = 'URL'
    MESSAGE = 'MESSAGE'
    EMAIL = 'EMAIL'

class IndicatorCategory(str, Enum):
    THREAT = 'Threat'
    DOMAIN = 'Domain'
    URL = 'Url'
    KEYWORD = 'Keyword'
    MESSAGE = 'Message'
    SIMILARITY = 'Similarity'

@dataclass
class Indicator:
    id: str
    description: str
    weight: int = 0
    category: IndicatorCategory = IndicatorCategory.URL
    detail: str = ''

@dataclass
class ImpersonationMatch:
    input_part: str
    trusted_domain: str
    distance: int = 0
    similarity: float = 0.0
    used_lookalike_chars: bool = False
    embedded: bool = False

@dataclass
class ScanFindings:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    threat_domains: list[str] = field(default_factory=list)
    impersonation: Optional[ImpersonationMatch] = None

@dataclass
class AnalysisResult:
    type: InputType = InputType.URL
    input: str = ''
    score: int = 0
    level: RiskLevel = RiskLevel.LOW
    indicators: list[Indicator] = field(default_factory=list)
    recommendation: str = ''
    findings: ScanFindings = field(default_factory=ScanFindings)


def risk_level_from_string(s: str) -> Optional[RiskLevel]:
    try:
        return RiskLevel[s.strip().upper()]
    except KeyError:
        return None


def input_type_from_string(s: str) -> Optional[InputType]:
    try:
        return InputType(s.strip().upper())
    except ValueError:
        return None


def risk_level_name(level: RiskLevel) -> str:
    return level.name


def input_type_name(kind: InputType) -> str:
    return kind.value
