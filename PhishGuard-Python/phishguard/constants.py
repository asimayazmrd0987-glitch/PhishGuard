"""Shared constants for paths, environment variables and data files."""
from __future__ import annotations

DEFAULT_HISTORY_FILE = 'phishguard_history.txt'

DATA_ENV_VAR = 'PHISHGUARD_DATA'
HISTORY_ENV_VAR = 'PHISHGUARD_HISTORY'
LOG_LEVEL_ENV_VAR = 'PHISHGUARD_LOG_LEVEL'

CONFIG_FILE = 'risk_config.txt'

REQUIRED_DATA_FILES = (
    CONFIG_FILE,
    'trusted_domains.txt',
    'sample_threats.txt',
    'suspicious_keywords.txt',
    'suspicious_phrases.txt',
    'suspicious_tlds.txt',
    'url_shorteners.txt',
    'known_tlds.txt',
    'public_suffixes.txt',
)

__all__ = [
    'DEFAULT_HISTORY_FILE',
    'DATA_ENV_VAR',
    'HISTORY_ENV_VAR',
    'LOG_LEVEL_ENV_VAR',
    'CONFIG_FILE',
    'REQUIRED_DATA_FILES',
]
