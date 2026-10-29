"""Small logging setup shared by the CLI and the package.

The library never configures the root logger by default.  The CLI calls
``configure_logging`` once, which keeps library use quiet for embedders and
tests.  ``PHISHGUARD_LOG_LEVEL`` can set the default level without any flags.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional, TextIO

from .constants import LOG_LEVEL_ENV_VAR

LOGGER_NAME = 'phishguard'
_FORMAT = '%(levelname)s %(name)s: %(message)s'
_VALID_LEVELS = {'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'}


def _coerce_level(level: Optional[str | int]) -> int:
    if isinstance(level, int):
        return level
    if not level:
        return logging.WARNING
    name = str(level).strip().upper()
    if name not in _VALID_LEVELS:
        return logging.WARNING
    return getattr(logging, name)


def configure_logging(level: Optional[str | int] = None, stream: Optional[TextIO] = None) -> logging.Logger:
    """Configure the ``phishguard`` logger and return it.

    Calling this repeatedly is safe; the handler is only added once.
    """
    logger = logging.getLogger(LOGGER_NAME)
    if level is None:
        level = os.environ.get(LOG_LEVEL_ENV_VAR)
    logger.setLevel(_coerce_level(level))
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
    return logger


def get_logger(name: str = '') -> logging.Logger:
    """Return a namespaced logger such as ``phishguard.storage``."""
    return logging.getLogger(f'{LOGGER_NAME}.{name}' if name else LOGGER_NAME)


__all__ = ['LOGGER_NAME', 'configure_logging', 'get_logger']
