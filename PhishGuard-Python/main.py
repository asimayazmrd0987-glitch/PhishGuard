#!/usr/bin/env python3
"""Backward-compatible entry point for ``python main.py``.

The implementation lives in :mod:`phishguard.cli`; this wrapper keeps the
historical invocation and exit codes working for the existing user guide.
"""
from __future__ import annotations

from phishguard.cli import main

if __name__ == '__main__':
    raise SystemExit(main())
