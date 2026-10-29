"""Allow ``python -m phishguard`` to run the full command-line interface."""
from __future__ import annotations

from .cli import main

if __name__ == '__main__':
    raise SystemExit(main())
