"""Single source of truth for the PhishGuard Python package version."""

__version__ = '2.0.0'
__version_info__ = tuple(int(part) for part in __version__.split('.') if part.isdigit())
