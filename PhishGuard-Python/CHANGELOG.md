# Changelog

All notable changes to the Python edition are documented here. The format follows the spirit of Keep a Changelog, and the project uses semantic versioning for the Python package.

## [2.0.0] — 2026-10-29

### Added

- Subcommand CLI: `scan`, `batch`, `demo`, `bench`, `history`, `data` and `version`, while keeping every legacy `main.py` flag working.
- Stable JSON output for scans, batches, demos, history and data validation.
- `--redact`, `--no-history` and `--fail-on LEVEL` automation options.
- Documented exit codes: `0` success, `1` risk threshold, `2` usage/validation/data error, `3` internal failure, `130` interrupt.
- Batch scanning shared by the CLI and menu, with skipped-line counts, per-line errors, limits and ranked output.
- `data validate` / `data path` commands and interactive menu option 14.
- Shared text/JSON reporting module used by the CLI, UI and tests.
- Typed exception hierarchy and a single-source package version (`phishguard.version`).
- Opt-in logging setup with `PHISHGUARD_LOG_LEVEL`, `-v`, `-q` and `--debug`.
- Strict configuration and data validation: numeric parsing, non-negative weights/caps, positive limits, ordered thresholds, unknown-key warnings and `--strict`.
- IPv4/IPv6 validation using the standard-library `ipaddress` module.
- Atomic history and data writes (temporary file + `os.replace` + best-effort directory sync).
- Versioned history header, owner-only permissions on POSIX, and malformed-line recovery with warnings.
- `scan_email`, `scan_auto`, `DataSummary`, `TrustedDomainStore.snapshot()` and `py.typed`.
- Packaging metadata, `phishguard` console script, editable data files under `share/phishguard/data`, optional `dev` extras and tool configuration.
- `docs/CLI.md`, `docs/DEVELOPMENT.md`, `docs/SECURITY.md`, `CONTRIBUTING.md` and this changelog.
- CLI, hardening, batch, reporting, validation and atomic-I/O tests (53 tests total).

### Changed

- `main.py` and `python -m phishguard` are thin wrappers around `phishguard.cli.main`.
- Demo execution, batch ranking and result rendering now use shared modules instead of separate UI/CLI implementations.
- The risk engine no longer mutates caller-supplied keyword indicators when applying the keyword cap.
- Message length and URL-count limits now come from validated configuration (`limit.max_message`, `limit.max_urls`).
- Data-directory discovery also checks `PHISHGUARD_DATA`, package-relative folders and installed `share/phishguard/data`.
- History and data saves are atomic; data saves preserve editable permissions and add explanatory headers.
- The CI workflow now covers Python 3.10–3.14 and adds a quality job that lints, builds a wheel and smoke-tests the installed entry point.

### Fixed

- History records containing `|` or embedded newlines can no longer corrupt the file layout.
- Malformed history lines are skipped with a warning instead of aborting the load.
- IPv4 literals with out-of-range octets and malformed IPv6 literals are rejected.
- BOM-prefixed data files are read correctly.
- Unknown configuration keys are reported instead of being silently accepted.
- Batch scans no longer crash on one invalid line.
- Interactive menu batch results use the same auto-detection and ranking as the CLI.

### Compatibility

- The Python package version is now `2.0.0` (previously `1.0.0-python`).
- Zero runtime third-party dependencies remain.
- Existing imports, legacy CLI flags, data files, demos and the educational DSA implementations are preserved.
- Domain exceptions subclass the built-in types the earlier code raised, so existing `except RuntimeError` / `except ValueError` handlers keep working.

## [1.0.0] — 2026

- Initial Python port of the C++17 PhishGuard: URL parsing, heuristic detectors, explainable indicators, local data files, history, graph exploration, interactive menu, batch mode, demos, benchmarks and unit tests.
