# Development guide

## Requirements

- Python 3.10 or newer. CI covers 3.10–3.14.
- No runtime third-party dependencies. The application uses only the standard library.
- Optional development tools: `ruff`, `mypy`, `coverage`, `build` (installed by the `dev` extra).

```bash
python -m pip install -e ".[dev]"
```

## Layout and responsibilities

| Module | Responsibility |
|---|---|
| `phishguard/cli.py` | argparse parsing, subcommand dispatch, JSON/text output, exit codes. No detection logic. |
| `phishguard/batch.py` | One-input-per-line scanning, error collection and ranking. Shared by CLI and menu. |
| `phishguard/reporting.py` | Text and JSON rendering, redaction of rendered inputs, history tables. |
| `phishguard/engine.py` | Indicator de-duplication, keyword cap, scoring and `ScanService` facade. |
| `phishguard/analyzers.py` | URL/domain/message detectors. Emits `Indicator` objects. |
| `phishguard/detection_data.py` | Config/data validation, threat/trusted stores, data-directory resolution. |
| `phishguard/storage.py` | Redacted history, sorting/filtering/statistics, atomic persistence. |
| `phishguard/files.py` | Atomic text writes and BOM-tolerant reads. |
| `phishguard/errors.py` | Expected-failure hierarchy. |
| `phishguard/logging_setup.py` | Opt-in logging setup; the library itself is silent. |
| `phishguard/ui.py` | Interactive menu. Delegates to the shared modules above. |
| `phishguard/demos.py` | The 14 deterministic scenarios and their expected bands. |

Keep the dependency direction one-way: `cli`/`ui` → shared modules → `engine` → `analyzers`/`data`. Detectors should not import the CLI or UI.

## Coding conventions

- Standard library only at runtime.
- Type annotations on new public functions; the package ships `py.typed`.
- Prefer dataclasses and immutable snapshots for shared state.
- Never mutate caller-supplied indicators; use `dataclasses.replace` when applying the keyword cap.
- Raise `PhishGuardError` subclasses for expected failures. Keep the existing compatibility (configuration/data/history errors also subclass `RuntimeError`; validation/usage/scan errors also subclass `ValueError`).
- Do not add network access, telemetry or implicit file uploads.
- Keep the educational DSA implementations (`algorithms.py`, `ds.py`) even where Python built-ins would be faster. They are part of the project's teaching purpose.

## Tests

The suite uses the standard-library `unittest` runner and does not require `pytest`.

```bash
python -m unittest discover -s tests -v
```

Coverage:

```bash
coverage run -m unittest discover -s tests
coverage report
```

Test modules:

- `tests/test_phishguard.py` — algorithms, data structures, analyzers, storage, integration.
- `tests/test_cli.py` — CLI text/JSON output, exit codes, history, data validation, legacy flags.
- `tests/test_hardening.py` — exceptions, atomic I/O, config validation, engine immutability, batch, reporting, demos.

When changing scoring, run `phishguard demo --strict` and update `tests/test_phishguard.py::IntegrationTests` plus `docs/DEMOS.md` only with a deliberate rationale.

## Quality checks

```bash
python -m compileall -q .
ruff check .
mypy phishguard
```

The committed ruff configuration is deliberately conservative (`E9`, `F63`, `F7`, `F82`) because the teaching code uses compact one-line branches. Do not weaken it to hide undefined names or syntax errors. Mypy is advisory; `ui.py` is excluded because its interactive handlers are intentionally loosely typed.

## Data files

All files live in `data/` and use `#` comments plus simple pipe-delimited rows. The loader validates them and reports the file and line number on failure.

| File | Format |
|---|---|
| `risk_config.txt` | `key=integer` |
| `trusted_domains.txt` | `domain\|brand\|category` |
| `sample_threats.txt` | `domain\|category\|risk\|note` |
| `suspicious_keywords.txt` | `word\|category\|weight` |
| `suspicious_phrases.txt` | `phrase\|category` (scam or safety category) |
| `suspicious_tlds.txt` | one suffix per line |
| `url_shorteners.txt` | one host per line |
| `known_tlds.txt` | one suffix per line |
| `public_suffixes.txt` | one multi-label suffix per line |

Phrase categories `urgency`, `credential`, `financial`, `prize` and `delivery` are general scam signals. The categories `threat`, `self_harm`, `extortion` and `harassment` are personal-safety signals: they are matched on whole words (so `kill you` does not match `kill your process`), use the `Safety` indicator category, and replace the normal phishing recommendation with safety-specific advice. Their weights are `weight.threat`, `weight.self_harm`, `weight.extortion` and `weight.harassment`.

Run `phishguard data validate --strict` after editing. Keep sample threat entries synthetic (`.test`, documentation IP ranges) unless you have a reliable, attributable source.

## Adding a detector

1. Emit an `Indicator` with a stable ID, plain-language description, category, weight from `RiskConfig`, and a short detail.
2. Add the weight key to `DEFAULTS` in `detection_data.py` and document it.
3. Add a deterministic test and, if it changes a demo outcome, update the expected band deliberately.
4. Do not mutate shared objects; return new indicators.
5. Avoid network calls and unbounded input work.

## Versioning and releases

- Version lives only in `phishguard/version.py` and is read by `pyproject.toml`.
- Update `CHANGELOG.md` for user-visible changes.
- Run the full suite, `demo --strict`, and `python -m build` before tagging.
- The release workflow attaches a source archive to the GitHub release.

## Manual smoke test

```bash
python main.py --version
python main.py --url "https://paypa1.com/signin"
python main.py --url "https://paypa1.com/signin" --json --no-history
python -m phishguard scan "https://paypa1.com/signin" --fail-on high; test $? -eq 1
python -m phishguard data validate
python -m phishguard demo --strict
python -m phishguard history stats
```

Then start `python main.py`, choose option 14, and confirm the data summary is printed before exiting with option 8.
