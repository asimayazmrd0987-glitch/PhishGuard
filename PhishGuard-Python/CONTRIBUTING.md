# Contributing to PhishGuard (Python)

Thanks for helping improve the project. PhishGuard is an educational, local heuristic analyzer; contributions should keep it dependency-free, explainable and safe by default.

## Before you start

- Read `README.md`, `docs/DEVELOPMENT.md` and `docs/SECURITY.md`.
- For large changes, open an issue first so the scope and detector policy can be discussed.
- Do not include real credentials, OTPs, personal data or live malicious links in issues, tests or fixtures. Use `.test` domains and documentation IP ranges.
- Do not claim that the score is a probability, a malware verdict or a production security guarantee.

## Development setup

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
python -m compileall -q .
ruff check .
```

`mypy phishguard` is advisory. Coverage is optional:

```bash
coverage run -m unittest discover -s tests
coverage report
```

## What to keep stable

- `python main.py`, `python main.py --url ...`, `--message`, `--demo`, `--bench`, `--data` and `--history` must keep working.
- Public imports listed in `phishguard.__all__` should not be removed without a documented deprecation.
- The custom DSA implementations in `algorithms.py` and `ds.py` are part of the teaching purpose; do not replace them with built-ins just for speed.
- Runtime dependencies must stay at zero. Development-only tools belong in the `dev` extra.
- No network access, telemetry or implicit uploads.
- No unsafe HTML rendering in future UIs; escape untrusted text.

## Coding guidelines

- Match the existing module boundaries: CLI/UI → shared reporting/batch/storage → engine → analyzers/data.
- Add type hints to new public functions. Ship `py.typed` and keep it valid.
- Raise the existing `PhishGuardError` subclasses for expected failures; do not use bare `except Exception` around new code.
- Never mutate caller-supplied `Indicator` objects. Use `dataclasses.replace`.
- Keep history and data writes atomic (`phishguard.files.atomic_write_text`).
- Redact before persisting or logging untrusted input.
- Validate new configuration keys in `RiskConfig.validate()` and document their defaults.

## Adding or changing a detector

1. Emit a stable indicator ID, a plain-language description, a category, a configurable weight and a short detail.
2. Add the weight/limit key to `DEFAULTS` and to the config documentation.
3. Add a deterministic test using synthetic data.
4. Run `phishguard demo --strict`. If an expected band changes, update `demos.py`, `docs/DEMOS.md` and the integration test together, with a clear rationale in the pull request.
5. Consider false positives and explainability, not only score changes.

## Adding CLI behaviour

- Put parsing in `phishguard/cli.py`, reusable logic in a shared module, and rendering in `phishguard/reporting.py`.
- Preserve JSON keys where possible; add new keys rather than renaming existing ones.
- Document new exit codes or flags in `docs/CLI.md`.
- Add an in-process test using `phishguard.cli.main([...])` and capture stdout/stderr.
- Ensure interactive mode still rejects options that make no sense there.

## Tests

- Use `unittest`; do not add `pytest` as a requirement.
- Test both success and failure paths, including exit codes and error messages.
- Use `tempfile.TemporaryDirectory()` for filesystem tests.
- Keep tests independent of network access and of the caller's working directory.
- Do not write into the repository's real history file from tests.

## Documentation

Update relevant files when behaviour changes:

- `README.md` — user-facing overview and quick start.
- `docs/CLI.md` — commands, flags, JSON and exit codes.
- `docs/DEVELOPMENT.md` — architecture and workflows.
- `docs/SECURITY.md` — threat model and privacy limits.
- `PhishGuard-Menu-User-Guide.md` — interactive menu.
- `CHANGELOG.md` — user-visible changes.

## Pull-request checklist

- [ ] Tests pass locally on a supported Python version.
- [ ] `python -m compileall -q .` and `ruff check .` pass.
- [ ] `python -m phishguard demo --strict` passes.
- [ ] New behaviour is documented and tested.
- [ ] No real secrets, personal data or live malicious links are included.
- [ ] Runtime dependencies remain empty.
- [ ] `CHANGELOG.md` is updated for user-visible changes.

## Licence

By contributing, you agree that your contribution is licensed under the project's MIT licence.
