# Roadmap

## Completed in this educational Python port

- Local URL parsing and extracted-link scanning, including strict IPv4/IPv6 validation.
- Domain heuristics and possible trusted-brand impersonation checks.
- Phrase and whole-word message analysis.
- Explainable risk indicators and configurable weights/caps/thresholds.
- Custom DSA implementations, history redaction, scan graph, interactive UI, batch mode, demos, benchmarks and unit tests.

## Completed in 2.0.0 (production hardening)

- Typed exception hierarchy and a single package version source.
- Strict configuration and data validation with clear file/line errors.
- Atomic history/data writes and owner-only history permissions where supported.
- Shared text/JSON reporting and batch scanning used by the CLI, UI and tests.
- Subcommands, JSON output, `--redact`, `--no-history`, `--fail-on` and documented exit codes.
- Packaging metadata, `console_scripts` entry point, `py.typed`, optional dev extras and CI quality job.
- CLI, validation, atomic-write, redaction, batch and reporting tests.
- CLI, development, security and contribution documentation.

## Next phases

### Phase 2 — Service API and browser UI

- Define a small service boundary over `ScanService` that does not leak CLI concerns.
- Add a standard-library HTTP API (or an explicitly optional framework) with request limits and JSON schemas.
- Build a local browser dashboard for scanning, explanations and history review.
- Keep the CLI and menu as clients of the same service layer.

### Phase 3 — Extensible detection engine

- Move detectors into a registry with stable IDs, categories and configuration keys.
- Version the scoring policy so rule changes are explicit and testable.
- Add detector-level fixtures and precision/recall reporting against a labelled corpus.
- Provide a documented plugin interface for local, offline rules.

## Recommended before real-world deployment

- Build and test against a carefully labelled corpus, and report false positives, false negatives, precision and recall.
- Review trusted/threat list sources and provide update provenance and timestamps.
- Use a maintained public-suffix source, with clear versioning.
- Improve Unicode/IDN confusable handling and add more languages.
- Have security practitioners review threat heuristics, data handling and user-facing language.
- Evaluate accessibility and localisation before presenting the tool to non-technical users.

Do not describe this project as a production security scanner or its score as a probability.
