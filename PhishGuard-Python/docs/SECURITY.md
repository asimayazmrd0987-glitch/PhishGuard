# Security and privacy notes

This document describes what PhishGuard 2.0 does and does not protect. It is an educational, local heuristic analyzer, not a security control, antivirus engine or threat-intelligence service.

## Supported versions

Security fixes are applied to the current 2.x line. Older snapshots are not maintained.

## Threat model

### In scope

- Accidental disclosure of pasted secrets through history files, logs, JSON output or screenshots.
- Partial history corruption caused by a crash, full disk or interrupted write.
- Malformed configuration/data files producing confusing failures instead of clear errors.
- Unbounded input causing excessive CPU or memory use in normal CLI use.
- Unsafe rendering of untrusted text into terminal output or JSON.
- Supply-chain risk from runtime dependencies.

### Out of scope

- Proving whether a real website, sender or message is malicious.
- Opening, sandboxing or detonating links.
- DNS, WHOIS, certificate, reputation or blocklist lookups.
- Protecting a machine that is already compromised.
- Multi-user isolation. PhishGuard is a single-user local tool; it has no authentication, authorization or server mode.

## Trust boundaries

- **User input** (URLs, messages, email text, batch files) is untrusted text. It is parsed and scored but never executed or fetched.
- **Local data files** are user-maintained configuration. They are parsed as text; a malformed file causes a validation error, not code execution.
- **History** may contain fragments of untrusted text. It is redacted before writing, but redaction is best-effort.
- **The terminal** renders untrusted text. Control characters are rejected in messages; URLs with control characters are treated as malformed. Always review output before pasting it into a report.

## Data handling

- No network access is performed by the application or tests.
- No telemetry, analytics or remote logging is included.
- Logs go to stderr only when the user enables them. The library does not configure the root logger.
- History redacts URL user-info, query strings and fragments, password/PIN/OTP/CVV/token-like values and long digit runs.
- History and exported JSON are written atomically through a temporary file and `os.replace`.
- On POSIX systems, history and exports are created with mode `0600` (owner read/write). Data files are written with `0644` so they remain editable.
- The history file is plain text. Treat it as private. Redaction reduces exposure but does not guarantee that every identifying detail is removed.
- `--redact` applies the same redaction to JSON output. Without it, JSON contains the input as supplied. Do not log unredacted JSON from untrusted sources.

## Input limits and validation

- Messages are limited to `limit.max_message` characters (default 10,000).
- Extracted URLs per message are limited to `limit.max_urls` (default 5).
- A single URL is limited to 2,048 characters.
- Ports must be numeric and in `0..65535`.
- IPv4 and IPv6 literals are validated with Python's `ipaddress` module.
- Host labels are checked for length, empty labels, leading/trailing hyphens and unusual characters.
- Message input containing unreadable control characters is rejected.
- Configuration requires non-negative weights/caps, positive limits and ordered thresholds.
- Unknown configuration keys are warned about, or rejected with `--strict`.

These are reliability limits, not a hardened sandbox. A caller embedding the library should still apply its own request-size and time limits.

## Privacy limitations

- Redaction is rule-based and can miss unusual formats.
- Pasted content is processed in memory; Python cannot guarantee secure memory erasure.
- Batch and history features store redacted copies of every scanned input by default. Use `--no-history` for sensitive one-off checks.
- Demo and test data are synthetic. Do not paste real credentials, OTPs, payment details or confidential messages into any example.
- JSON exports and terminal output may still identify a sender, domain or message context even after secret masking.

## Detection limitations

- The score is a judgement-based heuristic, not a probability or a verdict.
- False positives and false negatives are expected. The demos include both.
- Trusted-domain and threat lists are only as good as their local entries.
- Unicode/IDN confusables, homoglyphs and many languages are only partially handled.
- A LOW score does not prove safety. A HIGH/CRITICAL score does not prove malicious intent.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's security advisory feature (or directly to the maintainer listed on the repository profile) rather than opening a public issue with exploit details.

Include:

- the PhishGuard version and Python version;
- the platform;
- a minimal reproduction using synthetic data;
- the impact you believe is possible;
- whether the issue affects the CLI, library, data loader or file handling.

Do not include real credentials, personal data or live malicious links. A proof of concept that merely demonstrates a heuristic false positive is a detection-quality issue, not a security vulnerability; report it as a regular issue with a synthetic example.
