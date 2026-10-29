# PhishGuard — Python Edition

PhishGuard is a local, explainable risk analyzer for suspicious links and scam-like messages. This folder is the Python port of the original C++17 project. It uses custom educational implementations of core data structures and algorithms, then explains which signs contributed to each heuristic score.

**Important:** the score is a heuristic from 0–100, not a probability or proof. PhishGuard does not open links, resolve DNS, contact remote servers, use machine learning, or call an external API. The included threat entries use synthetic `.test` domains and documentation IP ranges.

Message and email scans also check high-confidence personal-safety language: direct threats of violence, self-harm or suicide risk, blackmail/extortion, and targeted harassment. These matches are reported separately from phishing indicators and switch the recommendation to safety-specific advice. PhishGuard is **not** an emergency or crisis service; if someone is in immediate danger, contact local emergency services.

**Version:** `2.0.0` · **Runtime dependencies:** none (Python standard library only) · **Python:** 3.10+

## Quick start

```bash
python main.py                 # interactive menu
python main.py --url "https://paypa1.com/signin"
python main.py --message "Your account is suspended. Verify now"
python main.py --demo
python main.py --bench
```

On Windows, `run_phishguard.bat` starts the interactive menu.

The program automatically detects `data/` when run from the project folder. Pass `--data <folder>` if you store it elsewhere. `--history` chooses the local text file used for scan history.

## Install as a command

The package can be installed with `pip` and then used as `phishguard`:

```bash
python -m pip install .
phishguard --version
phishguard scan "https://paypa1.com/signin"
```

An editable development install with the optional quality tools:

```bash
python -m pip install -e ".[dev]"
```

Wheels install the editable data files under `share/phishguard/data`. The application also honours `PHISHGUARD_DATA`, so a custom data folder can be selected without flags:

```bash
export PHISHGUARD_DATA=/path/to/data
```

Other environment variables: `PHISHGUARD_HISTORY` (history file) and `PHISHGUARD_LOG_LEVEL` (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).

## Command-line interface

The legacy flags remain fully supported. Version 2.0 adds subcommands, JSON output, safe batch scanning and automation-friendly exit codes.

```bash
# One-shot scans
phishguard scan "https://paypa1.com/signin"
phishguard scan --file message.txt --type message
cat message.txt | phishguard scan --stdin --json

# Batch: one input per line, ranked by risk
phishguard batch samples.txt
phishguard batch samples.txt --json --limit 100 --fail-on high

# History: list, stats, export, clear
phishguard history list --sort score-high --min-level high
phishguard history stats --json
phishguard history export --output history.json
phishguard history clear --yes

# Data and demos
phishguard data validate
phishguard data validate --strict --json
phishguard demo --strict
phishguard bench --quick
```

Useful flags: `--json`, `--redact`, `--no-history`, `--fail-on low|medium|high|critical`, `-v/--verbose`, `-q/--quiet`, `--debug`.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Completed; no `--fail-on` threshold was reached |
| `1` | Completed, but the result reached the `--fail-on` level (or `demo --strict` found a mismatch) |
| `2` | Usage, validation, configuration or data error |
| `3` | Unexpected internal failure |
| `130` | Interrupted with Ctrl+C |

JSON output is stable and contains the input, score, level, recommendation, indicators and extracted findings. Add `--redact` when JSON may be logged or shared; URL portals/queries and sensitive values are hidden.

See [docs/CLI.md](docs/CLI.md) for the complete reference.

## Interactive menu

1. Scan a URL/link
2. Scan a message (SMS, WhatsApp or social message)
3. Scan email text (finish multi-line input with `END` on its own line)
4. View, sort, filter, inspect, remove or clear scan history
5. View/add/update/remove/search local synthetic threat entries
6. View/add/remove trusted domains
7. View statistics and highest-risk history entries
8. Exit
9. Batch scan a text file (one message or link per line)
10. Explore links between scans using breadth-first/depth-first graph traversal
11. Search suspicious keywords by prefix
12. Run 14 demonstration scenarios
13. Run DSA benchmarks
14. Validate the data files and configuration

## Library use

```python
from phishguard import DetectionData, ScanService

data = DetectionData.load_from_directory('data')
service = ScanService(data)

result = service.scan_url('https://paypa1.com/signin')
print(result.score, result.level.name)
for indicator in result.indicators:
    print(indicator.weight, indicator.description)
```

`scan_message`, `scan_email` and `scan_auto` are also available. Importing `phishguard` is quiet: it installs a `NullHandler` and never configures the root logger.

## Project structure

```text
PhishGuard-Python/
├── main.py                       # Backward-compatible CLI entry point
├── phishguard/
│   ├── cli.py                    # argparse CLI, subcommands, JSON and exit codes
│   ├── batch.py                  # Shared batch scanning and ranking
│   ├── reporting.py              # Shared text/JSON rendering
│   ├── files.py                  # Atomic writes and BOM-tolerant reads
│   ├── errors.py                 # Typed exception hierarchy
│   ├── logging_setup.py          # Opt-in logging configuration
│   ├── constants.py              # Data-file and environment-variable names
│   ├── version.py                # Single source of truth for the version
│   ├── algorithms.py             # Levenshtein, KMP, Rabin–Karp, merge/quick sort, binary search
│   ├── ds.py                     # Chained hash table, custom set, max-heap, trie, graph
│   ├── text_utils.py             # Text helpers, data-file reader, privacy redaction
│   ├── types.py                  # Enums and result dataclasses
│   ├── detection_data.py         # Config validation, threat/trusted stores, data loading
│   ├── url_parser.py             # Strict URL parser, IPv4/IPv6 checks, link extraction
│   ├── analyzers.py              # Domain, URL and message checks
│   ├── engine.py                 # Indicator de-duplication, weighted scoring and facade
│   ├── storage.py                # Redacted atomic history, queries and statistics
│   ├── graph_builder.py          # Connect scan results to links/domains/keywords
│   ├── ui.py                     # Interactive terminal menu
│   ├── demos.py                  # 14 deterministic demo scenarios
│   └── benchmark.py              # Lightweight algorithm/data-structure comparisons
├── data/                         # Same editable data/configuration files as C++ edition
├── tests/                        # unittest suite (CLI, hardening, algorithms, integration)
└── docs/                         # Architecture, DSA, CLI, security, limitations, notes
```

## Risk scoring overview

Each detector emits an `Indicator` with a stable ID, plain-language description, category and point weight. The risk engine de-duplicates by ID, sorts strongest indicators first using the project's stable merge sort, applies a configurable total cap to keyword points, adds the retained weights, clamps the score to 100 and maps it to LOW/MEDIUM/HIGH/CRITICAL using `data/risk_config.txt`.

Default score bands: LOW ≤ 20; MEDIUM ≤ 40; HIGH ≤ 70; CRITICAL > 70. All weights and thresholds are judgement-based and editable; they are not statistically trained.

Configuration and data files are validated on load. Negative weights/caps, non-positive limits, out-of-order thresholds, malformed records and missing required files fail with a clear error. Editable data and history files are written atomically (temporary file + `os.replace`), and history is created with owner-only permissions where the platform supports it.

## Message-scan safety checks

Scam detection is not the only kind of harmful text. Message and email scans therefore include four high-confidence safety categories:

| Category | Examples of matched language | Default weight | Default level |
|---|---|---:|---|
| `threat` | direct threats of violence or harm | 60 | HIGH |
| `self_harm` | self-harm or suicide statements, or telling someone to self-harm | 65 | HIGH |
| `extortion` | blackmail, sextortion, or demands backed by threats | 50 | HIGH |
| `harassment` | targeted insults and degrading language | 25 | MEDIUM |

Safety phrases are matched as **whole words**, not raw substrings, so `kill you` does not fire on `kill your process`, and `kill yourself` is not treated as the same phrase as `kill you`. A message such as `I will kill you` now produces a HIGH result with a `phrase_threat` indicator, instead of a misleading LOW result. The recommendation changes to advice about saving evidence, not meeting the sender, blocking/reporting, and contacting emergency services when there is immediate danger.

The phrases live in `data/suspicious_phrases.txt` and the weights live in `data/risk_config.txt`, so both are editable. This remains pattern matching: it cannot understand context, sarcasm, quoted speech or every language. Do not rely on it as a substitute for emergency services or professional support.

## Privacy and safety

- No link is opened or fetched. All checks are performed on the supplied text.
- History redacts URL query strings, URL user-info, sensitive password/PIN/OTP/CVV/token values, and long digit runs before writing records to disk.
- History and exported files are written atomically and, on POSIX systems, with mode `0600`.
- The sample threat list is synthetic. A trusted-domain list also is only as accurate as the entries maintained by the user.
- A LOW result is not a guarantee that a link is safe. A high result is not proof that a site is malicious.
- See [docs/SECURITY.md](docs/SECURITY.md) for the threat model, data-handling notes and reporting guidance.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
python -m pip install -e ".[dev]"
ruff check .
mypy phishguard
coverage run -m unittest discover -s tests && coverage report
python -m build
```

CI runs the test suite on Python 3.10–3.14, lints for syntax/undefined names, builds a wheel and smoke-tests the installed `phishguard` entry point. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Porting note

The Python code preserves the architecture and intended behavior of the C++ edition (URL parsing, explainable indicators, local lists, DSA demonstrations, history, graph exploration, batch mode, demos and benchmarks). The Python implementation is not claimed to be bit-for-bit identical in every platform-dependent behavior or benchmark time.
