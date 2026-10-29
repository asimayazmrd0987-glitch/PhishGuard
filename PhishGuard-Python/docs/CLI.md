# Command-line reference

PhishGuard 2.0 keeps the historical `main.py` invocations and adds a modern subcommand interface. Both forms call the same engine, reporting layer and history store.

```bash
python main.py [legacy flags]
python -m phishguard <command> [options]
phishguard <command> [options]        # after pip install .
```

No command performs network access.

## Global options

| Option | Description |
|---|---|
| `--data DIR` | Data folder containing `risk_config.txt` and the other required files. Defaults to auto-detection (see below). |
| `--history FILE` | History file. Defaults to `PHISHGUARD_HISTORY` or `phishguard_history.txt`. |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. Defaults to `PHISHGUARD_LOG_LEVEL` or `WARNING`. Logs go to stderr. |
| `-v`, `--verbose` | Shortcut for `--log-level DEBUG`. |
| `-q`, `--quiet` | Shortcut for `--log-level ERROR`. |
| `--debug` | Show a traceback for expected and unexpected failures instead of a one-line message. |
| `--version` | Print `phishguard <version>` and exit. |

The global options may appear before or after a subcommand. For example, both of these work:

```bash
phishguard --data ./data scan "https://example.test"
phishguard scan "https://example.test" --data ./data
```

### Data-folder discovery

Search order:

1. the `--data` value (the folder itself, then `<value>/data`);
2. `PHISHGUARD_DATA` (the folder itself, then `<value>/data`);
3. `./data`, `./`, `../data`, `../../data`;
4. the package's neighbouring `data/` folders;
5. `<sysconfig data>/share/phishguard/data` and `<sys.prefix>/share/phishguard/data`.

The first directory containing `risk_config.txt` wins. If none is found, the command exits with status `2` and lists the searched paths.

## Legacy interface

All pre-2.0 invocations remain valid:

```bash
python main.py
python main.py --url "https://paypa1.com/signin"
python main.py --message "Your account is suspended. Verify now"
python main.py --email "Dear customer, ..."        # new in 2.0
python main.py --batch samples.txt
python main.py --demo
python main.py --bench
python main.py --data ./data --history ./history.txt
```

The legacy parser also accepts `--json`, `--redact`, `--no-history`, `--fail-on LEVEL`, `--type auto|url|message|email`, `--quick` and `--strict`, so existing scripts can opt into the new output without changing the command shape.

```bash
python main.py --url "https://paypa1.com/signin" --json
python main.py --url "https://paypa1.com/signin" --fail-on high --no-history
python main.py --demo --strict
```

With no source flag, the interactive menu starts. `--json`, `--fail-on`, `--no-history` and `--redact` are rejected in interactive mode because they have no meaningful output target.

## `scan`

Scan one URL, message or email.

```text
phishguard scan [INPUT] [--type auto|url|message|email]
                [--file FILE | --stdin]
                [--json] [--redact] [--no-history] [--fail-on LEVEL]
```

| Option | Description |
|---|---|
| `INPUT` | Text to scan. Omit it to read piped stdin. |
| `--type` | Force the input type. `auto` (default) treats a single line with a scheme/dot and no spaces as a URL, otherwise as a message. |
| `--file FILE` | Read the whole input from a file. |
| `--stdin` | Read the whole input from stdin. |
| `--json` | Emit JSON instead of the human-readable report. |
| `--redact` | Redact the input in JSON output. Recommended for logs. |
| `--no-history` | Do not append the scan to the history file. |
| `--fail-on LEVEL` | Exit `1` when the result reaches `low`, `medium`, `high` or `critical`. |

Only one input source may be used. If stdin is not a terminal and no source is supplied, `scan` reads it automatically.

```bash
phishguard scan "https://paypa1.com/signin"
phishguard scan --file email.txt --type email --json --redact
cat message.txt | phishguard scan --stdin --type message
phishguard scan "I will kill you" --type message --no-history
```

Message and email scans also run whole-word personal-safety checks for direct violence threats, self-harm/suicide risk, extortion and targeted harassment. A match uses the `Safety` indicator category and a safety-specific recommendation; for example, `I will kill you` returns a HIGH result with `phrase_threat`. These checks are heuristics, not an emergency service.

## `batch`

Scan one input per line. Blank lines and lines beginning with `#` are skipped. Invalid lines are reported and do not abort the batch.

```text
phishguard batch [FILE] [--stdin] [--type auto|url|message|email]
                 [--limit N] [--json] [--redact] [--no-history] [--fail-on LEVEL]
```

| Option | Description |
|---|---|
| `FILE` | Text file to read, or omit with `--stdin`. |
| `--type` | Force every line to one type, or auto-detect per line. |
| `--limit N` | Scan at most `N` valid lines. |
| `--json` | Emit ranked JSON with errors and summary fields. |
| `--redact` | Redact inputs in JSON output. |
| `--no-history` | Do not record batch results. |
| `--fail-on LEVEL` | Exit `1` when the highest-scoring result reaches `LEVEL`. |

Text output is ranked highest risk first. JSON includes `items` (ranked), `scanned`, `skipped`, `errors`, `max_score`, `max_level` and `limit_reached`. If every non-blank line was rejected, the command exits `2`; partial success exits `0` or `1` according to `--fail-on`.

```bash
phishguard batch samples.txt
phishguard batch samples.txt --json --limit 100 --fail-on high
phishguard batch --stdin --type url
```

## `demo`

Run the 14 deterministic scenarios and compare each result with its expected level band.

```text
phishguard demo [--json] [--strict]
```

`--strict` exits `1` if any scenario leaves its expected band, making the command a regression check for scoring changes. JSON contains `scenarios` and the `passed`/`total` counts.

```bash
phishguard demo
phishguard demo --json
phishguard demo --strict
```

## `bench`

Run the educational DSA benchmarks.

```text
phishguard bench [--quick]
```

`--quick` uses smaller input sizes for faster runs. Timings are illustrative only.

## `history`

Inspect or manage the local history file. History is redacted before it is written.

```text
phishguard history list   [--sort newest|oldest|score-high|score-low|level]
                          [--limit N] [--min-level LEVEL]
                          [--type url|message|email] [--contains TEXT]
                          [--json]
phishguard history stats  [--json]
phishguard history clear  [--yes]
phishguard history export [--output FILE]
```

| Action | Description |
|---|---|
| `list` | Print records, newest first by default. Combine filters freely. |
| `stats` | Total scans, per-level counts, average score, top indicators and highest-risk records. |
| `clear` | Delete all records. Prompts unless `--yes`; non-interactive use requires `--yes`. |
| `export` | Write all records plus stats as JSON to stdout or `--output FILE` (mode `0600`). |

```bash
phishguard history list --sort score-high --min-level high --limit 10
phishguard history stats --json
phishguard history export --output history.json
phishguard history clear --yes
```

## `data`

Validate or locate the detection data.

```text
phishguard data validate [--strict] [--json]
phishguard data path     [--json]
```

Validation checks required files, numeric values, non-negative weights/caps, positive limits and ordered thresholds. It reports unknown configuration keys and empty trusted/threat lists as warnings. `--strict` turns unknown keys into errors.

```bash
phishguard data validate
phishguard data validate --strict --json
phishguard data path
```

## `version`

```bash
phishguard version
# phishguard 2.0.0
```

Equivalent to `phishguard --version`.

## JSON output

A one-shot scan produces an object like this (trimmed):

```json
{
  "type": "URL",
  "input": "https://paypa1.com/signin",
  "score": 42,
  "level": "HIGH",
  "recommendation": "Several suspicious signs were found...",
  "indicators": [
    {
      "id": "lookalike_domain",
      "description": "This website name is very similar to a trusted website (paypal.com)...",
      "weight": 30,
      "category": "Similarity",
      "detail": "paypal.com"
    }
  ],
  "findings": {
    "urls": ["https://paypa1.com/signin"],
    "domains": ["paypa1.com"],
    "ips": [],
    "keywords": ["signin"],
    "threat_domains": [],
    "impersonation": {
      "input_part": "paypa1.com",
      "trusted_domain": "paypal.com",
      "distance": 1,
      "similarity": 0.9,
      "used_lookalike_chars": true,
      "embedded": false
    }
  }
}
```

Keys are sorted and non-ASCII text is preserved. `--redact` replaces URL user-info and query/fragment content and sensitive values in the input. History records are redacted when written regardless of the output flag.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success; no fail threshold reached |
| `1` | Risk threshold reached via `--fail-on`, or `demo --strict` mismatch |
| `2` | Usage, validation, configuration or data error |
| `3` | Unexpected internal failure |
| `130` | Keyboard interrupt |

## Environment variables

| Variable | Purpose |
|---|---|
| `PHISHGUARD_DATA` | Default data directory. |
| `PHISHGUARD_HISTORY` | Default history file. |
| `PHISHGUARD_LOG_LEVEL` | Default logging level. |

## Shell completion and programming use

`phishguard.cli.main(argv)` returns the exit code instead of raising `SystemExit`, so it can be called from tests or other Python programs:

```python
from phishguard.cli import main

code = main(['scan', 'https://paypa1.com/signin', '--json', '--no-history'])
```
