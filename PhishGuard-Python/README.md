# PhishGuard — Python Edition

PhishGuard is a local, explainable risk analyzer for suspicious links and scam-like messages. This folder is the Python port of the original C++17 project. It uses custom educational implementations of core data structures and algorithms, then explains which signs contributed to each heuristic score.

**Important:** the score is a heuristic from 0–100, not a probability or proof. PhishGuard does not open links, resolve DNS, contact remote servers, use machine learning, or call an external API. The included threat entries use synthetic `.test` domains and documentation IP ranges.

## Run it

Python 3.10 or newer is recommended. No third-party Python packages are required.

From this directory, open a terminal and run:

```bash
python main.py
```

On Windows, `run_phishguard.bat` starts the interactive menu.

### One-shot scans and other commands

```bash
python main.py --url "https://paypa1.com/signin"
python main.py --message "Your account is suspended. Verify now"
python main.py --demo
python main.py --bench
python main.py --data ./data --history ./phishguard_history.txt
python -m unittest discover -s tests -v
```

The program automatically detects `data/` when run from the project folder. Pass `--data <folder>` if you store it elsewhere. `--history` chooses the local text file used for scan history.

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

## Project structure

```text
PhishGuard-Python/
├── main.py                       # CLI entry point
├── phishguard/
│   ├── algorithms.py             # Levenshtein, KMP, Rabin–Karp, merge/quick sort, binary search
│   ├── ds.py                     # Chained hash table, custom set, max-heap, trie, graph
│   ├── text_utils.py             # Text helpers, data-file reader, privacy redaction
│   ├── types.py                  # Enums and result dataclasses
│   ├── detection_data.py         # Config, threat/trusted stores, data loading
│   ├── url_parser.py             # Strict URL parser and message link extraction
│   ├── analyzers.py              # Domain, URL and message checks
│   ├── engine.py                 # Indicator de-duplication, weighted scoring and facade
│   ├── storage.py                # Redacted history, queries and statistics
│   ├── graph_builder.py          # Connect scan results to links/domains/keywords
│   ├── ui.py                     # Interactive terminal menu
│   ├── demos.py                  # 14 deterministic demo scenarios
│   └── benchmark.py              # Lightweight algorithm/data-structure comparisons
├── data/                         # Same editable data/configuration files as C++ edition
├── tests/test_phishguard.py      # unittest suite
└── docs/                         # Architecture, DSA, limitations, report and viva notes
```

## Risk scoring overview

Each detector emits an `Indicator` with a stable ID, plain-language description, category and point weight. The risk engine de-duplicates by ID, sorts strongest indicators first using the project's stable merge sort, applies a configurable total cap to keyword points, adds the retained weights, clamps the score to 100 and maps it to LOW/MEDIUM/HIGH/CRITICAL using `data/risk_config.txt`.

Default score bands: LOW ≤ 20; MEDIUM ≤ 40; HIGH ≤ 70; CRITICAL > 70. All weights and thresholds are judgement-based and editable; they are not statistically trained.

## Privacy and safety

- No link is opened or fetched. All checks are performed on the supplied text.
- History redacts URL query strings, URL user-info, sensitive password/PIN/OTP/CVV values, and long digit runs before writing records to disk.
- The sample threat list is synthetic. A trusted-domain list also is only as accurate as the entries maintained by the user.
- A LOW result is not a guarantee that a link is safe. A high result is not proof that a site is malicious.

## Porting note

The Python code preserves the architecture and intended behavior of the C++ edition (URL parsing, explainable indicators, local lists, DSA demonstrations, history, graph exploration, batch mode, demos and benchmarks). The Python implementation is not claimed to be bit-for-bit identical in every platform-dependent behavior or benchmark time.
