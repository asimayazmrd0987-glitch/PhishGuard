# Architecture and code tour

## Request flow

```text
phishguard CLI / legacy main.py / interactive menu
                |
                v
        batch / reporting (shared)
                |
                v
           ScanService (facade)
               /      \
        scan_url    scan_message
           |            |
       URL parser    phrase matching + keyword trie
           |            |
       DomainAnalyzer  extract each link (up to five)
           |            |  \
       URL indicators + message indicators + URL indicators
                          |
                          v
                     RiskEngine
       de-duplicate -> stable merge sort -> keyword cap -> score/level
                          |
                          v
             AnalysisResult + plain-language recommendation
                          |
             +------------+-------------+
             |            |             |
           history      graph        terminal/JSON report
```

The engine never fetches a URL. It only examines strings and local text files.

## Hardening layer

`phishguard/cli.py` contains only argument parsing, dispatch and exit codes. It delegates to:

- `phishguard/batch.py` for one-input-per-line scanning and ranking;
- `phishguard/reporting.py` for text and JSON rendering;
- `phishguard/storage.py` for redacted history and statistics;
- `phishguard/demos.py` for the deterministic scenario runner.

Expected failures use the hierarchy in `phishguard/errors.py`. Configuration and data files are validated in `phishguard/detection_data.py` before use. File writes go through `phishguard/files.py`, which uses a temporary file in the same directory, `fsync`, `os.replace` and a best-effort directory sync. Logging is opt-in through `phishguard/logging_setup.py`; importing the library stays quiet.

## Suggested reading order

1. `phishguard/types.py`: stable indicator/result vocabulary.
2. `phishguard/ds.py`: the data structures being demonstrated.
3. `phishguard/algorithms.py`: the string and sorting algorithms.
4. `phishguard/detection_data.py`: validated configuration and local data-file loading.
5. `phishguard/url_parser.py`: URL decomposition, IPv4/IPv6 checks and link extraction.
6. `phishguard/analyzers.py`: domain impersonation, URL heuristics and message heuristics.
7. `phishguard/engine.py`: aggregation and explainable scoring.
8. `phishguard/storage.py` and `graph_builder.py`: privacy-aware persistence and relationship graph.
9. `phishguard/files.py`, `errors.py`, `logging_setup.py`: the reliability layer.
10. `phishguard/reporting.py`, `batch.py`, `demos.py`: reusable output and scanning flows.
11. `phishguard/cli.py`, `phishguard/ui.py`, `main.py`: command-line, interactive and legacy entry points.

## Key design choice: every point has a reason

Detectors produce `Indicator` records rather than changing the score directly. Every included indicator has an ID, point weight, category and readable description. The scoring engine then de-duplicates and applies the scoring policy. This permits the result to show what contributed to its score.

## Extending detection data

- `data/risk_config.txt`: weights, limits, keyword cap and risk thresholds.
- `data/trusted_domains.txt`: `domain|brand|category`.
- `data/sample_threats.txt`: `domain|category|risk|note` (the supplied domains are synthetic).
- `data/suspicious_keywords.txt`: `word|category|weight`.
- `data/suspicious_phrases.txt`: `phrase|category`.
- `data/suspicious_tlds.txt`, `data/url_shorteners.txt`, `data/known_tlds.txt`, `data/public_suffixes.txt`: one item per line.

Additions should be reviewed before real-world use. In particular, an incorrect threat-list entry can unfairly label a legitimate domain.
