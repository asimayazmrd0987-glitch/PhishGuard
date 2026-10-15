# PhishGuard — project report

## Abstract

PhishGuard is a local, explainable heuristic analyzer for suspicious URLs and scam-like text messages. It demonstrates classic data structures and algorithms in a practical security-oriented application. Rather than producing an unexplained label, each detection contributes an indicator with a reason and weight. The result is a risk score from 0 to 100 and a recommendation for the user.

## Problem statement

Everyday users receive links and messages that create urgency, ask for credentials or payments, or imitate a recognized service. A non-technical person may struggle to understand the warning signs. PhishGuard attempts to surface common clues in understandable language without requiring an external service.

## Objectives

1. Analyze URL strings and messages locally without opening links or contacting hosts.
2. Apply hash tables, tries, heaps, graphs, string matching, edit distance, and sorting.
3. Explain every counted risk indicator in plain language.
4. Store scan history with sensitive details redacted.
5. Provide interactive, batch, demo and benchmark workflows.
6. Keep rule weights and reference lists editable using text files.

## Methodology

The URL pipeline parses the URL into scheme, user information, host, port, path, query and fragment. Domain analysis compares the host against local trusted and synthetic threat lists and checks for suspicious endings, shorteners, numerous subdomains, hyphens, digits, punycode and possible brand impersonation. URL analysis checks formatting patterns, redirect parameters, encoded characters and watched words.

Message analysis searches phrase categories using KMP, detects whole-word keywords via a trie, checks writing patterns, extracts link-like tokens and submits up to five links to the URL analyzer. The risk engine de-duplicates indicators by ID, sorts by weight, applies a configurable cap to keyword points, sums the retained weights and maps the total into a configured risk band.

## Data structures and algorithms

- Separate-chaining hash table: local lookups and configurable entries.
- Custom set: de-duplicate indicator IDs and watched values.
- Trie: keyword membership, prefix search and whole-word text scanning.
- Max-heap: extract highest-risk scan records efficiently.
- Adjacency-list graph: connect scans with links, host names, watched keywords and trusted look-alikes; traverse with BFS/DFS.
- Levenshtein dynamic programming: estimate character edits in a look-alike domain.
- KMP and Rabin–Karp: phrase and substring matching.
- Merge sort, quicksort and binary search: ranking and algorithm demonstrations.

## Testing

Run:

```bash
python -m unittest discover -s tests -v
python main.py --demo
```

The tests cover algorithm results, data-structure edge cases, URL parsing, message validation, key heuristics, history redaction and persistence, graph connectivity and expected risk ranges for all demos.

## Limitations

This is an educational rule-based project, not a production anti-phishing guarantee. Weights are expert-chosen rather than trained on a labelled corpus; rule lists are small and English-focused; valid sites can trigger false positives; sophisticated scams can evade heuristics. A small hand-maintained public-suffix list cannot represent the entire public DNS suffix space. Punycode and Unicode handling is a warning heuristic, not a complete visual-confusable detector.

## Future work

Use a reviewed public-suffix source, evaluate against a labelled and maintained data set, measure false-positive/false-negative rates, improve Unicode confusable analysis, add local-language phrases, improve configuration validation, and build a lightweight front end while preserving local-only analysis.

## Conclusion

PhishGuard connects DSA coursework to an everyday cybersecurity concern. Its primary output is not a claim that a site is safe or malicious; it presents a list of visible indicators so users can make more informed decisions and verify through official channels.
