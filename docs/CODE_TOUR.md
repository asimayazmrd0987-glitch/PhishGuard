# Code Tour: how to read PhishGuard in 60 minutes

Every source file starts with a header block: **WHAT** it is, **HOW** it works, **WHY** it exists,
and its complexity. Read in this order and each file only needs the ones before it.

## 1. The vocabulary (5 min)
1. `common/types.hpp`: Indicator, AnalysisResult. *Every score point is an Indicator with a plain-language reason.*
2. `common/text_utils.hpp`: string helpers, look-alike folding, privacy redaction.

## 2. Data structures (20 min)
3. `ds/hash_table.hpp`: chaining, rehashing, load factor. **Read this one twice.**
4. `ds/custom_set.hpp`: a set is a hash table with no values.
5. `ds/trie.hpp` + `ds/trie.cpp`: prefix tree, deletion with pruning, whole-word scan.
6. `ds/heap.hpp`: sift-up / sift-down, heapify.
7. `ds/graph.hpp` + `ds/graph.cpp`: adjacency list, BFS (queue), DFS (stack).

## 3. Algorithms (15 min)
8. `algorithms/levenshtein.hpp/.cpp`: the DP table. Draw `paypa1` vs `paypal` by hand.
9. `algorithms/string_match.hpp/.cpp`: naive, KMP prefix table, Rabin-Karp rolling hash.
10. `algorithms/sorting.hpp`: merge sort, quick sort, binary search.

## 4. The detection pipeline (15 min)
11. `analyzers/url_parser.*`: one-pass URL parser.
12. `analyzers/domain_analyzer.*`: the impersonation search (Levenshtein + Rabin-Karp + KMP).
13. `analyzers/url_analyzer.*` and `analyzers/message_analyzer.*`: the rest of the checks.
14. `security/risk_engine.*`: de-duplicate, cap, sum, level.
15. `security/scan_service.*`: the front door that ties it together.

## 5. Around the pipeline (5 min)
16. `security/*database*`, `trusted_domains`, `detection_data`: the data files.
17. `storage/history_manager.*`, `security/graph_builder.*`, `ui/interface.*`, `main.cpp`.

## Data flow of one scan
```
 "https://paypa1-secure-login.example.xyz"
        |  UrlParser            -> host, labels, registered domain, TLD
        |  DomainAnalyzer       -> threat lookup (hash) | TLD set | look-alike (Levenshtein, Rabin-Karp, KMP)
        |  UrlAnalyzer          -> length, %xx, redirect params | keywords (Trie)
        v  list of Indicators   (each: id, plain-language reason, points)
        |  RiskEngine           -> de-duplicate (set) | sort | keyword cap | sum | level
        v  AnalysisResult       -> UI prints reasons + recommendation
        |  HistoryManager       -> redacted record (sort / filter / heap ranking)
        '  GraphBuilder         -> scan -> link -> website -> keyword / trusted site (BFS / DFS)
```

## Where to look when something goes wrong
| Symptom | Look at |
|---|---|
| A real site is flagged | `domain_analyzer.cpp` (allowed edits, token rules) and `data/trusted_domains.txt` |
| A scam scores LOW | `data/suspicious_phrases.txt`, `suspicious_keywords.txt`, weights in `risk_config.txt` |
| Score too high / too low overall | `risk_config.txt` (weights and thresholds), `risk_engine.cpp` (cap) |
| Program cannot find data | `detection_data.cpp::findDataDirectory`, or run with `--data <folder>` |
| A test fails after your change | the test name tells you the module; each test file has a header explaining its scope |
