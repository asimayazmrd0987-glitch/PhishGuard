# PhishGuard: A Data-Structure-Based Phishing, Scam Message and Malicious URL Risk Analyzer
Semester project report (Data Structures and Algorithms, C++17)

## Chapter 1. Introduction
Phishing is a form of social engineering: an attacker sends a message or link that imitates a trusted party to
trick the victim into revealing passwords, one-time codes or money. Ordinary users receive such links by SMS,
WhatsApp, email and social media, usually with no easy way to judge them. PhishGuard is an offline tool that
checks a link or message, produces a **Risk Score**, and explains *why*, in plain language. The project's main
aim is to demonstrate data structures and algorithms (DSA) on a real security problem.

## Chapter 2. Problem Statement
Non-technical users (parents, elderly users, students) cannot reliably tell a look-alike link such as `paypa1.com`
from the real site, and scam wording ("act now", "verify your account") is designed to bypass careful thought.
Many tools just say "dangerous" with no reason, need cloud services, or use technical jargon. We need a tool that is
fast, offline, explainable and honest about uncertainty.

## Chapter 3. Objectives (measurable)
1. Analyze URLs, SMS/WhatsApp-style messages and email text through one engine.
2. Implement by hand: hash table, trie, custom set, max-heap, adjacency-list graph with BFS/DFS, Levenshtein DP, KMP, Rabin-Karp, merge/quick sort, binary search.
3. Every score point must map to a named, plain-language indicator (100% of indicators carry a description).
4. Weights, limits and thresholds configurable in a data file (no magic numbers in logic).
5. At least 10 demonstrations and a test suite covering every structure and algorithm (delivered: 14 demos, 57 tests, sanitizer-clean).
6. Experiments comparing linear/binary/hash search, array/trie, naive/KMP/Rabin-Karp, linear scan/heap.
7. Never state a result is guaranteed safe or malicious.

## Chapter 4. Existing Solutions and Limits
* Browser/vendor blocklists: strong for known threats, weak against brand-new domains; need network; give little explanation.
* Spam filters and ML classifiers: powerful but opaque, need training data and can be hard to defend or reproduce.
* Manual advice ("check the URL"): requires knowledge users lack.
PhishGuard is *not* a replacement for these. It is an educational heuristic layer whose reasoning is fully visible.

## Chapter 5. Proposed System
Pipeline: input validation -> URL extraction and parsing -> threat-list lookup -> keyword and phrase analysis ->
look-alike analysis -> risk engine -> explanation and recommendation -> graph/heap/history. Target users and personas:
a parent (45) who gets "bank account blocked" SMS messages, a student (19) tempted by prize links, an elderly user (68) who needs a simple "do not click" message.

## Chapter 6. System Architecture
```
 UI (menu, CLI flags) --> ScanService (facade)
                            |-> UrlAnalyzer -> UrlParser, DomainAnalyzer
                            |-> MessageAnalyzer -> UrlAnalyzer, Trie, KMP
                            '-> RiskEngine (+RiskConfig)
 DetectionData: TrustedDomainStore(hash) ThreatDatabase(hash) Trie CustomSet(TLDs) RiskConfig(hash)
 Session: Graph (adjacency list), HistoryManager (merge sort, max-heap), Benchmark
```
Layering rule: UI -> services -> analyzers -> algorithms/data structures; lower layers never include upper ones.
The core is a library (`phishguard_core`) linked by the app and the tests.

## Chapter 7. Data Structures
| Structure | File | Used for | Why |
|---|---|---|---|
| Hash table (chaining, FNV-1a, prime sizes, rehash at load 0.75) | `ds/hash_table.hpp` | threat DB, trusted domains, config, graph label index, stats counting | average O(1) lookup vs O(n) scan |
| Custom set | `ds/custom_set.hpp` | indicator de-duplication, TLD / shortener lists | membership in O(1) |
| Trie | `ds/trie.cpp` | suspicious keywords, whole-word scanning, prefix search, deletion with pruning | O(L) lookup independent of keyword count; prefix queries |
| Max-heap | `ds/heap.hpp` | ranking batch scans and top-risk history | O(log n) insert/extract, O(n) build |
| Graph (adjacency list) | `ds/graph.cpp` | message-link-website-keyword-trusted-site relationships | sparse data: O(V+E) space instead of O(V^2) |
Collision strategy: separate chaining, because deletion is simple and performance degrades gracefully; open addressing would be
more cache-friendly but needs tombstones. A test forces all keys into one bucket to prove correctness under worst-case collisions.
Alternatives considered: sorted array + binary search (needs O(n) insert), `std::unordered_map` (hides the mechanism we must demonstrate).

## Chapter 8. Algorithms
* **Trie:** insert/search/prefix/remove O(L); `scanText` walks the trie from each word start and accepts a match only at word boundaries ("pin" matches in "your PIN", not in "pinterest").
* **Hashing:** FNV-1a: XOR each byte then multiply by a large prime; table size is prime; load factor bounded by rehashing (new size = next prime >= 2x).
* **KMP:** builds the longest-proper-prefix-that-is-also-suffix table so the text index never moves backward; used for scam phrases and for brand-in-token checks.
* **Rabin-Karp:** rolling polynomial hash (base 256, modulus 1,000,000,007); on equal hash it verifies characters because collisions are possible; used to detect a whole trusted domain hidden inside a host (`paypal.com.evil.example`).
* **Levenshtein:** `dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)`. Two implementations (full table O(mn) space, two-row O(min) space), tested equal on random input. Look-alike folding (0->o, 1->l, 3->e, 4->a, 5->s, 7->t, @->a, $->s) is applied before comparison so `g00gle` is recognised even though its raw distance is 2. Edit distance thresholds depend on length (0 for <=4 characters, 1 for <=8, 2 above) to limit false positives on short words.
* **Heap:** array-based binary max-heap, sift-up / sift-down, Floyd heapify.
* **BFS:** queue (vector + head index), gives nearest related indicators with hop depth. **DFS:** iterative with an explicit stack, follows one chain fully; both O(V+E).
* **Sorting:** stable top-down merge sort (history, indicators, trusted/threat lists); quick sort with median-of-three and insertion sort for small ranges (tested on sorted, reversed and duplicate input); binary search for the benchmark.

## Chapter 9. Risk Scoring
Additive weighted indicators, clamped to 100. It is a heuristic **Risk Score**, not a probability. Weights are in `data/risk_config.txt`.
Main weights: known threat +50, look-alike +30, trusted name hidden in address +25, IP address host +20, credential request +15, financial request +15,
`@` trick +15, urgency/prize/delivery wording +10, suspicious ending +10, many subdomains +10, shortener/redirect +8, keywords +3..+10 (total capped at +25), long URL/host +5.
Rules that keep the score honest: each indicator id counts once (de-duplication); keyword points are capped so keyword stuffing cannot reach 100 alone; trusted domains skip wording heuristics (so `accounts.google.com/login` is LOW).
Levels (configurable): 0-20 LOW, 21-40 MEDIUM, 41-70 HIGH, 71-100 CRITICAL.
The weights were chosen by reasoning about how strong each signal is (a listed domain is much stronger than a long URL); they are **not statistically calibrated**.
Fact-check note: the "suspicious TLD" list (xyz, top, click, icu, tk, ml, ga, cf, gq, work, zip, cfd, support, buzz) is a heuristic list of endings commonly cited as heavily abused;
many legitimate sites use some of them, and the list should be reviewed against a current source before real deployment.

## Chapter 10. Implementation
| Module | Responsibility |
|---|---|
| `UrlParser` | manual parse: scheme, userinfo, host, port, path, query, fragment, IPv4/IPv6, labels, TLD, registered domain (with small multi-part suffix list), URL extraction from text |
| `DomainAnalyzer` | threat lookup, IP, TLD, shortener, subdomains, hyphens, digits, punycode, impersonation (Levenshtein + Rabin-Karp + KMP) |
| `UrlAnalyzer` | scheme, `@` trick, length, `%xx` encoding, redirect-like parameters, keywords (Trie) |
| `MessageAnalyzer` | phrase categories (KMP), keywords (Trie), punctuation, capitals, repeated letters, encoded-looking strings, embedded links |
| `RiskEngine` | de-duplication, caps, sum, level, recommendation |
| `ThreatDatabase`, `TrustedDomainStore` | hash-table CRUD, categories, risk levels, file load/save |
| `HistoryManager` | add/remove/sort/filter/inspect, redaction, statistics, persistence |
| `Interface` | 8-option menu plus extra tools; streams are injected so it is testable |
Engineering: C++17, CMake, header/source separation, RAII (`unique_ptr` nodes, no raw `new`), const correctness, input validation, exceptions for bad input/files, no global mutable state, clean under `-Wall -Wextra -Wpedantic` and AddressSanitizer/UBSan.

## Chapter 11. Testing
57 automated tests (custom dependency-free harness, CTest-compatible): hash collisions (forced single bucket), rehash, trie prefix sharing and deletion, heap with equal priorities, graph cycles and disconnected nodes, Levenshtein known values + random cross-check, KMP/Rabin-Karp vs naive on 300 random cases (including overlapping matches), sort vs `std::sort` and stability, URL parser (valid, no scheme, IP, malformed, long, bad port), URL scenarios (trusted, look-alike, embedded brand, IP, subdomains, TLD, `@`, shortener, punycode, redirect, encoded, long), message scenarios (prize, bank/credential, delivery, urgency, style rules), validation (empty, oversized, control characters), history redaction/sort/filter/persistence, scripted UI sessions, and all 14 demo scenarios. Run under AddressSanitizer + UBSan: no findings.

## Chapter 12. Performance Evaluation
See `BENCHMARKS.md` and `COMPLEXITY.md`. Highlights: at 100,000 domains linear search needed ~74,900 comparisons per lookup versus ~15.8 for binary search and ~0.9 for the hash table; the trie was ~29x faster than a 5,000-word array scan; KMP needed 399,600 comparisons where naive needed 80,039,600 on a repetitive worst case; the heap used ~5x fewer comparisons than repeated linear scans for the top 10 of 100,000. Honest caveats: hash lookup was not faster than binary search in wall-clock time at 100,000 entries, and on ordinary text KMP/Rabin-Karp gave no real speed-up over naive search.

## Chapter 13. Results
All 14 demonstrations landed in their pre-declared level ranges (`DEMOS.md`). Typical scores: trusted URL 0; look-alike `paypa1.com/signin` 42 (HIGH); typosquat `micr0soft.com` 35 (MEDIUM); brand hidden in address 62 (HIGH); prize scam with a listed link 90 (CRITICAL); bank phishing with listed link 100 (CRITICAL); text-only OTP scam 50 (HIGH).
Note: the example in the original spec (`paypa1-secure-login.example.xyz` = 87) is illustrative; our configurable weights give 55 (HIGH) for it, and we report what the scoring model produces.

## Chapter 14. Limitations (including false positives and false negatives)
* **False positive:** a legitimate message can look suspicious. Demo 12 ("URGENT: your bank card payment failed... update your payment details in the official app") scores 25 (MEDIUM) because it contains common scam words. Short brand names, real sites with digits, and look-alike thresholds can also misfire.
* **False negative:** a scam with no keywords or links ("Hi Mum, I dropped my phone... new number") scores 0 (LOW). Attackers can rephrase, use images, other languages, or compromised legitimate sites; a LOW score is not a guarantee.
* Heuristic weights are not statistically validated; the score is not a probability.
* No DNS, WHOIS, certificate, page-content or reputation checks; the threat list is synthetic; no real domain is labelled malicious.
* Look-alike detection covers ASCII digit/symbol swaps and edit distance (no Unicode homoglyph table, no transposition-aware Damerau distance); the multi-part public-suffix list is small.
* Keyword matching is whole-word, so `securelogin` is missed; English only.
* Subdomains of a trusted domain are trusted, so a hijacked subdomain or open redirect on a trusted site would not be caught.
* Trie nodes use 128-slot arrays (fast, memory heavy for very large dictionaries).

## Chapter 15. Future Improvements (not implemented)
Real-time threat intelligence feeds, browser extension, mobile app, multilingual and Unicode-homoglyph support, machine-learning-assisted detection as an optional extension, cloud reputation service, Damerau-Levenshtein, full Public Suffix List, statistically calibrated scoring with labelled data.
