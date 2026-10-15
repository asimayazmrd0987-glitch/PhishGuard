# PhishGuard: Presentation (15 slides, ~12 minutes)

1. **Title:** PhishGuard, cybersecurity for everyone. Name, course, supervisor.
2. **Problem:** Phishing links/messages reach everyone daily (SMS, WhatsApp, email); users cannot judge them. Example: `paypa1.com`.
3. **Motivation:** Existing tools say "dangerous" without a reason; we want explainable, offline, honest results. And: a real problem to apply DSA to.
4. **Target users:** Parent (45), student (19), elderly user (68): plain language, one clear next step.
5. **Existing problem:** Blocklists miss new domains; ML is opaque; manual advice needs expertise.
6. **Proposed solution:** Paste link/message -> Risk Score 0-100 + reasons + recommendation. Never "safe" or "malicious".
7. **Architecture:** diagram from Report ch. 6 (UI -> ScanService -> analyzers -> RiskEngine; data structures underneath).
8. **DSA used:** hash table, trie, set, heap, graph + BFS/DFS, KMP, Rabin-Karp, Levenshtein DP, merge/quick sort, binary search, with one line each on *where* they are used.
9. **Detection pipeline:** validate -> extract/parse -> threat lookup -> trie + KMP -> Levenshtein -> risk engine -> explain.
10. **Risk scoring:** weights table, cap, de-duplication, thresholds; "heuristic, not a probability".
11. **Demonstration:** live: `paypa1.com/signin` (42 HIGH), prize scam (90 CRITICAL), `google.com` (0 LOW), polite scam (0 LOW, a miss). Show the graph of related items.
12. **Testing:** 57 tests, random cross-checks vs naive/`std::sort`, forced hash collisions, ASan/UBSan clean, 14 demo scenarios.
13. **Performance:** table of linear vs binary vs hash (74,891 vs 15.8 vs 0.9 comparisons at 100k); KMP 399,600 vs naive 80,039,600 worst case; be upfront that hash was not faster than binary search in wall-clock at 100k.
14. **Limitations:** false positives (urgent real bank alert = MEDIUM), false negatives (text-only scam = LOW), unvalidated weights, no network checks.
15. **Future work and Q&A:** threat feeds, browser extension, mobile app, multilingual, ML as optional extension, Unicode homoglyphs.
