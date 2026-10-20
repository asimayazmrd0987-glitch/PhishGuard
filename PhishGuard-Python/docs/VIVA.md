# Viva / oral-exam preparation

**What does PhishGuard do?** It locally analyzes link and message text for heuristic phishing/scam signs and explains which indicators contribute to a 0–100 risk score.

**Why use a hash table?** Trusted domains, threat entries and configuration values need frequent key lookups. Separate chaining handles collisions; average lookup is O(1), though worst-case lookup is O(n).

**Why a trie?** Watched keywords can be scanned as whole words and searched by prefix. Lookup depends primarily on key length rather than the total number of stored keywords.

**Why KMP?** KMP reuses information from the already-matched prefix after a mismatch. For a text of length N and pattern of length M its time complexity is O(N+M).

**Why Rabin–Karp?** It quickly compares rolling hashes for substrings. Equal hashes are verified character-by-character because hash collisions are possible.

**What is Levenshtein distance?** The minimum number of insertions, deletions and substitutions needed to change one string into another. A small distance can be a clue that one domain imitates another, but it does not prove malicious intent.

**Why a heap?** A max-heap returns high-priority entries without sorting the entire collection for every retrieval. Heapify is O(n), and each pop is O(log n).

**Why a graph?** Scans may share domains, URLs and keywords. A graph makes those relationships visible; BFS finds nearby items by hop depth and DFS follows a connected chain.

**How is the risk score calculated?** Detectors emit weighted indicators; the engine de-duplicates stable indicator IDs, sorts by weight, caps the keyword contribution, sums positive weights, clamps the score to 100 and maps it to LOW/MEDIUM/HIGH/CRITICAL.

**Is the score the probability that a link is a scam?** No. It is a heuristic, not a calibrated probability.

**Does the program open or ping the URL?** No. It only parses and analyzes strings; there are no network requests.

**How is history protected?** Before writing history, it redacts URL user-info/query strings, secret values after certain terms and long digit sequences. Users should still avoid putting real secrets into test input.

**Can it have false positives/negatives?** Yes. A legitimate urgent bank message can look suspicious, and a polite social-engineering scam may not contain any watched clue. The demo set intentionally includes both cases.

**What is the role of the configuration file?** It centralizes weights, caps, limits and score thresholds so they can be reviewed without editing code.
