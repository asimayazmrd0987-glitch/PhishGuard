# PhishGuard Requirements (Phase 1)

## Functional
FR1 Scan URL / message / email text. FR2 Extract URLs from text (no regex).
FR3 Parse URL parts. FR4 Trie keyword + prefix detection. FR5 Levenshtein look-alike
detection. FR6 Threat DB (insert/delete/update/search, category, risk level).
FR7 Configurable explainable Risk Score. FR8 Max-heap ranking. FR9 Indicator graph
with BFS/DFS. FR10 Scan history (view/sort/filter/remove/inspect, no passwords).
FR11 8-option menu, statistics, benchmarks.

## Non-functional
Explainable (every point maps to an indicator). Honest wording (never "safe" /
"malicious"). Synthetic data only. C++17, CMake, no global mutable state, clean
under -Wall -Wextra -Wpedantic. Windows + Linux. Weights/thresholds in data files.

## Layering
UI -> analyzers -> risk engine -> algorithms / data structures. Lower layers never
include upper ones.

## Personas
Parent (45), Student (19), Elder (68): plain language, clear next step.
