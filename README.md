# PhishGuard

![CI](https://github.com/<your-username>/<your-repo>/actions/workflows/ci.yml/badge.svg)
<!-- replace <your-username>/<your-repo> with your GitHub path so the badge works -->

A data-structure-based phishing, scam-message and malicious-URL **risk analyzer** for non-technical users.
Written in C++17. It gives a heuristic **Risk Score (0-100)**, explains every point of the score in plain
language, and never claims a link is "safe" or "malicious".

Everything runs on our own code: hash table, trie, max-heap, adjacency-list graph (BFS/DFS), custom set,
Levenshtein (DP), KMP, Rabin-Karp, merge sort, quick sort, binary search. No ML, no external APIs, no network access.
(STL is used only for `std::vector`, `std::string`, `std::unique_ptr`, `std::optional` and I/O streams.)

## Build, test, run
    cmake -S . -B build
    cmake --build build
    ./build/phishguard_tests                 # 57 tests (or: ctest --test-dir build)
    ./build/phishguard                       # interactive menu
    ./build/phishguard --demo                # 14 demo scenarios
    ./build/phishguard --bench               # benchmarks
    ./build/phishguard --url "https://paypa1.com/signin"
    ./build/phishguard --message "Your account is suspended. Verify now"
Sanitizers (Linux/WSL): `cmake -S . -B build -DPG_SANITIZE=ON`
Run from the project folder, or pass `--data <folder>`.

## Layout
    include/phishguard/   headers (templates are header-only: hash_table, heap, custom_set, sorting)
      ds/ algorithms/ analyzers/ security/ storage/ ui/ benchmark/ common/
    src/                  implementations (mirrors include/), main.cpp
    data/                 trusted_domains, sample_threats (synthetic .test only), keywords, phrases, tlds, risk_config
    tests/                dependency-free test harness + 57 tests
    docs/                 REPORT, COMPLEXITY, VIVA, PRESENTATION, DEMOS, BENCHMARKS, CODE_TOUR, ROADMAP
    .github/workflows/    ci.yml (build+test on 3 OS, sanitizers), release.yml (downloadable builds on tags)

## Safety
Defensive tool. Only text is analyzed: it never opens a link, resolves DNS or contacts any server.
All sample threats use the reserved `.test` TLD or documentation IP ranges. History never stores passwords,
PINs, OTPs, long digit runs or URL query strings.

## Reading the code
Every file starts with a header explaining WHAT it does, HOW it works and WHY. `docs/CODE_TOUR.md` gives a
reading order; `docs/ROADMAP.md` lists what is needed to turn this into a tool for real users.

## Releases
`git tag v1.0.0 && git push origin v1.0.0` makes GitHub build and attach downloads for Windows, Linux and macOS.
