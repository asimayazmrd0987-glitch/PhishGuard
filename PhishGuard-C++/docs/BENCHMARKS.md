# Benchmarks and what they really show

Source: `./build/phishguard --bench` (raw output in `BENCHMARK_OUTPUT.txt`). Single run on a shared sandbox
machine with synthetic deterministic data, so absolute times are only indicative. Comparison counts are exact.
Memory is a sizeof-based estimate.

## A. Lookup (1000 queries, half hits / half misses)
| domains | linear (avg compares / ms) | binary (avg compares / ms) | hash (avg key compares / ms) |
|---:|---|---|---|
| 100 | 75.0 / 0.191 | 5.8 / 0.031 | 1.0 / 0.033 |
| 1,000 | 750.0 / 0.950 | 9.0 / 0.074 | 1.0 / 0.038 |
| 10,000 | 7,481 / 7.852 | 12.7 / 0.153 | 0.8 / 0.076 |
| 100,000 | 74,891 / 147.162 | 15.8 / 0.516 | 0.9 / 0.578 |

* Linear grows proportionally to n (as O(n) predicts). Binary grows like log n. Hash stays near 1 comparison.
* **Honest observation:** at 100,000 entries the hash table was *not* faster in wall-clock time than binary search
  (0.578 ms vs 0.516 ms for 1000 queries). Hashing a string costs work, and chained nodes are scattered in memory
  (cache misses), while binary search touches ~17 strings. Hashing wins clearly on *comparison count*, needs no sorting,
  and supports O(1) insert/delete, whereas binary search needs a sorted array (O(n) insert). Both beat linear search massively.
* Hash tables used more memory (estimated 7.9 MB vs 5.0 MB at 100k) for the buckets and node pointers.
* Hash quality at 100k: load 0.57, longest chain 6, so FNV-1a with prime table sizes spreads keys well.

## B. Trie vs array (5,000 keywords, 20,000 lookups)
Array: 170 ms and 3,750 word comparisons per lookup on average. Trie: 5.8 ms, at most one step per character.
Cost: 24,829 nodes (each has a 128-slot child array), so the trie trades memory for speed.

## C. Substring search (200,000 characters)
| case | naive | KMP | Rabin-Karp |
|---|---:|---:|---:|
| random text, pattern 8 | 267,147 | 250,212 | 200,033 |
| worst case a^n vs a^400 b | 80,039,600 | 399,600 | 199,600 |

On ordinary text all three are similar (naive is already near-linear and very fast in practice). KMP and Rabin-Karp
matter in adversarial/repetitive input, where naive does 200x more work. Rabin-Karp's count mixes hash and character comparisons.

## D. Ranking the top 10 of 100,000 scans
| method | time | comparisons |
|---|---:|---:|
| linear scan x10 | 1.212 ms | 999,955 |
| max-heap (heapify + 10 pops) | 1.088 ms | 187,960 |
| full merge sort | 8.463 ms | 1,532,427 |

The heap needs about 5x fewer comparisons than ten linear scans, but at k = 10 the wall-clock times are close
(simple linear loops are cache-friendly). The heap's real advantage appears when k grows or when items arrive
continuously (a live alert queue): each push/pop is O(log n) with no re-sorting. A full sort is the slowest when only the top few are needed.
