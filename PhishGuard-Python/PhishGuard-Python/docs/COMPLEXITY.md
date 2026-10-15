# Data structures and algorithm complexity

| Component | Expected or worst-case time | Space | How PhishGuard uses it |
|---|---|---|---|
| Separate-chaining hash table | Average insert/find/remove O(1); worst O(n); rehash O(n) | O(n + buckets) | Config keys, trusted domains, threat database, sets, graph label index |
| Custom set | Average membership/insert O(1) | O(n) | TLD lists and de-duplication |
| Trie | Insert/find/prefix O(L); text scan worst O(N·Lmax) | O(total keyword characters) | Whole-word detection and prefix menu |
| Binary max-heap | Top O(1); push/pop O(log n); heapify O(n) | O(n) | Top-risk history rows and batch ranking |
| Adjacency-list graph | BFS/DFS O(V+E) | O(V+E) | Connect scans, URLs, domains, and keywords |
| Levenshtein DP | O(mn) time and O(mn) table space; two-row version O(min(m,n)) space | O(mn) or O(min) | Compare likely impersonation domains |
| KMP | O(N+M) | O(M) | Search phrase patterns and embedded brand strings |
| Rabin–Karp | Average near O(N+M); worst O(NM) if many hash collisions | O(1) extra beyond output | Search a trusted domain hidden inside another host |
| Stable merge sort | O(n log n) | O(n) | Rank indicators and history entries |
| Quicksort | Average O(n log n), worst O(n²) | O(log n) average stack | DSA demonstration and benchmark support |
| Binary search | O(log n) comparisons on sorted data | O(1) | DSA demonstration and benchmarks |

`N` is text length, `M` is pattern/keyword length, `L` is the searched key length, and `V`/`E` are graph vertices/edges. Python object overhead differs from C++; benchmark timings and memory must be measured independently on the target machine.
