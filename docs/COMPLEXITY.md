# Complexity Analysis (n, m = sizes noted in the table)

| Component | Algorithm / structure | Time | Space | Notes |
|---|---|---|---|---|
| Threat / trusted / config lookup | Hash table, separate chaining | avg O(1); worst O(n) | O(n + buckets) | worst case = all keys in one chain (tested with a constant hash) |
| Hash insert with growth | rehash at load > 0.75, size -> next prime >= 2x | O(n) per rehash, amortised O(1) per insert | O(n) | |
| Set (dedupe indicators, TLD list) | Hash table of keys | avg O(1) | O(n) | |
| Keyword lookup | Trie | O(L) per word | O(total chars x 128 pointers) | L = word length; 128-slot arrays trade memory for speed |
| Keyword scan of text of length n | Trie from each word start | O(n x Lmax) worst | O(matches) | |
| Phrase search | KMP (per phrase) | O(n + m) | O(m) | |
| Domain hidden in host | Rabin-Karp | avg O(n + m); worst O(n x m) | O(1) | hash collisions force verification |
| Naive search (baseline) | brute force | O(n x m) worst | O(1) | |
| Edit distance | DP, full table | O(m x n) | O(m x n) | `editDistanceTable`, used for teaching |
| Edit distance | DP, two rows | O(m x n) | O(min(m, n)) | same answer, tested equal |
| Impersonation check, one URL | Levenshtein vs each trusted entry and token | O(T x (tokens + 1) x m x n) | O(m x n) | T = #trusted domains |
| Priority queue push / pop | binary max-heap | O(log n) | O(n) | |
| Heap build from array | Floyd heapify | O(n) | O(n) | |
| Top-k ranking | heapify + k pops | O(n + k log n) | O(n) | vs O(k x n) repeated scan |
| Graph add node / edge | adjacency list + hash index | avg O(1) / O(deg) (duplicate check) | O(V + E) | |
| BFS, DFS | queue / explicit stack | O(V + E) | O(V) | |
| History sort | merge sort (stable) | O(n log n) | O(n) | |
| Quick sort (educational) | median-of-3 + insertion sort | avg O(n log n); worst O(n^2) | O(log n) stack | recursion on smaller half |
| Binary search | on sorted vector | O(log n) | O(1) | |
| Trusted host check | walk up domain labels | O(labels) hash lookups | O(1) | |
| Risk evaluation | dedupe (set) + merge sort | O(k log k) | O(k) | k = #indicators |
| URL parsing | single pass | O(len) | O(len) | |

Verification: each row follows from the code in `include/phishguard/ds`, `algorithms`, and the experiments in
`docs/BENCHMARK_OUTPUT.txt` (for example KMP: 399,600 comparisons on a 200,000-char worst case vs naive 80,039,600).
