# Viva Preparation: 36 questions with answers
(Numbers quoted come from this project's own benchmark run. Be ready to say they vary by machine.)

## A. Data structures
1. **Why a hash table for the threat database?** We look up a domain for every scan; a hash table gives average O(1) versus O(n) for scanning a list. In our benchmark at 100,000 domains: ~0.9 key comparisons vs ~74,891 for linear search.
2. **How does collision resolution work?** Separate chaining: each bucket is a linked list. A colliding key is added to the chain; lookup walks the chain comparing keys. Test `hash_collisions_are_handled_by_chaining` forces all 50 keys into one bucket and still finds/removes every one.
3. **Why is lookup approximately O(1)?** The hash picks the bucket directly; with load factor <= 0.75 and a good hash the expected chain length is a small constant. It degrades to O(n) only if all keys collide.
4. **What is the load factor and what do you do about it?** size / buckets. When inserting would exceed 0.75 we rehash into the next prime >= 2x buckets (O(n) occasionally, amortised O(1) per insert).
5. **Why prime table sizes and FNV-1a?** Prime sizes reduce clustering from patterned hashes; FNV-1a (xor byte, multiply by a large prime) is simple and mixes well. At 100k keys the longest chain was 6.
6. **Separate chaining vs open addressing?** Chaining: simple deletion, tolerates high load. Open addressing: better cache locality but needs tombstones and degrades quickly near full. We chose chaining for clarity and safe deletion.
7. **Why a Trie for keywords?** Lookup costs O(L) regardless of how many keywords exist, supports prefix queries (menu option 11), and lets us scan text without checking every keyword. Benchmark: 5.8 ms vs 170 ms for an array of 5,000 words.
8. **What is the trie's downside?** Memory: our nodes hold 128 child pointers (24,829 nodes in the benchmark). A map-based or compressed (radix) trie would save memory.
9. **How does trie deletion work?** Recursively unmark the word's end; on the way back up, delete child nodes that have no children and do not end another word. So deleting "banker" keeps "bank".
10. **Why a heap?** To always get the highest-risk item first. Push/pop are O(log n); building from n items is O(n). For a live alert queue it avoids re-sorting after every arrival.
11. **Heap vs sorting for ranking?** For the top 10 of 100,000: heap 187,960 comparisons, repeated linear scans 999,955, full sort 1,532,427. (Wall-clock times for k=10 were similar, which I report honestly.)
12. **Why a graph and why an adjacency list?** Relationships message-link-website-keyword-trusted site are sparse. Adjacency list is O(V+E) space; a matrix is O(V^2) and wastes space and neighbour-scan time.
13. **BFS vs DFS, and where did you use them?** BFS finds the nearest related indicators and their hop distance (used to show "related items" after a scan). DFS follows a whole chain (used in the explore tool). Both O(V+E). DFS is iterative to avoid deep recursion.
14. **Why a custom set?** To de-duplicate indicators so the same reason is never counted twice, and for fast membership tests (TLD list). It is a hash table storing keys only.
15. **Why implement structures yourself instead of using the STL?** The assignment is about understanding them; we still use `vector`, `string` and smart pointers as building blocks.

## B. Algorithms
16. **Why dynamic programming for edit distance?** Sub-problems overlap: the distance of two prefixes reuses smaller prefix distances. Filling a table avoids exponential recursion.
17. **Complexity of Levenshtein?** O(m x n) time; O(m x n) space for the full table, O(min(m,n)) with two rows. We implemented both and test they agree.
18. **Why not just compare the whole host?** `paypa1-secure-login.example.xyz` is far from `paypal.com` as a whole string. We split into tokens, fold look-alike characters (1->l), compare each token to brands and registered domain to trusted domains.
19. **Why distance thresholds by length?** For short names (<=4 chars) one edit changes the word entirely, so we require exact; <=8 chars allow 1 edit; longer allow 2. This reduces false positives.
20. **KMP vs Rabin-Karp vs naive?** Naive O(nm) worst case. KMP O(n+m) guaranteed using the prefix table; never moves back in the text. Rabin-Karp O(n+m) average using a rolling hash, worst case O(nm) with many collisions; good for multi-pattern or 2-D search. Benchmark: worst case 80,039,600 (naive) vs 399,600 (KMP) vs 199,600 (RK) comparisons; on random text all three were similar.
21. **Why does Rabin-Karp verify after a hash match?** Different strings can share a hash (collision), so we compare characters to avoid false matches.
22. **Where do you use KMP and Rabin-Karp?** KMP: scam phrases in messages and brand names inside tokens. Rabin-Karp: a whole trusted domain hidden inside a host (`paypal.com.evil.example`).
23. **Why a stable sort for history?** Merge sort keeps records with equal scores in their original order. O(n log n) always, O(n) extra space.
24. **Quick sort worst case and how do you avoid it?** O(n^2) on bad pivots. We use median-of-three, insertion sort for small ranges, and recurse on the smaller half (O(log n) stack). Tested on sorted, reversed and all-equal input.
25. **Binary search precondition?** The array must be sorted; O(log n) (about 16 comparisons for 100,000 items).

## C. Cybersecurity
26. **What is phishing?** A social-engineering attack that imitates a trusted party to steal credentials, codes or money.
27. **What is typosquatting?** Registering a name that is a small typo or look-alike of a trusted one (`micr0soft.com`) hoping users do not notice.
28. **What is social engineering?** Manipulating people (urgency, fear, rewards) rather than breaking systems; our urgency/prize/credential phrase categories target that.
29. **Why can phishing detection produce false positives?** Legitimate messages can contain the same words (a real bank alert) and legitimate domains can resemble each other. Demo 12 shows a real-looking alert scoring MEDIUM.
30. **And false negatives?** Scams with no keywords, new tactics, other languages, or compromised legitimate sites evade heuristics. Demo 14 scores 0 although it is a known scam pattern.
31. **Why is domain similarity useful but not sufficient?** It catches impersonation of known brands, but two unrelated legitimate sites can be similar, and many attacks use completely different names. So we label it "possible impersonation" and combine it with other signals.
32. **Why do trusted domains skip keyword checks?** `accounts.google.com/login` contains "account" and "login" legitimately; counting them would be a false positive. Limitation: a hijacked subdomain of a trusted domain would also be trusted.
33. **Why a "Risk Score" and not a probability?** The weights are expert-chosen, not statistically trained and calibrated on labelled data, so calling it a probability would be dishonest.

## D. Software engineering
34. **Why C++ and why CMake?** C++ gives direct control over memory layout and algorithms (good for DSA) and is fast; CMake builds on Windows/Linux/macOS and handles the library/app/tests structure.
35. **Why modular architecture, and how did you test it?** Layers (UI, services, analyzers, algorithms) can be tested independently; the core is a library linked by app and tests. 57 tests, random cross-checks against naive/`std::sort`, forced hash collisions, scripted UI sessions, ASan+UBSan clean.
36. **What are the limitations and how would you scale it?** Limitations: see report ch. 14. Scaling: load a real threat feed (millions of domains fit a hash table; a Bloom filter could cut memory), a compressed trie, a full Public Suffix List, run the service behind an API or browser extension, and calibrate weights with labelled data.

## Likely "show me" requests
* Trace `editDistance("paypa1","paypal")` on paper (answer 1: one substitution).
* Insert 5 keys into a table with 5 buckets and show a collision and a chain.
* Delete "bank" and "banker" from the trie in both orders.
* Run KMP's prefix table for `abcabd` -> `0 0 0 1 2 0`.
* Run BFS on a 5-node graph and explain the queue.
