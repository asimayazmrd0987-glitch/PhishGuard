"""Lightweight, deterministic DSA demonstrations; measured timings vary by computer."""
from __future__ import annotations
import random, time
from .algorithms import merge_sort, binary_search, naive_search, kmp_search, rabin_karp_search
from .ds import HashTable, Trie, MaxHeap
from .types import RiskLevel


def run_benchmarks(out=print, sizes=(100, 1000, 10000)) -> None:
    out('PhishGuard benchmarks (synthetic data, single run; times vary by machine)')
    out('\n=== A. Domain lookup: linear vs binary search vs custom hash table ===')
    for n in sizes:
        rng = random.Random(12345)
        domains = [f'd{rng.randrange(2_000_000_000):x}x{i}.test' for i in range(n)]
        queries = [domains[(q * 7919) % n] if q % 2 == 0 else f'absent-{q}.test' for q in range(200)]
        for name, op in (
            ('linear', lambda q: next((d for d in domains if d == q), None)),
            ('binary', None),
            ('hash', None)):
            started = time.perf_counter()
            comparisons = 0
            if name == 'linear':
                hits = 0
                for q in queries:
                    for d in domains:
                        comparisons += 1
                        if d == q: hits += 1; break
            elif name == 'binary':
                sorted_domains = sorted(domains)
                hits = 0
                for q in queries:
                    lo, hi = 0, len(sorted_domains)
                    while lo < hi:
                        mid = (lo + hi) // 2; comparisons += 1
                        if sorted_domains[mid] < q: lo = mid + 1
                        elif q < sorted_domains[mid]: hi = mid
                        else: hits += 1; break
            else:
                table = HashTable[str, int]()
                for i, domain in enumerate(domains): table.insert(domain, i)
                table.reset_comparisons()
                hits = sum(table.contains(q) for q in queries)
                comparisons = table.comparisons
            ms = (time.perf_counter() - started) * 1000
            out(f'{n:>7} domains | {name:<6} | {ms:>9.2f} ms | {comparisons / len(queries):>10.1f} avg comparisons | hits={hits}')
    out('\n=== B. Keyword lookup: list vs Trie ===')
    rng = random.Random(777)
    words = [''.join(rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(rng.randint(4, 10))) for _ in range(1500)]
    trie = Trie()
    for word in words: trie.insert(word)
    lookups = [words[(i * 31) % len(words)] if i % 2 == 0 else 'absentwordq' for i in range(3000)]
    for name, func in [('list', lambda q: q in words), ('trie', trie.contains)]:
        t0 = time.perf_counter(); hits = sum(func(q) for q in lookups); elapsed = (time.perf_counter() - t0) * 1000
        out(f'{name:<6} | {elapsed:>8.2f} ms | hits={hits}')
    out(f'Trie nodes: {trie.node_count}')
    out('\n=== C. Substring search: Naive, KMP and Rabin-Karp ===')
    random.seed(99)
    text = ''.join(random.choice('abcd') for _ in range(50000))
    pattern = text[35000:35008]
    for name, func in [('Naive', naive_search), ('KMP', kmp_search), ('Rabin-Karp', rabin_karp_search)]:
        counter = [0]; t0 = time.perf_counter(); matches = func(text, pattern, counter); elapsed = (time.perf_counter() - t0) * 1000
        out(f'{name:<11} | {elapsed:>8.2f} ms | comparisons={counter[0]} | matches={len(matches)}')
    out('\n=== D. Top-risk ranking: heap vs full sort ===')
    rng = random.Random(4242)
    items = [(rng.randrange(101), i) for i in range(20000)]
    heap_less = lambda a, b: a < b
    t0 = time.perf_counter(); heap = MaxHeap(items, heap_less); top = [heap.pop() for _ in range(10)]; heap_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter(); sorted_top = sorted(items, reverse=True)[:10]; sort_ms = (time.perf_counter() - t0) * 1000
    out(f'Heap (heapify + 10 pops): {heap_ms:.2f} ms, highest scores={ [x[0] for x in top[:5]] }')
    out(f'Full sort:               {sort_ms:.2f} ms, highest scores={ [x[0] for x in sorted_top[:5]] }')
    out('\nMemory figures are omitted in the Python port; timings are illustrative, not a security metric.')
