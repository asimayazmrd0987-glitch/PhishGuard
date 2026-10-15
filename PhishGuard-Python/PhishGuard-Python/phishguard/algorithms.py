"""String and sorting/search algorithms used by PhishGuard.

Kept explicit instead of delegating every task to Python built-ins so the DSA
implementations are visible for learning and viva demonstrations.
"""
from __future__ import annotations
from typing import Callable, TypeVar, Optional
T = TypeVar('T')


def edit_distance_table(a: str, b: str) -> list[list[int]]:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1): dp[i][0] = i
    for j in range(n + 1): dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp


def edit_distance(a: str, b: str) -> int:
    return edit_distance_table(a, b)[len(a)][len(b)]


def edit_distance_two_row(a: str, b: str) -> int:
    longer, shorter = (a, b) if len(a) >= len(b) else (b, a)
    prev = list(range(len(shorter) + 1))
    for i, ch1 in enumerate(longer, 1):
        cur = [i] + [0] * len(shorter)
        for j, ch2 in enumerate(shorter, 1):
            cost = 0 if ch1 == ch2 else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    longest = max(len(a), len(b))
    return 1.0 if longest == 0 else 1.0 - edit_distance(a, b) / longest


def similarity_label(score: float) -> str:
    if score >= .85: return 'Very High'
    if score >= .70: return 'High'
    if score >= .50: return 'Moderate'
    return 'Low'


def build_prefix_table(pattern: str) -> list[int]:
    lps = [0] * len(pattern)
    length, i = 0, 1
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        elif length:
            length = lps[length - 1]
        else:
            lps[i] = 0
            i += 1
    return lps


def naive_search(text: str, pattern: str, comparisons: Optional[list[int]] = None) -> list[int]:
    out = []
    if not pattern or len(pattern) > len(text): return out
    def tick():
        if comparisons is not None: comparisons[0] += 1
    for i in range(len(text) - len(pattern) + 1):
        j = 0
        while j < len(pattern):
            tick()
            if text[i + j] != pattern[j]: break
            j += 1
        if j == len(pattern): out.append(i)
    return out


def kmp_search(text: str, pattern: str, comparisons: Optional[list[int]] = None) -> list[int]:
    out = []
    if not pattern or len(pattern) > len(text): return out
    lps = build_prefix_table(pattern)
    i = j = 0
    while i < len(text):
        if comparisons is not None: comparisons[0] += 1
        if text[i] == pattern[j]:
            i += 1; j += 1
            if j == len(pattern):
                out.append(i - j)
                j = lps[j - 1]
        elif j:
            j = lps[j - 1]
        else:
            i += 1
    return out


def rabin_karp_search(text: str, pattern: str, comparisons: Optional[list[int]] = None) -> list[int]:
    n, m = len(text), len(pattern)
    if not m or m > n: return []
    base, mod = 256, 1_000_000_007
    high_pow = pow(base, m - 1, mod)
    ph = th = 0
    for i in range(m):
        ph = (ph * base + ord(pattern[i]) % 256) % mod
        th = (th * base + ord(text[i]) % 256) % mod
    out = []
    for i in range(n - m + 1):
        if comparisons is not None: comparisons[0] += 1
        if ph == th:
            j = 0
            while j < m:
                if comparisons is not None: comparisons[0] += 1
                if text[i + j] != pattern[j]: break
                j += 1
            if j == m: out.append(i)
        if i + m < n:
            th = (th + mod - ((ord(text[i]) % 256) * high_pow) % mod) % mod
            th = (th * base + ord(text[i + m]) % 256) % mod
    return out


def merge_sort(items: list[T], less: Callable[[T, T], bool]) -> list[T]:
    """Stable in-place merge sort; returns the same list for convenience."""
    n = len(items)
    if n <= 1: return items
    mid = n // 2
    left = merge_sort(items[:mid], less)
    right = merge_sort(items[mid:], less)
    i = j = k = 0
    while i < len(left) and j < len(right):
        if less(right[j], left[i]):
            items[k] = right[j]; j += 1
        else:
            items[k] = left[i]; i += 1
        k += 1
    while i < len(left): items[k] = left[i]; i += 1; k += 1
    while j < len(right): items[k] = right[j]; j += 1; k += 1
    return items


def quick_sort(items: list[T], less: Callable[[T, T], bool]) -> list[T]:
    """Quicksort using an iterative Hoare-style partition to avoid deep recursion."""
    if len(items) < 2: return items
    stack = [(0, len(items) - 1)]
    while stack:
        lo, hi = stack.pop()
        if lo >= hi: continue
        pivot = items[(lo + hi) // 2]
        i, j = lo - 1, hi + 1
        while True:
            i += 1
            while less(items[i], pivot): i += 1
            j -= 1
            while less(pivot, items[j]): j -= 1
            if i >= j: break
            items[i], items[j] = items[j], items[i]
        split = j
        if split - lo > hi - (split + 1):
            stack.append((lo, split)); stack.append((split + 1, hi))
        else:
            stack.append((split + 1, hi)); stack.append((lo, split))
    return items


def binary_search(sorted_items: list[T], target: T, less: Callable[[T, T], bool]) -> int:
    lo, hi = 0, len(sorted_items)
    while lo < hi:
        mid = (lo + hi) // 2
        if less(sorted_items[mid], target): lo = mid + 1
        elif less(target, sorted_items[mid]): hi = mid
        else: return mid
    return -1
