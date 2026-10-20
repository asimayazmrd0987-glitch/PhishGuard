"""Core data structures used by PhishGuard (educational implementations)."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Generic, Iterable, Iterator, Optional, TypeVar

K = TypeVar('K')
V = TypeVar('V')
T = TypeVar('T')


def _next_prime(n: int) -> int:
    n = max(2, n)
    if n > 2 and n % 2 == 0:
        n += 1
    while True:
        if n == 2 or all(n % d for d in range(3, int(n ** .5) + 1, 2)):
            return n
        n += 1 if n == 2 else 2


def _fnv1a(value: Any) -> int:
    """FNV-1a 64-bit hash for string-like keys."""
    data = str(value).encode('utf-8', errors='replace')
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


@dataclass
class _HashNode(Generic[K, V]):
    key: K
    value: V
    next: Optional['_HashNode[K, V]'] = None


class HashTable(Generic[K, V]):
    """Separate-chaining hash table. Average insert/find/remove: O(1)."""
    def __init__(self, initial_buckets: int = 17, max_load_factor: float = .75,
                 hash_func: Callable[[K], int] = _fnv1a):
        self._buckets: list[Optional[_HashNode[K, V]]] = [None] * _next_prime(max(3, initial_buckets))
        self._max_load = max_load_factor
        self._hash = hash_func
        self._size = 0
        self._comparisons = 0

    def _index(self, key: K, count: Optional[int] = None) -> int:
        return self._hash(key) % (count or len(self._buckets))

    def insert(self, key: K, value: V) -> bool:
        node = self._buckets[self._index(key)]
        while node:
            if node.key == key:
                node.value = value
                return False
            node = node.next
        if (self._size + 1) > self._max_load * len(self._buckets):
            self._rehash(_next_prime(len(self._buckets) * 2))
        i = self._index(key)
        self._buckets[i] = _HashNode(key, value, self._buckets[i])
        self._size += 1
        return True

    def find(self, key: K, default: Any = None) -> Any:
        node = self._buckets[self._index(key)]
        while node:
            self._comparisons += 1
            if node.key == key:
                return node.value
            node = node.next
        return default

    def contains(self, key: K) -> bool:
        sentinel = object()
        return self.find(key, sentinel) is not sentinel

    def remove(self, key: K) -> bool:
        i = self._index(key)
        node = self._buckets[i]
        prev = None
        while node:
            self._comparisons += 1
            if node.key == key:
                if prev is None:
                    self._buckets[i] = node.next
                else:
                    prev.next = node.next
                self._size -= 1
                return True
            prev, node = node, node.next
        return False

    def for_each(self) -> Iterator[tuple[K, V]]:
        for head in self._buckets:
            node = head
            while node:
                yield node.key, node.value
                node = node.next

    def clear(self) -> None:
        self._buckets = [None] * len(self._buckets)
        self._size = 0

    def _rehash(self, new_count: int) -> None:
        old = self._buckets
        self._buckets = [None] * new_count
        for head in old:
            node = head
            while node:
                next_node = node.next
                i = self._index(node.key)
                node.next = self._buckets[i]
                self._buckets[i] = node
                node = next_node

    def __len__(self) -> int:
        return self._size

    @property
    def size(self) -> int:
        return self._size

    @property
    def bucket_count(self) -> int:
        return len(self._buckets)

    @property
    def load_factor(self) -> float:
        return self._size / len(self._buckets) if self._buckets else 0.0

    @property
    def max_chain_length(self) -> int:
        best = 0
        for head in self._buckets:
            n = 0
            while head:
                n += 1
                head = head.next
            best = max(best, n)
        return best

    @property
    def collision_count(self) -> int:
        used = sum(head is not None for head in self._buckets)
        return self._size - used

    @property
    def comparisons(self) -> int:
        return self._comparisons

    def reset_comparisons(self) -> None:
        self._comparisons = 0


class CustomSet(Generic[T]):
    """Set-like collection backed by the project's custom hash table."""
    def __init__(self, values: Optional[Iterable[T]] = None):
        self._table: HashTable[T, int] = HashTable()
        if values:
            for value in values:
                self.insert(value)

    def insert(self, value: T) -> bool:
        return self._table.insert(value, 1)

    def contains(self, value: T) -> bool:
        return self._table.contains(value)

    def remove(self, value: T) -> bool:
        return self._table.remove(value)

    def clear(self) -> None:
        self._table.clear()

    def to_list(self) -> list[T]:
        return [k for k, _ in self._table.for_each()]

    def __contains__(self, value: T) -> bool:
        return self.contains(value)

    def __len__(self) -> int:
        return len(self._table)

    def __iter__(self) -> Iterator[T]:
        return iter(self.to_list())


class MaxHeap(Generic[T]):
    """Binary max-heap. `less(a, b)` should be true when a has lower priority than b."""
    def __init__(self, values: Optional[Iterable[T]] = None,
                 less: Optional[Callable[[T, T], bool]] = None):
        self._less = less or (lambda a, b: a < b)
        self._data = list(values or [])
        for i in range(len(self._data) // 2 - 1, -1, -1):
            self._sift_down(i)

    def push(self, value: T) -> None:
        self._data.append(value)
        i = len(self._data) - 1
        while i > 0:
            parent = (i - 1) // 2
            if not self._less(self._data[parent], self._data[i]):
                break
            self._data[parent], self._data[i] = self._data[i], self._data[parent]
            i = parent

    def pop(self) -> T:
        if not self._data:
            raise IndexError('MaxHeap.pop on empty heap')
        result = self._data[0]
        last = self._data.pop()
        if self._data:
            self._data[0] = last
            self._sift_down(0)
        return result

    def top(self) -> T:
        if not self._data:
            raise IndexError('MaxHeap.top on empty heap')
        return self._data[0]

    def _sift_down(self, i: int) -> None:
        size = len(self._data)
        while True:
            left, right = 2 * i + 1, 2 * i + 2
            largest = i
            if left < size and self._less(self._data[largest], self._data[left]):
                largest = left
            if right < size and self._less(self._data[largest], self._data[right]):
                largest = right
            if largest == i:
                return
            self._data[i], self._data[largest] = self._data[largest], self._data[i]
            i = largest

    def empty(self) -> bool:
        return not self._data

    def __len__(self) -> int:
        return len(self._data)


@dataclass
class KeywordInfo:
    category: str = ''
    weight: int = 0

@dataclass
class KeywordMatch:
    word: str
    position: int
    info: KeywordInfo


class _TrieNode:
    __slots__ = ('children', 'end', 'info')
    def __init__(self):
        self.children: dict[str, _TrieNode] = {}
        self.end = False
        self.info = KeywordInfo()


class Trie:
    """ASCII trie for keyword and prefix operations."""
    def __init__(self):
        self._root = _TrieNode()
        self._size = 0
        self._nodes = 1

    @staticmethod
    def _validate(word: str, allow_empty: bool = False) -> str:
        word = word.lower()
        if not word and not allow_empty:
            raise ValueError('keyword must not be empty')
        if any(ord(c) >= 128 for c in word):
            raise ValueError(f'keyword must be ASCII: {word}')
        return word

    def insert(self, word: str, info: Optional[KeywordInfo] = None) -> bool:
        word = self._validate(word)
        node = self._root
        for char in word:
            if char not in node.children:
                node.children[char] = _TrieNode()
                self._nodes += 1
            node = node.children[char]
        if node.end:
            return False
        node.end = True
        node.info = info or KeywordInfo()
        self._size += 1
        return True

    def _walk(self, word: str) -> Optional[_TrieNode]:
        try:
            word = self._validate(word, allow_empty=True)
        except ValueError:
            return None
        node = self._root
        for char in word:
            node = node.children.get(char)
            if node is None:
                return None
        return node

    def find(self, word: str) -> Optional[KeywordInfo]:
        node = self._walk(word)
        return node.info if node is not None and node.end else None

    def contains(self, word: str) -> bool:
        return self.find(word) is not None

    def starts_with(self, prefix: str) -> bool:
        return self._walk(prefix) is not None

    def words_with_prefix(self, prefix: str, limit: int = 100) -> list[str]:
        node = self._walk(prefix)
        if node is None or limit <= 0:
            return []
        words: list[str] = []
        cur = prefix.lower()
        def visit(n: _TrieNode, path: str) -> None:
            if len(words) >= limit:
                return
            if n.end:
                words.append(path)
            for ch in sorted(n.children):
                if len(words) >= limit:
                    return
                visit(n.children[ch], path + ch)
        visit(node, cur)
        return words

    def remove(self, word: str) -> bool:
        word = word.lower()
        if not word:
            return False
        def rec(node: _TrieNode, depth: int) -> tuple[bool, bool]:
            if depth == len(word):
                if not node.end:
                    return False, False
                node.end = False
                node.info = KeywordInfo()
                self._size -= 1
                return True, not node.children
            ch = word[depth]
            child = node.children.get(ch)
            if child is None:
                return False, False
            removed, prune = rec(child, depth + 1)
            if prune:
                del node.children[ch]
                self._nodes -= 1
            return removed, (not node.end and not node.children)
        removed, _ = rec(self._root, 0)
        return removed

    def scan_text(self, text: str) -> list[KeywordMatch]:
        matches: list[KeywordMatch] = []
        n = len(text)
        for start in range(n):
            if start > 0 and text[start - 1].isalnum():
                continue
            node = self._root
            j = start
            found_end: Optional[int] = None
            found_info: Optional[KeywordInfo] = None
            while j < n:
                ch = text[j].lower()
                if ord(ch) >= 128:
                    break
                node = node.children.get(ch)
                if node is None:
                    break
                j += 1
                if node.end and (j == n or not text[j].isalnum()):
                    found_end = j
                    found_info = node.info
            if found_end is not None and found_info is not None:
                matches.append(KeywordMatch(text[start:found_end].lower(), start, found_info))
        return matches

    @property
    def size(self) -> int:
        return self._size

    @property
    def node_count(self) -> int:
        return self._nodes


class NodeType:
    MESSAGE = 'MESSAGE'
    URL = 'URL'
    DOMAIN = 'DOMAIN'
    IP = 'IP'
    KEYWORD = 'KEYWORD'
    TRUSTED_DOMAIN = 'TRUSTED DOMAIN'
    SUSPICIOUS_DOMAIN = 'SUSPICIOUS DOMAIN'

@dataclass
class GraphNode:
    label: str
    type: str

@dataclass
class Visit:
    node: int
    depth: int

class Graph:
    """Undirected graph represented as adjacency lists."""
    def __init__(self):
        self._index: HashTable[str, int] = HashTable()
        self._nodes: list[GraphNode] = []
        self._adj: list[list[tuple[int, str]]] = []
        self._edge_count = 0

    def add_node(self, label: str, node_type: str) -> int:
        existing = self._index.find(label, None)
        if existing is not None:
            return existing
        idx = len(self._nodes)
        self._nodes.append(GraphNode(label, node_type))
        self._adj.append([])
        self._index.insert(label, idx)
        return idx

    def index_of(self, label: str) -> int:
        value = self._index.find(label, None)
        return -1 if value is None else value

    def add_edge(self, a: int | str, b: int | str, relation: str = '') -> bool:
        if isinstance(a, str):
            a = self.index_of(a)
        if isinstance(b, str):
            b = self.index_of(b)
        if a < 0 or b < 0 or a >= len(self._nodes) or b >= len(self._nodes) or a == b:
            return False
        if any(to == b for to, _ in self._adj[a]):
            return False
        self._adj[a].append((b, relation))
        self._adj[b].append((a, relation))
        self._edge_count += 1
        return True

    def neighbors(self, index: int) -> list[int]:
        self._check(index)
        return [to for to, _ in self._adj[index]]

    def relation_between(self, a: int, b: int) -> str:
        self._check(a); self._check(b)
        for to, relation in self._adj[a]:
            if to == b:
                return relation
        return ''

    def _check(self, index: int) -> None:
        if index < 0 or index >= len(self._nodes):
            raise IndexError('graph node index out of range')

    def node(self, index: int) -> GraphNode:
        self._check(index)
        return self._nodes[index]

    def bfs(self, start: int, max_depth: int = -1) -> list[Visit]:
        if start < 0 or start >= len(self._nodes):
            return []
        out = [Visit(start, 0)]
        seen = {start}
        q = deque([(start, 0)])
        while q:
            node, depth = q.popleft()
            if max_depth >= 0 and depth >= max_depth:
                continue
            for to, _ in self._adj[node]:
                if to in seen:
                    continue
                seen.add(to)
                out.append(Visit(to, depth + 1))
                q.append((to, depth + 1))
        return out

    def dfs(self, start: int) -> list[Visit]:
        if start < 0 or start >= len(self._nodes):
            return []
        out: list[Visit] = []
        seen: set[int] = set()
        stack = [(start, 0)]
        while stack:
            node, depth = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            out.append(Visit(node, depth))
            for to, _ in reversed(self._adj[node]):
                if to not in seen:
                    stack.append((to, depth + 1))
        return out

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return self._edge_count
