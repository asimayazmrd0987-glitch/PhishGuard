"""Persistent scan history with privacy redaction, sorting, filtering and summaries."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from .algorithms import merge_sort
from .ds import HashTable, MaxHeap
from .text_utils import current_timestamp, redact_sensitive, redact_url, split, to_lower
from .types import AnalysisResult, InputType, RiskLevel, input_type_from_string, risk_level_from_string

@dataclass
class ScanRecord:
    id: int = 0
    timestamp: str = ''
    type: InputType = InputType.URL
    input: str = ''
    score: int = 0
    level: RiskLevel = RiskLevel.LOW
    indicator_ids: list[str] = field(default_factory=list)

class SortKey:
    NEWEST = 'newest'
    OLDEST = 'oldest'
    SCORE_HIGH = 'score_high'
    SCORE_LOW = 'score_low'
    LEVEL = 'level'

@dataclass
class HistoryStats:
    total: int = 0
    per_level: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    average_score: float = 0.0
    top_indicators: list[tuple[str, int]] = field(default_factory=list)

class HistoryManager:
    def __init__(self):
        self._records: list[ScanRecord] = []
        self._next_id = 1

    def add(self, result: AnalysisResult) -> int:
        if result.type == InputType.URL:
            input_copy = redact_url(result.input)
        else:
            input_copy = redact_sensitive(result.input)
        input_copy = input_copy.replace('|', ' ').replace('\n', ' ').replace('\r', ' ')
        record = ScanRecord(self._next_id, current_timestamp(), result.type, input_copy,
                            result.score, result.level, [i.id for i in result.indicators])
        self._records.append(record)
        self._next_id += 1
        return record.id

    def remove(self, record_id: int) -> bool:
        for i, record in enumerate(self._records):
            if record.id == record_id:
                del self._records[i]
                return True
        return False

    def find(self, record_id: int) -> Optional[ScanRecord]:
        return next((r for r in self._records if r.id == record_id), None)

    def clear(self) -> None: self._records.clear()
    @property
    def size(self) -> int: return len(self._records)
    @property
    def records(self) -> list[ScanRecord]: return list(self._records)

    def sorted(self, key: str = SortKey.NEWEST) -> list[ScanRecord]:
        out = list(self._records)
        keys = {
            SortKey.NEWEST: lambda r: -r.id,
            SortKey.OLDEST: lambda r: r.id,
            SortKey.SCORE_HIGH: lambda r: -r.score,
            SortKey.SCORE_LOW: lambda r: r.score,
            SortKey.LEVEL: lambda r: -int(r.level),
        }
        merge_sort(out, lambda a, b: keys[key](a) < keys[key](b))
        return out

    def filter(self, min_level: Optional[RiskLevel] = None, kind: Optional[InputType] = None, contains: str = '') -> list[ScanRecord]:
        needle = to_lower(contains)
        return [r for r in self._records if
                (min_level is None or int(r.level) >= int(min_level)) and
                (kind is None or r.type == kind) and
                (not needle or needle in to_lower(r.input))]

    def top_risk(self, k: int) -> list[ScanRecord]:
        less = lambda a, b: (a.score < b.score) if a.score != b.score else (a.id > b.id)
        heap = MaxHeap(self._records, less)
        out = []
        while not heap.empty() and len(out) < k: out.append(heap.pop())
        return out

    def stats(self) -> HistoryStats:
        stats = HistoryStats(total=len(self._records))
        counts: HashTable[str, int] = HashTable()
        total_score = 0
        for record in self._records:
            stats.per_level[int(record.level)] += 1
            total_score += record.score
            for indicator_id in record.indicator_ids:
                current = counts.find(indicator_id, None)
                counts.insert(indicator_id, (current + 1) if current is not None else 1)
        stats.average_score = total_score / stats.total if stats.total else 0.0
        stats.top_indicators = list(counts.for_each())
        merge_sort(stats.top_indicators, lambda a, b: (-a[1], a[0]) < (-b[1], b[0]))
        stats.top_indicators = stats.top_indicators[:5]
        return stats

    def save(self, path: str | Path) -> None:
        try:
            with open(path, 'w', encoding='utf-8') as output:
                for r in self._records:
                    output.write(f'{r.id}|{r.timestamp}|{r.type.value}|{r.score}|{r.level.name}|{",".join(r.indicator_ids)}|{r.input}\n')
        except OSError as exc:
            raise RuntimeError(f'cannot write history file: {path}') from exc

    @classmethod
    def load(cls, path: str | Path) -> 'HistoryManager':
        manager = cls()
        try: lines = Path(path).read_text(encoding='utf-8').splitlines()
        except OSError: return manager
        for line in lines:
            parts = split(line, '|')
            if len(parts) < 7: continue
            try:
                record_id, score = int(parts[0]), int(parts[3])
            except ValueError: continue
            kind, level = input_type_from_string(parts[2]), risk_level_from_string(parts[4])
            if kind is None or level is None: continue
            ids = split(parts[5], ',') if parts[5] else []
            record = ScanRecord(record_id, parts[1], kind, '|'.join(parts[6:]), score, level, ids)
            manager._records.append(record)
            manager._next_id = max(manager._next_id, record_id + 1)
        return manager
