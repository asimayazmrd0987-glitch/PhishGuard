"""Persistent scan history with privacy redaction, sorting, filtering and summaries."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .algorithms import merge_sort
from .ds import HashTable, MaxHeap
from .errors import HistoryError
from .files import atomic_write_text, read_text_file
from .logging_setup import get_logger
from .text_utils import current_timestamp, redact_sensitive, redact_url, split, to_lower
from .types import AnalysisResult, InputType, RiskLevel, input_type_from_string, risk_level_from_string

_log = get_logger('storage')

_HISTORY_HEADER = (
    '# PhishGuard scan history (v2)\n'
    '# Format: id|timestamp|type|score|level|indicator_ids|input\n'
    '# Sensitive parts are redacted before writing. Keep this file private.\n'
)


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


SORT_KEYS = {
    SortKey.NEWEST,
    SortKey.OLDEST,
    SortKey.SCORE_HIGH,
    SortKey.SCORE_LOW,
    SortKey.LEVEL,
}


@dataclass
class HistoryStats:
    total: int = 0
    per_level: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    average_score: float = 0.0
    top_indicators: list[tuple[str, int]] = field(default_factory=list)


def _clean_field(value: str) -> str:
    """Keep one history record on one pipe-delimited line."""
    return (
        value.replace('|', ' ')
        .replace('\n', ' ')
        .replace('\r', ' ')
        .replace('\x00', '')
    )


class HistoryManager:
    def __init__(self) -> None:
        self._records: list[ScanRecord] = []
        self._next_id = 1

    def add(self, result: AnalysisResult) -> int:
        if result.type == InputType.URL:
            input_copy = redact_url(result.input)
        else:
            input_copy = redact_sensitive(result.input)
        input_copy = _clean_field(input_copy)
        record = ScanRecord(
            self._next_id,
            current_timestamp(),
            result.type,
            input_copy,
            result.score,
            result.level,
            [indicator.id for indicator in result.indicators],
        )
        self._records.append(record)
        self._next_id += 1
        return record.id

    def remove(self, record_id: int) -> bool:
        for index, record in enumerate(self._records):
            if record.id == record_id:
                del self._records[index]
                return True
        return False

    def find(self, record_id: int) -> Optional[ScanRecord]:
        return next((record for record in self._records if record.id == record_id), None)

    def clear(self) -> None:
        self._records.clear()

    @property
    def size(self) -> int:
        return len(self._records)

    @property
    def records(self) -> list[ScanRecord]:
        return list(self._records)

    def sorted(self, key: str = SortKey.NEWEST) -> list[ScanRecord]:
        if key not in SORT_KEYS:
            raise KeyError(f'unknown sort key: {key}')
        out = list(self._records)
        keys = {
            SortKey.NEWEST: lambda record: -record.id,
            SortKey.OLDEST: lambda record: record.id,
            SortKey.SCORE_HIGH: lambda record: -record.score,
            SortKey.SCORE_LOW: lambda record: record.score,
            SortKey.LEVEL: lambda record: -int(record.level),
        }
        merge_sort(out, lambda a, b: keys[key](a) < keys[key](b))
        return out

    def filter(
        self,
        min_level: Optional[RiskLevel] = None,
        kind: Optional[InputType] = None,
        contains: str = '',
    ) -> list[ScanRecord]:
        needle = to_lower(contains)
        return [
            record
            for record in self._records
            if (min_level is None or int(record.level) >= int(min_level))
            and (kind is None or record.type == kind)
            and (not needle or needle in to_lower(record.input))
        ]

    def top_risk(self, k: int) -> list[ScanRecord]:
        if k <= 0:
            return []
        less = lambda a, b: (a.score < b.score) if a.score != b.score else (a.id > b.id)
        heap = MaxHeap(self._records, less)
        out = []
        while not heap.empty() and len(out) < k:
            out.append(heap.pop())
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
        lines = [_HISTORY_HEADER]
        for record in self._records:
            lines.append(
                f'{record.id}|{record.timestamp}|{record.type.value}|{record.score}|'
                f'{record.level.name}|{",".join(record.indicator_ids)}|{record.input}\n'
            )
        try:
            atomic_write_text(path, ''.join(lines), mode=0o600)
        except OSError as exc:
            raise HistoryError(f'cannot write history file: {path}') from exc

    @classmethod
    def load(cls, path: str | Path) -> 'HistoryManager':
        manager = cls()
        try:
            lines = read_text_file(path).splitlines()
        except FileNotFoundError:
            return manager
        except (OSError, UnicodeError) as exc:
            _log.warning('could not read history %s: %s', path, exc)
            return manager
        skipped = 0
        for line in lines:
            if not line or line.startswith('#'):
                continue
            parts = split(line, '|')
            if len(parts) < 7:
                skipped += 1
                continue
            try:
                record_id, score = int(parts[0]), int(parts[3])
            except ValueError:
                skipped += 1
                continue
            kind, level = input_type_from_string(parts[2]), risk_level_from_string(parts[4])
            if kind is None or level is None:
                skipped += 1
                continue
            ids = split(parts[5], ',') if parts[5] else []
            record = ScanRecord(record_id, parts[1], kind, '|'.join(parts[6:]), score, level, ids)
            manager._records.append(record)
            manager._next_id = max(manager._next_id, record_id + 1)
        if skipped:
            _log.warning('ignored %d malformed history line(s) in %s', skipped, path)
        return manager


__all__ = ['ScanRecord', 'SortKey', 'SORT_KEYS', 'HistoryStats', 'HistoryManager']
