"""Shared batch scanning used by the terminal UI and the CLI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .engine import ScanService
from .logging_setup import get_logger
from .reporting import analysis_result_to_dict, clip_text
from .types import AnalysisResult, InputType
from .text_utils import trim

_log = get_logger('batch')


def looks_like_url(line: str) -> bool:
    """Match the interactive UI's deliberately simple URL/message heuristic."""
    return bool(line) and ' ' not in line and ('://' in line or '.' in line)


@dataclass(frozen=True)
class BatchItem:
    line_number: int
    input: str
    result: AnalysisResult


@dataclass
class BatchResult:
    items: list[BatchItem] = field(default_factory=list)
    skipped: int = 0
    errors: list[tuple[int, str]] = field(default_factory=list)
    limit_reached: bool = False

    def ranked_items(self) -> list[BatchItem]:
        """Highest score first; stable for equal scores by original line order."""
        return sorted(self.items, key=lambda item: (-item.result.score, item.line_number))

    @property
    def max_item(self) -> Optional[BatchItem]:
        return max(self.items, key=lambda item: item.result.score) if self.items else None

    def to_dict(self, *, redact: bool = False) -> dict:
        max_item = self.max_item
        items = []
        for item in self.ranked_items():
            rendered = analysis_result_to_dict(item.result, redact=redact)
            items.append({'line': item.line_number, 'input': rendered['input'], 'result': rendered})
        return {
            'items': items,
            'scanned': len(self.items),
            'skipped': self.skipped,
            'errors': [{'line': line, 'message': message} for line, message in self.errors],
            'max_score': max_item.result.score if max_item else 0,
            'max_level': max_item.result.level.name if max_item else None,
            'limit_reached': self.limit_reached,
        }


def scan_lines(
    service: ScanService,
    lines: Iterable[str],
    *,
    input_type: Optional[InputType] = None,
    max_items: Optional[int] = None,
) -> BatchResult:
    """Scan one input per line.

    ``input_type=None`` selects URL vs. message with :func:`looks_like_url`.
    Blank lines and ``#`` comments are skipped.  Invalid items are recorded in
    ``errors`` rather than aborting the whole batch.
    """
    if max_items is not None and max_items < 1:
        raise ValueError('max_items must be positive')

    result = BatchResult()
    for line_number, raw in enumerate(lines, 1):
        line = trim(raw)
        if not line or line.startswith('#'):
            result.skipped += 1
            continue
        if max_items is not None and len(result.items) >= max_items:
            result.limit_reached = True
            break
        try:
            if input_type == InputType.URL or (input_type is None and looks_like_url(line)):
                analysis = service.scan_url(line)
            elif input_type == InputType.EMAIL:
                analysis = service.scan_message(line, InputType.EMAIL)
            else:
                analysis = service.scan_message(line, InputType.MESSAGE)
        except (ValueError, KeyError) as exc:
            _log.debug('line %d rejected: %s', line_number, exc)
            result.errors.append((line_number, str(exc)))
            continue
        result.items.append(BatchItem(line_number, line, analysis))
    return result


def format_batch_result(batch: BatchResult, *, input_width: int = 60) -> str:
    lines = ['Ranked by risk (priority queue):']
    if not batch.items:
        lines.append('(no scannable lines)')
    for rank, item in enumerate(batch.ranked_items(), 1):
        lines.append(
            f'{rank:>3}. {item.result.level.name:<9}{item.result.score:>3}  '
            f'{clip_text(item.input, input_width)}'
        )
    details = []
    if batch.skipped:
        details.append(f'{batch.skipped} blank/comment line(s) skipped')
    if batch.errors:
        details.append(f'{len(batch.errors)} line(s) rejected')
    if batch.limit_reached:
        details.append('item limit reached')
    if details:
        lines.append('(' + '; '.join(details) + ')')
    return '\n'.join(lines)


__all__ = ['BatchItem', 'BatchResult', 'looks_like_url', 'scan_lines', 'format_batch_result']
