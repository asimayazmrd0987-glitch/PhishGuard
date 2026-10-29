"""Stable text and JSON rendering for scan results and history.

The interactive UI and the command-line interface share this module so a
score, indicator and recommendation are never rendered two different ways.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Iterable, Optional

from .storage import HistoryStats, ScanRecord
from .text_utils import redact_sensitive, redact_url
from .types import AnalysisResult

WIDTH = 68
FOOTER = (
    'PhishGuard is an educational tool. A LOW result is not a guarantee of safety, '
    'and a high result is not proof of a scam.'
)


def clip_text(text: str, size: int) -> str:
    """Shorten ``text`` for a terminal table without losing the ending marker."""
    if size <= 0:
        return ''
    return text if len(text) <= size else text[: max(0, size - 3)] + '...'


def _redacted_input(result: AnalysisResult) -> str:
    return redact_url(result.input) if result.type.value == 'URL' else redact_sensitive(result.input)


def analysis_result_to_dict(
    result: AnalysisResult,
    *,
    redact: bool = False,
    include_findings: bool = True,
) -> dict[str, Any]:
    """Convert an :class:`AnalysisResult` into a JSON-safe dictionary."""
    data: dict[str, Any] = {
        'type': result.type.value,
        'input': _redacted_input(result) if redact else result.input,
        'score': result.score,
        'level': result.level.name,
        'recommendation': result.recommendation,
        'indicators': [
            {
                'id': indicator.id,
                'description': indicator.description,
                'weight': indicator.weight,
                'category': indicator.category.value,
                'detail': indicator.detail,
            }
            for indicator in result.indicators
        ],
    }
    if include_findings:
        findings = result.findings
        data['findings'] = {
            'urls': [redact_url(url) if redact else url for url in findings.urls],
            'domains': [domain for domain in findings.domains if domain],
            'ips': list(findings.ips),
            'keywords': list(findings.keywords),
            'threat_domains': list(findings.threat_domains),
            'impersonation': asdict(findings.impersonation) if findings.impersonation else None,
        }
    return data


def analysis_result_to_json(
    result: AnalysisResult,
    *,
    redact: bool = False,
    indent: int = 2,
) -> str:
    return json.dumps(
        analysis_result_to_dict(result, redact=redact),
        indent=indent,
        ensure_ascii=False,
        sort_keys=True,
    )


def format_analysis_result(result: AnalysisResult, *, footer: bool = True) -> str:
    """Render the concise one-shot report used by the original CLI."""
    lines = [
        f'Risk Score : {result.score} / 100',
        f'Risk Level : {result.level.name}',
    ]
    if result.indicators:
        lines.append('')
        lines.append('Why this score:')
        lines.extend(
            f' [+{indicator.weight}] {indicator.description}'
            for indicator in result.indicators
        )
    else:
        lines.append('')
        lines.append('No suspicious signs were found by our checks.')
    lines.append('')
    lines.append('Recommendation:')
    lines.append(result.recommendation)
    if footer:
        lines.append('')
        lines.append(FOOTER)
    return '\n'.join(lines)


def scan_record_to_dict(record: ScanRecord) -> dict[str, Any]:
    return {
        'id': record.id,
        'timestamp': record.timestamp,
        'type': record.type.value,
        'input': record.input,
        'score': record.score,
        'level': record.level.name,
        'indicator_ids': list(record.indicator_ids),
    }


def history_stats_to_dict(stats: HistoryStats) -> dict[str, Any]:
    names = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    return {
        'total': stats.total,
        'per_level': dict(zip(names, stats.per_level)),
        'average_score': round(stats.average_score, 2),
        'top_indicators': [
            {'id': indicator_id, 'count': count}
            for indicator_id, count in stats.top_indicators
        ],
    }


def format_record_table(records: Iterable[ScanRecord], *, input_width: int = 40) -> str:
    rows = list(records)
    if not rows:
        return '(no records)'
    lines = [
        f"{'ID':<5}{'Time':<21}{'Type':<9}{'Score':<7}{'Level':<10}Input"
    ]
    for record in rows:
        lines.append(
            f'{record.id:<5}{record.timestamp:<21}{record.type.value:<9}'
            f'{record.score:<7}{record.level.name:<10}'
            f'{clip_text(record.input, input_width)}'
        )
    return '\n'.join(lines)


def format_record(record: ScanRecord) -> str:
    lines = [
        f'Scan #{record.id}  {record.timestamp}  {record.type.value}',
        f'Score: {record.score} ({record.level.name})',
        'Input (sensitive parts hidden): ' + record.input,
        'Indicators:' + (' none' if not record.indicator_ids else ''),
    ]
    lines.extend('  - ' + indicator_id for indicator_id in record.indicator_ids)
    return '\n'.join(lines)


def format_history_stats(stats: HistoryStats, top_records: Optional[Iterable[ScanRecord]] = None) -> str:
    lines = ['-' * WIDTH, 'STATISTICS'.center(WIDTH), '-' * WIDTH]
    lines.append(f'Total scans: {stats.total}')
    for level, count in zip(('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), stats.per_level):
        lines.append(f' {level:<9}{count:<5}{"#" * min(count, 40)}')
    lines.append(f'Average risk score: {stats.average_score:.1f}')
    if stats.top_indicators:
        lines.append('Most common indicators:')
        lines.extend(f'  {count} x {indicator_id}' for indicator_id, count in stats.top_indicators)
    top = list(top_records or [])
    if top:
        lines.append('Highest-risk scans (max-heap):')
        lines.append(format_record_table(top))
    return '\n'.join(lines)


__all__ = [
    'WIDTH',
    'FOOTER',
    'clip_text',
    'analysis_result_to_dict',
    'analysis_result_to_json',
    'format_analysis_result',
    'scan_record_to_dict',
    'history_stats_to_dict',
    'format_record_table',
    'format_record',
    'format_history_stats',
]
