"""Command-line interface for PhishGuard.

Legacy invocations remain supported::

    python main.py
    python main.py --url "https://paypa1.com/signin"
    python main.py --message "Your account is suspended"
    python main.py --demo
    python main.py --bench

The same actions are also available as subcommands, with JSON output and
automation-friendly exit codes::

    phishguard scan "https://paypa1.com/signin" --json
    phishguard batch samples.txt --fail-on high
    phishguard history stats
    phishguard data validate --strict
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

from . import __version__
from .batch import BatchResult, format_batch_result, scan_lines
from .constants import DATA_ENV_VAR, DEFAULT_HISTORY_FILE, HISTORY_ENV_VAR, LOG_LEVEL_ENV_VAR
from .demos import run_scenarios
from .detection_data import DetectionData
from .engine import ScanService
from .errors import PhishGuardError, UsageError
from .files import atomic_write_text, read_text_file
from .logging_setup import configure_logging, get_logger
from .reporting import (
    analysis_result_to_json,
    format_analysis_result,
    format_history_stats,
    format_record_table,
    history_stats_to_dict,
    scan_record_to_dict,
)
from .storage import HistoryManager, SortKey
from .text_utils import trim
from .types import AnalysisResult, InputType, RiskLevel, input_type_from_string

_log = get_logger('cli')

EXIT_OK = 0
EXIT_RISK = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

_COMMANDS = {'scan', 'batch', 'demo', 'bench', 'history', 'data', 'version'}
_LEVELS = {
    'low': RiskLevel.LOW,
    'medium': RiskLevel.MEDIUM,
    'high': RiskLevel.HIGH,
    'critical': RiskLevel.CRITICAL,
}
_LEVEL_CHOICES = tuple(_LEVELS)
_INPUT_CHOICES = ('auto', 'url', 'message', 'email')
_SORT_CHOICES = {
    'newest': SortKey.NEWEST,
    'oldest': SortKey.OLDEST,
    'score-high': SortKey.SCORE_HIGH,
    'score-low': SortKey.SCORE_LOW,
    'level': SortKey.LEVEL,
}

_VALUE_OPTIONS = {
    '--data', '--history', '--log-level', '--url', '--message', '--email',
    '--batch', '--type', '--fail-on',
}
_VALUE_PREFIXES = (
    '--data=', '--history=', '--log-level=', '--url=', '--message=',
    '--email=', '--batch=', '--type=', '--fail-on=',
)


def _detect_command(arguments: Sequence[str]) -> Optional[str]:
    """Return the subcommand even when global options come before it.

    Both ``phishguard --data data scan ...`` and ``phishguard scan ... --data data``
    must work.  The legacy interface has no positional arguments, so the first
    non-option token can safely be inspected for a command name.
    """
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == '--':
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument in _VALUE_OPTIONS:
            index += 2
            continue
        if argument.startswith(_VALUE_PREFIXES):
            index += 1
            continue
        if argument.startswith('-'):
            index += 1
            continue
        return argument if argument in _COMMANDS else None
    return None


class _ParserExit(Exception):
    """Internal control flow for ``--help``, ``--version`` and usage errors."""

    def __init__(self, status: int, message: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises instead of calling ``sys.exit``."""

    def exit(self, status: int = 0, message: Optional[str] = None) -> None:
        raise _ParserExit(status, message)

    def error(self, message: str) -> None:
        raise _ParserExit(EXIT_USAGE, f'{self.format_usage()}{self.prog}: error: {message}\n')


def _common_parent() -> argparse.ArgumentParser:
    """Options accepted both before and after a subcommand."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument('--data', default=argparse.SUPPRESS, metavar='DIR',
                        help=f'data folder (default: auto-detect or ${DATA_ENV_VAR})')
    parent.add_argument('--history', default=argparse.SUPPRESS, metavar='FILE',
                        help=f'history file (default: {DEFAULT_HISTORY_FILE} or ${HISTORY_ENV_VAR})')
    parent.add_argument('--log-level', default=argparse.SUPPRESS, type=str.upper,
                        choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
                        help=f'logging threshold (default: ${LOG_LEVEL_ENV_VAR} or WARNING)')
    parent.add_argument('-v', '--verbose', action='store_true', default=argparse.SUPPRESS,
                        help='enable debug logging')
    parent.add_argument('-q', '--quiet', action='store_true', default=argparse.SUPPRESS,
                        help='only show errors')
    parent.add_argument('--debug', action='store_true', default=argparse.SUPPRESS,
                        help='show tracebacks for unexpected failures')
    return parent


def _add_one_shot_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    parser.add_argument('--redact', action='store_true',
                        help='redact input in JSON output (recommended for logs)')
    parser.add_argument('--no-history', action='store_true',
                        help='do not append this scan to the history file')
    parser.add_argument('--fail-on', choices=_LEVEL_CHOICES, metavar='LEVEL',
                        help='exit with status 1 when the result reaches LEVEL')


def _build_parser() -> argparse.ArgumentParser:
    common = _common_parent()
    parser = _ArgumentParser(
        prog='phishguard',
        description='Local, explainable phishing and scam-message risk analysis.',
        epilog=(
            'Legacy flags (--url, --message, --demo, --bench) remain supported. '
            'No network access is performed.'
        ),
        parents=[common],
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    subparsers = parser.add_subparsers(dest='command', metavar='COMMAND')

    scan = subparsers.add_parser(
        'scan', parents=[common], help='scan one URL, message or email',
        description='Scan one URL, message or email. Reads stdin when no input is supplied.',
    )
    scan.add_argument('input', nargs='?', help='URL, message or email text')
    scan.add_argument('--type', choices=_INPUT_CHOICES, default='auto',
                      help='input type (default: auto-detect URL vs. message)')
    scan.add_argument('--file', metavar='FILE', help='read the whole input from a file')
    scan.add_argument('--stdin', action='store_true', help='read the whole input from stdin')
    _add_one_shot_options(scan)

    batch = subparsers.add_parser(
        'batch', parents=[common], help='scan one input per line from a file',
        description='Scan one input per line. Blank lines and # comments are skipped.',
    )
    batch.add_argument('file', nargs='?', help='text file with one input per line')
    batch.add_argument('--stdin', action='store_true', help='read inputs from stdin')
    batch.add_argument('--type', choices=_INPUT_CHOICES, default='auto',
                       help='force all lines to URL/message/email, or auto-detect')
    batch.add_argument('--limit', type=int, metavar='N', help='scan at most N valid lines')
    _add_one_shot_options(batch)

    demo = subparsers.add_parser(
        'demo', parents=[common], help='run the 14 deterministic demo scenarios',
        description='Run the deterministic demo scenarios and compare risk bands.',
    )
    demo.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    demo.add_argument('--strict', action='store_true',
                      help='exit with status 1 if any scenario is outside its expected band')

    bench = subparsers.add_parser(
        'bench', parents=[common], help='run the DSA benchmarks',
        description='Run lightweight, non-security DSA demonstrations.',
    )
    bench.add_argument('--quick', action='store_true', help='use smaller input sizes')

    history = subparsers.add_parser(
        'history', parents=[common], help='inspect or manage saved scan history',
        description='Inspect or manage the local history file.',
    )
    history_sub = history.add_subparsers(dest='history_command', metavar='ACTION')
    history_list = history_sub.add_parser('list', parents=[common], help='list saved scans')
    history_list.add_argument('--sort', choices=tuple(_SORT_CHOICES), default='newest')
    history_list.add_argument('--limit', type=int, metavar='N')
    history_list.add_argument('--min-level', choices=_LEVEL_CHOICES)
    history_list.add_argument('--type', choices=('url', 'message', 'email'))
    history_list.add_argument('--contains', default='', metavar='TEXT')
    history_list.add_argument('--json', action='store_true')
    history_stats = history_sub.add_parser('stats', parents=[common], help='show history statistics')
    history_stats.add_argument('--json', action='store_true')
    history_clear = history_sub.add_parser('clear', parents=[common], help='delete all history')
    history_clear.add_argument('--yes', action='store_true', help='confirm non-interactively')
    history_export = history_sub.add_parser('export', parents=[common], help='export history as JSON')
    history_export.add_argument('--output', metavar='FILE', help='write to FILE instead of stdout')

    data = subparsers.add_parser(
        'data', parents=[common], help='inspect or validate detection data',
        description='Validate the local configuration and data files.',
    )
    data_sub = data.add_subparsers(dest='data_command', metavar='ACTION')
    data_validate = data_sub.add_parser('validate', parents=[common],
                                        help='validate every data file and configuration key')
    data_validate.add_argument('--strict', action='store_true',
                               help='reject unknown configuration keys')
    data_validate.add_argument('--json', action='store_true')
    data_path = data_sub.add_parser('path', parents=[common], help='print the resolved data directory')
    data_path.add_argument('--json', action='store_true')

    subparsers.add_parser('version', parents=[common], help='print the version')
    return parser


def _build_legacy_parser() -> argparse.ArgumentParser:
    common = _common_parent()
    parser = _ArgumentParser(
        prog='phishguard',
        description='Local, explainable phishing and scam-message risk analysis.',
        epilog='With no arguments, the interactive terminal menu starts.',
        parents=[common],
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--url', help='scan one URL')
    source.add_argument('--message', help='scan one message')
    source.add_argument('--email', help='scan one email body')
    source.add_argument('--batch', metavar='FILE', help='scan one input per line from FILE')
    source.add_argument('--stdin', dest='stdin_source', action='store_true',
                        help='scan one input read from stdin')
    source.add_argument('--demo', action='store_true', help='run 14 demo scenarios')
    source.add_argument('--bench', action='store_true', help='run DSA benchmarks')
    parser.add_argument('--type', choices=_INPUT_CHOICES, default='auto',
                        help='input type for --stdin/--batch (default: auto)')
    _add_one_shot_options(parser)
    parser.add_argument('--quick', action='store_true', help='use smaller benchmark sizes')
    parser.add_argument('--strict', action='store_true',
                        help='fail when a demo scenario leaves its expected band')
    return parser


def _resolve_log_level(args: argparse.Namespace) -> str:
    if getattr(args, 'debug', False) or getattr(args, 'verbose', False):
        return 'DEBUG'
    if getattr(args, 'quiet', False):
        return 'ERROR'
    return getattr(args, 'log_level', None) or os.environ.get(LOG_LEVEL_ENV_VAR) or 'WARNING'


def _history_path(args: argparse.Namespace) -> str:
    return getattr(args, 'history', None) or os.environ.get(HISTORY_ENV_VAR) or DEFAULT_HISTORY_FILE


def _input_type(args: argparse.Namespace) -> Optional[InputType]:
    value = getattr(args, 'type', 'auto')
    if value == 'auto':
        return None
    return {
        'url': InputType.URL,
        'message': InputType.MESSAGE,
        'email': InputType.EMAIL,
    }[value]


def _level(value: Optional[str]) -> Optional[RiskLevel]:
    return _LEVELS[value] if value else None


def _risk_code(result: AnalysisResult, fail_on: Optional[str]) -> int:
    threshold = _level(fail_on)
    return EXIT_RISK if threshold is not None and result.level >= threshold else EXIT_OK


def _batch_risk_code(batch: BatchResult, fail_on: Optional[str]) -> int:
    threshold = _level(fail_on)
    max_item = batch.max_item
    return EXIT_RISK if threshold is not None and max_item and max_item.result.level >= threshold else EXIT_OK


def _load_data(args: argparse.Namespace, *, strict_config: bool = False) -> DetectionData:
    hint = getattr(args, 'data', None) or ''
    directory = DetectionData.resolve_data_directory(hint)
    _log.debug('loading data from %s', directory)
    return DetectionData.load_from_directory(directory, strict_config=strict_config)


def _emit_result(result: AnalysisResult, args: argparse.Namespace) -> None:
    if getattr(args, 'json', False):
        print(analysis_result_to_json(result, redact=getattr(args, 'redact', False)))
    else:
        print(format_analysis_result(result))


def _record_result(result: AnalysisResult, args: argparse.Namespace) -> None:
    if getattr(args, 'no_history', False):
        return
    path = _history_path(args)
    history = HistoryManager.load(path)
    scan_id = history.add(result)
    history.save(path)
    _log.debug('recorded scan #%d in %s', scan_id, path)


def _record_batch(batch: BatchResult, args: argparse.Namespace) -> None:
    if getattr(args, 'no_history', False) or not batch.items:
        return
    path = _history_path(args)
    history = HistoryManager.load(path)
    ids = [history.add(item.result) for item in batch.items]
    history.save(path)
    _log.debug('recorded %d scan(s) in %s', len(ids), path)


def _run_single(args: argparse.Namespace, text: str, input_type: Optional[InputType]) -> int:
    data = _load_data(args)
    service = ScanService(data)
    if input_type == InputType.URL:
        result = service.scan_url(text)
    elif input_type == InputType.EMAIL:
        result = service.scan_email(text)
    elif input_type == InputType.MESSAGE:
        result = service.scan_message(text)
    else:
        result = service.scan_auto(trim(text))
    _emit_result(result, args)
    _record_result(result, args)
    return _risk_code(result, getattr(args, 'fail_on', None))


def _read_batch_lines(args: argparse.Namespace, filename: Optional[str]) -> list[str]:
    if filename:
        return read_text_file(filename).splitlines()
    if getattr(args, 'stdin', False):
        return sys.stdin.read().splitlines()
    raise UsageError('pass a file or --stdin to batch scan')


def _run_batch(args: argparse.Namespace, filename: Optional[str]) -> int:
    lines = _read_batch_lines(args, filename)
    data = _load_data(args)
    service = ScanService(data)
    batch = scan_lines(
        service,
        lines,
        input_type=_input_type(args),
        max_items=getattr(args, 'limit', None),
    )
    for line_number, message in batch.errors:
        _log.warning('line %d rejected: %s', line_number, message)
    _record_batch(batch, args)
    if getattr(args, 'json', False):
        print(json.dumps(batch.to_dict(redact=getattr(args, 'redact', False)),
                         indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(format_batch_result(batch))
    if batch.errors and not batch.items:
        return EXIT_USAGE
    return _batch_risk_code(batch, getattr(args, 'fail_on', None))


def _run_demo(args: argparse.Namespace) -> int:
    data = _load_data(args)
    outcomes = run_scenarios(ScanService(data))
    matched = sum(outcome.matched for outcome in outcomes)
    if getattr(args, 'json', False):
        payload = {
            'scenarios': [outcome.to_dict() for outcome in outcomes],
            'passed': matched,
            'total': len(outcomes),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print('PhishGuard demo scenarios')
        for outcome in outcomes:
            scenario = outcome.scenario
            print('\n' + '-' * 68)
            print(scenario.title)
            print(f'Input     : {scenario.input}')
            print(f'Algorithms: {scenario.algorithms}')
            print(f'Note      : {scenario.note}')
            for indicator in outcome.result.indicators:
                print(f'  [ +{indicator.weight} ] {indicator.id}')
            print(
                f'Risk Score: {outcome.result.score} / 100   Level: {outcome.result.level.name}'
                f'   (expected {outcome.expected_label}: '
                f'{"OK" if outcome.matched else "DIFFERENT"})'
            )
            print('Recommendation: ' + outcome.result.recommendation)
        print(f'\n{matched} of {len(outcomes)} demo scenarios landed in their expected level range.')
    if getattr(args, 'strict', False) and matched != len(outcomes):
        return EXIT_RISK
    return EXIT_OK


def _run_bench(args: argparse.Namespace) -> int:
    from .benchmark import run_benchmarks

    sizes = (100, 1000) if getattr(args, 'quick', False) else (100, 1000, 10000)
    run_benchmarks(sizes=sizes)
    return EXIT_OK


def _run_interactive(args: argparse.Namespace) -> int:
    if getattr(args, 'json', False):
        raise UsageError('--json requires --url, --message, --email, --batch or --stdin')
    if getattr(args, 'fail_on', None):
        raise UsageError('--fail-on requires a non-interactive scan')
    if getattr(args, 'no_history', False):
        raise UsageError('--no-history is only available for non-interactive scans')
    if getattr(args, 'redact', False):
        raise UsageError('--redact is only available with --json scans')
    data = _load_data(args)
    from .ui import Interface  # imported lazily so one-shot scans stay lightweight

    return Interface(data, _history_path(args)).run()


def _scan_input(args: argparse.Namespace) -> str:
    positional = getattr(args, 'input', None)
    filename = getattr(args, 'file', None)
    use_stdin = getattr(args, 'stdin', False)
    sources = sum(source is not None for source in (positional, filename)) + int(use_stdin)
    if sources > 1:
        raise UsageError('choose only one input source: positional text, --file or --stdin')
    if filename:
        return read_text_file(filename)
    if use_stdin:
        return sys.stdin.read()
    if positional is not None:
        return positional
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise UsageError('no input supplied; pass text, --file or --stdin')


def _run_history(args: argparse.Namespace) -> int:
    command = getattr(args, 'history_command', None)
    if not command:
        raise UsageError('choose a history action: list, stats, clear or export')
    path = _history_path(args)
    history = HistoryManager.load(path)

    if command == 'list':
        wanted = {
            record.id
            for record in history.filter(
                min_level=_level(getattr(args, 'min_level', None)),
                kind=input_type_from_string(getattr(args, 'type', '') or ''),
                contains=getattr(args, 'contains', ''),
            )
        }
        records = [
            record
            for record in history.sorted(_SORT_CHOICES[getattr(args, 'sort', 'newest')])
            if record.id in wanted
        ]
        limit = getattr(args, 'limit', None)
        if limit is not None:
            if limit < 0:
                raise UsageError('--limit must not be negative')
            records = records[:limit]
        if getattr(args, 'json', False):
            print(json.dumps([scan_record_to_dict(record) for record in records],
                             indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print(format_record_table(records))
        return EXIT_OK

    if command == 'stats':
        stats = history.stats()
        top = history.top_risk(5)
        if getattr(args, 'json', False):
            payload = history_stats_to_dict(stats)
            payload['top_records'] = [scan_record_to_dict(record) for record in top]
            print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print(format_history_stats(stats, top))
        return EXIT_OK

    if command == 'clear':
        if not getattr(args, 'yes', False):
            if not sys.stdin.isatty():
                raise UsageError('pass --yes to clear history non-interactively')
            answer = input(f'Delete all history in {path}? (yes/no): ').strip().lower()
            if answer != 'yes':
                print('History was not changed.')
                return EXIT_OK
        history.clear()
        history.save(path)
        print('History cleared.')
        return EXIT_OK

    if command == 'export':
        payload = {
            'records': [scan_record_to_dict(record) for record in history.sorted(SortKey.OLDEST)],
            'stats': history_stats_to_dict(history.stats()),
        }
        text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
        output = getattr(args, 'output', None)
        if output:
            atomic_write_text(output, text, mode=0o600)
            print(f'Exported {history.size} record(s) to {output}.')
        else:
            print(text, end='')
        return EXIT_OK

    raise UsageError(f'unknown history action: {command}')


def _run_data(args: argparse.Namespace) -> int:
    command = getattr(args, 'data_command', None)
    if not command:
        raise UsageError('choose a data action: validate or path')
    directory = DetectionData.resolve_data_directory(getattr(args, 'data', None) or '')
    if command == 'path':
        if getattr(args, 'json', False):
            print(json.dumps({'data_dir': directory}, indent=2))
        else:
            print(directory)
        return EXIT_OK
    if command != 'validate':
        raise UsageError(f'unknown data action: {command}')

    data = DetectionData.load_from_directory(
        directory, strict_config=getattr(args, 'strict', False)
    )
    summary = data.summary()
    if getattr(args, 'json', False):
        print(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(f'Data directory: {summary.data_dir}')
        print(f'Config keys: {summary.config_keys}')
        print(f'Trusted domains: {summary.trusted}')
        print(f'Threat entries: {summary.threats}')
        print(f'Keywords: {summary.keywords} ({summary.keyword_nodes} trie nodes)')
        print(f'Phrases: {summary.phrases}')
        print(f'Suspicious TLDs: {summary.suspicious_tlds}')
        print(f'URL shorteners: {summary.url_shorteners}')
        print(f'Known TLDs: {summary.known_tlds}')
        print(f'Public suffixes: {summary.public_suffixes}')
        for warning in summary.warnings:
            print(f'Warning: {warning}')
        print('Data files are valid.')
    return EXIT_OK


def _dispatch_command(args: argparse.Namespace) -> int:
    command = args.command
    if command == 'version':
        print(f'phishguard {__version__}')
        return EXIT_OK
    if command == 'bench':
        return _run_bench(args)
    if command == 'demo':
        return _run_demo(args)
    if command == 'scan':
        return _run_single(args, _scan_input(args), _input_type(args))
    if command == 'batch':
        return _run_batch(args, getattr(args, 'file', None))
    if command == 'history':
        return _run_history(args)
    if command == 'data':
        return _run_data(args)
    raise UsageError(f'unknown command: {command}')


def _dispatch_legacy(args: argparse.Namespace) -> int:
    if getattr(args, 'demo', False):
        return _run_demo(args)
    if getattr(args, 'bench', False):
        return _run_bench(args)
    if getattr(args, 'batch', None):
        return _run_batch(args, args.batch)
    if getattr(args, 'stdin_source', False):
        return _run_single(args, sys.stdin.read(), _input_type(args))
    if getattr(args, 'url', None) is not None:
        return _run_single(args, args.url, InputType.URL)
    if getattr(args, 'message', None) is not None:
        return _run_single(args, args.message, InputType.MESSAGE)
    if getattr(args, 'email', None) is not None:
        return _run_single(args, args.email, InputType.EMAIL)
    return _run_interactive(args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return a process exit code."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    args: Optional[argparse.Namespace] = None
    try:
        if _detect_command(arguments):
            args = _build_parser().parse_args(arguments)
            configure_logging(_resolve_log_level(args))
            return _dispatch_command(args)
        args = _build_legacy_parser().parse_args(arguments)
        configure_logging(_resolve_log_level(args))
        return _dispatch_legacy(args)
    except _ParserExit as exc:
        if exc.message:
            stream = sys.stdout if exc.status == 0 else sys.stderr
            stream.write(exc.message)
        return exc.status
    except KeyboardInterrupt:
        print('\nInterrupted.', file=sys.stderr)
        return 130
    except (PhishGuardError, ValueError, KeyError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        if args is not None and getattr(args, 'debug', False):
            raise
        return EXIT_USAGE
    except (OSError, UnicodeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        if args is not None and getattr(args, 'debug', False):
            raise
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - defensive boundary
        _log.exception('unexpected failure')
        print(f'Error: unexpected failure: {exc}', file=sys.stderr)
        if args is not None and getattr(args, 'debug', False):
            raise
        return EXIT_INTERNAL


__all__ = ['main', 'EXIT_OK', 'EXIT_RISK', 'EXIT_USAGE', 'EXIT_INTERNAL']
