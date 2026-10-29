"""Tests for the 2.0 command-line interface, JSON output and exit codes."""
from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from phishguard import cli
from phishguard.version import __version__

ROOT = Path(__file__).resolve().parents[1]
DATA = str(ROOT / 'data')


def run_cli(*argv: str) -> tuple[int, str, str]:
    """Invoke the CLI in-process and capture its output."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        logger = logging.getLogger('phishguard')
        logger.handlers.clear()
        logger.setLevel(logging.CRITICAL)

    def test_version_and_help(self):
        code, out, _ = run_cli('--version')
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

        code, out, _ = run_cli('version')
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

        code, out, _ = run_cli('--help')
        self.assertEqual(code, 0)
        self.assertIn('scan', out)

    def test_scan_json_and_fail_on_thresholds(self):
        code, out, _ = run_cli(
            'scan', 'https://paypa1.com/signin', '--data', DATA,
            '--json', '--no-history', '--log-level', 'ERROR',
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload['type'], 'URL')
        self.assertEqual(payload['score'], 42)
        self.assertEqual(payload['level'], 'HIGH')
        self.assertIn('lookalike_domain', [i['id'] for i in payload['indicators']])

        # Global options may appear before the subcommand.
        code, out, _ = run_cli(
            '--data', DATA, 'scan', 'https://paypa1.com/signin',
            '--json', '--no-history', '--log-level', 'ERROR',
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['score'], 42)

        code, _, _ = run_cli(
            'scan', 'https://paypa1.com/signin', '--data', DATA,
            '--no-history', '--fail-on', 'high', '--log-level', 'ERROR',
        )
        self.assertEqual(code, cli.EXIT_RISK)

        code, _, _ = run_cli(
            'scan', 'https://paypa1.com/signin', '--data', DATA,
            '--no-history', '--fail-on', 'critical', '--log-level', 'ERROR',
        )
        self.assertEqual(code, cli.EXIT_OK)

    def test_scan_redaction_hides_query(self):
        code, out, _ = run_cli(
            'scan', 'https://user:pw@example.com/login?token=secret',
            '--data', DATA, '--json', '--redact', '--no-history', '--log-level', 'ERROR',
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertNotIn('pw', payload['input'])
        self.assertNotIn('secret', payload['input'])
        self.assertIn('[query hidden]', payload['input'])

    def test_scan_stdin_and_usage_errors(self):
        with mock.patch('sys.stdin', io.StringIO('Your OTP is 123456. Pay now.')):
            code, out, _ = run_cli(
                'scan', '--stdin', '--data', DATA, '--json', '--no-history',
                '--log-level', 'ERROR',
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['type'], 'MESSAGE')

        code, _, err = run_cli('scan', 'text', '--file', 'x', '--data', DATA,
                               '--no-history', '--log-level', 'ERROR')
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn('only one input source', err)

        with mock.patch('sys.stdin', io.StringIO('')):
            code, _, _ = run_cli('scan', '--stdin', '--data', DATA,
                                 '--no-history', '--log-level', 'ERROR')
        self.assertEqual(code, cli.EXIT_USAGE)

    def test_batch_json_ranking_and_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'samples.txt'
            source.write_text(
                '# comment\n'
                '\n'
                'https://www.google.com\n'
                'https://paypa1.com/signin\n'
                'Hi Mum, the meeting is at noon.\n',
                encoding='utf-8',
            )
            code, out, _ = run_cli(
                'batch', str(source), '--data', DATA, '--json', '--no-history',
                '--log-level', 'ERROR',
            )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload['scanned'], 3)
        self.assertEqual(payload['skipped'], 2)
        self.assertEqual(payload['items'][0]['result']['level'], 'HIGH')
        self.assertEqual(payload['max_score'], 42)
        self.assertEqual(payload['max_level'], 'HIGH')

    def test_batch_invalid_lines_return_usage_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'bad.txt'
            source.write_text('hello\x01world\n', encoding='utf-8')
            code, out, _ = run_cli(
                'batch', str(source), '--type', 'message', '--data', DATA,
                '--json', '--no-history', '--log-level', 'ERROR',
            )
        self.assertEqual(code, cli.EXIT_USAGE)
        payload = json.loads(out)
        self.assertEqual(payload['scanned'], 0)
        self.assertEqual(len(payload['errors']), 1)

    def test_history_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = str(Path(tmp) / 'history.txt')
            code, _, _ = run_cli(
                '--url', 'https://paypa1.com/signin', '--data', DATA,
                '--history', history, '--log-level', 'ERROR',
            )
            self.assertEqual(code, 0)
            code, _, _ = run_cli(
                '--message', 'Your OTP is 123456. Pay the fee now.',
                '--data', DATA, '--history', history, '--log-level', 'ERROR',
            )
            self.assertEqual(code, 0)

            contents = Path(history).read_text(encoding='utf-8')
            self.assertIn('PhishGuard scan history (v2)', contents)
            self.assertNotIn('123456', contents)

            code, out, _ = run_cli('history', 'stats', '--history', history, '--json',
                                   '--log-level', 'ERROR')
            self.assertEqual(code, 0)
            stats = json.loads(out)
            self.assertEqual(stats['total'], 2)
            self.assertEqual(stats['per_level']['HIGH'], 1)

            code, out, _ = run_cli(
                'history', 'list', '--history', history, '--json',
                '--sort', 'score-high', '--limit', '1', '--log-level', 'ERROR',
            )
            self.assertEqual(code, 0)
            records = json.loads(out)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['score'], 42)

            exported = Path(tmp) / 'export.json'
            code, _, _ = run_cli('history', 'export', '--history', history,
                                 '--output', str(exported), '--log-level', 'ERROR')
            self.assertEqual(code, 0)
            self.assertEqual(len(json.loads(exported.read_text(encoding='utf-8'))['records']), 2)

            code, _, _ = run_cli('history', 'clear', '--history', history, '--yes',
                                 '--log-level', 'ERROR')
            self.assertEqual(code, 0)
            code, out, _ = run_cli('history', 'stats', '--history', history, '--json',
                                   '--log-level', 'ERROR')
            self.assertEqual(json.loads(out)['total'], 0)

    def test_data_validate_path_and_strict_mode(self):
        code, out, _ = run_cli('data', 'validate', '--data', DATA, '--json',
                               '--log-level', 'ERROR')
        self.assertEqual(code, 0)
        summary = json.loads(out)
        self.assertGreaterEqual(summary['trusted_domains'], 4)
        self.assertGreaterEqual(summary['threat_entries'], 4)

        code, out, _ = run_cli('data', 'path', '--data', DATA, '--json',
                               '--log-level', 'ERROR')
        self.assertEqual(code, 0)
        self.assertTrue(Path(json.loads(out)['data_dir']).is_dir())

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            import shutil
            shutil.copytree(ROOT / 'data', target, dirs_exist_ok=True)
            config = target / 'risk_config.txt'
            with config.open('a', encoding='utf-8') as handle:
                handle.write('surprise.setting=1\n')

            code, out, _ = run_cli('data', 'validate', '--data', str(target),
                                   '--log-level', 'ERROR')
            self.assertEqual(code, 0)
            self.assertIn('unknown config key', out)

            code, _, err = run_cli('data', 'validate', '--data', str(target), '--strict',
                                   '--log-level', 'ERROR')
            self.assertEqual(code, cli.EXIT_USAGE)
            self.assertIn('unknown config key', err)

    def test_invalid_config_and_missing_data_return_usage_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            import shutil
            shutil.copytree(ROOT / 'data', target, dirs_exist_ok=True)
            (target / 'risk_config.txt').write_text('weight.keyword=-1\n', encoding='utf-8')
            code, _, err = run_cli('data', 'validate', '--data', str(target),
                                   '--log-level', 'ERROR')
            self.assertEqual(code, cli.EXIT_USAGE)
            self.assertIn('must not be negative', err)

            (target / 'trusted_domains.txt').unlink()
            code, _, err = run_cli('data', 'validate', '--data', str(target),
                                   '--log-level', 'ERROR')
            self.assertEqual(code, cli.EXIT_USAGE)
            self.assertIn('missing required file', err)

    def test_legacy_flags_still_work(self):
        code, out, _ = run_cli('--demo', '--data', DATA, '--strict', '--log-level', 'ERROR')
        self.assertEqual(code, 0)
        self.assertIn('14 of 14', out)

        code, out, _ = run_cli('--message', 'Hi Mum, the meeting is at noon.',
                               '--data', DATA, '--no-history', '--log-level', 'ERROR')
        self.assertEqual(code, 0)
        self.assertIn('Risk Level : LOW', out)

        # A message whose text happens to equal a subcommand name must not be
        # interpreted as a subcommand.
        code, out, _ = run_cli('--message', 'scan', '--data', DATA,
                               '--no-history', '--log-level', 'ERROR')
        self.assertEqual(code, 0)
        self.assertIn('Risk Level : LOW', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
