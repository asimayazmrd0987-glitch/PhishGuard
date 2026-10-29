"""Tests for the 2.0 hardening layer: validation, atomic I/O, batch and reporting."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from phishguard import (
    AnalysisResult,
    ConfigurationError,
    DataError,
    DetectionData,
    InputType,
    PhishGuardError,
    RiskConfig,
    RiskEngine,
    RiskLevel,
    ScanService,
    ThreatEntry,
    TrustedEntry,
    UsageError,
    ValidationError,
    __version__,
)
from phishguard.batch import format_batch_result, looks_like_url, scan_lines
from phishguard.demos import run_scenarios
from phishguard.files import atomic_write_text, read_text_file
from phishguard.reporting import (
    analysis_result_to_dict,
    analysis_result_to_json,
    format_analysis_result,
    format_record_table,
    history_stats_to_dict,
)
from phishguard.storage import HistoryManager, SortKey
from phishguard.text_utils import redact_sensitive, redact_url
from phishguard.types import Indicator, IndicatorCategory
from phishguard.url_parser import UrlParser

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'


def data() -> DetectionData:
    return DetectionData.load_from_directory(DATA)


class PackageTests(unittest.TestCase):
    def test_version_and_public_api(self):
        self.assertEqual(__version__, '2.0.0')
        self.assertTrue(issubclass(ConfigurationError, PhishGuardError))
        self.assertTrue(issubclass(ConfigurationError, RuntimeError))
        self.assertTrue(issubclass(ValidationError, ValueError))
        self.assertTrue(issubclass(UsageError, ValueError))

    def test_scan_helpers(self):
        service = ScanService(data())
        self.assertEqual(service.scan_auto('https://paypa1.com/signin').type, InputType.URL)
        self.assertEqual(service.scan_auto('Hi Mum, lunch at noon.').type, InputType.MESSAGE)
        self.assertEqual(service.scan_email('Your OTP is 123456.').type, InputType.EMAIL)


class AtomicFileTests(unittest.TestCase):
    def test_atomic_write_replaces_and_sets_private_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.txt'
            atomic_write_text(path, 'first\n')
            self.assertEqual(path.read_text(encoding='utf-8'), 'first\n')
            atomic_write_text(path, 'second\n')
            self.assertEqual(path.read_text(encoding='utf-8'), 'second\n')
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(Path(tmp).glob('*.tmp')), [])

    def test_atomic_write_requires_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / 'nope' / 'file.txt'
            with self.assertRaises(OSError):
                atomic_write_text(missing, 'x')

    def test_bom_tolerant_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cfg.txt'
            path.write_text('weight.keyword=9\n', encoding='utf-8-sig')
            self.assertEqual(read_text_file(path), 'weight.keyword=9\n')
            self.assertEqual(RiskConfig.load_from_file(path).weight('weight.keyword'), 9)

    def test_history_header_and_corrupt_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.txt'
            history = HistoryManager()
            history.add(ScanService(data()).scan_url('https://paypa1.com/signin'))
            history.save(path)
            text = path.read_text(encoding='utf-8')
            self.assertTrue(text.startswith('# PhishGuard scan history (v2)'))
            with path.open('a', encoding='utf-8') as handle:
                handle.write('not-a-record\n')
                handle.write('# another comment\n')
            loaded = HistoryManager.load(path)
            self.assertEqual(loaded.size, 1)
            self.assertEqual(loaded.sorted(SortKey.NEWEST)[0].score, 42)


class ConfigurationTests(unittest.TestCase):
    def test_negative_weights_and_bad_thresholds_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cfg.txt'
            path.write_text('weight.keyword=-1\n', encoding='utf-8')
            with self.assertRaises(ConfigurationError):
                RiskConfig.load_from_file(path)
            path.write_text('threshold.low_max=50\nthreshold.medium_max=40\n', encoding='utf-8')
            with self.assertRaises(ConfigurationError):
                RiskConfig.load_from_file(path)

    def test_strict_unknown_key_and_reported_unknown_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cfg.txt'
            path.write_text('made.up=1\n', encoding='utf-8')
            config = RiskConfig.load_from_file(path)
            self.assertEqual(config.unknown_keys(), ['made.up'])
            with self.assertRaises(ConfigurationError):
                RiskConfig.load_from_file(path, strict=True)

    def test_data_summary_and_validation_warnings(self):
        summary = data().summary()
        self.assertGreaterEqual(summary.trusted, 4)
        self.assertGreaterEqual(summary.threats, 4)
        self.assertGreater(summary.keywords, 0)
        self.assertEqual(summary.warnings, ())

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'data'
            import shutil
            shutil.copytree(DATA, target)
            (target / 'trusted_domains.txt').write_text('', encoding='utf-8')
            (target / 'sample_threats.txt').write_text('', encoding='utf-8')
            summary = DetectionData.load_from_directory(target).summary()
            self.assertEqual(summary.trusted, 0)
            self.assertEqual(summary.threats, 0)
            self.assertTrue(any('trusted-domain' in warning for warning in summary.warnings))
            self.assertTrue(any('threat list' in warning for warning in summary.warnings))

    def test_missing_required_file_is_a_data_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'data'
            import shutil
            shutil.copytree(DATA, target)
            (target / 'suspicious_tlds.txt').unlink()
            with self.assertRaises(DataError):
                DetectionData.load_from_directory(target)

    def test_missing_directory_is_a_data_error(self):
        with self.assertRaises(DataError):
            DetectionData.load_from_directory('/definitely/not/here')

    def test_trusted_snapshot_is_immutable_and_cached(self):
        store = data().trusted
        first = store.snapshot()
        self.assertIs(first, store.snapshot())
        self.assertIsInstance(first, tuple)
        with self.assertRaises(AttributeError):
            first.append(TrustedEntry('x.test', 'x', 'test'))  # type: ignore[attr-defined]

    def test_threat_store_validation(self):
        db = data().threats
        with self.assertRaises(ValueError):
            db.add(ThreatEntry('', 'credential', RiskLevel.HIGH))


class EngineTests(unittest.TestCase):
    def test_keyword_cap_does_not_mutate_input(self):
        config = RiskConfig()
        indicator = Indicator('keyword:test', 'test', 100, IndicatorCategory.KEYWORD)
        result = RiskEngine(config).evaluate([indicator])
        self.assertEqual(indicator.weight, 100)
        self.assertEqual(result.indicators[0].weight, 25)
        self.assertEqual(result.score, 25)

    def test_parser_ipv4_and_ipv6_validation(self):
        parser = UrlParser(data().public_suffixes)
        self.assertTrue(parser.parse('http://[2001:db8::1]/').host_is_ip)
        self.assertTrue(parser.parse('http://[::1]:8080/').host_is_ip)
        for raw in ('http://[::zz]/', 'http://[::1', 'http://999.1.1.1/'):
            with self.subTest(raw=raw):
                self.assertFalse(parser.parse(raw).valid)

    def test_looks_like_url(self):
        self.assertTrue(looks_like_url('https://example.com'))
        self.assertTrue(looks_like_url('example.com'))
        self.assertFalse(looks_like_url('hello world'))
        self.assertFalse(looks_like_url(''))


class BatchTests(unittest.TestCase):
    def test_scan_lines_reports_errors_and_ranking(self):
        service = ScanService(data())
        result = scan_lines(
            service,
            ['# comment', '', 'https://www.google.com', 'https://paypa1.com/signin', 'bad\x01message'],
        )
        self.assertEqual(len(result.items), 2)
        self.assertEqual(result.skipped, 2)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0][0], 5)
        self.assertIsNotNone(result.max_item)
        self.assertEqual(result.ranked_items()[0].line_number, 4)
        self.assertEqual(result.max_item.result.score, 42)

        payload = result.to_dict()
        self.assertEqual(payload['scanned'], 2)
        self.assertEqual(len(payload['errors']), 1)
        self.assertIn('Ranked by risk', format_batch_result(result))

    def test_batch_type_forcing(self):
        service = ScanService(data())
        result = scan_lines(service, ['https://paypa1.com/signin'], input_type=InputType.MESSAGE)
        self.assertEqual(result.items[0].result.type, InputType.MESSAGE)

    def test_batch_limit(self):
        service = ScanService(data())
        result = scan_lines(service, ['a.test', 'b.test', 'c.test'], max_items=2)
        self.assertEqual(len(result.items), 2)
        self.assertTrue(result.limit_reached)


class ReportingTests(unittest.TestCase):
    def test_json_redacts_input_and_findings(self):
        result = AnalysisResult(
            type=InputType.URL,
            input='https://user:pw@a.test/p?token=abc#frag',
            score=10,
            level=RiskLevel.LOW,
        )
        result.findings.urls.append(result.input)
        payload = analysis_result_to_dict(result, redact=True)
        self.assertNotIn('pw', payload['input'])
        self.assertNotIn('token=abc', payload['input'])
        self.assertEqual(payload['findings']['urls'], [redact_url(result.input)])
        self.assertEqual(json.loads(analysis_result_to_json(result, redact=True))['input'], payload['input'])

    def test_text_rendering(self):
        result = ScanService(data()).scan_url('https://paypa1.com/signin')
        text = format_analysis_result(result)
        self.assertIn('Risk Score : 42 / 100', text)
        self.assertIn('Why this score:', text)
        self.assertIn('educational tool', text)

    def test_history_rendering_helpers(self):
        history = HistoryManager()
        history.add(ScanService(data()).scan_url('https://paypa1.com/signin'))
        records = history.sorted(SortKey.NEWEST)
        self.assertIn('ID', format_record_table(records))
        stats = history_stats_to_dict(history.stats())
        self.assertEqual(stats['total'], 1)
        self.assertEqual(stats['per_level']['HIGH'], 1)

    def test_extra_redaction_words(self):
        self.assertEqual(redact_sensitive('token=abc123'), 'token=[hidden]')
        self.assertEqual(redact_sensitive('api_key: xyz'), 'api_key: [hidden]')
        self.assertEqual(redact_sensitive('session 123456'), 'session [hidden]')


class DemoRunnerTests(unittest.TestCase):
    def test_all_scenarios_match(self):
        outcomes = run_scenarios(ScanService(data()))
        self.assertEqual(len(outcomes), 14)
        self.assertTrue(all(outcome.matched for outcome in outcomes))
        payload = outcomes[0].to_dict()
        self.assertIn('expected', payload)
        self.assertTrue(payload['matched'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
