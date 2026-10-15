from __future__ import annotations
import random
import tempfile
import unittest
from pathlib import Path

from phishguard.algorithms import (
    edit_distance, edit_distance_two_row, edit_distance_table, similarity,
    similarity_label, build_prefix_table, naive_search, kmp_search,
    rabin_karp_search, merge_sort, quick_sort, binary_search,
)
from phishguard.detection_data import DetectionData, RiskConfig, ThreatDatabase, ThreatEntry, TrustedDomainStore, TrustedEntry
from phishguard.ds import HashTable, CustomSet, Trie, KeywordInfo, MaxHeap, Graph, NodeType
from phishguard.engine import ScanService
from phishguard.graph_builder import add_scan_to_graph
from phishguard.storage import HistoryManager, SortKey
from phishguard.text_utils import redact_sensitive, redact_url
from phishguard.types import InputType, RiskLevel, Indicator, IndicatorCategory
from phishguard.url_parser import UrlParser

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'

def data():
    return DetectionData.load_from_directory(DATA)

def has_indicator(result, id_):
    return any(i.id == id_ for i in result.indicators)

class AlgorithmsTests(unittest.TestCase):
    def test_levenshtein_and_similarity(self):
        self.assertEqual(edit_distance('kitten', 'sitting'), 3)
        self.assertEqual(edit_distance('', 'abc'), 3)
        self.assertEqual(edit_distance('paypal.com', 'paypa1.com'), 1)
        self.assertEqual(edit_distance('google.com', 'g00gle.com'), 2)
        self.assertEqual(edit_distance('a', 'b'), edit_distance('b', 'a'))
        self.assertEqual(edit_distance('abracadabra', 'abracadabra'), edit_distance_two_row('abracadabra', 'abracadabra'))
        self.assertGreater(similarity('paypal.com', 'paypa1.com'), .85)
        self.assertEqual(similarity_label(similarity('paypal.com', 'paypa1.com')), 'Very High')
        self.assertEqual(edit_distance_table('ab', 'ba')[-1][-1], 2)

    def test_string_matching_overlap_and_random_agreement(self):
        for func in (naive_search, kmp_search, rabin_karp_search):
            self.assertEqual(func('aaaaa', 'aa'), [0, 1, 2, 3])
            self.assertEqual(func('abc', 'abcd'), [])
            self.assertEqual(func('abc', ''), [])
        self.assertEqual(kmp_search('ababcabcab', 'abcab'), [2, 5])
        self.assertEqual(build_prefix_table('abcabd'), [0, 0, 0, 1, 2, 0])
        rng = random.Random(12)
        for _ in range(100):
            text = ''.join(rng.choice('abc') for _ in range(rng.randrange(5, 45)))
            pat = ''.join(rng.choice('abc') for _ in range(rng.randrange(1, 5)))
            expected = naive_search(text, pat)
            self.assertEqual(kmp_search(text, pat), expected)
            self.assertEqual(rabin_karp_search(text, pat), expected)

    def test_sorts_and_binary_search(self):
        rng = random.Random(77)
        for _ in range(30):
            values = [rng.randrange(-10, 11) for _ in range(rng.randrange(0, 100))]
            self.assertEqual(merge_sort(values.copy(), lambda a,b:a < b), sorted(values))
            self.assertEqual(quick_sort(values.copy(), lambda a,b:a < b), sorted(values))
        vals = ['a.test', 'c.test', 'e.test', 'g.test']
        self.assertEqual(binary_search(vals, 'e.test', lambda a,b:a < b), 2)
        self.assertEqual(binary_search(vals, 'b.test', lambda a,b:a < b), -1)

class DataStructureTests(unittest.TestCase):
    def test_hash_table_update_remove_collisions_and_rehash(self):
        table = HashTable[str, int](initial_buckets=3, hash_func=lambda _: 0)
        self.assertTrue(table.insert('a', 1))
        self.assertTrue(table.insert('b', 2))
        self.assertFalse(table.insert('a', 3))
        self.assertEqual(table.find('a'), 3)
        for i in range(50): table.insert(f'k{i}', i)
        self.assertEqual(table.find('k27'), 27)
        self.assertEqual(table.max_chain_length, len(table))
        self.assertTrue(table.remove('b'))
        self.assertFalse(table.remove('missing'))
        self.assertGreater(table.bucket_count, 3)

    def test_custom_set(self):
        s = CustomSet([1, 2, 2])
        self.assertEqual(len(s), 2)
        self.assertTrue(s.contains(1))
        self.assertTrue(s.remove(1))
        self.assertFalse(s.contains(1))

    def test_trie_prefix_remove_and_whole_word_scan(self):
        trie = Trie()
        trie.insert('pin', KeywordInfo('credential', 10))
        trie.insert('bank', KeywordInfo('financial', 6))
        trie.insert('banker')
        self.assertTrue(trie.starts_with('ban'))
        self.assertEqual(trie.words_with_prefix('bank'), ['bank', 'banker'])
        matches = trie.scan_text('Send your PIN to the Bank, not pinterest or banking!')
        self.assertEqual([m.word for m in matches], ['pin', 'bank'])
        self.assertTrue(trie.remove('banker'))
        self.assertTrue(trie.contains('bank'))
        self.assertFalse(trie.contains('banker'))
        with self.assertRaises(ValueError): trie.insert('')

    def test_heap(self):
        heap = MaxHeap()
        for n in [42, 18, 92, 88, 74, 69]: heap.push(n)
        self.assertEqual([heap.pop() for _ in range(6)], [92, 88, 74, 69, 42, 18])
        heap = MaxHeap([5, 5, 1, 9])
        self.assertEqual([heap.pop() for _ in range(4)], [9, 5, 5, 1])
        with self.assertRaises(IndexError): heap.pop()

    def test_graph_bfs_dfs(self):
        graph = Graph()
        for label in 'ABCDE': graph.add_node(label, NodeType.DOMAIN)
        graph.add_edge('A', 'B'); graph.add_edge('A', 'C'); graph.add_edge('B', 'D')
        self.assertEqual([graph.node(v.node).label for v in graph.bfs(graph.index_of('A'))], ['A','B','C','D'])
        self.assertEqual([graph.node(v.node).label for v in graph.dfs(graph.index_of('A'))], ['A','B','D','C'])
        self.assertEqual(len(graph.bfs(graph.index_of('A'), 1)), 3)
        self.assertFalse(graph.add_edge('A', 'B'))
        self.assertFalse(graph.add_edge('A', 'A'))

class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.d = data()
        self.service = ScanService(self.d)
        self.parser = UrlParser(self.d.public_suffixes)

    def test_parser_full_url_and_validation(self):
        u = self.parser.parse('HTTPS://user:pw@Login.Example.co.uk:8443/a/b?x=1&y=2#frag')
        self.assertTrue(u.valid)
        self.assertEqual((u.scheme, u.userinfo, u.host, u.port), ('https','user:pw','login.example.co.uk',8443))
        self.assertEqual((u.path, u.query, u.fragment), ('/a/b','x=1&y=2','frag'))
        self.assertEqual((u.registered_domain, u.subdomain_count, u.tld), ('example.co.uk',1,'uk'))
        self.assertTrue(self.parser.parse('example.com/path').valid)
        self.assertFalse(self.parser.parse('example.com/path').had_scheme)
        self.assertTrue(self.parser.parse('http://[::1]:80/').host_is_ip)
        for raw in ['', 'http://999.1.1.1/', 'http://exa mple.com', 'http://bad..com', 'http://example.com:99999', 'http://-bad.com', 'a'*3000]:
            self.assertFalse(self.parser.parse(raw).valid, raw[:40])

    def test_extract_urls(self):
        urls = self.parser.extract_urls('Visit https://a.test/x, or www.b.test. Also paypa1-login.xyz/verify! Mail me@x.com e.g. Hi.There', self.d.known_tlds)
        self.assertEqual(urls, ['https://a.test/x', 'www.b.test', 'paypa1-login.xyz/verify'])

    def test_trusted_and_lookalikes(self):
        result = self.service.scan_url('https://accounts.google.com/login')
        self.assertEqual(result.score, 0)
        result = self.service.scan_url('https://paypa1.com/')
        self.assertTrue(has_indicator(result, 'lookalike_domain'))
        self.assertEqual(result.findings.impersonation.trusted_domain, 'paypal.com')
        self.assertEqual(result.findings.impersonation.distance, 1)
        self.assertTrue(has_indicator(self.service.scan_url('https://g00gle.com/'), 'lookalike_domain'))
        self.assertTrue(has_indicator(self.service.scan_url('https://paypal.com.evil-check.example.xyz/'), 'brand_embedded'))

    def test_url_features(self):
        checks = [
            ('http://203.0.113.45/login', 'ip_host'),
            ('http://a.b.c.d.example.com/', 'many_subdomains'),
            ('http://shop.example.top/', 'suspicious_tld'),
            ('http://www.google.com@evil.example.net/', 'userinfo_trick'),
            ('http://a-b-c-d.example.net/', 'many_hyphens'),
            ('http://bit.ly/abc123', 'url_shortener'),
            ('http://xn--pypal-4ve.example.net/', 'punycode'),
            ('http://example.net/go?url=http://other.example.com', 'redirect_param'),
        ]
        for url, indicator in checks:
            with self.subTest(url=url): self.assertTrue(has_indicator(self.service.scan_url(url), indicator))
        self.assertTrue(has_indicator(self.service.scan_url('http://bad..domain.com/page'), 'malformed_url'))

    def test_messages_validation_capping_and_links(self):
        result = self.service.scan_message('CONGRATULATIONS!!! You are the WINNER of a free reward. Claim your prize now: http://free-prize-claim.test/win')
        self.assertGreaterEqual(result.score, 70)
        result = self.service.scan_message('Hi Mum, the meeting is at noon.')
        self.assertEqual(result.level, RiskLevel.LOW)
        self.assertLessEqual(sum(i.weight for i in result.indicators if i.category == IndicatorCategory.KEYWORD), 25)
        with self.assertRaises(ValueError): self.service.scan_message('  ')
        with self.assertRaises(ValueError): self.service.scan_message('x' * 10001)
        result = self.service.scan_message('Your account is suspended. Visit http://bank-verify-now.test/verify')
        self.assertTrue(result.findings.urls)
        self.assertGreaterEqual(result.score, 50)

    def test_score_dedupe_and_levels(self):
        cfg = self.d.config
        self.assertEqual(cfg.level_for(20), RiskLevel.LOW)
        self.assertEqual(cfg.level_for(21), RiskLevel.MEDIUM)
        self.assertEqual(cfg.level_for(41), RiskLevel.HIGH)
        self.assertEqual(cfg.level_for(71), RiskLevel.CRITICAL)
        self.assertEqual(cfg.level_for(1000), RiskLevel.CRITICAL)
        from phishguard.engine import RiskEngine
        indicators = [Indicator('same','one',10,IndicatorCategory.DOMAIN), Indicator('same','duplicate',10,IndicatorCategory.DOMAIN)]
        self.assertEqual(len(RiskEngine(cfg).evaluate(indicators).indicators), 1)

class StorageAndConfigTests(unittest.TestCase):
    def test_config_load_override_and_error(self):
        cfg = RiskConfig.load_from_file(DATA / 'risk_config.txt')
        self.assertEqual(cfg.weight('weight.known_threat'), 50)
        self.assertEqual(cfg.level_for(20), RiskLevel.LOW)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'cfg.txt'; p.write_text('weight.keyword=19\n', encoding='utf-8')
            self.assertEqual(RiskConfig.load_from_file(p).weight('weight.keyword'), 19)
            p.write_text('bad-line\n', encoding='utf-8')
            with self.assertRaises(RuntimeError): RiskConfig.load_from_file(p)
        with self.assertRaises(KeyError): cfg.weight('unknown.key')

    def test_threat_and_trusted_stores(self):
        db = ThreatDatabase()
        self.assertTrue(db.add(ThreatEntry('Bad-One.test','credential',RiskLevel.HIGH,'sample')))
        self.assertFalse(db.add(ThreatEntry('bad-one.test','credential',RiskLevel.CRITICAL,'dup')))
        self.assertEqual(db.find('BAD-ONE.test').risk, RiskLevel.CRITICAL)
        self.assertIsNotNone(db.find_for_host('login.bad-one.test'))
        self.assertTrue(db.update('bad-one.test', ThreatEntry('ignored','delivery',RiskLevel.HIGH,'x')))
        self.assertEqual(db.find('bad-one.test').domain, 'bad-one.test')
        trusted = TrustedDomainStore(); trusted.add(TrustedEntry('paypal.com','paypal','payments'))
        self.assertTrue(trusted.is_trusted_host('www.paypal.com'))
        self.assertFalse(trusted.is_trusted_host('paypal.com.evil.test'))
        self.assertFalse(trusted.is_trusted_host('notpaypal.com'))

    def test_redaction(self):
        self.assertEqual(redact_sensitive('my password is hunter2 ok'), 'my password is [hidden] ok')
        self.assertEqual(redact_sensitive('pin:4821'), 'pin:[hidden]')
        self.assertEqual(redact_sensitive('your OTP is 482913 thanks'), 'your OTP is [hidden] thanks')
        self.assertEqual(redact_sensitive('call 03001234567 now'), 'call [digits] now')
        self.assertEqual(redact_url('https://user:pw@a.test/p?token=abc#x'), 'https://[hidden]@a.test/p?[query hidden]')

    def test_history_sort_filter_persist_and_graph(self):
        service = ScanService(data()); history = HistoryManager()
        a = history.add(service.scan_url('https://www.google.com'))
        b = history.add(service.scan_url('https://paypa1.com/signin'))
        c = history.add(service.scan_message('Your OTP is 123456. Pay the fee now http://bank-verify-now.test'))
        self.assertEqual(history.sorted(SortKey.NEWEST)[0].id, c)
        self.assertEqual(history.sorted(SortKey.OLDEST)[0].id, a)
        self.assertEqual(history.sorted(SortKey.SCORE_HIGH)[0].id, c)
        self.assertEqual(len(history.filter(RiskLevel.HIGH, None, '')), 2)
        self.assertEqual(len(history.filter(None, InputType.URL, '')), 2)
        self.assertNotIn('123456', history.find(c).input)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.txt'; history.save(path)
            with path.open('a', encoding='utf-8') as f: f.write('malformed\n')
            loaded = HistoryManager.load(path)
            self.assertEqual(loaded.size, 3)
        self.assertTrue(history.remove(b)); self.assertFalse(history.remove(b))
        graph = Graph()
        r1 = service.scan_message('Verify now http://bank-verify-now.test/a')
        r2 = service.scan_message('Another one http://bank-verify-now.test/b')
        add_scan_to_graph(graph, 1, r1); add_scan_to_graph(graph, 2, r2)
        scans = [graph.node(v.node).label for v in graph.bfs(graph.index_of('Scan #1'))]
        self.assertIn('Scan #2', scans)

class IntegrationTests(unittest.TestCase):
    def test_all_demos_in_expected_bands(self):
        service = ScanService(data())
        for scenario in __import__('phishguard.demos', fromlist=['demo_scenarios']).demo_scenarios():
            result = service.scan_url(scenario.input) if scenario.type == InputType.URL else service.scan_message(scenario.input, scenario.type)
            with self.subTest(scenario=scenario.title):
                self.assertGreaterEqual(result.level, scenario.min_level)
                self.assertLessEqual(result.level, scenario.max_level)

if __name__ == '__main__':
    unittest.main(verbosity=2)
