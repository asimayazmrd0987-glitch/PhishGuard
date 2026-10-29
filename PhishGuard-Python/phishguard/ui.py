"""Interactive terminal menu corresponding to the C++ edition.

The heavy lifting lives in the reusable modules (:mod:`phishguard.batch`,
:mod:`phishguard.reporting`, :mod:`phishguard.demos`) so the menu, the CLI and
the tests all render and score results identically.
"""
from __future__ import annotations

from pathlib import Path

from .algorithms import similarity_label
from .batch import format_batch_result, scan_lines
from .benchmark import run_benchmarks
from .demos import run_scenarios
from .detection_data import DetectionData, ThreatEntry, TrustedEntry
from .ds import Graph
from .engine import ScanService
from .errors import PhishGuardError
from .files import read_text_file
from .graph_builder import add_scan_to_graph
from .logging_setup import get_logger
from .reporting import (
    FOOTER,
    WIDTH,
    clip_text,
    format_history_stats,
    format_record,
    format_record_table,
)
from .storage import HistoryManager, SortKey
from .text_utils import to_lower, trim
from .types import AnalysisResult, InputType, RiskLevel, input_type_from_string, risk_level_from_string

_log = get_logger('ui')


def _level_message(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: 'Probably safe based on available indicators, but you should still be careful.',
        RiskLevel.MEDIUM: 'Some suspicious characteristics were detected.',
        RiskLevel.HIGH: 'Multiple suspicious characteristics were detected.',
        RiskLevel.CRITICAL: 'Strong indicators of phishing or scam behavior were detected.',
    }[level]


class Interface:
    def __init__(self, data: DetectionData, history_path: str = 'phishguard_history.txt'):
        self.data = data
        self.service = ScanService(data)
        self.history_path = history_path
        self.history = HistoryManager.load(history_path)
        self.graph = Graph()

    @staticmethod
    def read(prompt: str) -> str:
        try:
            return trim(input(prompt))
        except EOFError:
            return ''

    @staticmethod
    def read_block(prompt: str) -> str:
        print(prompt + ' (type END on its own line when finished)')
        lines = []
        try:
            while True:
                line = input()
                if trim(line) == 'END':
                    break
                lines.append(line)
        except EOFError:
            pass
        return trim('\n'.join(lines))

    def banner(self) -> None:
        print('=' * WIDTH)
        print('PHISHGUARD'.center(WIDTH))
        print('CYBERSECURITY FOR EVERYONE'.center(WIDTH))
        print('=' * WIDTH)

    @staticmethod
    def menu() -> None:
        print('\n 1. Scan a link (URL)\n 2. Scan a message (SMS / WhatsApp / social)\n 3. Scan email text\n 4. View scan history')
        print(' 5. View threat database\n 6. View trusted websites\n 7. View statistics\n 8. Exit')
        print(' Extra tools: 9. Batch scan a file   10. Explore related indicators')
        print('              11. Keyword prefix search   12. Demo scenarios   13. Benchmarks')
        print('              14. Validate data files')

    def save_history(self) -> None:
        try:
            self.history.save(self.history_path)
        except (OSError, PhishGuardError) as exc:
            print(f'(Could not save history: {exc})')

    def print_result(self, result: AnalysisResult, scan_id: int) -> None:
        print('\nAnalyzing...\n')
        for step in (
            'Input checked',
            'Links extracted and split into parts',
            'Threat list checked',
            'Keyword analysis completed',
            'Similarity analysis completed',
            'Risk engine completed',
        ):
            print(f'[OK] {step}')
        print('\n' + '-' * WIDTH)
        print('SECURITY RESULT'.center(WIDTH))
        print('-' * WIDTH)
        print(f'\nRisk Score : {result.score} / 100\nRisk Level : {result.level.name}\n{_level_message(result.level)}')
        if not result.indicators:
            print('\nNo suspicious signs were found by our checks.')
        else:
            print('\nWhy this score:')
            for indicator in result.indicators:
                print(f' [ +{indicator.weight} ] {indicator.description}')
        match = result.findings.impersonation
        if match:
            points = next(
                (i.weight for i in result.indicators if i.id in {'lookalike_domain', 'brand_embedded'}),
                0,
            )
            print('\n' + ('TRUSTED NAME HIDDEN IN ADDRESS' if match.embedded else 'POSSIBLE DOMAIN IMPERSONATION'))
            print(f'Input:                      {match.input_part}\nPossible legitimate domain: {match.trusted_domain}')
            print(f'Edit distance:              {match.distance}\nSimilarity:                 {similarity_label(match.similarity)}')
            print(f'Risk contribution:          +{points}')
            print('Reason: ' + (
                'The name of a trusted website is placed inside a different address.'
                if match.embedded
                else 'The name differs from a trusted website by a small number of character changes.'
            ))
            print('(Similarity alone does not prove bad intent.)')
        print('\nRecommendation:\n' + result.recommendation)
        root = self.graph.index_of(f'Scan #{scan_id}')
        if root >= 0:
            visits = self.graph.bfs(root, 3)
            if len(visits) > 1:
                print('\nRelated items found (graph search):')
                for visit in visits[1:11]:
                    node = self.graph.node(visit.node)
                    print(' ' * (visit.depth * 2) + f'- {node.type}: {clip_text(node.label, 60)}')
        print('\n' + '-' * WIDTH)
        print(FOOTER)

    def scan_once(self, kind: InputType, value: str) -> None:
        try:
            if kind == InputType.URL:
                result = self.service.scan_url(value)
            else:
                result = self.service.scan_message(value, kind)
        except (ValueError, KeyError) as exc:
            print(f'Sorry: {exc}')
            return
        scan_id = self.history.add(result)
        add_scan_to_graph(self.graph, scan_id, result)
        self.print_result(result, scan_id)
        self.save_history()

    def handle_scan(self, kind: InputType) -> None:
        value = (
            self.read_block('Paste the email text')
            if kind == InputType.EMAIL
            else self.read('Enter link: ' if kind == InputType.URL else 'Enter message: ')
        )
        if not value:
            print('Nothing was entered.')
            return
        self.scan_once(kind, value)

    def handle_history(self) -> None:
        while True:
            choice = self.read(
                '\nHistory: 1) view  2) sort  3) filter  4) inspect  5) remove  '
                '6) clear all  0) back\n> '
            )
            if choice in {'', '0'}:
                return
            if choice == '1':
                print(format_record_table(self.history.sorted(SortKey.NEWEST)))
            elif choice == '2':
                sort_choice = self.read('Sort by 1) newest 2) oldest 3) highest score 4) lowest score 5) risk level: ')
                keys = {
                    '1': SortKey.NEWEST,
                    '2': SortKey.OLDEST,
                    '3': SortKey.SCORE_HIGH,
                    '4': SortKey.SCORE_LOW,
                    '5': SortKey.LEVEL,
                }
                if sort_choice not in keys:
                    print('Please choose 1-5.')
                else:
                    print(format_record_table(self.history.sorted(keys[sort_choice])))
            elif choice == '3':
                level_s = self.read('Minimum level (low/medium/high/critical, blank = any): ')
                type_s = self.read('Type (url/message/email, blank = any): ')
                needle = self.read('Text contains (blank = anything): ')
                level = risk_level_from_string(level_s) if level_s else None
                kind = input_type_from_string(type_s) if type_s else None
                if level_s and level is None:
                    print('Unknown level.')
                    continue
                if type_s and kind is None:
                    print('Unknown type.')
                    continue
                print(format_record_table(self.history.filter(level, kind, needle)))
            elif choice in {'4', '5'}:
                try:
                    record_id = int(self.read('Scan ID: '))
                except ValueError:
                    print('Invalid ID.')
                    continue
                record = self.history.find(record_id)
                if not record:
                    print('No scan with that ID.')
                    continue
                if choice == '4':
                    print(format_record(record))
                else:
                    self.history.remove(record_id)
                    self.save_history()
                    print(f'Removed scan #{record_id}.')
            elif choice == '6':
                if self.read('Delete ALL history? (yes/no): ') == 'yes':
                    self.history.clear()
                    self.save_history()
                    print('History cleared.')

    def handle_threats(self) -> None:
        while True:
            print(f'\nThreat database ({self.data.threats.size} synthetic sample entries)')
            for entry in self.data.threats.all():
                print(f' {entry.domain:<28}{entry.category:<16}{entry.risk.name:<10}{entry.note}')
            choice = self.read('a) add  u) update  d) delete  s) search  c) by category  0) back\n> ')
            if not choice or choice == '0':
                return
            domain = ''
            try:
                if choice in {'a', 'u'}:
                    domain = self.read('Domain: ')
                    category = self.read('Category: ')
                    risk = risk_level_from_string(self.read('Risk (low/medium/high/critical): '))
                    note = self.read('Note: ')
                    if risk is None:
                        print('Unknown risk level.')
                        continue
                    entry = ThreatEntry(domain, category, risk, note)
                    if choice == 'a':
                        print('Added.' if self.data.threats.add(entry) else 'Existing entry replaced.')
                    else:
                        print('Updated.' if self.data.threats.update(domain, entry) else 'No such domain.')
                elif choice == 'd':
                    domain = self.read('Domain: ')
                    print('Deleted.' if self.data.threats.remove(domain) else 'No such domain.')
                elif choice == 's':
                    domain = self.read('Domain: ')
                    found = self.data.threats.find_for_host(domain)
                    print(
                        f'Found: {found.domain} ({found.category}, {found.risk.name})'
                        if found
                        else 'Not in the local list. (That does not mean a site is safe.)'
                    )
                elif choice == 'c':
                    for entry in self.data.threats.by_category(self.read('Category: ')):
                        print(f' {entry.domain}  {entry.risk.name}')
                else:
                    continue
                if choice in {'a', 'u', 'd'}:
                    self.data.threats.save_to_file(Path(self.data.data_dir) / 'sample_threats.txt')
            except (OSError, ValueError, PhishGuardError) as exc:
                print(f'Error: {exc}')

    def handle_trusted(self) -> None:
        while True:
            print(f'\nTrusted websites ({self.data.trusted.size})')
            for entry in self.data.trusted.all():
                print(f' {entry.domain:<22}{entry.brand:<14}{entry.category}')
            choice = self.read('a) add  d) delete  0) back\n> ')
            if not choice or choice == '0':
                return
            try:
                if choice == 'a':
                    domain = self.read('Domain (e.g. mybank.com): ')
                    brand = self.read('Brand name (e.g. mybank): ')
                    category = self.read('Category: ')
                    print('Added.' if self.data.trusted.add(TrustedEntry(domain, brand, category)) else 'Existing entry replaced.')
                elif choice == 'd':
                    domain = self.read('Domain: ')
                    print('Deleted.' if self.data.trusted.remove(domain) else 'No such domain.')
                else:
                    continue
                self.data.trusted.save_to_file(Path(self.data.data_dir) / 'trusted_domains.txt')
            except (OSError, ValueError, PhishGuardError) as exc:
                print(f'Error: {exc}')

    def handle_stats(self) -> None:
        stats = self.history.stats()
        top = self.history.top_risk(5)
        print('\n' + format_history_stats(stats, top))
        print(
            f'System: {self.data.trusted.size} trusted sites, {self.data.threats.size} threat samples '
            f'(hash load {self.data.threats.load_factor:.2f}), {self.data.keywords.size} keywords in trie '
            f'({self.data.keywords.node_count} nodes), graph {self.graph.node_count} nodes / '
            f'{self.graph.edge_count} edges'
        )

    def handle_batch(self) -> None:
        path = self.read('File with one link or message per line: ')
        try:
            lines = read_text_file(path).splitlines()
        except OSError:
            print('Cannot open that file.')
            return
        batch = scan_lines(self.service, lines)
        for line_number, message in batch.errors:
            _log.debug('batch line %d rejected: %s', line_number, message)
        for item in batch.items:
            scan_id = self.history.add(item.result)
            add_scan_to_graph(self.graph, scan_id, item.result)
        print('\n' + format_batch_result(batch))
        self.save_history()

    def handle_graph(self) -> None:
        label = self.read("Enter a website, link, keyword or 'Scan #N': ")
        start = self.graph.index_of(label)
        if start < 0:
            start = self.graph.index_of(to_lower(label))
        if start < 0:
            print('Nothing like that has been scanned in this session yet.')
            return
        print('\nNearest related items (breadth-first search):')
        for visit in self.graph.bfs(start):
            node = self.graph.node(visit.node)
            print(' ' * (visit.depth * 2) + f'- {node.type}: {clip_text(node.label, 60)}')
        print('\nFull chain (depth-first search):')
        for visit in self.graph.dfs(start):
            print(' ' * (visit.depth * 2) + '- ' + clip_text(self.graph.node(visit.node).label, 60))

    def handle_keywords(self) -> None:
        prefix = self.read('Keyword prefix (e.g. verif): ')
        words = self.data.keywords.words_with_prefix(prefix)
        if not words:
            print('No watched keywords start with that.')
        for word in words:
            info = self.data.keywords.find(word)
            print(f' - {word} ({info.category if info else "unknown"})')

    def run_demos(self) -> None:
        self.banner()
        outcomes = run_scenarios(self.service)
        for outcome in outcomes:
            scenario = outcome.scenario
            print('\n' + '-' * WIDTH + f'\n{scenario.title}\nInput     : {scenario.input}')
            print(f'Algorithms: {scenario.algorithms}\nNote      : {scenario.note}')
            for indicator in outcome.result.indicators:
                print(f'  [ +{indicator.weight} ] {indicator.id}')
            print(
                f'Risk Score: {outcome.result.score} / 100   Level: {outcome.result.level.name}'
                f'   (expected {outcome.expected_label}: {"OK" if outcome.matched else "DIFFERENT"})'
            )
            print('Recommendation: ' + outcome.result.recommendation)
        matched = sum(outcome.matched for outcome in outcomes)
        print(f'\n{matched} of {len(outcomes)} demo scenarios landed in their expected level range.')

    def handle_data(self) -> None:
        try:
            summary = self.data.summary()
        except PhishGuardError as exc:
            print(f'Data validation failed: {exc}')
            return
        print('\n' + '-' * WIDTH + '\nDATA VALIDATION'.center(WIDTH) + '\n' + '-' * WIDTH)
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

    def run(self) -> int:
        self.banner()
        print('Paste a link or message and PhishGuard will explain what looks suspicious.')
        handlers = {
            1: lambda: self.handle_scan(InputType.URL),
            2: lambda: self.handle_scan(InputType.MESSAGE),
            3: lambda: self.handle_scan(InputType.EMAIL),
            4: self.handle_history,
            5: self.handle_threats,
            6: self.handle_trusted,
            7: self.handle_stats,
            9: self.handle_batch,
            10: self.handle_graph,
            11: self.handle_keywords,
            12: self.run_demos,
            13: lambda: run_benchmarks(),
            14: self.handle_data,
        }
        while True:
            self.menu()
            choice = self.read('Choose an option: ')
            if not choice:
                break
            try:
                number = int(choice)
            except ValueError:
                number = -1
            if number == 8:
                break
            handler = handlers.get(number)
            if handler:
                handler()
            else:
                print('Please type a number from 1 to 14.')
        print('Stay safe online. Goodbye!')
        return 0


__all__ = ['Interface']
