"""Console user interface corresponding to the C++ menu."""
from __future__ import annotations
from pathlib import Path
from .algorithms import similarity_label
from .benchmark import run_benchmarks
from .demos import demo_scenarios
from .ds import Graph, NodeType, MaxHeap
from .engine import ScanService
from .graph_builder import add_scan_to_graph
from .storage import HistoryManager, SortKey
from .types import (AnalysisResult, InputType, RiskLevel, input_type_from_string,
                    risk_level_from_string)
from .text_utils import trim, to_lower
from .detection_data import DetectionData, ThreatEntry, TrustedEntry

WIDTH = 68

def clip(text: str, size: int) -> str:
    return text if len(text) <= size else text[:max(0, size - 3)] + '...'

def looks_like_url(line: str) -> bool:
    return ' ' not in line and ('://' in line or '.' in line)

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
        try: return trim(input(prompt))
        except EOFError: return ''

    @staticmethod
    def read_block(prompt: str) -> str:
        print(prompt + ' (type END on its own line when finished)')
        lines = []
        try:
            while True:
                line = input()
                if trim(line) == 'END': break
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

    def save_history(self) -> None:
        try: self.history.save(self.history_path)
        except Exception as exc: print(f'(Could not save history: {exc})')

    def print_result(self, result: AnalysisResult, scan_id: int) -> None:
        print('\nAnalyzing...\n')
        for step in ('Input checked', 'Links extracted and split into parts', 'Threat list checked', 'Keyword analysis completed', 'Similarity analysis completed', 'Risk engine completed'):
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
            points = next((i.weight for i in result.indicators if i.id in {'lookalike_domain', 'brand_embedded'}), 0)
            print('\n' + ('TRUSTED NAME HIDDEN IN ADDRESS' if match.embedded else 'POSSIBLE DOMAIN IMPERSONATION'))
            print(f'Input:                      {match.input_part}\nPossible legitimate domain: {match.trusted_domain}')
            print(f'Edit distance:              {match.distance}\nSimilarity:                 {similarity_label(match.similarity)}')
            print(f'Risk contribution:          +{points}')
            print('Reason: ' + ('The name of a trusted website is placed inside a different address.' if match.embedded else 'The name differs from a trusted website by a small number of character changes.'))
            print('(Similarity alone does not prove bad intent.)')
        print('\nRecommendation:\n' + result.recommendation)
        root = self.graph.index_of(f'Scan #{scan_id}')
        if root >= 0:
            visits = self.graph.bfs(root, 3)
            if len(visits) > 1:
                print('\nRelated items found (graph search):')
                for visit in visits[1:11]:
                    node = self.graph.node(visit.node)
                    print(' ' * (visit.depth * 2) + f'- {node.type}: {clip(node.label, 60)}')
        print('\n' + '-' * WIDTH)
        print('PhishGuard is an educational tool. A LOW result is not a guarantee of safety,\nand a high result is not proof of a scam.')

    def scan_once(self, kind: InputType, value: str) -> None:
        try:
            result = self.service.scan_url(value) if kind == InputType.URL else self.service.scan_message(value, kind)
        except (ValueError, KeyError) as exc:
            print(f'Sorry: {exc}')
            return
        scan_id = self.history.add(result)
        add_scan_to_graph(self.graph, scan_id, result)
        self.print_result(result, scan_id)
        self.save_history()

    def handle_scan(self, kind: InputType) -> None:
        value = self.read_block('Paste the email text') if kind == InputType.EMAIL else self.read('Enter link: ' if kind == InputType.URL else 'Enter message: ')
        if not value:
            print('Nothing was entered.'); return
        self.scan_once(kind, value)

    def _print_records(self, records) -> None:
        if not records: print('(no records)'); return
        print(f"{'ID':<5}{'Time':<21}{'Type':<9}{'Score':<7}{'Level':<10}Input")
        for rec in records:
            print(f'{rec.id:<5}{rec.timestamp:<21}{rec.type.value:<9}{rec.score:<7}{rec.level.name:<10}{clip(rec.input, 40)}')

    def _print_record(self, rec) -> None:
        print(f'Scan #{rec.id}  {rec.timestamp}  {rec.type.value}\nScore: {rec.score} ({rec.level.name})')
        print('Input (sensitive parts hidden): ' + rec.input)
        print('Indicators:' + (' none' if not rec.indicator_ids else ''))
        for indicator_id in rec.indicator_ids: print('  - ' + indicator_id)

    def handle_history(self) -> None:
        while True:
            choice = self.read('\nHistory: 1) view  2) sort  3) filter  4) inspect  5) remove  6) clear all  0) back\n> ')
            if choice in {'', '0'}: return
            if choice == '1': self._print_records(self.history.sorted(SortKey.NEWEST))
            elif choice == '2':
                sort_choice = self.read('Sort by 1) newest 2) oldest 3) highest score 4) lowest score 5) risk level: ')
                keys = {'1':SortKey.NEWEST,'2':SortKey.OLDEST,'3':SortKey.SCORE_HIGH,'4':SortKey.SCORE_LOW,'5':SortKey.LEVEL}
                if sort_choice not in keys: print('Please choose 1-5.')
                else: self._print_records(self.history.sorted(keys[sort_choice]))
            elif choice == '3':
                level_s = self.read('Minimum level (low/medium/high/critical, blank = any): ')
                type_s = self.read('Type (url/message/email, blank = any): ')
                needle = self.read('Text contains (blank = anything): ')
                level = risk_level_from_string(level_s) if level_s else None
                kind = input_type_from_string(type_s) if type_s else None
                if level_s and level is None: print('Unknown level.'); continue
                if type_s and kind is None: print('Unknown type.'); continue
                self._print_records(self.history.filter(level, kind, needle))
            elif choice in {'4','5'}:
                try: record_id = int(self.read('Scan ID: '))
                except ValueError: print('Invalid ID.'); continue
                rec = self.history.find(record_id)
                if not rec: print('No scan with that ID.'); continue
                if choice == '4': self._print_record(rec)
                else: self.history.remove(record_id); self.save_history(); print(f'Removed scan #{record_id}.')
            elif choice == '6':
                if self.read('Delete ALL history? (yes/no): ') == 'yes':
                    self.history.clear(); self.save_history(); print('History cleared.')

    def handle_threats(self) -> None:
        while True:
            print(f'\nThreat database ({self.data.threats.size} synthetic sample entries)')
            for e in self.data.threats.all(): print(f' {e.domain:<28}{e.category:<16}{e.risk.name:<10}{e.note}')
            choice = self.read('a) add  u) update  d) delete  s) search  c) by category  0) back\n> ')
            if not choice or choice == '0': return
            domain = ''
            try:
                if choice in {'a','u'}:
                    domain = self.read('Domain: '); category = self.read('Category: ')
                    risk = risk_level_from_string(self.read('Risk (low/medium/high/critical): '))
                    note = self.read('Note: ')
                    if risk is None: print('Unknown risk level.'); continue
                    entry = ThreatEntry(domain, category, risk, note)
                    if choice == 'a': print('Added.' if self.data.threats.add(entry) else 'Existing entry replaced.')
                    else: print('Updated.' if self.data.threats.update(domain, entry) else 'No such domain.')
                elif choice == 'd':
                    domain = self.read('Domain: '); print('Deleted.' if self.data.threats.remove(domain) else 'No such domain.')
                elif choice == 's':
                    domain = self.read('Domain: '); e = self.data.threats.find_for_host(domain)
                    print(f'Found: {e.domain} ({e.category}, {e.risk.name})' if e else 'Not in the local list. (That does not mean a site is safe.)')
                elif choice == 'c':
                    for e in self.data.threats.by_category(self.read('Category: ')): print(f' {e.domain}  {e.risk.name}')
                else: continue
                if choice in {'a','u','d'}: self.data.threats.save_to_file(Path(self.data.data_dir) / 'sample_threats.txt')
            except Exception as exc: print(f'Error: {exc}')

    def handle_trusted(self) -> None:
        while True:
            print(f'\nTrusted websites ({self.data.trusted.size})')
            for e in self.data.trusted.all(): print(f' {e.domain:<22}{e.brand:<14}{e.category}')
            choice = self.read('a) add  d) delete  0) back\n> ')
            if not choice or choice == '0': return
            try:
                if choice == 'a':
                    domain = self.read('Domain (e.g. mybank.com): ')
                    brand = self.read('Brand name (e.g. mybank): ')
                    category = self.read('Category: ')
                    print('Added.' if self.data.trusted.add(TrustedEntry(domain, brand, category)) else 'Existing entry replaced.')
                elif choice == 'd':
                    domain = self.read('Domain: ')
                    print('Deleted.' if self.data.trusted.remove(domain) else 'No such domain.')
                else: continue
                self.data.trusted.save_to_file(Path(self.data.data_dir) / 'trusted_domains.txt')
            except Exception as exc: print(f'Error: {exc}')

    def handle_stats(self) -> None:
        stats = self.history.stats()
        print('\n' + '-' * WIDTH + '\nSTATISTICS'.center(WIDTH) + '\n' + '-' * WIDTH)
        print(f'Total scans: {stats.total}')
        for level, count in zip(('LOW','MEDIUM','HIGH','CRITICAL'), stats.per_level): print(f' {level:<9}{count:<5}{"#" * min(count, 40)}')
        print(f'Average risk score: {stats.average_score:.1f}')
        if stats.top_indicators:
            print('Most common indicators:')
            for key, count in stats.top_indicators: print(f'  {count} x {key}')
        top = self.history.top_risk(5)
        if top: print('Highest-risk scans (max-heap):'); self._print_records(top)
        print(f'System: {self.data.trusted.size} trusted sites, {self.data.threats.size} threat samples (hash load {self.data.threats.load_factor:.2f}), {self.data.keywords.size} keywords in trie ({self.data.keywords.node_count} nodes), graph {self.graph.node_count} nodes / {self.graph.edge_count} edges')

    def handle_batch(self) -> None:
        path = self.read('File with one link or message per line: ')
        try: lines = Path(path).read_text(encoding='utf-8').splitlines()
        except OSError: print('Cannot open that file.'); return
        items = []
        for index, line in enumerate(lines):
            line = trim(line)
            if not line or line.startswith('#'): continue
            try:
                result = self.service.scan_url(line) if looks_like_url(line) else self.service.scan_message(line)
                scan_id = self.history.add(result); add_scan_to_graph(self.graph, scan_id, result)
                items.append((result.score, -index, result, line))
            except Exception: continue
        heap = MaxHeap(items, less=lambda a,b: a[:2] < b[:2])
        print('\nRanked by risk (priority queue):')
        rank = 1
        while not heap.empty():
            _, _, result, line = heap.pop()
            print(f'{rank:>3}. {result.level.name:<9}{result.score:>3}  {clip(line,60)}'); rank += 1
        self.save_history()

    def handle_graph(self) -> None:
        label = self.read("Enter a website, link, keyword or 'Scan #N': ")
        start = self.graph.index_of(label)
        if start < 0: start = self.graph.index_of(to_lower(label))
        if start < 0: print('Nothing like that has been scanned in this session yet.'); return
        print('\nNearest related items (breadth-first search):')
        for visit in self.graph.bfs(start):
            node = self.graph.node(visit.node)
            print(' ' * (visit.depth * 2) + f'- {node.type}: {clip(node.label,60)}')
        print('\nFull chain (depth-first search):')
        for visit in self.graph.dfs(start): print(' ' * (visit.depth * 2) + '- ' + clip(self.graph.node(visit.node).label,60))

    def handle_keywords(self) -> None:
        prefix = self.read('Keyword prefix (e.g. verif): ')
        words = self.data.keywords.words_with_prefix(prefix)
        if not words: print('No watched keywords start with that.')
        for word in words:
            info = self.data.keywords.find(word)
            print(f' - {word} ({info.category if info else "unknown"})')

    def run_demos(self) -> None:
        self.banner(); matched = 0
        for demo in demo_scenarios():
            result = self.service.scan_url(demo.input) if demo.type == InputType.URL else self.service.scan_message(demo.input, demo.type)
            ok = demo.min_level <= result.level <= demo.max_level
            matched += bool(ok)
            expected = demo.min_level.name if demo.min_level == demo.max_level else f'{demo.min_level.name}-{demo.max_level.name}'
            print('\n' + '-' * WIDTH + f'\n{demo.title}\nInput     : {demo.input}\nAlgorithms: {demo.algorithms}\nNote      : {demo.note}')
            for indicator in result.indicators: print(f'  [ +{indicator.weight} ] {indicator.id}')
            print(f'Risk Score: {result.score} / 100   Level: {result.level.name}   (expected {expected}: {"OK" if ok else "DIFFERENT"})')
            print('Recommendation: ' + result.recommendation)
        print(f'\n{matched} of {len(demo_scenarios())} demo scenarios landed in their expected level range.')

    def run(self) -> int:
        self.banner()
        print('Paste a link or message and PhishGuard will explain what looks suspicious.')
        while True:
            self.menu()
            choice = self.read('Choose an option: ')
            if not choice: break
            try: number = int(choice)
            except ValueError: number = -1
            if number == 8: break
            handlers = {
                1: lambda: self.handle_scan(InputType.URL),
                2: lambda: self.handle_scan(InputType.MESSAGE),
                3: lambda: self.handle_scan(InputType.EMAIL),
                4: self.handle_history, 5: self.handle_threats, 6: self.handle_trusted,
                7: self.handle_stats, 9: self.handle_batch, 10: self.handle_graph,
                11: self.handle_keywords, 12: self.run_demos, 13: lambda: run_benchmarks(),
            }
            handler = handlers.get(number)
            if handler: handler()
            else: print('Please type a number from 1 to 13.')
        print('Stay safe online. Goodbye!')
        return 0
