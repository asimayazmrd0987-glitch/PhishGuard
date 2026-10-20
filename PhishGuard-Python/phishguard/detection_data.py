"""Configuration, trusted-domain data, threat data and detector resources."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from .ds import HashTable, CustomSet, Trie, KeywordInfo
from .algorithms import merge_sort
from .text_utils import trim, to_lower, read_data_lines
from .types import RiskLevel, risk_level_from_string

DEFAULTS = {
    'weight.known_threat':50, 'weight.lookalike':30, 'weight.brand_embedded':25,
    'weight.ip_host':20, 'weight.credential_request':15, 'weight.financial_request':15,
    'weight.userinfo_trick':15, 'weight.urgency':10, 'weight.prize':10, 'weight.delivery':10,
    'weight.suspicious_tld':10, 'weight.many_subdomains':10, 'weight.punycode':10,
    'weight.unusual_scheme':10, 'weight.malformed':10, 'weight.url_shortener':8,
    'weight.redirect_param':8, 'weight.keyword':5, 'weight.long_url':5, 'weight.long_host':5,
    'weight.many_hyphens':5, 'weight.digits_in_domain':5, 'weight.encoded_chars':5,
    'weight.encoded_text':5, 'weight.excessive_punct':5, 'weight.all_caps':5,
    'weight.repeated_chars':3, 'cap.keyword':25, 'limit.long_url':75, 'limit.long_host':30,
    'limit.many_subdomains':3, 'limit.many_hyphens':3, 'limit.encoded_chars':3,
    'threshold.low_max':20, 'threshold.medium_max':40, 'threshold.high_max':70,
}

class RiskConfig:
    def __init__(self):
        self._values: HashTable[str, int] = HashTable()
        for key, value in DEFAULTS.items(): self._values.insert(key, value)

    def weight(self, key: str) -> int:
        value = self._values.find(key, None)
        if value is None: raise KeyError(f'unknown config key: {key}')
        return value

    value = weight

    def has(self, key: str) -> bool:
        return self._values.contains(key)

    def set(self, key: str, value: int) -> None:
        self._values.insert(key, int(value))

    def level_for(self, score: int) -> RiskLevel:
        score = max(0, min(100, score))
        if score <= self.weight('threshold.low_max'): return RiskLevel.LOW
        if score <= self.weight('threshold.medium_max'): return RiskLevel.MEDIUM
        if score <= self.weight('threshold.high_max'): return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    @classmethod
    def load_from_file(cls, path: str | Path) -> 'RiskConfig':
        cfg = cls()
        p = Path(path)
        try:
            lines = p.read_text(encoding='utf-8').splitlines()
        except OSError as exc:
            raise RuntimeError(f'cannot open config file: {p}') from exc
        for number, raw in enumerate(lines, 1):
            line = trim(raw)
            if not line or line.startswith('#'): continue
            if '=' not in line: raise RuntimeError(f'missing = at {p}:{number}')
            key, raw_value = map(trim, line.split('=', 1))
            if not key or not raw_value: raise RuntimeError(f'empty key/value at {p}:{number}')
            try:
                value = int(raw_value, 10)
            except ValueError as exc:
                raise RuntimeError(f'bad number at {p}:{number}') from exc
            cfg.set(key, value)
        return cfg

@dataclass
class ThreatEntry:
    domain: str
    category: str
    risk: RiskLevel
    note: str = ''

class ThreatDatabase:
    def __init__(self): self._table: HashTable[str, ThreatEntry] = HashTable()

    @staticmethod
    def _normalized(entry: ThreatEntry) -> ThreatEntry:
        domain, category = to_lower(trim(entry.domain)), to_lower(trim(entry.category))
        if not domain: raise ValueError('threat domain must not be empty')
        return ThreatEntry(domain, category, entry.risk, trim(entry.note))

    def add(self, entry: ThreatEntry) -> bool:
        e = self._normalized(entry)
        return self._table.insert(e.domain, e)

    def update(self, domain: str, entry: ThreatEntry) -> bool:
        key = to_lower(trim(domain))
        old = self._table.find(key, None)
        if old is None: return False
        e = self._normalized(entry); e.domain = old.domain
        self._table.insert(key, e)
        return True

    def remove(self, domain: str) -> bool: return self._table.remove(to_lower(trim(domain)))
    def find(self, domain: str) -> Optional[ThreatEntry]: return self._table.find(to_lower(domain), None)

    def find_for_host(self, host: str) -> Optional[ThreatEntry]:
        candidate = to_lower(host)
        while True:
            found = self._table.find(candidate, None)
            if found is not None: return found
            dot = candidate.find('.')
            if dot < 0: return None
            candidate = candidate[dot + 1:]

    def all(self) -> list[ThreatEntry]:
        out = [entry for _, entry in self._table.for_each()]
        merge_sort(out, lambda a, b: (-int(a.risk), a.domain) < (-int(b.risk), b.domain))
        return out

    def by_category(self, category: str) -> list[ThreatEntry]:
        c = to_lower(trim(category))
        return [e for e in self.all() if e.category == c]

    @classmethod
    def load_from_file(cls, path: str | Path) -> 'ThreatDatabase':
        db = cls()
        for line in read_data_lines(path):
            parts = line.text.split('|')
            if len(parts) < 4: raise RuntimeError(f'{path}:{line.number}: expected domain|category|risk|note')
            risk = risk_level_from_string(parts[2])
            if risk is None: raise RuntimeError(f"{path}:{line.number}: unknown risk level '{parts[2]}'")
            db.add(ThreatEntry(parts[0], parts[1], risk, trim('|'.join(parts[3:]))))
        return db

    def save_to_file(self, path: str | Path) -> None:
        with open(path, 'w', encoding='utf-8') as out:
            out.write('# Threat list (SYNTHETIC SAMPLES ONLY: reserved .test domains, never real sites).\n')
            out.write('# FORMAT domain|category|risk|note\n')
            out.write('# Only add a real domain if you have a reliable source: a wrong entry accuses an innocent site.\n')
            for e in self.all(): out.write(f'{e.domain}|{e.category}|{e.risk.name}|{e.note}\n')

    @property
    def size(self) -> int: return len(self._table)
    @property
    def load_factor(self) -> float: return self._table.load_factor

@dataclass
class TrustedEntry:
    domain: str
    brand: str
    category: str

class TrustedDomainStore:
    def __init__(self): self._table: HashTable[str, TrustedEntry] = HashTable()

    def add(self, entry: TrustedEntry) -> bool:
        e = TrustedEntry(to_lower(trim(entry.domain)), to_lower(trim(entry.brand)), trim(entry.category))
        if not e.domain: raise ValueError('trusted domain must not be empty')
        return self._table.insert(e.domain, e)

    def remove(self, domain: str) -> bool: return self._table.remove(to_lower(trim(domain)))
    def find(self, domain: str) -> Optional[TrustedEntry]: return self._table.find(to_lower(domain), None)

    def is_trusted_host(self, host: str) -> bool:
        candidate = to_lower(host)
        while True:
            if self._table.contains(candidate): return True
            dot = candidate.find('.')
            if dot < 0: return False
            candidate = candidate[dot + 1:]

    def snapshot(self) -> list[TrustedEntry]: return [e for _, e in self._table.for_each()]
    def all(self) -> list[TrustedEntry]:
        out = self.snapshot()
        merge_sort(out, lambda a, b: a.domain < b.domain)
        return out

    @classmethod
    def load_from_file(cls, path: str | Path) -> 'TrustedDomainStore':
        store = cls()
        for line in read_data_lines(path):
            parts = line.text.split('|')
            if len(parts) < 3: raise RuntimeError(f'{path}:{line.number}: expected domain|brand|category')
            store.add(TrustedEntry(parts[0], parts[1], trim('|'.join(parts[2:]))))
        return store

    def save_to_file(self, path: str | Path) -> None:
        with open(path, 'w', encoding='utf-8') as out:
            out.write('# Trusted websites: used to spot look-alikes and avoid false alarms.\n')
            out.write('# FORMAT domain|brand|category\n')
            for e in self.all(): out.write(f'{e.domain}|{e.brand}|{e.category}\n')

    @property
    def size(self) -> int: return len(self._table)

@dataclass
class Phrase:
    text: str
    category: str

@dataclass
class DetectionData:
    config: RiskConfig
    trusted: TrustedDomainStore
    threats: ThreatDatabase
    keywords: Trie
    phrases: list[Phrase]
    suspicious_tlds: CustomSet[str]
    url_shorteners: CustomSet[str]
    known_tlds: CustomSet[str]
    public_suffixes: CustomSet[str]
    data_dir: str

    @classmethod
    def load_from_directory(cls, directory: str | Path) -> 'DetectionData':
        d = Path(directory)
        config = RiskConfig.load_from_file(d / 'risk_config.txt')
        trusted = TrustedDomainStore.load_from_file(d / 'trusted_domains.txt')
        threats = ThreatDatabase.load_from_file(d / 'sample_threats.txt')
        keywords = Trie()
        for line in read_data_lines(d / 'suspicious_keywords.txt'):
            parts = line.text.split('|')
            where = f'{d / "suspicious_keywords.txt"}:{line.number}'
            if len(parts) < 3: raise RuntimeError(f'{where}: expected word|category|weight')
            try: weight = int(trim(parts[2]))
            except ValueError as exc: raise RuntimeError(f'{where}: bad weight') from exc
            keywords.insert(trim(parts[0]), KeywordInfo(trim(parts[1]), weight))
        phrases = []
        for line in read_data_lines(d / 'suspicious_phrases.txt'):
            parts = line.text.split('|')
            if len(parts) < 2: raise RuntimeError(f'{d / "suspicious_phrases.txt"}:{line.number}: expected phrase|category')
            phrases.append(Phrase(to_lower(trim(parts[0])), to_lower(trim(parts[1]))))
        def wordlist(name: str) -> CustomSet[str]:
            return CustomSet(to_lower(line.text) for line in read_data_lines(d / name))
        return cls(config, trusted, threats, keywords, phrases,
                   wordlist('suspicious_tlds.txt'), wordlist('url_shorteners.txt'),
                   wordlist('known_tlds.txt'), wordlist('public_suffixes.txt'), str(d.resolve()))

    @staticmethod
    def find_data_directory(hint: str = '') -> str:
        here = Path(__file__).resolve().parent.parent
        candidates = [Path(hint)] if hint else []
        candidates += [Path.cwd() / 'data', Path.cwd().parent / 'data', Path.cwd().parent.parent / 'data', here / 'data']
        for candidate in candidates:
            if candidate and (candidate / 'risk_config.txt').is_file(): return str(candidate.resolve())
        return ''
