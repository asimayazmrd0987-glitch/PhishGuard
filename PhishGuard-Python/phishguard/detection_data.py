"""Configuration, trusted-domain data, threat data and detector resources."""
from __future__ import annotations

import os
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .algorithms import merge_sort
from .constants import CONFIG_FILE, DATA_ENV_VAR, REQUIRED_DATA_FILES
from .ds import CustomSet, HashTable, KeywordInfo, Trie
from .errors import ConfigurationError, DataError
from .files import atomic_write_text, read_text_file
from .logging_setup import get_logger
from .text_utils import read_data_lines, to_lower, trim
from .types import RiskLevel, risk_level_from_string

_log = get_logger('detection_data')

DEFAULTS = {
    'weight.known_threat': 50, 'weight.lookalike': 30, 'weight.brand_embedded': 25,
    'weight.ip_host': 20, 'weight.credential_request': 15, 'weight.financial_request': 15,
    'weight.userinfo_trick': 15, 'weight.urgency': 10, 'weight.prize': 10, 'weight.delivery': 10,
    'weight.suspicious_tld': 10, 'weight.many_subdomains': 10, 'weight.punycode': 10,
    'weight.unusual_scheme': 10, 'weight.malformed': 10, 'weight.url_shortener': 8,
    'weight.redirect_param': 8, 'weight.keyword': 5, 'weight.long_url': 5, 'weight.long_host': 5,
    'weight.many_hyphens': 5, 'weight.digits_in_domain': 5, 'weight.encoded_chars': 5,
    'weight.encoded_text': 5, 'weight.excessive_punct': 5, 'weight.all_caps': 5,
    'weight.repeated_chars': 3, 'weight.threat': 60, 'weight.self_harm': 65,
    'weight.extortion': 50, 'weight.harassment': 25,
    'cap.keyword': 25, 'limit.long_url': 75, 'limit.long_host': 30,
    'limit.many_subdomains': 3, 'limit.many_hyphens': 3, 'limit.encoded_chars': 3,
    'limit.max_urls': 5, 'limit.max_message': 10000,
    'threshold.low_max': 20, 'threshold.medium_max': 40, 'threshold.high_max': 70,
}

_NON_NEGATIVE_PREFIXES = ('weight.', 'cap.')
_POSITIVE_PREFIXES = ('limit.',)


class RiskConfig:
    """Validated key/value configuration backed by the project's hash table."""

    KNOWN_KEYS = frozenset(DEFAULTS)

    def __init__(self) -> None:
        self._values: HashTable[str, int] = HashTable()
        for key, value in DEFAULTS.items():
            self._values.insert(key, value)

    def weight(self, key: str) -> int:
        value = self._values.find(key, None)
        if value is None:
            raise KeyError(f'unknown config key: {key}')
        return value

    value = weight

    def has(self, key: str) -> bool:
        return self._values.contains(key)

    def set(self, key: str, value: int) -> None:
        self._values.insert(key, int(value))

    def as_dict(self) -> dict[str, int]:
        return {key: value for key, value in sorted(self._values.for_each(), key=lambda item: item[0])}

    def unknown_keys(self) -> list[str]:
        return sorted(key for key, _ in self._values.for_each() if key not in self.KNOWN_KEYS)

    def validate(self) -> None:
        """Reject configurations that would make scoring unpredictable."""
        for key in sorted(DEFAULTS):
            value = self._values.find(key, None)
            if value is None:
                raise ConfigurationError(f'missing config key: {key}')
            if key.startswith(_NON_NEGATIVE_PREFIXES) and value < 0:
                raise ConfigurationError(f'{key} must not be negative (got {value})')
            if key.startswith(_POSITIVE_PREFIXES) and value <= 0:
                raise ConfigurationError(f'{key} must be positive (got {value})')
        low = self.weight('threshold.low_max')
        medium = self.weight('threshold.medium_max')
        high = self.weight('threshold.high_max')
        if not (0 <= low <= medium <= high <= 100):
            raise ConfigurationError(
                'thresholds must satisfy 0 <= low_max <= medium_max <= high_max <= 100 '
                f'(got {low}, {medium}, {high})'
            )

    def level_for(self, score: int) -> RiskLevel:
        score = max(0, min(100, score))
        if score <= self.weight('threshold.low_max'):
            return RiskLevel.LOW
        if score <= self.weight('threshold.medium_max'):
            return RiskLevel.MEDIUM
        if score <= self.weight('threshold.high_max'):
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    @classmethod
    def load_from_file(cls, path: str | Path, *, strict: bool = False) -> 'RiskConfig':
        cfg = cls()
        p = Path(path)
        try:
            lines = read_text_file(p).splitlines()
        except (OSError, UnicodeError) as exc:
            raise ConfigurationError(f'cannot open config file: {p}') from exc
        unknown: list[str] = []
        for number, raw in enumerate(lines, 1):
            line = trim(raw)
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                raise ConfigurationError(f'missing = at {p}:{number}')
            key, raw_value = map(trim, line.split('=', 1))
            if not key or not raw_value:
                raise ConfigurationError(f'empty key/value at {p}:{number}')
            try:
                value = int(raw_value, 10)
            except ValueError as exc:
                raise ConfigurationError(f'bad number at {p}:{number}') from exc
            if key not in cls.KNOWN_KEYS:
                unknown.append(key)
                if strict:
                    raise ConfigurationError(f'unknown config key at {p}:{number}: {key}')
            cfg.set(key, value)
        if unknown and not strict:
            _log.warning('ignoring unknown config key(s): %s', ', '.join(sorted(set(unknown))))
        cfg.validate()
        return cfg

    def save_to_file(self, path: str | Path) -> None:
        lines = [
            '# PhishGuard configuration (generated by the application).\n',
            '# Format: key=value. Weights, caps and limits are non-negative.\n',
        ]
        for key in sorted(DEFAULTS):
            lines.append(f'{key}={self.weight(key)}\n')
        try:
            atomic_write_text(path, ''.join(lines), mode=0o644)
        except OSError as exc:
            raise ConfigurationError(f'cannot write config file: {path}') from exc


@dataclass
class ThreatEntry:
    domain: str
    category: str
    risk: RiskLevel
    note: str = ''


class ThreatDatabase:
    def __init__(self) -> None:
        self._table: HashTable[str, ThreatEntry] = HashTable()

    @staticmethod
    def _normalized(entry: ThreatEntry) -> ThreatEntry:
        domain, category = to_lower(trim(entry.domain)), to_lower(trim(entry.category))
        if not domain:
            raise ValueError('threat domain must not be empty')
        return ThreatEntry(domain, category, entry.risk, trim(entry.note))

    def add(self, entry: ThreatEntry) -> bool:
        normalized = self._normalized(entry)
        return self._table.insert(normalized.domain, normalized)

    def update(self, domain: str, entry: ThreatEntry) -> bool:
        key = to_lower(trim(domain))
        old = self._table.find(key, None)
        if old is None:
            return False
        normalized = self._normalized(entry)
        normalized.domain = old.domain
        self._table.insert(key, normalized)
        return True

    def remove(self, domain: str) -> bool:
        return self._table.remove(to_lower(trim(domain)))

    def find(self, domain: str) -> Optional[ThreatEntry]:
        return self._table.find(to_lower(trim(domain)), None)

    def find_for_host(self, host: str) -> Optional[ThreatEntry]:
        candidate = to_lower(trim(host))
        while True:
            found = self._table.find(candidate, None)
            if found is not None:
                return found
            dot = candidate.find('.')
            if dot < 0:
                return None
            candidate = candidate[dot + 1:]

    def all(self) -> list[ThreatEntry]:
        out = [entry for _, entry in self._table.for_each()]
        merge_sort(out, lambda a, b: (-int(a.risk), a.domain) < (-int(b.risk), b.domain))
        return out

    def by_category(self, category: str) -> list[ThreatEntry]:
        wanted = to_lower(trim(category))
        return [entry for entry in self.all() if entry.category == wanted]

    @classmethod
    def load_from_file(cls, path: str | Path) -> 'ThreatDatabase':
        db = cls()
        p = Path(path)
        for line in read_data_lines(p):
            parts = line.text.split('|')
            if len(parts) < 4:
                raise DataError(f'{p}:{line.number}: expected domain|category|risk|note')
            risk = risk_level_from_string(parts[2])
            if risk is None:
                raise DataError(f"{p}:{line.number}: unknown risk level '{parts[2]}'")
            try:
                db.add(ThreatEntry(parts[0], parts[1], risk, trim('|'.join(parts[3:]))))
            except ValueError as exc:
                raise DataError(f'{p}:{line.number}: {exc}') from exc
        return db

    def save_to_file(self, path: str | Path) -> None:
        lines = [
            '# Threat list (SYNTHETIC SAMPLES ONLY: reserved .test domains, never real sites).\n',
            '# FORMAT domain|category|risk|note\n',
            '# Only add a real domain if you have a reliable source: a wrong entry accuses an innocent site.\n',
        ]
        for entry in self.all():
            lines.append(f'{entry.domain}|{entry.category}|{entry.risk.name}|{entry.note}\n')
        try:
            atomic_write_text(path, ''.join(lines), mode=0o644)
        except OSError as exc:
            raise DataError(f'cannot write threat file: {path}') from exc

    @property
    def size(self) -> int:
        return len(self._table)

    @property
    def load_factor(self) -> float:
        return self._table.load_factor


@dataclass
class TrustedEntry:
    domain: str
    brand: str
    category: str


class TrustedDomainStore:
    def __init__(self) -> None:
        self._table: HashTable[str, TrustedEntry] = HashTable()
        self._snapshot: Optional[tuple[TrustedEntry, ...]] = None

    def _invalidate(self) -> None:
        self._snapshot = None

    def add(self, entry: TrustedEntry) -> bool:
        normalized = TrustedEntry(
            to_lower(trim(entry.domain)),
            to_lower(trim(entry.brand)),
            trim(entry.category),
        )
        if not normalized.domain:
            raise ValueError('trusted domain must not be empty')
        inserted = self._table.insert(normalized.domain, normalized)
        self._invalidate()
        return inserted

    def remove(self, domain: str) -> bool:
        removed = self._table.remove(to_lower(trim(domain)))
        if removed:
            self._invalidate()
        return removed

    def find(self, domain: str) -> Optional[TrustedEntry]:
        return self._table.find(to_lower(trim(domain)), None)

    def is_trusted_host(self, host: str) -> bool:
        candidate = to_lower(trim(host))
        while True:
            if self._table.contains(candidate):
                return True
            dot = candidate.find('.')
            if dot < 0:
                return False
            candidate = candidate[dot + 1:]

    def snapshot(self) -> tuple[TrustedEntry, ...]:
        """Return an immutable, cached view for impersonation checks."""
        if self._snapshot is None:
            self._snapshot = tuple(entry for _, entry in self._table.for_each())
        return self._snapshot

    def all(self) -> list[TrustedEntry]:
        out = list(self.snapshot())
        merge_sort(out, lambda a, b: a.domain < b.domain)
        return out

    @classmethod
    def load_from_file(cls, path: str | Path) -> 'TrustedDomainStore':
        store = cls()
        p = Path(path)
        for line in read_data_lines(p):
            parts = line.text.split('|')
            if len(parts) < 3:
                raise DataError(f'{p}:{line.number}: expected domain|brand|category')
            try:
                store.add(TrustedEntry(parts[0], parts[1], trim('|'.join(parts[2:]))))
            except ValueError as exc:
                raise DataError(f'{p}:{line.number}: {exc}') from exc
        return store

    def save_to_file(self, path: str | Path) -> None:
        lines = [
            '# Trusted websites: used to spot look-alikes and avoid false alarms.\n',
            '# FORMAT domain|brand|category\n',
        ]
        for entry in self.all():
            lines.append(f'{entry.domain}|{entry.brand}|{entry.category}\n')
        try:
            atomic_write_text(path, ''.join(lines), mode=0o644)
        except OSError as exc:
            raise DataError(f'cannot write trusted-domain file: {path}') from exc

    @property
    def size(self) -> int:
        return len(self._table)


@dataclass
class Phrase:
    text: str
    category: str


@dataclass(frozen=True)
class DataSummary:
    data_dir: str
    trusted: int
    threats: int
    keywords: int
    keyword_nodes: int
    phrases: int
    suspicious_tlds: int
    url_shorteners: int
    known_tlds: int
    public_suffixes: int
    config_keys: int
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            'data_dir': self.data_dir,
            'trusted_domains': self.trusted,
            'threat_entries': self.threats,
            'keywords': self.keywords,
            'keyword_trie_nodes': self.keyword_nodes,
            'phrases': self.phrases,
            'suspicious_tlds': self.suspicious_tlds,
            'url_shorteners': self.url_shorteners,
            'known_tlds': self.known_tlds,
            'public_suffixes': self.public_suffixes,
            'config_keys': self.config_keys,
            'warnings': list(self.warnings),
        }


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
    def load_from_directory(
        cls,
        directory: str | Path,
        *,
        strict_config: bool = False,
    ) -> 'DetectionData':
        d = Path(directory).expanduser()
        if not d.is_dir():
            raise DataError(f'data directory does not exist: {d}')
        missing = [name for name in REQUIRED_DATA_FILES if not (d / name).is_file()]
        if missing:
            raise DataError(
                f'data directory {d} is missing required file(s): ' + ', '.join(missing)
            )

        try:
            config = RiskConfig.load_from_file(d / CONFIG_FILE, strict=strict_config)
            trusted = TrustedDomainStore.load_from_file(d / 'trusted_domains.txt')
            threats = ThreatDatabase.load_from_file(d / 'sample_threats.txt')

            keywords = Trie()
            keyword_path = d / 'suspicious_keywords.txt'
            for line in read_data_lines(keyword_path):
                parts = line.text.split('|')
                where = f'{keyword_path}:{line.number}'
                if len(parts) < 3:
                    raise DataError(f'{where}: expected word|category|weight')
                try:
                    weight = int(trim(parts[2]))
                except ValueError as exc:
                    raise DataError(f'{where}: bad weight') from exc
                if weight < 0:
                    raise DataError(f'{where}: weight must not be negative')
                try:
                    keywords.insert(trim(parts[0]), KeywordInfo(trim(parts[1]), weight))
                except ValueError as exc:
                    raise DataError(f'{where}: {exc}') from exc

            phrases: list[Phrase] = []
            phrase_path = d / 'suspicious_phrases.txt'
            for line in read_data_lines(phrase_path):
                parts = line.text.split('|')
                where = f'{phrase_path}:{line.number}'
                if len(parts) < 2:
                    raise DataError(f'{where}: expected phrase|category')
                text = to_lower(trim(parts[0]))
                category = to_lower(trim(parts[1]))
                if not text or not category:
                    raise DataError(f'{where}: phrase and category must not be empty')
                phrases.append(Phrase(text, category))

            def wordlist(name: str) -> CustomSet[str]:
                return CustomSet(to_lower(line.text) for line in read_data_lines(d / name))

            data = cls(
                config,
                trusted,
                threats,
                keywords,
                phrases,
                wordlist('suspicious_tlds.txt'),
                wordlist('url_shorteners.txt'),
                wordlist('known_tlds.txt'),
                wordlist('public_suffixes.txt'),
                str(d.resolve()),
            )
            data.validate()
            return data
        except (OSError, UnicodeError) as exc:
            raise DataError(f'cannot read data directory {d}: {exc}') from exc

    def validate(self) -> DataSummary:
        """Validate loaded resources and return a summary for diagnostics."""
        self.config.validate()
        warnings = []
        unknown = self.config.unknown_keys()
        if unknown:
            warnings.append('unknown config key(s): ' + ', '.join(unknown))
        if self.trusted.size == 0:
            warnings.append('trusted-domain list is empty; look-alike checks are disabled')
        if self.threats.size == 0:
            warnings.append('threat list is empty; no known-threat matches are possible')
        if self.keywords.size == 0:
            warnings.append('keyword trie is empty')
        return DataSummary(
            data_dir=self.data_dir,
            trusted=self.trusted.size,
            threats=self.threats.size,
            keywords=self.keywords.size,
            keyword_nodes=self.keywords.node_count,
            phrases=len(self.phrases),
            suspicious_tlds=len(self.suspicious_tlds),
            url_shorteners=len(self.url_shorteners),
            known_tlds=len(self.known_tlds),
            public_suffixes=len(self.public_suffixes),
            config_keys=len(self.config.as_dict()),
            warnings=tuple(warnings),
        )

    def summary(self) -> DataSummary:
        return self.validate()

    @staticmethod
    def _is_data_dir(path: Path) -> bool:
        return path.is_dir() and (path / CONFIG_FILE).is_file()

    @classmethod
    def _candidate_directories(cls, hint: str = '') -> Iterable[Path]:
        candidates: list[Path] = []
        for raw in (hint, os.environ.get(DATA_ENV_VAR, '')):
            if raw:
                candidate = Path(raw).expanduser()
                candidates.extend((candidate, candidate / 'data'))
        here = Path(__file__).resolve().parent
        candidates.extend(
            (
                Path.cwd() / 'data',
                Path.cwd(),
                Path.cwd().parent / 'data',
                Path.cwd().parent.parent / 'data',
                here.parent / 'data',
                here / 'data',
            )
        )
        for share in (
            Path(sysconfig.get_path('data')) / 'share' / 'phishguard' / 'data',
            Path(sys.prefix) / 'share' / 'phishguard' / 'data',
        ):
            candidates.append(share)

        seen: set[Path] = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            yield resolved

    @classmethod
    def find_data_directory(cls, hint: str = '') -> str:
        for candidate in cls._candidate_directories(hint):
            if cls._is_data_dir(candidate):
                return str(candidate)
        return ''

    @classmethod
    def resolve_data_directory(cls, hint: str = '') -> str:
        found = cls.find_data_directory(hint)
        if found:
            return found
        searched = ', '.join(str(path) for path in cls._candidate_directories(hint))
        raise DataError(
            'could not find a data directory containing risk_config.txt. '
            f'Pass --data <folder> or set {DATA_ENV_VAR}. Searched: {searched}'
        )


__all__ = [
    'DEFAULTS',
    'RiskConfig',
    'ThreatEntry',
    'ThreatDatabase',
    'TrustedEntry',
    'TrustedDomainStore',
    'Phrase',
    'DataSummary',
    'DetectionData',
]
