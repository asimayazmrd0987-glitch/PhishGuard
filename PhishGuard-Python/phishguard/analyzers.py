"""Domain, URL and message analyzers. These inspect text only and never open links."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .algorithms import edit_distance, similarity, kmp_search, rabin_karp_search
from .detection_data import DetectionData
from .ds import CustomSet, KeywordMatch
from .text_utils import (trim, normalize_lookalikes, split, split_any,
                         is_alpha_char, is_digit_char, is_alnum_char)
from .types import Indicator, IndicatorCategory, ImpersonationMatch
from .url_parser import ParsedUrl, UrlParser

@dataclass
class UrlAnalysis:
    parsed: ParsedUrl = field(default_factory=ParsedUrl)
    indicators: list[Indicator] = field(default_factory=list)
    impersonation: Optional[ImpersonationMatch] = None

@dataclass
class MessageAnalysis:
    indicators: list[Indicator] = field(default_factory=list)
    urls: list[UrlAnalysis] = field(default_factory=list)
    keywords: list[KeywordMatch] = field(default_factory=list)


class DomainAnalyzer:
    def __init__(self, data: DetectionData): self.data = data

    @staticmethod
    def allowed_edits(length: int) -> int:
        if length <= 4: return 0
        return 1 if length <= 8 else 2

    def find_impersonation(self, p: ParsedUrl) -> Optional[ImpersonationMatch]:
        if not p.valid or p.host_is_ip or self.data.trusted.is_trusted_host(p.host): return None
        trusted = self.data.trusted.snapshot()
        best: Optional[ImpersonationMatch] = None
        def consider(match: ImpersonationMatch) -> None:
            nonlocal best
            if best is None or match.distance < best.distance or (match.distance == best.distance and match.embedded and not best.embedded):
                best = match
        for entry in trusted:
            if rabin_karp_search(p.host, entry.domain):
                consider(ImpersonationMatch(p.host, entry.domain, 0, 1.0, False, True))
            raw = edit_distance(p.registered_domain, entry.domain)
            folded = edit_distance(normalize_lookalikes(p.registered_domain), entry.domain) == 0
            if raw >= 1 and (raw <= self.allowed_edits(len(entry.domain)) or folded):
                consider(ImpersonationMatch(p.registered_domain, entry.domain, raw, similarity(p.registered_domain, entry.domain), folded and raw > 0, False))
        for token in split_any(p.host, '.-_'):
            if len(token) < 4: continue
            folded = normalize_lookalikes(token)
            for entry in trusted:
                brand = entry.brand
                if len(brand) < 4: continue
                if token == brand:
                    consider(ImpersonationMatch(token, entry.domain, 0, 1.0, False, True))
                    continue
                distance = edit_distance(token, brand)
                if folded == brand:
                    consider(ImpersonationMatch(token, entry.domain, distance, similarity(token, brand), True, False))
                elif 1 <= distance <= self.allowed_edits(len(brand)):
                    consider(ImpersonationMatch(token, entry.domain, distance, similarity(token, brand), False, False))
                elif len(brand) >= 5 and kmp_search(folded, brand):
                    consider(ImpersonationMatch(token, entry.domain, 0, 1.0, folded != token, True))
        return best

    def analyze(self, p: ParsedUrl) -> tuple[list[Indicator], Optional[ImpersonationMatch]]:
        out: list[Indicator] = []
        impersonation = None
        if not p.valid: return out, None
        cfg = self.data.config
        threat = self.data.threats.find_for_host(p.host)
        if threat:
            out.append(Indicator('known_threat', f'This website address is in our local list of known scam examples ({threat.category}).', cfg.weight('weight.known_threat'), IndicatorCategory.THREAT, threat.domain))
        if p.host_is_ip:
            out.append(Indicator('ip_host', 'The link uses a number address instead of a normal website name. Real companies rarely do this.', cfg.weight('weight.ip_host'), IndicatorCategory.DOMAIN, p.host))
            return out, None
        if self.data.trusted.is_trusted_host(p.host): return out, None
        if self.data.suspicious_tlds.contains(p.tld):
            out.append(Indicator('suspicious_tld', f'The website ends in ".{p.tld}", an ending that is often used by throw-away scam sites.', cfg.weight('weight.suspicious_tld'), IndicatorCategory.DOMAIN, p.tld))
        if self.data.url_shorteners.contains(p.registered_domain):
            out.append(Indicator('url_shortener', 'The link is shortened, so you cannot see where it really leads.', cfg.weight('weight.url_shortener'), IndicatorCategory.DOMAIN, p.registered_domain))
        if p.subdomain_count >= cfg.value('limit.many_subdomains'):
            out.append(Indicator('many_subdomains', 'The website name has many parts before the main name, which is a common way to look official.', cfg.weight('weight.many_subdomains'), IndicatorCategory.DOMAIN, str(p.subdomain_count)))
        hyphens = p.host.count('-')
        if hyphens >= cfg.value('limit.many_hyphens'):
            out.append(Indicator('many_hyphens', 'The website name contains many hyphens, which is unusual for genuine sites.', cfg.weight('weight.many_hyphens'), IndicatorCategory.DOMAIN, str(hyphens)))
        if len(p.host) > cfg.value('limit.long_host'):
            out.append(Indicator('long_host', 'The website name is unusually long.', cfg.weight('weight.long_host'), IndicatorCategory.DOMAIN, str(len(p.host))))
        digits = sum(is_digit_char(c) for c in p.registered_label)
        letters = sum(is_alpha_char(c) for c in p.registered_label)
        if digits >= 1 and letters >= 3:
            out.append(Indicator('digits_in_domain', 'The main website name mixes numbers into a word, a trick used to imitate real names.', cfg.weight('weight.digits_in_domain'), IndicatorCategory.DOMAIN, p.registered_label))
        puny = any(label.startswith('xn--') for label in p.labels) or any(ord(c) >= 128 for c in p.host)
        if puny:
            out.append(Indicator('punycode', 'The website name uses special or foreign characters that can imitate normal letters.', cfg.weight('weight.punycode'), IndicatorCategory.DOMAIN, p.host))
        impersonation = self.find_impersonation(p)
        if impersonation:
            if impersonation.embedded:
                out.append(Indicator('brand_embedded', f'The name of a trusted website ({impersonation.trusted_domain}) appears inside this address, but the site itself is different. Scammers do this to look official.', cfg.weight('weight.brand_embedded'), IndicatorCategory.SIMILARITY, impersonation.trusted_domain))
            else:
                out.append(Indicator('lookalike_domain', f'This website name is very similar to a trusted website ({impersonation.trusted_domain}), which may indicate impersonation.', cfg.weight('weight.lookalike'), IndicatorCategory.SIMILARITY, impersonation.trusted_domain))
        return out, impersonation


class UrlAnalyzer:
    REDIRECT_KEYS = {'url','redirect','redirect_uri','redirecturl','next','return','returnurl','goto','dest','destination','continue','link'}
    def __init__(self, data: DetectionData):
        self.data = data
        self.parser = UrlParser(data.public_suffixes)
        self.domain = DomainAnalyzer(data)

    @staticmethod
    def _count_percent_encoded(value: str) -> int:
        count = 0
        for i in range(len(value) - 2):
            if value[i] == '%' and all(c in '0123456789abcdefABCDEF' for c in value[i+1:i+3]): count += 1
        return count

    def analyze(self, raw_url: str) -> UrlAnalysis:
        result = UrlAnalysis()
        result.parsed = self.parser.parse(raw_url)
        p = result.parsed
        cfg = self.data.config
        out = result.indicators
        if not p.valid:
            out.append(Indicator('malformed_url', f'The link is not formatted like a normal web address ({p.error}).', cfg.weight('weight.malformed'), IndicatorCategory.URL, p.error))
            return result
        if p.scheme not in {'http', 'https', 'ftp'}:
            out.append(Indicator('unusual_scheme', f'The link uses an unusual type ("{p.scheme}://") instead of a normal web link.', cfg.weight('weight.unusual_scheme'), IndicatorCategory.URL, p.scheme))
        if p.userinfo:
            out.append(Indicator('userinfo_trick', 'The link has an "@" sign before the real website name, a trick that hides where it leads.', cfg.weight('weight.userinfo_trick'), IndicatorCategory.URL, p.host))
        domain_indicators, result.impersonation = self.domain.analyze(p)
        out.extend(domain_indicators)
        if not p.host_is_ip and self.data.trusted.is_trusted_host(p.host): return result
        trimmed = trim(raw_url)
        if len(trimmed) > cfg.value('limit.long_url'):
            out.append(Indicator('long_url', 'The link is very long, which can hide where it really goes.', cfg.weight('weight.long_url'), IndicatorCategory.URL, str(len(trimmed))))
        if self._count_percent_encoded(trimmed) >= cfg.value('limit.encoded_chars'):
            out.append(Indicator('encoded_chars', 'The link contains unusual characters that are commonly seen in suspicious URLs.', cfg.weight('weight.encoded_chars'), IndicatorCategory.URL, ''))
        for pair in split(p.query, '&'):
            if '=' not in pair: continue
            key, val = pair.split('=', 1)
            key, val = key.lower(), val.lower()
            if key in self.REDIRECT_KEYS and (kmp_search(val, 'http') or kmp_search(val, '//') or kmp_search(val, '%2f%2f')):
                out.append(Indicator('redirect_param', 'The link contains another web address inside it, which can send you somewhere else.', cfg.weight('weight.redirect_param'), IndicatorCategory.URL, key))
                break
        seen = CustomSet[str]()
        for match in self.data.keywords.scan_text(p.host + ' ' + p.path + ' ' + p.query):
            if not seen.insert(match.word): continue
            weight = match.info.weight if match.info.weight > 0 else cfg.weight('weight.keyword')
            out.append(Indicator('keyword:' + match.word, f'The link contains the word "{match.word}", which scammers often use to look trustworthy or create pressure.', weight, IndicatorCategory.KEYWORD, match.word))
        return result


class MessageAnalyzer:
    MAX_LENGTH = 10000
    MAX_URLS = 5
    CATEGORY_INFO = {
        'urgency': ('weight.urgency', 'The message tries to rush you. Scammers create pressure so you act before thinking.'),
        'credential': ('weight.credential_request', 'The message asks you to verify or share account details such as a password, PIN or code.'),
        'financial': ('weight.financial_request', 'The message asks for money, fees or payment details.'),
        'prize': ('weight.prize', 'The message says you won something. Unexpected prizes are a very common scam.'),
        'delivery': ('weight.delivery', 'The message mentions a parcel or delivery problem, a very common scam theme.'),
    }
    def __init__(self, data: DetectionData):
        self.data = data
        self.url_analyzer = UrlAnalyzer(data)

    @staticmethod
    def _has_long_run(value: str, min_run: int, letters_only: bool) -> bool:
        run = 1
        for i in range(1, len(value)):
            same = value[i] == value[i-1] and (not letters_only or is_alpha_char(value[i]))
            run = run + 1 if same else 1
            if run >= min_run: return True
        return False

    def analyze(self, input_text: str) -> MessageAnalysis:
        msg = trim(input_text)
        if not msg:
            raise ValueError('Nothing was entered.')
        max_length = self.data.config.value('limit.max_message')
        if len(msg) > max_length:
            raise ValueError(f'The text is too long (limit is {max_length} characters).')
        if any(ord(c) < 0x20 and c not in '\n\r\t' for c in msg):
            raise ValueError('The text contains unreadable control characters.')
        cfg = self.data.config
        res = MessageAnalysis()
        out = res.indicators
        lowered = msg.lower()
        seen_category = CustomSet[str]()
        for phrase in self.data.phrases:
            if not kmp_search(lowered, phrase.text) or not seen_category.insert(phrase.category): continue
            key, explanation = self.CATEGORY_INFO.get(phrase.category, ('weight.keyword', 'The message contains wording often used in scams.'))
            out.append(Indicator('phrase_' + phrase.category, f'{explanation} (for example: "{phrase.text}")', cfg.weight(key), IndicatorCategory.MESSAGE, phrase.text))
        seen_word = CustomSet[str]()
        for match in self.data.keywords.scan_text(msg):
            if not seen_word.insert(match.word): continue
            weight = match.info.weight if match.info.weight > 0 else cfg.weight('weight.keyword')
            out.append(Indicator('keyword:' + match.word, f'The text contains the word "{match.word}", often used in scams.', weight, IndicatorCategory.KEYWORD, match.word))
            res.keywords.append(match)
        punct = sum(c in '!?' for c in msg)
        if punct >= 4 or '!!!' in msg or '???' in msg:
            out.append(Indicator('excessive_punct', 'The message uses a lot of exclamation or question marks to grab attention.', cfg.weight('weight.excessive_punct'), IndicatorCategory.MESSAGE, ''))
        letters = sum(is_alpha_char(c) for c in msg)
        upper = sum('A' <= c <= 'Z' for c in msg)
        if letters >= 15 and upper * 10 >= letters * 6:
            out.append(Indicator('all_caps', 'Much of the message is written in capital letters, which is a pressure tactic.', cfg.weight('weight.all_caps'), IndicatorCategory.MESSAGE, ''))
        if self._has_long_run(msg, 4, True):
            out.append(Indicator('repeated_chars', 'The message has stretched-out words such as "heyyyy", common in spam.', cfg.weight('weight.repeated_chars'), IndicatorCategory.MESSAGE, ''))
        for token in split_any(msg, ' \t\r\n'):
            lower = token.lower()
            if len(token) < 24 or '://' in token or lower.startswith('www.'):
                continue
            letter = digit = False
            allowed = True
            for c in token:
                letter = letter or is_alpha_char(c)
                digit = digit or is_digit_char(c)
                allowed = allowed and (is_alnum_char(c) or c in '+/=_-')
            if allowed and letter and digit:
                out.append(Indicator('encoded_text', 'The message contains a long scrambled-looking string that may hide something.', cfg.weight('weight.encoded_text'), IndicatorCategory.MESSAGE, ''))
                break
        count = 0
        max_urls = self.data.config.value('limit.max_urls')
        for url in UrlParser.extract_urls(msg, self.data.known_tlds):
            if count >= max_urls:
                break
            count += 1
            ua = self.url_analyzer.analyze(url)
            out.extend(ua.indicators)
            res.urls.append(ua)
        return res
