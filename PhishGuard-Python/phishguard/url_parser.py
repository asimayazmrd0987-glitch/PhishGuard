"""Strict URL-like text parser and link extraction; does not access the network."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .ds import CustomSet
from .text_utils import trim, is_alnum_char, is_all_digits, split_any


def looks_like_url(line: str) -> bool:
    """Deliberately simple URL-vs-message heuristic shared by the CLI and UI."""
    return bool(line) and ' ' not in line and ('://' in line or '.' in line)

@dataclass
class ParsedUrl:
    valid: bool = False
    error: str = ''
    original: str = ''
    had_scheme: bool = True
    scheme: str = ''
    userinfo: str = ''
    host: str = ''
    path: str = ''
    query: str = ''
    fragment: str = ''
    port: int = -1
    host_is_ip: bool = False
    labels: list[str] = field(default_factory=list)
    tld: str = ''
    registered_domain: str = ''
    registered_label: str = ''
    subdomain_count: int = 0

class UrlParser:
    MAX_URL_LENGTH = 2048

    def __init__(self, public_suffixes: CustomSet[str] | None = None):
        self.suffixes = public_suffixes

    def parse(self, raw: str) -> ParsedUrl:
        p = ParsedUrl(original=raw)
        def fail(message: str) -> ParsedUrl:
            p.valid = False; p.error = message; return p
        value = trim(raw)
        if not value: return fail('nothing was entered')
        if len(value) > self.MAX_URL_LENGTH: return fail('the link is extremely long')
        if any(ord(c) <= 0x20 or ord(c) == 0x7f for c in value):
            return fail('the link contains spaces or control characters')

        sep = value.find('://')
        scheme_ok = sep > 0 and all(is_alnum_char(c) or c in '+-.' for c in value[:sep])
        if scheme_ok:
            p.scheme = value[:sep].lower()
            rest = value[sep + 3:]
        else:
            p.had_scheme = False
            p.scheme = 'http'
            rest = value

        auth_end_candidates = [i for i in (rest.find('/'), rest.find('?'), rest.find('#')) if i >= 0]
        auth_end = min(auth_end_candidates) if auth_end_candidates else len(rest)
        authority, remainder = rest[:auth_end], rest[auth_end:]
        if not authority: return fail('the website name is missing')
        host_port = authority
        at = authority.rfind('@')
        if at >= 0:
            p.userinfo = authority[:at]
            host_port = authority[at + 1:]
        if not host_port: return fail('the website name is missing')

        port_text = ''
        if host_port.startswith('['):
            close = host_port.find(']')
            if close < 0:
                return fail('the address is not formatted correctly')
            p.host = host_port[1:close].lower()
            try:
                ipaddress.IPv6Address(p.host)
            except ValueError:
                return fail('the IP address is not valid')
            p.host_is_ip = True
            if close + 1 < len(host_port):
                if host_port[close + 1] != ':':
                    return fail('the address is not formatted correctly')
                port_text = host_port[close + 2:]
        else:
            colon = host_port.rfind(':')
            if colon < 0:
                p.host = host_port.lower()
            else:
                p.host = host_port[:colon].lower()
                port_text = host_port[colon + 1:]
        if port_text:
            if not is_all_digits(port_text) or len(port_text) > 5 or int(port_text) > 65535:
                return fail('the port number is not valid')
            p.port = int(port_text)
        while p.host.endswith('.') and not p.host_is_ip:
            p.host = p.host[:-1]
        if not p.host: return fail('the website name is missing')

        tail = remainder
        hash_pos = tail.find('#')
        if hash_pos >= 0:
            p.fragment = tail[hash_pos + 1:]
            tail = tail[:hash_pos]
        query_pos = tail.find('?')
        if query_pos >= 0:
            p.query = tail[query_pos + 1:]
            tail = tail[:query_pos]
        p.path = tail

        if p.host_is_ip:
            p.registered_domain = p.host
            p.valid = True
            return p

        for c in p.host:
            if not (is_alnum_char(c) or c in '-.' or ord(c) >= 128):
                return fail('the website name contains unusual characters')
        if len(p.host) > 253: return fail('the website name is too long')
        p.labels = p.host.split('.')
        for label in p.labels:
            if not label: return fail('the website name has an empty section')
            if len(label) > 63: return fail('part of the website name is too long')
            if label.startswith('-') or label.endswith('-'):
                return fail('part of the website name starts or ends with a hyphen')
        if len(p.labels) == 4:
            all_numeric = all(is_all_digits(label) and len(label) <= 3 for label in p.labels)
            if all_numeric:
                try:
                    ipaddress.IPv4Address(p.host)
                except ValueError:
                    return fail('the number address is not valid')
                p.host_is_ip = True
                p.registered_domain = p.host
                p.registered_label = p.host
                p.valid = True
                return p
        n = len(p.labels)
        p.tld = p.labels[-1]
        suffix_labels = 1
        if self.suffixes and n >= 3 and self.suffixes.contains(p.labels[-2] + '.' + p.labels[-1]):
            suffix_labels = 2
        if n > suffix_labels:
            reg = n - suffix_labels - 1
            p.registered_label = p.labels[reg]
            p.registered_domain = '.'.join(p.labels[reg:])
            p.subdomain_count = reg
        else:
            p.registered_label = p.labels[0]
            p.registered_domain = p.host
            p.subdomain_count = 0
        p.valid = True
        return p

    @staticmethod
    def extract_urls(text: str, known_tlds: CustomSet[str]) -> list[str]:
        urls: list[str] = []
        seen = CustomSet[str]()
        for token in split_any(text, ' \t\r\n'):
            while token and token[0] in '([{<"\'': token = token[1:]
            while token and token[-1] in '.,;:!?)]}>"\'': token = token[:-1]
            if not token: continue
            lower = token.lower()
            accept = lower.startswith(('http://', 'https://', 'www.'))
            if not accept and '@' not in lower:
                end_candidates = [i for i in (lower.find('/'), lower.find('?'), lower.find('#')) if i >= 0]
                end = min(end_candidates) if end_candidates else len(lower)
                host = lower[:end]
                dot = host.rfind('.')
                if dot > 0 and dot + 1 < len(host):
                    chars = all(is_alnum_char(c) or c in '-.' for c in host)
                    accept = chars and known_tlds.contains(host[dot + 1:]) and '..' not in host
            if accept and seen.insert(lower): urls.append(token)
        return urls
