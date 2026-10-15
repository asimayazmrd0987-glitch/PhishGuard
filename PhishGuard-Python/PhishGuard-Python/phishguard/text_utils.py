"""Shared text, validation, data-file and privacy helpers."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import string


def to_lower(value: str) -> str:
    return value.lower()

def trim(value: str) -> str:
    return value.strip(' \t\r\n')

def split(value: str, delim: str) -> list[str]:
    return value.split(delim)

def split_any(value: str, delims: str) -> list[str]:
    out, cur = [], []
    for ch in value:
        if ch in delims:
            if cur:
                out.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    if cur: out.append(''.join(cur))
    return out

def starts_with(value: str, prefix: str) -> bool:
    return value.startswith(prefix)

def ends_with(value: str, suffix: str) -> bool:
    return value.endswith(suffix)

def is_all_digits(value: str) -> bool:
    return bool(value) and all(c.isdigit() and ord(c) < 128 for c in value)

def is_alnum_char(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()

def is_alpha_char(ch: str) -> bool:
    return ch.isascii() and ch.isalpha()

def is_digit_char(ch: str) -> bool:
    return ch.isascii() and ch.isdigit()

def join(parts: list[str], start: int = 0, sep: str = '.') -> str:
    return sep.join(parts[start:])

def normalize_lookalikes(value: str) -> str:
    return value.translate(str.maketrans({'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s'}))

def _is_secret_word(word: str) -> bool:
    word = word.rstrip(':=,.').lower()
    return word in {'password', 'passcode', 'passwd', 'pwd', 'pin', 'otp', 'cvv'}

def _mask_digit_runs(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        if is_digit_char(value[i]):
            j = i
            while j < len(value) and is_digit_char(value[j]): j += 1
            out.append('[digits]' if j - i >= 4 else value[i:j])
            i = j
        else:
            out.append(value[i]); i += 1
    return ''.join(out)

def _clip(value: str, max_len: int) -> str:
    return value if len(value) <= max_len else value[:max_len] + '...'

def redact_sensitive(value: str, max_len: int = 300) -> str:
    tokens = split_any(value, ' \t\r\n')
    out: list[str] = []
    pending_weak = pending_strong = False
    for tok in tokens:
        lower = tok.lower()
        is_url = '://' in lower or lower.startswith('www.')
        if not is_url:
            sep = next((i for i, ch in enumerate(tok) if ch in ':='), -1)
            if sep >= 0 and sep + 1 < len(tok) and _is_secret_word(tok[:sep]):
                tok = tok[:sep + 1] + '[hidden]'
                pending_weak = pending_strong = False
            elif (pending_weak or pending_strong) and lower in {'is', 'are', ':', '='}:
                pending_strong = True
            elif pending_strong:
                tok = '[hidden]'
                pending_weak = pending_strong = False
            elif pending_weak:
                if any(is_digit_char(c) for c in tok): tok = '[hidden]'
                pending_weak = False
            else:
                tok = _mask_digit_runs(tok)
            if tok != '[hidden]' and _is_secret_word(lower):
                colon = lower.endswith((':', '='))
                pending_strong, pending_weak = colon, not colon
        if out: out.append(' ')
        out.append(tok)
    return _clip(''.join(out), max_len)

def redact_url(url: str, max_len: int = 300) -> str:
    value = trim(url)
    scheme = value.find('://')
    auth_start = 0 if scheme < 0 else scheme + 3
    auth_end = min([i for i in (value.find('/', auth_start), value.find('?', auth_start), value.find('#', auth_start)) if i >= 0] or [len(value)])
    at = value.rfind('@', auth_start, auth_end)
    if at >= auth_start:
        value = value[:auth_start] + '[hidden]' + value[at:]
    q = min([i for i in (value.find('?'), value.find('#')) if i >= 0] or [len(value)])
    if q < len(value): value = value[:q] + '?[query hidden]'
    return _clip(value, max_len)

def current_timestamp() -> str:
    return datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')

@dataclass
class DataLine:
    number: int
    text: str

def read_data_lines(path: str | Path) -> list[DataLine]:
    p = Path(path)
    try:
        lines = p.read_text(encoding='utf-8').splitlines()
    except OSError as exc:
        raise RuntimeError(f'cannot open data file: {p}') from exc
    out = []
    for number, line in enumerate(lines, 1):
        line = trim(line)
        if not line or line.startswith('#'):
            continue
        out.append(DataLine(number, line))
    return out
