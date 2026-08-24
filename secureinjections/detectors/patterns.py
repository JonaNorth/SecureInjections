"""Bounded, non-executing transformations for detecting common obfuscation."""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
_BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
_HEX_ESCAPE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_SEPARATED_WORD = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z](?:\s*[._\-·•:/|]\s*)){4,}"
    r"[A-Za-z][._\-·•:/|]?(?![A-Za-z0-9])"
)
_SPACED_WORD = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z][ \t]){4,}[A-Za-z](?![A-Za-z0-9])")
_SPACED_TOKEN = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z0-9][ \t]){7,}[A-Za-z0-9](?![A-Za-z0-9])")
_ISOLATED_SEPARATOR = re.compile(r"\s+[._\-·•:/|]\s+")
_HIGH_VALUE_SPLIT_TERMS = frozenset(
    {
        "agent",
        "admin",
        "access",
        "anweisungen",
        "assistant",
        "begin",
        "command",
        "connector",
        "credential",
        "credentials",
        "download",
        "environment",
        "execute",
        "ignore",
        "ignorer",
        "ignoriere",
        "ignorera",
        "install",
        "instructions",
        "https",
        "instrucciones",
        "instrukcje",
        "instruktioner",
        "instruksjoner",
        "instructies",
        "istruzioni",
        "internal",
        "localhost",
        "metadata",
        "override",
        "passwd",
        "password",
        "passwords",
        "printenv",
        "private",
        "privatekey",
        "prompt",
        "read",
        "reveal",
        "script",
        "secret",
        "secrets",
        "select",
        "send",
        "shell",
        "systemprompt",
        "token",
        "tokens",
        "union",
        "upload",
        "zignoruj",
    }
)
_CONFUSABLES = str.maketrans(
    {
        "Α": "A",
        "А": "A",
        "Β": "B",
        "В": "B",
        "Ε": "E",
        "Е": "E",
        "Η": "H",
        "Н": "H",
        "Ι": "I",
        "І": "I",
        "Κ": "K",
        "К": "K",
        "Μ": "M",
        "М": "M",
        "Ν": "N",
        "О": "O",
        "Ο": "O",
        "Ρ": "P",
        "Р": "P",
        "С": "C",
        "Τ": "T",
        "Т": "T",
        "Χ": "X",
        "Х": "X",
        "а": "a",
        "α": "a",
        "е": "e",
        "ε": "e",
        "і": "i",
        "ι": "i",
        "ο": "o",
        "о": "o",
        "р": "p",
        "ρ": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "ν": "v",
        "к": "k",
        "м": "m",
        "т": "t",
    }
)


def _collapse_separated(match: re.Match[str]) -> str:
    collapsed = re.sub(r"[\s._\-·•:/|]", "", match.group(0))
    raw = match.group(0)
    structural = re.sub(r"[\s._\-·•|]", "", raw).casefold()
    if collapsed.casefold() in _HIGH_VALUE_SPLIT_TERMS or structural.startswith(
        ("http://", "https://")
    ):
        return re.sub(r"[\s._\-·•|]", "", raw)
    return raw


def _reconstructed_variant(text: str) -> str:
    """Rebuild high-confidence character-split tokens without globally stripping punctuation."""
    rebuilt = _SEPARATED_WORD.sub(_collapse_separated, text)
    rebuilt = _SPACED_TOKEN.sub(_collapse_separated, rebuilt)
    rebuilt = _SPACED_WORD.sub(_collapse_separated, rebuilt)
    return _ISOLATED_SEPARATOR.sub(" ", rebuilt)


def _base64_decodes(text: str, max_candidates: int, max_length: int) -> list[str]:
    decoded: list[str] = []
    for candidate in _BASE64_CANDIDATE.findall(text)[:max_candidates]:
        try:
            raw = base64.b64decode(candidate, validate=True)
            value = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(char.isprintable() or char.isspace() for char in value)
        if value and printable / len(value) >= 0.85:
            decoded.append(value[:max_length])
    return decoded


def _hex_decodes(text: str, max_candidates: int, max_length: int) -> list[str]:
    candidates = _HEX_ESCAPE.findall(text)[:max_candidates]
    if not candidates:
        return []

    decoded_count = 0

    def decode_candidate(match: re.Match[str]) -> str:
        nonlocal decoded_count
        if decoded_count >= max_candidates:
            return match.group(0)
        try:
            value = bytes.fromhex(match.group(0).replace("\\x", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)
        decoded_count += 1
        return value

    return [_HEX_ESCAPE.sub(decode_candidate, text)[:max_length]]


def text_variants(
    text: str, *, max_candidates: int = 8, max_decoded_length: int = 32_768
) -> tuple[str, ...]:
    """Return bounded normalized/decoded variants without evaluating hostile input."""
    normalized = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_CONFUSABLES)
    url_decoded = unquote(unquote(normalized))
    html_decoded = html.unescape(normalized)
    variants = [normalized]
    reconstructed = _reconstructed_variant(normalized)
    if reconstructed != normalized:
        variants.append(reconstructed[:max_decoded_length])
    if url_decoded != normalized:
        variants.append(url_decoded[:max_decoded_length])
    if html_decoded != normalized:
        variants.append(html_decoded[:max_decoded_length])
    variants.extend(_base64_decodes(normalized, max_candidates, max_decoded_length))
    variants.extend(_hex_decodes(normalized, max_candidates, max_decoded_length))
    return tuple(dict.fromkeys(variants))
