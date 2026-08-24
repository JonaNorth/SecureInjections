"""Language-neutral intent signals backed by bounded multilingual phrase tables."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

_MAX_CHARS = 65_536
_TOKEN = re.compile(r"[^\W_]+(?:['’][^\W_]+)?", re.UNICODE)
_SUPPORTED_PREFIXES = (
    "ACTION.",
    "TARGET.",
    "RECIPIENT.",
    "DESTINATION.",
    "PERSISTENCE.",
    "PAYLOAD.",
)


@dataclass(frozen=True, slots=True)
class AbstractIntentMatches:
    """Sanitized concepts found in hostile text; matched surface text is never retained."""

    signals: frozenset[str]
    languages: frozenset[str]
    reconstructed_signals: frozenset[str]


def _tokens(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", text[:_MAX_CHARS]).casefold()
    return tuple(_TOKEN.findall(normalized))


class MultilingualIntentLexicon:
    """Compile curated multilingual phrases into one O(n) bounded lookup table."""

    def __init__(self) -> None:
        path = files("secureinjections").joinpath("languages/signals.json")
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "max_phrase_tokens",
            "languages",
        }:
            raise RuntimeError("abstract intent lexicon fields are invalid")
        if raw["schema_version"] != 1 or not isinstance(raw["languages"], dict):
            raise RuntimeError("unsupported abstract intent lexicon")
        max_phrase_tokens = raw["max_phrase_tokens"]
        if not isinstance(max_phrase_tokens, int) or not 1 <= max_phrase_tokens <= 6:
            raise RuntimeError("abstract intent phrase bound is invalid")

        index: dict[tuple[str, ...], set[tuple[str, str]]] = {}
        supported_languages: set[str] = set()
        for language, signals in raw["languages"].items():
            if not isinstance(language, str) or not re.fullmatch(r"[a-z]{2}", language):
                raise RuntimeError("abstract intent language code is invalid")
            if not isinstance(signals, dict) or not signals:
                raise RuntimeError("abstract intent language entry is invalid")
            supported_languages.add(language)
            for signal, phrases in signals.items():
                if not isinstance(signal, str) or not signal.startswith(_SUPPORTED_PREFIXES):
                    raise RuntimeError("abstract intent signal name is invalid")
                if not isinstance(phrases, list) or not phrases:
                    raise RuntimeError("abstract intent phrases are invalid")
                for phrase in phrases:
                    if not isinstance(phrase, str) or not phrase or len(phrase) > 100:
                        raise RuntimeError("abstract intent phrase is invalid")
                    key = _tokens(phrase)
                    if not key or len(key) > max_phrase_tokens:
                        raise RuntimeError("abstract intent phrase exceeds token bound")
                    index.setdefault(key, set()).add((signal, language))
        self.max_phrase_tokens = max_phrase_tokens
        self.supported_languages = frozenset(supported_languages)
        self._index = {key: frozenset(value) for key, value in index.items()}
        self._split_terms = {
            key[0]: value
            for key, value in self._index.items()
            if len(key) == 1
            and 4 <= len(key[0]) <= 18
            and any(signal.startswith("ACTION.") for signal, _ in value)
        }

    def match(self, text: str, *, language_hint: str | None = None) -> AbstractIntentMatches:
        if language_hint is not None and language_hint not in self.supported_languages:
            raise ValueError(f"unsupported language hint: {language_hint}")
        tokens = _tokens(text)
        signals: set[str] = set()
        languages: set[str] = set()
        reconstructed: set[str] = set()

        for start in range(len(tokens)):
            remaining = min(self.max_phrase_tokens, len(tokens) - start)
            for width in range(1, remaining + 1):
                matches = self._index.get(tokens[start : start + width])
                if matches is None:
                    continue
                for signal, language in matches:
                    signals.add(signal)
                    languages.add(language)

        # Reconstruct only bounded runs of single-character tokens whose joined form is a known
        # high-value action. Arbitrary spaced prose is never collapsed.
        index = 0
        while index < len(tokens):
            if len(tokens[index]) != 1:
                index += 1
                continue
            end = index
            while end < len(tokens) and len(tokens[end]) == 1 and end - index < 18:
                end += 1
            for stop in range(end, index + 3, -1):
                joined = "".join(tokens[index:stop])
                matches = self._split_terms.get(joined)
                if matches is None:
                    continue
                for signal, language in matches:
                    signals.add(signal)
                    reconstructed.add(signal)
                    languages.add(language)
                index = stop - 1
                break
            index += 1

        if language_hint is not None:
            languages.add(language_hint)
        return AbstractIntentMatches(
            frozenset(signals), frozenset(languages), frozenset(reconstructed)
        )
