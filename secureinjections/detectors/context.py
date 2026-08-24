"""Bounded structural and multilingual presentation-context analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from ..models import ContextEvidence

_MAX_CONTEXT_CHARS = 65_536
_REFERENCE_SPAN = re.compile(
    r"```.{0,8192}?```|`[^`\n]{1,4096}`|\"[^\"\n]{1,4096}\"|"
    r"'[^'\n]{1,4096}'|“[^”\n]{1,4096}”|‘[^’\n]{1,4096}’|"
    r"«[^»\n]{1,4096}»|‹[^›\n]{1,4096}›",
    re.DOTALL,
)
_CODE_BLOCK = re.compile(r"```.{0,8192}?```", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]{1,4096}`")
_MARKDOWN_QUOTE = re.compile(r"(?m)^\s{0,3}>\s+\S")
_JSON_STRING = re.compile(r"\"[^\"\n]{1,128}\"\s*:\s*\"[^\"\n]{1,4096}\"")
_XML_VALUE = re.compile(r"<([A-Za-z][\w:.-]{0,63})\b[^>]{0,256}>.{1,4096}?</\1>", re.DOTALL)
_LOG_FIELD = re.compile(
    r"\b(?:message|payload|record|entry|event|log|details|description)\s*[:=]", re.IGNORECASE
)
_DIRECT_START = re.compile(
    r"^\s*(?:please\s+|kindly\s+|(?:you|the\s+(?:agent|assistant|model))\s+(?:must|should)\s+)?",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ContextAnalysis:
    evidence: tuple[ContextEvidence, ...]
    kinds: frozenset[str]
    languages: frozenset[str]
    reference_framing: bool
    direct_imperative: bool


def _load_language_patterns() -> dict[str, re.Pattern[str]]:
    path = files("secureinjections").joinpath("context-signals.json")
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "languages"}:
        raise RuntimeError("context signal data is invalid")
    if raw["schema_version"] != 1 or not isinstance(raw["languages"], dict):
        raise RuntimeError("unsupported context signal data")
    by_signal: dict[str, list[str]] = {
        "education": [],
        "descriptive": [],
        "imperative": [],
    }
    for language, signals in raw["languages"].items():
        if not isinstance(language, str) or not isinstance(signals, dict):
            raise RuntimeError("context language entry is invalid")
        if set(signals) != {"education", "descriptive", "imperative"}:
            raise RuntimeError("context language signal fields are invalid")
        for name, patterns in signals.items():
            if (
                not isinstance(patterns, list)
                or not patterns
                or not all(
                    isinstance(pattern, str) and len(pattern) <= 2048 for pattern in patterns
                )
            ):
                raise RuntimeError("context language patterns are invalid")
            by_signal[name].append(f"(?P<{name}_{language}>(?:" + ")|(?:".join(patterns) + "))")
    return {
        name: re.compile("|".join(alternatives), re.IGNORECASE)
        for name, alternatives in by_signal.items()
    }


_LANGUAGE_PATTERNS = _load_language_patterns()


def strip_reference_spans(text: str) -> tuple[str, bool]:
    """Replace bounded quoted/code spans with spaces while preserving offsets."""

    found = False

    def replace(match: re.Match[str]) -> str:
        nonlocal found
        found = True
        return " " * len(match.group(0))

    return _REFERENCE_SPAN.sub(replace, text), found


class ContextAnalyzer:
    """Classify presentation context; never decide whether content is safe."""

    def analyze(self, text: str) -> ContextAnalysis:
        bounded = text[:_MAX_CONTEXT_CHARS]
        kinds: set[str] = set()
        languages: set[str] = set()
        education = descriptive = False
        for name in ("education", "descriptive"):
            for match in _LANGUAGE_PATTERNS[name].finditer(bounded):
                if match.lastgroup is not None:
                    languages.add(match.lastgroup.rsplit("_", 1)[-1])
                if name == "education":
                    education = True
                else:
                    descriptive = True

        structural = {
            "code_block": bool(_CODE_BLOCK.search(bounded)),
            "inline_code": bool(_INLINE_CODE.search(bounded)),
            "markdown_quote": bool(_MARKDOWN_QUOTE.search(bounded)),
            "json_string": bool(_JSON_STRING.search(bounded)),
            "xml_value": bool(_XML_VALUE.search(bounded)),
            "log_field": bool(_LOG_FIELD.search(bounded)),
        }
        kinds.update(name for name, present in structural.items() if present)
        outside_references, has_reference = strip_reference_spans(bounded)
        if has_reference:
            kinds.add("quotation")
        question = "?" in bounded and education
        if education:
            kinds.add("security_explanation")
        if descriptive:
            kinds.add("descriptive_attack_reference")
        if question:
            kinds.add("question_about_attack")

        start = _DIRECT_START.match(outside_references)
        start_offset = start.end() if start else 0
        imperative = _LANGUAGE_PATTERNS["imperative"].match(outside_references, start_offset)
        imperative_language = (
            imperative.lastgroup.rsplit("_", 1)[-1]
            if imperative is not None and imperative.lastgroup is not None
            else None
        )
        direct_imperative = imperative is not None and (
            not languages or imperative_language in languages
        )
        if direct_imperative:
            kinds.add("direct_imperative")

        reference_framing = has_reference and (education or descriptive or question)
        if reference_framing:
            kinds.add("quoted_security_example")

        evidence: list[ContextEvidence] = []
        language = sorted(languages)[0] if len(languages) == 1 else None
        if education:
            evidence.append(ContextEvidence("security_explanation", 0.86, -15.0, language))
        if descriptive:
            evidence.append(ContextEvidence("descriptive_attack_reference", 0.82, -8.0, language))
        if question:
            evidence.append(ContextEvidence("question_about_attack", 0.84, -6.0, language))
        if reference_framing:
            evidence.append(ContextEvidence("quoted_security_example", 0.9, -12.0, language))
        if (structural["code_block"] or structural["inline_code"]) and (education or descriptive):
            evidence.append(ContextEvidence("documentation_code_example", 0.82, -7.0, language))
        if (structural["json_string"] or structural["xml_value"]) and (education or descriptive):
            evidence.append(ContextEvidence("structured_data_example", 0.8, -6.0, language))
        if direct_imperative:
            evidence.append(ContextEvidence("direct_imperative", 0.78, 6.0, language))
        return ContextAnalysis(
            tuple(evidence),
            frozenset(kinds),
            frozenset(languages),
            reference_framing,
            direct_imperative,
        )
