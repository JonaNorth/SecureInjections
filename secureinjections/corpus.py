"""Versioned corpus format, deterministic splits, and offline adversarial mutations."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import random
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .models import Decision

MAX_CORPUS_FILE_BYTES = 32 * 1024 * 1024
MAX_CASE_TEXT_LENGTH = 1_000_000
LABELS = frozenset({"malicious", "benign", "ambiguous"})
DIFFICULTIES = frozenset({"easy", "medium", "hard", "adversarial"})
SPLITS = frozenset({"development", "validation", "holdout"})


class CorpusError(ValueError):
    pass


def deterministic_split(case_id: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(case_id.encode()).digest()[:4], "big") % 100
    return "development" if bucket < 70 else "validation" if bucket < 90 else "holdout"


@dataclass(frozen=True, slots=True)
class CorpusCase:
    id: str
    text: str
    label: str
    expected_decision: Decision
    categories: tuple[str, ...]
    attack_family: str
    language: str
    source_type: str
    difficulty: str
    notes: str
    provenance: str
    license: str
    split: str
    expected_rule_ids: tuple[str, ...] = ()
    parent_case_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["expected_decision"] = self.expected_decision.value
        result["categories"] = list(self.categories)
        result["expected_rule_ids"] = list(self.expected_rule_ids)
        if self.parent_case_id is None:
            result.pop("parent_case_id")
        return result


def _legacy_case(raw: dict[str, Any]) -> dict[str, Any]:
    """Read the v0.2 six-field corpus during the v0.3 deprecation window."""
    from .rules.migration import canonical_id

    decision = str(raw["expected_decision"])
    return {
        "id": raw["id"],
        "text": raw["text"],
        "label": "benign" if decision == "allow" else "malicious",
        "expected_decision": decision,
        "categories": raw["expected_categories"],
        "attack_family": "legacy-regression",
        "language": "en",
        "source_type": "user",
        "difficulty": "medium",
        "notes": raw["notes"],
        "provenance": "SecureInjections v0.2 regression corpus",
        "license": "Apache-2.0",
        "split": deterministic_split(str(raw["id"])),
        "expected_rule_ids": [canonical_id(value) for value in raw["expected_rule_ids"]],
    }


def load_corpus(path: Path, *, split: str | None = None) -> tuple[CorpusCase, ...]:
    if split is not None and split not in SPLITS:
        raise CorpusError(f"unknown corpus split: {split}")
    files = sorted(path.rglob("*.jsonl")) if path.is_dir() else [path]
    if not files:
        raise CorpusError(f"no JSONL corpus files found at {path}")
    cases: list[CorpusCase] = []
    ids: set[str] = set()
    for file in files:
        if file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_CORPUS_FILE_BYTES:
            raise CorpusError(f"unsafe or oversized corpus file: {file}")
        for line_number, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                loaded = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(f"{file}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(loaded, dict):
                raise CorpusError(f"{file}:{line_number}: case must be an object")
            raw: dict[str, Any] = (
                _legacy_case(loaded)
                if "expected_categories" in loaded and "label" not in loaded
                else loaded
            )
            required = {
                "id",
                "text",
                "label",
                "expected_decision",
                "categories",
                "attack_family",
                "language",
                "source_type",
                "difficulty",
                "notes",
                "provenance",
                "license",
                "split",
            }
            optional = {"expected_rule_ids", "parent_case_id"}
            if set(raw) - required - optional or required - set(raw):
                raise CorpusError(f"{file}:{line_number}: invalid corpus fields")
            case_id = raw["id"]
            text = raw["text"]
            if not isinstance(case_id, str) or not case_id or case_id in ids:
                raise CorpusError(f"{file}:{line_number}: invalid or duplicate case id")
            if not isinstance(text, str) or len(text) > MAX_CASE_TEXT_LENGTH:
                raise CorpusError(f"{file}:{line_number}: invalid or oversized text")
            if raw["label"] not in LABELS or raw["difficulty"] not in DIFFICULTIES:
                raise CorpusError(f"{file}:{line_number}: invalid label or difficulty")
            if raw["split"] not in SPLITS:
                raise CorpusError(f"{file}:{line_number}: invalid split")
            if raw["split"] != deterministic_split(case_id):
                raise CorpusError(f"{file}:{line_number}: non-deterministic split assignment")
            categories = raw["categories"]
            expected_ids = raw.get("expected_rule_ids", [])
            if not isinstance(categories, list) or not all(isinstance(x, str) for x in categories):
                raise CorpusError(f"{file}:{line_number}: categories must be a string list")
            if not isinstance(expected_ids, list) or not all(
                isinstance(x, str) for x in expected_ids
            ):
                raise CorpusError(f"{file}:{line_number}: expected_rule_ids must be a string list")
            string_fields = (
                "attack_family",
                "language",
                "source_type",
                "notes",
                "provenance",
                "license",
            )
            if any(not isinstance(raw[field], str) for field in string_fields):
                raise CorpusError(f"{file}:{line_number}: metadata fields must be strings")
            try:
                decision = Decision(raw["expected_decision"])
            except (TypeError, ValueError) as exc:
                raise CorpusError(f"{file}:{line_number}: invalid expected_decision") from exc
            parent = raw.get("parent_case_id")
            if parent is not None and not isinstance(parent, str):
                raise CorpusError(f"{file}:{line_number}: invalid parent_case_id")
            ids.add(case_id)
            case = CorpusCase(
                id=case_id,
                text=text,
                label=str(raw["label"]),
                expected_decision=decision,
                categories=tuple(categories),
                attack_family=str(raw["attack_family"]),
                language=str(raw["language"]),
                source_type=str(raw["source_type"]),
                difficulty=str(raw["difficulty"]),
                notes=str(raw["notes"]),
                provenance=str(raw["provenance"]),
                license=str(raw["license"]),
                split=str(raw["split"]),
                expected_rule_ids=tuple(expected_ids),
                parent_case_id=parent,
            )
            if split is None or case.split == split:
                cases.append(case)
    if not cases:
        raise CorpusError("corpus is empty for the requested split")
    return tuple(cases)


def _random_case(text: str, rng: random.Random) -> str:
    return "".join(char.upper() if rng.random() < 0.5 else char.lower() for char in text)


def mutate_text(text: str, mutation: str, rng: random.Random) -> str:
    """Apply one bounded deterministic, non-executing adversarial transformation."""
    if mutation == "random_casing":
        return _random_case(text, rng)
    if mutation == "whitespace":
        return " ".join(text.split()).replace(" ", "  ")
    if mutation == "punctuation":
        return text.replace(" ", rng.choice((" . ", " / ", " _ ")))
    if mutation == "zero_width":
        return "\u200b".join(text)
    if mutation == "unicode":
        substitutions: dict[str, str | int | None] = {
            "a": "ａ",
            "e": "ｅ",
            "i": "ｉ",
            "o": "ο",
        }
        return text.translate(str.maketrans(substitutions))
    if mutation == "url_encoding":
        return quote(text, safe="")
    if mutation == "base64":
        return base64.b64encode(text.encode()).decode()
    if mutation == "hex_escape":
        return "".join(f"\\x{byte:02x}" for byte in text.encode())
    if mutation == "word_splitting":
        words = text.split()
        return " ".join("_".join(word) if len(word) > 6 else word for word in words)
    if mutation == "markdown":
        return f"> **{text}**"
    if mutation == "html":
        return f'<div data-content="untrusted">{html.escape(text)}</div>'
    if mutation == "json":
        return json.dumps({"record": {"message": text}}, ensure_ascii=False)
    if mutation == "delimiters":
        return f"<<<>>>[[[{text}]]]<<<>>>"
    raise CorpusError(f"unknown mutation: {mutation}")


MUTATIONS = (
    "random_casing",
    "whitespace",
    "punctuation",
    "zero_width",
    "unicode",
    "url_encoding",
    "base64",
    "hex_escape",
    "word_splitting",
    "markdown",
    "html",
    "json",
    "delimiters",
)


def mutate_cases(
    cases: tuple[CorpusCase, ...], *, seed: int, mutations: tuple[str, ...] = MUTATIONS
) -> tuple[CorpusCase, ...]:
    generated: list[CorpusCase] = []
    for case in cases:
        # Never recursively mutate generated cases when a corpus directory contains both base
        # and derived fixtures. This keeps release mutation matrices comparable and bounded.
        if case.label != "malicious" or case.parent_case_id is not None:
            continue
        for mutation in mutations:
            rng = random.Random(f"{seed}:{case.id}:{mutation}")
            case_id = f"MUT-{case.id}-{mutation}"
            generated.append(
                replace(
                    case,
                    id=case_id,
                    text=mutate_text(case.text, mutation, rng),
                    difficulty="adversarial",
                    split=deterministic_split(case_id),
                    parent_case_id=case.id,
                    notes=f"Deterministic {mutation} mutation (seed {seed}).",
                )
            )
    return tuple(generated)


def write_corpus(cases: tuple[CorpusCase, ...], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(
            json.dumps(case.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for case in cases
        ),
        encoding="utf-8",
    )
