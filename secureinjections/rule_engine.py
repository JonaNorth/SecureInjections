"""Versioned rule loading, validation, compilation, and deterministic matching."""

from __future__ import annotations

import re
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from .config import CustomPattern
from .models import Rule, RuleMatch
from .safe_yaml import bounded_safe_load

SEVERITY_WEIGHTS = {"low": 10, "medium": 25, "high": 45, "critical": 70}
REQUIRED_FIELDS = {
    "id",
    "name",
    "category",
    "description",
    "severity",
    "patterns",
    "tags",
    "references",
    "enabled",
}


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    rule: Rule
    patterns: tuple[re.Pattern[str], ...]
    literal_patterns: tuple[str, ...]


@lru_cache(maxsize=8_192)
def _compile_pattern(pattern: str) -> re.Pattern[str]:
    """Reuse immutable compiled signatures across Scanner instances and threads."""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def bundled_rules_path() -> Path:
    """Return the canonical Threat Rule v1 source of bundled signatures."""
    return Path(str(files("secureinjections.rules").joinpath("canonical")))


def legacy_bundled_rules_path() -> Path:
    return Path(str(files("secureinjections.rules").joinpath("v1")))


def _validate_rule(raw: Any, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleValidationError(f"{source}: each rule must be a mapping")
    missing = REQUIRED_FIELDS - raw.keys()
    if missing:
        raise RuleValidationError(f"{source}: missing fields: {', '.join(sorted(missing))}")
    if not isinstance(raw["id"], str) or not re.fullmatch(r"[A-Z][A-Z0-9]+-\d{3}", raw["id"]):
        raise RuleValidationError(f"{source}: invalid rule id {raw['id']!r}")
    if raw["severity"] not in SEVERITY_WEIGHTS:
        raise RuleValidationError(f"{source}: invalid severity for {raw['id']}")
    if not isinstance(raw["patterns"], list) or not raw["patterns"]:
        raise RuleValidationError(f"{source}: {raw['id']} requires at least one pattern")
    try:
        for pattern in raw["patterns"]:
            if not isinstance(pattern, str):
                raise TypeError
            if len(pattern) > 4_096:
                raise RuleValidationError(f"{source}: pattern exceeds 4096 characters")
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except (re.error, TypeError) as exc:
        raise RuleValidationError(f"{source}: invalid pattern in {raw['id']}: {exc}") from exc
    for list_field in ("tags", "references"):
        if not isinstance(raw[list_field], list) or not all(
            isinstance(item, str) for item in raw[list_field]
        ):
            raise RuleValidationError(f"{source}: {list_field} must be a string list")
    if not isinstance(raw["enabled"], bool):
        raise RuleValidationError(f"{source}: enabled must be boolean")
    return Rule(
        id=raw["id"],
        name=str(raw["name"]),
        category=str(raw["category"]),
        description=str(raw["description"]),
        severity=raw["severity"],
        patterns=tuple(raw["patterns"]),
        tags=tuple(raw["tags"]),
        references=tuple(raw["references"]),
        enabled=raw["enabled"],
    )


def _load_rules_from_roots(roots: tuple[Path, ...]) -> tuple[Rule, ...]:
    loaded: list[Rule] = []
    ids: set[str] = set()
    for root in roots:
        if root.is_symlink():
            raise RuleValidationError(f"symlinked legacy rule path is not accepted: {root}")
        candidates = sorted(root.glob("*.yml")) if root.is_dir() else [root]
        if not candidates:
            raise RuleValidationError(f"no .yml rule files found at {root}")
        for path in candidates:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
                raise RuleValidationError(f"unsafe or oversized legacy rule file: {path}")
            try:
                document = bounded_safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise RuleValidationError(f"unable to load {path}: {exc}") from exc
            if not isinstance(document, dict) or document.get("version") != 1:
                raise RuleValidationError(f"{path}: expected rule schema version 1")
            rules = document.get("rules")
            if not isinstance(rules, list):
                raise RuleValidationError(f"{path}: rules must be a list")
            for index, raw in enumerate(rules):
                rule = _validate_rule(raw, f"{path}:{index + 1}")
                if rule.id in ids:
                    raise RuleValidationError(f"duplicate rule id: {rule.id}")
                ids.add(rule.id)
                loaded.append(rule)
    return tuple(loaded)


@lru_cache(maxsize=1)
def _load_bundled_rules() -> tuple[Rule, ...]:
    from .rules.loader import load_bundled_threat_rules, threat_rule_to_legacy

    return tuple(threat_rule_to_legacy(rule) for rule in load_bundled_threat_rules())


def load_rules(paths: Iterable[Path] = ()) -> tuple[Rule, ...]:
    """Load rules, caching only immutable bundled resources.

    External paths are intentionally re-read for each new Scanner so an administrative feed
    activation is visible without unsafe cache invalidation. Existing Scanner instances retain
    their immutable compiled rule set while an update is installed.
    """
    roots = tuple(paths)
    if roots:
        warnings.warn(
            "aggregate legacy rule files are deprecated; migrate to Threat Rule v1",
            DeprecationWarning,
            stacklevel=2,
        )
        return _load_rules_from_roots(roots)
    return _load_bundled_rules()


def custom_rules(patterns: Iterable[CustomPattern]) -> tuple[Rule, ...]:
    rules = []
    for item in patterns:
        raw = {
            "id": item.id,
            "name": item.name,
            "category": item.category,
            "description": item.description,
            "severity": item.severity,
            "patterns": [item.pattern],
            "tags": ["custom"],
            "references": [],
            "enabled": True,
        }
        rules.append(_validate_rule(raw, "custom pattern"))
    return tuple(rules)


class RuleEngine:
    """Compiled regex engine. Rules are compiled once and reused across scans."""

    def __init__(self, rules: Iterable[Rule], disabled_rule_ids: frozenset[str] = frozenset()):
        self.rules = tuple(
            rule for rule in rules if rule.enabled and rule.id not in disabled_rule_ids
        )
        self._compiled = tuple(
            _CompiledRule(
                rule=rule,
                patterns=tuple(_compile_pattern(pattern) for pattern in rule.patterns),
                literal_patterns=tuple(item.casefold() for item in rule.literal_patterns),
            )
            for rule in self.rules
        )

    def match(
        self, variants: Iterable[str], *, excluded_categories: frozenset[str] = frozenset()
    ) -> tuple[RuleMatch, ...]:
        texts = tuple(variants)
        folded_texts = tuple(text.casefold() for text in texts)
        matches: list[RuleMatch] = []
        for compiled in self._compiled:
            rule = compiled.rule
            if rule.category in excluded_categories:
                continue
            regex_match = any(
                pattern.search(text) for text in texts for pattern in compiled.patterns
            )
            literal_match = any(
                literal in text for text in folded_texts for literal in compiled.literal_patterns
            )
            if regex_match or literal_match:
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        confidence=rule.confidence,
                        taxonomy=rule.taxonomy,
                        legacy_rule_id=rule.legacy_id,
                    )
                )
        return tuple(matches)

    def list_rules(self) -> tuple[Rule, ...]:
        return self.rules
