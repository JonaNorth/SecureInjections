"""Safe loading and conversion of first-class threat rules."""

from __future__ import annotations

import json
from collections.abc import Iterable
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from ..models import Rule
from ..safe_yaml import bounded_safe_load
from .models import ThreatRule
from .validator import ThreatRuleValidationError, validate_threat_rule

MAX_RULE_FILE_BYTES = 1_048_576
MAX_RULE_FILES = 100_000


def _rule_files(path: Path) -> tuple[Path, ...]:
    if path.is_symlink():
        raise ThreatRuleValidationError(f"symlinked rule paths are not accepted: {path}")
    if path.is_file():
        return (path,)
    if not path.is_dir():
        raise ThreatRuleValidationError(f"rule path does not exist: {path}")
    candidates = tuple(
        candidate
        for candidate in sorted(path.rglob("*"))
        if candidate.suffix.lower() in {".yml", ".yaml", ".json"} and candidate.is_file()
    )
    if len(candidates) > MAX_RULE_FILES:
        raise ThreatRuleValidationError(f"too many rule files below {path}")
    for candidate in candidates:
        if candidate.is_symlink():
            raise ThreatRuleValidationError(f"symlinked rule file is not accepted: {candidate}")
    return candidates


def _read_document(path: Path) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ThreatRuleValidationError(f"unable to inspect {path}: {exc}") from exc
    if size > MAX_RULE_FILE_BYTES:
        raise ThreatRuleValidationError(f"rule file exceeds 1 MiB: {path}")
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text) if path.suffix.lower() == ".json" else bounded_safe_load(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ThreatRuleValidationError(f"unable to parse {path}: {exc}") from exc


def load_threat_rules(
    paths: Iterable[Path], *, quality_gate: bool = False
) -> tuple[ThreatRule, ...]:
    rules: list[ThreatRule] = []
    ids: set[str] = set()
    for root in paths:
        for path in _rule_files(root):
            document = _read_document(path)
            # Repository metadata and JSON schemas are not threat rules.
            if path.name == "migration-manifest.json" or (
                isinstance(document, dict) and "schema_version" not in document
            ):
                continue
            rule = validate_threat_rule(document, source=str(path), quality_gate=quality_gate)
            if rule.id in ids:
                raise ThreatRuleValidationError(f"duplicate threat rule id: {rule.id}")
            ids.add(rule.id)
            rules.append(rule)
    if not rules:
        raise ThreatRuleValidationError("no Threat Rule v1 documents found")
    return tuple(rules)


@lru_cache(maxsize=1)
def load_bundled_threat_rules() -> tuple[ThreatRule, ...]:
    """Load and cache immutable packaged Threat Rule v1 objects."""
    path = Path(str(files("secureinjections.rules").joinpath("canonical")))
    return load_threat_rules((path,), quality_gate=True)


def threat_rule_to_legacy(rule: ThreatRule) -> Rule:
    return Rule(
        id=rule.id,
        name=rule.name,
        category=rule.category,
        description=rule.description,
        severity=rule.severity,
        patterns=tuple(rule.regex_patterns),
        literal_patterns=tuple(rule.literal_patterns),
        tags=rule.tags,
        references=rule.references,
        enabled=rule.enabled and rule.status != "deprecated",
        confidence=rule.confidence,
        taxonomy=rule.taxonomy,
        legacy_id=rule.legacy_id,
    )
