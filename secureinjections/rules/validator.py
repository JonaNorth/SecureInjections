"""Strict validation and quality checks for Threat Rule v1."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from ..version import ENGINE_VERSION, THREAT_RULE_SCHEMA_VERSION
from .models import ThreatRule

RULE_ID_PATTERN = re.compile(
    r"SI-(?:PI|AGENT|SECRET|SSRF|SHELL|SQL|TRAVERSAL|NETWORK|OBFUSCATION)-\d{6}\Z"
)
SEMVER_PATTERN = re.compile(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}(?:[-+][0-9A-Za-z.-]+)?\Z")
SEVERITIES = frozenset({"low", "medium", "high", "critical"})
STATUSES = frozenset({"draft", "testing", "published", "deprecated"})
INDICATOR_STRENGTHS = frozenset({"weak", "moderate", "strong", "critical"})
KNOWN_CATEGORIES = frozenset(
    {
        "prompt_injection",
        "indirect_prompt_injection",
        "agent_manipulation",
        "credential_access",
        "internal_resource_access",
        "file_access",
        "secret_leakage",
        "ssrf",
        "suspicious_url",
        "shell_command",
        "package_manager",
        "sql_injection",
        "path_traversal",
        "obfuscation",
    }
)
KNOWN_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "description",
        "category",
        "severity",
        "confidence",
        "status",
        "created",
        "updated",
        "author",
        "license",
        "tags",
        "references",
        "attack_patterns",
        "regex_patterns",
        "literal_patterns",
        "semantic_examples",
        "negative_examples",
        "platforms",
        "languages",
        "minimum_engine_version",
        "enabled",
        "taxonomy",
        "legacy_id",
        "indicator_strength",
    }
)
REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "description",
        "category",
        "severity",
        "confidence",
        "status",
        "created",
        "updated",
        "author",
        "license",
        "enabled",
    }
)
LIST_FIELDS = (
    "tags",
    "references",
    "attack_patterns",
    "regex_patterns",
    "literal_patterns",
    "semantic_examples",
    "negative_examples",
    "platforms",
    "languages",
)


class ThreatRuleValidationError(ValueError):
    pass


def parse_version(value: str) -> tuple[int, int, int]:
    if not SEMVER_PATTERN.fullmatch(value):
        raise ThreatRuleValidationError(f"invalid semantic version: {value!r}")
    base = re.split(r"[-+]", value, maxsplit=1)[0]
    major, minor, patch = base.split(".")
    return int(major), int(minor), int(patch)


def _date(value: Any, field: str, source: str) -> str:
    if not isinstance(value, str):
        raise ThreatRuleValidationError(f"{source}: {field} must be an ISO date")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ThreatRuleValidationError(f"{source}: invalid {field}: {value!r}") from exc
    return value


def _strings(raw: dict[str, Any], field: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    value = raw.get(field, list(default))
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ThreatRuleValidationError(f"{field} must be a list of non-empty strings")
    return tuple(value)


def validate_threat_rule(
    raw: Any, *, source: str = "rule", quality_gate: bool = False
) -> ThreatRule:
    if not isinstance(raw, dict):
        raise ThreatRuleValidationError(f"{source}: rule must be an object")
    unknown = raw.keys() - KNOWN_FIELDS
    missing = REQUIRED_FIELDS - raw.keys()
    if unknown:
        raise ThreatRuleValidationError(f"{source}: unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ThreatRuleValidationError(f"{source}: missing fields: {', '.join(sorted(missing))}")
    if raw["schema_version"] != THREAT_RULE_SCHEMA_VERSION:
        raise ThreatRuleValidationError(f"{source}: unsupported schema_version")
    if not isinstance(raw["id"], str) or not RULE_ID_PATTERN.fullmatch(raw["id"]):
        raise ThreatRuleValidationError(f"{source}: invalid threat rule id {raw['id']!r}")
    for field in ("name", "description", "category", "author", "license"):
        if not isinstance(raw[field], str) or not raw[field].strip():
            raise ThreatRuleValidationError(f"{source}: {field} must be a non-empty string")
    if raw["severity"] not in SEVERITIES:
        raise ThreatRuleValidationError(f"{source}: invalid severity")
    if raw["status"] not in STATUSES:
        raise ThreatRuleValidationError(f"{source}: invalid status")
    confidence = raw["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        raise ThreatRuleValidationError(f"{source}: confidence must be numeric")
    if not 0.0 <= float(confidence) <= 1.0:
        raise ThreatRuleValidationError(f"{source}: confidence must be between 0 and 1")
    if not isinstance(raw["enabled"], bool):
        raise ThreatRuleValidationError(f"{source}: enabled must be boolean")
    taxonomy = raw.get("taxonomy")
    if taxonomy is not None and (
        not isinstance(taxonomy, str)
        or not re.fullmatch(r"[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+", taxonomy)
    ):
        raise ThreatRuleValidationError(f"{source}: invalid taxonomy category")
    legacy_id = raw.get("legacy_id")
    if legacy_id is not None and (
        not isinstance(legacy_id, str) or not re.fullmatch(r"[A-Z][A-Z0-9]+-\d{3}", legacy_id)
    ):
        raise ThreatRuleValidationError(f"{source}: invalid legacy_id")
    indicator_strength = raw.get("indicator_strength", "moderate")
    if indicator_strength not in INDICATOR_STRENGTHS:
        raise ThreatRuleValidationError(f"{source}: invalid indicator_strength")

    regex_patterns = _strings(raw, "regex_patterns")
    literal_patterns = _strings(raw, "literal_patterns")
    semantic_examples = _strings(raw, "semantic_examples")
    attack_patterns = _strings(raw, "attack_patterns")
    negative_examples = _strings(raw, "negative_examples")
    if not (regex_patterns or literal_patterns or semantic_examples):
        raise ThreatRuleValidationError(f"{source}: at least one detection pattern is required")
    for pattern in regex_patterns:
        if len(pattern) > 4_096:
            raise ThreatRuleValidationError(f"{source}: regex exceeds 4096 characters")
        try:
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            raise ThreatRuleValidationError(f"{source}: invalid regex: {exc}") from exc

    created = _date(raw["created"], "created", source)
    updated = _date(raw["updated"], "updated", source)
    if updated < created:
        raise ThreatRuleValidationError(f"{source}: updated date precedes created date")
    minimum_version = raw.get("minimum_engine_version", "0.2.0")
    if not isinstance(minimum_version, str):
        raise ThreatRuleValidationError(f"{source}: minimum_engine_version must be a string")
    parse_version(minimum_version)
    if parse_version(minimum_version) > parse_version(ENGINE_VERSION):
        raise ThreatRuleValidationError(f"{source}: rule requires newer engine {minimum_version}")
    if quality_gate and raw["status"] == "published":
        if raw["category"] not in KNOWN_CATEGORIES:
            raise ThreatRuleValidationError(f"{source}: unknown published category")
        if taxonomy is None:
            raise ThreatRuleValidationError(f"{source}: published rules require taxonomy")
        if not attack_patterns:
            raise ThreatRuleValidationError(f"{source}: published rules require attack_patterns")
        if not negative_examples:
            raise ThreatRuleValidationError(f"{source}: published rules require negative_examples")
        if not raw.get("references"):
            raise ThreatRuleValidationError(f"{source}: published rules require references")

    return ThreatRule(
        schema_version=THREAT_RULE_SCHEMA_VERSION,
        id=raw["id"],
        name=raw["name"].strip(),
        description=raw["description"].strip(),
        category=raw["category"].strip(),
        severity=raw["severity"],
        confidence=float(confidence),
        status=raw["status"],
        created=created,
        updated=updated,
        author=raw["author"].strip(),
        license=raw["license"].strip(),
        tags=_strings(raw, "tags"),
        references=_strings(raw, "references"),
        attack_patterns=attack_patterns,
        regex_patterns=regex_patterns,
        literal_patterns=literal_patterns,
        semantic_examples=semantic_examples,
        negative_examples=negative_examples,
        platforms=_strings(raw, "platforms", ("any",)),
        languages=_strings(raw, "languages", ("en",)),
        minimum_engine_version=minimum_version,
        enabled=raw["enabled"],
        taxonomy=taxonomy,
        legacy_id=legacy_id,
        indicator_strength=indicator_strength,
    )


def lint_threat_rule(rule: ThreatRule) -> tuple[str, ...]:
    warnings: list[str] = []
    suspicious_regex = re.compile(r"(?:\([^)]*[+*][^)]*\))[+*]|\.\*[+*?]|\.\+[*+?]")
    for pattern in rule.regex_patterns:
        if suspicious_regex.search(pattern):
            warnings.append(f"{rule.id}: regex may exhibit catastrophic backtracking")
        if pattern in {".*", ".+", r"\w+", r"\S+"}:
            warnings.append(f"{rule.id}: regex is overly broad")
    for literal in rule.literal_patterns:
        if len(literal.strip()) < 4:
            warnings.append(f"{rule.id}: literal pattern is shorter than four characters")
    if rule.confidence < 0.5 and rule.severity in {"high", "critical"}:
        warnings.append(f"{rule.id}: high severity with low confidence")
    return tuple(warnings)


def test_threat_rule(rule: ThreatRule) -> tuple[str, ...]:
    failures: list[str] = []
    compiled = tuple(
        re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in rule.regex_patterns
    )

    def matches(text: str) -> bool:
        folded = text.casefold()
        return any(pattern.search(text) for pattern in compiled) or any(
            literal.casefold() in folded for literal in rule.literal_patterns
        )

    if rule.regex_patterns or rule.literal_patterns:
        for index, example in enumerate(rule.attack_patterns):
            if not matches(example):
                failures.append(f"{rule.id}: attack_patterns[{index}] did not match")
        for index, example in enumerate(rule.negative_examples):
            if matches(example):
                failures.append(f"{rule.id}: negative_examples[{index}] matched")
    return tuple(failures)
