"""Fail-closed deterministic policy evaluation for Guard."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..safe_yaml import bounded_safe_load
from .models import (
    ContentContext,
    DestinationType,
    FindingType,
    GuardAction,
    GuardDecision,
    GuardFinding,
    InspectionRequest,
    PolicyBinding,
    SourceType,
    TrustLevel,
)


class GuardPolicyError(ValueError):
    """A security-critical Guard policy is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    finding_types: frozenset[FindingType]
    sources: frozenset[SourceType]
    destinations: frozenset[DestinationType]
    source_trust: frozenset[TrustLevel]
    contexts: frozenset[ContentContext]
    decision: GuardDecision
    actions: tuple[GuardAction, ...]
    reason_code: str

    def matches(
        self,
        request: InspectionRequest,
        findings: tuple[GuardFinding, ...],
        source_trust: TrustLevel,
        context: ContentContext,
    ) -> bool:
        return (
            (not self.finding_types or any(f.finding_type in self.finding_types for f in findings))
            and (not self.sources or request.source in self.sources)
            and (not self.destinations or request.destination in self.destinations)
            and (not self.source_trust or source_trust in self.source_trust)
            and (not self.contexts or context in self.contexts)
        )


@dataclass(frozen=True, slots=True)
class GuardPolicy:
    policy_id: str
    version: str
    policy_hash: str
    source_trust: Mapping[SourceType, TrustLevel]
    destination_trust: Mapping[DestinationType, TrustLevel]
    rules: tuple[PolicyRule, ...]
    default_decision: GuardDecision
    default_actions: tuple[GuardAction, ...]
    default_reason_code: str

    @classmethod
    def default(cls) -> GuardPolicy:
        return cls.from_path(Path(__file__).with_name("default-policy.yaml"))

    @classmethod
    def from_path(cls, path: Path) -> GuardPolicy:
        try:
            raw_text = path.read_text(encoding="utf-8")
            payload = bounded_safe_load(raw_text)
        except Exception as exc:
            raise GuardPolicyError(f"could not safely load Guard policy: {exc}") from exc
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Any) -> GuardPolicy:
        if not isinstance(payload, Mapping):
            raise GuardPolicyError("Guard policy root must be a mapping")
        allowed_root = {
            "policy_id",
            "version",
            "source_trust",
            "destination_trust",
            "rules",
            "default",
        }
        unknown = set(payload) - allowed_root
        if unknown:
            raise GuardPolicyError(f"unknown Guard policy fields: {sorted(unknown)}")
        try:
            policy_id = _bounded_string(payload["policy_id"], "policy_id")
            version = _bounded_string(payload["version"], "version")
            source_map = _enum_map(payload["source_trust"], SourceType, TrustLevel)
            destination_map = _enum_map(payload["destination_trust"], DestinationType, TrustLevel)
            if set(source_map) != set(SourceType) or set(destination_map) != set(DestinationType):
                raise GuardPolicyError("trust maps must cover every closed source and destination")
            raw_rules = payload["rules"]
            if not isinstance(raw_rules, list) or not raw_rules:
                raise GuardPolicyError("rules must be a non-empty ordered list")
            rules = tuple(_parse_rule(item) for item in raw_rules)
            if len({item.rule_id for item in rules}) != len(rules):
                raise GuardPolicyError("policy rule IDs must be unique")
            default = payload["default"]
            if not isinstance(default, Mapping):
                raise GuardPolicyError("default must be a mapping")
            _require_exact(default, {"decision", "actions", "reason_code"}, "default")
            default_decision = GuardDecision(default["decision"])
            default_actions = _actions(default["actions"])
            _validate_outcome(default_decision, default_actions, "default")
            default_reason = _bounded_string(default["reason_code"], "default.reason_code")
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, GuardPolicyError):
                raise
            raise GuardPolicyError(f"invalid Guard policy: {exc}") from exc
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return cls(
            policy_id,
            version,
            hashlib.sha256(canonical.encode()).hexdigest(),
            source_map,
            destination_map,
            rules,
            default_decision,
            default_actions,
            default_reason,
        )

    def evaluate(
        self,
        request: InspectionRequest,
        findings: tuple[GuardFinding, ...],
        source_trust: TrustLevel,
        context: ContentContext,
    ) -> tuple[GuardDecision, tuple[GuardAction, ...], PolicyBinding]:
        for rule in self.rules:
            if rule.matches(request, findings, source_trust, context):
                return (
                    rule.decision,
                    rule.actions,
                    PolicyBinding(
                        self.policy_id,
                        self.version,
                        self.policy_hash,
                        rule.rule_id,
                        rule.reason_code,
                    ),
                )
        # Findings may never disappear into an ALLOW fallback, even under a custom policy.
        if findings and self.default_decision is GuardDecision.ALLOW:
            return (
                GuardDecision.REVIEW,
                (GuardAction.REQUIRE_HUMAN_REVIEW, GuardAction.LOG_SECURITY_EVENT),
                PolicyBinding(
                    self.policy_id,
                    self.version,
                    self.policy_hash,
                    "GUARD-FAIL-CLOSED",
                    "UNHANDLED_SECURITY_FINDING",
                ),
            )
        return (
            self.default_decision,
            self.default_actions,
            PolicyBinding(
                self.policy_id, self.version, self.policy_hash, "default", self.default_reason_code
            ),
        )


def _bounded_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise GuardPolicyError(f"{name} must be a bounded non-empty string")
    return value


def _require_exact(mapping: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(mapping) != expected:
        raise GuardPolicyError(f"{name} fields must be exactly {sorted(expected)}")


def _enum_map(raw: Any, key_enum: type[Any], value_enum: type[Any]) -> dict[Any, Any]:
    if not isinstance(raw, Mapping):
        raise GuardPolicyError("trust configuration must be a mapping")
    return {key_enum(key): value_enum(value) for key, value in raw.items()}


def _enum_set(raw: Any, enum: type[Any], name: str) -> frozenset[Any]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list):
        raise GuardPolicyError(f"{name} must be a list")
    return frozenset(enum(value) for value in raw)


def _actions(raw: Any) -> tuple[GuardAction, ...]:
    if not isinstance(raw, list) or not raw:
        raise GuardPolicyError("policy actions must be a non-empty list")
    actions = tuple(GuardAction(value) for value in raw)
    if len(set(actions)) != len(actions):
        raise GuardPolicyError("policy actions must be unique")
    return actions


def _parse_rule(raw: Any) -> PolicyRule:
    if not isinstance(raw, Mapping):
        raise GuardPolicyError("each policy rule must be a mapping")
    expected = {"id", "when", "decision", "actions", "reason_code"}
    _require_exact(raw, expected, "policy rule")
    when = raw["when"]
    if not isinstance(when, Mapping):
        raise GuardPolicyError("rule when must be a mapping")
    allowed_conditions = {"finding_types", "sources", "destinations", "source_trust", "contexts"}
    unknown = set(when) - allowed_conditions
    if unknown:
        raise GuardPolicyError(f"unknown rule conditions: {sorted(unknown)}")
    decision = GuardDecision(raw["decision"])
    actions = _actions(raw["actions"])
    _validate_outcome(decision, actions, f"rule {raw['id']}")
    return PolicyRule(
        _bounded_string(raw["id"], "rule.id"),
        _enum_set(when.get("finding_types"), FindingType, "finding_types"),
        _enum_set(when.get("sources"), SourceType, "sources"),
        _enum_set(when.get("destinations"), DestinationType, "destinations"),
        _enum_set(when.get("source_trust"), TrustLevel, "source_trust"),
        _enum_set(when.get("contexts"), ContentContext, "contexts"),
        decision,
        actions,
        _bounded_string(raw["reason_code"], "rule.reason_code"),
    )


def _validate_outcome(decision: GuardDecision, actions: tuple[GuardAction, ...], name: str) -> None:
    blocking = {
        GuardAction.BLOCK_REQUEST,
        GuardAction.BLOCK_TOOL_CALL,
        GuardAction.BLOCK_EXTERNAL_TRANSFER,
        GuardAction.PREVENT_MEMORY_WRITE,
    }
    if decision is GuardDecision.ALLOW and actions != (GuardAction.ALLOW,):
        raise GuardPolicyError(f"{name}: ALLOW must use only the allow action")
    if decision is GuardDecision.REVIEW and GuardAction.REQUIRE_HUMAN_REVIEW not in actions:
        raise GuardPolicyError(f"{name}: REVIEW must require human review")
    if decision is GuardDecision.BLOCK and not blocking.intersection(actions):
        raise GuardPolicyError(f"{name}: BLOCK must contain an enforcement action")
