"""Immutable data models exposed by the scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from .version import ENGINE_VERSION


class Decision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class IndicatorStrength(StrEnum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Caller-supplied provenance. It tunes risk; it never creates an authorization grant."""

    source: str = "user"
    trust_level: str = "untrusted"
    content_type: str = "text/plain"
    language: str | None = None

    def __post_init__(self) -> None:
        sources = {
            "user",
            "retrieved_document",
            "webpage",
            "email",
            "log",
            "database",
            "tool_output",
            "internal_system",
        }
        if self.source not in sources:
            raise ValueError(f"unknown scan source: {self.source}")
        if self.trust_level not in {"trusted", "semi_trusted", "untrusted"}:
            raise ValueError(f"unknown trust level: {self.trust_level}")
        if not self.content_type or len(self.content_type) > 255:
            raise ValueError("content_type must be between 1 and 255 characters")
        if self.language is not None and self.language not in {
            "en",
            "da",
            "de",
            "fr",
            "es",
            "sv",
            "no",
            "nl",
            "it",
            "pt",
            "pl",
        }:
            raise ValueError(f"unsupported language hint: {self.language}")


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    category: str
    description: str
    severity: str
    patterns: tuple[str, ...]
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    enabled: bool = True
    literal_patterns: tuple[str, ...] = ()
    confidence: float = 1.0
    taxonomy: str | None = None
    legacy_id: str | None = None


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A safe match record. The hostile matched substring is deliberately omitted."""

    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    redacted: str = "[REDACTED]"
    confidence: float = 1.0
    taxonomy: str | None = None
    legacy_rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RiskEvidence:
    """Sanitized, deterministic signal used by the ensemble score.

    Positive weights raise risk. Bounded negative weights represent reference, educational, or
    development context; Scanner never lets them neutralize critical evidence.
    """

    signal: str
    weight: float
    category: str
    confidence: float
    strength: IndicatorStrength
    rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["strength"] = self.strength.value
        return value


@dataclass(frozen=True, slots=True)
class ContextEvidence:
    """Inspectable, bounded evidence about how hostile text is presented.

    Context never grants authorization and never marks input safe by itself. Negative weights are
    consumed by Scanner's global cap; positive weights only corroborate security evidence.
    """

    kind: str
    confidence: float
    weight: float
    language: str | None = None

    def __post_init__(self) -> None:
        if not self.kind or len(self.kind) > 100:
            raise ValueError("context evidence kind must be between 1 and 100 characters")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("context evidence confidence must be between 0 and 1")
        if not -20.0 <= self.weight <= 20.0:
            raise ValueError("context evidence weight must be between -20 and 20")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScanResult:
    decision: Decision
    risk_score: int
    matched_rules: tuple[RuleMatch, ...]
    detected_categories: tuple[str, ...]
    explanation: str
    scan_duration_ms: float
    deterministic_duration_ms: float | None = None
    classifier_duration_ms: float | None = None
    semantic_analysis: dict[str, Any] | None = field(default=None)
    classifier_analysis: dict[str, Any] | None = field(default=None)
    evidence: tuple[RiskEvidence, ...] = ()
    context: dict[str, str] | None = None
    context_evidence: tuple[ContextEvidence, ...] = ()
    feed_version: str | None = None
    rules_version: str = "bundled-v1"
    engine_version: str = ENGINE_VERSION

    @property
    def categories(self) -> tuple[str, ...]:
        """Convenience alias used by the HTTP representation."""
        return self.detected_categories

    @property
    def matches(self) -> tuple[RuleMatch, ...]:
        """Convenience alias used by the HTTP representation."""
        return self.matched_rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "matched_rules": [match.to_dict() for match in self.matched_rules],
            "detected_categories": list(self.detected_categories),
            "explanation": self.explanation,
            "scan_duration_ms": self.scan_duration_ms,
            "semantic_analysis": self.semantic_analysis,
            "classifier_analysis": self.classifier_analysis,
            "evidence": [item.to_dict() for item in self.evidence],
            "context": self.context,
            "context_evidence": [item.to_dict() for item in self.context_evidence],
            "feed_version": self.feed_version,
            "rules_version": self.rules_version,
            "engine_version": self.engine_version,
        }
