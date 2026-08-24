"""Closed, immutable models for the deterministic Guard runtime."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class GuardDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Certainty(StrEnum):
    INDICATIVE = "INDICATIVE"
    STRONG = "STRONG"
    DEFINITE = "DEFINITE"


class TrustLevel(StrEnum):
    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    UNTRUSTED = "UNTRUSTED"
    EXTERNAL = "EXTERNAL"


class SourceType(StrEnum):
    USER = "user"
    SYSTEM = "system"
    MODEL = "model"
    RETRIEVED_CONTENT = "retrieved_content"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    FILE = "file"
    EXTERNAL = "external"
    INTERNAL = "internal"


class DestinationType(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    MEMORY = "memory"
    USER = "user"
    EXTERNAL = "external"
    INTERNAL = "internal"


class ContentContext(StrEnum):
    OPERATIVE = "OPERATIVE"
    QUOTED_ATTACK = "QUOTED_ATTACK"
    SECURITY_DISCUSSION = "SECURITY_DISCUSSION"
    INCIDENT_REPORT = "INCIDENT_REPORT"
    DEVELOPER_GUIDANCE = "DEVELOPER_GUIDANCE"
    GENERAL_BENIGN = "GENERAL_BENIGN"


class FindingType(StrEnum):
    DIRECT_PROMPT_INJECTION = "DIRECT_PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    SYSTEM_SECRET_EXTRACTION = "SYSTEM_SECRET_EXTRACTION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    EXFILTRATION = "EXFILTRATION"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    PATH_ACCESS = "PATH_ACCESS"
    METADATA_ACCESS = "METADATA_ACCESS"
    PERSISTENCE = "PERSISTENCE"
    CROSS_AGENT_POISONING = "CROSS_AGENT_POISONING"
    SUSPICIOUS_URL_DESTINATION = "SUSPICIOUS_URL_DESTINATION"


class ClassifierFamily(StrEnum):
    ATTACK_DIRECT_INJECTION = "ATTACK_DIRECT_INJECTION"
    ATTACK_INDIRECT_INJECTION = "ATTACK_INDIRECT_INJECTION"
    ATTACK_TOOL_EXECUTION = "ATTACK_TOOL_EXECUTION"
    ATTACK_CREDENTIAL_ACCESS = "ATTACK_CREDENTIAL_ACCESS"
    ATTACK_EXFILTRATION = "ATTACK_EXFILTRATION"
    ATTACK_CROSS_AGENT = "ATTACK_CROSS_AGENT"
    ATTACK_PERSISTENCE = "ATTACK_PERSISTENCE"
    ATTACK_PATH_ACCESS = "ATTACK_PATH_ACCESS"
    ATTACK_METADATA_ACCESS = "ATTACK_METADATA_ACCESS"


class GuardAction(StrEnum):
    ALLOW = "allow"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    BLOCK_REQUEST = "block_request"
    BLOCK_TOOL_CALL = "block_tool_call"
    BLOCK_EXTERNAL_TRANSFER = "block_external_transfer"
    PREVENT_MEMORY_WRITE = "prevent_memory_write"
    STRIP_UNTRUSTED_INSTRUCTION = "strip_untrusted_instruction"
    QUARANTINE_CONTENT = "quarantine_content"
    REDACT_SENSITIVE_EXCERPT = "redact_sensitive_excerpt"
    LOG_SECURITY_EVENT = "log_security_event"


@dataclass(frozen=True, slots=True)
class InspectionContext:
    """Caller context. Presentation is a claim, not an authorization grant."""

    request_id: str | None = None
    presentation: ContentContext | None = None
    source_trust: TrustLevel | None = None
    destination_trust: TrustLevel | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.presentation, str):
            object.__setattr__(self, "presentation", ContentContext(self.presentation.upper()))
        if isinstance(self.source_trust, str):
            object.__setattr__(self, "source_trust", TrustLevel(self.source_trust.upper()))
        if isinstance(self.destination_trust, str):
            object.__setattr__(
                self, "destination_trust", TrustLevel(self.destination_trust.upper())
            )
        if self.request_id is not None and (not self.request_id or len(self.request_id) > 200):
            raise ValueError("request_id must be between 1 and 200 characters")
        if len(self.metadata) > 32 or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or len(key) > 100
            or len(value) > 500
            for key, value in self.metadata.items()
        ):
            raise ValueError("context metadata must contain at most 32 bounded string pairs")


@dataclass(frozen=True, slots=True)
class InspectionRequest:
    content: str
    source: SourceType | str
    destination: DestinationType | str
    context: InspectionContext | Mapping[str, Any] = field(default_factory=InspectionContext)

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")
        if len(self.content) > 1_000_000:
            raise ValueError("content exceeds the 1,000,000 character limit")
        if isinstance(self.source, str):
            object.__setattr__(self, "source", SourceType(self.source))
        if isinstance(self.destination, str):
            object.__setattr__(self, "destination", DestinationType(self.destination))
        if isinstance(self.context, Mapping):
            object.__setattr__(self, "context", InspectionContext(**dict(self.context)))


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    tool_name: str
    arguments: Mapping[str, Any]
    source: SourceType | str = SourceType.MODEL
    destination: DestinationType | str = DestinationType.TOOL
    context: InspectionContext | Mapping[str, Any] = field(default_factory=InspectionContext)

    def __post_init__(self) -> None:
        if not self.tool_name or len(self.tool_name) > 200:
            raise ValueError("tool_name must be between 1 and 200 characters")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        if isinstance(self.source, str):
            object.__setattr__(self, "source", SourceType(self.source))
        if isinstance(self.destination, str):
            object.__setattr__(self, "destination", DestinationType(self.destination))
        if isinstance(self.context, Mapping):
            object.__setattr__(self, "context", InspectionContext(**dict(self.context)))


@dataclass(frozen=True, slots=True)
class EvidenceSpan:
    start: int
    end: int
    excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GuardFinding:
    rule_id: str
    finding_type: FindingType
    classifier_family: ClassifierFamily
    severity: Severity
    certainty: Certainty
    evidence: EvidenceSpan
    reason_code: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "type": self.finding_type.value,
            "classifier_family": self.classifier_family.value,
            "severity": self.severity.value,
            "certainty": self.certainty.value,
            "evidence": self.evidence.to_dict(),
            "reason_code": self.reason_code,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class PolicyBinding:
    policy_id: str
    policy_version: str
    policy_hash: str
    rule_id: str
    reason_code: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AdvisorySignal:
    provider_id: str
    signal: str
    authoritative: bool = False

    def __post_init__(self) -> None:
        if self.authoritative:
            raise ValueError("Guard v0.1 advisory signals cannot be authoritative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class InspectionResult:
    decision: GuardDecision
    risk: RiskLevel
    findings: tuple[GuardFinding, ...]
    actions: tuple[GuardAction, ...]
    policy: PolicyBinding
    audit_id: str
    dry_run: bool
    content_context: ContentContext
    source_trust: TrustLevel
    destination_trust: TrustLevel
    normalized_content_hash: str
    detector_hash: str
    audit_record_hash: str
    advisory_signals: tuple[AdvisorySignal, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk": self.risk.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "actions": [action.value for action in self.actions],
            "policy": self.policy.to_dict(),
            "audit_id": self.audit_id,
            "dry_run": self.dry_run,
            "content_context": self.content_context.value,
            "source_trust": self.source_trust.value,
            "destination_trust": self.destination_trust.value,
            "normalized_content_hash": self.normalized_content_hash,
            "detector_hash": self.detector_hash,
            "audit_record_hash": self.audit_record_hash,
            "advisory_signals": [signal.to_dict() for signal in self.advisory_signals],
        }
