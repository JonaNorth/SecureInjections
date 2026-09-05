"""Deterministic causal-event history and conservative compound-risk policy."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .causal_audit import append_chained_audit
from .envelope import ContentEnvelope

SEQUENCE_POLICY_VERSION = "gateway-sequence-policy-v0.3c2-2026-08-27"


class SecurityEventType(StrEnum):
    FILE_READ = "file_read"
    CONTENT_TRANSFORM = "content_transform"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    AGENT_MESSAGE = "agent_message"
    CAPABILITY_REQUEST = "capability_request"
    TOOL_PROPOSAL = "tool_proposal"
    EXTERNAL_SEND = "external_send"
    POLICY_DECISION = "policy_decision"
    MODEL_TURN = "model_turn"
    MODEL_OUTPUT = "model_output"


class SequenceDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    correlation_id: str
    event_type: SecurityEventType
    causal_parent_ids: tuple[str, ...]
    content_ids: tuple[str, ...]
    attributes: dict[str, str] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        correlation_id: str,
        event_type: SecurityEventType,
        *,
        causal_parent_ids: tuple[str, ...] = (),
        content_ids: tuple[str, ...] = (),
        attributes: dict[str, str] | None = None,
    ) -> SecurityEvent:
        return cls(
            "security-event-" + uuid.uuid4().hex,
            correlation_id,
            event_type,
            causal_parent_ids,
            content_ids,
            dict(attributes or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type.value,
            "causal_parent_ids": list(self.causal_parent_ids),
            "content_ids": list(self.content_ids),
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class SequencePolicyResult:
    decision: SequenceDecision
    reason_code: str
    matched_event_ids: tuple[str, ...] = ()


class CausalEventStore:
    """Bounded in-memory causal graph used by enforcement, not a probabilistic planner."""

    def __init__(
        self,
        *,
        max_events: int = 10_000,
        max_ancestry: int = 256,
        audit_path: Path | None = None,
    ) -> None:
        if max_events < 1 or max_ancestry < 1:
            raise ValueError("event bounds must be positive")
        self.max_events = max_events
        self.max_ancestry = max_ancestry
        self._ordered: list[SecurityEvent] = []
        self._events: dict[str, SecurityEvent] = {}
        self.audit_path = audit_path

    def append(self, event: SecurityEvent) -> None:
        if event.event_id in self._events:
            raise ValueError("event_id must be unique")
        if event.event_id in event.causal_parent_ids:
            raise ValueError("security event cannot be a causal parent of itself")
        if len(set(event.causal_parent_ids)) != len(event.causal_parent_ids):
            raise ValueError("security event has a duplicate causal parent")
        unknown = tuple(
            parent_id for parent_id in event.causal_parent_ids if parent_id not in self._events
        )
        if unknown:
            raise ValueError(f"security event has unknown causal parent: {unknown[0]}")
        self._events[event.event_id] = event
        self._ordered.append(event)
        if self.audit_path is not None:
            record: dict[str, Any] = {
                "schema_version": "causal-security-event-v0.1",
                **event.to_dict(),
                "raw_content_retained": False,
            }
            append_chained_audit(self.audit_path, record)
        if len(self._ordered) > self.max_events:
            expired = self._ordered.pop(0)
            self._events.pop(expired.event_id, None)

    def register_envelope(self, envelope: ContentEnvelope) -> ContentEnvelope:
        """Backend hook; ephemeral state already owns the supplied envelope."""

        return envelope

    def consume_once(
        self,
        token_kind: str,
        token_id: str,
        consuming_event_id: str,
        action_fingerprint: str | None = None,
    ) -> str | None:
        """Persistent backends override this; ephemeral callers keep local sets."""

        return None

    def get(self, event_id: str) -> SecurityEvent | None:
        return self._events.get(event_id)

    def ancestry(self, parent_ids: tuple[str, ...]) -> tuple[SecurityEvent, ...]:
        pending = list(parent_ids)
        seen: set[str] = set()
        output: list[SecurityEvent] = []
        while pending and len(output) < self.max_ancestry:
            event_id = pending.pop()
            if event_id in seen:
                continue
            seen.add(event_id)
            event = self._events.get(event_id)
            if event is None:
                continue
            output.append(event)
            pending.extend(event.causal_parent_ids)
        return tuple(output)

    def correlation_events(self, correlation_id: str) -> tuple[SecurityEvent, ...]:
        return tuple(item for item in self._ordered if item.correlation_id == correlation_id)

    def validate_parent_ids(self, parent_ids: tuple[str, ...]) -> None:
        if len(set(parent_ids)) != len(parent_ids):
            raise ValueError("duplicate causal parent ID")
        unknown = tuple(parent_id for parent_id in parent_ids if parent_id not in self._events)
        if unknown:
            raise ValueError(f"unknown causal parent ID: {unknown[0]}")


class SequencePolicy:
    """Small fail-safe policy over provenance plus recent causal events."""

    def evaluate(
        self,
        operation: SecurityEventType,
        *,
        envelope: ContentEnvelope | None,
        ancestry: tuple[SecurityEvent, ...],
        privileged: bool = False,
        persistent_instruction: bool = False,
    ) -> SequencePolicyResult:
        sensitive_reads = tuple(
            item
            for item in ancestry
            if item.event_type is SecurityEventType.FILE_READ
            and item.attributes.get("sensitive") == "true"
            and item.attributes.get("decision") == "ALLOW"
        )
        envelope_sensitive = envelope is not None and any(
            finding.finding_type == "SENSITIVE_CONTENT" for finding in envelope.security_findings
        )
        if operation is SecurityEventType.EXTERNAL_SEND and sensitive_reads:
            return SequencePolicyResult(
                SequenceDecision.BLOCK,
                "SENSITIVE_READ_TO_EXTERNAL_SEND",
                tuple(item.event_id for item in sensitive_reads),
            )
        if operation is SecurityEventType.EXTERNAL_SEND and envelope_sensitive:
            return SequencePolicyResult(
                SequenceDecision.BLOCK,
                "SENSITIVE_CONTENT_TO_EXTERNAL_SEND",
            )
        if persistent_instruction and envelope is not None and envelope.ever_untrusted:
            return SequencePolicyResult(
                SequenceDecision.BLOCK,
                "UNTRUSTED_DERIVED_PERSISTENT_INSTRUCTION",
            )
        if (
            operation is SecurityEventType.CAPABILITY_REQUEST
            and envelope is not None
            and envelope.ever_untrusted
        ):
            return SequencePolicyResult(
                SequenceDecision.REVIEW,
                "UNTRUSTED_AGENT_CAPABILITY_REQUEST",
            )
        if privileged and envelope is not None and envelope.suspicious_encoded:
            return SequencePolicyResult(
                SequenceDecision.REVIEW,
                "SUSPICIOUS_ENCODED_CONTENT_TO_PRIVILEGED_ACTION",
            )
        if privileged and envelope is not None and envelope.ever_untrusted:
            return SequencePolicyResult(
                SequenceDecision.REVIEW,
                "UNTRUSTED_DERIVED_PRIVILEGED_ACTION",
            )
        return SequencePolicyResult(SequenceDecision.ALLOW, "NO_COMPOUND_RISK")
