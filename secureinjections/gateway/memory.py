"""Provenance-preserving persistent-memory boundary."""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .content_inspection import inspect_content
from .envelope import ContentEnvelope, ContentSourceType
from .sequence import (
    CausalEventStore,
    SecurityEvent,
    SecurityEventType,
    SequenceDecision,
    SequencePolicy,
)


class MemoryDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class MemoryWriteRequest:
    key: str
    content: ContentEnvelope
    correlation_id: str
    causal_parent_ids: tuple[str, ...] = ()
    purpose: str = "data"

    def __post_init__(self) -> None:
        if not self.key or len(self.key) > 500:
            raise ValueError("memory key must be a bounded non-empty string")
        if not self.correlation_id or len(self.correlation_id) > 200:
            raise ValueError("correlation_id must be a bounded non-empty string")
        if not self.purpose or len(self.purpose) > 100:
            raise ValueError("memory purpose must be a bounded non-empty string")
        if len(self.causal_parent_ids) > 128:
            raise ValueError("memory write has too many causal parents")


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    record_id: str
    key: str
    content: ContentEnvelope = field(repr=False)
    correlation_id: str
    causal_parent_ids: tuple[str, ...]
    write_event_id: str

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "key": self.key,
            "correlation_id": self.correlation_id,
            "causal_parent_ids": list(self.causal_parent_ids),
            "write_event_id": self.write_event_id,
            "content": self.content.metadata_dict(),
        }


@dataclass(frozen=True, slots=True)
class MemoryWriteResult:
    decision: MemoryDecision
    reason_code: str
    record: MemoryRecord | None = field(default=None, repr=False)
    event_id: str | None = None


@dataclass(frozen=True, slots=True)
class MemoryReadResult:
    decision: MemoryDecision
    reason_code: str
    envelope: ContentEnvelope | None = field(default=None, repr=False)
    event_id: str | None = None


_PERSISTENT_INSTRUCTION = re.compile(
    r"\b(?:always|from\s+now\s+on|when\s+you\s+see|instruction|rule|bypass|ignore|execute|send)\b",
    re.IGNORECASE,
)


class ProvenanceMemory:
    def __init__(
        self,
        events: CausalEventStore,
        *,
        sequence_policy: SequencePolicy | None = None,
        execution_gate: Callable[[], None] | None = None,
    ) -> None:
        self.events = events
        self.sequence_policy = sequence_policy or SequencePolicy()
        self._execution_gate = execution_gate
        self._records: dict[str, MemoryRecord] = {}

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._records.values())

    def write(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        if self._execution_gate is not None:
            self._execution_gate()
        source = self.events.register_envelope(request.content)
        if source is not request.content:
            request = MemoryWriteRequest(
                request.key,
                source,
                request.correlation_id,
                request.causal_parent_ids,
                request.purpose,
            )
        try:
            self.events.validate_parent_ids(request.causal_parent_ids)
        except ValueError:
            event = SecurityEvent.create(
                request.correlation_id,
                SecurityEventType.POLICY_DECISION,
                content_ids=(request.content.content_id,),
                attributes={
                    "operation": SecurityEventType.MEMORY_WRITE.value,
                    "decision": MemoryDecision.BLOCK.value,
                    "reason_code": "INVALID_CAUSAL_PARENT",
                },
            )
            self.events.append(event)
            return MemoryWriteResult(
                MemoryDecision.BLOCK, "INVALID_CAUSAL_PARENT", None, event.event_id
            )
        inspection = inspect_content(request.content.content)
        inspected = ContentEnvelope.derive(
            request.content.content,
            parents=(request.content,),
            source_type=ContentSourceType.MEMORY,
            producing_boundary="memory_write_boundary",
            transformation="memory_write_inspection",
            producer="gateway",
            security_findings=inspection.findings,
            inspection_sha256=inspection.inspection_sha256,
        )
        persistent_instruction = request.purpose.casefold() in {
            "instruction",
            "rule",
            "control",
        } or bool(_PERSISTENT_INSTRUCTION.search(inspected.content))
        ancestry = self.events.ancestry(request.causal_parent_ids)
        policy = self.sequence_policy.evaluate(
            SecurityEventType.MEMORY_WRITE,
            envelope=inspected,
            ancestry=ancestry,
            privileged=persistent_instruction,
            persistent_instruction=persistent_instruction,
        )
        if policy.decision is not SequenceDecision.ALLOW:
            decision = (
                MemoryDecision.BLOCK
                if policy.decision is SequenceDecision.BLOCK
                else MemoryDecision.REVIEW
            )
            event = self._policy_event(
                request.correlation_id,
                request.causal_parent_ids,
                inspected,
                decision.value,
                policy.reason_code,
                SecurityEventType.MEMORY_WRITE,
            )
            return MemoryWriteResult(decision, policy.reason_code, None, event.event_id)
        if inspection.suspicious:
            event = self._policy_event(
                request.correlation_id,
                request.causal_parent_ids,
                inspected,
                MemoryDecision.REVIEW.value,
                "SUSPICIOUS_MEMORY_CONTENT",
                SecurityEventType.MEMORY_WRITE,
            )
            return MemoryWriteResult(
                MemoryDecision.REVIEW, "SUSPICIOUS_MEMORY_CONTENT", None, event.event_id
            )
        record_id = "memory-record-" + uuid.uuid4().hex
        event = SecurityEvent.create(
            request.correlation_id,
            SecurityEventType.MEMORY_WRITE,
            causal_parent_ids=request.causal_parent_ids,
            content_ids=(inspected.content_id,),
            attributes={
                "persistent_instruction": str(persistent_instruction).lower(),
                "content_trust": inspected.trust.value,
                "ever_untrusted": str(inspected.ever_untrusted).lower(),
                "producing_boundary": inspected.producing_boundary,
                "record_id": record_id,
                "memory_key_sha256": hashlib.sha256(request.key.encode("utf-8")).hexdigest(),
            },
        )
        inspected = self.events.register_envelope(inspected)
        event = SecurityEvent(
            event.event_id,
            event.correlation_id,
            event.event_type,
            event.causal_parent_ids,
            (inspected.content_id,),
            event.attributes,
        )
        self.events.append(event)
        record = MemoryRecord(
            record_id,
            request.key,
            inspected,
            request.correlation_id,
            request.causal_parent_ids,
            event.event_id,
        )
        self._records[record.record_id] = record
        return MemoryWriteResult(
            MemoryDecision.ALLOW, "MEMORY_WRITE_ALLOWED", record, event.event_id
        )

    def read(
        self, record_id: str, *, destination_agent: str, correlation_id: str
    ) -> MemoryReadResult:
        record = self._records.get(record_id)
        if record is None:
            return MemoryReadResult(MemoryDecision.BLOCK, "MEMORY_RECORD_NOT_FOUND")
        inspection = inspect_content(record.content.content)
        envelope = ContentEnvelope.derive(
            record.content.content,
            parents=(record.content,),
            source_type=ContentSourceType.MEMORY,
            producing_boundary="memory_read_boundary",
            transformation="memory_retrieval",
            producer=destination_agent,
            security_findings=inspection.findings,
            inspection_sha256=inspection.inspection_sha256,
        )
        event = SecurityEvent.create(
            correlation_id,
            SecurityEventType.MEMORY_READ,
            causal_parent_ids=(record.write_event_id,),
            content_ids=(envelope.content_id,),
            attributes={
                "destination_agent": destination_agent,
                "record_id": record_id,
                "content_trust": envelope.trust.value,
                "ever_untrusted": str(envelope.ever_untrusted).lower(),
                "write_event_id": record.write_event_id,
            },
        )
        envelope = self.events.register_envelope(envelope)
        event = SecurityEvent(
            event.event_id,
            event.correlation_id,
            event.event_type,
            event.causal_parent_ids,
            (envelope.content_id,),
            event.attributes,
        )
        self.events.append(event)
        if inspection.suspicious:
            return MemoryReadResult(
                MemoryDecision.REVIEW, "SUSPICIOUS_MEMORY_RETRIEVAL", None, event.event_id
            )
        return MemoryReadResult(
            MemoryDecision.ALLOW, "MEMORY_READ_ALLOWED", envelope, event.event_id
        )

    def _restore_verified_record(self, record: MemoryRecord) -> None:
        """Install payload only after the persistent backend authenticated its metadata."""

        self._records[record.record_id] = record

    def _policy_event(
        self,
        correlation_id: str,
        causal_parent_ids: tuple[str, ...],
        envelope: ContentEnvelope,
        decision: str,
        reason_code: str,
        operation: SecurityEventType,
    ) -> SecurityEvent:
        event = SecurityEvent.create(
            correlation_id,
            SecurityEventType.POLICY_DECISION,
            causal_parent_ids=causal_parent_ids,
            content_ids=(envelope.content_id,),
            attributes={
                "operation": operation.value,
                "decision": decision,
                "reason_code": reason_code,
                "content_trust": envelope.trust.value,
                "ever_untrusted": str(envelope.ever_untrusted).lower(),
            },
        )
        self.events.append(event)
        return event
