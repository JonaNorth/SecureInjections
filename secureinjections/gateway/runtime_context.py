"""Host-owned security context for model turns and normalized actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..guard import TrustLevel
from .envelope import (
    ContentEnvelope,
    ContentSecurityFinding,
    compact_security_findings,
    least_trusted,
)

RUNTIME_SECURITY_CONTEXT_VERSION = "agent-runtime-security-context-v0.2"


@dataclass(frozen=True, slots=True)
class RuntimeSecurityContext:
    """Immutable ancestry associated with one model call.

    This object is created by :class:`GuardedToolGateway`; it is never parsed
    from provider output or reconstructed from model-visible text.
    """

    correlation_id: str
    turn_id: str
    turn_event_id: str
    input_envelopes: tuple[ContentEnvelope, ...]
    causal_parent_ids: tuple[str, ...]
    trust_floor: TrustLevel
    ever_untrusted: bool
    security_findings: tuple[ContentSecurityFinding, ...]

    def __post_init__(self) -> None:
        for value, label in (
            (self.correlation_id, "correlation_id"),
            (self.turn_id, "turn_id"),
            (self.turn_event_id, "turn_event_id"),
        ):
            if not value or len(value) > 500:
                raise ValueError(f"{label} must be bounded and non-empty")
        if not self.input_envelopes or len(self.input_envelopes) > 64:
            raise ValueError("runtime context requires between 1 and 64 input envelopes")
        if len(self.causal_parent_ids) > 128:
            raise ValueError("runtime context has too many causal parents")
        if len(self.security_findings) > 128:
            raise ValueError("runtime context has too many security findings")
        if len(set(self.input_envelope_ids)) != len(self.input_envelope_ids):
            raise ValueError("runtime context has duplicate input envelope IDs")
        if len(set(self.causal_parent_ids)) != len(self.causal_parent_ids):
            raise ValueError("runtime context has duplicate causal parent IDs")

    @property
    def input_envelope_ids(self) -> tuple[str, ...]:
        return tuple(item.content_id for item in self.input_envelopes)

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "turn_id": self.turn_id,
            "turn_event_id": self.turn_event_id,
            "input_envelope_ids": list(self.input_envelope_ids),
            "causal_parent_ids": list(self.causal_parent_ids),
            "trust_floor": self.trust_floor.value,
            "ever_untrusted": self.ever_untrusted,
            "security_findings": [item.to_dict() for item in self.security_findings],
            "raw_content_retained": False,
        }

    @classmethod
    def _from_host(
        cls,
        *,
        correlation_id: str,
        turn_id: str,
        turn_event_id: str,
        input_envelopes: tuple[ContentEnvelope, ...],
        causal_parent_ids: tuple[str, ...],
    ) -> RuntimeSecurityContext:
        if not input_envelopes:
            raise ValueError("a model turn requires at least one host-owned input envelope")
        findings = compact_security_findings(
            tuple(
                dict.fromkeys(
                    finding
                    for envelope in input_envelopes
                    for finding in envelope.security_findings
                )
            )
        )
        return cls(
            correlation_id,
            turn_id,
            turn_event_id,
            input_envelopes,
            causal_parent_ids,
            least_trusted(tuple(item.trust for item in input_envelopes)),
            any(item.ever_untrusted for item in input_envelopes),
            findings,
        )


@dataclass(frozen=True, slots=True)
class RuntimeDerivedOutput:
    """A normalized model output bound to its host-derived ancestry."""

    action_type: str
    envelope: ContentEnvelope
    event_id: str
    context: RuntimeSecurityContext

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "event_id": self.event_id,
            "context": self.context.metadata_dict(),
            "output": self.envelope.metadata_dict(),
        }
