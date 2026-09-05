"""Typed, capability-authenticated agent-to-agent message boundary."""

from __future__ import annotations

import secrets
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
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


class MessagePurpose(StrEnum):
    DATA = "data"
    STATUS = "status"
    CONTROL = "control"


class AgentMessageDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class AgentAuthority:
    agent_id: str
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizedControl:
    authorization_id: str
    operation: str
    source_agent: str
    destination_agent: str
    correlation_id: str
    expires_at_ns: int
    parameters: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))


@dataclass(frozen=True, slots=True)
class AgentMessageRequest:
    source_agent: str
    destination_agent: str
    purpose: MessagePurpose
    content: ContentEnvelope
    correlation_id: str
    causal_parent_ids: tuple[str, ...] = ()
    requested_capability: str | None = None
    control: AuthorizedControl | None = None

    def __post_init__(self) -> None:
        if isinstance(self.purpose, str):
            object.__setattr__(self, "purpose", MessagePurpose(self.purpose))
        for value, name in (
            (self.source_agent, "source_agent"),
            (self.destination_agent, "destination_agent"),
            (self.correlation_id, "correlation_id"),
        ):
            if not value or len(value) > 200:
                raise ValueError(f"{name} must be a bounded non-empty string")
        if self.requested_capability is not None and (
            not self.requested_capability or len(self.requested_capability) > 200
        ):
            raise ValueError("requested_capability must be a bounded non-empty string")
        if len(self.causal_parent_ids) > 128:
            raise ValueError("agent message has too many causal parents")


@dataclass(frozen=True, slots=True)
class AgentMessageResult:
    message_id: str
    decision: AgentMessageDecision
    reason_code: str
    message: AgentMessageRequest | None = field(default=None, repr=False)
    event_id: str | None = None
    granted_capabilities: tuple[str, ...] = ()

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "message_id": self.message_id,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "event_id": self.event_id,
            "granted_capabilities": list(self.granted_capabilities),
        }
        if self.message is not None:
            output["source_agent"] = self.message.source_agent
            output["destination_agent"] = self.message.destination_agent
            output["purpose"] = self.message.purpose.value
            output["requested_capability"] = self.message.requested_capability
            output["content"] = self.message.content.metadata_dict()
            if include_content and self.decision is AgentMessageDecision.ALLOW:
                output["content"]["text"] = self.message.content.content
        return output


class AgentDirectory:
    """Host-owned agent identities and explicit control authorizations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tokens: dict[str, str] = {}
        self._capabilities: dict[str, frozenset[str]] = {}
        self._controls: dict[str, AuthorizedControl] = {}
        self._used_controls: set[str] = set()
        self._security_revision = 0
        self._capability_revisions: dict[str, int] = {}

    def register(self, agent_id: str, *, capabilities: tuple[str, ...] = ()) -> AgentAuthority:
        with self._lock:
            if not agent_id or len(agent_id) > 200 or agent_id in self._tokens:
                raise ValueError("agent_id must be bounded and unique")
            token = secrets.token_urlsafe(32)
            if any(not item or len(item) > 200 for item in capabilities):
                raise ValueError("agent capabilities must be bounded non-empty strings")
            self._tokens[agent_id] = token
            self._capabilities[agent_id] = frozenset(capabilities)
            self._security_revision += 1
            self._capability_revisions[agent_id] = 1
            return AgentAuthority(agent_id, token)

    def replace_capabilities(self, agent_id: str, *, capabilities: tuple[str, ...]) -> int:
        """Host-side capability replacement; callers must not expose it to model code."""

        if any(not item or len(item) > 200 for item in capabilities):
            raise ValueError("agent capabilities must be bounded non-empty strings")
        with self._lock:
            if agent_id not in self._tokens:
                raise ValueError("agent must be registered")
            updated = frozenset(capabilities)
            if updated != self._capabilities[agent_id]:
                self._capabilities[agent_id] = updated
                self._security_revision += 1
                self._capability_revisions[agent_id] += 1
            return self._capability_revisions[agent_id]

    def security_snapshot(self, agent_id: str) -> tuple[int, tuple[str, ...]]:
        """Return a deterministic host snapshot for execution-policy binding."""

        with self._lock:
            return self._capability_revisions.get(agent_id, 0), tuple(
                sorted(self._capabilities.get(agent_id, ()))
            )

    def execution_security_snapshot(self) -> dict[str, tuple[str, ...]]:
        """Return canonical capability semantics without process-local revision counters."""

        with self._lock:
            return {
                agent_id: tuple(sorted(capabilities))
                for agent_id, capabilities in sorted(self._capabilities.items())
            }

    def authorize_control(
        self,
        operation: str,
        *,
        source_agent: str,
        destination_agent: str,
        correlation_id: str,
        parameters: dict[str, str] | None = None,
        ttl_seconds: float = 300.0,
    ) -> AuthorizedControl:
        if not operation or len(operation) > 200:
            raise ValueError("control operation must be bounded")
        if source_agent not in self._tokens or destination_agent not in self._tokens:
            raise ValueError("control authorization agents must be registered")
        if not correlation_id or len(correlation_id) > 200:
            raise ValueError("control correlation_id must be bounded")
        if ttl_seconds <= 0 or ttl_seconds > 3_600:
            raise ValueError("control authorization TTL must be between 0 and 3,600 seconds")
        control = AuthorizedControl(
            "control-auth-" + uuid.uuid4().hex,
            operation,
            source_agent,
            destination_agent,
            correlation_id,
            time.monotonic_ns() + int(ttl_seconds * 1_000_000_000),
            dict(parameters or {}),
        )
        self._controls[control.authorization_id] = control
        return control

    def authenticate(self, authority: AgentAuthority, source_agent: str) -> bool:
        with self._lock:
            expected = self._tokens.get(source_agent)
            return (
                authority.agent_id == source_agent
                and expected is not None
                and secrets.compare_digest(expected, authority.token)
            )

    def has_agent(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._tokens

    def has_capability(self, agent_id: str, capability: str) -> bool:
        with self._lock:
            return capability in self._capabilities.get(agent_id, frozenset())

    def consume_control(
        self,
        control: AuthorizedControl,
        *,
        source_agent: str,
        destination_agent: str,
        correlation_id: str,
    ) -> str | None:
        registered = self._controls.get(control.authorization_id)
        if registered != control:
            return "UNAUTHORIZED_CONTROL_MESSAGE"
        if (
            control.source_agent != source_agent
            or control.destination_agent != destination_agent
            or control.correlation_id != correlation_id
        ):
            return "CONTROL_AUTHORIZATION_SCOPE_MISMATCH"
        if control.authorization_id in self._used_controls:
            return "CONTROL_AUTHORIZATION_REPLAYED"
        if time.monotonic_ns() > control.expires_at_ns:
            return "CONTROL_AUTHORIZATION_EXPIRED"
        self._used_controls.add(control.authorization_id)
        return None


class AgentMessageBoundary:
    def __init__(
        self,
        directory: AgentDirectory,
        events: CausalEventStore,
        *,
        sequence_policy: SequencePolicy | None = None,
        fragment_window: int = 4,
        execution_gate: Callable[[], None] | None = None,
    ) -> None:
        self.directory = directory
        self.events = events
        self.sequence_policy = sequence_policy or SequencePolicy()
        if fragment_window < 1 or fragment_window > 16:
            raise ValueError("fragment_window must be between 1 and 16")
        self.fragment_window = fragment_window
        self._execution_gate = execution_gate
        self._recent: dict[tuple[str, str, str], list[str]] = {}

    def send(self, authority: AgentAuthority, request: AgentMessageRequest) -> AgentMessageResult:
        if self._execution_gate is not None:
            self._execution_gate()
        source_content = self.events.register_envelope(request.content)
        if source_content is not request.content:
            request = AgentMessageRequest(
                request.source_agent,
                request.destination_agent,
                request.purpose,
                source_content,
                request.correlation_id,
                request.causal_parent_ids,
                request.requested_capability,
                request.control,
            )
        message_id = "agent-message-" + uuid.uuid4().hex
        try:
            self.events.validate_parent_ids(request.causal_parent_ids)
        except ValueError:
            return self._contained(
                message_id,
                request,
                AgentMessageDecision.BLOCK,
                "INVALID_CAUSAL_PARENT",
                causal_parent_ids=(),
            )
        if len(request.content.content) > 250_000:
            return self._contained(
                message_id, request, AgentMessageDecision.BLOCK, "AGENT_MESSAGE_TOO_LARGE"
            )
        if not self.directory.authenticate(authority, request.source_agent):
            return self._contained(
                message_id, request, AgentMessageDecision.BLOCK, "AGENT_AUTHENTICATION_FAILED"
            )
        if not self.directory.has_agent(request.destination_agent):
            return self._contained(
                message_id, request, AgentMessageDecision.BLOCK, "UNKNOWN_DESTINATION_AGENT"
            )
        if request.purpose is MessagePurpose.CONTROL:
            if request.control is None:
                return self._contained(
                    message_id, request, AgentMessageDecision.BLOCK, "UNAUTHORIZED_CONTROL_MESSAGE"
                )
            control_error = self.directory.consume_control(
                request.control,
                source_agent=request.source_agent,
                destination_agent=request.destination_agent,
                correlation_id=request.correlation_id,
            )
            if control_error is not None:
                return self._contained(
                    message_id, request, AgentMessageDecision.BLOCK, control_error
                )
        elif request.control is not None:
            return self._contained(
                message_id, request, AgentMessageDecision.BLOCK, "CONTROL_IN_DATA_MESSAGE"
            )

        inspection = inspect_content(request.content.content)
        envelope = ContentEnvelope.derive(
            request.content.content,
            parents=(request.content,),
            source_type=ContentSourceType.AGENT_MESSAGE,
            producing_boundary="agent_message_boundary",
            transformation="agent_message_forward",
            producer=request.source_agent,
            security_findings=inspection.findings,
            inspection_sha256=inspection.inspection_sha256,
        )
        key = (request.source_agent, request.destination_agent, request.correlation_id)
        recent = self._recent.setdefault(key, [])
        recent.append(request.content.content)
        del recent[: max(0, len(recent) - self.fragment_window)]
        combined = inspect_content("".join(recent))
        suspicious = inspection.suspicious or (len(recent) > 1 and combined.suspicious)

        ancestry = self.events.ancestry(request.causal_parent_ids)
        if request.requested_capability is not None:
            policy = self.sequence_policy.evaluate(
                SecurityEventType.CAPABILITY_REQUEST,
                envelope=envelope,
                ancestry=ancestry,
                privileged=True,
            )
            if policy.decision is not SequenceDecision.ALLOW:
                decision = (
                    AgentMessageDecision.BLOCK
                    if policy.decision is SequenceDecision.BLOCK
                    else AgentMessageDecision.REVIEW
                )
                return self._contained(message_id, request, decision, policy.reason_code)
        if suspicious and request.purpose is not MessagePurpose.CONTROL:
            return self._contained(
                message_id,
                request,
                AgentMessageDecision.REVIEW,
                "SUSPICIOUS_ENCODED_OR_FRAGMENTED_MESSAGE",
            )
        event = SecurityEvent.create(
            request.correlation_id,
            SecurityEventType.AGENT_MESSAGE,
            causal_parent_ids=request.causal_parent_ids,
            content_ids=(envelope.content_id,),
            attributes={
                "source_agent": request.source_agent,
                "destination_agent": request.destination_agent,
                "purpose": request.purpose.value,
                "requested_capability": request.requested_capability or "",
                "capability_granted": "false",
                "content_trust": envelope.trust.value,
                "ever_untrusted": str(envelope.ever_untrusted).lower(),
                "producing_boundary": envelope.producing_boundary,
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
        accepted = AgentMessageRequest(
            request.source_agent,
            request.destination_agent,
            request.purpose,
            envelope,
            request.correlation_id,
            request.causal_parent_ids,
            request.requested_capability,
            request.control,
        )
        # Even an allowed message grants no capability. Control is a separately
        # authorized typed directive and does not bypass downstream boundaries.
        return AgentMessageResult(
            message_id,
            AgentMessageDecision.ALLOW,
            "MESSAGE_ALLOWED",
            accepted,
            event.event_id,
            (),
        )

    def _contained(
        self,
        message_id: str,
        request: AgentMessageRequest,
        decision: AgentMessageDecision,
        reason_code: str,
        *,
        causal_parent_ids: tuple[str, ...] | None = None,
    ) -> AgentMessageResult:
        event = SecurityEvent.create(
            request.correlation_id,
            SecurityEventType.POLICY_DECISION,
            causal_parent_ids=(
                request.causal_parent_ids if causal_parent_ids is None else causal_parent_ids
            ),
            content_ids=(request.content.content_id,),
            attributes={
                "operation": SecurityEventType.AGENT_MESSAGE.value,
                "decision": decision.value,
                "reason_code": reason_code,
                "source_agent": request.source_agent,
                "destination_agent": request.destination_agent,
                "content_trust": request.content.trust.value,
                "ever_untrusted": str(request.content.ever_untrusted).lower(),
                "capability_granted": "false",
            },
        )
        self.events.append(event)
        return AgentMessageResult(message_id, decision, reason_code, None, event.event_id, ())
