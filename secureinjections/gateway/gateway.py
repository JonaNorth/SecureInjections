"""Reusable guarded boundary gateway for local tool-using workflows."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, cast

from ..guard import Guard, GuardDecision, InspectionRequest, InspectionResult, TrustLevel
from ..persistent_state import IdempotencyClass
from ..persistent_state.fake_destination import FakeDestination, FakeDestinationMode
from .agent_boundary import (
    AgentAuthority,
    AgentDirectory,
    AgentMessageBoundary,
    AgentMessageRequest,
    AgentMessageResult,
)
from .content_inspection import inspect_content
from .envelope import ContentEnvelope, ContentSourceType, least_trusted
from .execution import (
    DestinationClassification,
    GatewayExecutionError,
    GatewayExecutionHostControl,
    GatewayExecutionOutcome,
    GatewayExecutionPreparation,
    GatewayExecutionRuntime,
    GatewayRecoveryPolicy,
    GatewayWorker,
)
from .file_access import FileReadDecision, FileReadRequest, FileReadResult, SafeFileReader
from .memory import (
    MemoryDecision,
    MemoryReadResult,
    MemoryWriteRequest,
    MemoryWriteResult,
    ProvenanceMemory,
)
from .models import (
    BoundaryAuditEvent,
    BoundaryStage,
    GatewayResult,
    GatewayStatus,
    GuardSummary,
)
from .persistent_runtime import (
    PersistentCausalEventStore,
    PersistentRuntimeConfig,
    PersistentRuntimeError,
    RuntimeBackend,
    open_persistent_runtime,
    runtime_action_fingerprint,
)
from .recovery import (
    GatewayRecoveryCandidate,
    GatewayRecoveryCoordinator,
    GatewayRecoveryOutcome,
)
from .runtime_context import RuntimeDerivedOutput, RuntimeSecurityContext
from .sequence import CausalEventStore, SecurityEvent, SecurityEventType, SequencePolicy
from .tools import LocalToolRegistry, ToolRegistryError, _GatewayCapability


class GuardedToolGateway:
    """The only workflow-facing path to protected local tools and side effects."""

    MAX_ACTIVE_WORKFLOWS = 1_024

    def __init__(
        self,
        guard: Guard,
        tools: LocalToolRegistry,
        *,
        agent_directory: AgentDirectory | None = None,
        event_store: CausalEventStore | None = None,
        backend: RuntimeBackend = RuntimeBackend.EPHEMERAL,
        persistent_config: PersistentRuntimeConfig | None = None,
        recovery_policy: GatewayRecoveryPolicy | None = None,
    ) -> None:
        if not isinstance(backend, RuntimeBackend):
            raise TypeError("backend must be a RuntimeBackend value")
        if backend is RuntimeBackend.PERSISTENT:
            if event_store is not None or persistent_config is None:
                raise ValueError("persistent mode requires its explicit persistent configuration")
            event_store = open_persistent_runtime(persistent_config)
        elif persistent_config is not None:
            raise ValueError("persistent configuration requires PERSISTENT backend selection")
        self.backend = backend
        self.guard = guard
        self.__tools = tools
        self.__capability: _GatewayCapability = tools._gateway_capability()
        self.__events: dict[str, list[BoundaryAuditEvent]] = {}
        self.__workflow_tails: dict[str, str] = {}
        self.__workflow_envelopes: dict[str, ContentEnvelope] = {}
        self.__content_envelopes: dict[str, ContentEnvelope] = {}
        self.__workflow_turns: dict[str, int] = {}
        self.__consumed_model_turns: set[str] = set()
        self.__consumed_model_outputs: set[str] = set()
        self.__consumed_agent_messages: set[str] = set()
        self.__runtime_external_approvals: dict[object, tuple[str, str, str]] = {}
        self.__execution: GatewayExecutionRuntime | None = None
        self.__recovery: GatewayRecoveryCoordinator | None = None
        self.security_events = event_store or CausalEventStore(audit_path=guard.audit_path)
        self.sequence_policy = SequencePolicy()
        self.agent_directory = agent_directory or AgentDirectory()
        self.agent_messages = AgentMessageBoundary(
            self.agent_directory,
            self.security_events,
            sequence_policy=self.sequence_policy,
            execution_gate=self._reject_direct_c2_side_effect,
        )
        self.memory = ProvenanceMemory(
            self.security_events,
            sequence_policy=self.sequence_policy,
            execution_gate=self._reject_direct_c2_side_effect,
        )
        self.file_reader = SafeFileReader(
            tools._gateway_file_policy(self.__capability),
            guard=guard,
            audit_path=guard.audit_path,
            execution_gate=self._reject_direct_c2_side_effect,
        )
        if isinstance(self.security_events, PersistentCausalEventStore):
            try:
                self.__execution = GatewayExecutionRuntime(
                    self,
                    self.security_events,
                    self.agent_directory,
                    self.sequence_policy,
                    recovery_policy,
                )
                self.__recovery = GatewayRecoveryCoordinator(self.__execution)
            except Exception:
                self.security_events.close()
                raise

    def __copy__(self) -> object:
        raise TypeError("Gateway authority objects are not copyable")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("Gateway authority objects are not copyable")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("Gateway authority objects are not serializable")

    @staticmethod
    def new_workflow_id() -> str:
        return "gateway-run-" + uuid.uuid4().hex

    def close(self) -> None:
        """Close persistent authority resources; ephemeral mode has nothing to release."""

        if isinstance(self.security_events, PersistentCausalEventStore):
            self.security_events.close()

    def _execution_control_for_host(self) -> GatewayExecutionHostControl:
        """DANGEROUS_INTERNAL: issue no authority unless persistent c2 is enabled."""

        return self._require_execution_runtime().host_control()

    def register_fake_execution_destination(
        self,
        control: GatewayExecutionHostControl,
        *,
        destination_id: str,
        action_types: tuple[str, ...],
        runner: FakeDestination,
        runner_identity: str,
        configuration: Mapping[str, Any],
        idempotency_class: IdempotencyClass,
        required_capability: str,
        classification: DestinationClassification = DestinationClassification.DEVELOPMENT_TEST_ONLY,
    ) -> None:
        """CAPABILITY_PROTECTED: register a deterministic local c2 destination."""

        self._require_execution_runtime().register_fake_destination(
            control,
            destination_id=destination_id,
            action_types=action_types,
            runner=runner,
            runner_identity=runner_identity,
            configuration=configuration,
            idempotency_class=idempotency_class,
            required_capability=required_capability,
            classification=classification,
        )

    def prepare_runtime_execution(
        self,
        output: RuntimeDerivedOutput,
        action: Mapping[str, Any] | str,
        *,
        destination_id: str,
        agent: AgentAuthority,
    ) -> GatewayExecutionPreparation:
        """SAFE_BY_CONSTRUCTION: apply current policy and consume source authority."""

        return self._require_execution_runtime().prepare(
            output, action, destination_id=destination_id, agent=agent
        )

    def register_runtime_execution_worker(
        self, agent: AgentAuthority, *, scope: str
    ) -> GatewayWorker:
        """CAPABILITY_PROTECTED: register a current local runtime worker."""

        return self._require_execution_runtime().register_worker(agent, scope=scope)

    def execute_prepared_runtime_action(
        self,
        worker: GatewayWorker,
        agent: AgentAuthority,
        intent_id: str,
        *,
        mode: FakeDestinationMode = FakeDestinationMode.SUCCESS,
        lease_seconds: float = 30.0,
    ) -> GatewayExecutionOutcome:
        """CAPABILITY_PROTECTED: revalidate and cross the persistent dispatch fence."""

        return self._require_execution_runtime().execute(
            worker, agent, intent_id, mode=mode, lease_seconds=lease_seconds
        )

    def replace_execution_capabilities(
        self,
        control: GatewayExecutionHostControl,
        agent_id: str,
        capabilities: tuple[str, ...],
    ) -> int:
        return self._require_execution_runtime().replace_agent_capabilities(
            control, agent_id, capabilities
        )

    def disable_execution_destination(
        self, control: GatewayExecutionHostControl, destination_id: str
    ) -> None:
        self._require_execution_runtime().disable_destination(control, destination_id)

    def advance_execution_policy_revision(self, control: GatewayExecutionHostControl) -> int:
        return self._require_execution_runtime().advance_policy_revision(control)

    def replace_execution_recovery_policy(
        self,
        control: GatewayExecutionHostControl,
        policy: GatewayRecoveryPolicy,
    ) -> GatewayRecoveryPolicy:
        return self._require_execution_runtime().replace_recovery_policy(control, policy)

    def discover_unresolved_runtime_actions(
        self,
        control: GatewayExecutionHostControl,
        *,
        limit: int = 128,
    ) -> tuple[GatewayRecoveryCandidate, ...]:
        """CAPABILITY_PROTECTED: discover unresolved targets from authenticated state only."""

        return self._require_recovery_coordinator().discover(control, limit=limit)

    def diagnose_runtime_recovery(
        self,
        control: GatewayExecutionHostControl,
        candidate: GatewayRecoveryCandidate,
        *,
        automatic: bool = False,
    ) -> GatewayRecoveryCandidate:
        """CAPABILITY_PROTECTED: reconcile/query one host-discovered candidate."""

        return self._require_recovery_coordinator().diagnose(
            control, candidate, automatic=automatic
        )

    def approve_runtime_recovery(
        self,
        control: GatewayExecutionHostControl,
        candidate: GatewayRecoveryCandidate,
    ) -> GatewayRecoveryCandidate:
        """CAPABILITY_PROTECTED: apply the current explicit host recovery policy."""

        return self._require_recovery_coordinator().approve(control, candidate)

    def execute_approved_runtime_recovery(
        self,
        worker: GatewayWorker,
        agent: AgentAuthority,
        candidate: GatewayRecoveryCandidate,
        *,
        mode: FakeDestinationMode = FakeDestinationMode.SUCCESS,
        lease_seconds: float = 30.0,
    ) -> GatewayRecoveryOutcome:
        """CAPABILITY_PROTECTED: consume one authenticated c3b recovery authorization."""

        return self._require_recovery_coordinator().execute(
            worker,
            agent,
            candidate,
            mode=mode,
            lease_seconds=lease_seconds,
        )

    def issue_execution_worker_attach_token(self, control: GatewayExecutionHostControl) -> str:
        return self._require_execution_runtime().worker_attach_token(control)

    def _require_execution_runtime(self) -> GatewayExecutionRuntime:
        if self.__execution is None:
            raise RuntimeError("persistent execution integration is unavailable in EPHEMERAL mode")
        return self.__execution

    def _require_recovery_coordinator(self) -> GatewayRecoveryCoordinator:
        if self.__recovery is None:
            raise RuntimeError("Gateway recovery integration requires persistent authority")
        return self.__recovery

    def _reject_direct_c2_side_effect(self) -> None:
        if self.__execution is not None and self.__execution.active:
            raise GatewayExecutionError(
                "C2_EXECUTION_PATH_REQUIRED",
                "c2-managed persistent state requires intent and dispatch authority",
            )

    def inspect_user_input(
        self, content: str, *, workflow_id: str | None = None, dry_run: bool = False
    ) -> GatewayResult:
        correlation_id = workflow_id or self.new_workflow_id()
        self._admit_workflow(correlation_id)
        result = self._inspect_boundary(
            content,
            source="user",
            destination="model",
            stage=BoundaryStage.INGRESS,
            operation_type="forward_user_input",
            workflow_id=correlation_id,
            dry_run=dry_run,
        )
        if result.status is GatewayStatus.PROCEEDED:
            inspection = inspect_content(content)
            envelope = ContentEnvelope._create_authoritative(
                content,
                source_type=ContentSourceType.USER,
                trust=TrustLevel.TRUSTED,
                provenance=(f"user:{correlation_id}",),
                producing_boundary="gateway_user_ingress",
                security_findings=inspection.findings,
                inspection_sha256=inspection.inspection_sha256,
            )
            self._remember_content(correlation_id, envelope, SecurityEventType.CONTENT_TRANSFORM)
        return result

    def inspect_retrieved_content(
        self, content: str, *, workflow_id: str, dry_run: bool = False
    ) -> GatewayResult:
        result = self._inspect_boundary(
            content,
            source="retrieved_content",
            destination="model",
            stage=BoundaryStage.RETRIEVAL,
            operation_type="forward_retrieved_content",
            workflow_id=workflow_id,
            dry_run=dry_run,
        )
        if result.status is GatewayStatus.PROCEEDED and not dry_run:
            inspection = inspect_content(content)
            parent = self.current_content(workflow_id)
            envelope = (
                ContentEnvelope.derive(
                    content,
                    parents=(parent,),
                    source_type=ContentSourceType.RETRIEVAL,
                    producing_boundary="gateway_retrieval",
                    transformation="retrieval_normalization",
                    producer="gateway",
                    requested_trust=TrustLevel.UNTRUSTED,
                    security_findings=inspection.findings,
                    inspection_sha256=inspection.inspection_sha256,
                )
                if parent is not None
                else ContentEnvelope._create_authoritative(
                    content,
                    source_type=ContentSourceType.RETRIEVAL,
                    trust=TrustLevel.UNTRUSTED,
                    provenance=(f"retrieval:{workflow_id}",),
                    producing_boundary="gateway_retrieval",
                    security_findings=inspection.findings,
                    inspection_sha256=inspection.inspection_sha256,
                )
            )
            self._remember_content(workflow_id, envelope, SecurityEventType.CONTENT_TRANSFORM)
        return result

    def current_content(self, workflow_id: str) -> ContentEnvelope | None:
        """Return host-owned current content for runtime composition."""

        if isinstance(self.security_events, PersistentCausalEventStore):
            current = self.security_events.workflow_content(workflow_id)
            if current is not None:
                self.__workflow_envelopes[workflow_id] = current
                self.__content_envelopes[current.content_id] = current
            return current
        return self.__workflow_envelopes.get(workflow_id)

    def current_causal_parent_ids(self, workflow_id: str) -> tuple[str, ...]:
        """Return the current causal tail without exposing mutation authority."""

        return self._tail_parents(workflow_id)

    def attach_safe_file_context(
        self, workflow_id: str, envelope: ContentEnvelope
    ) -> ContentEnvelope:
        """Attach an existing host-authoritative SafeFileReader ALLOW envelope."""

        if not self._tail_parents(workflow_id):
            raise ValueError("safe file context requires an active guarded workflow")
        if (
            not envelope.authoritative
            or envelope.source_type is not ContentSourceType.FILE
            or envelope.producing_boundary != "safe_file_reader"
            or envelope.inspection_sha256 is None
            or any(item.suspicious for item in envelope.security_findings)
        ):
            raise ValueError("safe file context is not an authoritative allowed file envelope")
        self._remember_content(workflow_id, envelope, SecurityEventType.CONTENT_TRANSFORM)
        return envelope

    def begin_model_turn(
        self,
        workflow_id: str,
        *,
        input_envelopes: tuple[ContentEnvelope, ...] = (),
        causal_parent_ids: tuple[str, ...] = (),
        turn: int,
    ) -> RuntimeSecurityContext:
        """Bind a model call to authoritative inputs before invoking a provider."""

        expected_turn = self._current_turn(workflow_id) + 1
        if turn != expected_turn:
            raise ValueError(f"model turn must be the next host sequence number ({expected_turn})")
        inputs = input_envelopes
        if not inputs:
            current = self.current_content(workflow_id)
            inputs = (current,) if current is not None else ()
        if not inputs:
            raise ValueError("model turn requires at least one host-owned input envelope")
        if len(inputs) > 64:
            raise ValueError("model turn exceeds the 64-envelope input limit")
        if any(self.__content_envelopes.get(item.content_id) != item for item in inputs):
            raise ValueError("model turn input is not a gateway-recorded envelope")
        parents = causal_parent_ids or self._tail_parents(workflow_id)
        if len(parents) > 128:
            raise ValueError("model turn exceeds the 128-parent causal limit")
        self.security_events.validate_parent_ids(parents)
        turn_attributes = {
            "turn": str(turn),
            "input_count": str(len(inputs)),
            "trust_floor": least_trusted(tuple(item.trust for item in inputs)).value,
            "ever_untrusted": str(any(item.ever_untrusted for item in inputs)).lower(),
        }
        if isinstance(self.security_events, PersistentCausalEventStore):
            turn_attributes["boot_epoch"] = self.security_events.boot_epoch
        event = SecurityEvent.create(
            workflow_id,
            SecurityEventType.MODEL_TURN,
            causal_parent_ids=parents,
            content_ids=tuple(item.content_id for item in inputs),
            attributes=turn_attributes,
        )
        self.security_events.append(event)
        self.__workflow_tails[workflow_id] = event.event_id
        self.__workflow_turns[workflow_id] = turn
        return RuntimeSecurityContext._from_host(
            correlation_id=workflow_id,
            turn_id=f"{workflow_id}:turn:{turn}",
            turn_event_id=event.event_id,
            input_envelopes=inputs,
            causal_parent_ids=parents,
        )

    def derive_model_output(
        self,
        content: str,
        *,
        context: RuntimeSecurityContext,
        action_type: str,
    ) -> RuntimeDerivedOutput:
        """Derive normalized output solely from the host-owned turn ancestry."""

        turn_event = self.security_events.get(context.turn_event_id)
        turn_number = turn_event.attributes.get("turn") if turn_event is not None else None
        recorded_inputs = self._recorded_event_content(turn_event)
        expected_context = (
            RuntimeSecurityContext._from_host(
                correlation_id=turn_event.correlation_id,
                turn_id=f"{turn_event.correlation_id}:turn:{turn_number}",
                turn_event_id=turn_event.event_id,
                input_envelopes=recorded_inputs,
                causal_parent_ids=turn_event.causal_parent_ids,
            )
            if turn_event is not None and turn_number is not None
            else None
        )
        if (
            turn_event is None
            or turn_event.event_type is not SecurityEventType.MODEL_TURN
            or turn_event.correlation_id != context.correlation_id
            or tuple(turn_event.content_ids) != context.input_envelope_ids
            or expected_context != context
            or self._tail_parents(context.correlation_id) != (context.turn_event_id,)
            or context.turn_event_id in self.__consumed_model_turns
            or (
                isinstance(self.security_events, PersistentCausalEventStore)
                and turn_event.attributes.get("boot_epoch") != self.security_events.boot_epoch
            )
        ):
            raise ValueError("runtime context is not bound to the active causal event store")
        inspection = inspect_content(content)
        envelope = ContentEnvelope.derive(
            content,
            parents=context.input_envelopes,
            source_type=ContentSourceType.MODEL,
            producing_boundary="local_agent_protocol_normalization",
            transformation=f"model_{action_type.casefold()}",
            producer="model",
            security_findings=inspection.findings,
            inspection_sha256=inspection.inspection_sha256,
        )
        envelope = self._register_envelope(envelope)
        event = SecurityEvent.create(
            context.correlation_id,
            SecurityEventType.MODEL_OUTPUT,
            causal_parent_ids=(context.turn_event_id,),
            content_ids=(envelope.content_id,),
            attributes={
                "turn_id": context.turn_id,
                "action_type": action_type,
                "content_trust": envelope.trust.value,
                "ever_untrusted": str(envelope.ever_untrusted).lower(),
                "producing_boundary": envelope.producing_boundary,
            },
        )
        self.security_events.append(event)
        persistent_reason = self.security_events.consume_once(
            "model_turn", context.turn_event_id, event.event_id
        )
        if persistent_reason is not None:
            raise ValueError("model turn authority was already consumed")
        self.__consumed_model_turns.add(context.turn_event_id)
        self._prune_consumed_events()
        self.__workflow_tails[context.correlation_id] = event.event_id
        self.__workflow_envelopes[context.correlation_id] = envelope
        return RuntimeDerivedOutput(action_type, envelope, event.event_id, context)

    def dispatch_runtime_tool_call(
        self,
        output: RuntimeDerivedOutput | None,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        workflow_id: str,
        dry_run: bool = False,
    ) -> GatewayResult:
        if self.__execution is not None and self.__execution.active:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.PRE_TOOL,
                SecurityEventType.TOOL_PROPOSAL,
                "C2_EXECUTION_PATH_REQUIRED",
            )
        expected_payload = {"action": "TOOL_CALL", "tool": tool_name, "arguments": dict(arguments)}
        privileged = _privileged_tool(tool_name)
        reason = self._claim_runtime_output(
            output, workflow_id, "TOOL_CALL", None, privileged=privileged
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id, BoundaryStage.PRE_TOOL, SecurityEventType.TOOL_PROPOSAL, reason
            )
        assert output is not None
        if not _runtime_action_payload_matches(output, expected_payload):
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.PRE_TOOL,
                SecurityEventType.TOOL_PROPOSAL,
                "RUNTIME_ACTION_PAYLOAD_MISMATCH",
            )
        reason = self._claim_runtime_output(
            output, workflow_id, "TOOL_CALL", expected_payload, privileged=privileged
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.PRE_TOOL,
                SecurityEventType.TOOL_PROPOSAL,
                reason,
            )
        return self.dispatch_tool_call(
            tool_name,
            arguments,
            workflow_id=workflow_id,
            source_envelope=output.envelope,
            causal_parent_ids=(output.event_id,),
            dry_run=dry_run,
        )

    def write_runtime_memory(
        self,
        output: RuntimeDerivedOutput | None,
        record: Mapping[str, Any],
        *,
        workflow_id: str,
        dry_run: bool = False,
    ) -> GatewayResult:
        if self.__execution is not None and self.__execution.active:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.MEMORY,
                SecurityEventType.MEMORY_WRITE,
                "C2_EXECUTION_PATH_REQUIRED",
            )
        expected_payload = {"action": "MEMORY_WRITE", "memory": dict(record)}
        reason = self._claim_runtime_output(
            output, workflow_id, "MEMORY_WRITE", None, privileged=True
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id, BoundaryStage.MEMORY, SecurityEventType.MEMORY_WRITE, reason
            )
        assert output is not None
        if not _runtime_action_payload_matches(output, expected_payload):
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.MEMORY,
                SecurityEventType.MEMORY_WRITE,
                "RUNTIME_ACTION_PAYLOAD_MISMATCH",
            )
        reason = self._claim_runtime_output(
            output, workflow_id, "MEMORY_WRITE", expected_payload, privileged=True
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.MEMORY,
                SecurityEventType.MEMORY_WRITE,
                reason,
            )
        return self.write_memory(
            record,
            workflow_id=workflow_id,
            source_envelope=output.envelope,
            causal_parent_ids=(output.event_id,),
            dry_run=dry_run,
        )

    def send_runtime_external(
        self,
        output: RuntimeDerivedOutput | None,
        transfer: Mapping[str, Any],
        *,
        workflow_id: str,
        approval: object | None = None,
        dry_run: bool = False,
    ) -> GatewayResult:
        if self.__execution is not None and self.__execution.active:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EXTERNAL,
                SecurityEventType.EXTERNAL_SEND,
                "C2_EXECUTION_PATH_REQUIRED",
            )
        expected_payload = {"action": "EXTERNAL_SEND", "external": dict(transfer)}
        reason = self._claim_runtime_output(
            output, workflow_id, "EXTERNAL_SEND", None, privileged=True
        )
        if reason is not None:
            if output is not None:
                self._revoke_runtime_external_approvals(workflow_id, output.event_id)
            return self._runtime_context_failure(
                workflow_id, BoundaryStage.EXTERNAL, SecurityEventType.EXTERNAL_SEND, reason
            )
        assert output is not None
        if not _runtime_action_payload_matches(output, expected_payload):
            self._revoke_runtime_external_approvals(workflow_id, output.event_id)
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EXTERNAL,
                SecurityEventType.EXTERNAL_SEND,
                "RUNTIME_ACTION_PAYLOAD_MISMATCH",
            )
        if output.envelope.ever_untrusted or output.envelope.security_findings:
            preflight = self.send_external(
                transfer,
                workflow_id=workflow_id,
                source_envelope=output.envelope,
                causal_parent_ids=(output.event_id,),
                _effect_authorized=False,
            )
            self._revoke_runtime_external_approvals(workflow_id, output.event_id)
            if preflight.status is not GatewayStatus.PROCEEDED:
                return preflight
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EXTERNAL,
                SecurityEventType.EXTERNAL_SEND,
                "HOST_EXTERNAL_APPROVAL_REQUIRED",
            )
        expected_approval = (
            workflow_id,
            output.event_id,
            runtime_action_fingerprint(expected_payload),
        )
        binding = self.__runtime_external_approvals.pop(approval, None)
        if binding != expected_approval:
            self._revoke_runtime_external_approvals(workflow_id, output.event_id)
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EXTERNAL,
                SecurityEventType.EXTERNAL_SEND,
                "HOST_EXTERNAL_APPROVAL_REQUIRED",
            )
        reason = self._claim_runtime_output(
            output, workflow_id, "EXTERNAL_SEND", expected_payload, privileged=True
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EXTERNAL,
                SecurityEventType.EXTERNAL_SEND,
                reason,
            )
        return self.send_external(
            transfer,
            workflow_id=workflow_id,
            source_envelope=output.envelope,
            causal_parent_ids=(output.event_id,),
            dry_run=dry_run,
        )

    def _revoke_runtime_external_approvals(self, workflow_id: str, event_id: str) -> None:
        stale = [
            approval
            for approval, binding in self.__runtime_external_approvals.items()
            if binding[:2] == (workflow_id, event_id)
        ]
        for approval in stale:
            self.__runtime_external_approvals.pop(approval, None)

    def authorize_runtime_external(
        self,
        output: RuntimeDerivedOutput | None,
        transfer: Mapping[str, Any],
        *,
        workflow_id: str,
    ) -> object:
        """Issue one exact host-owned approval for a model-origin external action."""

        if self.__execution is not None and self.__execution.active:
            raise GatewayExecutionError(
                "C2_EXECUTION_PATH_REQUIRED",
                "persistent external execution requires c2 authority",
            )
        expected_payload = {"action": "EXTERNAL_SEND", "external": dict(transfer)}
        reason = self._validate_runtime_output_for_execution(
            output, workflow_id, "EXTERNAL_SEND", None
        )
        if reason is not None or output is None:
            raise GatewayExecutionError(
                reason or "RUNTIME_CONTEXT_MISSING",
                "runtime external approval requires current model-output authority",
            )
        if not _runtime_action_payload_matches(output, expected_payload):
            raise GatewayExecutionError(
                "RUNTIME_ACTION_PAYLOAD_MISMATCH",
                "runtime external approval payload does not match model output",
            )
        if len(self.__runtime_external_approvals) >= self.MAX_ACTIVE_WORKFLOWS:
            raise GatewayExecutionError(
                "EXTERNAL_APPROVAL_CAPACITY",
                "runtime external approval capacity is exhausted",
            )
        approval = object()
        self.__runtime_external_approvals[approval] = (
            workflow_id,
            output.event_id,
            runtime_action_fingerprint(expected_payload),
        )
        return approval

    def release_runtime_final(
        self,
        output: RuntimeDerivedOutput | None,
        content: str,
        *,
        workflow_id: str,
        dry_run: bool = False,
    ) -> GatewayResult:
        expected_payload = {"action": "FINAL_RESPONSE", "response": content}
        reason = self._claim_runtime_output(
            output, workflow_id, "FINAL_RESPONSE", None, privileged=False
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EGRESS,
                SecurityEventType.MODEL_OUTPUT,
                reason,
            )
        assert output is not None
        if content != output.envelope.content:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EGRESS,
                SecurityEventType.MODEL_OUTPUT,
                "RUNTIME_ACTION_PAYLOAD_MISMATCH",
            )
        reason = self._claim_runtime_output(
            output, workflow_id, "FINAL_RESPONSE", expected_payload, privileged=False
        )
        if reason is not None:
            return self._runtime_context_failure(
                workflow_id,
                BoundaryStage.EGRESS,
                SecurityEventType.MODEL_OUTPUT,
                reason,
            )
        return self.inspect_model_output(content, workflow_id=workflow_id, dry_run=dry_run)

    def create_content(
        self,
        content: str,
        *,
        source_type: ContentSourceType,
        trust: TrustLevel,
        provenance: tuple[str, ...],
        producing_boundary: str,
    ) -> ContentEnvelope:
        """Create host-authoritative content metadata at a trusted application boundary."""

        inspection = inspect_content(content)
        envelope = ContentEnvelope._create_authoritative(
            content,
            source_type=source_type,
            trust=trust,
            provenance=provenance,
            producing_boundary=producing_boundary,
            security_findings=inspection.findings,
            inspection_sha256=inspection.inspection_sha256,
        )
        return self._register_envelope(envelope)

    def read_file(self, request: FileReadRequest) -> FileReadResult:
        """Execute an explicit typed file request through pre/post-read policy."""

        self._reject_direct_c2_side_effect()

        effective_parents = request.causal_parent_ids or self._tail_parents(request.correlation_id)
        if effective_parents != request.causal_parent_ids:
            request = replace(request, causal_parent_ids=effective_parents)
        self.security_events.validate_parent_ids(request.causal_parent_ids)
        result = self.file_reader.read(request)
        if result.content_was_read:
            self.__tools._record_workspace_read(self.__capability)
        if result.envelope is not None:
            persisted_envelope = self._register_envelope(result.envelope)
            result = replace(result, envelope=persisted_envelope)
        event = SecurityEvent.create(
            request.correlation_id,
            SecurityEventType.FILE_READ,
            causal_parent_ids=request.causal_parent_ids,
            content_ids=(result.content_id,) if result.content_id is not None else (),
            attributes={
                "request_id": result.request_id,
                "decision": result.decision.value,
                "reason_code": result.reason_code.value,
                "sensitive": str(result.sensitive).lower(),
                "audit_id": result.audit_id,
            },
        )
        self.security_events.append(event)
        self.__workflow_tails[request.correlation_id] = event.event_id
        if result.envelope is not None:
            self.__workflow_envelopes[request.correlation_id] = result.envelope
        return replace(result, event_id=event.event_id)

    def send_agent_message(
        self, authority: AgentAuthority, request: AgentMessageRequest
    ) -> AgentMessageResult:
        self._reject_direct_c2_side_effect()
        parents = request.causal_parent_ids or self._tail_parents(request.correlation_id)
        if parents != request.causal_parent_ids:
            request = replace(request, causal_parent_ids=parents)
        result = self.agent_messages.send(authority, request)
        if result.event_id is not None:
            self.__workflow_tails[request.correlation_id] = result.event_id
        if result.message is not None:
            self.__workflow_envelopes[request.correlation_id] = result.message.content
            self._register_envelope(result.message.content)
        return result

    def resolve_agent_message_input(
        self,
        result: AgentMessageResult,
        *,
        destination_agent: str,
    ) -> tuple[ContentEnvelope, str] | None:
        """Revalidate an accepted message before admitting it to a model turn."""

        if result.message is None or result.event_id is None or result.decision.value != "ALLOW":
            return None
        event = self.security_events.get(result.event_id)
        message = result.message
        if (
            event is None
            or event.event_type is not SecurityEventType.AGENT_MESSAGE
            or event.correlation_id != message.correlation_id
            or event.content_ids != (message.content.content_id,)
            or event.attributes.get("destination_agent") != destination_agent
            or message.destination_agent != destination_agent
            or event.event_id in self.__consumed_agent_messages
        ):
            return None
        persistent_reason = self.security_events.consume_once(
            "agent_message", event.event_id, event.event_id
        )
        if persistent_reason is not None:
            return None
        self.__consumed_agent_messages.add(event.event_id)
        self._prune_consumed_events()
        return message.content, event.event_id

    def write_memory_envelope(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        self._reject_direct_c2_side_effect()
        result = self.memory.write(request)
        if result.event_id is not None:
            self.__workflow_tails[request.correlation_id] = result.event_id
        if result.record is not None:
            self.__workflow_envelopes[request.correlation_id] = result.record.content
            self._register_envelope(result.record.content)
            if isinstance(self.security_events, PersistentCausalEventStore):
                self.security_events.store_memory(result.record)
            self.__tools._write_memory(
                self.__capability,
                {
                    **result.record.metadata_dict(),
                    "content_text": result.record.content.content,
                    "storage_schema": "provenance-memory-v0.1",
                },
            )
        return result

    def read_memory_envelope(
        self, record_id: str, *, destination_agent: str, correlation_id: str
    ) -> MemoryReadResult:
        try:
            if isinstance(self.security_events, PersistentCausalEventStore):
                self.memory._restore_verified_record(self.security_events.load_memory(record_id))
            result = self.memory.read(
                record_id, destination_agent=destination_agent, correlation_id=correlation_id
            )
        except Exception as exc:
            if not isinstance(exc, PersistentRuntimeError):
                raise
            return MemoryReadResult(MemoryDecision.BLOCK, exc.code)
        if result.event_id is not None:
            self.__workflow_tails[correlation_id] = result.event_id
        if result.envelope is not None:
            self.__workflow_envelopes[correlation_id] = result.envelope
            self._register_envelope(result.envelope)
        return result

    def reconstruct_security_chain(self, event_id: str) -> tuple[SecurityEvent, ...]:
        event = self.security_events.get(event_id)
        if event is None:
            return ()
        return (event, *self.security_events.ancestry(event.causal_parent_ids))

    def process_tool_output(
        self, output: Any, *, workflow_id: str, dry_run: bool = False
    ) -> GatewayResult:
        content = _render_value(output)
        guard_result = self.guard.inspect_tool_output(
            content,
            context={"request_id": workflow_id},
            dry_run=dry_run,
        )
        result = self._result(
            guard_result,
            workflow_id,
            BoundaryStage.POST_TOOL,
            "forward_tool_output",
            value=output,
        )
        if result.status is not GatewayStatus.PROCEEDED:
            self._record_policy_decision(
                workflow_id,
                operation=SecurityEventType.CONTENT_TRANSFORM,
                decision=result.status.value,
                reason_code=result.guard.reason_codes[0],
                source_envelope=self.current_content(workflow_id),
            )
        if result.status is GatewayStatus.PROCEEDED and not dry_run:
            inspection = inspect_content(content)
            parent = self.current_content(workflow_id)
            envelope = (
                ContentEnvelope.derive(
                    content,
                    parents=(parent,),
                    source_type=ContentSourceType.TOOL_OUTPUT,
                    producing_boundary="gateway_tool_output",
                    transformation="tool_output_capture",
                    producer="gateway",
                    requested_trust=TrustLevel.UNTRUSTED,
                    security_findings=inspection.findings,
                    inspection_sha256=inspection.inspection_sha256,
                )
                if parent is not None
                else ContentEnvelope._create_authoritative(
                    content,
                    source_type=ContentSourceType.TOOL_OUTPUT,
                    trust=TrustLevel.UNTRUSTED,
                    provenance=(f"tool-output:{workflow_id}",),
                    producing_boundary="gateway_tool_output",
                    security_findings=inspection.findings,
                    inspection_sha256=inspection.inspection_sha256,
                )
            )
            self._remember_content(workflow_id, envelope, SecurityEventType.CONTENT_TRANSFORM)
        return result

    def inspect_model_output(
        self, content: str, *, workflow_id: str, dry_run: bool = False
    ) -> GatewayResult:
        result = self._inspect_boundary(
            content,
            source="model",
            destination="user",
            stage=BoundaryStage.EGRESS,
            operation_type="release_model_output",
            workflow_id=workflow_id,
            dry_run=dry_run,
        )
        if not dry_run:
            self._record_policy_decision(
                workflow_id,
                operation=SecurityEventType.MODEL_OUTPUT,
                decision=result.status.value,
                reason_code=result.guard.reason_codes[0],
                source_envelope=self.current_content(workflow_id),
            )
        return result

    def dispatch_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        workflow_id: str,
        source_envelope: ContentEnvelope | None = None,
        causal_parent_ids: tuple[str, ...] = (),
        dry_run: bool = False,
    ) -> GatewayResult:
        self._reject_direct_c2_side_effect()
        effective_source = source_envelope or self.current_content(workflow_id)
        effective_parents = causal_parent_ids or self._tail_parents(workflow_id)
        self.security_events.validate_parent_ids(effective_parents)
        proposal = SecurityEvent.create(
            workflow_id,
            SecurityEventType.TOOL_PROPOSAL,
            causal_parent_ids=effective_parents,
            content_ids=(effective_source.content_id,) if effective_source is not None else (),
            attributes={"tool_name": tool_name, "source": "model"},
        )
        self.security_events.append(proposal)
        self.__workflow_tails[workflow_id] = proposal.event_id
        if effective_source is not None:
            self.__workflow_envelopes[workflow_id] = effective_source
        pre = self.guard.inspect_tool_call(
            tool_name,
            arguments,
            source="model",
            destination="tool",
            context={"request_id": workflow_id},
            dry_run=dry_run,
        )

        pre_result = self._result(
            pre,
            workflow_id,
            BoundaryStage.PRE_TOOL,
            "dispatch_tool_call",
            operation={"type": "tool_call", "tool_name": tool_name},
        )
        if pre_result.status is not GatewayStatus.PROCEEDED or dry_run:
            if pre_result.status is not GatewayStatus.PROCEEDED:
                self._record_policy_decision(
                    workflow_id,
                    operation=SecurityEventType.TOOL_PROPOSAL,
                    decision=pre_result.status.value,
                    reason_code=pre_result.guard.reason_codes[0],
                    source_envelope=effective_source,
                )
            return pre_result
        if effective_source is not None and _privileged_tool(tool_name):
            policy_parents = self._tail_parents(workflow_id)
            sequence = self.sequence_policy.evaluate(
                SecurityEventType.TOOL_PROPOSAL,
                envelope=effective_source,
                ancestry=self.security_events.ancestry(policy_parents),
                privileged=True,
            )
            if sequence.decision.value != "ALLOW":
                event = SecurityEvent.create(
                    workflow_id,
                    SecurityEventType.POLICY_DECISION,
                    causal_parent_ids=policy_parents,
                    content_ids=(effective_source.content_id,),
                    attributes={
                        "operation": SecurityEventType.TOOL_PROPOSAL.value,
                        "decision": sequence.decision.value,
                        "reason_code": sequence.reason_code,
                        "tool_name": tool_name,
                    },
                )
                self.security_events.append(event)
                self.__workflow_tails[workflow_id] = event.event_id
                return GatewayResult(
                    workflow_id,
                    GatewayStatus.BLOCKED
                    if sequence.decision.value == "BLOCK"
                    else GatewayStatus.REVIEW_REQUIRED,
                    BoundaryStage.PRE_TOOL,
                    pre_result.guard,
                    {
                        "type": "tool_call",
                        "tool_name": tool_name,
                        "sequence_reason_code": sequence.reason_code,
                    },
                    False,
                    False,
                    pre_result.audit_ids,
                    "Compound-risk policy contained the tool proposal.",
                )
        if tool_name == "workspace_reader":
            path = arguments.get("path")
            root_id = arguments.get("root_id", "workspace")
            if not isinstance(path, str) or not isinstance(root_id, str):
                self._record_policy_decision(
                    workflow_id,
                    operation=SecurityEventType.FILE_READ,
                    decision=GatewayStatus.BLOCKED.value,
                    reason_code="INVALID_TYPED_FILE_REQUEST",
                    source_envelope=effective_source,
                )
                return GatewayResult(
                    workflow_id,
                    GatewayStatus.BLOCKED,
                    BoundaryStage.PRE_TOOL,
                    pre_result.guard,
                    {"type": "file_read", "local_rejection": "INVALID_TYPED_FILE_REQUEST"},
                    False,
                    False,
                    pre_result.audit_ids,
                    "Local file boundary rejected the request.",
                )
            file_result = self.read_file(FileReadRequest(root_id, path, workflow_id))
            file_audits = tuple(
                item
                for item in (file_result.audit_id, file_result.guard_audit_id)
                if item is not None
            )
            status = {
                FileReadDecision.ALLOW: GatewayStatus.PROCEEDED,
                FileReadDecision.REVIEW: GatewayStatus.REVIEW_REQUIRED,
                FileReadDecision.BLOCK: GatewayStatus.BLOCKED,
            }[file_result.decision]
            for audit_id in file_audits:
                self.__events.setdefault(workflow_id, []).append(
                    BoundaryAuditEvent(
                        workflow_id,
                        BoundaryStage.POST_TOOL
                        if file_result.content_was_read
                        else BoundaryStage.PRE_TOOL,
                        audit_id,
                        status,
                        file_result.decision.value,
                        (file_result.reason_code.value,),
                        "typed_file_read",
                    )
                )
            operation = {
                "type": "file_read",
                "root_id": root_id,
                "requested_path": path,
                "resolved_path": file_result.resolved_path,
                "reason_code": file_result.reason_code.value,
                "content_id": file_result.content_id,
                "content_forwarded": status is GatewayStatus.PROCEEDED,
            }
            return GatewayResult(
                workflow_id,
                status,
                BoundaryStage.POST_TOOL if file_result.content_was_read else BoundaryStage.PRE_TOOL,
                pre_result.guard,
                operation,
                file_result.content_was_read,
                False,
                (*pre_result.audit_ids, *file_audits),
                (
                    "File read passed pre-read and post-read security policy."
                    if status is GatewayStatus.PROCEEDED
                    else "Local file boundary contained the request."
                ),
                (
                    file_result.envelope.content
                    if status is GatewayStatus.PROCEEDED and file_result.envelope is not None
                    else None
                ),
            )
        try:
            output = self.__tools._dispatch(self.__capability, tool_name, arguments)
        except ToolRegistryError as exc:
            self._record_policy_decision(
                workflow_id,
                operation=SecurityEventType.TOOL_PROPOSAL,
                decision=GatewayStatus.BLOCKED.value,
                reason_code=type(exc).__name__,
                source_envelope=effective_source,
            )
            return GatewayResult(
                workflow_id,
                GatewayStatus.BLOCKED,
                BoundaryStage.PRE_TOOL,
                pre_result.guard,
                {
                    "type": "tool_call",
                    "tool_name": tool_name,
                    "local_rejection": type(exc).__name__,
                },
                False,
                False,
                pre_result.audit_ids,
                "Local tool rejected the operation.",
            )
        post = self.process_tool_output(output, workflow_id=workflow_id)
        audit_ids = (*pre_result.audit_ids, *post.audit_ids)
        if post.status is not GatewayStatus.PROCEEDED:
            return GatewayResult(
                workflow_id,
                post.status,
                BoundaryStage.POST_TOOL,
                post.guard,
                {"type": "tool_call", "tool_name": tool_name, "output_forwarded": False},
                True,
                False,
                audit_ids,
                post.safe_message,
            )
        return GatewayResult(
            workflow_id,
            GatewayStatus.PROCEEDED,
            BoundaryStage.POST_TOOL,
            post.guard,
            {"type": "tool_call", "tool_name": tool_name, "output_forwarded": True},
            True,
            False,
            audit_ids,
            "Tool call and output passed security inspection.",
            output,
        )

    def dispatch_agent_tool_call(
        self,
        authority: AgentAuthority,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        workflow_id: str,
        source_envelope: ContentEnvelope,
        causal_parent_ids: tuple[str, ...] = (),
        dry_run: bool = False,
    ) -> GatewayResult:
        """Authorize an identified agent before the normal tool boundary runs."""

        self._reject_direct_c2_side_effect()

        self.security_events.validate_parent_ids(causal_parent_ids)
        authenticated = self.agent_directory.authenticate(authority, authority.agent_id)
        capability_allowed = self.agent_directory.has_capability(
            authority.agent_id, f"tool:{tool_name}"
        )
        ancestry_present = bool(causal_parent_ids)
        sequence = self.sequence_policy.evaluate(
            SecurityEventType.TOOL_PROPOSAL,
            envelope=source_envelope,
            ancestry=self.security_events.ancestry(causal_parent_ids),
            privileged=True,
        )
        if (
            not authenticated
            or not capability_allowed
            or not ancestry_present
            or sequence.decision.value != "ALLOW"
        ):
            reason = (
                "AGENT_AUTHENTICATION_FAILED"
                if not authenticated
                else "AGENT_CAPABILITY_NOT_GRANTED"
                if not capability_allowed
                else "AGENT_RUNTIME_ANCESTRY_MISSING"
                if not ancestry_present
                else sequence.reason_code
            )
            guard_result = self.guard.inspect_tool_call(
                tool_name,
                arguments,
                source="model",
                destination="tool",
                context={"request_id": workflow_id},
                dry_run=dry_run,
            )
            inspected = self._result(
                guard_result,
                workflow_id,
                BoundaryStage.PRE_TOOL,
                "agent_tool_authorization",
                operation={"type": "agent_tool_call", "tool_name": tool_name},
            )
            event = SecurityEvent.create(
                workflow_id,
                SecurityEventType.POLICY_DECISION,
                causal_parent_ids=causal_parent_ids,
                content_ids=(source_envelope.content_id,),
                attributes={
                    "operation": SecurityEventType.TOOL_PROPOSAL.value,
                    "agent_id": authority.agent_id,
                    "decision": (
                        "BLOCK"
                        if not authenticated or not capability_allowed or not ancestry_present
                        else sequence.decision.value
                    ),
                    "reason_code": reason,
                },
            )
            self.security_events.append(event)
            status = (
                GatewayStatus.BLOCKED
                if not authenticated
                or not capability_allowed
                or not ancestry_present
                or sequence.decision.value == "BLOCK"
                else GatewayStatus.REVIEW_REQUIRED
            )
            return GatewayResult(
                workflow_id,
                status,
                BoundaryStage.PRE_TOOL,
                inspected.guard,
                {
                    "type": "agent_tool_call",
                    "tool_name": tool_name,
                    "agent_id": authority.agent_id,
                    "reason_code": reason,
                },
                False,
                False,
                inspected.audit_ids,
                "Agent tool authorization contained the proposal.",
            )
        return self.dispatch_tool_call(
            tool_name,
            arguments,
            workflow_id=workflow_id,
            source_envelope=source_envelope,
            causal_parent_ids=causal_parent_ids,
            dry_run=dry_run,
        )

    def write_memory(
        self,
        record: Mapping[str, Any],
        *,
        workflow_id: str,
        source_envelope: ContentEnvelope | None = None,
        causal_parent_ids: tuple[str, ...] = (),
        dry_run: bool = False,
    ) -> GatewayResult:
        self._reject_direct_c2_side_effect()
        source_envelope = source_envelope or self.current_content(workflow_id)
        content = "write memory record\n" + _render_value(record)
        guard_result = self.guard.inspect(
            InspectionRequest(
                content,
                "model",
                "memory",
                {"request_id": workflow_id},
            ),
            dry_run=dry_run,
        )
        result = self._result(
            guard_result,
            workflow_id,
            BoundaryStage.MEMORY,
            "memory_write",
            operation={"type": "memory_write"},
        )
        if result.status is not GatewayStatus.PROCEEDED or dry_run:
            if result.status is not GatewayStatus.PROCEEDED:
                self._record_policy_decision(
                    workflow_id,
                    operation=SecurityEventType.MEMORY_WRITE,
                    decision=result.status.value,
                    reason_code=result.guard.reason_codes[0],
                    source_envelope=source_envelope,
                )
            return result
        if source_envelope is not None:
            derived = ContentEnvelope.derive(
                content,
                parents=(source_envelope,),
                source_type=ContentSourceType.MODEL,
                producing_boundary="legacy_memory_adapter",
                transformation="model_memory_proposal",
                producer="model",
            )
            purpose = (
                "instruction"
                if any(key.casefold() in {"instruction", "rule", "control"} for key in record)
                else "data"
            )
            memory_result = self.write_memory_envelope(
                MemoryWriteRequest(
                    f"legacy:{workflow_id}",
                    derived,
                    workflow_id,
                    causal_parent_ids or self._tail_parents(workflow_id),
                    purpose,
                )
            )
            if memory_result.decision.value != "ALLOW":
                return GatewayResult(
                    workflow_id,
                    GatewayStatus.BLOCKED
                    if memory_result.decision.value == "BLOCK"
                    else GatewayStatus.REVIEW_REQUIRED,
                    BoundaryStage.MEMORY,
                    result.guard,
                    {
                        "type": "memory_write",
                        "sequence_reason_code": memory_result.reason_code,
                    },
                    False,
                    False,
                    result.audit_ids,
                    "Provenance-aware memory policy contained the write.",
                )
            return GatewayResult(
                workflow_id,
                GatewayStatus.PROCEEDED,
                BoundaryStage.MEMORY,
                result.guard,
                {"type": "memory_write", "provenance_preserved": True},
                False,
                True,
                result.audit_ids,
                "Memory write passed provenance-aware security inspection.",
                memory_result.record.metadata_dict() if memory_result.record else None,
            )
        stored = self.__tools._write_memory(self.__capability, record)
        return GatewayResult(
            workflow_id,
            result.status,
            result.stage,
            result.guard,
            result.operation,
            False,
            True,
            result.audit_ids,
            "Memory write passed security inspection.",
            stored,
        )

    def send_external(
        self,
        transfer: Mapping[str, Any],
        *,
        workflow_id: str,
        dry_run: bool = False,
        source_envelope: ContentEnvelope | None = None,
        causal_parent_ids: tuple[str, ...] = (),
        _effect_authorized: bool = True,
    ) -> GatewayResult:
        self._reject_direct_c2_side_effect()
        effective_parents = causal_parent_ids or self._tail_parents(workflow_id)
        self.security_events.validate_parent_ids(effective_parents)
        if source_envelope is None:
            source_envelope = self.current_content(workflow_id)
        content = "send " + _render_value(transfer) + "\nto external destination"
        guard_result = self.guard.inspect(
            InspectionRequest(
                content,
                "model",
                "external",
                {"request_id": workflow_id},
            ),
            dry_run=dry_run,
        )
        result = self._result(
            guard_result,
            workflow_id,
            BoundaryStage.EXTERNAL,
            "external_transfer",
            operation={"type": "external_transfer", "simulated": True},
        )
        if result.status is not GatewayStatus.PROCEEDED or dry_run:
            if result.status is not GatewayStatus.PROCEEDED:
                self._record_policy_decision(
                    workflow_id,
                    operation=SecurityEventType.EXTERNAL_SEND,
                    decision=result.status.value,
                    reason_code=result.guard.reason_codes[0],
                    source_envelope=source_envelope,
                )
            return result
        sequence = self.sequence_policy.evaluate(
            SecurityEventType.EXTERNAL_SEND,
            envelope=source_envelope,
            ancestry=self.security_events.ancestry(effective_parents),
            privileged=True,
        )
        if sequence.decision.value != "ALLOW":
            event = SecurityEvent.create(
                workflow_id,
                SecurityEventType.POLICY_DECISION,
                causal_parent_ids=effective_parents,
                content_ids=(source_envelope.content_id,) if source_envelope else (),
                attributes={
                    "decision": sequence.decision.value,
                    "reason_code": sequence.reason_code,
                    "operation": SecurityEventType.EXTERNAL_SEND.value,
                },
            )
            self.security_events.append(event)
            self.__workflow_tails[workflow_id] = event.event_id
            return GatewayResult(
                workflow_id,
                GatewayStatus.BLOCKED
                if sequence.decision.value == "BLOCK"
                else GatewayStatus.REVIEW_REQUIRED,
                BoundaryStage.EXTERNAL,
                result.guard,
                {
                    "type": "external_transfer",
                    "simulated": True,
                    "sequence_reason_code": sequence.reason_code,
                    "causal_parent_ids": list(effective_parents),
                },
                False,
                False,
                result.audit_ids,
                "Compound-risk policy contained the external transfer.",
            )
        if not _effect_authorized:
            return result
        receipt = self.__tools._send_external_simulated(self.__capability, transfer)
        event = SecurityEvent.create(
            workflow_id,
            SecurityEventType.EXTERNAL_SEND,
            causal_parent_ids=effective_parents,
            content_ids=(source_envelope.content_id,) if source_envelope else (),
            attributes={"decision": "ALLOW", "simulated": "true"},
        )
        self.security_events.append(event)
        self.__workflow_tails[workflow_id] = event.event_id
        return GatewayResult(
            workflow_id,
            result.status,
            result.stage,
            result.guard,
            result.operation,
            False,
            True,
            result.audit_ids,
            "Simulated external transfer passed security inspection.",
            receipt,
        )

    def reconstruct_audit_chain(self, workflow_id: str) -> tuple[BoundaryAuditEvent, ...]:
        return tuple(self.__events.get(workflow_id, ()))

    def _tail_parents(self, workflow_id: str) -> tuple[str, ...]:
        if isinstance(self.security_events, PersistentCausalEventStore):
            workflow = self.security_events.workflow_head(workflow_id)
            tail = workflow[0] if workflow is not None else None
        else:
            tail = self.__workflow_tails.get(workflow_id)
        return (tail,) if tail is not None else ()

    def _claim_runtime_output(
        self,
        output: RuntimeDerivedOutput | None,
        workflow_id: str,
        expected_action_type: str,
        action_payload: Mapping[str, Any] | None,
        *,
        privileged: bool,
    ) -> str | None:
        reason = self._validate_runtime_output_for_execution(
            output, workflow_id, expected_action_type, None
        )
        if reason is not None:
            return reason
        assert output is not None
        if isinstance(self.security_events, PersistentCausalEventStore):
            self.security_events.enforce_audit_bound(privileged=privileged)
        if action_payload is None:
            return None
        persistent_reason = self.security_events.consume_once(
            "model_output",
            output.event_id,
            output.event_id,
            runtime_action_fingerprint(action_payload),
        )
        if persistent_reason is not None:
            return persistent_reason
        self.__consumed_model_outputs.add(output.event_id)
        self._prune_consumed_events()
        return None

    def _validate_runtime_output_for_execution(
        self,
        output: RuntimeDerivedOutput | None,
        workflow_id: str,
        expected_action_type: str,
        action_payload: Mapping[str, Any] | None,
    ) -> str | None:
        """Validate current model-output authority without consuming it."""

        if output is None:
            return "RUNTIME_CONTEXT_MISSING"
        if output.action_type != expected_action_type:
            return "RUNTIME_ACTION_TYPE_MISMATCH"
        if output.context.correlation_id != workflow_id:
            return "RUNTIME_CORRELATION_MISMATCH"
        event = self.security_events.get(output.event_id)
        turn_event = self.security_events.get(output.context.turn_event_id)
        if event is None or turn_event is None:
            return "RUNTIME_EVENT_NOT_FOUND"
        turn_number = turn_event.attributes.get("turn")
        recorded_inputs = self._recorded_event_content(turn_event)
        recorded_output = (
            self.security_events.load_envelope(output.envelope.content_id)
            if isinstance(self.security_events, PersistentCausalEventStore)
            else self.__content_envelopes.get(output.envelope.content_id)
        )
        expected_context = (
            RuntimeSecurityContext._from_host(
                correlation_id=workflow_id,
                turn_id=f"{workflow_id}:turn:{turn_number}",
                turn_event_id=turn_event.event_id,
                input_envelopes=recorded_inputs,
                causal_parent_ids=turn_event.causal_parent_ids,
            )
            if turn_number is not None
            else None
        )
        if (
            turn_event.event_type is not SecurityEventType.MODEL_TURN
            or expected_context != output.context
            or event.event_type is not SecurityEventType.MODEL_OUTPUT
            or event.correlation_id != workflow_id
            or event.causal_parent_ids != (turn_event.event_id,)
            or event.content_ids != (output.envelope.content_id,)
            or recorded_output != output.envelope
            or event.attributes.get("action_type") != expected_action_type
            or event.attributes.get("turn_id") != output.context.turn_id
            or (
                isinstance(self.security_events, PersistentCausalEventStore)
                and turn_event.attributes.get("boot_epoch") != self.security_events.boot_epoch
            )
        ):
            return "RUNTIME_OUTPUT_CONTEXT_MISMATCH"
        if output.event_id in self.__consumed_model_outputs:
            return "RUNTIME_OUTPUT_REPLAYED"
        current_tail = self._tail_parents(workflow_id)
        if current_tail != (output.event_id,):
            return "RUNTIME_OUTPUT_NOT_CURRENT"
        if action_payload is not None and not _runtime_action_payload_matches(
            output, action_payload
        ):
            return "RUNTIME_ACTION_PAYLOAD_MISMATCH"
        return None

    def _admit_workflow(self, workflow_id: str) -> None:
        if workflow_id in self.__workflow_tails:
            return
        while len(self.__workflow_tails) >= self.MAX_ACTIVE_WORKFLOWS:
            expired = next(iter(self.__workflow_tails))
            self.__workflow_tails.pop(expired, None)
            self.__workflow_envelopes.pop(expired, None)
            self.__workflow_turns.pop(expired, None)

    def _prune_consumed_events(self) -> None:
        if (
            len(self.__consumed_model_turns)
            + len(self.__consumed_model_outputs)
            + len(self.__consumed_agent_messages)
            <= self.security_events.max_events * 2
        ):
            return
        self.__consumed_model_turns = {
            event_id
            for event_id in self.__consumed_model_turns
            if self.security_events.get(event_id) is not None
        }
        self.__consumed_model_outputs = {
            event_id
            for event_id in self.__consumed_model_outputs
            if self.security_events.get(event_id) is not None
        }
        self.__consumed_agent_messages = {
            event_id
            for event_id in self.__consumed_agent_messages
            if self.security_events.get(event_id) is not None
        }

    def _runtime_context_failure(
        self,
        workflow_id: str,
        stage: BoundaryStage,
        operation: SecurityEventType,
        reason_code: str,
    ) -> GatewayResult:
        guard_result = self.guard.inspect(
            InspectionRequest(
                "runtime security context validation",
                "internal",
                "internal",
                {"request_id": workflow_id},
            )
        )
        inspected = self._result(
            guard_result,
            workflow_id,
            stage,
            "runtime_context_validation",
            operation={"type": operation.value, "runtime_reason_code": reason_code},
        )
        self._record_policy_decision(
            workflow_id,
            operation=operation,
            decision=GatewayStatus.BLOCKED.value,
            reason_code=reason_code,
            source_envelope=self.current_content(workflow_id),
        )
        return GatewayResult(
            workflow_id,
            GatewayStatus.BLOCKED,
            stage,
            inspected.guard,
            {"type": operation.value, "runtime_reason_code": reason_code},
            False,
            False,
            inspected.audit_ids,
            "Invalid or missing runtime security context blocked the model action.",
        )

    def _remember_content(
        self,
        workflow_id: str,
        envelope: ContentEnvelope,
        event_type: SecurityEventType,
    ) -> None:
        envelope = self._register_envelope(envelope)
        event = SecurityEvent.create(
            workflow_id,
            event_type,
            causal_parent_ids=self._tail_parents(workflow_id),
            content_ids=(envelope.content_id,),
            attributes={
                "content_trust": envelope.trust.value,
                "ever_untrusted": str(envelope.ever_untrusted).lower(),
                "producing_boundary": envelope.producing_boundary,
            },
        )
        self.security_events.append(event)
        self.__workflow_tails[workflow_id] = event.event_id
        self.__workflow_envelopes[workflow_id] = envelope

    def _register_envelope(self, envelope: ContentEnvelope) -> ContentEnvelope:
        """Keep a bounded authoritative snapshot for runtime equality checks."""

        envelope = self.security_events.register_envelope(envelope)

        existing = self.__content_envelopes.get(envelope.content_id)
        if existing is not None and existing != envelope:
            raise ValueError("content ID is already bound to different metadata")
        self.__content_envelopes[envelope.content_id] = envelope
        while len(self.__content_envelopes) > self.security_events.max_events:
            self.__content_envelopes.pop(next(iter(self.__content_envelopes)))
        return envelope

    def _current_turn(self, workflow_id: str) -> int:
        if not isinstance(self.security_events, PersistentCausalEventStore):
            return self.__workflow_turns.get(workflow_id, 0)
        parents = self._tail_parents(workflow_id)
        values = [
            int(event.attributes["turn"])
            for event in self.security_events.ancestry(parents)
            if event.event_type is SecurityEventType.MODEL_TURN
            and event.attributes.get("turn", "").isdigit()
        ]
        return max(values, default=0)

    def _recorded_event_content(self, event: SecurityEvent | None) -> tuple[ContentEnvelope, ...]:
        if event is None:
            return ()
        if isinstance(self.security_events, PersistentCausalEventStore):
            envelopes = tuple(
                self.security_events.load_envelope(content_id) for content_id in event.content_ids
            )
            for envelope in envelopes:
                self.__content_envelopes[envelope.content_id] = envelope
            return envelopes
        if not all(item in self.__content_envelopes for item in event.content_ids):
            return ()
        return tuple(self.__content_envelopes[item] for item in event.content_ids)

    def _record_policy_decision(
        self,
        workflow_id: str,
        *,
        operation: SecurityEventType,
        decision: str,
        reason_code: str,
        source_envelope: ContentEnvelope | None,
    ) -> SecurityEvent:
        event = SecurityEvent.create(
            workflow_id,
            SecurityEventType.POLICY_DECISION,
            causal_parent_ids=self._tail_parents(workflow_id),
            content_ids=(source_envelope.content_id,) if source_envelope is not None else (),
            attributes={
                "operation": operation.value,
                "decision": decision,
                "reason_code": reason_code,
            },
        )
        self.security_events.append(event)
        self.__workflow_tails[workflow_id] = event.event_id
        return event

    def _inspect_boundary(
        self,
        content: str,
        *,
        source: str,
        destination: str,
        stage: BoundaryStage,
        operation_type: str,
        workflow_id: str,
        dry_run: bool,
    ) -> GatewayResult:
        inspection = inspect_content(content)
        guard_result = self.guard.inspect(
            InspectionRequest(
                content,
                source,
                destination,
                {
                    "request_id": workflow_id,
                    "metadata": {
                        "suspicious_encoded": str(
                            inspection.suspicious and source == "user"
                        ).lower(),
                    },
                },
            ),
            dry_run=dry_run,
        )
        return self._result(
            guard_result,
            workflow_id,
            stage,
            operation_type,
            value=content,
        )

    def _result(
        self,
        guard_result: InspectionResult,
        workflow_id: str,
        stage: BoundaryStage,
        operation_type: str,
        *,
        operation: Mapping[str, Any] | None = None,
        value: Any = None,
    ) -> GatewayResult:
        decision = cast(GuardDecision, guard_result.decision)
        status = {
            GuardDecision.ALLOW: GatewayStatus.PROCEEDED,
            GuardDecision.REVIEW: GatewayStatus.REVIEW_REQUIRED,
            GuardDecision.BLOCK: GatewayStatus.BLOCKED,
        }[decision]
        summary = GuardSummary.from_result(guard_result)
        safe_message = {
            GatewayStatus.PROCEEDED: "Operation passed security inspection.",
            GatewayStatus.REVIEW_REQUIRED: "Operation requires security review.",
            GatewayStatus.BLOCKED: "Operation blocked by security policy.",
        }[status]
        result = GatewayResult(
            workflow_id,
            status,
            stage,
            summary,
            operation or {"type": operation_type},
            False,
            False,
            (summary.audit_id,),
            safe_message,
            value if status is GatewayStatus.PROCEEDED else None,
        )
        self.__events.setdefault(workflow_id, []).append(
            BoundaryAuditEvent(
                workflow_id,
                stage,
                summary.audit_id,
                status,
                summary.decision,
                summary.reason_codes,
                operation_type,
            )
        )
        return result


def _render_value(value: Any, *, depth: int = 0) -> str:
    if depth > 12:
        raise ValueError("gateway value exceeds maximum nesting depth")
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    if isinstance(value, Mapping):
        if len(value) > 1_000:
            raise ValueError("gateway mapping is too large")
        parts = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError("gateway mapping keys must be strings")
            parts.append(f"{key}={_render_value(value[key], depth=depth + 1)}")
        return "\n".join(parts)
    if isinstance(value, (list, tuple)):
        if len(value) > 1_000:
            raise ValueError("gateway sequence is too large")
        return "\n".join(_render_value(item, depth=depth + 1) for item in value)
    raise TypeError("gateway values must be bounded JSON-like data")


def _runtime_action_payload_matches(
    output: RuntimeDerivedOutput, expected: Mapping[str, Any]
) -> bool:
    try:
        payload = json.loads(
            output.envelope.content,
            object_pairs_hook=_runtime_json_object,
        )
        return isinstance(payload, dict) and runtime_action_fingerprint(
            payload
        ) == runtime_action_fingerprint(dict(expected))
    except (json.JSONDecodeError, RecursionError, ValueError, TypeError):
        return False


def _runtime_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate runtime action key")
        value[key] = item
    return value


def _privileged_tool(tool_name: str) -> bool:
    lowered = tool_name.casefold()
    if lowered == "calculator":
        return False
    return any(
        token in lowered
        for token in (
            "read",
            "retriev",
            "file",
            "upload",
            "send",
            "post",
            "shell",
            "exec",
            "credential",
            "secret",
            "memory",
            "external",
        )
    ) or lowered not in {"calculator"}
