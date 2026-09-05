"""Persistent Gateway execution preparation and local pre-dispatch integration.

The integration is intentionally local-only.  It joins the authenticated Gateway
policy path to the v0.3c1 persistent execution state machine, but the only runner
accepted in v0.3c2 is the deterministic :class:`FakeDestination`.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from ..guard import GuardDecision, InspectionRequest
from ..guard.detectors import DETECTOR_HASH
from ..persistent_state import (
    ExecutionAuthority,
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionDecisionHandle,
    ExecutionState,
    IdempotencyClass,
)
from ..persistent_state.canonical import canonical_text
from ..persistent_state.execution import _HOST_EXECUTION_AUTHORITY_CAPABILITY, normalize_action
from ..persistent_state.fake_destination import (
    FakeCallerTermination,
    FakeDestination,
    FakeDestinationFailure,
    FakeDestinationMode,
    FakeDestinationStatusAdapter,
    FakeDestinationTimeout,
)
from .agent_boundary import AgentAuthority, AgentDirectory
from .envelope import ContentEnvelope
from .models import GuardSummary
from .persistent_runtime import PersistentCausalEventStore, PersistentRuntimeError
from .runtime_context import RuntimeDerivedOutput
from .sequence import (
    SEQUENCE_POLICY_VERSION,
    SecurityEvent,
    SecurityEventType,
    SequenceDecision,
    SequencePolicy,
)

_HOST_CONTROL_ISSUER: Final = object()
_POLICY_AUTHORIZATION_ISSUER: Final = object()
_WORKER_ISSUER: Final = object()
_DESTINATION_REGISTRY_ID: Final = "gateway-local-v0.3c2"


class GatewayExecutionError(ExecutionAuthorityError):
    """Typed fail-closed error from the integrated execution path."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message, code=code)


class ExecutionPolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class DestinationClassification(StrEnum):
    DEVELOPMENT_TEST_ONLY = "DEVELOPMENT_TEST_ONLY"
    LOCAL_DETERMINISTIC = "LOCAL_DETERMINISTIC"


@dataclass(frozen=True, slots=True)
class DestinationRegistration:
    destination_id: str
    action_types: tuple[str, ...]
    runner_identity: str
    configuration_digest: str
    idempotency_class: IdempotencyClass
    required_capability: str
    enabled: bool
    classification: DestinationClassification
    revision: int
    runner: FakeDestination


@dataclass(frozen=True, slots=True)
class GatewayRecoveryPolicy:
    """Host-owned c3c policy; recovery is disabled unless explicitly configured."""

    enabled: bool = False
    automatic_query: bool = False
    allow_caller_supplied_key: bool = False
    allow_queryable_operation: bool = False
    revision: int = 1

    def __post_init__(self) -> None:
        if any(
            type(value) is not bool
            for value in (
                self.enabled,
                self.automatic_query,
                self.allow_caller_supplied_key,
                self.allow_queryable_operation,
            )
        ):
            raise TypeError("recovery policy flags must be booleans")
        if type(self.revision) is not int:
            raise TypeError("recovery policy revision must be an integer")
        if not 1 <= self.revision <= 2_147_483_647:
            raise ValueError("recovery policy revision is out of bounds")
        if not self.enabled and any(
            (
                self.automatic_query,
                self.allow_caller_supplied_key,
                self.allow_queryable_operation,
            )
        ):
            raise ValueError("disabled recovery policy cannot grant recovery behavior")
        if self.automatic_query and not self.allow_queryable_operation:
            raise ValueError("automatic query requires queryable recovery policy")


@dataclass(frozen=True, slots=True)
class GatewayExecutionPreparation:
    decision_id: str
    source_output_event_id: str
    decision: ExecutionPolicyDecision
    reason_code: str
    intent_id: str | None
    action_fingerprint: str | None
    destination_id: str
    security_configuration_digest: str


@dataclass(frozen=True, slots=True)
class GatewayExecutionOutcome:
    intent_id: str
    state: ExecutionState
    reason_code: str
    result: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.result is not None:
            object.__setattr__(self, "result", MappingProxyType(dict(self.result)))


class GatewayExecutionHostControl:
    """Opaque host authority for destination/configuration administration."""

    __slots__ = ("_boot_event_id", "_capability", "_pid", "_thread_id")

    _boot_event_id: str
    _capability: object
    _pid: int
    _thread_id: int

    def __init__(self, issuer: object, capability: object, boot_event_id: str) -> None:
        if issuer is not _HOST_CONTROL_ISSUER:
            raise TypeError("Gateway execution host controls cannot be caller-constructed")
        object.__setattr__(self, "_capability", capability)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_thread_id", threading.get_ident())
        object.__setattr__(self, "_boot_event_id", boot_event_id)

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Gateway execution host controls are immutable")
        object.__setattr__(self, name, value)

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("Gateway execution host controls are not serializable")

    def __copy__(self) -> object:
        raise TypeError("Gateway execution host controls are not copyable")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("Gateway execution host controls are not copyable")


class GatewayWorker:
    """Opaque process/thread-local wrapper around a persistent worker capability."""

    __slots__ = ("agent_id", "scope", "_handle", "_capability", "_pid", "_thread_id")

    def __init__(
        self,
        issuer: object,
        *,
        agent_id: str,
        scope: str,
        handle: Any,
        capability: object,
    ) -> None:
        if issuer is not _WORKER_ISSUER:
            raise TypeError("Gateway workers cannot be caller-constructed")
        self.agent_id = agent_id
        self.scope = scope
        self._handle = handle
        self._capability = capability
        self._pid = os.getpid()
        self._thread_id = threading.get_ident()

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("Gateway workers are not serializable")


class _PolicyAuthorization:
    """Single-use, host-created preparation snapshot."""

    __slots__ = (
        "authorization_id",
        "source_output_event_id",
        "source_turn_event_id",
        "proposal_event_id",
        "workflow_id",
        "workflow_head_event_id",
        "workflow_revision",
        "action",
        "action_fingerprint",
        "action_type",
        "ancestry_event_ids",
        "content_digests",
        "decision",
        "guard_decision_id",
        "sequence_decision_id",
        "security_configuration_digest",
        "destination",
        "agent_id",
        "_capability",
    )

    authorization_id: str
    source_output_event_id: str
    source_turn_event_id: str
    proposal_event_id: str
    workflow_id: str
    workflow_head_event_id: str
    workflow_revision: int
    action: Mapping[str, Any]
    action_fingerprint: str
    action_type: str
    ancestry_event_ids: tuple[str, ...]
    content_digests: tuple[str, ...]
    decision: ExecutionPolicyDecision
    guard_decision_id: str
    sequence_decision_id: str
    security_configuration_digest: str
    destination: DestinationRegistration
    agent_id: str
    _capability: object

    def __init__(self, issuer: object, capability: object, **values: Any) -> None:
        if issuer is not _POLICY_AUTHORIZATION_ISSUER:
            raise TypeError("policy authorizations cannot be caller-constructed")
        self.authorization_id = "gateway-policy-auth-" + uuid.uuid4().hex
        for name, value in values.items():
            object.__setattr__(self, name, value)
        self._capability = capability

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("policy authorizations are not serializable")

    def __copy__(self) -> object:
        raise TypeError("policy authorizations are not copyable")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("policy authorizations are not copyable")


class GatewayExecutionRuntime:
    """Host-owned v0.3c2 bridge from Gateway decisions to local dispatch."""

    def __init__(
        self,
        gateway: Any,
        store: PersistentCausalEventStore,
        agent_directory: AgentDirectory,
        sequence_policy: SequencePolicy,
        recovery_policy: GatewayRecoveryPolicy | None = None,
    ) -> None:
        self._gateway = gateway
        self.store = store
        self.agent_directory = agent_directory
        self.sequence_policy = sequence_policy
        self.authority = ExecutionAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, store.state
        )
        self._lock = threading.RLock()
        self._host_capability = object()
        self._policy_capability = object()
        self._worker_capabilities: dict[int, object] = {}
        self._destinations: dict[str, DestinationRegistration] = {}
        self._destination_revision = 0
        self._policy_revision = 1
        if recovery_policy is not None and type(recovery_policy) is not GatewayRecoveryPolicy:
            raise TypeError("recovery_policy must be an exact GatewayRecoveryPolicy")
        self._recovery_policy = self._copy_recovery_policy(
            recovery_policy or GatewayRecoveryPolicy()
        )
        self._used_authorizations: set[str] = set()
        self._host_control = GatewayExecutionHostControl(
            _HOST_CONTROL_ISSUER, self._host_capability, self.store.boot_epoch
        )
        self._worker_attach_token = secrets.token_urlsafe(32)
        shared = self.authority.get_security_configuration()
        self._shared_epoch = 0 if shared is None else shared.epoch
        self._shared_configuration_digest = None if shared is None else shared.configuration_digest
        if self.store.config.worker_attach:
            assert self.store.config.worker_attach_token is not None
            supplied = self._worker_bootstrap_digest(
                self.store.config.worker_attach_token, self.store.boot_epoch
            )
            if (
                shared is None
                or shared.mode != "C2_REQUIRED"
                or not secrets.compare_digest(supplied, shared.worker_attach_digest)
            ):
                raise GatewayExecutionError(
                    "WORKER_ATTACH_AUTHORITY_INVALID",
                    "worker attach requires the current host bootstrap authority",
                )
            self._worker_attach_token = self.store.config.worker_attach_token
        elif shared is not None:
            shared = self.authority.update_security_configuration(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                expected_epoch=shared.epoch,
                configuration_digest=shared.configuration_digest,
                worker_attach_digest=self._worker_bootstrap_digest(
                    self._worker_attach_token, self.store.boot_epoch
                ),
                expected_boot_event_id=self.store.boot_epoch,
            )
            self._shared_epoch = shared.epoch
            self._shared_configuration_digest = shared.configuration_digest

    def host_control(self) -> GatewayExecutionHostControl:
        """DANGEROUS_INTERNAL: return host configuration authority."""

        return self._host_control

    @property
    def active(self) -> bool:
        """Whether this persistent deployment has enabled the c2 execution path."""

        shared = self.authority.get_security_configuration()
        return bool(self._destinations) or (shared is not None and shared.mode == "C2_REQUIRED")

    def worker_attach_token(self, control: GatewayExecutionHostControl) -> str:
        """CAPABILITY_PROTECTED: export the current boot's out-of-band worker bootstrap."""

        self._require_host(control)
        if self.store.config.worker_attach or not self.active:
            raise GatewayExecutionError(
                "WORKER_ATTACH_AUTHORITY_INVALID", "only an active host may issue worker bootstrap"
            )
        return self._worker_attach_token

    def register_fake_destination(
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
    ) -> DestinationRegistration:
        """CAPABILITY_PROTECTED: register a deterministic local-only runner."""

        self._require_host(control)
        if type(runner) is not FakeDestination:
            raise TypeError("v0.3c2 accepts only the deterministic fake destination")
        if (
            not destination_id
            or len(destination_id) > 200
            or not runner_identity
            or len(runner_identity) > 200
            or not required_capability
            or len(required_capability) > 200
            or not action_types
            or any(not value or len(value) > 200 for value in action_types)
        ):
            raise ValueError("destination registration fields must be bounded")
        if not isinstance(idempotency_class, IdempotencyClass):
            raise TypeError("idempotency class must be host-selected")
        configuration_digest = self._digest(
            {
                "classification": classification.value,
                "configuration": dict(configuration),
                "idempotency_class": idempotency_class.value,
                "runner_identity": runner_identity,
            }
        )
        with self._lock:
            self._destination_revision += 1
            registration = DestinationRegistration(
                destination_id,
                tuple(sorted(set(action_types))),
                runner_identity,
                configuration_digest,
                idempotency_class,
                required_capability,
                True,
                classification,
                self._destination_revision,
                FakeDestination(runner.path.resolve(), failure_injector=runner.failure_injector),
            )
            self._destinations[destination_id] = registration
            if not self.store.config.worker_attach:
                self._commit_security_configuration()
            return registration

    def disable_destination(
        self, control: GatewayExecutionHostControl, destination_id: str
    ) -> DestinationRegistration:
        """CAPABILITY_PROTECTED: fail closed for new and prepared actions."""

        self._require_host(control)
        self._require_configuration_admin()
        with self._lock:
            current = self._destination(destination_id)
            self._destination_revision += 1
            disabled = DestinationRegistration(
                current.destination_id,
                current.action_types,
                current.runner_identity,
                current.configuration_digest,
                current.idempotency_class,
                current.required_capability,
                False,
                current.classification,
                self._destination_revision,
                current.runner,
            )
            self._destinations[destination_id] = disabled
            self._commit_security_configuration()
            return disabled

    def replace_agent_capabilities(
        self,
        control: GatewayExecutionHostControl,
        agent_id: str,
        capabilities: tuple[str, ...],
    ) -> int:
        """CAPABILITY_PROTECTED: update current agent execution authority."""

        self._require_host(control)
        self._require_configuration_admin()
        with self._lock:
            revision = self.agent_directory.replace_capabilities(
                agent_id, capabilities=capabilities
            )
            self._commit_security_configuration()
            return revision

    def advance_policy_revision(self, control: GatewayExecutionHostControl) -> int:
        """CAPABILITY_PROTECTED: invalidate snapshots after a security-policy change."""

        self._require_host(control)
        self._require_configuration_admin()
        with self._lock:
            self._policy_revision += 1
            self._commit_security_configuration()
            return self._policy_revision

    @property
    def recovery_policy(self) -> GatewayRecoveryPolicy:
        return self._copy_recovery_policy(self._recovery_policy)

    def replace_recovery_policy(
        self,
        control: GatewayExecutionHostControl,
        policy: GatewayRecoveryPolicy,
    ) -> GatewayRecoveryPolicy:
        """CAPABILITY_PROTECTED: replace the host recovery policy and invalidate snapshots."""

        self._require_host(control)
        self._require_configuration_admin()
        if type(policy) is not GatewayRecoveryPolicy:
            raise TypeError("policy must be an exact host-selected GatewayRecoveryPolicy")
        with self._lock:
            if policy.revision <= self._recovery_policy.revision:
                raise GatewayExecutionError(
                    "RECOVERY_POLICY_REVISION_STALE",
                    "recovery policy revision must advance monotonically",
                )
            self._recovery_policy = self._copy_recovery_policy(policy)
            self._commit_security_configuration()
            return self.recovery_policy

    def prepare(
        self,
        output: RuntimeDerivedOutput,
        action: Mapping[str, Any] | str,
        *,
        destination_id: str,
        agent: AgentAuthority,
    ) -> GatewayExecutionPreparation:
        """SAFE_BY_CONSTRUCTION: make one terminal decision from current Gateway policy."""

        normalized, _rendered, fingerprint = normalize_action(action)
        action_type = str(normalized["action"])
        with self._lock:
            self._require_current_shared_configuration()
            self.store.enforce_audit_bound(privileged=True)
            reason = self._gateway._validate_runtime_output_for_execution(
                output,
                output.context.correlation_id,
                action_type,
                normalized,
            )
            if reason is not None:
                raise GatewayExecutionError(reason, "runtime output is not current authority")
            registration = self._destinations.get(destination_id)
            if registration is None:
                registration = DestinationRegistration(
                    destination_id,
                    (action_type,),
                    "unregistered",
                    "0" * 64,
                    IdempotencyClass.NO_IDEMPOTENCY,
                    "unavailable",
                    False,
                    DestinationClassification.DEVELOPMENT_TEST_ONLY,
                    0,
                    FakeDestination(
                        self.store.state.paths.directory / ".unregistered-destination.sqlite3"
                    ),
                )
                return self._terminal_nonexecutable(
                    output,
                    normalized,
                    registration,
                    agent,
                    ExecutionPolicyDecision.BLOCK,
                    "DESTINATION_NOT_REGISTERED",
                )
            if not registration.enabled:
                return self._terminal_nonexecutable(
                    output,
                    normalized,
                    registration,
                    agent,
                    ExecutionPolicyDecision.BLOCK,
                    "DESTINATION_DISABLED",
                )
            if action_type not in registration.action_types:
                return self._terminal_nonexecutable(
                    output,
                    normalized,
                    registration,
                    agent,
                    ExecutionPolicyDecision.BLOCK,
                    "DESTINATION_ACTION_UNSUPPORTED",
                )
            authenticated = self.agent_directory.authenticate(agent, agent.agent_id)
            capable = self.agent_directory.has_capability(
                agent.agent_id, registration.required_capability
            )
            policy_decision, guard_id, sequence_id, reason_code = self._evaluate_policy(
                output.envelope, normalized, output.context.correlation_id
            )
            if not authenticated or not capable:
                policy_decision = ExecutionPolicyDecision.BLOCK
                reason_code = (
                    "AGENT_AUTHENTICATION_FAILED" if not authenticated else "CAPABILITY_MISSING"
                )
            proposal = self._append_proposal(
                output,
                normalized,
                fingerprint,
                registration,
                agent.agent_id,
                policy_decision,
                reason_code,
            )
            persistent_output = self.store.persistent_event_id(output.event_id)
            persistent_turn = self.store.persistent_event_id(output.context.turn_event_id)
            persistent_proposal = self.store.persistent_event_id(proposal.event_id)
            if policy_decision is not ExecutionPolicyDecision.ALLOW:
                handle = self.authority.record_nonexecutable_decision(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                    workflow_id=output.context.correlation_id,
                    source_output_event_id=persistent_output,
                    proposal_event_id=persistent_proposal,
                    decision=policy_decision.value,
                    reason_code=reason_code,
                )
                self.store.project_audit()
                return self._preparation(handle, reason_code, destination_id, None, "")
            workflow = self.store.state.get_workflow(output.context.correlation_id)
            digest = self._security_configuration_digest(agent.agent_id, registration)
            authorization = _PolicyAuthorization(
                _POLICY_AUTHORIZATION_ISSUER,
                self._policy_capability,
                source_output_event_id=persistent_output,
                source_turn_event_id=persistent_turn,
                proposal_event_id=persistent_proposal,
                workflow_id=output.context.correlation_id,
                workflow_head_event_id=workflow.head_event_id,
                workflow_revision=workflow.revision,
                action=normalized,
                action_fingerprint=fingerprint,
                action_type=action_type,
                ancestry_event_ids=tuple(
                    self.store.persistent_event_id(item.event_id)
                    for item in self.store.ancestry((proposal.event_id,))
                ),
                content_digests=tuple(
                    sorted(
                        {
                            output.envelope.original_sha256,
                            *output.envelope.ancestor_sha256,
                        }
                    )
                ),
                decision=policy_decision,
                guard_decision_id=guard_id,
                sequence_decision_id=sequence_id,
                security_configuration_digest=digest,
                destination=registration,
                agent_id=agent.agent_id,
            )
            return self._consume_policy_authorization(authorization)

    def register_worker(
        self,
        agent: AgentAuthority,
        *,
        scope: str,
    ) -> GatewayWorker:
        """CAPABILITY_PROTECTED: register an authenticated current local worker."""

        if not scope or len(scope) > 200:
            raise ValueError("worker scope must be bounded")
        if not self.agent_directory.authenticate(agent, agent.agent_id):
            raise GatewayExecutionError("AGENT_AUTHENTICATION_FAILED", "worker agent is invalid")
        capability = object()
        handle = self.authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            boot_event_id=self.store.boot_epoch,
            metadata={"agent_id": agent.agent_id, "scope": scope, "runtime": "gateway-v0.3c2"},
        )
        worker = GatewayWorker(
            _WORKER_ISSUER,
            agent_id=agent.agent_id,
            scope=scope,
            handle=handle,
            capability=capability,
        )
        self._worker_capabilities[id(worker)] = capability
        self.store.project_audit()
        return worker

    def execute(
        self,
        worker: GatewayWorker,
        agent: AgentAuthority,
        intent_id: str,
        *,
        mode: FakeDestinationMode = FakeDestinationMode.SUCCESS,
        lease_seconds: float = 30.0,
    ) -> GatewayExecutionOutcome:
        """CAPABILITY_PROTECTED: claim, revalidate, fence, and invoke the local runner."""

        self._validate_worker(worker, agent)
        claim = self.authority.claim_execution(
            worker._handle, intent_id, lease_seconds=lease_seconds
        )
        with self._lock:
            intent = self.authority.get_intent(intent_id)
            background_action = intent.action_type == "BACKGROUND_AGENT_ACTION"
            if background_action != (worker.scope == "background"):
                return self._cancel(intent_id, "WORKER_SCOPE_MISMATCH")
            try:
                shared = self._require_current_shared_configuration()
            except GatewayExecutionError:
                return self._cancel(intent_id, "AUTHORIZATION_STALE")
            registration = self._destinations.get(intent.destination)
            if registration is None or not registration.enabled:
                return self._cancel(intent_id, "DESTINATION_DISABLED")
            if registration.configuration_digest != intent.destination_config_digest:
                return self._cancel(intent_id, "DESTINATION_CHANGED")
            if not self.agent_directory.authenticate(agent, worker.agent_id):
                return self._cancel(intent_id, "AGENT_AUTHENTICATION_FAILED")
            if not self.agent_directory.has_capability(
                worker.agent_id, registration.required_capability
            ):
                return self._cancel(intent_id, "CAPABILITY_REVOKED")
            output_event = self.store.state.get_event(intent.source_output_event_id)
            if not output_event.content_ids:
                return self._cancel(intent_id, "AUTHENTICATED_SOURCE_MISSING")
            envelope = self.store.load_envelope(output_event.content_ids[0])
            decision, _guard_id, _sequence_id, reason = self._evaluate_policy(
                envelope, intent.normalized_action, intent.workflow_id
            )
            if decision is not ExecutionPolicyDecision.ALLOW:
                return self._cancel(intent_id, "POLICY_REJECTED_" + reason)
            current_digest = self._security_configuration_digest(worker.agent_id, registration)
            if current_digest != intent.policy_config_digest:
                return self._cancel(intent_id, "POLICY_CHANGED")
            self.store.enforce_audit_bound(privileged=True)
            try:
                dispatch = self.authority.begin_dispatch(
                    claim,
                    action=intent.normalized_action,
                    destination_registry=_DESTINATION_REGISTRY_ID,
                    destination=registration.destination_id,
                    destination_config_digest=registration.configuration_digest,
                    authorization_validator=lambda: self._dispatch_snapshot_current(
                        worker.agent_id, registration, intent.policy_config_digest
                    ),
                    security_configuration_epoch=shared.epoch,
                    security_configuration_digest=shared.configuration_digest,
                )
            except ExecutionBindingError:
                return self._cancel(intent_id, "AUTHORIZATION_STALE")
        self.store.project_audit()
        try:
            result = FakeDestination.invoke(
                registration.runner,
                self.authority,
                dispatch,
                intent.normalized_action,
                mode=mode,
            )
        except (FakeDestinationTimeout, FakeCallerTermination) as exc:
            record = self.authority.mark_outcome_unknown(
                dispatch, destination_operation_id=exc.operation_id
            )
            self.store.project_audit()
            return GatewayExecutionOutcome(record.intent_id, record.state, "OUTCOME_UNKNOWN")
        except FakeDestinationFailure:
            if mode is FakeDestinationMode.FAIL_BEFORE_EFFECT:
                structured = {"mode": mode.value, "status": "PROVEN_NO_EFFECT"}
                record = self.authority.fail_no_effect(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                    dispatch,
                    result_digest=self._digest(structured),
                )
                self.store.project_audit()
                return GatewayExecutionOutcome(
                    record.intent_id, record.state, "PROVEN_NO_EFFECT", structured
                )
            record = self.authority.mark_outcome_unknown(dispatch)
            self.store.project_audit()
            return GatewayExecutionOutcome(record.intent_id, record.state, "OUTCOME_UNKNOWN")
        if result.get("status") in {"SUCCEEDED", "DEDUPLICATED"}:
            try:
                self.store.enforce_audit_bound(privileged=True)
            except PersistentRuntimeError:
                record = self.authority.mark_outcome_unknown(
                    dispatch,
                    destination_operation_id=str(result.get("operation_id")),
                )
                self.store.project_audit()
                return GatewayExecutionOutcome(
                    record.intent_id,
                    record.state,
                    "AUDIT_BACKLOG_OUTCOME_UNKNOWN",
                )
            record = self.authority.complete_execution(
                dispatch,
                result_digest=self._digest(result),
                destination_operation_id=str(result.get("operation_id")),
            )
            self.store.project_audit()
            return GatewayExecutionOutcome(record.intent_id, record.state, "COMPLETED", result)
        if result.get("status") == "PAUSED_BEFORE_EFFECT":
            structured = {"mode": mode.value, "status": "PROVEN_NO_EFFECT"}
            record = self.authority.fail_no_effect(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                dispatch,
                result_digest=self._digest(structured),
            )
            self.store.project_audit()
            return GatewayExecutionOutcome(
                record.intent_id, record.state, "PROVEN_NO_EFFECT", structured
            )
        operation_id = result.get("operation_id")
        record = self.authority.mark_outcome_unknown(
            dispatch,
            destination_operation_id=(operation_id if isinstance(operation_id, str) else None),
        )
        self.store.project_audit()
        return GatewayExecutionOutcome(record.intent_id, record.state, "OUTCOME_UNKNOWN", result)

    def _consume_policy_authorization(
        self, authorization: _PolicyAuthorization
    ) -> GatewayExecutionPreparation:
        if (
            not isinstance(authorization, _PolicyAuthorization)
            or authorization._capability is not self._policy_capability
            or authorization.authorization_id in self._used_authorizations
            or authorization.decision is not ExecutionPolicyDecision.ALLOW
        ):
            raise GatewayExecutionError(
                "POLICY_AUTHORIZATION_INVALID", "preparation authorization is invalid"
            )
        current = self.store.state.get_workflow(authorization.workflow_id)
        if (
            current.head_event_id != authorization.workflow_head_event_id
            or current.revision != authorization.workflow_revision
            or self._security_configuration_digest(
                authorization.agent_id, authorization.destination
            )
            != authorization.security_configuration_digest
        ):
            raise GatewayExecutionError(
                "POLICY_AUTHORIZATION_STALE", "preparation authorization snapshot is stale"
            )
        self._used_authorizations.add(authorization.authorization_id)
        handle = self.authority.prepare_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=authorization.workflow_id,
            expected_head_event_id=authorization.workflow_head_event_id,
            expected_revision=authorization.workflow_revision,
            source_turn_event_id=authorization.source_turn_event_id,
            source_output_event_id=authorization.source_output_event_id,
            proposal_event_id=authorization.proposal_event_id,
            action=authorization.action,
            destination_registry=_DESTINATION_REGISTRY_ID,
            destination=authorization.destination.destination_id,
            destination_config_digest=authorization.destination.configuration_digest,
            idempotency_class=authorization.destination.idempotency_class,
            ancestry_event_ids=authorization.ancestry_event_ids,
            content_digests=authorization.content_digests,
            policy_config_digest=authorization.security_configuration_digest,
        )
        self.store.project_audit()
        return self._preparation(
            handle,
            "CURRENT_POLICY_ALLOW",
            authorization.destination.destination_id,
            authorization.action_fingerprint,
            authorization.security_configuration_digest,
        )

    def _terminal_nonexecutable(
        self,
        output: RuntimeDerivedOutput,
        action: Mapping[str, Any],
        registration: DestinationRegistration,
        agent: AgentAuthority,
        decision: ExecutionPolicyDecision,
        reason_code: str,
    ) -> GatewayExecutionPreparation:
        _normalized, _rendered, fingerprint = normalize_action(action)
        proposal = self._append_proposal(
            output,
            action,
            fingerprint,
            registration,
            agent.agent_id,
            decision,
            reason_code,
        )
        handle = self.authority.record_nonexecutable_decision(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=output.context.correlation_id,
            source_output_event_id=self.store.persistent_event_id(output.event_id),
            proposal_event_id=self.store.persistent_event_id(proposal.event_id),
            decision=decision.value,
            reason_code=reason_code,
        )
        self.store.project_audit()
        return self._preparation(handle, reason_code, registration.destination_id, None, "")

    def _append_proposal(
        self,
        output: RuntimeDerivedOutput,
        action: Mapping[str, Any],
        fingerprint: str,
        registration: DestinationRegistration,
        agent_id: str,
        decision: ExecutionPolicyDecision,
        reason_code: str,
    ) -> SecurityEvent:
        proposal = SecurityEvent.create(
            output.context.correlation_id,
            self._event_type(str(action["action"])),
            causal_parent_ids=(output.event_id,),
            content_ids=(output.envelope.content_id,),
            attributes={
                "action_fingerprint": fingerprint,
                "action_type": str(action["action"]),
                "agent_id": agent_id,
                "decision": decision.value,
                "destination": registration.destination_id,
                "destination_config_digest": registration.configuration_digest,
                "reason_code": reason_code,
                "runtime": "gateway-v0.3c2",
            },
        )
        self.store.append(proposal)
        return proposal

    def _evaluate_policy(
        self,
        envelope: ContentEnvelope,
        action: Mapping[str, Any],
        workflow_id: str,
    ) -> tuple[ExecutionPolicyDecision, str, str, str]:
        action_type = str(action["action"])
        if action_type in {"TOOL_CALL", "WORKSPACE_READ"}:
            tool = action.get("tool")
            arguments = action.get("arguments")
            if not isinstance(tool, str) or not isinstance(arguments, Mapping):
                return (
                    ExecutionPolicyDecision.BLOCK,
                    "guard:invalid-action",
                    "sequence:not-run",
                    "INVALID_TYPED_ACTION",
                )
            inspected = self._gateway.guard.inspect_tool_call(
                tool,
                arguments,
                source="model",
                destination="tool",
                context={"request_id": workflow_id},
            )
        else:
            destination = "memory" if action_type == "MEMORY_WRITE" else "external"
            inspected = self._gateway.guard.inspect(
                InspectionRequest(
                    canonical_text(action),
                    "model",
                    destination,
                    {"request_id": workflow_id},
                )
            )
        guard_decision = GuardDecision(inspected.decision)
        event_type = self._event_type(action_type)
        ancestry = self.store.ancestry(self._gateway._tail_parents(workflow_id))
        sequence = self.sequence_policy.evaluate(
            event_type,
            envelope=envelope,
            ancestry=ancestry,
            privileged=True,
            persistent_instruction=action_type == "MEMORY_WRITE",
        )
        decision = self._combined_decision(guard_decision, sequence.decision)
        reason_codes = GuardSummary.from_result(inspected).reason_codes
        reason = (
            reason_codes[0] if guard_decision is not GuardDecision.ALLOW else sequence.reason_code
        )
        return (
            decision,
            "guard:" + inspected.audit_id,
            "sequence:" + sequence.reason_code,
            self._reason_code(reason),
        )

    def _security_configuration_digest(
        self, agent_id: str, registration: DestinationRegistration
    ) -> str:
        shared = self.authority.get_security_configuration()
        epoch = self._shared_epoch if shared is None else shared.epoch
        return self._digest(
            {
                "agent_id": agent_id,
                "destination_id": registration.destination_id,
                "security_configuration_digest": self._local_security_semantic_digest(),
                "security_configuration_epoch": epoch,
                "schema": "gateway-security-configuration-v0.3c3c",
            }
        )

    def _dispatch_snapshot_current(
        self,
        agent_id: str,
        registration: DestinationRegistration,
        expected_digest: str,
    ) -> bool:
        current = self._destinations.get(registration.destination_id)
        return (
            current == registration
            and current.enabled
            and self.agent_directory.has_capability(agent_id, current.required_capability)
            and self._security_configuration_digest(agent_id, current) == expected_digest
        )

    def _validate_worker(self, worker: GatewayWorker, agent: AgentAuthority) -> None:
        capability = self._worker_capabilities.get(id(worker))
        if (
            not isinstance(worker, GatewayWorker)
            or capability is None
            or capability is not worker._capability
            or worker._pid != os.getpid()
            or worker._thread_id != threading.get_ident()
            or agent.agent_id != worker.agent_id
            or not self.agent_directory.authenticate(agent, worker.agent_id)
        ):
            raise GatewayExecutionError("WORKER_AUTHORITY_INVALID", "worker authority is stale")

    def _require_host(self, control: GatewayExecutionHostControl) -> None:
        if (
            not isinstance(control, GatewayExecutionHostControl)
            or control._capability is not self._host_capability
            or control._pid != os.getpid()
            or control._thread_id != threading.get_ident()
            or control._boot_event_id != self.store.boot_epoch
        ):
            raise GatewayExecutionError("HOST_AUTHORITY_INVALID", "host control is invalid")
        if self.authority.current_runtime_boot_event_id() != self.store.boot_epoch:
            raise GatewayExecutionError(
                "HOST_AUTHORITY_STALE_BOOT", "host control belongs to an old runtime boot"
            )

    def _require_configuration_admin(self) -> None:
        if self.store.config.worker_attach:
            raise GatewayExecutionError(
                "WORKER_CONFIGURATION_READ_ONLY",
                "attached workers cannot update shared security configuration",
            )

    def _local_security_semantic_digest(self) -> str:
        destinations = {
            destination_id: {
                "action_types": registration.action_types,
                "classification": registration.classification.value,
                "configuration_digest": registration.configuration_digest,
                "enabled": registration.enabled,
                "idempotency_class": registration.idempotency_class.value,
                "required_capability": registration.required_capability,
                "runner_implementation": (
                    "secureinjections.persistent_state.fake_destination.FakeDestination:v0.3c3c"
                ),
                "runner_identity": registration.runner_identity,
                "runner_path": str(registration.runner.path.resolve()),
            }
            for destination_id, registration in sorted(self._destinations.items())
        }
        return self._digest(
            {
                "agents": self.agent_directory.execution_security_snapshot(),
                "destinations": destinations,
                "detector_hash": DETECTOR_HASH,
                "guard_policy_hash": self._gateway.guard.policy.policy_hash,
                "integration_policy_revision": self._policy_revision,
                "recovery_policy": {
                    "allow_caller_supplied_key": self._recovery_policy.allow_caller_supplied_key,
                    "allow_queryable_operation": self._recovery_policy.allow_queryable_operation,
                    "automatic_query": self._recovery_policy.automatic_query,
                    "enabled": self._recovery_policy.enabled,
                    "revision": self._recovery_policy.revision,
                },
                "persistent_authority_mode": "C2_REQUIRED",
                "recovery_capability_issuance": "host-process-thread-boot-v0.3c3c",
                "recovery_coordinator": (
                    "secureinjections.gateway.recovery.GatewayRecoveryCoordinator:v0.3c3c"
                ),
                "recovery_query_adapter": {
                    "adapter_identity": FakeDestinationStatusAdapter.adapter_identity,
                    "adapter_version": FakeDestinationStatusAdapter.adapter_version,
                    "implementation": (
                        "secureinjections.persistent_state.fake_destination."
                        "FakeDestinationStatusAdapter:v0.3c3c"
                    ),
                },
                "schema": "gateway-shared-security-semantics-v0.3c3c",
                "sequence_policy_version": SEQUENCE_POLICY_VERSION,
            }
        )

    def _commit_security_configuration(self) -> None:
        try:
            configuration = self.authority.update_security_configuration(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                expected_epoch=self._shared_epoch,
                configuration_digest=self._local_security_semantic_digest(),
                worker_attach_digest=self._worker_bootstrap_digest(
                    self._worker_attach_token, self.store.boot_epoch
                ),
                expected_boot_event_id=self.store.boot_epoch,
            )
        except ExecutionBindingError as exc:
            if "stale runtime boot" in str(exc):
                raise GatewayExecutionError(
                    "HOST_AUTHORITY_STALE_BOOT",
                    "security configuration belongs to an old runtime boot",
                ) from exc
            raise
        self._shared_epoch = configuration.epoch
        self._shared_configuration_digest = configuration.configuration_digest

    @staticmethod
    def _copy_recovery_policy(policy: GatewayRecoveryPolicy) -> GatewayRecoveryPolicy:
        return GatewayRecoveryPolicy(
            enabled=policy.enabled,
            automatic_query=policy.automatic_query,
            allow_caller_supplied_key=policy.allow_caller_supplied_key,
            allow_queryable_operation=policy.allow_queryable_operation,
            revision=policy.revision,
        )

    def _require_current_shared_configuration(self) -> Any:
        shared = self.authority.get_security_configuration()
        if (
            shared is None
            or shared.mode != "C2_REQUIRED"
            or shared.configuration_digest != self._local_security_semantic_digest()
        ):
            raise GatewayExecutionError(
                "AUTHORIZATION_STALE", "local execution configuration is not shared current"
            )
        self._shared_epoch = shared.epoch
        self._shared_configuration_digest = shared.configuration_digest
        return shared

    @staticmethod
    def _worker_bootstrap_digest(token: str, boot_event_id: str) -> str:
        return hashlib.sha256(f"{token}\0{boot_event_id}".encode()).hexdigest()

    def _destination(self, destination_id: str) -> DestinationRegistration:
        registration = self._destinations.get(destination_id)
        if registration is None:
            raise GatewayExecutionError("DESTINATION_NOT_REGISTERED", "destination is unknown")
        return registration

    def _cancel(self, intent_id: str, reason_code: str) -> GatewayExecutionOutcome:
        record = self.authority.cancel_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, intent_id, reason_code=reason_code
        )
        self.store.project_audit()
        return GatewayExecutionOutcome(record.intent_id, record.state, reason_code)

    @staticmethod
    def _preparation(
        handle: ExecutionDecisionHandle,
        reason_code: str,
        destination_id: str,
        fingerprint: str | None,
        digest: str,
    ) -> GatewayExecutionPreparation:
        return GatewayExecutionPreparation(
            handle.decision_id,
            handle.source_output_event_id,
            ExecutionPolicyDecision(handle.decision),
            reason_code,
            handle.intent_id,
            fingerprint,
            destination_id,
            digest,
        )

    @staticmethod
    def _combined_decision(
        guard: GuardDecision, sequence: SequenceDecision
    ) -> ExecutionPolicyDecision:
        if guard is GuardDecision.BLOCK or sequence is SequenceDecision.BLOCK:
            return ExecutionPolicyDecision.BLOCK
        if guard is GuardDecision.REVIEW or sequence is SequenceDecision.REVIEW:
            return ExecutionPolicyDecision.REVIEW
        return ExecutionPolicyDecision.ALLOW

    @staticmethod
    def _event_type(action_type: str) -> SecurityEventType:
        return {
            "TOOL_CALL": SecurityEventType.TOOL_PROPOSAL,
            "WORKSPACE_READ": SecurityEventType.FILE_READ,
            "MEMORY_WRITE": SecurityEventType.MEMORY_WRITE,
            "EXTERNAL_SEND": SecurityEventType.EXTERNAL_SEND,
            "AGENT_ACTION": SecurityEventType.CAPABILITY_REQUEST,
            "BACKGROUND_AGENT_ACTION": SecurityEventType.CAPABILITY_REQUEST,
        }.get(action_type, SecurityEventType.TOOL_PROPOSAL)

    @staticmethod
    def _reason_code(value: str) -> str:
        rendered = "".join(ch if ch.isalnum() else "_" for ch in value.upper()).strip("_")
        return (rendered or "POLICY_INDETERMINATE")[:200]

    @staticmethod
    def _digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_text(value).encode()).hexdigest()
