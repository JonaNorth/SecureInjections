"""Host-owned c3c coordinator for Gateway reconciliation and recovery."""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final
from weakref import WeakKeyDictionary

from ..persistent_state import (
    DestinationQueryResult,
    ExecutionIntentRecord,
    ExecutionState,
    ExecutionStateConflict,
    IdempotencyClass,
    ReconciliationAuthority,
    RecoveryAuthority,
    RecoveryRecord,
    RecoveryState,
    WorkflowCASConflict,
)
from ..persistent_state.execution import _HOST_EXECUTION_AUTHORITY_CAPABILITY
from ..persistent_state.fake_destination import (
    FakeCallerTermination,
    FakeDestination,
    FakeDestinationFailure,
    FakeDestinationMode,
    FakeDestinationStatusAdapter,
    FakeDestinationTimeout,
)
from .agent_boundary import AgentAuthority
from .execution import (
    _DESTINATION_REGISTRY_ID,
    DestinationRegistration,
    GatewayExecutionError,
    GatewayExecutionHostControl,
    GatewayExecutionRuntime,
    GatewayWorker,
)

_CANDIDATE_ISSUER: Final = object()
_MAX_LIVE_CANDIDATES: Final = 512


class GatewayRecoveryStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    CONFIGURATION_STALE = "CONFIGURATION_STALE"
    RECONCILIATION_ACTIVE = "RECONCILIATION_ACTIVE"
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    NO_EFFECT_CONFIRMED = "NO_EFFECT_CONFIRMED"
    STILL_UNKNOWN = "STILL_UNKNOWN"
    CONFLICT = "CONFLICT"
    QUERY_FAILED = "QUERY_FAILED"
    ORIGINAL_OPERATION_UNAVAILABLE = "ORIGINAL_OPERATION_UNAVAILABLE"
    DESTINATION_CLASS_UNSUPPORTED = "DESTINATION_CLASS_UNSUPPORTED"
    AUTHORIZED = "AUTHORIZED"
    DISPATCHING = "DISPATCHING"
    RECOVERY_OUTCOME_UNKNOWN = "RECOVERY_OUTCOME_UNKNOWN"


class GatewayRecoveryCandidate:
    """Opaque process/thread-local snapshot; persisted state remains authoritative."""

    __slots__ = (
        "candidate_id",
        "intent_id",
        "workflow_id",
        "agent_id",
        "action_fingerprint",
        "destination_id",
        "destination_contract_digest",
        "destination_class",
        "policy_config_digest",
        "original_operation_id",
        "reconciliation_id",
        "query_evidence_id",
        "query_evidence_digest",
        "query_result",
        "recovery_id",
        "recovery_state",
        "status",
        "_coordinator",
        "_capability",
        "_pid",
        "_thread_id",
        "_boot_event_id",
        "__weakref__",
    )

    candidate_id: str
    intent_id: str
    workflow_id: str
    agent_id: str
    action_fingerprint: str
    destination_id: str
    destination_contract_digest: str
    destination_class: IdempotencyClass
    policy_config_digest: str
    original_operation_id: str | None
    reconciliation_id: str | None
    query_evidence_id: str | None
    query_evidence_digest: str | None
    query_result: DestinationQueryResult | None
    recovery_id: str | None
    recovery_state: RecoveryState | None
    status: GatewayRecoveryStatus
    _coordinator: GatewayRecoveryCoordinator
    _capability: object
    _pid: int
    _thread_id: int
    _boot_event_id: str

    def __init__(
        self, issuer: object, coordinator: GatewayRecoveryCoordinator, **values: Any
    ) -> None:
        if issuer is not _CANDIDATE_ISSUER:
            raise TypeError("Gateway recovery candidates cannot be caller-constructed")
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_coordinator", coordinator)

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Gateway recovery candidates are immutable")
        object.__setattr__(self, name, value)

    def __copy__(self) -> object:
        raise TypeError("Gateway recovery candidates are not copyable")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("Gateway recovery candidates are not copyable")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("Gateway recovery candidates are process-local and non-serializable")


@dataclass(frozen=True, slots=True)
class GatewayRecoveryOutcome:
    intent_id: str
    recovery_id: str | None
    state: ExecutionState | RecoveryState
    reason_code: str
    result: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.result is not None:
            object.__setattr__(self, "result", MappingProxyType(dict(self.result)))


@dataclass(frozen=True, slots=True)
class _CandidateBinding:
    token: object
    snapshot: tuple[Any, ...]
    pid: int
    thread_id: int
    boot_event_id: str


class GatewayRecoveryCoordinator:
    """Narrow host authority bridge; model/provider inputs never select recovery targets."""

    def __init__(self, runtime: GatewayExecutionRuntime) -> None:
        self._runtime = runtime
        self.execution = runtime.authority
        self.reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, self.execution
        )
        self.recovery = RecoveryAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, self.execution
        )
        self._inspection = self.reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        self._reconciler = self.reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="gateway-c3c-reconciler",
            identity_class="HOST_COORDINATOR",
        )
        self._recovery_decision = self.recovery.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="gateway-c3c-recovery-policy",
            identity_class="HOST_POLICY",
        )
        self._query = self.recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="gateway-c3c-query-adapter",
            identity_class="HOST_ADAPTER",
        )
        self._candidate_bindings: WeakKeyDictionary[GatewayRecoveryCandidate, _CandidateBinding] = (
            WeakKeyDictionary()
        )

    def __copy__(self) -> object:
        raise TypeError("Gateway recovery coordinators are not copyable")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("Gateway recovery coordinators are not copyable")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("Gateway recovery coordinators are not serializable")

    def discover(
        self, control: GatewayExecutionHostControl, *, limit: int = 128
    ) -> tuple[GatewayRecoveryCandidate, ...]:
        """CAPABILITY_PROTECTED: discover targets solely from authenticated store state."""

        self._runtime._require_host(control)
        self._require_enabled()
        self._runtime._require_current_shared_configuration()
        candidates: list[GatewayRecoveryCandidate] = []
        for intent in self.execution.list_outcome_unknown_intents(limit=limit):
            registration = self._registration_for(intent)
            agent_id = self._agent_id_for(intent)
            current_digest = self._runtime._security_configuration_digest(agent_id, registration)
            recovery = self.recovery.get_current_recovery(intent.intent_id)
            status = (
                GatewayRecoveryStatus.DISCOVERED
                if current_digest == intent.policy_config_digest
                else GatewayRecoveryStatus.CONFIGURATION_STALE
            )
            # A persisted lifecycle can describe what was authorized under an older
            # configuration, but it cannot override the current configuration epoch.
            if recovery is not None and status is not GatewayRecoveryStatus.CONFIGURATION_STALE:
                status = {
                    RecoveryState.READY: GatewayRecoveryStatus.AUTHORIZED,
                    RecoveryState.CLAIMED: GatewayRecoveryStatus.AUTHORIZED,
                    RecoveryState.DISPATCHING: GatewayRecoveryStatus.DISPATCHING,
                    RecoveryState.OUTCOME_UNKNOWN: GatewayRecoveryStatus.RECOVERY_OUTCOME_UNKNOWN,
                }.get(recovery.state, status)
            candidates.append(
                self._issue_candidate(
                    intent,
                    registration,
                    agent_id=agent_id,
                    status=status,
                    recovery=recovery,
                )
            )
        return tuple(candidates)

    def diagnose(
        self,
        control: GatewayExecutionHostControl,
        candidate: GatewayRecoveryCandidate,
        *,
        automatic: bool = False,
    ) -> GatewayRecoveryCandidate:
        """CAPABILITY_PROTECTED: begin reconciliation and optionally run a normalized query."""

        self._runtime._require_host(control)
        intent, registration = self._validate_candidate(candidate)
        self._require_enabled()
        if automatic and not self._runtime.recovery_policy.automatic_query:
            raise GatewayExecutionError(
                "AUTOMATIC_RECOVERY_QUERY_DISABLED",
                "automatic diagnostic query is not enabled by host policy",
            )
        reconciliation = self._ensure_reconciliation(intent, registration)
        if intent.idempotency_class is not IdempotencyClass.QUERYABLE_OPERATION_ID:
            status = (
                GatewayRecoveryStatus.RECONCILIATION_ACTIVE
                if intent.idempotency_class is IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY
                else GatewayRecoveryStatus.DESTINATION_CLASS_UNSUPPORTED
            )
            return self._issue_candidate(
                intent,
                registration,
                agent_id=candidate.agent_id,
                status=status,
                reconciliation_id=reconciliation.reconciliation_id,
                recovery=self.recovery.get_current_recovery(intent.intent_id),
            )
        if intent.destination_operation_id is None:
            return self._issue_candidate(
                intent,
                registration,
                agent_id=candidate.agent_id,
                status=GatewayRecoveryStatus.ORIGINAL_OPERATION_UNAVAILABLE,
                reconciliation_id=reconciliation.reconciliation_id,
            )
        adapter = FakeDestinationStatusAdapter(
            registration.runner,
            destination_registry=_DESTINATION_REGISTRY_ID,
            destination_name=registration.destination_id,
            destination_contract_digest=registration.configuration_digest,
        )
        self.recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, adapter)
        evidence = self.recovery.query_destination_status(
            self._query, intent.intent_id, adapter=adapter
        )
        self._runtime.store.project_audit()
        status = GatewayRecoveryStatus(evidence.normalized_result.value)
        return self._issue_candidate(
            intent,
            registration,
            agent_id=candidate.agent_id,
            status=status,
            reconciliation_id=evidence.reconciliation_id,
            query_evidence_id=evidence.query_evidence_id,
            query_evidence_digest=evidence.evidence_digest,
            query_result=evidence.normalized_result,
            recovery=self.recovery.get_current_recovery(intent.intent_id),
        )

    def approve(
        self,
        control: GatewayExecutionHostControl,
        candidate: GatewayRecoveryCandidate,
    ) -> GatewayRecoveryCandidate:
        """CAPABILITY_PROTECTED: apply explicit host policy through c3b authorization."""

        self._runtime._require_host(control)
        intent, registration = self._validate_candidate(candidate)
        self._require_enabled()
        self._require_current_policy(intent, registration, candidate.agent_id)
        if candidate.reconciliation_id is None:
            raise GatewayExecutionError(
                "RECOVERY_RECONCILIATION_REQUIRED",
                "recovery approval requires host-established reconciliation",
            )
        policy = self._runtime.recovery_policy
        if intent.idempotency_class is IdempotencyClass.NO_IDEMPOTENCY:
            raise GatewayExecutionError(
                "RECOVERY_DESTINATION_UNSUPPORTED", "NO_IDEMPOTENCY cannot recover"
            )
        if intent.idempotency_class is IdempotencyClass.TRANSACTIONALLY_LOCAL:
            raise GatewayExecutionError(
                "RECOVERY_DESTINATION_UNSUPPORTED", "transactionally-local recovery is absent"
            )
        query_evidence_id: str | None = None
        if intent.idempotency_class is IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY:
            if not policy.allow_caller_supplied_key:
                raise GatewayExecutionError(
                    "RECOVERY_POLICY_DENIED", "same-key recovery is disabled"
                )
        else:
            if not policy.allow_queryable_operation:
                raise GatewayExecutionError(
                    "RECOVERY_POLICY_DENIED", "queryable recovery is disabled"
                )
            if (
                candidate.query_result is not DestinationQueryResult.NO_EFFECT_CONFIRMED
                or candidate.query_evidence_id is None
            ):
                raise GatewayExecutionError(
                    "RECOVERY_EVIDENCE_INELIGIBLE",
                    "latest normalized query evidence does not prove no effect",
                )
            query_evidence_id = candidate.query_evidence_id
        proposal = self.recovery.propose_recovery(
            self._recovery_decision,
            intent.intent_id,
            destination_contract_digest=registration.configuration_digest,
            policy_config_digest=intent.policy_config_digest,
            query_evidence_id=query_evidence_id,
            authorization_validator=lambda: self._snapshot_current(
                intent, registration, candidate.agent_id
            ),
        )
        recovery = self.recovery.authorize_recovery(
            self._recovery_decision,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=registration.configuration_digest,
            policy_config_digest=intent.policy_config_digest,
            authorization_validator=lambda: self._snapshot_current(
                intent, registration, candidate.agent_id
            ),
        )
        self._runtime.store.project_audit()
        return self._issue_candidate(
            intent,
            registration,
            agent_id=candidate.agent_id,
            status=GatewayRecoveryStatus.AUTHORIZED,
            reconciliation_id=recovery.reconciliation_id,
            query_evidence_id=query_evidence_id,
            query_evidence_digest=candidate.query_evidence_digest,
            query_result=candidate.query_result,
            recovery=recovery,
        )

    def execute(
        self,
        worker: GatewayWorker,
        agent: AgentAuthority,
        candidate: GatewayRecoveryCandidate,
        *,
        mode: FakeDestinationMode = FakeDestinationMode.SUCCESS,
        lease_seconds: float = 30.0,
    ) -> GatewayRecoveryOutcome:
        """CAPABILITY_PROTECTED: claim, fence, and invoke one authorized local recovery."""

        intent, registration = self._validate_candidate(candidate)
        self._runtime._validate_worker(worker, agent)
        if candidate.recovery_id is None:
            raise GatewayExecutionError(
                "RECOVERY_AUTHORIZATION_REQUIRED", "candidate has no c3b authorization"
            )
        if worker.agent_id != candidate.agent_id:
            raise GatewayExecutionError(
                "RECOVERY_WORKER_MISMATCH", "recovery worker differs from original agent"
            )
        if (intent.action_type == "BACKGROUND_AGENT_ACTION") != (worker.scope == "background"):
            raise GatewayExecutionError(
                "RECOVERY_WORKER_SCOPE_MISMATCH", "recovery worker scope is incompatible"
            )
        self._require_current_policy(intent, registration, candidate.agent_id)
        if not self._runtime.agent_directory.has_capability(
            worker.agent_id, registration.required_capability
        ):
            raise GatewayExecutionError("CAPABILITY_REVOKED", "recovery capability was revoked")
        current = self.recovery.get_current_recovery(intent.intent_id)
        if current is None or current.recovery_id != candidate.recovery_id:
            raise GatewayExecutionError(
                "RECOVERY_AUTHORIZATION_STALE", "candidate is not the current recovery lineage"
            )
        self._runtime.store.enforce_audit_bound(privileged=True)
        claim = self.recovery.claim_recovery(
            worker._handle, current.recovery_id, lease_seconds=lease_seconds
        )
        with self._runtime._lock:
            self._require_current_policy(intent, registration, candidate.agent_id)
            dispatch = self.recovery.begin_recovery_dispatch(
                claim,
                action=intent.normalized_action,
                destination_registry=_DESTINATION_REGISTRY_ID,
                destination=registration.destination_id,
                destination_contract_digest=registration.configuration_digest,
                policy_config_digest=intent.policy_config_digest,
                authorization_validator=lambda: self._snapshot_current(
                    intent, registration, candidate.agent_id
                ),
            )
        self._runtime.store.project_audit()
        try:
            result = FakeDestination.invoke_recovery(
                registration.runner,
                self.recovery,
                dispatch,
                intent.normalized_action,
                mode=mode,
            )
        except (FakeDestinationTimeout, FakeCallerTermination) as exc:
            record = self.recovery.mark_recovery_outcome_unknown(
                dispatch, destination_operation_id=exc.operation_id
            )
            return self._outcome(record, "RECOVERY_OUTCOME_UNKNOWN")
        except FakeDestinationFailure:
            if mode is FakeDestinationMode.FAIL_BEFORE_EFFECT:
                digest = self._runtime._digest({"mode": mode.value, "status": "PROVEN_NO_EFFECT"})
                record = self.recovery.fail_recovery_no_effect(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY, dispatch, result_digest=digest
                )
                return self._outcome(record, "RECOVERY_PROVEN_NO_EFFECT")
            record = self.recovery.mark_recovery_outcome_unknown(dispatch)
            return self._outcome(record, "RECOVERY_OUTCOME_UNKNOWN")
        if not isinstance(result, Mapping):
            record = self.recovery.mark_recovery_outcome_unknown(dispatch)
            return self._outcome(record, "RECOVERY_MALFORMED_OUTCOME")
        if result.get("status") in {"SUCCEEDED", "DEDUPLICATED"} and isinstance(
            result.get("operation_id"), str
        ):
            record = self.recovery.complete_recovery(
                dispatch,
                result_digest=self._runtime._digest(dict(result)),
                destination_operation_id=str(result["operation_id"]),
            )
            return self._outcome(record, "RECOVERY_COMPLETED", result)
        if result.get("status") == "PAUSED_BEFORE_EFFECT":
            digest = self._runtime._digest({"mode": mode.value, "status": "PROVEN_NO_EFFECT"})
            record = self.recovery.fail_recovery_no_effect(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY, dispatch, result_digest=digest
            )
            return self._outcome(record, "RECOVERY_PROVEN_NO_EFFECT", result)
        operation = result.get("operation_id")
        record = self.recovery.mark_recovery_outcome_unknown(
            dispatch,
            destination_operation_id=operation if isinstance(operation, str) else None,
        )
        return self._outcome(record, "RECOVERY_OUTCOME_UNKNOWN", result)

    def _ensure_reconciliation(
        self, intent: ExecutionIntentRecord, registration: DestinationRegistration
    ) -> Any:
        inspection = self.reconciliation.inspect_execution(self._inspection, intent.intent_id)
        if inspection.reconciliation_id is not None:
            return inspection
        try:
            inspection = self.reconciliation.begin_reconciliation(
                self._reconciler,
                intent.intent_id,
                destination_contract_digest=registration.configuration_digest,
            )
            self._runtime.store.project_audit()
            return inspection
        except (ExecutionStateConflict, WorkflowCASConflict):
            return self.reconciliation.inspect_execution(self._inspection, intent.intent_id)

    def _validate_candidate(
        self, candidate: GatewayRecoveryCandidate
    ) -> tuple[ExecutionIntentRecord, DestinationRegistration]:
        if not isinstance(candidate, GatewayRecoveryCandidate):
            raise GatewayExecutionError(
                "RECOVERY_CANDIDATE_INVALID", "host recovery candidate is required"
            )
        binding = self._candidate_bindings.get(candidate)
        if (
            binding is None
            or candidate._coordinator is not self
            or candidate._capability is not binding.token
            or candidate._pid != binding.pid
            or candidate._thread_id != binding.thread_id
            or binding.pid != os.getpid()
            or binding.thread_id != threading.get_ident()
            or candidate._boot_event_id != binding.boot_event_id
            or binding.boot_event_id != self._runtime.store.boot_epoch
            or self._candidate_snapshot(candidate) != binding.snapshot
        ):
            raise GatewayExecutionError(
                "RECOVERY_CANDIDATE_INVALID", "candidate is forged, mutated, or stale"
            )
        intent = self.execution.get_intent(candidate.intent_id)
        if intent.state is not ExecutionState.OUTCOME_UNKNOWN:
            raise GatewayExecutionError(
                "RECOVERY_TARGET_RESOLVED", "canonical intent is no longer unresolved"
            )
        registration = self._registration_for(intent)
        if any(
            (
                intent.workflow_id != candidate.workflow_id,
                self._agent_id_for(intent) != candidate.agent_id,
                intent.action_fingerprint != candidate.action_fingerprint,
                intent.destination != candidate.destination_id,
                intent.destination_config_digest != candidate.destination_contract_digest,
                intent.idempotency_class is not candidate.destination_class,
                intent.policy_config_digest != candidate.policy_config_digest,
                intent.destination_operation_id != candidate.original_operation_id,
            )
        ):
            raise GatewayExecutionError(
                "RECOVERY_CANDIDATE_STALE", "canonical recovery binding changed"
            )
        return intent, registration

    def _registration_for(self, intent: ExecutionIntentRecord) -> DestinationRegistration:
        registration = self._runtime._destinations.get(intent.destination)
        if (
            registration is None
            or not registration.enabled
            or intent.destination_registry != _DESTINATION_REGISTRY_ID
            or registration.configuration_digest != intent.destination_config_digest
            or registration.idempotency_class is not intent.idempotency_class
        ):
            raise GatewayExecutionError(
                "RECOVERY_DESTINATION_STALE", "destination registration is not exact current"
            )
        return registration

    def _agent_id_for(self, intent: ExecutionIntentRecord) -> str:
        event = self._runtime.store.state.get_event(intent.proposal_event_id)
        agent_id = event.attributes.get("agent_id")
        if not agent_id:
            raise GatewayExecutionError(
                "RECOVERY_PROVENANCE_MISSING", "original host agent provenance is absent"
            )
        return agent_id

    def _require_enabled(self) -> None:
        if not self._runtime.recovery_policy.enabled:
            raise GatewayExecutionError(
                "RECOVERY_INTEGRATION_DISABLED", "host recovery integration is disabled"
            )

    def _require_current_policy(
        self,
        intent: ExecutionIntentRecord,
        registration: DestinationRegistration,
        agent_id: str,
    ) -> None:
        self._require_enabled()
        self._runtime._require_current_shared_configuration()
        if not self._snapshot_current(intent, registration, agent_id):
            raise GatewayExecutionError(
                "RECOVERY_CONFIGURATION_STALE", "recovery policy or destination changed"
            )

    def _snapshot_current(
        self,
        intent: ExecutionIntentRecord,
        registration: DestinationRegistration,
        agent_id: str,
    ) -> bool:
        current = self._runtime._destinations.get(registration.destination_id)
        return bool(
            self._runtime.recovery_policy.enabled
            and current == registration
            and current.enabled
            and self._runtime.agent_directory.has_capability(agent_id, current.required_capability)
            and self._runtime._security_configuration_digest(agent_id, current)
            == intent.policy_config_digest
        )

    def _issue_candidate(
        self,
        intent: ExecutionIntentRecord,
        registration: DestinationRegistration,
        *,
        agent_id: str,
        status: GatewayRecoveryStatus,
        reconciliation_id: str | None = None,
        query_evidence_id: str | None = None,
        query_evidence_digest: str | None = None,
        query_result: DestinationQueryResult | None = None,
        recovery: RecoveryRecord | None = None,
    ) -> GatewayRecoveryCandidate:
        if len(self._candidate_bindings) >= _MAX_LIVE_CANDIDATES:
            raise GatewayExecutionError(
                "RECOVERY_CANDIDATE_BOUND_EXHAUSTED",
                "live host recovery candidate bound is exhausted",
            )
        token = object()
        candidate = GatewayRecoveryCandidate(
            _CANDIDATE_ISSUER,
            self,
            candidate_id="gateway-recovery-candidate-" + uuid.uuid4().hex,
            intent_id=intent.intent_id,
            workflow_id=intent.workflow_id,
            agent_id=agent_id,
            action_fingerprint=intent.action_fingerprint,
            destination_id=registration.destination_id,
            destination_contract_digest=registration.configuration_digest,
            destination_class=intent.idempotency_class,
            policy_config_digest=intent.policy_config_digest,
            original_operation_id=intent.destination_operation_id,
            reconciliation_id=(
                recovery.reconciliation_id if recovery is not None else reconciliation_id
            ),
            query_evidence_id=query_evidence_id,
            query_evidence_digest=query_evidence_digest,
            query_result=query_result,
            recovery_id=None if recovery is None else recovery.recovery_id,
            recovery_state=None if recovery is None else recovery.state,
            status=status,
            _capability=token,
            _pid=os.getpid(),
            _thread_id=threading.get_ident(),
            _boot_event_id=self._runtime.store.boot_epoch,
        )
        self._candidate_bindings[candidate] = _CandidateBinding(
            token,
            self._candidate_snapshot(candidate),
            os.getpid(),
            threading.get_ident(),
            self._runtime.store.boot_epoch,
        )
        return candidate

    @staticmethod
    def _candidate_snapshot(candidate: GatewayRecoveryCandidate) -> tuple[Any, ...]:
        return tuple(
            getattr(candidate, name)
            for name in GatewayRecoveryCandidate.__slots__
            if name not in {"_coordinator", "_capability", "__weakref__"}
        )

    def _outcome(
        self,
        recovery: RecoveryRecord,
        reason: str,
        result: Mapping[str, Any] | None = None,
    ) -> GatewayRecoveryOutcome:
        self._runtime.store.project_audit()
        return GatewayRecoveryOutcome(
            recovery.execution_intent_id,
            recovery.recovery_id,
            recovery.state,
            reason,
            result,
        )
