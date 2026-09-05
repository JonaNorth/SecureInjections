"""Closed public models for the isolated v0.3a authority-store foundation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class StoreDirectoryState(StrEnum):
    EMPTY_NEW_STORE = "EMPTY_NEW_STORE"
    COMPLETE_EXISTING_STORE = "COMPLETE_EXISTING_STORE"
    PARTIAL_STATE = "PARTIAL_STATE"


class AnchorState(StrEnum):
    FINAL = "FINAL"
    PREPARED = "PREPARED"


class VerificationLevel(StrEnum):
    STARTUP = "STARTUP"
    HEAD = "HEAD"
    FULL = "FULL"


class PersistentStateError(RuntimeError):
    code = "PERSISTENT_STATE_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class StateDirectoryError(PersistentStateError):
    code = "STATE_DIRECTORY_UNSAFE"


class StateInitializationError(PersistentStateError):
    code = "STATE_INITIALIZATION_FAILED"


class StateVerificationError(PersistentStateError):
    code = "STATE_VERIFICATION_FAILED"


class StateAuthenticationError(StateVerificationError):
    code = "STATE_AUTHENTICATION_FAILED"


class StateRollbackError(StateVerificationError):
    code = "ROLLBACK_DETECTED"


class StateBusyError(PersistentStateError):
    code = "AUTHORITY_STORE_BUSY"


class TrustedRootIssuanceRequired(PersistentStateError):
    code = "TRUSTED_ROOT_ISSUANCE_REQUIRED"


class WorkflowCASConflict(PersistentStateError):
    code = "WORKFLOW_CAS_CONFLICT"


class ExecutionAuthorityError(PersistentStateError):
    code = "EXECUTION_AUTHORITY_DENIED"


class ExecutionStateConflict(ExecutionAuthorityError):
    code = "EXECUTION_STATE_CONFLICT"


class ExecutionBindingError(ExecutionAuthorityError):
    code = "EXECUTION_BINDING_MISMATCH"


class UnknownAuthorityRecord(PersistentStateError):
    code = "UNKNOWN_AUTHORITY_RECORD"


class InjectedAuthorityCrash(PersistentStateError):
    code = "INJECTED_AUTHORITY_CRASH"


@dataclass(frozen=True, slots=True)
class PersistentStateConfig:
    state_directory: Path
    deployment_id: str
    busy_timeout_ms: int = 1_000
    require_wal: bool = True


@dataclass(frozen=True, slots=True)
class StoreHealth:
    status: str
    instance_id: str
    deployment_id: str
    latest_sequence: int
    journal_mode: str
    anchor_state: AnchorState


@dataclass(frozen=True, slots=True)
class VerificationReport:
    valid: bool
    level: VerificationLevel
    latest_sequence: int
    mutation_count: int
    envelope_count: int
    event_count: int
    workflow_count: int
    consumption_count: int
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EnvelopeHandle:
    content_id: str
    trust: str
    ever_untrusted: bool
    sensitive: bool
    suspicious: bool
    content_digest: str
    creation_event_id: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class EventHandle:
    event_id: str
    event_type: str
    correlation_id: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class WorkflowHandle:
    workflow_id: str
    head_event_id: str
    current_content_id: str
    revision: int
    status: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class ConsumptionResult:
    consumed: bool
    reason_code: str
    token_kind: str
    token_id: str
    consumption_id: str | None = None
    mutation_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class VerifiedEnvelopeRecord:
    """Authenticated metadata only; this is not a runtime ContentEnvelope."""

    content_id: str
    authority_kind: str
    source_type: str
    trust: str
    ever_untrusted: bool
    sensitive: bool
    suspicious: bool
    findings: tuple[dict[str, Any], ...]
    provenance: tuple[str, ...]
    parent_content_ids: tuple[str, ...]
    transformations: tuple[dict[str, Any], ...]
    content_digest: str
    ancestor_digests: tuple[str, ...]
    inspection_digest: str | None
    producing_boundary: str
    creation_event_id: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class VerifiedEventRecord:
    event_id: str
    event_type: str
    correlation_id: str
    parent_event_ids: tuple[str, ...]
    content_ids: tuple[str, ...]
    attributes: dict[str, str]
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class AuditOutboxRecord:
    outbox_id: int
    mutation_sequence: int
    mutation_type: str
    payload_json: str
    created_unix_ns: int


class ExecutionState(StrEnum):
    READY = "READY"
    CLAIMED = "CLAIMED"
    DISPATCHING = "DISPATCHING"
    COMPLETED = "COMPLETED"
    FAILED_NO_EFFECT = "FAILED_NO_EFFECT"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    CANCELLED = "CANCELLED"


class IdempotencyClass(StrEnum):
    NO_IDEMPOTENCY = "NO_IDEMPOTENCY"
    CALLER_SUPPLIED_IDEMPOTENCY_KEY = "CALLER_SUPPLIED_IDEMPOTENCY_KEY"
    QUERYABLE_OPERATION_ID = "QUERYABLE_OPERATION_ID"
    TRANSACTIONALLY_LOCAL = "TRANSACTIONALLY_LOCAL"


class ReconciliationEvidenceCategory(StrEnum):
    EXTERNALLY_VERIFIED_COMPLETED = "EXTERNALLY_VERIFIED_COMPLETED"
    EXTERNALLY_VERIFIED_NO_EFFECT = "EXTERNALLY_VERIFIED_NO_EFFECT"
    OPERATOR_VERIFIED_COMPLETED = "OPERATOR_VERIFIED_COMPLETED"
    OPERATOR_VERIFIED_NO_EFFECT = "OPERATOR_VERIFIED_NO_EFFECT"
    CONFLICT = "CONFLICT"
    INSUFFICIENT = "INSUFFICIENT"
    ABANDONED = "ABANDONED"


class ReconciliationProposalType(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED_NO_EFFECT = "FAILED_NO_EFFECT"


class ReconciliationDisposition(StrEnum):
    ACTIVE = "ACTIVE"
    PROPOSED = "PROPOSED"
    CONFIRMED_COMPLETED = "CONFIRMED_COMPLETED"
    CONFIRMED_NO_EFFECT = "CONFIRMED_NO_EFFECT"
    CONFLICT = "CONFLICT"
    INSUFFICIENT = "INSUFFICIENT"
    ABANDONED = "ABANDONED"


class DestinationQueryResult(StrEnum):
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    NO_EFFECT_CONFIRMED = "NO_EFFECT_CONFIRMED"
    STILL_UNKNOWN = "STILL_UNKNOWN"
    CONFLICT = "CONFLICT"
    QUERY_FAILED = "QUERY_FAILED"


class RecoveryState(StrEnum):
    READY = "READY"
    CLAIMED = "CLAIMED"
    DISPATCHING = "DISPATCHING"
    COMPLETED = "COMPLETED"
    FAILED_NO_EFFECT = "FAILED_NO_EFFECT"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class ReconciliationInspection:
    reconciliation_id: str | None
    intent_id: str
    ambiguous_attempt_id: str
    generation: int
    action_fingerprint: str
    destination: str
    destination_contract_digest: str
    external_operation_id: str | None
    disposition: ReconciliationDisposition | None
    proposal_type: ReconciliationProposalType | None
    evidence_category: ReconciliationEvidenceCategory | None
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class ReconciliationEvidenceRecord:
    evidence_id: str
    reconciliation_id: str
    intent_id: str
    ambiguous_attempt_id: str
    generation: int
    category: ReconciliationEvidenceCategory
    evidence_digest: str
    external_operation_id: str | None
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class ReconciliationProposalRecord:
    proposal_id: str
    proposal_digest: str
    reconciliation_id: str
    intent_id: str
    generation: int
    proposal_type: ReconciliationProposalType
    evidence_id: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class DestinationQueryObservation:
    """Host-normalized query result; arbitrary remote payload is deliberately absent."""

    result: DestinationQueryResult
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class QueryEvidenceRecord:
    query_evidence_id: str
    query_authorization_id: str
    execution_intent_id: str
    reconciliation_id: str
    reconciliation_generation: int
    recovery_generation: int
    normalized_result: DestinationQueryResult
    evidence_digest: str
    original_operation_id: str
    adapter_identity: str
    adapter_version: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class RecoveryProposalRecord:
    proposal_id: str
    proposal_digest: str
    execution_intent_id: str
    reconciliation_id: str
    reconciliation_generation: int
    recovery_generation: int
    query_evidence_id: str | None
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class RecoveryRecord:
    recovery_id: str
    execution_intent_id: str
    reconciliation_id: str
    reconciliation_generation: int
    recovery_generation: int
    destination_class: IdempotencyClass
    action_fingerprint: str
    destination_registry: str
    destination: str
    destination_contract_digest: str
    original_idempotency_key: str | None
    original_operation_id: str | None
    policy_config_digest: str
    state: RecoveryState
    claim_generation: int
    claim_id: str | None
    worker_id: str | None
    boot_event_id: str | None
    attempt_id: str | None
    dispatch_authorization_id: str | None
    outcome_operation_id: str | None
    outcome_digest: str | None
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class ExecutionDecisionHandle:
    decision_id: str
    source_output_event_id: str
    decision: str
    intent_id: str | None
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class ExecutionSecurityConfiguration:
    """Authenticated store-wide execution mode and current configuration binding."""

    mode: str
    epoch: int
    configuration_digest: str
    worker_attach_digest: str
    mutation_sequence: int


@dataclass(frozen=True, slots=True)
class ExecutionIntentRecord:
    intent_id: str
    workflow_id: str
    source_turn_event_id: str
    source_output_event_id: str
    proposal_event_id: str
    action_type: str
    normalized_action: dict[str, Any]
    action_fingerprint: str
    destination_registry: str
    destination: str
    destination_config_digest: str
    ancestry_event_ids: tuple[str, ...]
    content_digests: tuple[str, ...]
    policy_config_digest: str
    idempotency_class: IdempotencyClass
    idempotency_key: str | None
    state: ExecutionState
    claim_generation: int
    active_claim_id: str | None
    worker_id: str | None
    boot_event_id: str | None
    attempt_id: str | None
    lease_deadline_ns: int | None
    destination_operation_id: str | None
    result_digest: str | None
    mutation_sequence: int
