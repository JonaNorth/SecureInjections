"""Host-only authenticated query and recovery authority for Agent Boundary v0.3c3b.

Recovery is a separate lineage for one already-ambiguous canonical execution
intent.  This module never rewrites that intent to READY, CLAIMED, or
DISPATCHING and has no Gateway, provider, model-tool, or real-network adapter.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any, Final, NamedTuple, Protocol, cast

from .canonical import canonical_text
from .execution import (
    _DIGEST,
    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
    ExecutionAuthority,
    WorkerHandle,
    _logical,
    _mac,
    _new_id,
    _verified_row,
    _verified_workflow_row,
    normalize_action,
)
from .models import (
    DestinationQueryObservation,
    DestinationQueryResult,
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionState,
    ExecutionStateConflict,
    IdempotencyClass,
    QueryEvidenceRecord,
    ReconciliationDisposition,
    ReconciliationEvidenceCategory,
    RecoveryProposalRecord,
    RecoveryRecord,
    RecoveryState,
    StateAuthenticationError,
    StateVerificationError,
    UnknownAuthorityRecord,
    WorkflowCASConflict,
)
from .reconciliation import ReconciliationAuthority, _verified_reconciliation_row
from .store import (
    _EXECUTION_EXTENSION_CAPABILITY,
    SCHEMA_VERSION,
    _change,
    _consumption_logical_from_row,
    _verify_common_record,
    _workflow_logical_from_row,
)

RECOVERY_SCHEMA_VERSION: Final = "execution-recovery-v0.3c3b"
MAX_QUERY_EVIDENCE_PER_INTENT: Final = 32
MAX_RECOVERY_GENERATIONS_PER_INTENT: Final = 1
MAX_RECOVERY_LIFECYCLE_PER_INTENT: Final = 32
MAX_PENDING_RECOVERIES: Final = 128
MAX_PENDING_AUDIT: Final = 512
MAX_IDENTITY_BYTES: Final = 256
MAX_RECOVERY_LEASE_NS: Final = 300_000_000_000
_CAPABILITY_ISSUER = object()
_HANDLE_ISSUER = object()
_RECOVERY_IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")


_TABLES = (
    """CREATE TABLE IF NOT EXISTS execution_recovery_extensions(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_query_authorizations(
    query_authorization_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL, schema_version TEXT NOT NULL,
    execution_intent_id TEXT NOT NULL, ambiguous_attempt_id TEXT NOT NULL,
    reconciliation_id TEXT NOT NULL, reconciliation_generation INTEGER NOT NULL,
    recovery_generation INTEGER NOT NULL, action_fingerprint TEXT NOT NULL,
    destination_registry TEXT NOT NULL, destination TEXT NOT NULL,
    destination_contract_digest TEXT NOT NULL, original_operation_id TEXT NOT NULL,
    adapter_identity TEXT NOT NULL, adapter_version TEXT NOT NULL,
    security_configuration_epoch INTEGER, security_configuration_digest TEXT,
    querier_identity TEXT NOT NULL, querier_class TEXT NOT NULL,
    query_unix_ns INTEGER NOT NULL, mutation_sequence INTEGER NOT NULL
    REFERENCES state_mutations(sequence), key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_query_evidence(
    query_evidence_id TEXT PRIMARY KEY, query_authorization_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL, schema_version TEXT NOT NULL,
    execution_intent_id TEXT NOT NULL, ambiguous_attempt_id TEXT NOT NULL,
    reconciliation_id TEXT NOT NULL, reconciliation_generation INTEGER NOT NULL,
    recovery_generation INTEGER NOT NULL, action_fingerprint TEXT NOT NULL,
    destination_registry TEXT NOT NULL, destination TEXT NOT NULL,
    destination_contract_digest TEXT NOT NULL, original_operation_id TEXT NOT NULL,
    adapter_identity TEXT NOT NULL, adapter_version TEXT NOT NULL,
    security_configuration_epoch INTEGER, security_configuration_digest TEXT,
    normalized_result TEXT NOT NULL, observation_digest TEXT NOT NULL,
    evidence_digest TEXT NOT NULL, previous_query_evidence_id TEXT,
    mutation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_recovery_proposals(
    proposal_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, execution_intent_id TEXT NOT NULL UNIQUE,
    reconciliation_id TEXT NOT NULL, reconciliation_generation INTEGER NOT NULL,
    recovery_generation INTEGER NOT NULL, query_evidence_id TEXT,
    action_fingerprint TEXT NOT NULL, destination_registry TEXT NOT NULL,
    destination TEXT NOT NULL, destination_contract_digest TEXT NOT NULL,
    destination_class TEXT NOT NULL, original_idempotency_key TEXT,
    original_operation_id TEXT, policy_config_digest TEXT NOT NULL,
    security_configuration_epoch INTEGER, security_configuration_digest TEXT,
    proposer_identity TEXT NOT NULL, proposer_class TEXT NOT NULL,
    proposal_digest TEXT NOT NULL UNIQUE, mutation_sequence INTEGER NOT NULL
    REFERENCES state_mutations(sequence), key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_recovery_authorizations(
    authorization_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL, schema_version TEXT NOT NULL,
    proposal_id TEXT NOT NULL UNIQUE, proposal_digest TEXT NOT NULL,
    execution_intent_id TEXT NOT NULL UNIQUE, reconciliation_id TEXT NOT NULL,
    reconciliation_generation INTEGER NOT NULL, recovery_generation INTEGER NOT NULL,
    authorizer_identity TEXT NOT NULL, authorizer_class TEXT NOT NULL,
    mutation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_recovery_heads(
    execution_intent_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL, schema_version TEXT NOT NULL,
    current_recovery_id TEXT NOT NULL, current_generation INTEGER NOT NULL,
    state TEXT NOT NULL, updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_recoveries(
    recovery_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, execution_intent_id TEXT NOT NULL,
    reconciliation_id TEXT NOT NULL, reconciliation_generation INTEGER NOT NULL,
    recovery_generation INTEGER NOT NULL, proposal_id TEXT NOT NULL UNIQUE,
    authorization_id TEXT NOT NULL UNIQUE, query_evidence_id TEXT,
    action_fingerprint TEXT NOT NULL, destination_registry TEXT NOT NULL,
    destination TEXT NOT NULL, destination_contract_digest TEXT NOT NULL,
    destination_class TEXT NOT NULL, original_idempotency_key TEXT,
    original_operation_id TEXT, policy_config_digest TEXT NOT NULL,
    security_configuration_epoch INTEGER, security_configuration_digest TEXT,
    state TEXT NOT NULL, claim_generation INTEGER NOT NULL, claim_id TEXT,
    worker_id TEXT, boot_event_id TEXT, attempt_id TEXT, lease_deadline_ns INTEGER,
    dispatch_authorization_id TEXT, outcome_operation_id TEXT, outcome_digest TEXT,
    creation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL,
    UNIQUE(execution_intent_id,recovery_generation))""",
    """CREATE TABLE IF NOT EXISTS execution_recovery_lifecycle(
    lifecycle_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, recovery_id TEXT NOT NULL, execution_intent_id TEXT NOT NULL,
    recovery_generation INTEGER NOT NULL, claim_generation INTEGER NOT NULL,
    transition TEXT NOT NULL, state TEXT NOT NULL, claim_id TEXT, worker_id TEXT,
    boot_event_id TEXT, attempt_id TEXT, dispatch_authorization_id TEXT,
    outcome_operation_id TEXT, outcome_digest TEXT,
    mutation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL,
    UNIQUE(recovery_id,mutation_sequence))""",
)


class DestinationStatusAdapter(Protocol):
    """Host-selected adapter contract.  It returns normalized evidence, never authority."""

    adapter_identity: str
    adapter_version: str
    destination_registry: str
    destination: str
    destination_contract_digest: str

    def query_operation_status(self, operation_id: str) -> DestinationQueryObservation: ...


def install_recovery_schema(connection: sqlite3.Connection) -> None:
    for statement in _TABLES:
        connection.execute(statement)
    row = connection.execute(
        "SELECT schema_version FROM execution_recovery_extensions WHERE singleton=1"
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO execution_recovery_extensions VALUES(1,?)",
            (RECOVERY_SCHEMA_VERSION,),
        )
    elif row[0] != RECOVERY_SCHEMA_VERSION:
        raise StateVerificationError("recovery authority schema is incompatible")


def recovery_schema_present(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='execution_recovery_extensions'"
        ).fetchone()
        is not None
    )


def recovery_expected_entities() -> dict[str, dict[str, str]]:
    return {
        "execution_query_authorization": {},
        "execution_query_evidence": {},
        "execution_recovery_proposal": {},
        "execution_recovery_authorization": {},
        "execution_recovery_head": {},
        "execution_recovery": {},
        "execution_recovery_lifecycle": {},
    }


_TABLE_KIND = {
    "execution_query_authorizations": "execution_query_authorization",
    "execution_query_evidence": "execution_query_evidence",
    "execution_recovery_proposals": "execution_recovery_proposal",
    "execution_recovery_authorizations": "execution_recovery_authorization",
    "execution_recovery_heads": "execution_recovery_head",
    "execution_recoveries": "execution_recovery",
    "execution_recovery_lifecycle": "execution_recovery_lifecycle",
}


def _verified_recovery_row(
    authority: RecoveryAuthority,
    connection: sqlite3.Connection,
    table: str,
    key: str,
    value: str,
) -> sqlite3.Row:
    row = connection.execute(f"SELECT * FROM {table} WHERE {key}=?", (value,)).fetchone()
    if row is None:
        raise UnknownAuthorityRecord(f"unknown recovery authority record: {value}")
    logical = dict(row)
    logical.pop("record_mac", None)
    _verify_common_record(authority.state, logical)
    kind = _TABLE_KIND[table]
    if not authority.state._verify_execution_record_mac(
        _EXECUTION_EXTENSION_CAPABILITY, kind, logical, str(row["record_mac"])
    ):
        raise StateAuthenticationError(f"{kind} MAC is invalid")
    return row


class _RecoveryCapability:
    __slots__ = (
        "_authority",
        "_capability",
        "_pid",
        "_thread_id",
        "boot_event_id",
        "identity",
        "identity_class",
    )

    def __init__(
        self,
        issuer: object,
        authority: RecoveryAuthority,
        capability: object,
        *,
        boot_event_id: str,
        identity: str,
        identity_class: str,
    ) -> None:
        if issuer is not _CAPABILITY_ISSUER:
            raise TypeError("recovery capabilities cannot be constructed by callers")
        self._authority = authority
        self._capability = capability
        self._pid = os.getpid()
        self._thread_id = threading.get_ident()
        self.boot_event_id = boot_event_id
        self.identity = identity
        self.identity_class = identity_class

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("recovery capabilities are immutable")
        object.__setattr__(self, name, value)

    def __copy__(self) -> object:
        raise TypeError("recovery capabilities cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("recovery capabilities cannot be copied")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("recovery capabilities are process-local and non-serializable")


class QueryAuthorityCapability(_RecoveryCapability):
    """Opaque host-only authority to query one persisted destination binding."""


class RecoveryDecisionCapability(_RecoveryCapability):
    """Opaque host-only authority to propose or authorize recovery."""


class _CapabilityBinding(NamedTuple):
    token: object
    authority: RecoveryAuthority
    pid: int
    thread_id: int
    boot_event_id: str
    identity: str
    identity_class: str


class _AdapterBinding(NamedTuple):
    adapter: DestinationStatusAdapter
    authority: RecoveryAuthority
    pid: int
    thread_id: int
    adapter_identity: str
    adapter_version: str
    destination_registry: str
    destination: str
    destination_contract_digest: str


class _RecoveryHandle:
    __slots__ = ("_authority", "_capability", "_pid", "_thread_id")

    def __init__(self, issuer: object, authority: RecoveryAuthority, capability: object) -> None:
        if issuer is not _HANDLE_ISSUER:
            raise TypeError("recovery handles cannot be constructed by callers")
        self._authority = authority
        self._capability = capability
        self._pid = os.getpid()
        self._thread_id = threading.get_ident()

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("recovery handles are immutable")
        object.__setattr__(self, name, value)

    def __copy__(self) -> object:
        raise TypeError("recovery handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("recovery handles cannot be copied")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("recovery handles are process-local and non-serializable")


class RecoveryClaimHandle(_RecoveryHandle):
    __slots__ = (
        "recovery_id",
        "execution_intent_id",
        "recovery_generation",
        "claim_generation",
        "claim_id",
        "worker_id",
        "boot_event_id",
        "attempt_id",
    )

    def __init__(self, issuer: object, authority: RecoveryAuthority, capability: object, **v: Any):
        super().__init__(issuer, authority, capability)
        self.recovery_id = str(v["recovery_id"])
        self.execution_intent_id = str(v["execution_intent_id"])
        self.recovery_generation = int(v["recovery_generation"])
        self.claim_generation = int(v["claim_generation"])
        self.claim_id = str(v["claim_id"])
        self.worker_id = str(v["worker_id"])
        self.boot_event_id = str(v["boot_event_id"])
        self.attempt_id = str(v["attempt_id"])


class RecoveryDispatchHandle(RecoveryClaimHandle):
    __slots__ = (
        "dispatch_authorization_id",
        "action_fingerprint",
        "destination_registry",
        "destination",
        "destination_contract_digest",
        "destination_class",
        "original_idempotency_key",
        "original_operation_id",
    )

    def __init__(self, issuer: object, authority: RecoveryAuthority, capability: object, **v: Any):
        self.dispatch_authorization_id = str(v.pop("dispatch_authorization_id"))
        self.action_fingerprint = str(v.pop("action_fingerprint"))
        self.destination_registry = str(v.pop("destination_registry"))
        self.destination = str(v.pop("destination"))
        self.destination_contract_digest = str(v.pop("destination_contract_digest"))
        self.destination_class = IdempotencyClass(str(v.pop("destination_class")))
        key = v.pop("original_idempotency_key")
        self.original_idempotency_key = None if key is None else str(key)
        operation = v.pop("original_operation_id")
        self.original_operation_id = None if operation is None else str(operation)
        super().__init__(issuer, authority, capability, **v)


class RecoveryAuthority:
    """Authenticated c3b query/recovery authority with no Gateway integration."""

    def __init__(self, execution: ExecutionAuthority) -> None:
        self.execution = execution
        self.state = execution.state
        self.reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        self._query_capabilities: dict[int, _CapabilityBinding] = {}
        self._decision_capabilities: dict[int, _CapabilityBinding] = {}
        self._claim_capabilities: dict[tuple[str, int], object] = {}
        self._adapter_bindings: dict[int, _AdapterBinding] = {}

    @classmethod
    def _for_host(cls, host_capability: object, execution: ExecutionAuthority) -> RecoveryAuthority:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("recovery authority construction requires host authority")
        return cls(execution)

    def issue_query_capability(
        self, host_capability: object, *, identity: str, identity_class: str
    ) -> QueryAuthorityCapability:
        self._require_host(host_capability)
        return cast(
            QueryAuthorityCapability,
            self._issue_capability(
                QueryAuthorityCapability,
                self._query_capabilities,
                identity,
                identity_class,
            ),
        )

    def issue_decision_capability(
        self, host_capability: object, *, identity: str, identity_class: str
    ) -> RecoveryDecisionCapability:
        self._require_host(host_capability)
        return cast(
            RecoveryDecisionCapability,
            self._issue_capability(
                RecoveryDecisionCapability,
                self._decision_capabilities,
                identity,
                identity_class,
            ),
        )

    def register_query_adapter(
        self, host_capability: object, adapter: DestinationStatusAdapter
    ) -> None:
        """Bind one host-selected adapter object to this local authority context."""

        self._require_host(host_capability)
        for value, label in (
            (adapter.adapter_identity, "query adapter identity"),
            (adapter.adapter_version, "query adapter version"),
            (adapter.destination_registry, "query destination registry"),
            (adapter.destination, "query destination"),
        ):
            _bounded_identifier(value, label)
        _require_digest(adapter.destination_contract_digest, "query destination contract digest")
        self._adapter_bindings[id(adapter)] = _AdapterBinding(
            adapter,
            self,
            os.getpid(),
            threading.get_ident(),
            adapter.adapter_identity,
            adapter.adapter_version,
            adapter.destination_registry,
            adapter.destination,
            adapter.destination_contract_digest,
        )

    def query_destination_status(
        self,
        capability: QueryAuthorityCapability,
        execution_intent_id: str,
        *,
        adapter: DestinationStatusAdapter,
    ) -> QueryEvidenceRecord:
        identity = self._validate_capability(capability, query=True)
        target = self._query_target(execution_intent_id, adapter)
        observation = adapter.query_operation_status(target["original_operation_id"])
        if not isinstance(observation, DestinationQueryObservation):
            raise ExecutionBindingError("query adapter did not return a normalized observation")
        if not isinstance(observation.result, DestinationQueryResult) or not _DIGEST.fullmatch(
            observation.evidence_digest
        ):
            raise ExecutionBindingError("query adapter observation is malformed")
        query_authorization_id = _new_id("query-authorization")
        query_evidence_id = _new_id("query-evidence")
        queried_ns = time.time_ns()

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], QueryEvidenceRecord]:
            self._require_audit_capacity(conn)
            intent, head, reconciliation = self._require_current_unknown(
                conn,
                execution_intent_id,
                target["destination_contract_digest"],
                allow_abandoned=True,
            )
            self._require_registered_adapter(adapter)
            self._require_query_adapter_binding(intent, adapter)
            if self._security_snapshot(conn) != (
                target["security_configuration_epoch"],
                target["security_configuration_digest"],
            ):
                raise ExecutionBindingError("security configuration changed during query")
            if intent["idempotency_class"] != IdempotencyClass.QUERYABLE_OPERATION_ID.value:
                raise ExecutionAuthorityError("destination class has no query authority")
            if intent["destination_operation_id"] != target["original_operation_id"]:
                raise ExecutionBindingError("query operation binding changed")
            count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM execution_query_evidence WHERE execution_intent_id=?",
                    (execution_intent_id,),
                ).fetchone()[0]
            )
            if count >= MAX_QUERY_EVIDENCE_PER_INTENT:
                raise ExecutionStateConflict("query evidence bound is exhausted")
            previous_row = conn.execute(
                "SELECT query_evidence_id FROM execution_query_evidence "
                "WHERE execution_intent_id=? ORDER BY mutation_sequence DESC LIMIT 1",
                (execution_intent_id,),
            ).fetchone()
            previous = None if previous_row is None else str(previous_row[0])
            authorization = self._base() | {
                "action_fingerprint": str(intent["action_fingerprint"]),
                "adapter_identity": adapter.adapter_identity,
                "adapter_version": adapter.adapter_version,
                "ambiguous_attempt_id": str(intent["attempt_id"]),
                "destination": str(intent["destination"]),
                "destination_contract_digest": str(intent["destination_config_digest"]),
                "destination_registry": str(intent["destination_registry"]),
                "execution_intent_id": execution_intent_id,
                "mutation_sequence": seq,
                "original_operation_id": str(intent["destination_operation_id"]),
                "querier_class": identity.identity_class,
                "querier_identity": identity.identity,
                "query_authorization_id": query_authorization_id,
                "query_unix_ns": queried_ns,
                "reconciliation_generation": int(reconciliation["generation"]),
                "reconciliation_id": str(reconciliation["reconciliation_id"]),
                "recovery_generation": 1,
                "security_configuration_digest": target["security_configuration_digest"],
                "security_configuration_epoch": target["security_configuration_epoch"],
            }
            digest_fields = {
                "action_fingerprint": authorization["action_fingerprint"],
                "adapter_identity": adapter.adapter_identity,
                "adapter_version": adapter.adapter_version,
                "destination": authorization["destination"],
                "destination_contract_digest": authorization["destination_contract_digest"],
                "execution_intent_id": execution_intent_id,
                "normalized_result": observation.result.value,
                "observation_digest": observation.evidence_digest,
                "original_operation_id": authorization["original_operation_id"],
                "query_authorization_id": query_authorization_id,
                "reconciliation_generation": int(reconciliation["generation"]),
                "reconciliation_id": str(reconciliation["reconciliation_id"]),
                "recovery_generation": 1,
                "security_configuration_digest": target["security_configuration_digest"],
                "security_configuration_epoch": target["security_configuration_epoch"],
            }
            evidence_digest = hashlib.sha256(canonical_text(digest_fields).encode()).hexdigest()
            evidence = (
                self._base()
                | {
                    k: authorization[k]
                    for k in (
                        "action_fingerprint",
                        "adapter_identity",
                        "adapter_version",
                        "ambiguous_attempt_id",
                        "destination",
                        "destination_contract_digest",
                        "destination_registry",
                        "execution_intent_id",
                        "original_operation_id",
                        "reconciliation_generation",
                        "reconciliation_id",
                        "recovery_generation",
                        "security_configuration_digest",
                        "security_configuration_epoch",
                    )
                }
                | {
                    "evidence_digest": evidence_digest,
                    "mutation_sequence": seq,
                    "normalized_result": observation.result.value,
                    "observation_digest": observation.evidence_digest,
                    "previous_query_evidence_id": previous,
                    "query_authorization_id": query_authorization_id,
                    "query_evidence_id": query_evidence_id,
                }
            )
            records = (
                ("execution_query_authorization", query_authorization_id, authorization),
                ("execution_query_evidence", query_evidence_id, evidence),
            )
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_query_authorization(
                    db, authorization, macs[(records[0][0], records[0][1])]
                )
                self._insert_query_evidence(db, evidence, macs[(records[1][0], records[1][1])])

            result = QueryEvidenceRecord(
                query_evidence_id,
                query_authorization_id,
                execution_intent_id,
                str(reconciliation["reconciliation_id"]),
                int(reconciliation["generation"]),
                1,
                observation.result,
                evidence_digest,
                str(intent["destination_operation_id"]),
                adapter.adapter_identity,
                adapter.adapter_version,
                seq,
            )
            return self._payload("QUERY_DESTINATION_STATUS", records, macs), apply, result

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "QUERY_DESTINATION_STATUS", build
        )

    def propose_recovery(
        self,
        capability: RecoveryDecisionCapability,
        execution_intent_id: str,
        *,
        destination_contract_digest: str,
        policy_config_digest: str,
        query_evidence_id: str | None = None,
        authorization_validator: Callable[[], bool] | None = None,
    ) -> RecoveryProposalRecord:
        identity = self._validate_capability(capability)
        _require_digest(destination_contract_digest, "destination contract digest")
        _require_digest(policy_config_digest, "policy configuration digest")
        proposal_id = _new_id("recovery-proposal")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], RecoveryProposalRecord]:
            self._require_audit_capacity(conn)
            intent, _head, reconciliation = self._require_current_unknown(
                conn, execution_intent_id, destination_contract_digest
            )
            self._require_source_consumed(conn, intent)
            self._require_recovery_eligible(conn, intent, reconciliation, query_evidence_id)
            if intent["policy_config_digest"] != policy_config_digest:
                raise ExecutionBindingError("recovery policy differs from original operation")
            if authorization_validator is not None and not authorization_validator():
                raise ExecutionBindingError("current recovery policy denied proposal")
            if conn.execute(
                "SELECT 1 FROM execution_recovery_proposals WHERE execution_intent_id=?",
                (execution_intent_id,),
            ).fetchone():
                raise ExecutionStateConflict("recovery proposal already exists")
            self._require_pending_recovery_capacity(conn)
            security = self._security_snapshot(conn)
            digest_fields = {
                "action_fingerprint": str(intent["action_fingerprint"]),
                "destination": str(intent["destination"]),
                "destination_class": str(intent["idempotency_class"]),
                "destination_contract_digest": str(intent["destination_config_digest"]),
                "destination_registry": str(intent["destination_registry"]),
                "execution_intent_id": execution_intent_id,
                "original_idempotency_key": intent["idempotency_key"],
                "original_operation_id": intent["destination_operation_id"],
                "policy_config_digest": policy_config_digest,
                "proposal_id": proposal_id,
                "query_evidence_id": query_evidence_id,
                "reconciliation_generation": int(reconciliation["generation"]),
                "reconciliation_id": str(reconciliation["reconciliation_id"]),
                "recovery_generation": 1,
                "security_configuration_digest": security[1],
                "security_configuration_epoch": security[0],
            }
            proposal_digest = hashlib.sha256(canonical_text(digest_fields).encode()).hexdigest()
            proposal = (
                self._base()
                | digest_fields
                | {
                    "mutation_sequence": seq,
                    "proposer_class": identity.identity_class,
                    "proposer_identity": identity.identity,
                    "proposal_digest": proposal_digest,
                }
            )
            records = (("execution_recovery_proposal", proposal_id, proposal),)
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_proposal(db, proposal, macs[(records[0][0], proposal_id)])

            return (
                self._payload("PROPOSE_RECOVERY", records, macs),
                apply,
                RecoveryProposalRecord(
                    proposal_id,
                    proposal_digest,
                    execution_intent_id,
                    str(reconciliation["reconciliation_id"]),
                    int(reconciliation["generation"]),
                    1,
                    query_evidence_id,
                    seq,
                ),
            )

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "PROPOSE_RECOVERY", build
        )

    def authorize_recovery(
        self,
        capability: RecoveryDecisionCapability,
        proposal_id: str,
        *,
        proposal_digest: str,
        destination_contract_digest: str,
        policy_config_digest: str,
        authorization_validator: Callable[[], bool] | None = None,
    ) -> RecoveryRecord:
        identity = self._validate_capability(capability)
        _require_digest(proposal_digest, "recovery proposal digest")
        _require_digest(destination_contract_digest, "destination contract digest")
        _require_digest(policy_config_digest, "policy configuration digest")
        authorization_id = _new_id("recovery-authorization")
        recovery_id = _new_id("recovery")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], RecoveryRecord]:
            self._require_audit_capacity(conn)
            proposal = _verified_recovery_row(
                self, conn, "execution_recovery_proposals", "proposal_id", proposal_id
            )
            if proposal["proposal_digest"] != proposal_digest:
                raise ExecutionBindingError("recovery proposal digest is stale")
            intent, _head, reconciliation = self._require_current_unknown(
                conn, str(proposal["execution_intent_id"]), destination_contract_digest
            )
            self._require_source_consumed(conn, intent)
            self._require_proposal_binding(
                conn, proposal, intent, reconciliation, policy_config_digest
            )
            if authorization_validator is not None and not authorization_validator():
                raise ExecutionBindingError("current recovery policy denied authorization")
            if conn.execute(
                "SELECT 1 FROM execution_recovery_heads WHERE execution_intent_id=?",
                (intent["intent_id"],),
            ).fetchone():
                raise ExecutionStateConflict("a recovery generation already exists")
            if MAX_RECOVERY_GENERATIONS_PER_INTENT < 1:
                raise ExecutionStateConflict("recovery generation bound is exhausted")
            authorization = self._base() | {
                "authorization_id": authorization_id,
                "authorizer_class": identity.identity_class,
                "authorizer_identity": identity.identity,
                "execution_intent_id": str(intent["intent_id"]),
                "mutation_sequence": seq,
                "proposal_digest": proposal_digest,
                "proposal_id": proposal_id,
                "reconciliation_generation": int(reconciliation["generation"]),
                "reconciliation_id": str(reconciliation["reconciliation_id"]),
                "recovery_generation": 1,
            }
            recovery = self._base() | {
                "action_fingerprint": str(intent["action_fingerprint"]),
                "attempt_id": None,
                "authorization_id": authorization_id,
                "boot_event_id": None,
                "claim_generation": 0,
                "claim_id": None,
                "creation_sequence": seq,
                "destination": str(intent["destination"]),
                "destination_class": str(intent["idempotency_class"]),
                "destination_contract_digest": str(intent["destination_config_digest"]),
                "destination_registry": str(intent["destination_registry"]),
                "dispatch_authorization_id": None,
                "execution_intent_id": str(intent["intent_id"]),
                "lease_deadline_ns": None,
                "original_idempotency_key": intent["idempotency_key"],
                "original_operation_id": intent["destination_operation_id"],
                "outcome_digest": None,
                "outcome_operation_id": None,
                "policy_config_digest": policy_config_digest,
                "proposal_id": proposal_id,
                "query_evidence_id": proposal["query_evidence_id"],
                "reconciliation_generation": int(reconciliation["generation"]),
                "reconciliation_id": str(reconciliation["reconciliation_id"]),
                "recovery_generation": 1,
                "recovery_id": recovery_id,
                "security_configuration_digest": proposal["security_configuration_digest"],
                "security_configuration_epoch": proposal["security_configuration_epoch"],
                "state": RecoveryState.READY.value,
                "updated_sequence": seq,
                "worker_id": None,
            }
            head = self._head(recovery, seq)
            lifecycle = self._lifecycle(recovery, "READY", seq)
            records = (
                ("execution_recovery_authorization", authorization_id, authorization),
                ("execution_recovery", recovery_id, recovery),
                ("execution_recovery_head", str(intent["intent_id"]), head),
                ("execution_recovery_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            )
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_authorization(
                    db, authorization, macs[(records[0][0], authorization_id)]
                )
                self._insert_recovery(db, recovery, macs[(records[1][0], recovery_id)])
                self._upsert_head(db, head, macs[(records[2][0], str(intent["intent_id"]))])
                self._insert_lifecycle(
                    db, lifecycle, macs[(records[3][0], str(lifecycle["lifecycle_id"]))]
                )

            return self._payload("AUTHORIZE_RECOVERY", records, macs), apply, self._record(recovery)

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "AUTHORIZE_RECOVERY", build
        )

    def claim_recovery(
        self, worker: WorkerHandle, recovery_id: str, *, lease_seconds: float = 30.0
    ) -> RecoveryClaimHandle:
        self.execution._validate_worker_handle(worker)
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int | float)
            or not math.isfinite(lease_seconds)
        ):
            raise ValueError("recovery lease must be finite")
        lease_ns = int(lease_seconds * 1_000_000_000)
        if lease_ns < 1 or lease_ns > MAX_RECOVERY_LEASE_NS:
            raise ValueError("recovery lease is outside configured bounds")
        now = time.monotonic_ns()
        claim_id, attempt_id, claim_capability = (
            _new_id("recovery-claim"),
            _new_id("recovery-attempt"),
            object(),
        )

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], RecoveryClaimHandle]:
            recovery = _verified_recovery_row(
                self, conn, "execution_recoveries", "recovery_id", recovery_id
            )
            self._require_live_recovery_binding(conn, recovery)
            worker_row = _verified_row(
                self.state, conn, "execution_workers", "worker_id", worker.worker_id
            )
            current_boot = self._current_boot_row(conn)
            if (
                worker_row["boot_event_id"] != worker.boot_event_id
                or current_boot["event_id"] != worker.boot_event_id
            ):
                raise ExecutionAuthorityError("recovery worker is not on the current boot")
            current_state = RecoveryState(str(recovery["state"]))
            reclaim = current_state is RecoveryState.CLAIMED and (
                recovery["boot_event_id"] != worker.boot_event_id
                or int(recovery["lease_deadline_ns"] or 0) <= now
            )
            if current_state is not RecoveryState.READY and not reclaim:
                raise ExecutionStateConflict("recovery is not safely claimable")
            self._require_lifecycle_capacity(conn, recovery_id)
            updated = self._updated(recovery, seq)
            updated.update(
                {
                    "attempt_id": attempt_id,
                    "boot_event_id": worker.boot_event_id,
                    "claim_generation": int(recovery["claim_generation"]) + 1,
                    "claim_id": claim_id,
                    "lease_deadline_ns": now + lease_ns,
                    "state": RecoveryState.CLAIMED.value,
                    "worker_id": worker.worker_id,
                }
            )
            lifecycle = self._lifecycle(updated, "RECLAIM" if reclaim else "CLAIM", seq)
            head = self._head(updated, seq)
            records = (
                ("execution_recovery", recovery_id, updated),
                ("execution_recovery_head", str(recovery["execution_intent_id"]), head),
                ("execution_recovery_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            )
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._update_recovery(db, updated, macs[(records[0][0], recovery_id)])
                self._upsert_head(
                    db, head, macs[(records[1][0], str(recovery["execution_intent_id"]))]
                )
                self._insert_lifecycle(
                    db, lifecycle, macs[(records[2][0], str(lifecycle["lifecycle_id"]))]
                )

            handle = RecoveryClaimHandle(
                _HANDLE_ISSUER,
                self,
                claim_capability,
                recovery_id=recovery_id,
                execution_intent_id=recovery["execution_intent_id"],
                recovery_generation=recovery["recovery_generation"],
                claim_generation=updated["claim_generation"],
                claim_id=claim_id,
                worker_id=worker.worker_id,
                boot_event_id=worker.boot_event_id,
                attempt_id=attempt_id,
            )
            return self._payload("CLAIM_RECOVERY", records, macs), apply, handle

        handle = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "CLAIM_RECOVERY", build
        )
        self._claim_capabilities[(recovery_id, handle.claim_generation)] = claim_capability
        return handle

    def begin_recovery_dispatch(
        self,
        claim: RecoveryClaimHandle,
        *,
        action: Mapping[str, Any] | str,
        destination_registry: str,
        destination: str,
        destination_contract_digest: str,
        policy_config_digest: str,
        authorization_validator: Callable[[], bool] | None = None,
    ) -> RecoveryDispatchHandle:
        self._validate_claim_handle(claim)
        _, _, fingerprint = normalize_action(action)
        _require_digest(destination_contract_digest, "destination contract digest")
        _require_digest(policy_config_digest, "policy configuration digest")
        dispatch_authorization_id = _new_id("recovery-dispatch")
        dispatch_capability = object()

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], RecoveryDispatchHandle]:
            self._require_audit_capacity(conn)
            recovery = _verified_recovery_row(
                self, conn, "execution_recoveries", "recovery_id", claim.recovery_id
            )
            self._require_current_claim(recovery, claim)
            self._require_live_recovery_binding(conn, recovery, require_latest_query=True)
            if (
                recovery["state"] != RecoveryState.CLAIMED.value
                or int(recovery["lease_deadline_ns"] or 0) <= time.monotonic_ns()
            ):
                raise ExecutionStateConflict("recovery claim is stale at dispatch fence")
            if self._current_boot_row(conn)["event_id"] != claim.boot_event_id:
                raise ExecutionAuthorityError("recovery claim belongs to an old runtime boot")
            if any(
                (
                    fingerprint != recovery["action_fingerprint"],
                    destination_registry != recovery["destination_registry"],
                    destination != recovery["destination"],
                    destination_contract_digest != recovery["destination_contract_digest"],
                    policy_config_digest != recovery["policy_config_digest"],
                )
            ):
                raise ExecutionBindingError("recovery dispatch binding changed")
            self._require_security_snapshot(conn, recovery)
            if authorization_validator is not None and not authorization_validator():
                raise ExecutionBindingError("current recovery dispatch policy denied execution")
            if recovery["dispatch_authorization_id"] is not None:
                raise ExecutionStateConflict("recovery dispatch was already authorized")
            self._require_lifecycle_capacity(conn, claim.recovery_id)
            updated = self._updated(recovery, seq)
            updated.update(
                {
                    "dispatch_authorization_id": dispatch_authorization_id,
                    "lease_deadline_ns": None,
                    "state": RecoveryState.DISPATCHING.value,
                }
            )
            lifecycle = self._lifecycle(updated, "DISPATCHING", seq)
            head = self._head(updated, seq)
            records = (
                ("execution_recovery", claim.recovery_id, updated),
                ("execution_recovery_head", claim.execution_intent_id, head),
                ("execution_recovery_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            )
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._update_recovery(db, updated, macs[(records[0][0], claim.recovery_id)])
                self._upsert_head(db, head, macs[(records[1][0], claim.execution_intent_id)])
                self._insert_lifecycle(
                    db, lifecycle, macs[(records[2][0], str(lifecycle["lifecycle_id"]))]
                )

            handle = RecoveryDispatchHandle(
                _HANDLE_ISSUER,
                self,
                dispatch_capability,
                recovery_id=claim.recovery_id,
                execution_intent_id=claim.execution_intent_id,
                recovery_generation=claim.recovery_generation,
                claim_generation=claim.claim_generation,
                claim_id=claim.claim_id,
                worker_id=claim.worker_id,
                boot_event_id=claim.boot_event_id,
                attempt_id=claim.attempt_id,
                dispatch_authorization_id=dispatch_authorization_id,
                action_fingerprint=fingerprint,
                destination_registry=destination_registry,
                destination=destination,
                destination_contract_digest=destination_contract_digest,
                destination_class=recovery["destination_class"],
                original_idempotency_key=recovery["original_idempotency_key"],
                original_operation_id=recovery["original_operation_id"],
            )
            return self._payload("BEGIN_RECOVERY_DISPATCH", records, macs), apply, handle

        handle = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "BEGIN_RECOVERY_DISPATCH", build
        )
        self._claim_capabilities[(claim.recovery_id, claim.claim_generation)] = dispatch_capability
        return handle

    def complete_recovery(
        self,
        dispatch: RecoveryDispatchHandle,
        *,
        result_digest: str,
        destination_operation_id: str,
    ) -> RecoveryRecord:
        _require_digest(result_digest, "recovery result digest")
        _bounded_identifier(destination_operation_id, "destination operation ID")
        return self._finish_recovery(
            dispatch,
            RecoveryState.COMPLETED,
            result_digest,
            destination_operation_id,
        )

    def fail_recovery_no_effect(
        self,
        host_capability: object,
        dispatch: RecoveryDispatchHandle,
        *,
        result_digest: str,
    ) -> RecoveryRecord:
        self._require_host(host_capability)
        _require_digest(result_digest, "recovery result digest")
        return self._finish_recovery(dispatch, RecoveryState.FAILED_NO_EFFECT, result_digest, None)

    def mark_recovery_outcome_unknown(
        self, dispatch: RecoveryDispatchHandle, *, destination_operation_id: str | None = None
    ) -> RecoveryRecord:
        if destination_operation_id is not None:
            _bounded_identifier(destination_operation_id, "destination operation ID")
        return self._finish_recovery(
            dispatch, RecoveryState.OUTCOME_UNKNOWN, None, destination_operation_id
        )

    def cancel_recovery(
        self, host_capability: object, recovery_id: str, *, reason_code: str
    ) -> RecoveryRecord:
        self._require_host(host_capability)
        _bounded_identifier(reason_code, "recovery cancellation reason")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], RecoveryRecord]:
            recovery = _verified_recovery_row(
                self, conn, "execution_recoveries", "recovery_id", recovery_id
            )
            if recovery["state"] not in {RecoveryState.READY.value, RecoveryState.CLAIMED.value}:
                raise ExecutionStateConflict("recovery cannot be cancelled after dispatch")
            self._require_lifecycle_capacity(conn, recovery_id)
            updated = self._updated(recovery, seq)
            updated.update(
                {
                    "lease_deadline_ns": None,
                    "outcome_digest": hashlib.sha256(reason_code.encode()).hexdigest(),
                    "state": RecoveryState.CANCELLED.value,
                }
            )
            lifecycle = self._lifecycle(updated, "CANCELLED", seq)
            head = self._head(updated, seq)
            records = (
                ("execution_recovery", recovery_id, updated),
                ("execution_recovery_head", str(recovery["execution_intent_id"]), head),
                ("execution_recovery_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            )
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._update_recovery(db, updated, macs[(records[0][0], recovery_id)])
                self._upsert_head(
                    db, head, macs[(records[1][0], str(recovery["execution_intent_id"]))]
                )
                self._insert_lifecycle(
                    db, lifecycle, macs[(records[2][0], str(lifecycle["lifecycle_id"]))]
                )

            return self._payload("CANCEL_RECOVERY", records, macs), apply, self._record(updated)

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "CANCEL_RECOVERY", build
        )

    def get_recovery(self, recovery_id: str) -> RecoveryRecord:
        def read() -> RecoveryRecord:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            return self._record(
                _verified_recovery_row(
                    self, conn, "execution_recoveries", "recovery_id", recovery_id
                )
            )

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def get_current_recovery(self, execution_intent_id: str) -> RecoveryRecord | None:
        """Return the authenticated current recovery lineage for host integration."""

        def read() -> RecoveryRecord | None:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            head = conn.execute(
                "SELECT current_recovery_id FROM execution_recovery_heads "
                "WHERE execution_intent_id=?",
                (execution_intent_id,),
            ).fetchone()
            if head is None:
                return None
            return self._record(
                _verified_recovery_row(
                    self,
                    conn,
                    "execution_recoveries",
                    "recovery_id",
                    str(head["current_recovery_id"]),
                )
            )

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def validate_recovery_dispatch_handle(self, handle: RecoveryDispatchHandle) -> RecoveryRecord:
        self._validate_claim_handle(handle)
        record = self.get_recovery(handle.recovery_id)
        if (
            record.state is not RecoveryState.DISPATCHING
            or record.execution_intent_id != handle.execution_intent_id
            or record.recovery_generation != handle.recovery_generation
            or record.claim_id != handle.claim_id
            or record.attempt_id != handle.attempt_id
            or record.dispatch_authorization_id != handle.dispatch_authorization_id
            or record.action_fingerprint != handle.action_fingerprint
            or record.destination_registry != handle.destination_registry
            or record.destination != handle.destination
            or record.destination_contract_digest != handle.destination_contract_digest
            or record.destination_class is not handle.destination_class
            or record.original_idempotency_key != handle.original_idempotency_key
            or record.original_operation_id != handle.original_operation_id
        ):
            raise ExecutionStateConflict("recovery dispatch handle is stale or replayed")
        return record

    def _finish_recovery(
        self,
        handle: RecoveryDispatchHandle,
        target: RecoveryState,
        result_digest: str | None,
        operation_id: str | None,
    ) -> RecoveryRecord:
        self._validate_claim_handle(handle)
        self.validate_recovery_dispatch_handle(handle)

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], RecoveryRecord]:
            recovery = _verified_recovery_row(
                self, conn, "execution_recoveries", "recovery_id", handle.recovery_id
            )
            self._require_current_claim(recovery, handle)
            if (
                recovery["state"] != RecoveryState.DISPATCHING.value
                or recovery["dispatch_authorization_id"] != handle.dispatch_authorization_id
            ):
                raise ExecutionStateConflict("recovery dispatch is no longer current")
            if (
                recovery["destination_class"] == IdempotencyClass.QUERYABLE_OPERATION_ID.value
                and operation_id != recovery["original_operation_id"]
            ):
                raise ExecutionBindingError(
                    "queryable recovery outcome changed the original operation ID"
                )
            self._require_lifecycle_capacity(conn, handle.recovery_id)
            updated = self._updated(recovery, seq)
            updated.update(
                {
                    "outcome_digest": result_digest,
                    "outcome_operation_id": operation_id,
                    "state": target.value,
                }
            )
            head = self._head(updated, seq)
            lifecycle = self._lifecycle(updated, target.value, seq)
            records: list[tuple[str, str, Mapping[str, Any]]] = [
                ("execution_recovery", handle.recovery_id, updated),
                ("execution_recovery_head", handle.execution_intent_id, head),
                ("execution_recovery_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            ]
            intent_update: dict[str, Any] | None = None
            barrier_update: dict[str, Any] | None = None
            workflow_update: dict[str, Any] | None = None
            execution_lifecycle: dict[str, Any] | None = None
            if target is RecoveryState.COMPLETED:
                intent = _verified_row(
                    self.state,
                    conn,
                    "execution_intents",
                    "intent_id",
                    handle.execution_intent_id,
                )
                if intent["state"] != ExecutionState.OUTCOME_UNKNOWN.value:
                    raise ExecutionStateConflict("canonical intent is no longer ambiguous")
                barrier_row = _verified_row(
                    self.state,
                    conn,
                    "execution_workflow_barriers",
                    "workflow_id",
                    str(intent["workflow_id"]),
                )
                if (
                    barrier_row["active_intent_id"] != intent["intent_id"]
                    or barrier_row["status"] != "BLOCKED_UNKNOWN"
                ):
                    raise WorkflowCASConflict("workflow is not eligible for recovery completion")
                intent_update = _logical(intent, "execution_intent")
                intent_update.update(
                    {
                        "completion_sequence": seq,
                        "destination_operation_id": operation_id,
                        "result_digest": result_digest,
                        "state": ExecutionState.COMPLETED.value,
                        "updated_sequence": seq,
                    }
                )
                barrier_update = self.execution._barrier_logical(
                    str(intent["workflow_id"]),
                    None,
                    "ACTIVE",
                    str(barrier_row["expected_head_event_id"]),
                    int(barrier_row["expected_revision"]),
                    seq,
                )
                workflow_row = _verified_workflow_row(self.state, conn, str(intent["workflow_id"]))
                workflow_update = _workflow_logical_from_row(workflow_row)
                workflow_update.update({"status": "ACTIVE", "updated_sequence": seq})
                execution_lifecycle = self.execution._lifecycle_logical(
                    str(intent["intent_id"]),
                    int(intent["claim_generation"]),
                    intent["active_claim_id"],
                    intent["worker_id"],
                    intent["boot_event_id"],
                    intent["attempt_id"],
                    "RECOVERY_COMPLETED",
                    operation_id,
                    result_digest,
                    {
                        "dispatch_authorization_id": handle.dispatch_authorization_id,
                        "reconciliation_id": str(recovery["reconciliation_id"]),
                        "recovery_generation": int(recovery["recovery_generation"]),
                        "recovery_id": handle.recovery_id,
                    },
                    seq,
                )
                records.extend(
                    [
                        ("execution_intent", handle.execution_intent_id, intent_update),
                        (
                            "execution_workflow_barrier",
                            str(intent["workflow_id"]),
                            barrier_update,
                        ),
                        ("workflow_state", str(intent["workflow_id"]), workflow_update),
                        (
                            "execution_lifecycle",
                            str(execution_lifecycle["lifecycle_id"]),
                            execution_lifecycle,
                        ),
                    ]
                )
            macs = self._macs(records)

            def apply(db: sqlite3.Connection) -> None:
                self._update_recovery(db, updated, macs[("execution_recovery", handle.recovery_id)])
                self._upsert_head(
                    db, head, macs[("execution_recovery_head", handle.execution_intent_id)]
                )
                self._insert_lifecycle(
                    db,
                    lifecycle,
                    macs[("execution_recovery_lifecycle", str(lifecycle["lifecycle_id"]))],
                )
                if (
                    intent_update is not None
                    and barrier_update is not None
                    and workflow_update is not None
                    and execution_lifecycle is not None
                ):
                    workflow_id = str(intent_update["workflow_id"])
                    self.execution._update_intent(
                        db,
                        intent_update,
                        macs[("execution_intent", handle.execution_intent_id)],
                    )
                    self.execution._upsert_barrier(
                        db,
                        barrier_update,
                        macs[("execution_workflow_barrier", workflow_id)],
                    )
                    db.execute(
                        "UPDATE workflow_state SET status=?, updated_sequence=?, key_id=?, "
                        "record_mac=? WHERE workflow_id=?",
                        (
                            "ACTIVE",
                            seq,
                            self.state.key_id,
                            macs[("workflow_state", workflow_id)],
                            workflow_id,
                        ),
                    )
                    self.execution._insert_lifecycle(
                        db,
                        execution_lifecycle,
                        macs[
                            (
                                "execution_lifecycle",
                                str(execution_lifecycle["lifecycle_id"]),
                            )
                        ],
                    )

            return (
                self._payload("RECOVERY_" + target.value, records, macs),
                apply,
                self._record(updated),
            )

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "RECOVERY_" + target.value, build
        )

    def _query_target(
        self, execution_intent_id: str, adapter: DestinationStatusAdapter
    ) -> dict[str, Any]:
        _bounded_identifier(execution_intent_id, "execution intent ID")
        self._require_registered_adapter(adapter)
        for value, label in (
            (adapter.adapter_identity, "query adapter identity"),
            (adapter.adapter_version, "query adapter version"),
            (adapter.destination_registry, "query destination registry"),
            (adapter.destination, "query destination"),
        ):
            _bounded_identifier(value, label)
        _require_digest(adapter.destination_contract_digest, "query destination contract digest")

        def read() -> dict[str, Any]:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            intent, _head, reconciliation = self._require_current_unknown(
                conn,
                execution_intent_id,
                adapter.destination_contract_digest,
                allow_abandoned=True,
            )
            self._require_query_adapter_binding(intent, adapter)
            if intent["idempotency_class"] != IdempotencyClass.QUERYABLE_OPERATION_ID.value:
                raise ExecutionAuthorityError("destination class has no query authority")
            if intent["destination_operation_id"] is None:
                raise ExecutionBindingError("queryable intent lacks its original operation ID")
            security = self._security_snapshot(conn)
            return {
                "destination_contract_digest": str(intent["destination_config_digest"]),
                "original_operation_id": str(intent["destination_operation_id"]),
                "reconciliation_id": str(reconciliation["reconciliation_id"]),
                "security_configuration_digest": security[1],
                "security_configuration_epoch": security[0],
            }

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def _require_current_unknown(
        self,
        conn: sqlite3.Connection,
        execution_intent_id: str,
        destination_contract_digest: str,
        *,
        allow_abandoned: bool = False,
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        intent = _verified_row(
            self.state, conn, "execution_intents", "intent_id", execution_intent_id
        )
        if intent["state"] != ExecutionState.OUTCOME_UNKNOWN.value:
            raise ExecutionStateConflict("recovery requires an OUTCOME_UNKNOWN intent")
        if intent["destination_config_digest"] != destination_contract_digest:
            raise ExecutionBindingError("destination contract differs from original intent")
        head = _verified_reconciliation_row(
            self.reconciliation,
            conn,
            "execution_reconciliation_heads",
            "intent_id",
            execution_intent_id,
        )
        reconciliation = _verified_reconciliation_row(
            self.reconciliation,
            conn,
            "execution_reconciliations",
            "reconciliation_id",
            str(head["current_reconciliation_id"]),
        )
        if (
            reconciliation["intent_id"] != execution_intent_id
            or int(reconciliation["generation"]) != int(head["current_generation"])
            or reconciliation["ambiguous_attempt_id"] != intent["attempt_id"]
            or reconciliation["action_fingerprint"] != intent["action_fingerprint"]
            or reconciliation["destination"] != intent["destination"]
            or reconciliation["destination_contract_digest"] != intent["destination_config_digest"]
        ):
            raise ExecutionBindingError("recovery reconciliation lineage is stale")
        disposition = ReconciliationDisposition(str(head["disposition"]))
        allowed = {
            ReconciliationDisposition.ACTIVE,
            ReconciliationDisposition.INSUFFICIENT,
        }
        if allow_abandoned:
            allowed.add(ReconciliationDisposition.ABANDONED)
        if disposition not in allowed:
            raise ExecutionStateConflict("current reconciliation does not permit this operation")
        barrier = _verified_row(
            self.state,
            conn,
            "execution_workflow_barriers",
            "workflow_id",
            str(intent["workflow_id"]),
        )
        allowed_barriers = {"BLOCKED_UNKNOWN"}
        if allow_abandoned:
            allowed_barriers.add("BLOCKED_UNKNOWN_ABANDONED")
        if (
            barrier["active_intent_id"] != execution_intent_id
            or barrier["status"] not in allowed_barriers
        ):
            raise WorkflowCASConflict("recovery workflow barrier is not current")
        return intent, head, reconciliation

    def _require_recovery_eligible(
        self,
        conn: sqlite3.Connection,
        intent: sqlite3.Row,
        reconciliation: sqlite3.Row,
        query_evidence_id: str | None,
    ) -> None:
        destination_class = IdempotencyClass(str(intent["idempotency_class"]))
        if destination_class is IdempotencyClass.NO_IDEMPOTENCY:
            raise ExecutionAuthorityError("NO_IDEMPOTENCY cannot authorize recovery dispatch")
        if destination_class is IdempotencyClass.TRANSACTIONALLY_LOCAL:
            raise ExecutionAuthorityError("c3b has no transactionally-local recovery destination")
        if self._has_authoritative_completion(conn, str(intent["intent_id"])):
            raise ExecutionStateConflict("authoritative evidence already indicates completion")
        if destination_class is IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY:
            if intent["idempotency_key"] is None or query_evidence_id is not None:
                raise ExecutionBindingError("idempotency-key recovery binding is invalid")
            return
        if intent["destination_operation_id"] is None or query_evidence_id is None:
            raise ExecutionBindingError("queryable recovery requires original operation evidence")
        try:
            evidence = _verified_recovery_row(
                self,
                conn,
                "execution_query_evidence",
                "query_evidence_id",
                query_evidence_id,
            )
        except UnknownAuthorityRecord as exc:
            raise ExecutionBindingError(
                "query evidence does not belong to this authority store"
            ) from exc
        latest = conn.execute(
            "SELECT query_evidence_id FROM execution_query_evidence "
            "WHERE execution_intent_id=? ORDER BY mutation_sequence DESC LIMIT 1",
            (intent["intent_id"],),
        ).fetchone()
        if (
            latest is None
            or latest[0] != query_evidence_id
            or evidence["normalized_result"] != DestinationQueryResult.NO_EFFECT_CONFIRMED.value
            or evidence["execution_intent_id"] != intent["intent_id"]
            or evidence["reconciliation_id"] != reconciliation["reconciliation_id"]
            or int(evidence["reconciliation_generation"]) != int(reconciliation["generation"])
            or evidence["action_fingerprint"] != intent["action_fingerprint"]
            or evidence["destination_registry"] != intent["destination_registry"]
            or evidence["destination"] != intent["destination"]
            or evidence["destination_contract_digest"] != intent["destination_config_digest"]
            or evidence["original_operation_id"] != intent["destination_operation_id"]
        ):
            raise ExecutionBindingError("query evidence is stale, nonportable, or unsafe")
        self._require_security_snapshot(conn, evidence)

    def _require_proposal_binding(
        self,
        conn: sqlite3.Connection,
        proposal: sqlite3.Row,
        intent: sqlite3.Row,
        reconciliation: sqlite3.Row,
        policy_config_digest: str,
    ) -> None:
        fields = (
            (proposal["execution_intent_id"], intent["intent_id"]),
            (proposal["reconciliation_id"], reconciliation["reconciliation_id"]),
            (int(proposal["reconciliation_generation"]), int(reconciliation["generation"])),
            (int(proposal["recovery_generation"]), 1),
            (proposal["action_fingerprint"], intent["action_fingerprint"]),
            (proposal["destination_registry"], intent["destination_registry"]),
            (proposal["destination"], intent["destination"]),
            (proposal["destination_contract_digest"], intent["destination_config_digest"]),
            (proposal["destination_class"], intent["idempotency_class"]),
            (proposal["original_idempotency_key"], intent["idempotency_key"]),
            (proposal["original_operation_id"], intent["destination_operation_id"]),
            (proposal["policy_config_digest"], policy_config_digest),
            (intent["policy_config_digest"], policy_config_digest),
        )
        if any(left != right for left, right in fields):
            raise ExecutionBindingError("recovery proposal binding is stale")
        self._require_recovery_eligible(conn, intent, reconciliation, proposal["query_evidence_id"])
        self._require_security_snapshot(conn, proposal)

    def _require_live_recovery_binding(
        self,
        conn: sqlite3.Connection,
        recovery: sqlite3.Row,
        *,
        require_latest_query: bool = False,
    ) -> None:
        intent, head, reconciliation = self._require_current_unknown(
            conn,
            str(recovery["execution_intent_id"]),
            str(recovery["destination_contract_digest"]),
        )
        self._require_source_consumed(conn, intent)
        if any(
            (
                recovery["reconciliation_id"] != reconciliation["reconciliation_id"],
                int(recovery["reconciliation_generation"]) != int(head["current_generation"]),
                recovery["action_fingerprint"] != intent["action_fingerprint"],
                recovery["destination_registry"] != intent["destination_registry"],
                recovery["destination"] != intent["destination"],
                recovery["destination_contract_digest"] != intent["destination_config_digest"],
                recovery["destination_class"] != intent["idempotency_class"],
                recovery["original_idempotency_key"] != intent["idempotency_key"],
                recovery["original_operation_id"] != intent["destination_operation_id"],
                recovery["policy_config_digest"] != intent["policy_config_digest"],
            )
        ):
            raise ExecutionBindingError("recovery lineage no longer matches canonical intent")
        if self._has_authoritative_completion(conn, str(intent["intent_id"])):
            raise ExecutionStateConflict("completion evidence conflicts with recovery")
        if (
            require_latest_query
            and recovery["destination_class"] == IdempotencyClass.QUERYABLE_OPERATION_ID.value
        ):
            self._require_recovery_eligible(
                conn, intent, reconciliation, recovery["query_evidence_id"]
            )
        self._require_security_snapshot(conn, recovery)

    def _require_source_consumed(self, conn: sqlite3.Connection, intent: sqlite3.Row) -> None:
        row = conn.execute(
            "SELECT * FROM consumptions WHERE instance_id=? AND token_kind='model_output' "
            "AND token_id=?",
            (self.state.instance_id, intent["source_output_event_id"]),
        ).fetchone()
        if row is None:
            raise ExecutionBindingError("recovery source is not consumed")
        logical = _consumption_logical_from_row(row)
        if not self.state._verify_execution_record_mac(
            _EXECUTION_EXTENSION_CAPABILITY, "consumption", logical, str(row["record_mac"])
        ):
            raise StateAuthenticationError("recovery source consumption MAC is invalid")

    @staticmethod
    def _has_authoritative_completion(conn: sqlite3.Connection, intent_id: str) -> bool:
        return (
            conn.execute(
                "SELECT 1 FROM execution_reconciliation_evidence WHERE intent_id=? "
                "AND evidence_category IN (?,?) LIMIT 1",
                (
                    intent_id,
                    ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED.value,
                    ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED.value,
                ),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _require_query_adapter_binding(
        intent: sqlite3.Row, adapter: DestinationStatusAdapter
    ) -> None:
        if (
            adapter.destination_registry != intent["destination_registry"]
            or adapter.destination != intent["destination"]
            or adapter.destination_contract_digest != intent["destination_config_digest"]
        ):
            raise ExecutionBindingError("query adapter target differs from canonical intent")

    def _require_registered_adapter(self, adapter: DestinationStatusAdapter) -> None:
        binding = self._adapter_bindings.get(id(adapter))
        if (
            binding is None
            or binding.adapter is not adapter
            or binding.authority is not self
            or binding.pid != os.getpid()
            or binding.thread_id != threading.get_ident()
            or binding.adapter_identity != adapter.adapter_identity
            or binding.adapter_version != adapter.adapter_version
            or binding.destination_registry != adapter.destination_registry
            or binding.destination != adapter.destination
            or binding.destination_contract_digest != adapter.destination_contract_digest
        ):
            raise ExecutionAuthorityError("query adapter is unregistered, mutated, or stale")

    @staticmethod
    def _security_snapshot(conn: sqlite3.Connection) -> tuple[int | None, str | None]:
        row = conn.execute(
            "SELECT epoch,configuration_digest FROM execution_security_configuration "
            "WHERE singleton=1"
        ).fetchone()
        return (None, None) if row is None else (int(row[0]), str(row[1]))

    def _require_security_snapshot(self, conn: sqlite3.Connection, bound: Any) -> None:
        if self._security_snapshot(conn) != (
            None
            if bound["security_configuration_epoch"] is None
            else int(bound["security_configuration_epoch"]),
            None
            if bound["security_configuration_digest"] is None
            else str(bound["security_configuration_digest"]),
        ):
            raise ExecutionBindingError("security configuration changed during recovery")

    def _validate_capability(
        self, capability: _RecoveryCapability, *, query: bool = False
    ) -> _CapabilityBinding:
        expected_type = QueryAuthorityCapability if query else RecoveryDecisionCapability
        registry = self._query_capabilities if query else self._decision_capabilities
        if not isinstance(capability, expected_type):
            raise ExecutionAuthorityError("required recovery capability is absent")
        binding = registry.get(id(capability))
        if (
            binding is None
            or binding.authority is not self
            or capability._authority is not self
            or capability._capability is not binding.token
            or capability._pid != binding.pid
            or capability._thread_id != binding.thread_id
            or binding.pid != os.getpid()
            or binding.thread_id != threading.get_ident()
            or capability.boot_event_id != binding.boot_event_id
            or capability.identity != binding.identity
            or capability.identity_class != binding.identity_class
            or binding.boot_event_id != self._current_boot()
        ):
            raise ExecutionAuthorityError("recovery capability binding is invalid or stale")
        return binding

    def _issue_capability(
        self,
        capability_type: type[QueryAuthorityCapability] | type[RecoveryDecisionCapability],
        registry: dict[int, _CapabilityBinding],
        identity: str,
        identity_class: str,
    ) -> QueryAuthorityCapability | RecoveryDecisionCapability:
        _bounded_identifier(identity, "recovery identity")
        _bounded_identifier(identity_class, "recovery identity class")
        token = object()
        boot = self._current_boot()
        result = capability_type(
            _CAPABILITY_ISSUER,
            self,
            token,
            boot_event_id=boot,
            identity=identity,
            identity_class=identity_class,
        )
        registry[id(result)] = _CapabilityBinding(
            token,
            self,
            os.getpid(),
            threading.get_ident(),
            boot,
            identity,
            identity_class,
        )
        return result

    def _validate_claim_handle(self, handle: RecoveryClaimHandle) -> None:
        if not isinstance(handle, RecoveryClaimHandle):
            raise ExecutionAuthorityError("a recovery claim handle is required")
        expected = self._claim_capabilities.get((handle.recovery_id, handle.claim_generation))
        if (
            expected is None
            or handle._authority is not self
            or handle._capability is not expected
            or handle._pid != os.getpid()
            or handle._thread_id != threading.get_ident()
        ):
            raise ExecutionAuthorityError("recovery claim capability is invalid or stale")

    @staticmethod
    def _require_current_claim(recovery: sqlite3.Row, handle: RecoveryClaimHandle) -> None:
        if (
            recovery["recovery_id"] != handle.recovery_id
            or recovery["execution_intent_id"] != handle.execution_intent_id
            or int(recovery["recovery_generation"]) != handle.recovery_generation
            or int(recovery["claim_generation"]) != handle.claim_generation
            or recovery["claim_id"] != handle.claim_id
            or recovery["worker_id"] != handle.worker_id
            or recovery["boot_event_id"] != handle.boot_event_id
            or recovery["attempt_id"] != handle.attempt_id
        ):
            raise ExecutionStateConflict("recovery claim is stale")

    def _current_boot(self) -> str:
        def read() -> str:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            return str(self._current_boot_row(conn)["event_id"])

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    @staticmethod
    def _current_boot_row(conn: sqlite3.Connection) -> sqlite3.Row:
        row = conn.execute(
            "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
            "ORDER BY creation_sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ExecutionAuthorityError("recovery authority requires a runtime boot event")
        return row

    @staticmethod
    def _require_host(capability: object) -> None:
        if capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("operation requires host execution authority")

    @staticmethod
    def _require_audit_capacity(conn: sqlite3.Connection) -> None:
        pending = int(
            conn.execute(
                "SELECT COUNT(*) FROM audit_outbox WHERE exported_unix_ns IS NULL"
            ).fetchone()[0]
        )
        if pending >= MAX_PENDING_AUDIT:
            raise ExecutionStateConflict("audit outbox bound is exhausted")

    @staticmethod
    def _require_pending_recovery_capacity(conn: sqlite3.Connection) -> None:
        pending = int(
            conn.execute(
                "SELECT COUNT(*) FROM execution_recoveries "
                "WHERE state IN ('READY','CLAIMED','DISPATCHING')"
            ).fetchone()[0]
        )
        pending += int(
            conn.execute(
                "SELECT COUNT(*) FROM execution_recovery_proposals p "
                "LEFT JOIN execution_recovery_authorizations a "
                "ON a.proposal_id=p.proposal_id WHERE a.authorization_id IS NULL"
            ).fetchone()[0]
        )
        if pending >= MAX_PENDING_RECOVERIES:
            raise ExecutionStateConflict("pending recovery bound is exhausted")

    @staticmethod
    def _require_lifecycle_capacity(conn: sqlite3.Connection, recovery_id: str) -> None:
        count = int(
            conn.execute(
                "SELECT COUNT(*) FROM execution_recovery_lifecycle WHERE recovery_id=?",
                (recovery_id,),
            ).fetchone()[0]
        )
        if count >= MAX_RECOVERY_LIFECYCLE_PER_INTENT:
            raise ExecutionStateConflict("recovery lifecycle bound is exhausted")

    def _base(self) -> dict[str, Any]:
        return {
            "deployment_id": self.state.deployment_id,
            "instance_id": self.state.instance_id,
            "key_id": self.state.key_id,
            "schema_version": SCHEMA_VERSION,
        }

    def _head(self, recovery: Mapping[str, Any], seq: int) -> dict[str, Any]:
        return self._base() | {
            "current_generation": int(recovery["recovery_generation"]),
            "current_recovery_id": str(recovery["recovery_id"]),
            "execution_intent_id": str(recovery["execution_intent_id"]),
            "state": str(recovery["state"]),
            "updated_sequence": seq,
        }

    def _lifecycle(self, recovery: Mapping[str, Any], transition: str, seq: int) -> dict[str, Any]:
        return self._base() | {
            "attempt_id": recovery["attempt_id"],
            "boot_event_id": recovery["boot_event_id"],
            "claim_generation": int(recovery["claim_generation"]),
            "claim_id": recovery["claim_id"],
            "dispatch_authorization_id": recovery["dispatch_authorization_id"],
            "execution_intent_id": str(recovery["execution_intent_id"]),
            "lifecycle_id": _new_id("recovery-lifecycle"),
            "mutation_sequence": seq,
            "outcome_digest": recovery["outcome_digest"],
            "outcome_operation_id": recovery["outcome_operation_id"],
            "recovery_generation": int(recovery["recovery_generation"]),
            "recovery_id": str(recovery["recovery_id"]),
            "state": str(recovery["state"]),
            "transition": transition,
            "worker_id": recovery["worker_id"],
        }

    @staticmethod
    def _updated(row: sqlite3.Row, seq: int) -> dict[str, Any]:
        logical = dict(row)
        logical.pop("record_mac", None)
        logical["updated_sequence"] = seq
        return logical

    @staticmethod
    def _payload(
        operation: str,
        records: tuple[tuple[str, str, Mapping[str, Any]], ...]
        | list[tuple[str, str, Mapping[str, Any]]],
        macs: Mapping[tuple[str, str], str],
    ) -> dict[str, Any]:
        return {
            "changes": [
                _change(kind, identifier, macs[(kind, identifier)])
                for kind, identifier, _ in records
            ],
            "operation": operation,
        }

    def _macs(
        self,
        records: tuple[tuple[str, str, Mapping[str, Any]], ...]
        | list[tuple[str, str, Mapping[str, Any]]],
    ) -> dict[tuple[str, str], str]:
        return {
            (kind, identifier): _mac(self.state, kind, value) for kind, identifier, value in records
        }

    @staticmethod
    def _record(v: Any) -> RecoveryRecord:
        return RecoveryRecord(
            str(v["recovery_id"]),
            str(v["execution_intent_id"]),
            str(v["reconciliation_id"]),
            int(v["reconciliation_generation"]),
            int(v["recovery_generation"]),
            IdempotencyClass(str(v["destination_class"])),
            str(v["action_fingerprint"]),
            str(v["destination_registry"]),
            str(v["destination"]),
            str(v["destination_contract_digest"]),
            None if v["original_idempotency_key"] is None else str(v["original_idempotency_key"]),
            None if v["original_operation_id"] is None else str(v["original_operation_id"]),
            str(v["policy_config_digest"]),
            RecoveryState(str(v["state"])),
            int(v["claim_generation"]),
            None if v["claim_id"] is None else str(v["claim_id"]),
            None if v["worker_id"] is None else str(v["worker_id"]),
            None if v["boot_event_id"] is None else str(v["boot_event_id"]),
            None if v["attempt_id"] is None else str(v["attempt_id"]),
            None if v["dispatch_authorization_id"] is None else str(v["dispatch_authorization_id"]),
            None if v["outcome_operation_id"] is None else str(v["outcome_operation_id"]),
            None if v["outcome_digest"] is None else str(v["outcome_digest"]),
            int(v["updated_sequence"]),
        )

    @staticmethod
    def _insert_query_authorization(
        conn: sqlite3.Connection, v: Mapping[str, Any], mac: str
    ) -> None:
        conn.execute(
            "INSERT INTO execution_query_authorizations VALUES("
            + ",".join("?" for _ in range(24))
            + ")",
            tuple(
                v[k]
                for k in (
                    "query_authorization_id",
                    "instance_id",
                    "deployment_id",
                    "schema_version",
                    "execution_intent_id",
                    "ambiguous_attempt_id",
                    "reconciliation_id",
                    "reconciliation_generation",
                    "recovery_generation",
                    "action_fingerprint",
                    "destination_registry",
                    "destination",
                    "destination_contract_digest",
                    "original_operation_id",
                    "adapter_identity",
                    "adapter_version",
                    "security_configuration_epoch",
                    "security_configuration_digest",
                    "querier_identity",
                    "querier_class",
                    "query_unix_ns",
                    "mutation_sequence",
                    "key_id",
                )
            )
            + (mac,),
        )

    @staticmethod
    def _insert_query_evidence(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "query_evidence_id",
            "query_authorization_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "execution_intent_id",
            "ambiguous_attempt_id",
            "reconciliation_id",
            "reconciliation_generation",
            "recovery_generation",
            "action_fingerprint",
            "destination_registry",
            "destination",
            "destination_contract_digest",
            "original_operation_id",
            "adapter_identity",
            "adapter_version",
            "security_configuration_epoch",
            "security_configuration_digest",
            "normalized_result",
            "observation_digest",
            "evidence_digest",
            "previous_query_evidence_id",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_query_evidence VALUES("
            + ",".join("?" for _ in range(len(keys) + 1))
            + ")",
            tuple(v[k] for k in keys) + (mac,),
        )

    @staticmethod
    def _insert_proposal(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "proposal_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "execution_intent_id",
            "reconciliation_id",
            "reconciliation_generation",
            "recovery_generation",
            "query_evidence_id",
            "action_fingerprint",
            "destination_registry",
            "destination",
            "destination_contract_digest",
            "destination_class",
            "original_idempotency_key",
            "original_operation_id",
            "policy_config_digest",
            "security_configuration_epoch",
            "security_configuration_digest",
            "proposer_identity",
            "proposer_class",
            "proposal_digest",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_recovery_proposals VALUES("
            + ",".join("?" for _ in range(len(keys) + 1))
            + ")",
            tuple(v[k] for k in keys) + (mac,),
        )

    @staticmethod
    def _insert_authorization(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "authorization_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "proposal_id",
            "proposal_digest",
            "execution_intent_id",
            "reconciliation_id",
            "reconciliation_generation",
            "recovery_generation",
            "authorizer_identity",
            "authorizer_class",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_recovery_authorizations VALUES("
            + ",".join("?" for _ in range(len(keys) + 1))
            + ")",
            tuple(v[k] for k in keys) + (mac,),
        )

    @staticmethod
    def _insert_recovery(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "recovery_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "execution_intent_id",
            "reconciliation_id",
            "reconciliation_generation",
            "recovery_generation",
            "proposal_id",
            "authorization_id",
            "query_evidence_id",
            "action_fingerprint",
            "destination_registry",
            "destination",
            "destination_contract_digest",
            "destination_class",
            "original_idempotency_key",
            "original_operation_id",
            "policy_config_digest",
            "security_configuration_epoch",
            "security_configuration_digest",
            "state",
            "claim_generation",
            "claim_id",
            "worker_id",
            "boot_event_id",
            "attempt_id",
            "lease_deadline_ns",
            "dispatch_authorization_id",
            "outcome_operation_id",
            "outcome_digest",
            "creation_sequence",
            "updated_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_recoveries VALUES("
            + ",".join("?" for _ in range(len(keys) + 1))
            + ")",
            tuple(v[k] for k in keys) + (mac,),
        )

    @staticmethod
    def _update_recovery(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            """UPDATE execution_recoveries SET state=?,claim_generation=?,claim_id=?,worker_id=?,
            boot_event_id=?,attempt_id=?,lease_deadline_ns=?,dispatch_authorization_id=?,
            outcome_operation_id=?,outcome_digest=?,updated_sequence=?,record_mac=?
            WHERE recovery_id=?""",
            (
                v["state"],
                v["claim_generation"],
                v["claim_id"],
                v["worker_id"],
                v["boot_event_id"],
                v["attempt_id"],
                v["lease_deadline_ns"],
                v["dispatch_authorization_id"],
                v["outcome_operation_id"],
                v["outcome_digest"],
                v["updated_sequence"],
                mac,
                v["recovery_id"],
            ),
        )

    @staticmethod
    def _upsert_head(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            """INSERT INTO execution_recovery_heads VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(execution_intent_id) DO UPDATE SET
            current_recovery_id=excluded.current_recovery_id,
            current_generation=excluded.current_generation,state=excluded.state,
            updated_sequence=excluded.updated_sequence,key_id=excluded.key_id,
            record_mac=excluded.record_mac""",
            (
                v["execution_intent_id"],
                v["instance_id"],
                v["deployment_id"],
                v["schema_version"],
                v["current_recovery_id"],
                v["current_generation"],
                v["state"],
                v["updated_sequence"],
                v["key_id"],
                mac,
            ),
        )

    @staticmethod
    def _insert_lifecycle(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "lifecycle_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "recovery_id",
            "execution_intent_id",
            "recovery_generation",
            "claim_generation",
            "transition",
            "state",
            "claim_id",
            "worker_id",
            "boot_event_id",
            "attempt_id",
            "dispatch_authorization_id",
            "outcome_operation_id",
            "outcome_digest",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_recovery_lifecycle VALUES("
            + ",".join("?" for _ in range(len(keys) + 1))
            + ")",
            tuple(v[k] for k in keys) + (mac,),
        )


def verify_recovery_materialized(
    authority_state: Any,
    connection: sqlite3.Connection,
    expected: dict[str, dict[str, str]],
) -> None:
    extension = connection.execute(
        "SELECT schema_version FROM execution_recovery_extensions WHERE singleton=1"
    ).fetchone()
    if extension is None or extension[0] != RECOVERY_SCHEMA_VERSION:
        raise StateVerificationError("recovery extension marker is invalid")
    execution = ExecutionAuthority.__new__(ExecutionAuthority)
    execution.state = authority_state
    execution._worker_capabilities = {}
    execution._claim_capabilities = {}
    authority = RecoveryAuthority(execution)
    specs = (
        (
            "execution_query_authorization",
            "execution_query_authorizations",
            "query_authorization_id",
        ),
        ("execution_query_evidence", "execution_query_evidence", "query_evidence_id"),
        ("execution_recovery_proposal", "execution_recovery_proposals", "proposal_id"),
        (
            "execution_recovery_authorization",
            "execution_recovery_authorizations",
            "authorization_id",
        ),
        ("execution_recovery_head", "execution_recovery_heads", "execution_intent_id"),
        ("execution_recovery", "execution_recoveries", "recovery_id"),
        ("execution_recovery_lifecycle", "execution_recovery_lifecycle", "lifecycle_id"),
    )
    for kind, table, key in specs:
        actual: dict[str, str] = {}
        for row in connection.execute(f"SELECT * FROM {table}"):
            _verified_recovery_row(authority, connection, table, key, str(row[key]))
            actual[str(row[key])] = str(row["record_mac"])
        if actual != expected[kind]:
            raise StateVerificationError(f"{kind} materialized state mismatch")
    for head in connection.execute("SELECT * FROM execution_recovery_heads"):
        recovery = connection.execute(
            "SELECT * FROM execution_recoveries WHERE recovery_id=?",
            (head["current_recovery_id"],),
        ).fetchone()
        if recovery is None or any(
            (
                head["execution_intent_id"] != recovery["execution_intent_id"],
                int(head["current_generation"]) != int(recovery["recovery_generation"]),
                head["state"] != recovery["state"],
            )
        ):
            raise StateVerificationError("recovery head disagrees with materialized recovery")
        count = int(
            connection.execute(
                "SELECT COUNT(*) FROM execution_recoveries WHERE execution_intent_id=?",
                (head["execution_intent_id"],),
            ).fetchone()[0]
        )
        if count > MAX_RECOVERY_GENERATIONS_PER_INTENT:
            raise StateVerificationError("recovery generation bound is exceeded")
    for recovery in connection.execute("SELECT * FROM execution_recoveries"):
        intent = connection.execute(
            "SELECT * FROM execution_intents WHERE intent_id=?",
            (recovery["execution_intent_id"],),
        ).fetchone()
        reconciliation = connection.execute(
            "SELECT * FROM execution_reconciliations WHERE reconciliation_id=?",
            (recovery["reconciliation_id"],),
        ).fetchone()
        proposal = connection.execute(
            "SELECT * FROM execution_recovery_proposals WHERE proposal_id=?",
            (recovery["proposal_id"],),
        ).fetchone()
        authorization = connection.execute(
            "SELECT * FROM execution_recovery_authorizations WHERE authorization_id=?",
            (recovery["authorization_id"],),
        ).fetchone()
        if intent is None or reconciliation is None or proposal is None or authorization is None:
            raise StateVerificationError("recovery authoritative lineage is incomplete")
        consumption = connection.execute(
            "SELECT 1 FROM consumptions WHERE instance_id=? AND token_kind='model_output' "
            "AND token_id=?",
            (authority_state.instance_id, intent["source_output_event_id"]),
        ).fetchone()
        if consumption is None:
            raise StateVerificationError("recovery parent source is not consumed")
        binding_fields = (
            (recovery["execution_intent_id"], intent["intent_id"]),
            (recovery["reconciliation_id"], reconciliation["reconciliation_id"]),
            (int(recovery["reconciliation_generation"]), int(reconciliation["generation"])),
            (recovery["action_fingerprint"], intent["action_fingerprint"]),
            (recovery["destination_registry"], intent["destination_registry"]),
            (recovery["destination"], intent["destination"]),
            (recovery["destination_contract_digest"], intent["destination_config_digest"]),
            (recovery["destination_class"], intent["idempotency_class"]),
            (recovery["original_idempotency_key"], intent["idempotency_key"]),
            (recovery["policy_config_digest"], intent["policy_config_digest"]),
            (recovery["proposal_id"], authorization["proposal_id"]),
            (recovery["execution_intent_id"], proposal["execution_intent_id"]),
            (recovery["reconciliation_id"], proposal["reconciliation_id"]),
            (
                int(recovery["reconciliation_generation"]),
                int(proposal["reconciliation_generation"]),
            ),
            (int(recovery["recovery_generation"]), int(proposal["recovery_generation"])),
            (recovery["query_evidence_id"], proposal["query_evidence_id"]),
            (recovery["action_fingerprint"], proposal["action_fingerprint"]),
            (recovery["destination_registry"], proposal["destination_registry"]),
            (recovery["destination"], proposal["destination"]),
            (
                recovery["destination_contract_digest"],
                proposal["destination_contract_digest"],
            ),
            (recovery["destination_class"], proposal["destination_class"]),
            (recovery["original_idempotency_key"], proposal["original_idempotency_key"]),
            (recovery["original_operation_id"], proposal["original_operation_id"]),
            (recovery["policy_config_digest"], proposal["policy_config_digest"]),
            (
                recovery["security_configuration_epoch"],
                proposal["security_configuration_epoch"],
            ),
            (
                recovery["security_configuration_digest"],
                proposal["security_configuration_digest"],
            ),
        )
        if any(left != right for left, right in binding_fields):
            raise StateVerificationError("recovery binding contradicts authenticated lineage")
        if recovery["state"] == RecoveryState.COMPLETED.value:
            if intent["destination_operation_id"] != recovery["outcome_operation_id"]:
                raise StateVerificationError("recovery completion operation is inconsistent")
        elif recovery["original_operation_id"] != intent["destination_operation_id"]:
            raise StateVerificationError("recovery original operation binding changed")
        lifecycles = connection.execute(
            "SELECT * FROM execution_recovery_lifecycle WHERE recovery_id=? "
            "ORDER BY mutation_sequence",
            (recovery["recovery_id"],),
        ).fetchall()
        if not lifecycles or lifecycles[0]["transition"] != "READY":
            raise StateVerificationError("recovery lifecycle genesis is missing")
        if len(lifecycles) > MAX_RECOVERY_LIFECYCLE_PER_INTENT:
            raise StateVerificationError("recovery lifecycle bound is exceeded")
        machine = RecoveryState.READY.value
        claim_generation = 0
        for position, lifecycle in enumerate(lifecycles):
            if int(lifecycle["recovery_generation"]) != 1:
                raise StateVerificationError("recovery lifecycle generation is invalid")
            transition = str(lifecycle["transition"])
            if position == 0:
                if lifecycle["state"] != machine or int(lifecycle["claim_generation"]) != 0:
                    raise StateVerificationError("recovery lifecycle genesis is inconsistent")
                continue
            if transition in {"CLAIM", "RECLAIM"}:
                if machine not in {RecoveryState.READY.value, RecoveryState.CLAIMED.value}:
                    raise StateVerificationError("recovery claim transition is illegal")
                claim_generation += 1
                machine = RecoveryState.CLAIMED.value
            elif transition == "DISPATCHING":
                if machine != RecoveryState.CLAIMED.value:
                    raise StateVerificationError("recovery dispatch transition is illegal")
                machine = RecoveryState.DISPATCHING.value
            elif transition in {
                RecoveryState.COMPLETED.value,
                RecoveryState.FAILED_NO_EFFECT.value,
                RecoveryState.OUTCOME_UNKNOWN.value,
            }:
                if machine != RecoveryState.DISPATCHING.value:
                    raise StateVerificationError("recovery outcome transition is illegal")
                machine = transition
            elif transition == RecoveryState.CANCELLED.value:
                if machine not in {RecoveryState.READY.value, RecoveryState.CLAIMED.value}:
                    raise StateVerificationError("recovery cancellation transition is illegal")
                machine = RecoveryState.CANCELLED.value
            else:
                raise StateVerificationError("unknown recovery lifecycle transition")
            if lifecycle["state"] != machine:
                raise StateVerificationError("recovery lifecycle state is inconsistent")
        if machine != recovery["state"] or claim_generation != int(recovery["claim_generation"]):
            raise StateVerificationError("replayed recovery lifecycle disagrees with state")
        if recovery["state"] == RecoveryState.COMPLETED.value:
            if intent["state"] != ExecutionState.COMPLETED.value:
                raise StateVerificationError("completed recovery did not terminalize intent")
        elif intent["state"] != ExecutionState.OUTCOME_UNKNOWN.value:
            raise StateVerificationError("noncompleted recovery changed canonical intent")
    previous_by_intent: dict[str, str | None] = {}
    evidence_counts: dict[str, int] = {}
    for evidence in connection.execute(
        "SELECT * FROM execution_query_evidence ORDER BY mutation_sequence"
    ):
        authorization = connection.execute(
            "SELECT * FROM execution_query_authorizations WHERE query_authorization_id=?",
            (evidence["query_authorization_id"],),
        ).fetchone()
        if authorization is None or any(
            evidence[field] != authorization[field]
            for field in (
                "execution_intent_id",
                "ambiguous_attempt_id",
                "reconciliation_id",
                "reconciliation_generation",
                "recovery_generation",
                "action_fingerprint",
                "destination_registry",
                "destination",
                "destination_contract_digest",
                "original_operation_id",
                "adapter_identity",
                "adapter_version",
                "security_configuration_epoch",
                "security_configuration_digest",
            )
        ):
            raise StateVerificationError("query evidence lacks its exact authorization binding")
        try:
            DestinationQueryResult(str(evidence["normalized_result"]))
        except ValueError as exc:
            raise StateVerificationError("query evidence normalized result is invalid") from exc
        intent_id = str(evidence["execution_intent_id"])
        if evidence["previous_query_evidence_id"] != previous_by_intent.get(intent_id):
            raise StateVerificationError("query evidence chain is reordered or incomplete")
        previous_by_intent[intent_id] = str(evidence["query_evidence_id"])
        evidence_counts[intent_id] = evidence_counts.get(intent_id, 0) + 1
        digest_fields = {
            "action_fingerprint": str(evidence["action_fingerprint"]),
            "adapter_identity": str(evidence["adapter_identity"]),
            "adapter_version": str(evidence["adapter_version"]),
            "destination": str(evidence["destination"]),
            "destination_contract_digest": str(evidence["destination_contract_digest"]),
            "execution_intent_id": intent_id,
            "normalized_result": str(evidence["normalized_result"]),
            "observation_digest": str(evidence["observation_digest"]),
            "original_operation_id": str(evidence["original_operation_id"]),
            "query_authorization_id": str(evidence["query_authorization_id"]),
            "reconciliation_generation": int(evidence["reconciliation_generation"]),
            "reconciliation_id": str(evidence["reconciliation_id"]),
            "recovery_generation": int(evidence["recovery_generation"]),
            "security_configuration_digest": evidence["security_configuration_digest"],
            "security_configuration_epoch": evidence["security_configuration_epoch"],
        }
        if (
            hashlib.sha256(canonical_text(digest_fields).encode()).hexdigest()
            != evidence["evidence_digest"]
        ):
            raise StateVerificationError("query evidence digest is inconsistent")
    if any(count > MAX_QUERY_EVIDENCE_PER_INTENT for count in evidence_counts.values()):
        raise StateVerificationError("query evidence bound is exceeded")
    for proposal in connection.execute("SELECT * FROM execution_recovery_proposals"):
        digest_fields = {
            "action_fingerprint": str(proposal["action_fingerprint"]),
            "destination": str(proposal["destination"]),
            "destination_class": str(proposal["destination_class"]),
            "destination_contract_digest": str(proposal["destination_contract_digest"]),
            "destination_registry": str(proposal["destination_registry"]),
            "execution_intent_id": str(proposal["execution_intent_id"]),
            "original_idempotency_key": proposal["original_idempotency_key"],
            "original_operation_id": proposal["original_operation_id"],
            "policy_config_digest": str(proposal["policy_config_digest"]),
            "proposal_id": str(proposal["proposal_id"]),
            "query_evidence_id": proposal["query_evidence_id"],
            "reconciliation_generation": int(proposal["reconciliation_generation"]),
            "reconciliation_id": str(proposal["reconciliation_id"]),
            "recovery_generation": int(proposal["recovery_generation"]),
            "security_configuration_digest": proposal["security_configuration_digest"],
            "security_configuration_epoch": proposal["security_configuration_epoch"],
        }
        if (
            hashlib.sha256(canonical_text(digest_fields).encode()).hexdigest()
            != proposal["proposal_digest"]
        ):
            raise StateVerificationError("recovery proposal digest is inconsistent")
        if proposal["query_evidence_id"] is not None:
            evidence = connection.execute(
                "SELECT * FROM execution_query_evidence WHERE query_evidence_id=?",
                (proposal["query_evidence_id"],),
            ).fetchone()
            if (
                evidence is None
                or evidence["execution_intent_id"] != proposal["execution_intent_id"]
            ):
                raise StateVerificationError("recovery proposal query evidence is missing")
    for authorization in connection.execute("SELECT * FROM execution_recovery_authorizations"):
        proposal = connection.execute(
            "SELECT * FROM execution_recovery_proposals WHERE proposal_id=?",
            (authorization["proposal_id"],),
        ).fetchone()
        if (
            proposal is None
            or authorization["proposal_digest"] != proposal["proposal_digest"]
            or authorization["execution_intent_id"] != proposal["execution_intent_id"]
            or authorization["reconciliation_id"] != proposal["reconciliation_id"]
            or int(authorization["reconciliation_generation"])
            != int(proposal["reconciliation_generation"])
            or int(authorization["recovery_generation"]) != int(proposal["recovery_generation"])
        ):
            raise StateVerificationError("recovery authorization binding is inconsistent")


def recovery_active_for_intent(connection: sqlite3.Connection, intent_id: str) -> bool:
    """Internal c3a race fence: terminal reconciliation cannot outrun active recovery."""

    if not recovery_schema_present(connection):
        return False
    row = connection.execute(
        "SELECT state FROM execution_recovery_heads WHERE execution_intent_id=?", (intent_id,)
    ).fetchone()
    return row is not None and row[0] in {
        RecoveryState.READY.value,
        RecoveryState.CLAIMED.value,
        RecoveryState.DISPATCHING.value,
    }


def _bounded_identifier(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not _RECOVERY_IDENTIFIER.fullmatch(value)
        or len(value.encode()) > MAX_IDENTITY_BYTES
    ):
        raise ValueError(f"{label} is invalid or exceeds its bound")


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
