"""Authenticated, host-only reconciliation authority for v0.3c3a.

This module can resolve an ambiguous execution from authenticated evidence.  It
deliberately contains no destination query, retry, claim, or dispatch facility.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from collections.abc import Callable, Mapping
from typing import Any, Final, NamedTuple

from .canonical import canonical_text
from .execution import (
    _DIGEST,
    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
    _ID,
    ExecutionAuthority,
    _change,
    _logical,
    _mac,
    _new_id,
    _verified_row,
    _verified_workflow_row,
)
from .models import (
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionIntentRecord,
    ExecutionState,
    ExecutionStateConflict,
    ReconciliationDisposition,
    ReconciliationEvidenceCategory,
    ReconciliationEvidenceRecord,
    ReconciliationInspection,
    ReconciliationProposalRecord,
    ReconciliationProposalType,
    StateAuthenticationError,
    StateVerificationError,
    UnknownAuthorityRecord,
    WorkflowCASConflict,
)
from .store import (
    _EXECUTION_EXTENSION_CAPABILITY,
    SCHEMA_VERSION,
    _verify_common_record,
    _workflow_logical_from_row,
)

RECONCILIATION_SCHEMA_VERSION: Final = "execution-reconciliation-v0.3c3a"
MAX_RECONCILIATIONS_PER_INTENT: Final = 32
MAX_EVIDENCE_PER_INTENT: Final = 64
MAX_RECONCILIATION_LIFECYCLE_PER_INTENT: Final = 256
MAX_PENDING_AUDIT: Final = 512
MAX_IDENTITY_BYTES: Final = 256
_CAPABILITY_ISSUER = object()


_TABLES = (
    """CREATE TABLE IF NOT EXISTS execution_reconciliation_extensions(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_reconciliation_heads(
    intent_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, current_generation INTEGER NOT NULL,
    current_reconciliation_id TEXT NOT NULL, disposition TEXT NOT NULL,
    updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_reconciliations(
    reconciliation_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, intent_id TEXT NOT NULL, ambiguous_attempt_id TEXT NOT NULL,
    intent_state TEXT NOT NULL, generation INTEGER NOT NULL, action_fingerprint TEXT NOT NULL,
    destination TEXT NOT NULL, destination_contract_digest TEXT NOT NULL,
    external_operation_id TEXT, workflow_id TEXT NOT NULL,
    barrier_expected_head_event_id TEXT NOT NULL, barrier_expected_revision INTEGER NOT NULL,
    previous_reconciliation_id TEXT, disposition TEXT NOT NULL,
    creation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL,
    UNIQUE(intent_id,generation))""",
    """CREATE TABLE IF NOT EXISTS execution_reconciliation_evidence(
    evidence_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, reconciliation_id TEXT NOT NULL, intent_id TEXT NOT NULL,
    ambiguous_attempt_id TEXT NOT NULL, generation INTEGER NOT NULL,
    action_fingerprint TEXT NOT NULL, destination TEXT NOT NULL,
    destination_contract_digest TEXT NOT NULL, external_operation_id TEXT,
    verification_mechanism TEXT NOT NULL, verification_version TEXT NOT NULL,
    evidence_digest TEXT NOT NULL, verifier_identity TEXT NOT NULL,
    verifier_class TEXT NOT NULL, evidence_category TEXT NOT NULL,
    previous_evidence_id TEXT, mutation_sequence INTEGER NOT NULL
    REFERENCES state_mutations(sequence), key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_reconciliation_proposals(
    proposal_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, reconciliation_id TEXT NOT NULL UNIQUE,
    intent_id TEXT NOT NULL, ambiguous_attempt_id TEXT NOT NULL, generation INTEGER NOT NULL,
    action_fingerprint TEXT NOT NULL, destination TEXT NOT NULL,
    destination_contract_digest TEXT NOT NULL, evidence_id TEXT NOT NULL,
    evidence_category TEXT NOT NULL, evidence_digest TEXT NOT NULL,
    proposal_type TEXT NOT NULL, proposer_identity TEXT NOT NULL,
    proposer_class TEXT NOT NULL, proposal_digest TEXT NOT NULL UNIQUE,
    barrier_expected_head_event_id TEXT NOT NULL, barrier_expected_revision INTEGER NOT NULL,
    mutation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_reconciliation_confirmations(
    confirmation_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, reconciliation_id TEXT NOT NULL UNIQUE,
    proposal_id TEXT NOT NULL UNIQUE, proposal_digest TEXT NOT NULL,
    intent_id TEXT NOT NULL, ambiguous_attempt_id TEXT NOT NULL, generation INTEGER NOT NULL,
    proposal_type TEXT NOT NULL, confirmation_identity TEXT NOT NULL,
    confirmation_class TEXT NOT NULL, mutation_sequence INTEGER NOT NULL
    REFERENCES state_mutations(sequence), key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_reconciliation_lifecycle(
    lifecycle_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, reconciliation_id TEXT NOT NULL, intent_id TEXT NOT NULL,
    generation INTEGER NOT NULL, transition TEXT NOT NULL, evidence_id TEXT,
    proposal_id TEXT, confirmation_id TEXT, disposition TEXT NOT NULL,
    mutation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL,
    UNIQUE(reconciliation_id,mutation_sequence))""",
)


def install_reconciliation_schema(connection: sqlite3.Connection) -> None:
    for statement in _TABLES:
        connection.execute(statement)
    row = connection.execute(
        "SELECT schema_version FROM execution_reconciliation_extensions WHERE singleton=1"
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO execution_reconciliation_extensions VALUES(1,?)",
            (RECONCILIATION_SCHEMA_VERSION,),
        )
    elif row[0] != RECONCILIATION_SCHEMA_VERSION:
        raise StateVerificationError("reconciliation authority schema is incompatible")


def reconciliation_schema_present(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='execution_reconciliation_extensions'"
        ).fetchone()
        is not None
    )


def reconciliation_expected_entities() -> dict[str, dict[str, str]]:
    return {
        "execution_reconciliation_head": {},
        "execution_reconciliation": {},
        "execution_reconciliation_evidence": {},
        "execution_reconciliation_proposal": {},
        "execution_reconciliation_confirmation": {},
        "execution_reconciliation_lifecycle": {},
    }


_TABLE_KIND = {
    "execution_reconciliation_heads": "execution_reconciliation_head",
    "execution_reconciliations": "execution_reconciliation",
    "execution_reconciliation_evidence": "execution_reconciliation_evidence",
    "execution_reconciliation_proposals": "execution_reconciliation_proposal",
    "execution_reconciliation_confirmations": "execution_reconciliation_confirmation",
    "execution_reconciliation_lifecycle": "execution_reconciliation_lifecycle",
}


def _verified_reconciliation_row(
    authority: ReconciliationAuthority,
    connection: sqlite3.Connection,
    table: str,
    key: str,
    value: str,
) -> sqlite3.Row:
    row = connection.execute(f"SELECT * FROM {table} WHERE {key}=?", (value,)).fetchone()
    if row is None:
        raise UnknownAuthorityRecord(f"unknown reconciliation authority record: {value}")
    kind = _TABLE_KIND[table]
    logical = dict(row)
    logical.pop("record_mac", None)
    _verify_common_record(authority.state, logical)
    if not authority.state._verify_execution_record_mac(
        _EXECUTION_EXTENSION_CAPABILITY, kind, logical, str(row["record_mac"])
    ):
        raise StateAuthenticationError(f"{kind} MAC is invalid")
    return row


class _ReconciliationCapability:
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
        authority: ReconciliationAuthority,
        capability: object,
        *,
        boot_event_id: str,
        identity: str,
        identity_class: str,
    ) -> None:
        if issuer is not _CAPABILITY_ISSUER:
            raise TypeError("reconciliation capabilities cannot be constructed by callers")
        self._authority = authority
        self._capability = capability
        self._pid = os.getpid()
        self._thread_id = threading.get_ident()
        self.boot_event_id = boot_event_id
        self.identity = identity
        self.identity_class = identity_class

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("reconciliation capabilities are immutable")
        object.__setattr__(self, name, value)

    def __copy__(self) -> object:
        raise TypeError("reconciliation capabilities cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("reconciliation capabilities cannot be copied")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("reconciliation capabilities are process-local and non-serializable")


class ReconciliationInspectionCapability(_ReconciliationCapability):
    """Opaque read-only reconciliation authority."""


class ReconciliationDecisionCapability(_ReconciliationCapability):
    """Opaque authority for dangerous two-step reconciliation decisions."""


class _CapabilityBinding(NamedTuple):
    token: object
    authority: ReconciliationAuthority
    pid: int
    thread_id: int
    boot_event_id: str
    identity: str
    identity_class: str


class ReconciliationAuthority:
    """Host-only c3a authority; this type has no execution or retry operation."""

    def __init__(self, execution: ExecutionAuthority) -> None:
        self.execution = execution
        self.state = execution.state
        self._inspection_capabilities: dict[int, _CapabilityBinding] = {}
        self._decision_capabilities: dict[int, _CapabilityBinding] = {}

    @classmethod
    def _for_host(
        cls, host_capability: object, execution: ExecutionAuthority
    ) -> ReconciliationAuthority:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("reconciliation authority construction requires host authority")
        return cls(execution)

    def issue_inspection_capability(
        self, host_capability: object
    ) -> ReconciliationInspectionCapability:
        self._require_host(host_capability)
        token = object()
        boot_event_id = self._current_boot()
        identity = "host-inspector"
        identity_class = "HOST_INTERNAL"
        result = ReconciliationInspectionCapability(
            _CAPABILITY_ISSUER,
            self,
            token,
            boot_event_id=boot_event_id,
            identity=identity,
            identity_class=identity_class,
        )
        self._inspection_capabilities[id(result)] = _CapabilityBinding(
            token,
            self,
            os.getpid(),
            threading.get_ident(),
            boot_event_id,
            identity,
            identity_class,
        )
        return result

    def issue_decision_capability(
        self,
        host_capability: object,
        *,
        identity: str,
        identity_class: str,
    ) -> ReconciliationDecisionCapability:
        self._require_host(host_capability)
        _bounded_identifier(identity, "decision identity")
        _bounded_identifier(identity_class, "decision identity class")
        token = object()
        boot_event_id = self._current_boot()
        result = ReconciliationDecisionCapability(
            _CAPABILITY_ISSUER,
            self,
            token,
            boot_event_id=boot_event_id,
            identity=identity,
            identity_class=identity_class,
        )
        self._decision_capabilities[id(result)] = _CapabilityBinding(
            token,
            self,
            os.getpid(),
            threading.get_ident(),
            boot_event_id,
            identity,
            identity_class,
        )
        return result

    def inspect_execution(
        self, capability: ReconciliationInspectionCapability, intent_id: str
    ) -> ReconciliationInspection:
        self._validate_capability(capability, inspection=True)

        def read() -> ReconciliationInspection:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            intent = _verified_row(self.state, conn, "execution_intents", "intent_id", intent_id)
            if intent["state"] != ExecutionState.OUTCOME_UNKNOWN.value:
                raise ExecutionStateConflict(
                    "only OUTCOME_UNKNOWN may be inspected for reconciliation"
                )
            head = conn.execute(
                "SELECT * FROM execution_reconciliation_heads WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if head is None:
                return self._inspection(intent, None, None)
            verified_head = _verified_reconciliation_row(
                self, conn, "execution_reconciliation_heads", "intent_id", intent_id
            )
            reconciliation = _verified_reconciliation_row(
                self,
                conn,
                "execution_reconciliations",
                "reconciliation_id",
                str(verified_head["current_reconciliation_id"]),
            )
            evidence = conn.execute(
                "SELECT * FROM execution_reconciliation_evidence WHERE reconciliation_id=? "
                "ORDER BY mutation_sequence DESC LIMIT 1",
                (reconciliation["reconciliation_id"],),
            ).fetchone()
            proposal = conn.execute(
                "SELECT * FROM execution_reconciliation_proposals WHERE reconciliation_id=?",
                (reconciliation["reconciliation_id"],),
            ).fetchone()
            if evidence is not None:
                evidence = _verified_reconciliation_row(
                    self,
                    conn,
                    "execution_reconciliation_evidence",
                    "evidence_id",
                    str(evidence["evidence_id"]),
                )
            if proposal is not None:
                proposal = _verified_reconciliation_row(
                    self,
                    conn,
                    "execution_reconciliation_proposals",
                    "proposal_id",
                    str(proposal["proposal_id"]),
                )
            return self._inspection(intent, verified_head, reconciliation, evidence, proposal)

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def begin_reconciliation(
        self,
        capability: ReconciliationDecisionCapability,
        intent_id: str,
        *,
        destination_contract_digest: str,
    ) -> ReconciliationInspection:
        self._validate_capability(capability)
        _require_digest(destination_contract_digest, "destination contract digest")
        reconciliation_id = _new_id("reconciliation")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ReconciliationInspection]:
            self._require_audit_capacity(conn)
            intent = _verified_row(self.state, conn, "execution_intents", "intent_id", intent_id)
            self._require_unknown_binding(intent, destination_contract_digest)
            barrier = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(intent["workflow_id"]),
            )
            if barrier["active_intent_id"] != intent_id or barrier["status"] not in {
                "BLOCKED_UNKNOWN",
                "BLOCKED_UNKNOWN_ABANDONED",
            }:
                raise WorkflowCASConflict("UNKNOWN workflow barrier is not current")
            previous: str | None = None
            generation = 1
            head_row = conn.execute(
                "SELECT * FROM execution_reconciliation_heads WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if head_row is not None:
                previous_head = _verified_reconciliation_row(
                    self, conn, "execution_reconciliation_heads", "intent_id", intent_id
                )
                disposition = ReconciliationDisposition(str(previous_head["disposition"]))
                if disposition not in {
                    ReconciliationDisposition.CONFLICT,
                    ReconciliationDisposition.INSUFFICIENT,
                }:
                    raise ExecutionStateConflict("intent already has a current reconciliation")
                previous = str(previous_head["current_reconciliation_id"])
                generation = int(previous_head["current_generation"]) + 1
            count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM execution_reconciliations WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()[0]
            )
            if count >= MAX_RECONCILIATIONS_PER_INTENT or generation > 2**63 - 1:
                raise ExecutionStateConflict("reconciliation history bound is exhausted")
            reconciliation = self._reconciliation_logical(
                reconciliation_id,
                intent,
                generation,
                str(barrier["expected_head_event_id"]),
                int(barrier["expected_revision"]),
                previous,
                ReconciliationDisposition.ACTIVE,
                seq,
            )
            head = self._head_logical(
                intent_id,
                generation,
                reconciliation_id,
                ReconciliationDisposition.ACTIVE,
                seq,
            )
            lifecycle = self._lifecycle_logical(
                reconciliation_id,
                intent_id,
                generation,
                "BEGIN",
                ReconciliationDisposition.ACTIVE,
                seq,
            )
            records = (
                ("execution_reconciliation", reconciliation_id, reconciliation),
                ("execution_reconciliation_head", intent_id, head),
                (
                    "execution_reconciliation_lifecycle",
                    str(lifecycle["lifecycle_id"]),
                    lifecycle,
                ),
            )
            macs = self._macs(records)
            payload = self._payload("BEGIN_RECONCILIATION", records, macs)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_reconciliation(
                    db, reconciliation, macs[(records[0][0], records[0][1])]
                )
                self._upsert_head(db, head, macs[(records[1][0], records[1][1])])
                self._insert_lifecycle(db, lifecycle, macs[(records[2][0], records[2][1])])

            return payload, apply, self._inspection(intent, head, reconciliation)

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "BEGIN_RECONCILIATION", build
        )

    def record_reconciliation_evidence(
        self,
        capability: ReconciliationDecisionCapability,
        reconciliation_id: str,
        *,
        category: ReconciliationEvidenceCategory,
        evidence_digest: str,
        verification_mechanism: str,
        verification_version: str,
        destination_contract_digest: str,
        external_operation_id: str | None = None,
    ) -> ReconciliationEvidenceRecord:
        identity = self._validate_capability(capability)
        if not isinstance(category, ReconciliationEvidenceCategory):
            raise TypeError("evidence category must be host-selected")
        _require_digest(evidence_digest, "evidence digest")
        _require_digest(destination_contract_digest, "destination contract digest")
        _bounded_identifier(verification_mechanism, "verification mechanism")
        _bounded_identifier(verification_version, "verification version")
        if external_operation_id is not None:
            _bounded_identifier(external_operation_id, "external operation ID")
        evidence_id = _new_id("reconciliation-evidence")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[
            dict[str, Any], Callable[[sqlite3.Connection], None], ReconciliationEvidenceRecord
        ]:
            self._require_audit_capacity(conn)
            reconciliation, intent, head = self._require_current_reconciliation(
                conn, reconciliation_id, destination_contract_digest
            )
            current_disposition = ReconciliationDisposition(str(reconciliation["disposition"]))
            if current_disposition is not ReconciliationDisposition.ACTIVE and not (
                current_disposition is ReconciliationDisposition.PROPOSED
                and category
                in {
                    ReconciliationEvidenceCategory.CONFLICT,
                    ReconciliationEvidenceCategory.INSUFFICIENT,
                }
            ):
                raise ExecutionStateConflict("evidence requires an active reconciliation")
            stored_operation = intent["destination_operation_id"]
            if (
                stored_operation is not None
                and external_operation_id is not None
                and stored_operation != external_operation_id
            ):
                raise ExecutionBindingError("external operation ID differs from ambiguous attempt")
            evidence_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM execution_reconciliation_evidence WHERE intent_id=?",
                    (intent["intent_id"],),
                ).fetchone()[0]
            )
            if evidence_count >= MAX_EVIDENCE_PER_INTENT:
                raise ExecutionStateConflict("reconciliation evidence bound is exhausted")
            previous_row = conn.execute(
                "SELECT evidence_id FROM execution_reconciliation_evidence "
                "WHERE reconciliation_id=? ORDER BY mutation_sequence DESC LIMIT 1",
                (reconciliation_id,),
            ).fetchone()
            previous = None if previous_row is None else str(previous_row[0])
            evidence = self._evidence_logical(
                evidence_id,
                reconciliation,
                category,
                evidence_digest,
                verification_mechanism,
                verification_version,
                identity,
                external_operation_id,
                previous,
                seq,
            )
            disposition = {
                ReconciliationEvidenceCategory.CONFLICT: ReconciliationDisposition.CONFLICT,
                ReconciliationEvidenceCategory.INSUFFICIENT: ReconciliationDisposition.INSUFFICIENT,
            }.get(category)
            records: list[tuple[str, str, Mapping[str, Any]]] = [
                ("execution_reconciliation_evidence", evidence_id, evidence)
            ]
            updated_reconciliation: dict[str, Any] | None = None
            updated_head: dict[str, Any] | None = None
            lifecycle: dict[str, Any] | None = None
            if disposition is not None:
                updated_reconciliation = self._updated(reconciliation, disposition, seq)
                updated_head = self._head_logical(
                    str(intent["intent_id"]),
                    int(reconciliation["generation"]),
                    reconciliation_id,
                    disposition,
                    seq,
                )
                lifecycle = self._lifecycle_logical(
                    reconciliation_id,
                    str(intent["intent_id"]),
                    int(reconciliation["generation"]),
                    category.value,
                    disposition,
                    seq,
                    evidence_id=evidence_id,
                )
                records.extend(
                    [
                        ("execution_reconciliation", reconciliation_id, updated_reconciliation),
                        ("execution_reconciliation_head", str(intent["intent_id"]), updated_head),
                        (
                            "execution_reconciliation_lifecycle",
                            str(lifecycle["lifecycle_id"]),
                            lifecycle,
                        ),
                    ]
                )
            macs = self._macs(records)
            payload = self._payload("RECORD_RECONCILIATION_EVIDENCE", records, macs)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_evidence(db, evidence, macs[(records[0][0], records[0][1])])
                if (
                    updated_reconciliation is not None
                    and updated_head is not None
                    and lifecycle is not None
                ):
                    self._update_reconciliation(
                        db,
                        updated_reconciliation,
                        macs[("execution_reconciliation", reconciliation_id)],
                    )
                    self._upsert_head(
                        db,
                        updated_head,
                        macs[("execution_reconciliation_head", str(intent["intent_id"]))],
                    )
                    self._insert_lifecycle(
                        db,
                        lifecycle,
                        macs[
                            ("execution_reconciliation_lifecycle", str(lifecycle["lifecycle_id"]))
                        ],
                    )

            result = ReconciliationEvidenceRecord(
                evidence_id,
                reconciliation_id,
                str(intent["intent_id"]),
                str(intent["attempt_id"]),
                int(reconciliation["generation"]),
                category,
                evidence_digest,
                external_operation_id,
                seq,
            )
            return payload, apply, result

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "RECORD_RECONCILIATION_EVIDENCE", build
        )

    def propose_reconciliation_completed(
        self,
        capability: ReconciliationDecisionCapability,
        reconciliation_id: str,
        evidence_id: str,
        *,
        destination_contract_digest: str,
    ) -> ReconciliationProposalRecord:
        return self._propose(
            capability,
            reconciliation_id,
            evidence_id,
            destination_contract_digest,
            ReconciliationProposalType.COMPLETED,
        )

    def propose_reconciliation_no_effect(
        self,
        capability: ReconciliationDecisionCapability,
        reconciliation_id: str,
        evidence_id: str,
        *,
        destination_contract_digest: str,
    ) -> ReconciliationProposalRecord:
        return self._propose(
            capability,
            reconciliation_id,
            evidence_id,
            destination_contract_digest,
            ReconciliationProposalType.FAILED_NO_EFFECT,
        )

    def confirm_reconciliation_decision(
        self,
        capability: ReconciliationDecisionCapability,
        proposal_id: str,
        *,
        proposal_digest: str,
        destination_contract_digest: str,
    ) -> ExecutionIntentRecord:
        identity = self._validate_capability(capability)
        _require_digest(proposal_digest, "proposal digest")
        _require_digest(destination_contract_digest, "destination contract digest")
        confirmation_id = _new_id("reconciliation-confirmation")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ExecutionIntentRecord]:
            self._require_audit_capacity(conn)
            proposal = _verified_reconciliation_row(
                self, conn, "execution_reconciliation_proposals", "proposal_id", proposal_id
            )
            if proposal["proposal_digest"] != proposal_digest:
                raise ExecutionBindingError("confirmation proposal digest is stale")
            reconciliation, intent, head = self._require_current_reconciliation(
                conn, str(proposal["reconciliation_id"]), destination_contract_digest
            )
            if (
                reconciliation["disposition"] != ReconciliationDisposition.PROPOSED.value
                or head["disposition"] != ReconciliationDisposition.PROPOSED.value
                or int(proposal["generation"]) != int(reconciliation["generation"])
                or proposal["ambiguous_attempt_id"] != intent["attempt_id"]
                or proposal["action_fingerprint"] != intent["action_fingerprint"]
                or proposal["destination"] != intent["destination"]
                or proposal["destination_contract_digest"] != intent["destination_config_digest"]
            ):
                raise ExecutionBindingError("confirmation binding is stale")
            if conn.execute(
                "SELECT 1 FROM execution_reconciliation_confirmations WHERE reconciliation_id=?",
                (reconciliation["reconciliation_id"],),
            ).fetchone():
                raise ExecutionStateConflict("reconciliation is already confirmed")
            from .recovery import recovery_active_for_intent

            if recovery_active_for_intent(conn, str(intent["intent_id"])):
                raise ExecutionStateConflict(
                    "terminal reconciliation conflicts with active recovery authority"
                )
            barrier = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(intent["workflow_id"]),
            )
            if (
                barrier["active_intent_id"] != intent["intent_id"]
                or barrier["status"] != "BLOCKED_UNKNOWN"
                or barrier["expected_head_event_id"] != proposal["barrier_expected_head_event_id"]
                or int(barrier["expected_revision"]) != int(proposal["barrier_expected_revision"])
            ):
                raise WorkflowCASConflict("workflow barrier changed before confirmation")
            evidence = _verified_reconciliation_row(
                self,
                conn,
                "execution_reconciliation_evidence",
                "evidence_id",
                str(proposal["evidence_id"]),
            )
            proposal_type = ReconciliationProposalType(str(proposal["proposal_type"]))
            target = (
                ExecutionState.COMPLETED
                if proposal_type is ReconciliationProposalType.COMPLETED
                else ExecutionState.FAILED_NO_EFFECT
            )
            disposition = (
                ReconciliationDisposition.CONFIRMED_COMPLETED
                if target is ExecutionState.COMPLETED
                else ReconciliationDisposition.CONFIRMED_NO_EFFECT
            )
            confirmation = self._confirmation_logical(confirmation_id, proposal, identity, seq)
            updated_intent = _logical(intent, "execution_intent")
            updated_intent.update(
                {
                    "state": target.value,
                    "destination_operation_id": evidence["external_operation_id"]
                    or intent["destination_operation_id"],
                    "completion_sequence": seq,
                    "result_digest": evidence["evidence_digest"],
                    "updated_sequence": seq,
                }
            )
            updated_reconciliation = self._updated(reconciliation, disposition, seq)
            updated_head = self._head_logical(
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                str(reconciliation["reconciliation_id"]),
                disposition,
                seq,
            )
            updated_barrier = self.execution._barrier_logical(
                str(intent["workflow_id"]),
                None,
                "ACTIVE",
                str(barrier["expected_head_event_id"]),
                int(barrier["expected_revision"]),
                seq,
            )
            workflow_row = _verified_workflow_row(self.state, conn, str(intent["workflow_id"]))
            workflow = _workflow_logical_from_row(workflow_row)
            workflow.update({"status": "ACTIVE", "updated_sequence": seq})
            execution_lifecycle = self.execution._lifecycle_logical(
                str(intent["intent_id"]),
                int(intent["claim_generation"]),
                intent["active_claim_id"],
                intent["worker_id"],
                intent["boot_event_id"],
                intent["attempt_id"],
                "RECONCILED_" + target.value,
                updated_intent["destination_operation_id"],
                str(evidence["evidence_digest"]),
                {
                    "confirmation_id": confirmation_id,
                    "evidence_id": evidence["evidence_id"],
                    "proposal_digest": proposal_digest,
                    "proposal_id": proposal_id,
                    "reconciliation_id": reconciliation["reconciliation_id"],
                },
                seq,
            )
            reconciliation_lifecycle = self._lifecycle_logical(
                str(reconciliation["reconciliation_id"]),
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                "CONFIRM_" + proposal_type.value,
                disposition,
                seq,
                evidence_id=str(evidence["evidence_id"]),
                proposal_id=proposal_id,
                confirmation_id=confirmation_id,
            )
            records = (
                ("execution_reconciliation_confirmation", confirmation_id, confirmation),
                (
                    "execution_reconciliation",
                    str(reconciliation["reconciliation_id"]),
                    updated_reconciliation,
                ),
                ("execution_reconciliation_head", str(intent["intent_id"]), updated_head),
                ("execution_intent", str(intent["intent_id"]), updated_intent),
                ("execution_workflow_barrier", str(intent["workflow_id"]), updated_barrier),
                ("workflow_state", str(intent["workflow_id"]), workflow),
                (
                    "execution_lifecycle",
                    str(execution_lifecycle["lifecycle_id"]),
                    execution_lifecycle,
                ),
                (
                    "execution_reconciliation_lifecycle",
                    str(reconciliation_lifecycle["lifecycle_id"]),
                    reconciliation_lifecycle,
                ),
            )
            macs = self._macs(records)
            payload = self._payload("CONFIRM_RECONCILIATION", records, macs)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_confirmation(db, confirmation, macs[(records[0][0], records[0][1])])
                self._update_reconciliation(
                    db, updated_reconciliation, macs[(records[1][0], records[1][1])]
                )
                self._upsert_head(db, updated_head, macs[(records[2][0], records[2][1])])
                self.execution._update_intent(
                    db, updated_intent, macs[(records[3][0], records[3][1])]
                )
                self.execution._upsert_barrier(
                    db, updated_barrier, macs[(records[4][0], records[4][1])]
                )
                db.execute(
                    "UPDATE workflow_state SET status=?, updated_sequence=?, key_id=?, "
                    "record_mac=? WHERE workflow_id=?",
                    (
                        "ACTIVE",
                        seq,
                        self.state.key_id,
                        macs[(records[5][0], records[5][1])],
                        intent["workflow_id"],
                    ),
                )
                self.execution._insert_lifecycle(
                    db, execution_lifecycle, macs[(records[6][0], records[6][1])]
                )
                self._insert_lifecycle(
                    db, reconciliation_lifecycle, macs[(records[7][0], records[7][1])]
                )

            return payload, apply, self.execution._record_dict(updated_intent)

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "CONFIRM_RECONCILIATION", build
        )

    def abandon_reconciliation(
        self,
        capability: ReconciliationDecisionCapability,
        reconciliation_id: str,
        evidence_id: str,
        *,
        destination_contract_digest: str,
    ) -> ReconciliationInspection:
        self._validate_capability(capability)
        _require_digest(destination_contract_digest, "destination contract digest")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ReconciliationInspection]:
            self._require_audit_capacity(conn)
            reconciliation, intent, _head = self._require_current_reconciliation(
                conn, reconciliation_id, destination_contract_digest
            )
            if reconciliation["disposition"] not in {
                ReconciliationDisposition.ACTIVE.value,
                ReconciliationDisposition.PROPOSED.value,
            }:
                raise ExecutionStateConflict("reconciliation cannot be abandoned")
            from .recovery import recovery_active_for_intent

            if recovery_active_for_intent(conn, str(intent["intent_id"])):
                raise ExecutionStateConflict(
                    "reconciliation abandonment conflicts with active recovery authority"
                )
            evidence = _verified_reconciliation_row(
                self, conn, "execution_reconciliation_evidence", "evidence_id", evidence_id
            )
            if (
                evidence["reconciliation_id"] != reconciliation_id
                or evidence["evidence_category"] != ReconciliationEvidenceCategory.ABANDONED.value
            ):
                raise ExecutionBindingError("abandonment evidence is not bound to reconciliation")
            barrier = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(intent["workflow_id"]),
            )
            if barrier["active_intent_id"] != intent["intent_id"]:
                raise WorkflowCASConflict("workflow barrier changed before abandonment")
            disposition = ReconciliationDisposition.ABANDONED
            updated_reconciliation = self._updated(reconciliation, disposition, seq)
            updated_head = self._head_logical(
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                reconciliation_id,
                disposition,
                seq,
            )
            updated_barrier = self.execution._barrier_logical(
                str(intent["workflow_id"]),
                str(intent["intent_id"]),
                "BLOCKED_UNKNOWN_ABANDONED",
                str(barrier["expected_head_event_id"]),
                int(barrier["expected_revision"]),
                seq,
            )
            workflow_row = _verified_workflow_row(self.state, conn, str(intent["workflow_id"]))
            workflow = _workflow_logical_from_row(workflow_row)
            workflow.update({"status": "BLOCKED_UNKNOWN_ABANDONED", "updated_sequence": seq})
            lifecycle = self._lifecycle_logical(
                reconciliation_id,
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                "ABANDON",
                disposition,
                seq,
                evidence_id=evidence_id,
            )
            records = (
                ("execution_reconciliation", reconciliation_id, updated_reconciliation),
                ("execution_reconciliation_head", str(intent["intent_id"]), updated_head),
                ("execution_workflow_barrier", str(intent["workflow_id"]), updated_barrier),
                ("workflow_state", str(intent["workflow_id"]), workflow),
                (
                    "execution_reconciliation_lifecycle",
                    str(lifecycle["lifecycle_id"]),
                    lifecycle,
                ),
            )
            macs = self._macs(records)
            payload = self._payload("ABANDON_RECONCILIATION", records, macs)

            def apply(db: sqlite3.Connection) -> None:
                self._update_reconciliation(
                    db, updated_reconciliation, macs[(records[0][0], records[0][1])]
                )
                self._upsert_head(db, updated_head, macs[(records[1][0], records[1][1])])
                self.execution._upsert_barrier(
                    db, updated_barrier, macs[(records[2][0], records[2][1])]
                )
                db.execute(
                    "UPDATE workflow_state SET status=?, updated_sequence=?, key_id=?, "
                    "record_mac=? WHERE workflow_id=?",
                    (
                        "BLOCKED_UNKNOWN_ABANDONED",
                        seq,
                        self.state.key_id,
                        macs[(records[3][0], records[3][1])],
                        intent["workflow_id"],
                    ),
                )
                self._insert_lifecycle(db, lifecycle, macs[(records[4][0], records[4][1])])

            return payload, apply, self._inspection(intent, updated_head, updated_reconciliation)

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "ABANDON_RECONCILIATION", build
        )

    def _propose(
        self,
        capability: ReconciliationDecisionCapability,
        reconciliation_id: str,
        evidence_id: str,
        destination_contract_digest: str,
        proposal_type: ReconciliationProposalType,
    ) -> ReconciliationProposalRecord:
        identity = self._validate_capability(capability)
        _require_digest(destination_contract_digest, "destination contract digest")
        proposal_id = _new_id("reconciliation-proposal")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[
            dict[str, Any], Callable[[sqlite3.Connection], None], ReconciliationProposalRecord
        ]:
            self._require_audit_capacity(conn)
            reconciliation, intent, _head = self._require_current_reconciliation(
                conn, reconciliation_id, destination_contract_digest
            )
            if reconciliation["disposition"] != ReconciliationDisposition.ACTIVE.value:
                raise ExecutionStateConflict("terminal proposal requires active reconciliation")
            evidence = _verified_reconciliation_row(
                self, conn, "execution_reconciliation_evidence", "evidence_id", evidence_id
            )
            allowed = (
                {
                    ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED.value,
                    ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED.value,
                }
                if proposal_type is ReconciliationProposalType.COMPLETED
                else {
                    ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_NO_EFFECT.value,
                    ReconciliationEvidenceCategory.OPERATOR_VERIFIED_NO_EFFECT.value,
                }
            )
            if (
                evidence["reconciliation_id"] != reconciliation_id
                or evidence["intent_id"] != intent["intent_id"]
                or evidence["ambiguous_attempt_id"] != intent["attempt_id"]
                or evidence["action_fingerprint"] != intent["action_fingerprint"]
                or evidence["destination"] != intent["destination"]
                or evidence["destination_contract_digest"] != destination_contract_digest
                or evidence["evidence_category"] not in allowed
            ):
                raise ExecutionBindingError("evidence cannot support proposed terminal outcome")
            barrier = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(intent["workflow_id"]),
            )
            proposal_fields = {
                "action_fingerprint": str(intent["action_fingerprint"]),
                "ambiguous_attempt_id": str(intent["attempt_id"]),
                "barrier_expected_head_event_id": str(barrier["expected_head_event_id"]),
                "barrier_expected_revision": int(barrier["expected_revision"]),
                "destination": str(intent["destination"]),
                "destination_contract_digest": destination_contract_digest,
                "evidence_category": str(evidence["evidence_category"]),
                "evidence_digest": str(evidence["evidence_digest"]),
                "evidence_id": evidence_id,
                "generation": int(reconciliation["generation"]),
                "intent_id": str(intent["intent_id"]),
                "proposal_id": proposal_id,
                "proposal_type": proposal_type.value,
                "reconciliation_id": reconciliation_id,
            }
            proposal_digest = hashlib.sha256(canonical_text(proposal_fields).encode()).hexdigest()
            proposal = self._proposal_logical(proposal_fields, proposal_digest, identity, seq)
            disposition = ReconciliationDisposition.PROPOSED
            updated_reconciliation = self._updated(reconciliation, disposition, seq)
            updated_head = self._head_logical(
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                reconciliation_id,
                disposition,
                seq,
            )
            lifecycle = self._lifecycle_logical(
                reconciliation_id,
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                "PROPOSE_" + proposal_type.value,
                disposition,
                seq,
                evidence_id=evidence_id,
                proposal_id=proposal_id,
            )
            records = (
                ("execution_reconciliation_proposal", proposal_id, proposal),
                ("execution_reconciliation", reconciliation_id, updated_reconciliation),
                ("execution_reconciliation_head", str(intent["intent_id"]), updated_head),
                (
                    "execution_reconciliation_lifecycle",
                    str(lifecycle["lifecycle_id"]),
                    lifecycle,
                ),
            )
            macs = self._macs(records)
            payload = self._payload("PROPOSE_RECONCILIATION", records, macs)

            def apply(db: sqlite3.Connection) -> None:
                self._insert_proposal(db, proposal, macs[(records[0][0], records[0][1])])
                self._update_reconciliation(
                    db, updated_reconciliation, macs[(records[1][0], records[1][1])]
                )
                self._upsert_head(db, updated_head, macs[(records[2][0], records[2][1])])
                self._insert_lifecycle(db, lifecycle, macs[(records[3][0], records[3][1])])

            result = ReconciliationProposalRecord(
                proposal_id,
                proposal_digest,
                reconciliation_id,
                str(intent["intent_id"]),
                int(reconciliation["generation"]),
                proposal_type,
                evidence_id,
                seq,
            )
            return payload, apply, result

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "PROPOSE_RECONCILIATION", build
        )

    def _require_current_reconciliation(
        self,
        conn: sqlite3.Connection,
        reconciliation_id: str,
        destination_contract_digest: str,
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        reconciliation = _verified_reconciliation_row(
            self, conn, "execution_reconciliations", "reconciliation_id", reconciliation_id
        )
        intent = _verified_row(
            self.state,
            conn,
            "execution_intents",
            "intent_id",
            str(reconciliation["intent_id"]),
        )
        self._require_unknown_binding(intent, destination_contract_digest)
        head = _verified_reconciliation_row(
            self,
            conn,
            "execution_reconciliation_heads",
            "intent_id",
            str(intent["intent_id"]),
        )
        if (
            head["current_reconciliation_id"] != reconciliation_id
            or int(head["current_generation"]) != int(reconciliation["generation"])
            or reconciliation["ambiguous_attempt_id"] != intent["attempt_id"]
            or reconciliation["action_fingerprint"] != intent["action_fingerprint"]
            or reconciliation["destination"] != intent["destination"]
            or reconciliation["destination_contract_digest"] != destination_contract_digest
        ):
            raise ExecutionBindingError("reconciliation generation or intent binding is stale")
        barrier = _verified_row(
            self.state,
            conn,
            "execution_workflow_barriers",
            "workflow_id",
            str(intent["workflow_id"]),
        )
        if (
            barrier["active_intent_id"] != intent["intent_id"]
            or barrier["status"] not in {"BLOCKED_UNKNOWN", "BLOCKED_UNKNOWN_ABANDONED"}
            or barrier["expected_head_event_id"] != reconciliation["barrier_expected_head_event_id"]
            or int(barrier["expected_revision"]) != int(reconciliation["barrier_expected_revision"])
        ):
            raise WorkflowCASConflict("reconciliation workflow barrier is stale")
        return reconciliation, intent, head

    @staticmethod
    def _require_unknown_binding(intent: sqlite3.Row, contract_digest: str) -> None:
        if intent["state"] != ExecutionState.OUTCOME_UNKNOWN.value:
            raise ExecutionStateConflict("only OUTCOME_UNKNOWN may enter reconciliation")
        if intent["attempt_id"] is None:
            raise ExecutionBindingError("UNKNOWN intent has no ambiguous attempt")
        if intent["destination_config_digest"] != contract_digest:
            raise ExecutionBindingError("destination contract changed during reconciliation")

    def _validate_capability(
        self,
        capability: _ReconciliationCapability,
        *,
        inspection: bool = False,
    ) -> _CapabilityBinding:
        expected_type = (
            ReconciliationInspectionCapability if inspection else ReconciliationDecisionCapability
        )
        registry = self._inspection_capabilities if inspection else self._decision_capabilities
        binding = registry.get(id(capability))
        if (
            not isinstance(capability, expected_type)
            or binding is None
            or binding.authority is not self
            or capability._authority is not self
            or capability._capability is not binding.token
            or capability._pid != binding.pid
            or binding.pid != os.getpid()
            or capability._thread_id != binding.thread_id
            or binding.thread_id != threading.get_ident()
            or capability.boot_event_id != binding.boot_event_id
            or binding.boot_event_id != self._current_boot()
            or capability.identity != binding.identity
            or capability.identity_class != binding.identity_class
        ):
            raise ExecutionAuthorityError(
                "reconciliation capability is invalid, stale, or cross-boundary"
            )
        return binding

    @staticmethod
    def _require_host(capability: object) -> None:
        if capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("reconciliation capability issuance requires host authority")

    def _current_boot(self) -> str:
        def read() -> str:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            row = conn.execute(
                "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
                "ORDER BY creation_sequence DESC LIMIT 1"
            ).fetchone()
            if row is None:
                raise ExecutionAuthorityError("reconciliation authority requires a runtime boot")
            return str(row[0])

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    @staticmethod
    def _require_audit_capacity(conn: sqlite3.Connection) -> None:
        pending = int(
            conn.execute(
                "SELECT COUNT(*) FROM audit_outbox WHERE exported_unix_ns IS NULL"
            ).fetchone()[0]
        )
        if pending >= MAX_PENDING_AUDIT:
            raise ExecutionAuthorityError("audit backlog blocks dangerous reconciliation mutation")

    def _base(self) -> dict[str, Any]:
        return {
            "deployment_id": self.state.deployment_id,
            "instance_id": self.state.instance_id,
            "key_id": self.state.key_id,
            "schema_version": SCHEMA_VERSION,
        }

    def _head_logical(
        self,
        intent_id: str,
        generation: int,
        reconciliation_id: str,
        disposition: ReconciliationDisposition,
        seq: int,
    ) -> dict[str, Any]:
        return self._base() | {
            "current_generation": generation,
            "current_reconciliation_id": reconciliation_id,
            "disposition": disposition.value,
            "intent_id": intent_id,
            "updated_sequence": seq,
        }

    def _reconciliation_logical(
        self,
        reconciliation_id: str,
        intent: sqlite3.Row,
        generation: int,
        barrier_head: str,
        barrier_revision: int,
        previous: str | None,
        disposition: ReconciliationDisposition,
        seq: int,
    ) -> dict[str, Any]:
        return self._base() | {
            "action_fingerprint": str(intent["action_fingerprint"]),
            "ambiguous_attempt_id": str(intent["attempt_id"]),
            "barrier_expected_head_event_id": barrier_head,
            "barrier_expected_revision": barrier_revision,
            "creation_sequence": seq,
            "destination": str(intent["destination"]),
            "destination_contract_digest": str(intent["destination_config_digest"]),
            "disposition": disposition.value,
            "external_operation_id": intent["destination_operation_id"],
            "generation": generation,
            "intent_id": str(intent["intent_id"]),
            "intent_state": ExecutionState.OUTCOME_UNKNOWN.value,
            "previous_reconciliation_id": previous,
            "reconciliation_id": reconciliation_id,
            "updated_sequence": seq,
            "workflow_id": str(intent["workflow_id"]),
        }

    def _evidence_logical(
        self,
        evidence_id: str,
        reconciliation: sqlite3.Row,
        category: ReconciliationEvidenceCategory,
        evidence_digest: str,
        mechanism: str,
        version: str,
        identity: _CapabilityBinding,
        operation_id: str | None,
        previous: str | None,
        seq: int,
    ) -> dict[str, Any]:
        return self._base() | {
            "action_fingerprint": str(reconciliation["action_fingerprint"]),
            "ambiguous_attempt_id": str(reconciliation["ambiguous_attempt_id"]),
            "destination": str(reconciliation["destination"]),
            "destination_contract_digest": str(reconciliation["destination_contract_digest"]),
            "evidence_category": category.value,
            "evidence_digest": evidence_digest,
            "evidence_id": evidence_id,
            "external_operation_id": operation_id or reconciliation["external_operation_id"],
            "generation": int(reconciliation["generation"]),
            "intent_id": str(reconciliation["intent_id"]),
            "mutation_sequence": seq,
            "previous_evidence_id": previous,
            "reconciliation_id": str(reconciliation["reconciliation_id"]),
            "verification_mechanism": mechanism,
            "verification_version": version,
            "verifier_class": identity.identity_class,
            "verifier_identity": identity.identity,
        }

    def _proposal_logical(
        self,
        fields: Mapping[str, Any],
        proposal_digest: str,
        identity: _CapabilityBinding,
        seq: int,
    ) -> dict[str, Any]:
        return (
            self._base()
            | dict(fields)
            | {
                "mutation_sequence": seq,
                "proposal_digest": proposal_digest,
                "proposer_class": identity.identity_class,
                "proposer_identity": identity.identity,
            }
        )

    def _confirmation_logical(
        self,
        confirmation_id: str,
        proposal: sqlite3.Row,
        identity: _CapabilityBinding,
        seq: int,
    ) -> dict[str, Any]:
        return self._base() | {
            "ambiguous_attempt_id": str(proposal["ambiguous_attempt_id"]),
            "confirmation_class": identity.identity_class,
            "confirmation_id": confirmation_id,
            "confirmation_identity": identity.identity,
            "generation": int(proposal["generation"]),
            "intent_id": str(proposal["intent_id"]),
            "mutation_sequence": seq,
            "proposal_digest": str(proposal["proposal_digest"]),
            "proposal_id": str(proposal["proposal_id"]),
            "proposal_type": str(proposal["proposal_type"]),
            "reconciliation_id": str(proposal["reconciliation_id"]),
        }

    def _lifecycle_logical(
        self,
        reconciliation_id: str,
        intent_id: str,
        generation: int,
        transition: str,
        disposition: ReconciliationDisposition,
        seq: int,
        *,
        evidence_id: str | None = None,
        proposal_id: str | None = None,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._base() | {
            "confirmation_id": confirmation_id,
            "disposition": disposition.value,
            "evidence_id": evidence_id,
            "generation": generation,
            "intent_id": intent_id,
            "lifecycle_id": _new_id("reconciliation-lifecycle"),
            "mutation_sequence": seq,
            "proposal_id": proposal_id,
            "reconciliation_id": reconciliation_id,
            "transition": transition,
        }

    @staticmethod
    def _updated(
        row: sqlite3.Row, disposition: ReconciliationDisposition, seq: int
    ) -> dict[str, Any]:
        logical = dict(row)
        logical.pop("record_mac", None)
        logical.update({"disposition": disposition.value, "updated_sequence": seq})
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
    def _inspection(
        intent: sqlite3.Row,
        head: Any | None,
        reconciliation: Any | None,
        evidence: Any | None = None,
        proposal: Any | None = None,
    ) -> ReconciliationInspection:
        return ReconciliationInspection(
            None if reconciliation is None else str(reconciliation["reconciliation_id"]),
            str(intent["intent_id"]),
            str(intent["attempt_id"]),
            0 if head is None else int(head["current_generation"]),
            str(intent["action_fingerprint"]),
            str(intent["destination"]),
            str(intent["destination_config_digest"]),
            None
            if intent["destination_operation_id"] is None
            else str(intent["destination_operation_id"]),
            None if head is None else ReconciliationDisposition(str(head["disposition"])),
            None
            if proposal is None
            else ReconciliationProposalType(str(proposal["proposal_type"])),
            None
            if evidence is None
            else ReconciliationEvidenceCategory(str(evidence["evidence_category"])),
            int(intent["updated_sequence"] if head is None else head["updated_sequence"]),
        )

    @staticmethod
    def _insert_reconciliation(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            "INSERT INTO execution_reconciliations VALUES("
            + ",".join("?" for _ in range(21))
            + ")",
            tuple(
                v[key]
                for key in (
                    "reconciliation_id",
                    "instance_id",
                    "deployment_id",
                    "schema_version",
                    "intent_id",
                    "ambiguous_attempt_id",
                    "intent_state",
                    "generation",
                    "action_fingerprint",
                    "destination",
                    "destination_contract_digest",
                    "external_operation_id",
                    "workflow_id",
                    "barrier_expected_head_event_id",
                    "barrier_expected_revision",
                    "previous_reconciliation_id",
                    "disposition",
                    "creation_sequence",
                    "updated_sequence",
                    "key_id",
                )
            )
            + (mac,),
        )

    @staticmethod
    def _update_reconciliation(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            "UPDATE execution_reconciliations SET disposition=?, updated_sequence=?, key_id=?, "
            "record_mac=? WHERE reconciliation_id=?",
            (v["disposition"], v["updated_sequence"], v["key_id"], mac, v["reconciliation_id"]),
        )

    @staticmethod
    def _upsert_head(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            """INSERT INTO execution_reconciliation_heads VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(intent_id) DO UPDATE SET current_generation=excluded.current_generation,
            current_reconciliation_id=excluded.current_reconciliation_id,
            disposition=excluded.disposition, updated_sequence=excluded.updated_sequence,
            key_id=excluded.key_id, record_mac=excluded.record_mac""",
            (
                v["intent_id"],
                v["instance_id"],
                v["deployment_id"],
                v["schema_version"],
                v["current_generation"],
                v["current_reconciliation_id"],
                v["disposition"],
                v["updated_sequence"],
                v["key_id"],
                mac,
            ),
        )

    @staticmethod
    def _insert_evidence(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "evidence_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "reconciliation_id",
            "intent_id",
            "ambiguous_attempt_id",
            "generation",
            "action_fingerprint",
            "destination",
            "destination_contract_digest",
            "external_operation_id",
            "verification_mechanism",
            "verification_version",
            "evidence_digest",
            "verifier_identity",
            "verifier_class",
            "evidence_category",
            "previous_evidence_id",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_reconciliation_evidence VALUES("
            + ",".join("?" for _ in range(22))
            + ")",
            tuple(v[key] for key in keys) + (mac,),
        )

    @staticmethod
    def _insert_proposal(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "proposal_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "reconciliation_id",
            "intent_id",
            "ambiguous_attempt_id",
            "generation",
            "action_fingerprint",
            "destination",
            "destination_contract_digest",
            "evidence_id",
            "evidence_category",
            "evidence_digest",
            "proposal_type",
            "proposer_identity",
            "proposer_class",
            "proposal_digest",
            "barrier_expected_head_event_id",
            "barrier_expected_revision",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_reconciliation_proposals VALUES("
            + ",".join("?" for _ in range(23))
            + ")",
            tuple(v[key] for key in keys) + (mac,),
        )

    @staticmethod
    def _insert_confirmation(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "confirmation_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "reconciliation_id",
            "proposal_id",
            "proposal_digest",
            "intent_id",
            "ambiguous_attempt_id",
            "generation",
            "proposal_type",
            "confirmation_identity",
            "confirmation_class",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_reconciliation_confirmations VALUES("
            + ",".join("?" for _ in range(16))
            + ")",
            tuple(v[key] for key in keys) + (mac,),
        )

    @staticmethod
    def _insert_lifecycle(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        keys = (
            "lifecycle_id",
            "instance_id",
            "deployment_id",
            "schema_version",
            "reconciliation_id",
            "intent_id",
            "generation",
            "transition",
            "evidence_id",
            "proposal_id",
            "confirmation_id",
            "disposition",
            "mutation_sequence",
            "key_id",
        )
        conn.execute(
            "INSERT INTO execution_reconciliation_lifecycle VALUES("
            + ",".join("?" for _ in range(15))
            + ")",
            tuple(v[key] for key in keys) + (mac,),
        )


def verify_reconciliation_materialized(
    authority_state: Any,
    connection: sqlite3.Connection,
    expected: dict[str, dict[str, str]],
) -> None:
    extension = connection.execute(
        "SELECT schema_version FROM execution_reconciliation_extensions WHERE singleton=1"
    ).fetchone()
    if extension is None or extension[0] != RECONCILIATION_SCHEMA_VERSION:
        raise StateVerificationError("reconciliation extension marker is invalid")
    execution = ExecutionAuthority.__new__(ExecutionAuthority)
    execution.state = authority_state
    authority = ReconciliationAuthority(execution)
    specs = (
        ("execution_reconciliation_head", "execution_reconciliation_heads", "intent_id"),
        ("execution_reconciliation", "execution_reconciliations", "reconciliation_id"),
        ("execution_reconciliation_evidence", "execution_reconciliation_evidence", "evidence_id"),
        ("execution_reconciliation_proposal", "execution_reconciliation_proposals", "proposal_id"),
        (
            "execution_reconciliation_confirmation",
            "execution_reconciliation_confirmations",
            "confirmation_id",
        ),
        (
            "execution_reconciliation_lifecycle",
            "execution_reconciliation_lifecycle",
            "lifecycle_id",
        ),
    )
    for kind, table, key in specs:
        actual: dict[str, str] = {}
        for row in connection.execute(f"SELECT * FROM {table}"):
            _verified_reconciliation_row(authority, connection, table, key, str(row[key]))
            actual[str(row[key])] = str(row["record_mac"])
        if actual != expected[kind]:
            raise StateVerificationError(f"{kind} materialized state mismatch")
    for head in connection.execute("SELECT * FROM execution_reconciliation_heads"):
        current = connection.execute(
            "SELECT * FROM execution_reconciliations WHERE reconciliation_id=?",
            (head["current_reconciliation_id"],),
        ).fetchone()
        if current is None or any(
            head[name] != current[other]
            for name, other in (
                ("intent_id", "intent_id"),
                ("current_generation", "generation"),
                ("disposition", "disposition"),
            )
        ):
            raise StateVerificationError("reconciliation head disagrees with current generation")
        generations = connection.execute(
            "SELECT reconciliation_id,generation,previous_reconciliation_id "
            "FROM execution_reconciliations WHERE intent_id=? ORDER BY generation",
            (head["intent_id"],),
        ).fetchall()
        if len(generations) > MAX_RECONCILIATIONS_PER_INTENT:
            raise StateVerificationError("reconciliation generation bound is exceeded")
        previous: str | None = None
        for expected_generation, item in enumerate(generations, 1):
            if (
                int(item["generation"]) != expected_generation
                or item["previous_reconciliation_id"] != previous
            ):
                raise StateVerificationError("reconciliation generation chain is invalid")
            previous = str(item["reconciliation_id"])
    for reconciliation in connection.execute("SELECT * FROM execution_reconciliations"):
        intent = connection.execute(
            "SELECT * FROM execution_intents WHERE intent_id=?", (reconciliation["intent_id"],)
        ).fetchone()
        lifecycles = connection.execute(
            "SELECT * FROM execution_reconciliation_lifecycle WHERE reconciliation_id=? "
            "ORDER BY mutation_sequence",
            (reconciliation["reconciliation_id"],),
        ).fetchall()
        if intent is None or not lifecycles or lifecycles[0]["transition"] != "BEGIN":
            raise StateVerificationError("reconciliation genesis or parent intent is missing")
        if (
            reconciliation["intent_state"] != ExecutionState.OUTCOME_UNKNOWN.value
            or reconciliation["ambiguous_attempt_id"] != intent["attempt_id"]
            or reconciliation["action_fingerprint"] != intent["action_fingerprint"]
            or reconciliation["destination"] != intent["destination"]
            or reconciliation["destination_contract_digest"] != intent["destination_config_digest"]
            or lifecycles[-1]["disposition"] != reconciliation["disposition"]
        ):
            raise StateVerificationError("reconciliation binding or lifecycle is inconsistent")
        if len(lifecycles) > MAX_RECONCILIATION_LIFECYCLE_PER_INTENT:
            raise StateVerificationError("reconciliation lifecycle bound is exceeded")
        machine = ReconciliationDisposition.ACTIVE.value
        for position, lifecycle in enumerate(lifecycles):
            if int(lifecycle["generation"]) != int(reconciliation["generation"]):
                raise StateVerificationError("reconciliation lifecycle generation is inconsistent")
            transition = str(lifecycle["transition"])
            if position == 0:
                if transition != "BEGIN" or lifecycle["disposition"] != machine:
                    raise StateVerificationError("reconciliation lifecycle genesis is invalid")
                continue
            if transition in {
                ReconciliationEvidenceCategory.CONFLICT.value,
                ReconciliationEvidenceCategory.INSUFFICIENT.value,
            }:
                if machine not in {
                    ReconciliationDisposition.ACTIVE.value,
                    ReconciliationDisposition.PROPOSED.value,
                }:
                    raise StateVerificationError("reconciliation evidence transition is illegal")
                machine = transition
            elif transition.startswith("PROPOSE_"):
                if machine != ReconciliationDisposition.ACTIVE.value:
                    raise StateVerificationError("reconciliation proposal transition is illegal")
                machine = ReconciliationDisposition.PROPOSED.value
            elif transition == "ABANDON":
                if machine not in {
                    ReconciliationDisposition.ACTIVE.value,
                    ReconciliationDisposition.PROPOSED.value,
                }:
                    raise StateVerificationError("reconciliation abandonment transition is illegal")
                machine = ReconciliationDisposition.ABANDONED.value
            elif transition == "CONFIRM_COMPLETED":
                if machine != ReconciliationDisposition.PROPOSED.value:
                    raise StateVerificationError("completed confirmation transition is illegal")
                machine = ReconciliationDisposition.CONFIRMED_COMPLETED.value
            elif transition == "CONFIRM_FAILED_NO_EFFECT":
                if machine != ReconciliationDisposition.PROPOSED.value:
                    raise StateVerificationError("no-effect confirmation transition is illegal")
                machine = ReconciliationDisposition.CONFIRMED_NO_EFFECT.value
            else:
                raise StateVerificationError("unknown reconciliation lifecycle transition")
            if lifecycle["disposition"] != machine:
                raise StateVerificationError("reconciliation lifecycle disposition is inconsistent")
        if machine != reconciliation["disposition"]:
            raise StateVerificationError("replayed reconciliation lifecycle disagrees with state")
        evidence_rows = connection.execute(
            "SELECT * FROM execution_reconciliation_evidence WHERE reconciliation_id=? "
            "ORDER BY mutation_sequence",
            (reconciliation["reconciliation_id"],),
        ).fetchall()
        if len(evidence_rows) > MAX_EVIDENCE_PER_INTENT:
            raise StateVerificationError("reconciliation evidence bound is exceeded")
        previous_evidence: str | None = None
        for evidence in evidence_rows:
            if (
                evidence["intent_id"] != reconciliation["intent_id"]
                or evidence["ambiguous_attempt_id"] != reconciliation["ambiguous_attempt_id"]
                or int(evidence["generation"]) != int(reconciliation["generation"])
                or evidence["action_fingerprint"] != reconciliation["action_fingerprint"]
                or evidence["destination"] != reconciliation["destination"]
                or evidence["destination_contract_digest"]
                != reconciliation["destination_contract_digest"]
                or evidence["previous_evidence_id"] != previous_evidence
            ):
                raise StateVerificationError("reconciliation evidence binding is inconsistent")
            previous_evidence = str(evidence["evidence_id"])
        proposal = connection.execute(
            "SELECT * FROM execution_reconciliation_proposals WHERE reconciliation_id=?",
            (reconciliation["reconciliation_id"],),
        ).fetchone()
        if proposal is not None:
            evidence = connection.execute(
                "SELECT * FROM execution_reconciliation_evidence WHERE evidence_id=?",
                (proposal["evidence_id"],),
            ).fetchone()
            if evidence is None:
                raise StateVerificationError("reconciliation proposal evidence is missing")
            digest_fields = {
                "action_fingerprint": str(proposal["action_fingerprint"]),
                "ambiguous_attempt_id": str(proposal["ambiguous_attempt_id"]),
                "barrier_expected_head_event_id": str(proposal["barrier_expected_head_event_id"]),
                "barrier_expected_revision": int(proposal["barrier_expected_revision"]),
                "destination": str(proposal["destination"]),
                "destination_contract_digest": str(proposal["destination_contract_digest"]),
                "evidence_category": str(proposal["evidence_category"]),
                "evidence_digest": str(proposal["evidence_digest"]),
                "evidence_id": str(proposal["evidence_id"]),
                "generation": int(proposal["generation"]),
                "intent_id": str(proposal["intent_id"]),
                "proposal_id": str(proposal["proposal_id"]),
                "proposal_type": str(proposal["proposal_type"]),
                "reconciliation_id": str(proposal["reconciliation_id"]),
            }
            if (
                hashlib.sha256(canonical_text(digest_fields).encode()).hexdigest()
                != proposal["proposal_digest"]
                or proposal["evidence_digest"] != evidence["evidence_digest"]
                or proposal["evidence_category"] != evidence["evidence_category"]
                or proposal["ambiguous_attempt_id"] != reconciliation["ambiguous_attempt_id"]
            ):
                raise StateVerificationError(
                    "reconciliation proposal digest or evidence is inconsistent"
                )
        confirmation = connection.execute(
            "SELECT * FROM execution_reconciliation_confirmations WHERE reconciliation_id=?",
            (reconciliation["reconciliation_id"],),
        ).fetchone()
        if reconciliation["disposition"] in {
            ReconciliationDisposition.CONFIRMED_COMPLETED.value,
            ReconciliationDisposition.CONFIRMED_NO_EFFECT.value,
        }:
            expected_state = (
                ExecutionState.COMPLETED.value
                if reconciliation["disposition"]
                == ReconciliationDisposition.CONFIRMED_COMPLETED.value
                else ExecutionState.FAILED_NO_EFFECT.value
            )
            if (
                confirmation is None
                or proposal is None
                or intent["state"] != expected_state
                or confirmation["proposal_id"] != proposal["proposal_id"]
                or confirmation["proposal_digest"] != proposal["proposal_digest"]
                or confirmation["proposal_type"] != proposal["proposal_type"]
            ):
                raise StateVerificationError("confirmed reconciliation lacks terminal lineage")
        elif confirmation is not None:
            raise StateVerificationError("nonterminal reconciliation has a confirmation")


def _bounded_identifier(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not _ID.fullmatch(value)
        or len(value.encode()) > MAX_IDENTITY_BYTES
    ):
        raise ValueError(f"{label} is invalid or exceeds its bound")


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
