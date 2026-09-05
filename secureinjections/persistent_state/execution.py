"""Isolated concurrent execution-authority primitives for Agent Boundary v0.3c1.

This module deliberately has no Gateway integration.  Its capabilities authorize
state transitions only; the test fake destination is the sole dispatch consumer.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any, Final

from .canonical import canonical_text, strict_json_object
from .models import (
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionDecisionHandle,
    ExecutionIntentRecord,
    ExecutionSecurityConfiguration,
    ExecutionState,
    ExecutionStateConflict,
    IdempotencyClass,
    StateAuthenticationError,
    StateVerificationError,
    UnknownAuthorityRecord,
    WorkflowCASConflict,
)
from .store import (
    _EXECUTION_EXTENSION_CAPABILITY,
    SCHEMA_VERSION,
    PersistentSecurityState,
    _change,
    _consumption_logical_from_row,
    _decode_items,
    _encode_items,
    _event_logical_from_row,
    _new_id,
    _verify_common_record,
    _workflow_logical_from_row,
)

EXECUTION_SCHEMA_VERSION: Final = "execution-authority-v0.3c1"
MAX_ACTION_BYTES: Final = 65_536
MAX_METADATA_BYTES: Final = 8_192
MAX_LEASE_NS: Final = 300_000_000_000
MAX_LIFECYCLE_RECORDS: Final = 256
_HOST_EXECUTION_AUTHORITY_CAPABILITY = object()
_HANDLE_ISSUER = object()
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


_TABLES = (
    """CREATE TABLE IF NOT EXISTS execution_extensions (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_decisions (
    decision_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, source_output_event_id TEXT NOT NULL UNIQUE,
    proposal_event_id TEXT NOT NULL, workflow_id TEXT NOT NULL, decision TEXT NOT NULL,
    reason_code TEXT NOT NULL, action_fingerprint TEXT, intent_id TEXT UNIQUE,
    creation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_intents (
    intent_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, key_id TEXT NOT NULL, workflow_id TEXT NOT NULL,
    source_turn_event_id TEXT NOT NULL, source_output_event_id TEXT NOT NULL UNIQUE,
    proposal_event_id TEXT NOT NULL, decision_id TEXT NOT NULL UNIQUE,
    action_type TEXT NOT NULL, normalized_action_json TEXT NOT NULL,
    action_fingerprint TEXT NOT NULL, destination_registry TEXT NOT NULL,
    destination TEXT NOT NULL, destination_config_digest TEXT NOT NULL,
    idempotency_class TEXT NOT NULL, ancestry_event_ids_json TEXT NOT NULL,
    content_digests_json TEXT NOT NULL, policy_config_digest TEXT NOT NULL,
    creation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence), state TEXT NOT NULL,
    claim_generation INTEGER NOT NULL, active_claim_id TEXT, worker_id TEXT,
    boot_event_id TEXT, attempt_id TEXT, lease_deadline_ns INTEGER,
    idempotency_key TEXT, destination_operation_id TEXT, completion_sequence INTEGER,
    result_digest TEXT, updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_workflow_barriers (
    workflow_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, active_intent_id TEXT, status TEXT NOT NULL,
    expected_head_event_id TEXT NOT NULL, expected_revision INTEGER NOT NULL,
    updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_workers (
    worker_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, boot_event_id TEXT NOT NULL, process_nonce_digest TEXT NOT NULL,
    registration_metadata_json TEXT NOT NULL, registration_sequence INTEGER NOT NULL,
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS execution_lifecycle (
    lifecycle_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL, intent_id TEXT NOT NULL, claim_generation INTEGER NOT NULL,
    claim_id TEXT, worker_id TEXT, boot_event_id TEXT, attempt_id TEXT,
    transition TEXT NOT NULL, destination_operation_id TEXT, result_digest TEXT,
    metadata_json TEXT NOT NULL,
    mutation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL, record_mac TEXT NOT NULL,
    UNIQUE(intent_id, mutation_sequence))""",
    """CREATE TABLE IF NOT EXISTS execution_security_configuration (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL, schema_version TEXT NOT NULL, mode TEXT NOT NULL,
    epoch INTEGER NOT NULL, configuration_digest TEXT NOT NULL,
    worker_attach_digest TEXT NOT NULL, updated_sequence INTEGER NOT NULL
    REFERENCES state_mutations(sequence), key_id TEXT NOT NULL, record_mac TEXT NOT NULL)""",
)


class _OpaqueHandle:
    __slots__ = ("_authority", "_capability", "_pid", "_thread_id")

    def __init__(self, issuer: object, authority: ExecutionAuthority, capability: object) -> None:
        if issuer is not _HANDLE_ISSUER:
            raise TypeError("authority handles cannot be constructed by callers")
        self._authority = authority
        self._capability = capability
        self._pid = os.getpid()
        self._thread_id = threading.get_ident()

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("authority handles are immutable")
        object.__setattr__(self, name, value)

    def __copy__(self) -> object:
        raise TypeError("authority handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> object:
        raise TypeError("authority handles cannot be copied")

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("authority handles are process-local and non-serializable")


class WorkerHandle(_OpaqueHandle):
    __slots__ = ("worker_id", "boot_event_id")

    def __init__(
        self,
        issuer: object,
        authority: ExecutionAuthority,
        capability: object,
        worker_id: str,
        boot_event_id: str,
    ) -> None:
        super().__init__(issuer, authority, capability)
        self.worker_id = worker_id
        self.boot_event_id = boot_event_id


class ClaimHandle(_OpaqueHandle):
    __slots__ = ("intent_id", "claim_id", "generation", "worker_id", "boot_event_id", "attempt_id")

    def __init__(
        self,
        issuer: object,
        authority: ExecutionAuthority,
        capability: object,
        *,
        intent_id: str,
        claim_id: str,
        generation: int,
        worker_id: str,
        boot_event_id: str,
        attempt_id: str,
    ) -> None:
        super().__init__(issuer, authority, capability)
        self.intent_id, self.claim_id, self.generation = intent_id, claim_id, generation
        self.worker_id, self.boot_event_id, self.attempt_id = worker_id, boot_event_id, attempt_id


class DispatchHandle(ClaimHandle):
    __slots__ = (
        "action_fingerprint",
        "destination_registry",
        "destination",
        "destination_config_digest",
        "idempotency_key",
    )

    def __init__(
        self, issuer: object, authority: ExecutionAuthority, capability: object, **values: Any
    ) -> None:
        self.action_fingerprint = str(values.pop("action_fingerprint"))
        self.destination_registry = str(values.pop("destination_registry"))
        self.destination = str(values.pop("destination"))
        self.destination_config_digest = str(values.pop("destination_config_digest"))
        key = values.pop("idempotency_key")
        self.idempotency_key = None if key is None else str(key)
        super().__init__(issuer, authority, capability, **values)


def execution_schema_present(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_extensions'"
        ).fetchone()
        is not None
    )


def execution_expected_entities() -> dict[str, dict[str, str]]:
    return {
        "execution_decision": {},
        "execution_intent": {},
        "execution_workflow_barrier": {},
        "execution_worker": {},
        "execution_lifecycle": {},
        "execution_security_configuration": {},
    }


def _install(connection: sqlite3.Connection) -> None:
    for statement in _TABLES:
        connection.execute(statement)
    row = connection.execute(
        "SELECT schema_version FROM execution_extensions WHERE singleton=1"
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO execution_extensions VALUES(1,?)", (EXECUTION_SCHEMA_VERSION,)
        )
    elif row[0] != EXECUTION_SCHEMA_VERSION:
        raise StateVerificationError("execution authority schema is incompatible")
    from .reconciliation import install_reconciliation_schema

    install_reconciliation_schema(connection)
    from .recovery import install_recovery_schema

    install_recovery_schema(connection)


def normalize_action(value: Mapping[str, Any] | str) -> tuple[dict[str, Any], str, str]:
    if isinstance(value, str):
        action = strict_json_object(value)
    elif isinstance(value, Mapping):
        action = dict(value)
    else:
        raise TypeError("action must be a canonical object or canonical JSON")
    rendered = canonical_text(action)
    if len(rendered.encode()) > MAX_ACTION_BYTES:
        raise ValueError("normalized action exceeds execution bound")
    fingerprint = hashlib.sha256(rendered.encode()).hexdigest()
    action_type = action.get("action")
    if not isinstance(action_type, str) or not _ID.fullmatch(action_type):
        raise ValueError("action type is missing or invalid")
    return action, rendered, fingerprint


def _logical(row: sqlite3.Row, kind: str) -> dict[str, Any]:
    data = dict(row)
    data.pop("record_mac", None)
    for key in ("normalized_action_json", "registration_metadata_json", "metadata_json"):
        if key in data:
            renamed = key.removesuffix("_json")
            data[renamed] = strict_json_object(str(data.pop(key)))
    for key in ("ancestry_event_ids_json", "content_digests_json"):
        if key in data:
            data[key.removesuffix("_json")] = _decode_items(str(data.pop(key)))
    return data


def _mac(state: PersistentSecurityState, kind: str, logical: Mapping[str, Any]) -> str:
    return state._execution_record_mac(_EXECUTION_EXTENSION_CAPABILITY, kind, logical)


def _verified_row(
    state: PersistentSecurityState, connection: sqlite3.Connection, table: str, key: str, value: str
) -> sqlite3.Row:
    row = connection.execute(f"SELECT * FROM {table} WHERE {key}=?", (value,)).fetchone()
    if row is None:
        raise UnknownAuthorityRecord(f"unknown execution authority record: {value}")
    kind = {
        "execution_decisions": "execution_decision",
        "execution_intents": "execution_intent",
        "execution_workflow_barriers": "execution_workflow_barrier",
        "execution_workers": "execution_worker",
        "execution_lifecycle": "execution_lifecycle",
        "execution_security_configuration": "execution_security_configuration",
    }[table]
    logical = _logical(row, kind)
    _verify_common_record(state, logical)
    if not state._verify_execution_record_mac(
        _EXECUTION_EXTENSION_CAPABILITY, kind, logical, str(row["record_mac"])
    ):
        raise StateAuthenticationError(f"{kind} MAC is invalid")
    return row


def _verified_workflow_row(
    state: PersistentSecurityState, connection: sqlite3.Connection, workflow_id: str
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM workflow_state WHERE workflow_id=?", (workflow_id,)
    ).fetchone()
    if row is None:
        raise UnknownAuthorityRecord("workflow does not exist")
    logical = _workflow_logical_from_row(row)
    _verify_common_record(state, logical)
    if not state._verify_execution_record_mac(
        _EXECUTION_EXTENSION_CAPABILITY,
        "workflow_state",
        logical,
        str(row["record_mac"]),
    ):
        raise StateAuthenticationError("workflow state MAC is invalid")
    return row


class ExecutionAuthority:
    """Host-owned v0.3c1 authority. It cannot invoke production destinations."""

    def __init__(self, capability: object, state: PersistentSecurityState) -> None:
        if capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("execution authority construction requires host authority")
        self.state = state
        self._worker_capabilities: dict[str, object] = {}
        self._claim_capabilities: dict[tuple[str, int], object] = {}
        state._enable_execution_extension(_EXECUTION_EXTENSION_CAPABILITY, _install)
        state.verify_full()

    @classmethod
    def _for_host(cls, capability: object, state: PersistentSecurityState) -> ExecutionAuthority:
        return cls(capability, state)

    def get_security_configuration(self) -> ExecutionSecurityConfiguration | None:
        """Return the authenticated shared c2 mode/configuration binding, if activated."""

        def read() -> ExecutionSecurityConfiguration | None:
            connection = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            row = connection.execute(
                "SELECT * FROM execution_security_configuration WHERE singleton=1"
            ).fetchone()
            if row is None:
                return None
            verified = _verified_row(
                self.state,
                connection,
                "execution_security_configuration",
                "singleton",
                "1",
            )
            return ExecutionSecurityConfiguration(
                str(verified["mode"]),
                int(verified["epoch"]),
                str(verified["configuration_digest"]),
                str(verified["worker_attach_digest"]),
                int(verified["updated_sequence"]),
            )

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def current_runtime_boot_event_id(self) -> str:
        """Return the authenticated latest runtime boot for host integration checks."""

        def read() -> str:
            connection = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            row = connection.execute(
                "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
                "ORDER BY creation_sequence DESC LIMIT 1"
            ).fetchone()
            if row is None:
                raise ExecutionAuthorityError("runtime boot authority is absent")
            event = self.state._execution_verify_event(
                _EXECUTION_EXTENSION_CAPABILITY, str(row["event_id"])
            )
            if event["event_type"] != "runtime_boot":
                raise ExecutionAuthorityError("latest boot authority is malformed")
            return str(event["event_id"])

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def update_security_configuration(
        self,
        host_capability: object,
        *,
        expected_epoch: int,
        configuration_digest: str,
        worker_attach_digest: str,
        expected_boot_event_id: str | None = None,
    ) -> ExecutionSecurityConfiguration:
        """Atomically activate/advance the authenticated store-wide c2 configuration."""

        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("security configuration update requires host authority")
        if not _DIGEST.fullmatch(configuration_digest) or not _DIGEST.fullmatch(
            worker_attach_digest
        ):
            raise ValueError("security configuration digests must be SHA-256 values")
        if expected_epoch < 0:
            raise ValueError("security configuration epoch cannot be negative")
        if expected_boot_event_id is not None and not _ID.fullmatch(expected_boot_event_id):
            raise ValueError("expected runtime boot event ID is invalid")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[
            dict[str, Any],
            Callable[[sqlite3.Connection], None],
            ExecutionSecurityConfiguration,
        ]:
            if expected_boot_event_id is not None:
                current_boot = conn.execute(
                    "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
                    "ORDER BY creation_sequence DESC LIMIT 1"
                ).fetchone()
                if current_boot is None:
                    raise ExecutionBindingError("runtime boot authority is absent")
                verified_boot = self.state._execution_verify_event(
                    _EXECUTION_EXTENSION_CAPABILITY, str(current_boot["event_id"])
                )
                if (
                    verified_boot["event_type"] != "runtime_boot"
                    or verified_boot["event_id"] != expected_boot_event_id
                ):
                    raise ExecutionBindingError(
                        "security configuration update belongs to a stale runtime boot"
                    )
            row = conn.execute(
                "SELECT * FROM execution_security_configuration WHERE singleton=1"
            ).fetchone()
            actual_epoch = 0
            if row is not None:
                row = _verified_row(
                    self.state,
                    conn,
                    "execution_security_configuration",
                    "singleton",
                    "1",
                )
                actual_epoch = int(row["epoch"])
            if actual_epoch != expected_epoch:
                raise ExecutionBindingError("security configuration epoch update lost CAS")
            epoch = (
                actual_epoch
                if row is not None and row["configuration_digest"] == configuration_digest
                else actual_epoch + 1
            )
            logical = {
                "configuration_digest": configuration_digest,
                "deployment_id": self.state.deployment_id,
                "epoch": epoch,
                "instance_id": self.state.instance_id,
                "key_id": self.state.key_id,
                "mode": "C2_REQUIRED",
                "schema_version": SCHEMA_VERSION,
                "singleton": 1,
                "updated_sequence": seq,
                "worker_attach_digest": worker_attach_digest,
            }
            mac = _mac(self.state, "execution_security_configuration", logical)
            payload = {
                "changes": [_change("execution_security_configuration", "1", mac)],
                "operation": "UPDATE_EXECUTION_SECURITY_CONFIGURATION",
            }

            def apply(target: sqlite3.Connection) -> None:
                target.execute(
                    """INSERT INTO execution_security_configuration VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(singleton) DO UPDATE SET
                    mode=excluded.mode, epoch=excluded.epoch,
                    configuration_digest=excluded.configuration_digest,
                    worker_attach_digest=excluded.worker_attach_digest,
                    updated_sequence=excluded.updated_sequence, key_id=excluded.key_id,
                    record_mac=excluded.record_mac""",
                    (
                        1,
                        logical["instance_id"],
                        logical["deployment_id"],
                        logical["schema_version"],
                        logical["mode"],
                        logical["epoch"],
                        logical["configuration_digest"],
                        logical["worker_attach_digest"],
                        logical["updated_sequence"],
                        logical["key_id"],
                        mac,
                    ),
                )

            return (
                payload,
                apply,
                ExecutionSecurityConfiguration(
                    "C2_REQUIRED", epoch, configuration_digest, worker_attach_digest, seq
                ),
            )

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY,
            "UPDATE_EXECUTION_SECURITY_CONFIGURATION",
            build,
        )

    def prepare_execution(
        self,
        host_capability: object,
        *,
        workflow_id: str,
        expected_head_event_id: str,
        expected_revision: int,
        source_turn_event_id: str,
        source_output_event_id: str,
        proposal_event_id: str,
        action: Mapping[str, Any] | str,
        destination_registry: str,
        destination: str,
        destination_config_digest: str,
        idempotency_class: IdempotencyClass,
        ancestry_event_ids: tuple[str, ...] = (),
        content_digests: tuple[str, ...] = (),
        policy_config_digest: str,
    ) -> ExecutionDecisionHandle:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("ALLOW preparation requires host authority")
        self.state._execution_inject(_EXECUTION_EXTENSION_CAPABILITY, "before_intent_mutation")
        normalized, action_json, fingerprint = normalize_action(action)
        self._validate_prepare_fields(
            workflow_id,
            destination_registry,
            destination,
            destination_config_digest,
            policy_config_digest,
            ancestry_event_ids,
            content_digests,
        )
        if not isinstance(idempotency_class, IdempotencyClass):
            raise TypeError("idempotency class must be host-selected")
        if idempotency_class is IdempotencyClass.TRANSACTIONALLY_LOCAL:
            raise ExecutionAuthorityError("v0.3c1 has no transactionally-local destination")
        decision_id, intent_id = _new_id("decision"), _new_id("intent")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ExecutionDecisionHandle]:
            source = self.state._execution_verify_event(
                _EXECUTION_EXTENSION_CAPABILITY, source_output_event_id
            )
            turn = self.state._execution_verify_event(
                _EXECUTION_EXTENSION_CAPABILITY, source_turn_event_id
            )
            proposal = self.state._execution_verify_event(
                _EXECUTION_EXTENSION_CAPABILITY, proposal_event_id
            )
            source_logical, turn_logical, proposal_logical = (
                _event_logical_from_row(source),
                _event_logical_from_row(turn),
                _event_logical_from_row(proposal),
            )
            if source_logical["event_type"] != "model_output":
                raise ExecutionBindingError("source is not an authenticated model output")
            if turn_logical["event_type"] != "model_turn":
                raise ExecutionBindingError("source turn is not an authenticated model turn")
            if source_turn_event_id not in source_logical["parent_event_ids"]:
                raise ExecutionBindingError("model output is not bound to source turn")
            if source_output_event_id not in proposal_logical["parent_event_ids"]:
                raise ExecutionBindingError("proposal is not causally bound to model output")
            if any(
                item["correlation_id"] != workflow_id
                for item in (source_logical, turn_logical, proposal_logical)
            ):
                raise ExecutionBindingError("execution events are bound to another workflow")
            recorded = source_logical["attributes"].get("action_fingerprint") or proposal_logical[
                "attributes"
            ].get("action_fingerprint")
            if recorded != fingerprint:
                raise ExecutionBindingError(
                    "normalized action fingerprint does not match source authority"
                )
            workflow = conn.execute(
                "SELECT * FROM workflow_state WHERE workflow_id=?", (workflow_id,)
            ).fetchone()
            if workflow is None:
                raise UnknownAuthorityRecord("workflow does not exist")
            if (
                int(workflow["revision"]) != expected_revision
                or workflow["head_event_id"] != expected_head_event_id
            ):
                raise WorkflowCASConflict("workflow head or revision is stale")
            if expected_head_event_id != proposal_event_id:
                raise ExecutionBindingError("proposal is not the expected workflow head")
            barrier = conn.execute(
                "SELECT * FROM execution_workflow_barriers WHERE workflow_id=?", (workflow_id,)
            ).fetchone()
            if barrier is not None:
                _verified_row(
                    self.state, conn, "execution_workflow_barriers", "workflow_id", workflow_id
                )
                if barrier["active_intent_id"] is not None or barrier["status"] != "ACTIVE":
                    raise ExecutionStateConflict("workflow has an active execution barrier")
            if conn.execute(
                "SELECT 1 FROM execution_decisions WHERE source_output_event_id=?",
                (source_output_event_id,),
            ).fetchone():
                raise ExecutionStateConflict("source output already has a terminal decision")
            if conn.execute(
                "SELECT 1 FROM consumptions WHERE instance_id=? "
                "AND token_kind='model_output' AND token_id=?",
                (self.state.instance_id, source_output_event_id),
            ).fetchone():
                raise ExecutionStateConflict("source output is already consumed")
            idempotency_key = (
                secrets.token_hex(32)
                if idempotency_class is IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY
                else None
            )
            decision = self._decision_logical(
                decision_id,
                source_output_event_id,
                proposal_event_id,
                workflow_id,
                "ALLOW",
                "HOST_ALLOW",
                fingerprint,
                intent_id,
                seq,
            )
            intent = self._intent_logical(
                intent_id=intent_id,
                workflow_id=workflow_id,
                source_turn_event_id=source_turn_event_id,
                source_output_event_id=source_output_event_id,
                proposal_event_id=proposal_event_id,
                decision_id=decision_id,
                action_type=str(normalized["action"]),
                normalized_action=normalized,
                action_fingerprint=fingerprint,
                destination_registry=destination_registry,
                destination=destination,
                destination_config_digest=destination_config_digest,
                idempotency_class=idempotency_class.value,
                ancestry_event_ids=ancestry_event_ids,
                content_digests=content_digests,
                policy_config_digest=policy_config_digest,
                creation_sequence=seq,
                state=ExecutionState.READY.value,
                claim_generation=0,
                idempotency_key=idempotency_key,
                updated_sequence=seq,
            )
            barrier_logical = self._barrier_logical(
                workflow_id,
                intent_id,
                "WAITING_EXECUTION",
                expected_head_event_id,
                expected_revision,
                seq,
            )
            consumption_id = _new_id("consumption")
            consumption = {
                "action_fingerprint": fingerprint,
                "commit_sequence": seq,
                "consuming_event_id": proposal_event_id,
                "consumption_id": consumption_id,
                "deployment_id": self.state.deployment_id,
                "instance_id": self.state.instance_id,
                "key_id": self.state.key_id,
                "schema_version": SCHEMA_VERSION,
                "token_id": source_output_event_id,
                "token_kind": "model_output",
            }
            lifecycle = self._lifecycle_logical(
                intent_id,
                0,
                None,
                None,
                None,
                None,
                "READY",
                None,
                None,
                {"decision": "ALLOW"},
                seq,
            )
            records = (
                ("execution_decision", decision_id, decision),
                ("execution_intent", intent_id, intent),
                ("execution_workflow_barrier", workflow_id, barrier_logical),
                ("consumption", f"model_output:{source_output_event_id}", consumption),
                ("execution_lifecycle", lifecycle["lifecycle_id"], lifecycle),
            )
            macs = {
                identifier: _mac(self.state, kind, logical) for kind, identifier, logical in records
            }
            payload = {
                "changes": [
                    _change(kind, identifier, macs[identifier]) for kind, identifier, _ in records
                ],
                "operation": "PREPARE_EXECUTION",
            }

            def apply(target: sqlite3.Connection) -> None:
                self.state._execution_inject(
                    _EXECUTION_EXTENSION_CAPABILITY, "during_intent_mutation"
                )
                self._insert_decision(target, decision, macs[decision_id])
                self._insert_intent(target, intent, macs[intent_id])
                self._upsert_barrier(target, barrier_logical, macs[workflow_id])
                target.execute(
                    "INSERT INTO consumptions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        consumption_id,
                        self.state.instance_id,
                        self.state.deployment_id,
                        SCHEMA_VERSION,
                        "model_output",
                        source_output_event_id,
                        proposal_event_id,
                        fingerprint,
                        seq,
                        self.state.key_id,
                        macs[f"model_output:{source_output_event_id}"],
                    ),
                )
                self._insert_lifecycle(target, lifecycle, macs[str(lifecycle["lifecycle_id"])])

            return (
                payload,
                apply,
                ExecutionDecisionHandle(
                    decision_id, source_output_event_id, "ALLOW", intent_id, seq
                ),
            )

        result = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "PREPARE_EXECUTION", build
        )
        self.state._execution_inject(_EXECUTION_EXTENSION_CAPABILITY, "after_intent_commit")
        return result

    def record_nonexecutable_decision(
        self,
        host_capability: object,
        *,
        workflow_id: str,
        source_output_event_id: str,
        proposal_event_id: str,
        decision: str,
        reason_code: str,
    ) -> ExecutionDecisionHandle:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("terminal decision requires host authority")
        if decision not in {"REVIEW", "BLOCK", "REJECT"} or not _ID.fullmatch(reason_code):
            raise ValueError("non-executable terminal decision is invalid")
        decision_id = _new_id("decision")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ExecutionDecisionHandle]:
            source = _event_logical_from_row(
                self.state._execution_verify_event(
                    _EXECUTION_EXTENSION_CAPABILITY, source_output_event_id
                )
            )
            proposal = _event_logical_from_row(
                self.state._execution_verify_event(
                    _EXECUTION_EXTENSION_CAPABILITY, proposal_event_id
                )
            )
            if (
                source["event_type"] != "model_output"
                or source["correlation_id"] != workflow_id
                or proposal["correlation_id"] != workflow_id
                or source_output_event_id not in proposal["parent_event_ids"]
            ):
                raise ExecutionBindingError("terminal decision source binding is invalid")
            if conn.execute(
                "SELECT 1 FROM execution_decisions WHERE source_output_event_id=?",
                (source_output_event_id,),
            ).fetchone():
                raise ExecutionStateConflict("source output already has a terminal decision")
            if conn.execute(
                "SELECT 1 FROM consumptions WHERE instance_id=? "
                "AND token_kind='model_output' AND token_id=?",
                (self.state.instance_id, source_output_event_id),
            ).fetchone():
                raise ExecutionStateConflict("source output is already consumed")
            logical = self._decision_logical(
                decision_id,
                source_output_event_id,
                proposal_event_id,
                workflow_id,
                decision,
                reason_code,
                None,
                None,
                seq,
            )
            consumption_id = _new_id("consumption")
            consumption = {
                "action_fingerprint": None,
                "commit_sequence": seq,
                "consuming_event_id": proposal_event_id,
                "consumption_id": consumption_id,
                "deployment_id": self.state.deployment_id,
                "instance_id": self.state.instance_id,
                "key_id": self.state.key_id,
                "schema_version": SCHEMA_VERSION,
                "token_id": source_output_event_id,
                "token_kind": "model_output",
            }
            dmac, cmac = (
                _mac(self.state, "execution_decision", logical),
                _mac(self.state, "consumption", consumption),
            )
            payload = {
                "changes": [
                    _change("execution_decision", decision_id, dmac),
                    _change("consumption", f"model_output:{source_output_event_id}", cmac),
                ],
                "operation": "TERMINAL_DECISION",
            }

            def apply(target: sqlite3.Connection) -> None:
                self._insert_decision(target, logical, dmac)
                target.execute(
                    "INSERT INTO consumptions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        consumption_id,
                        self.state.instance_id,
                        self.state.deployment_id,
                        SCHEMA_VERSION,
                        "model_output",
                        source_output_event_id,
                        proposal_event_id,
                        None,
                        seq,
                        self.state.key_id,
                        cmac,
                    ),
                )

            return (
                payload,
                apply,
                ExecutionDecisionHandle(decision_id, source_output_event_id, decision, None, seq),
            )

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "TERMINAL_DECISION", build
        )

    def register_worker(
        self,
        host_capability: object,
        *,
        boot_event_id: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> WorkerHandle:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("worker registration requires host authority")
        meta = dict(metadata or {})
        if len(canonical_text(meta).encode()) > MAX_METADATA_BYTES:
            raise ValueError("worker metadata exceeds bound")
        worker_id, nonce, capability = _new_id("worker"), secrets.token_bytes(32), object()

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], WorkerHandle]:
            boot = _event_logical_from_row(
                self.state._execution_verify_event(_EXECUTION_EXTENSION_CAPABILITY, boot_event_id)
            )
            if boot["event_type"] != "runtime_boot":
                raise ExecutionBindingError("worker boot record is not a runtime boot event")
            current_boot = conn.execute(
                "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
                "ORDER BY creation_sequence DESC LIMIT 1"
            ).fetchone()
            if current_boot is None or current_boot["event_id"] != boot_event_id:
                raise ExecutionAuthorityError("worker boot is not the current runtime boot")
            logical = {
                "boot_event_id": boot_event_id,
                "deployment_id": self.state.deployment_id,
                "instance_id": self.state.instance_id,
                "key_id": self.state.key_id,
                "process_nonce_digest": hashlib.sha256(nonce).hexdigest(),
                "registration_metadata": meta,
                "registration_sequence": seq,
                "schema_version": SCHEMA_VERSION,
                "worker_id": worker_id,
            }
            mac = _mac(self.state, "execution_worker", logical)
            payload = {
                "changes": [_change("execution_worker", worker_id, mac)],
                "operation": "REGISTER_WORKER",
            }

            def apply(target: sqlite3.Connection) -> None:
                target.execute(
                    "INSERT INTO execution_workers VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        worker_id,
                        self.state.instance_id,
                        self.state.deployment_id,
                        SCHEMA_VERSION,
                        boot_event_id,
                        logical["process_nonce_digest"],
                        canonical_text(meta),
                        seq,
                        self.state.key_id,
                        mac,
                    ),
                )

            return (
                payload,
                apply,
                WorkerHandle(_HANDLE_ISSUER, self, capability, worker_id, boot_event_id),
            )

        handle = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "REGISTER_WORKER", build
        )
        self._worker_capabilities[worker_id] = capability
        return handle

    def claim_execution(
        self, worker: WorkerHandle, intent_id: str, *, lease_seconds: float = 30.0
    ) -> ClaimHandle:
        self.state._execution_inject(_EXECUTION_EXTENSION_CAPABILITY, "before_claim_mutation")
        self._validate_worker_handle(worker)
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int | float)
            or not math.isfinite(lease_seconds)
        ):
            raise ValueError("claim lease must be a finite number")
        lease_ns = int(lease_seconds * 1_000_000_000)
        if lease_ns < 1 or lease_ns > MAX_LEASE_NS:
            raise ValueError("claim lease is outside configured bounds")
        now = time.monotonic_ns()
        claim_id, attempt_id, claim_cap = _new_id("claim"), _new_id("attempt"), object()

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ClaimHandle]:
            row = _verified_row(self.state, conn, "execution_intents", "intent_id", intent_id)
            worker_row = _verified_row(
                self.state, conn, "execution_workers", "worker_id", worker.worker_id
            )
            current_boot = conn.execute(
                "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
                "ORDER BY creation_sequence DESC LIMIT 1"
            ).fetchone()
            if (
                worker_row["boot_event_id"] != worker.boot_event_id
                or current_boot is None
                or current_boot["event_id"] != worker.boot_event_id
            ):
                raise ExecutionAuthorityError("worker is not bound to the current runtime boot")
            state = ExecutionState(str(row["state"]))
            reclaim = state is ExecutionState.CLAIMED and (
                str(row["boot_event_id"]) != worker.boot_event_id
                or int(row["lease_deadline_ns"] or 0) <= now
            )
            if state is not ExecutionState.READY and not reclaim:
                raise ExecutionStateConflict("intent is not safely claimable")
            self._ensure_lifecycle_capacity(conn, intent_id)
            generation = int(row["claim_generation"]) + 1
            if generation > 2**63 - 1:
                raise ExecutionStateConflict("claim generation is exhausted")
            logical = _logical(row, "execution_intent")
            logical.update(
                {
                    "state": "CLAIMED",
                    "claim_generation": generation,
                    "active_claim_id": claim_id,
                    "worker_id": worker.worker_id,
                    "boot_event_id": worker.boot_event_id,
                    "attempt_id": attempt_id,
                    "lease_deadline_ns": now + lease_ns,
                    "updated_sequence": seq,
                }
            )
            lifecycle = self._lifecycle_logical(
                intent_id,
                generation,
                claim_id,
                worker.worker_id,
                worker.boot_event_id,
                attempt_id,
                "RECLAIM" if reclaim else "CLAIM",
                None,
                None,
                {},
                seq,
            )
            imac, lmac = (
                _mac(self.state, "execution_intent", logical),
                _mac(self.state, "execution_lifecycle", lifecycle),
            )
            payload = {
                "changes": [
                    _change("execution_intent", intent_id, imac),
                    _change("execution_lifecycle", str(lifecycle["lifecycle_id"]), lmac),
                ],
                "operation": "RECLAIM_EXECUTION" if reclaim else "CLAIM_EXECUTION",
            }

            def apply(target: sqlite3.Connection) -> None:
                self.state._execution_inject(
                    _EXECUTION_EXTENSION_CAPABILITY, "during_claim_mutation"
                )
                self._update_intent(target, logical, imac)
                self._insert_lifecycle(target, lifecycle, lmac)

            handle = ClaimHandle(
                _HANDLE_ISSUER,
                self,
                claim_cap,
                intent_id=intent_id,
                claim_id=claim_id,
                generation=generation,
                worker_id=worker.worker_id,
                boot_event_id=worker.boot_event_id,
                attempt_id=attempt_id,
            )
            return payload, apply, handle

        handle = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "CLAIM_EXECUTION", build
        )
        self._claim_capabilities[(intent_id, handle.generation)] = claim_cap
        self.state._execution_inject(_EXECUTION_EXTENSION_CAPABILITY, "after_claim_mutation")
        return handle

    def begin_dispatch(
        self,
        claim: ClaimHandle,
        *,
        action: Mapping[str, Any] | str,
        destination_registry: str,
        destination: str,
        destination_config_digest: str,
        authorization_validator: Callable[[], bool] | None = None,
        security_configuration_epoch: int | None = None,
        security_configuration_digest: str | None = None,
    ) -> DispatchHandle:
        self.state._execution_inject(
            _EXECUTION_EXTENSION_CAPABILITY, "before_dispatch_fence_mutation"
        )
        self._validate_claim_handle(claim)
        _, _, fingerprint = normalize_action(action)
        dispatch_capability = object()

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], DispatchHandle]:
            row = _verified_row(self.state, conn, "execution_intents", "intent_id", claim.intent_id)
            self._require_current_claim(row, claim)
            current_boot = conn.execute(
                "SELECT event_id FROM causal_events WHERE event_type='runtime_boot' "
                "ORDER BY creation_sequence DESC LIMIT 1"
            ).fetchone()
            if current_boot is None or current_boot["event_id"] != claim.boot_event_id:
                raise ExecutionAuthorityError("claim belongs to an old runtime boot")
            if (
                row["state"] != "CLAIMED"
                or int(row["lease_deadline_ns"] or 0) <= time.monotonic_ns()
            ):
                raise ExecutionStateConflict("claim is not current at dispatch fence")
            self._ensure_lifecycle_capacity(conn, claim.intent_id)
            if (
                fingerprint != row["action_fingerprint"]
                or destination_registry != row["destination_registry"]
                or destination != row["destination"]
                or destination_config_digest != row["destination_config_digest"]
            ):
                raise ExecutionBindingError("dispatch binding differs from prepared intent")
            barrier = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(row["workflow_id"]),
            )
            workflow = conn.execute(
                "SELECT * FROM workflow_state WHERE workflow_id=?", (row["workflow_id"],)
            ).fetchone()
            if (
                barrier["active_intent_id"] != claim.intent_id
                or workflow is None
                or workflow["head_event_id"] != barrier["expected_head_event_id"]
                or int(workflow["revision"]) != int(barrier["expected_revision"])
            ):
                raise WorkflowCASConflict("workflow barrier changed before dispatch")
            if authorization_validator is not None and not authorization_validator():
                raise ExecutionBindingError("current pre-dispatch authorization snapshot is stale")
            if (security_configuration_epoch is None) != (security_configuration_digest is None):
                raise ExecutionBindingError("shared security configuration binding is incomplete")
            if security_configuration_epoch is not None:
                security = _verified_row(
                    self.state,
                    conn,
                    "execution_security_configuration",
                    "singleton",
                    "1",
                )
                if (
                    security["mode"] != "C2_REQUIRED"
                    or int(security["epoch"]) != security_configuration_epoch
                    or security["configuration_digest"] != security_configuration_digest
                ):
                    raise ExecutionBindingError(
                        "shared security configuration changed before dispatch"
                    )
            logical = _logical(row, "execution_intent")
            logical.update(
                {"state": "DISPATCHING", "lease_deadline_ns": None, "updated_sequence": seq}
            )
            lifecycle = self._lifecycle_logical(
                claim.intent_id,
                claim.generation,
                claim.claim_id,
                claim.worker_id,
                claim.boot_event_id,
                claim.attempt_id,
                "DISPATCHING",
                None,
                None,
                {},
                seq,
            )
            imac, lmac = (
                _mac(self.state, "execution_intent", logical),
                _mac(self.state, "execution_lifecycle", lifecycle),
            )
            payload = {
                "changes": [
                    _change("execution_intent", claim.intent_id, imac),
                    _change("execution_lifecycle", str(lifecycle["lifecycle_id"]), lmac),
                ],
                "operation": "BEGIN_DISPATCH",
            }

            def apply(target: sqlite3.Connection) -> None:
                self.state._execution_inject(
                    _EXECUTION_EXTENSION_CAPABILITY, "during_dispatch_fence_mutation"
                )
                self._update_intent(target, logical, imac)
                self._insert_lifecycle(target, lifecycle, lmac)

            dispatch = DispatchHandle(
                _HANDLE_ISSUER,
                self,
                dispatch_capability,
                intent_id=claim.intent_id,
                claim_id=claim.claim_id,
                generation=claim.generation,
                worker_id=claim.worker_id,
                boot_event_id=claim.boot_event_id,
                attempt_id=claim.attempt_id,
                action_fingerprint=fingerprint,
                destination_registry=destination_registry,
                destination=destination,
                destination_config_digest=destination_config_digest,
                idempotency_key=row["idempotency_key"],
            )
            return payload, apply, dispatch

        result = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, "BEGIN_DISPATCH", build
        )
        self.state._execution_inject(
            _EXECUTION_EXTENSION_CAPABILITY, "after_dispatch_fence_mutation"
        )
        self._claim_capabilities[(claim.intent_id, claim.generation)] = dispatch_capability
        return result

    def complete_execution(
        self,
        dispatch: DispatchHandle,
        *,
        result_digest: str,
        destination_operation_id: str | None = None,
    ) -> ExecutionIntentRecord:
        return self._finish_dispatch(
            dispatch, ExecutionState.COMPLETED, result_digest, destination_operation_id
        )

    def fail_no_effect(
        self,
        host_capability: object,
        dispatch: DispatchHandle,
        *,
        result_digest: str,
    ) -> ExecutionIntentRecord:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("definitive no-effect outcome requires host authority")
        return self._finish_dispatch(dispatch, ExecutionState.FAILED_NO_EFFECT, result_digest, None)

    def mark_outcome_unknown(
        self, dispatch: DispatchHandle, *, destination_operation_id: str | None = None
    ) -> ExecutionIntentRecord:
        return self._finish_dispatch(
            dispatch, ExecutionState.OUTCOME_UNKNOWN, None, destination_operation_id
        )

    def mark_abandoned_dispatch_unknown(
        self,
        host_capability: object,
        intent_id: str,
        *,
        destination_operation_id: str | None = None,
    ) -> ExecutionIntentRecord:
        """Conservatively resolve a lost process handle without permitting retry."""

        return self._host_transition(
            host_capability,
            intent_id,
            allowed={ExecutionState.DISPATCHING},
            target=ExecutionState.OUTCOME_UNKNOWN,
            reason_code="ABANDONED_DISPATCH",
            destination_operation_id=destination_operation_id,
        )

    def cancel_execution(
        self, host_capability: object, intent_id: str, *, reason_code: str
    ) -> ExecutionIntentRecord:
        return self._host_transition(
            host_capability,
            intent_id,
            allowed={
                ExecutionState.READY,
                ExecutionState.CLAIMED,
                ExecutionState.FAILED_NO_EFFECT,
            },
            target=ExecutionState.CANCELLED,
            reason_code=reason_code,
        )

    def retry_failed_no_effect(
        self, host_capability: object, intent_id: str, *, reason_code: str
    ) -> ExecutionIntentRecord:
        """Return only a proved no-effect failure to READY; unknown is never eligible."""

        return self._host_transition(
            host_capability,
            intent_id,
            allowed={ExecutionState.FAILED_NO_EFFECT},
            target=ExecutionState.READY,
            reason_code=reason_code,
            forbid_reconciled_no_effect=True,
        )

    def get_intent(self, intent_id: str) -> ExecutionIntentRecord:
        def read() -> ExecutionIntentRecord:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            return self._record(
                _verified_row(self.state, conn, "execution_intents", "intent_id", intent_id)
            )

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def list_outcome_unknown_intents(
        self, *, limit: int = 128
    ) -> tuple[ExecutionIntentRecord, ...]:
        """Return a bounded authenticated discovery view for host recovery integration."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 128:
            raise ValueError("unknown-intent discovery limit must be between 1 and 128")

        def read() -> tuple[ExecutionIntentRecord, ...]:
            conn = self.state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
            rows = conn.execute(
                "SELECT intent_id FROM execution_intents WHERE state=? "
                "ORDER BY updated_sequence,intent_id LIMIT ?",
                (ExecutionState.OUTCOME_UNKNOWN.value, limit),
            ).fetchall()
            return tuple(
                self._record(
                    _verified_row(
                        self.state,
                        conn,
                        "execution_intents",
                        "intent_id",
                        str(row["intent_id"]),
                    )
                )
                for row in rows
            )

        return self.state._run_execution_read(_EXECUTION_EXTENSION_CAPABILITY, read)

    def validate_dispatch_handle(self, handle: DispatchHandle) -> ExecutionIntentRecord:
        if not isinstance(handle, DispatchHandle):
            raise ExecutionAuthorityError("a DispatchHandle is required")
        self._validate_claim_handle(handle)
        record = self.get_intent(handle.intent_id)
        if (
            record.state is not ExecutionState.DISPATCHING
            or record.claim_generation != handle.generation
            or record.active_claim_id != handle.claim_id
            or record.action_fingerprint != handle.action_fingerprint
            or record.destination_registry != handle.destination_registry
            or record.destination != handle.destination
            or record.destination_config_digest != handle.destination_config_digest
            or record.idempotency_key != handle.idempotency_key
        ):
            raise ExecutionStateConflict("dispatch handle is stale or replayed")
        return record

    def _host_transition(
        self,
        host_capability: object,
        intent_id: str,
        *,
        allowed: set[ExecutionState],
        target: ExecutionState,
        reason_code: str,
        destination_operation_id: str | None = None,
        forbid_reconciled_no_effect: bool = False,
    ) -> ExecutionIntentRecord:
        if host_capability is not _HOST_EXECUTION_AUTHORITY_CAPABILITY:
            raise PermissionError("execution recovery transition requires host authority")
        if not _ID.fullmatch(reason_code):
            raise ValueError("transition reason is invalid")
        if destination_operation_id is not None and not _ID.fullmatch(destination_operation_id):
            raise ValueError("destination operation ID is invalid")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ExecutionIntentRecord]:
            row = _verified_row(self.state, conn, "execution_intents", "intent_id", intent_id)
            if ExecutionState(str(row["state"])) not in allowed:
                raise ExecutionStateConflict("host transition is illegal from current state")
            if forbid_reconciled_no_effect:
                latest = conn.execute(
                    "SELECT transition FROM execution_lifecycle WHERE intent_id=? "
                    "ORDER BY mutation_sequence DESC LIMIT 1",
                    (intent_id,),
                ).fetchone()
                if latest is not None and latest["transition"] == "RECONCILED_FAILED_NO_EFFECT":
                    raise ExecutionStateConflict(
                        "c3a reconciled no-effect outcome creates no retry authority"
                    )
            self._ensure_lifecycle_capacity(conn, intent_id)
            logical = _logical(row, "execution_intent")
            logical.update(
                {
                    "state": target.value,
                    "lease_deadline_ns": None,
                    "destination_operation_id": destination_operation_id,
                    "completion_sequence": (
                        seq
                        if target in {ExecutionState.OUTCOME_UNKNOWN, ExecutionState.CANCELLED}
                        else None
                    ),
                    "result_digest": None
                    if target is ExecutionState.READY
                    else row["result_digest"],
                    "active_claim_id": None
                    if target is ExecutionState.READY
                    else row["active_claim_id"],
                    "worker_id": None if target is ExecutionState.READY else row["worker_id"],
                    "boot_event_id": None
                    if target is ExecutionState.READY
                    else row["boot_event_id"],
                    "attempt_id": None if target is ExecutionState.READY else row["attempt_id"],
                    "updated_sequence": seq,
                }
            )
            barrier_row = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(row["workflow_id"]),
            )
            blocking = target in {ExecutionState.READY, ExecutionState.OUTCOME_UNKNOWN}
            barrier_status = (
                "BLOCKED_UNKNOWN"
                if target is ExecutionState.OUTCOME_UNKNOWN
                else ("WAITING_EXECUTION" if target is ExecutionState.READY else "ACTIVE")
            )
            barrier = self._barrier_logical(
                str(row["workflow_id"]),
                intent_id if blocking else None,
                barrier_status,
                str(barrier_row["expected_head_event_id"]),
                int(barrier_row["expected_revision"]),
                seq,
            )
            workflow_row = _verified_workflow_row(self.state, conn, str(row["workflow_id"]))
            workflow = _workflow_logical_from_row(workflow_row)
            workflow.update({"status": barrier_status, "updated_sequence": seq})
            lifecycle = self._lifecycle_logical(
                intent_id,
                int(row["claim_generation"]),
                row["active_claim_id"],
                row["worker_id"],
                row["boot_event_id"],
                row["attempt_id"],
                target.value,
                destination_operation_id,
                logical["result_digest"],
                {"reason_code": reason_code},
                seq,
            )
            records = (
                ("execution_intent", intent_id, logical),
                ("execution_workflow_barrier", str(row["workflow_id"]), barrier),
                ("workflow_state", str(row["workflow_id"]), workflow),
                ("execution_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            )
            macs = {
                (kind, identifier): _mac(self.state, kind, item)
                for kind, identifier, item in records
            }
            payload = {
                "changes": [
                    _change(kind, identifier, macs[(kind, identifier)])
                    for kind, identifier, _ in records
                ],
                "operation": target.value,
            }

            def apply(db: sqlite3.Connection) -> None:
                workflow_id = str(row["workflow_id"])
                self._update_intent(db, logical, macs[("execution_intent", intent_id)])
                self._upsert_barrier(
                    db,
                    barrier,
                    macs[("execution_workflow_barrier", workflow_id)],
                )
                db.execute(
                    "UPDATE workflow_state SET status=?, updated_sequence=?, key_id=?, "
                    "record_mac=? WHERE workflow_id=?",
                    (
                        barrier_status,
                        seq,
                        self.state.key_id,
                        macs[("workflow_state", workflow_id)],
                        workflow_id,
                    ),
                )
                self._insert_lifecycle(
                    db,
                    lifecycle,
                    macs[("execution_lifecycle", str(lifecycle["lifecycle_id"]))],
                )

            return payload, apply, self._record_dict(logical)

        return self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, target.value, build
        )

    def _finish_dispatch(
        self,
        handle: DispatchHandle,
        target: ExecutionState,
        result_digest: str | None,
        operation_id: str | None,
    ) -> ExecutionIntentRecord:
        if not isinstance(handle, DispatchHandle):
            raise ExecutionAuthorityError("completion requires a DispatchHandle")
        self.state._execution_inject(_EXECUTION_EXTENSION_CAPABILITY, "before_completion_mutation")
        self._validate_claim_handle(handle)
        if result_digest is not None and not _DIGEST.fullmatch(result_digest):
            raise ValueError("result digest is invalid")
        if operation_id is not None and not _ID.fullmatch(operation_id):
            raise ValueError("destination operation ID is invalid")

        def build(
            conn: sqlite3.Connection, seq: int, _mutation: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ExecutionIntentRecord]:
            row = _verified_row(
                self.state, conn, "execution_intents", "intent_id", handle.intent_id
            )
            self._require_current_claim(row, handle)
            if row["state"] != "DISPATCHING":
                raise ExecutionStateConflict("only DISPATCHING may record a dispatch outcome")
            self._ensure_lifecycle_capacity(conn, handle.intent_id)
            logical = _logical(row, "execution_intent")
            logical.update(
                {
                    "state": target.value,
                    "destination_operation_id": operation_id,
                    "completion_sequence": seq,
                    "result_digest": result_digest,
                    "updated_sequence": seq,
                }
            )
            barrier_row = _verified_row(
                self.state,
                conn,
                "execution_workflow_barriers",
                "workflow_id",
                str(row["workflow_id"]),
            )
            barrier_status = (
                "BLOCKED_UNKNOWN" if target is ExecutionState.OUTCOME_UNKNOWN else "ACTIVE"
            )
            active = handle.intent_id if target is ExecutionState.OUTCOME_UNKNOWN else None
            barrier = self._barrier_logical(
                str(row["workflow_id"]),
                active,
                barrier_status,
                str(barrier_row["expected_head_event_id"]),
                int(barrier_row["expected_revision"]),
                seq,
            )
            workflow_row = _verified_workflow_row(self.state, conn, str(row["workflow_id"]))
            workflow = _workflow_logical_from_row(workflow_row)
            workflow.update({"status": barrier_status, "updated_sequence": seq})
            lifecycle = self._lifecycle_logical(
                handle.intent_id,
                handle.generation,
                handle.claim_id,
                handle.worker_id,
                handle.boot_event_id,
                handle.attempt_id,
                target.value,
                operation_id,
                result_digest,
                {},
                seq,
            )
            records = (
                ("execution_intent", handle.intent_id, logical),
                ("execution_workflow_barrier", str(row["workflow_id"]), barrier),
                ("workflow_state", str(row["workflow_id"]), workflow),
                ("execution_lifecycle", str(lifecycle["lifecycle_id"]), lifecycle),
            )
            macs = {
                (kind, identifier): _mac(self.state, kind, item)
                for kind, identifier, item in records
            }
            payload = {
                "changes": [
                    _change(kind, identifier, macs[(kind, identifier)])
                    for kind, identifier, _ in records
                ],
                "operation": target.value,
            }

            def apply(db: sqlite3.Connection) -> None:
                self.state._execution_inject(
                    _EXECUTION_EXTENSION_CAPABILITY, "during_completion_mutation"
                )
                workflow_id = str(row["workflow_id"])
                self._update_intent(
                    db,
                    logical,
                    macs[("execution_intent", handle.intent_id)],
                )
                self._upsert_barrier(
                    db,
                    barrier,
                    macs[("execution_workflow_barrier", workflow_id)],
                )
                db.execute(
                    "UPDATE workflow_state SET status=?, updated_sequence=?, key_id=?, "
                    "record_mac=? WHERE workflow_id=?",
                    (
                        barrier_status,
                        seq,
                        self.state.key_id,
                        macs[("workflow_state", workflow_id)],
                        workflow_id,
                    ),
                )
                self._insert_lifecycle(
                    db,
                    lifecycle,
                    macs[("execution_lifecycle", str(lifecycle["lifecycle_id"]))],
                )

            return payload, apply, self._record_dict(logical)

        result = self.state._run_execution_mutation(
            _EXECUTION_EXTENSION_CAPABILITY, target.value, build
        )
        self.state._execution_inject(_EXECUTION_EXTENSION_CAPABILITY, "after_completion_mutation")
        return result

    def _validate_worker_handle(self, handle: WorkerHandle) -> None:
        if (
            not isinstance(handle, WorkerHandle)
            or handle._authority is not self
            or handle._pid != os.getpid()
            or handle._thread_id != threading.get_ident()
            or self._worker_capabilities.get(handle.worker_id) is not handle._capability
        ):
            raise ExecutionAuthorityError("worker capability is invalid in this process")

    def _validate_claim_handle(self, handle: ClaimHandle) -> None:
        if (
            not isinstance(handle, ClaimHandle)
            or handle._authority is not self
            or handle._pid != os.getpid()
            or handle._thread_id != threading.get_ident()
            or self._claim_capabilities.get((handle.intent_id, handle.generation))
            is not handle._capability
        ):
            raise ExecutionAuthorityError(
                "claim capability is invalid, stale, or from another process"
            )

    @staticmethod
    def _require_current_claim(row: sqlite3.Row, handle: ClaimHandle) -> None:
        if (
            int(row["claim_generation"]) != handle.generation
            or row["active_claim_id"] != handle.claim_id
            or row["worker_id"] != handle.worker_id
            or row["boot_event_id"] != handle.boot_event_id
            or row["attempt_id"] != handle.attempt_id
        ):
            raise ExecutionStateConflict("claim generation or worker binding is stale")

    @staticmethod
    def _ensure_lifecycle_capacity(connection: sqlite3.Connection, intent_id: str) -> None:
        count = int(
            connection.execute(
                "SELECT COUNT(*) FROM execution_lifecycle WHERE intent_id=?", (intent_id,)
            ).fetchone()[0]
        )
        if count >= MAX_LIFECYCLE_RECORDS:
            raise ExecutionStateConflict("intent lifecycle history bound is exhausted")

    def _validate_prepare_fields(self, *values: Any) -> None:
        workflow, registry, destination, *rest = values
        if not all(
            isinstance(item, str) and _ID.fullmatch(item)
            for item in (workflow, registry, destination)
        ):
            raise ValueError("execution routing identifier is invalid")
        for digest in (rest[0], rest[1], *rest[3]):
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise ValueError("execution digest is invalid")
        ancestry = rest[2]
        if len(ancestry) > 128 or any(not _ID.fullmatch(item) for item in ancestry):
            raise ValueError("execution ancestry is invalid")

    def _decision_logical(
        self,
        decision_id: str,
        source: str,
        proposal: str,
        workflow: str,
        decision: str,
        reason: str,
        fingerprint: str | None,
        intent: str | None,
        seq: int,
    ) -> dict[str, Any]:
        return {
            "action_fingerprint": fingerprint,
            "creation_sequence": seq,
            "decision": decision,
            "decision_id": decision_id,
            "deployment_id": self.state.deployment_id,
            "instance_id": self.state.instance_id,
            "intent_id": intent,
            "key_id": self.state.key_id,
            "proposal_event_id": proposal,
            "reason_code": reason,
            "schema_version": SCHEMA_VERSION,
            "source_output_event_id": source,
            "workflow_id": workflow,
        }

    def _intent_logical(self, **v: Any) -> dict[str, Any]:
        defaults: dict[str, Any] = {
            "active_claim_id": None,
            "attempt_id": None,
            "boot_event_id": None,
            "completion_sequence": None,
            "destination_operation_id": None,
            "lease_deadline_ns": None,
            "result_digest": None,
            "worker_id": None,
        }
        defaults.update(v)
        defaults.update(
            {
                "deployment_id": self.state.deployment_id,
                "instance_id": self.state.instance_id,
                "key_id": self.state.key_id,
                "schema_version": SCHEMA_VERSION,
            }
        )
        return defaults

    def _barrier_logical(
        self, workflow: str, active: str | None, status: str, head: str, revision: int, seq: int
    ) -> dict[str, Any]:
        return {
            "active_intent_id": active,
            "deployment_id": self.state.deployment_id,
            "expected_head_event_id": head,
            "expected_revision": revision,
            "instance_id": self.state.instance_id,
            "key_id": self.state.key_id,
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "updated_sequence": seq,
            "workflow_id": workflow,
        }

    def _lifecycle_logical(
        self,
        intent: str,
        generation: int,
        claim: str | None,
        worker: str | None,
        boot: str | None,
        attempt: str | None,
        transition: str,
        operation: str | None,
        result: str | None,
        metadata: Mapping[str, Any],
        seq: int,
    ) -> dict[str, Any]:
        return {
            "boot_event_id": boot,
            "claim_generation": generation,
            "claim_id": claim,
            "deployment_id": self.state.deployment_id,
            "destination_operation_id": operation,
            "instance_id": self.state.instance_id,
            "intent_id": intent,
            "key_id": self.state.key_id,
            "lifecycle_id": _new_id("lifecycle"),
            "metadata": dict(metadata),
            "mutation_sequence": seq,
            "result_digest": result,
            "schema_version": SCHEMA_VERSION,
            "transition": transition,
            "worker_id": worker,
            "attempt_id": attempt,
        }

    @staticmethod
    def _insert_decision(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            "INSERT INTO execution_decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                v["decision_id"],
                v["instance_id"],
                v["deployment_id"],
                v["schema_version"],
                v["source_output_event_id"],
                v["proposal_event_id"],
                v["workflow_id"],
                v["decision"],
                v["reason_code"],
                v["action_fingerprint"],
                v["intent_id"],
                v["creation_sequence"],
                v["key_id"],
                mac,
            ),
        )

    @staticmethod
    def _insert_intent(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            "INSERT INTO execution_intents VALUES(" + ",".join("?" for _ in range(34)) + ")",
            (
                v["intent_id"],
                v["instance_id"],
                v["deployment_id"],
                v["schema_version"],
                v["key_id"],
                v["workflow_id"],
                v["source_turn_event_id"],
                v["source_output_event_id"],
                v["proposal_event_id"],
                v["decision_id"],
                v["action_type"],
                canonical_text(v["normalized_action"]),
                v["action_fingerprint"],
                v["destination_registry"],
                v["destination"],
                v["destination_config_digest"],
                v["idempotency_class"],
                _encode_items(v["ancestry_event_ids"]),
                _encode_items(v["content_digests"]),
                v["policy_config_digest"],
                v["creation_sequence"],
                v["state"],
                v["claim_generation"],
                v["active_claim_id"],
                v["worker_id"],
                v["boot_event_id"],
                v["attempt_id"],
                v["lease_deadline_ns"],
                v["idempotency_key"],
                v["destination_operation_id"],
                v["completion_sequence"],
                v["result_digest"],
                v["updated_sequence"],
                mac,
            ),
        )

    @staticmethod
    def _update_intent(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            """UPDATE execution_intents SET state=?, claim_generation=?, active_claim_id=?,
            worker_id=?, boot_event_id=?, attempt_id=?, lease_deadline_ns=?,
            destination_operation_id=?, completion_sequence=?, result_digest=?,
            updated_sequence=?, record_mac=? WHERE intent_id=?""",
            (
                v["state"],
                v["claim_generation"],
                v["active_claim_id"],
                v["worker_id"],
                v["boot_event_id"],
                v["attempt_id"],
                v["lease_deadline_ns"],
                v["destination_operation_id"],
                v["completion_sequence"],
                v["result_digest"],
                v["updated_sequence"],
                mac,
                v["intent_id"],
            ),
        )

    @staticmethod
    def _upsert_barrier(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            """INSERT INTO execution_workflow_barriers VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(workflow_id) DO UPDATE SET
            active_intent_id=excluded.active_intent_id, status=excluded.status,
            expected_head_event_id=excluded.expected_head_event_id,
            expected_revision=excluded.expected_revision,
            updated_sequence=excluded.updated_sequence, key_id=excluded.key_id,
            record_mac=excluded.record_mac""",
            (
                v["workflow_id"],
                v["instance_id"],
                v["deployment_id"],
                v["schema_version"],
                v["active_intent_id"],
                v["status"],
                v["expected_head_event_id"],
                v["expected_revision"],
                v["updated_sequence"],
                v["key_id"],
                mac,
            ),
        )

    @staticmethod
    def _insert_lifecycle(conn: sqlite3.Connection, v: Mapping[str, Any], mac: str) -> None:
        conn.execute(
            "INSERT INTO execution_lifecycle VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                v["lifecycle_id"],
                v["instance_id"],
                v["deployment_id"],
                v["schema_version"],
                v["intent_id"],
                v["claim_generation"],
                v["claim_id"],
                v["worker_id"],
                v["boot_event_id"],
                v["attempt_id"],
                v["transition"],
                v["destination_operation_id"],
                v["result_digest"],
                canonical_text(v["metadata"]),
                v["mutation_sequence"],
                v["key_id"],
                mac,
            ),
        )

    @staticmethod
    def _record(row: sqlite3.Row) -> ExecutionIntentRecord:
        return ExecutionAuthority._record_dict(_logical(row, "execution_intent"))

    @staticmethod
    def _record_dict(v: Mapping[str, Any]) -> ExecutionIntentRecord:
        return ExecutionIntentRecord(
            intent_id=str(v["intent_id"]),
            workflow_id=str(v["workflow_id"]),
            source_turn_event_id=str(v["source_turn_event_id"]),
            source_output_event_id=str(v["source_output_event_id"]),
            proposal_event_id=str(v["proposal_event_id"]),
            action_type=str(v["action_type"]),
            normalized_action=dict(v["normalized_action"]),
            action_fingerprint=str(v["action_fingerprint"]),
            destination_registry=str(v["destination_registry"]),
            destination=str(v["destination"]),
            destination_config_digest=str(v["destination_config_digest"]),
            ancestry_event_ids=tuple(str(item) for item in v["ancestry_event_ids"]),
            content_digests=tuple(str(item) for item in v["content_digests"]),
            policy_config_digest=str(v["policy_config_digest"]),
            idempotency_class=IdempotencyClass(str(v["idempotency_class"])),
            idempotency_key=None if v["idempotency_key"] is None else str(v["idempotency_key"]),
            state=ExecutionState(str(v["state"])),
            claim_generation=int(v["claim_generation"]),
            active_claim_id=None if v["active_claim_id"] is None else str(v["active_claim_id"]),
            worker_id=None if v["worker_id"] is None else str(v["worker_id"]),
            boot_event_id=None if v["boot_event_id"] is None else str(v["boot_event_id"]),
            attempt_id=None if v["attempt_id"] is None else str(v["attempt_id"]),
            lease_deadline_ns=None
            if v["lease_deadline_ns"] is None
            else int(v["lease_deadline_ns"]),
            destination_operation_id=None
            if v["destination_operation_id"] is None
            else str(v["destination_operation_id"]),
            result_digest=None if v["result_digest"] is None else str(v["result_digest"]),
            mutation_sequence=int(v["updated_sequence"]),
        )


def verify_execution_materialized(
    state: PersistentSecurityState,
    connection: sqlite3.Connection,
    expected: dict[str, dict[str, str]],
) -> None:
    extension = connection.execute(
        "SELECT schema_version FROM execution_extensions WHERE singleton=1"
    ).fetchone()
    if extension is None or extension[0] != EXECUTION_SCHEMA_VERSION:
        raise StateVerificationError("execution extension marker is invalid")
    specs = (
        ("execution_decision", "execution_decisions", "decision_id"),
        ("execution_intent", "execution_intents", "intent_id"),
        ("execution_workflow_barrier", "execution_workflow_barriers", "workflow_id"),
        ("execution_worker", "execution_workers", "worker_id"),
        ("execution_lifecycle", "execution_lifecycle", "lifecycle_id"),
        (
            "execution_security_configuration",
            "execution_security_configuration",
            "singleton",
        ),
    )
    for kind, table, key in specs:
        actual = {}
        for row in connection.execute(f"SELECT * FROM {table}"):
            _verified_row(state, connection, table, key, str(row[key]))
            actual[str(row[key])] = str(row["record_mac"])
        if actual != expected[kind]:
            raise StateVerificationError(f"{kind} materialized state mismatch")
    for row in connection.execute("SELECT * FROM execution_decisions"):
        consumption = connection.execute(
            "SELECT * FROM consumptions WHERE instance_id=? "
            "AND token_kind='model_output' AND token_id=?",
            (state.instance_id, row["source_output_event_id"]),
        ).fetchone()
        if consumption is None:
            raise StateVerificationError("terminal decision lacks source consumption")
        logical = _consumption_logical_from_row(consumption)
        if not state._verify_execution_record_mac(
            _EXECUTION_EXTENSION_CAPABILITY, "consumption", logical, str(consumption["record_mac"])
        ):
            raise StateAuthenticationError("decision consumption MAC is invalid")
        if (row["decision"] == "ALLOW") != (row["intent_id"] is not None):
            raise StateVerificationError("terminal decision executable binding is inconsistent")
        if row["intent_id"] is not None:
            intent = connection.execute(
                "SELECT * FROM execution_intents WHERE intent_id=?", (row["intent_id"],)
            ).fetchone()
            if intent is None or any(
                intent[field] != row[field]
                for field in (
                    "decision_id",
                    "source_output_event_id",
                    "proposal_event_id",
                    "workflow_id",
                    "action_fingerprint",
                )
            ):
                raise StateVerificationError("ALLOW decision and intent binding disagree")
    for row in connection.execute("SELECT * FROM execution_intents"):
        lifecycles = connection.execute(
            "SELECT * FROM execution_lifecycle WHERE intent_id=? ORDER BY mutation_sequence",
            (row["intent_id"],),
        ).fetchall()
        terminal_transition = str(lifecycles[-1]["transition"]) if lifecycles else ""
        terminal_transition = {
            "RECONCILED_COMPLETED": "COMPLETED",
            "RECONCILED_FAILED_NO_EFFECT": "FAILED_NO_EFFECT",
            "RECOVERY_COMPLETED": "COMPLETED",
        }.get(terminal_transition, terminal_transition)
        lifecycle_state = (
            "CLAIMED" if terminal_transition in {"CLAIM", "RECLAIM"} else terminal_transition
        )
        if (
            not lifecycles
            or lifecycles[0]["transition"] != "READY"
            or lifecycle_state != row["state"]
        ):
            raise StateVerificationError("intent lifecycle disagrees with materialized state")
        if int(lifecycles[-1]["claim_generation"]) != int(row["claim_generation"]):
            raise StateVerificationError("intent generation disagrees with lifecycle")
        if len(lifecycles) > MAX_LIFECYCLE_RECORDS:
            raise StateVerificationError("intent lifecycle exceeds active-history bound")
        machine_state = "READY"
        generation = 0
        for position, lifecycle in enumerate(lifecycles):
            transition = str(lifecycle["transition"])
            current_generation = int(lifecycle["claim_generation"])
            if position == 0:
                if transition != "READY" or current_generation != 0:
                    raise StateVerificationError("intent lifecycle genesis is invalid")
                continue
            if transition in {"CLAIM", "RECLAIM"}:
                if (
                    machine_state not in {"READY", "CLAIMED"}
                    or current_generation != generation + 1
                ):
                    raise StateVerificationError("intent claim lifecycle transition is illegal")
                machine_state, generation = "CLAIMED", current_generation
            elif transition == "DISPATCHING":
                if machine_state != "CLAIMED" or current_generation != generation:
                    raise StateVerificationError("intent dispatch lifecycle transition is illegal")
                machine_state = "DISPATCHING"
            elif transition in {"COMPLETED", "FAILED_NO_EFFECT", "OUTCOME_UNKNOWN"}:
                if machine_state != "DISPATCHING" or current_generation != generation:
                    raise StateVerificationError("intent outcome lifecycle transition is illegal")
                machine_state = transition
            elif transition in {"RECONCILED_COMPLETED", "RECONCILED_FAILED_NO_EFFECT"}:
                if machine_state != "OUTCOME_UNKNOWN" or current_generation != generation:
                    raise StateVerificationError("intent reconciliation transition is illegal")
                metadata = _logical(lifecycle, "execution_lifecycle")["metadata"]
                required = {
                    "confirmation_id",
                    "evidence_id",
                    "proposal_digest",
                    "proposal_id",
                    "reconciliation_id",
                }
                if set(metadata) != required or not _DIGEST.fullmatch(
                    str(metadata["proposal_digest"])
                ):
                    raise StateVerificationError("intent reconciliation lineage is invalid")
                machine_state = transition.removeprefix("RECONCILED_")
            elif transition == "RECOVERY_COMPLETED":
                if machine_state != "OUTCOME_UNKNOWN" or current_generation != generation:
                    raise StateVerificationError("intent recovery transition is illegal")
                metadata = _logical(lifecycle, "execution_lifecycle")["metadata"]
                required = {
                    "dispatch_authorization_id",
                    "reconciliation_id",
                    "recovery_generation",
                    "recovery_id",
                }
                if set(metadata) != required or int(metadata["recovery_generation"]) != 1:
                    raise StateVerificationError("intent recovery lineage is invalid")
                machine_state = "COMPLETED"
            elif transition == "READY":
                if machine_state != "FAILED_NO_EFFECT" or current_generation != generation:
                    raise StateVerificationError("intent retry lifecycle transition is illegal")
                machine_state = "READY"
            elif transition == "CANCELLED":
                if machine_state not in {"READY", "CLAIMED", "FAILED_NO_EFFECT"}:
                    raise StateVerificationError(
                        "intent cancellation lifecycle transition is illegal"
                    )
                machine_state = "CANCELLED"
            else:
                raise StateVerificationError("unknown intent lifecycle transition")
        if machine_state != row["state"] or generation != int(row["claim_generation"]):
            raise StateVerificationError("replayed lifecycle does not reproduce intent state")
        last = lifecycles[-1]
        if row["state"] in {
            "CLAIMED",
            "DISPATCHING",
            "COMPLETED",
            "FAILED_NO_EFFECT",
            "OUTCOME_UNKNOWN",
        }:
            for field in ("claim_id", "worker_id", "boot_event_id", "attempt_id"):
                intent_field = "active_claim_id" if field == "claim_id" else field
                if last[field] != row[intent_field]:
                    raise StateVerificationError("intent claimant disagrees with lifecycle")
        if row["state"] in {"COMPLETED", "FAILED_NO_EFFECT", "OUTCOME_UNKNOWN"} and (
            last["destination_operation_id"] != row["destination_operation_id"]
            or last["result_digest"] != row["result_digest"]
        ):
            raise StateVerificationError("intent result disagrees with lifecycle")
        barrier = connection.execute(
            "SELECT * FROM execution_workflow_barriers WHERE workflow_id=?", (row["workflow_id"],)
        ).fetchone()
        if barrier is None:
            raise StateVerificationError("intent workflow barrier is missing")
        active = row["state"] in {"READY", "CLAIMED", "DISPATCHING", "OUTCOME_UNKNOWN"}
        if active and barrier["active_intent_id"] != row["intent_id"]:
            raise StateVerificationError("active intent is absent from workflow barrier")
        if row["state"] == "OUTCOME_UNKNOWN" and barrier["status"] not in {
            "BLOCKED_UNKNOWN",
            "BLOCKED_UNKNOWN_ABANDONED",
        }:
            raise StateVerificationError("unknown outcome does not block workflow")
    for barrier in connection.execute("SELECT * FROM execution_workflow_barriers"):
        workflow = connection.execute(
            "SELECT * FROM workflow_state WHERE workflow_id=?", (barrier["workflow_id"],)
        ).fetchone()
        if workflow is None:
            raise StateVerificationError("execution barrier workflow is missing")
        if barrier["active_intent_id"] is not None and (
            workflow["head_event_id"] != barrier["expected_head_event_id"]
            or int(workflow["revision"]) != int(barrier["expected_revision"])
        ):
            raise StateVerificationError("active execution barrier workflow fence is stale")
    from .reconciliation import reconciliation_schema_present, verify_reconciliation_materialized

    if reconciliation_schema_present(connection):
        verify_reconciliation_materialized(state, connection, expected)
    from .recovery import recovery_schema_present, verify_recovery_materialized

    if recovery_schema_present(connection):
        verify_recovery_materialized(state, connection, expected)
