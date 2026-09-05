"""SQLite-backed persistent authority primitives for Agent Boundary v0.3a.

This module is intentionally not integrated with the live Gateway runtime.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import re
import secrets
import sqlite3
import stat
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, TypeVar

from .canonical import (
    CanonicalAuthorityError,
    canonical_text,
    record_mac,
    sha256_hex,
    strict_json_object,
    verify_record_mac,
)
from .directory import (
    LocalRestrictedFileKeyBackend,
    StatePaths,
    _fsync_directory,
    classify_state,
    prepare_paths,
)
from .models import (
    AnchorState,
    AuditOutboxRecord,
    ConsumptionResult,
    EnvelopeHandle,
    EventHandle,
    PersistentStateConfig,
    StateAuthenticationError,
    StateBusyError,
    StateDirectoryError,
    StateInitializationError,
    StateRollbackError,
    StateVerificationError,
    StoreDirectoryState,
    StoreHealth,
    TrustedRootIssuanceRequired,
    UnknownAuthorityRecord,
    VerificationLevel,
    VerificationReport,
    VerifiedEnvelopeRecord,
    VerifiedEventRecord,
    WorkflowCASConflict,
    WorkflowHandle,
)

SCHEMA_VERSION = "persistent-security-state-v0.3a"
ANCHOR_FORMAT_VERSION = "persistent-security-anchor-v1"
MAX_ANCHOR_BYTES = 65_536
MAX_AUTHORITY_GRAPH_NODES = 4_096
KEY_BACKEND_NAME = "LOCAL_RESTRICTED_FILE"
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_DEPLOYMENT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_ROUTING_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}")
_TOKEN_KIND = re.compile(r"[a-z][a-z0-9_]{0,63}")
_AUTHORITY_ID = re.compile(r"[a-z][a-z0-9-]{0,63}-[0-9a-f]{32}")
_TRUST_ORDER = {"EXTERNAL": 0, "UNTRUSTED": 1, "INTERNAL": 2, "TRUSTED": 3}
_SOURCE_TYPES = frozenset(
    {"file", "retrieval", "tool_output", "memory", "agent_message", "user", "model", "internal"}
)

_SCHEMA = """
CREATE TABLE instance_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    instance_id TEXT NOT NULL UNIQUE,
    deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_backend TEXT NOT NULL,
    genesis_nonce TEXT NOT NULL,
    created_unix_ns INTEGER NOT NULL,
    latest_sequence INTEGER NOT NULL CHECK (latest_sequence >= 0),
    latest_mutation_mac TEXT NOT NULL,
    metadata_mac TEXT NOT NULL
);

CREATE TABLE state_mutations (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    mutation_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    mutation_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    previous_mutation_mac TEXT,
    key_id TEXT NOT NULL,
    mutation_mac TEXT NOT NULL UNIQUE
);

CREATE TABLE security_envelopes (
    content_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    authority_kind TEXT NOT NULL,
    source_type TEXT NOT NULL,
    trust TEXT NOT NULL,
    ever_untrusted INTEGER NOT NULL CHECK (ever_untrusted IN (0, 1)),
    sensitive INTEGER NOT NULL CHECK (sensitive IN (0, 1)),
    suspicious INTEGER NOT NULL CHECK (suspicious IN (0, 1)),
    findings_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    parent_ids_json TEXT NOT NULL,
    transformations_json TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    ancestor_digests_json TEXT NOT NULL,
    inspection_digest TEXT,
    producing_boundary TEXT NOT NULL,
    creation_event_id TEXT NOT NULL UNIQUE,
    creation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL,
    record_mac TEXT NOT NULL
);

CREATE TABLE envelope_parents (
    content_id TEXT NOT NULL REFERENCES security_envelopes(content_id),
    parent_content_id TEXT NOT NULL REFERENCES security_envelopes(content_id),
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (content_id, parent_content_id),
    UNIQUE (content_id, position)
);

CREATE TABLE causal_events (
    event_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    parent_ids_json TEXT NOT NULL,
    content_ids_json TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    creation_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL,
    record_mac TEXT NOT NULL
);

CREATE TABLE event_parents (
    event_id TEXT NOT NULL REFERENCES causal_events(event_id),
    parent_event_id TEXT NOT NULL REFERENCES causal_events(event_id),
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (event_id, parent_event_id),
    UNIQUE (event_id, position)
);

CREATE TABLE event_contents (
    event_id TEXT NOT NULL REFERENCES causal_events(event_id),
    content_id TEXT NOT NULL REFERENCES security_envelopes(content_id),
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (event_id, content_id),
    UNIQUE (event_id, position)
);

CREATE TABLE workflow_state (
    workflow_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    head_event_id TEXT NOT NULL REFERENCES causal_events(event_id),
    current_content_id TEXT NOT NULL REFERENCES security_envelopes(content_id),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    status TEXT NOT NULL,
    created_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    updated_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL,
    record_mac TEXT NOT NULL
);

CREATE TABLE consumptions (
    consumption_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    token_kind TEXT NOT NULL,
    token_id TEXT NOT NULL,
    consuming_event_id TEXT NOT NULL REFERENCES causal_events(event_id),
    action_fingerprint TEXT,
    commit_sequence INTEGER NOT NULL REFERENCES state_mutations(sequence),
    key_id TEXT NOT NULL,
    record_mac TEXT NOT NULL,
    UNIQUE (instance_id, token_kind, token_id)
);

CREATE TABLE audit_outbox (
    outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
    mutation_sequence INTEGER NOT NULL UNIQUE REFERENCES state_mutations(sequence),
    mutation_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_unix_ns INTEGER NOT NULL,
    exported_unix_ns INTEGER
);

CREATE TABLE runtime_extensions (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    runtime_schema_version TEXT NOT NULL
);

INSERT INTO runtime_extensions VALUES (1, 'gateway-persistent-runtime-v0.3b');
"""

T = TypeVar("T")
MutationBuilder = Callable[
    [sqlite3.Connection, int, str],
    tuple[dict[str, Any], Callable[[sqlite3.Connection], None], T],
]
FailureInjector = Callable[[str], None]
_FCNTL = importlib.import_module("fcntl") if os.name == "posix" else None
_HOST_ROOT_AUTHORITY_CAPABILITY = object()
_EXECUTION_EXTENSION_CAPABILITY = object()


class _NoMutation(Exception):
    def __init__(self, result: Any) -> None:
        self.result = result


class PersistentSecurityState:
    """Isolated authenticated authority store; not a live Gateway backend in v0.3a."""

    def __init__(
        self,
        config: PersistentStateConfig,
        paths: StatePaths,
        key: bytes,
        key_id: str,
        connection: sqlite3.Connection,
        journal_mode: str,
    ) -> None:
        self.config = config
        self.paths = paths
        self.__key = key
        self.key_id = key_id
        self.__connection = connection
        database_info = os.stat(paths.database, follow_symlinks=False)
        key_info = os.stat(paths.key, follow_symlinks=False)
        self.__database_identity = (database_info.st_dev, database_info.st_ino)
        self.__key_identity = (key_info.st_dev, key_info.st_ino)
        self.journal_mode = journal_mode
        self.__faulted = False
        self.__failure_injector: FailureInjector | None = None
        row = self.__metadata_row()
        self.instance_id = str(row["instance_id"])
        self.deployment_id = str(row["deployment_id"])

    @classmethod
    def initialize(cls, config: PersistentStateConfig) -> PersistentSecurityState:
        _validate_config(config)
        paths = prepare_paths(config.state_directory, create=True)
        initial_state = classify_state(paths)
        if initial_state is StoreDirectoryState.PARTIAL_STATE:
            raise StateDirectoryError("partial authority state must not be initialized")
        if initial_state is not StoreDirectoryState.EMPTY_NEW_STORE:
            raise StateInitializationError(
                "authority initialization requires an empty state directory"
            )
        backend = LocalRestrictedFileKeyBackend()
        with _authority_lock(paths, config.busy_timeout_ms):
            if classify_state(paths) is not StoreDirectoryState.EMPTY_NEW_STORE:
                raise StateInitializationError("authority state changed during initialization")
            key, key_id = backend.create(paths.key)
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(paths.database, flags, 0o600)
            except OSError as exc:
                raise StateInitializationError("authority database could not be created") from exc
            os.close(descriptor)
            os.chmod(paths.database, 0o600)
            connection, journal_mode = _open_connection(paths, config, create=True)
            try:
                connection.executescript(_SCHEMA)
                instance_id = _new_id("instance")
                mutation_id = _new_id("mutation")
                genesis_nonce = secrets.token_hex(32)
                created_ns = time.time_ns()
                metadata_payload = {
                    "created_unix_ns": created_ns,
                    "deployment_id": config.deployment_id,
                    "genesis_nonce": genesis_nonce,
                    "instance_id": instance_id,
                    "key_backend": KEY_BACKEND_NAME,
                    "key_id": key_id,
                    "schema_version": SCHEMA_VERSION,
                }
                metadata_mac = record_mac(key, "instance_metadata", metadata_payload)
                changes = [
                    {
                        "action": "upsert",
                        "entity": "instance_metadata",
                        "id": instance_id,
                        "record_mac": metadata_mac,
                    }
                ]
                payload = {"changes": changes, "operation": "GENESIS"}
                mutation = _mutation_payload(
                    key,
                    instance_id=instance_id,
                    deployment_id=config.deployment_id,
                    sequence=0,
                    mutation_id=mutation_id,
                    mutation_type="GENESIS",
                    payload=payload,
                    previous_mutation_mac=None,
                    key_id=key_id,
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO state_mutations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    _mutation_row(mutation),
                )
                connection.execute(
                    """INSERT INTO instance_metadata VALUES
                    (1, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
                    (
                        instance_id,
                        config.deployment_id,
                        SCHEMA_VERSION,
                        key_id,
                        KEY_BACKEND_NAME,
                        genesis_nonce,
                        created_ns,
                        mutation["mutation_mac"],
                        metadata_mac,
                    ),
                )
                connection.commit()
                _write_anchor(
                    paths,
                    key,
                    _final_anchor(
                        instance_id,
                        config.deployment_id,
                        0,
                        str(mutation["mutation_mac"]),
                        key_id,
                    ),
                )
                _fsync_directory(paths.directory)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
                raise
            try:
                store = cls(config, paths, key, key_id, connection, journal_mode)
                connection.execute("BEGIN")
                store.__verify_startup_unlocked()
                connection.commit()
                return store
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
                raise

    @classmethod
    def open(cls, config: PersistentStateConfig) -> PersistentSecurityState:
        _validate_config(config)
        paths = prepare_paths(config.state_directory, create=False)
        state = classify_state(paths)
        if state is StoreDirectoryState.PARTIAL_STATE:
            raise StateDirectoryError("partial authority state must not be opened")
        if state is StoreDirectoryState.EMPTY_NEW_STORE:
            raise StateDirectoryError("authority store does not exist; initialize explicitly")
        key, key_id = LocalRestrictedFileKeyBackend().load(paths.key)
        connection, journal_mode = _open_connection(paths, config, create=False)
        try:
            with _authority_lock(paths, config.busy_timeout_ms):
                connection.execute("BEGIN")
                _recover_anchor(paths, config, connection, key, key_id)
                store = cls(config, paths, key, key_id, connection, journal_mode)
                store.__verify_startup_unlocked()
                connection.commit()
                return store
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            raise StateVerificationError(
                "SQLite authority state is unreadable or inconsistent", code="SQLITE_CORRUPT"
            ) from exc
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            raise

    def close(self) -> None:
        self.__connection.close()

    def __enter__(self) -> PersistentSecurityState:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def health(self) -> StoreHealth:
        def read() -> StoreHealth:
            self.__verify_full_unlocked()
            metadata = self.__metadata_row()
            anchor = _read_and_verify_anchor(self.paths, self.__key)
            return StoreHealth(
                "HEALTHY",
                self.instance_id,
                self.deployment_id,
                int(metadata["latest_sequence"]),
                self.journal_mode,
                AnchorState(str(anchor["state"])),
            )

        return self.__run_verified_read(read)

    def verify_startup(self) -> VerificationReport:
        return self.__run_verified_read(self.__verify_startup_unlocked)

    def enable_runtime_v03b(self) -> None:
        """Install/validate non-authoritative v0.3b runtime support tables."""

        self.__assert_usable()
        with _authority_lock(self.paths, self.config.busy_timeout_ms):
            self.__connection.execute("BEGIN IMMEDIATE")
            try:
                self.__connection.execute(
                    """CREATE TABLE IF NOT EXISTS audit_outbox (
                    outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mutation_sequence INTEGER NOT NULL UNIQUE REFERENCES state_mutations(sequence),
                    mutation_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_unix_ns INTEGER NOT NULL,
                    exported_unix_ns INTEGER)"""
                )
                self.__connection.execute(
                    """CREATE TABLE IF NOT EXISTS runtime_extensions (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    runtime_schema_version TEXT NOT NULL)"""
                )
                expected_columns = {
                    "audit_outbox": (
                        ("outbox_id", "INTEGER", 0, 1),
                        ("mutation_sequence", "INTEGER", 1, 0),
                        ("mutation_type", "TEXT", 1, 0),
                        ("payload_json", "TEXT", 1, 0),
                        ("created_unix_ns", "INTEGER", 1, 0),
                        ("exported_unix_ns", "INTEGER", 0, 0),
                    ),
                    "runtime_extensions": (
                        ("singleton", "INTEGER", 0, 1),
                        ("runtime_schema_version", "TEXT", 1, 0),
                    ),
                }
                for table, expected_schema in expected_columns.items():
                    actual_schema = tuple(
                        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                        for row in self.__connection.execute(f"PRAGMA table_info({table})")
                    )
                    if actual_schema != expected_schema:
                        raise StateVerificationError(
                            f"persistent runtime table {table} is incompatible"
                        )
                row = self.__connection.execute(
                    "SELECT runtime_schema_version FROM runtime_extensions WHERE singleton = 1"
                ).fetchone()
                expected = "gateway-persistent-runtime-v0.3b"
                if row is None:
                    self.__connection.execute(
                        "INSERT INTO runtime_extensions VALUES (1, ?)", (expected,)
                    )
                elif row[0] != expected:
                    raise StateVerificationError("persistent runtime schema is incompatible")
                self.__connection.commit()
            except sqlite3.Error as exc:
                self.__connection.rollback()
                raise StateVerificationError(
                    "persistent runtime schema could not be installed"
                ) from exc
            except Exception:
                self.__connection.rollback()
                raise

    def _enable_execution_extension(
        self, capability: object, installer: Callable[[sqlite3.Connection], None]
    ) -> None:
        """Install the isolated v0.3c1 schema through its internal extension seam."""

        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution schema installation requires host authority")
        self.__assert_usable()
        with _authority_lock(self.paths, self.config.busy_timeout_ms):
            self.__connection.execute("BEGIN IMMEDIATE")
            try:
                installer(self.__connection)
                self.__connection.commit()
            except Exception:
                self.__connection.rollback()
                raise

    def _run_execution_mutation(
        self, capability: object, mutation_type: str, builder: MutationBuilder[T]
    ) -> T:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution mutation requires host authority")
        return self.__run_mutation(mutation_type, builder)

    def _run_execution_read(self, capability: object, operation: Callable[[], T]) -> T:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution read requires host authority")
        return self.__run_verified_read(operation)

    def _execution_record_mac(
        self, capability: object, record_type: str, logical: Mapping[str, Any]
    ) -> str:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution authentication requires host authority")
        return record_mac(self.__key, record_type, logical)

    def _verify_execution_record_mac(
        self,
        capability: object,
        record_type: str,
        logical: Mapping[str, Any],
        mac: str,
    ) -> bool:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution verification requires host authority")
        return verify_record_mac(self.__key, record_type, logical, mac)

    def _execution_verify_event(self, capability: object, event_id: str) -> sqlite3.Row:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution source verification requires host authority")
        return self.__verified_event_row(event_id)

    def _execution_connection(self, capability: object) -> sqlite3.Connection:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution connection requires host authority")
        return self.__connection

    def _execution_inject(self, capability: object, point: str) -> None:
        if capability is not _EXECUTION_EXTENSION_CAPABILITY:
            raise PermissionError("execution fault injection requires host authority")
        self.__inject(point)

    def __verify_startup_unlocked(self) -> VerificationReport:
        self.__assert_usable()
        quick = self.__connection.execute("PRAGMA quick_check").fetchone()
        if quick is None or quick[0] != "ok":
            raise StateVerificationError("SQLite quick_check failed", code="SQLITE_CORRUPT")
        self.__verify_full_unlocked()
        return self.__report(VerificationLevel.STARTUP)

    def verify_head(self) -> VerificationReport:
        def read() -> VerificationReport:
            self.__verify_metadata()
            self.__verify_head()
            return self.__report(VerificationLevel.HEAD)

        return self.__run_verified_read(read)

    def verify_full(self) -> VerificationReport:
        return self.__run_verified_read(self.__verify_full_unlocked)

    def __verify_full_unlocked(self) -> VerificationReport:
        self.__assert_usable()
        integrity = self.__connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise StateVerificationError("SQLite integrity_check failed", code="SQLITE_CORRUPT")
        self.__verify_metadata()
        self.__verify_genesis()
        self.__verify_head()
        expected: dict[str, dict[str, str]] = {
            "instance_metadata": {},
            "security_envelope": {},
            "causal_event": {},
            "workflow_state": {},
            "consumption": {},
        }
        from .execution import execution_expected_entities, execution_schema_present

        if execution_schema_present(self.__connection):
            expected.update(execution_expected_entities())
            from .reconciliation import (
                reconciliation_expected_entities,
                reconciliation_schema_present,
            )

            if reconciliation_schema_present(self.__connection):
                expected.update(reconciliation_expected_entities())
                from .recovery import recovery_expected_entities, recovery_schema_present

                if recovery_schema_present(self.__connection):
                    expected.update(recovery_expected_entities())
        previous_mac: str | None = None
        rows = self.__connection.execute(
            "SELECT * FROM state_mutations ORDER BY sequence"
        ).fetchall()
        for expected_sequence, row in enumerate(rows):
            if int(row["sequence"]) != expected_sequence:
                raise StateVerificationError("mutation sequence has a gap or reorder")
            mutation = self.__verify_mutation_row(row)
            if mutation["previous_mutation_mac"] != previous_mac:
                raise StateVerificationError("mutation chain previous MAC mismatch")
            previous_mac = str(mutation["mutation_mac"])
            payload = mutation["payload"]
            _require_exact(payload, {"changes", "operation"}, "mutation payload")
            changes = payload["changes"]
            if not isinstance(changes, list) or not changes:
                raise StateVerificationError("mutation changes must be a non-empty list")
            for change in changes:
                if not isinstance(change, dict):
                    raise StateVerificationError("mutation change must be an object")
                _require_exact(change, {"action", "entity", "id", "record_mac"}, "change")
                if change["action"] != "upsert" or change["entity"] not in expected:
                    raise StateVerificationError("unsupported materialized-state transition")
                expected[str(change["entity"])][str(change["id"])] = str(change["record_mac"])
        metadata = self.__metadata_row()
        if len(rows) != int(metadata["latest_sequence"]) + 1:
            raise StateVerificationError("mutation count does not match head sequence")
        outbox_rows = self.__connection.execute(
            "SELECT * FROM audit_outbox ORDER BY mutation_sequence"
        ).fetchall()
        if len(outbox_rows) != max(0, len(rows) - 1):
            raise StateVerificationError("audit outbox is incomplete or duplicated")
        for mutation_row, outbox_row in zip(rows[1:], outbox_rows, strict=True):
            if (
                int(outbox_row["mutation_sequence"]) != int(mutation_row["sequence"])
                or outbox_row["mutation_type"] != mutation_row["mutation_type"]
                or outbox_row["payload_json"] != mutation_row["payload_json"]
                or int(outbox_row["created_unix_ns"]) < 1
                or (
                    outbox_row["exported_unix_ns"] is not None
                    and int(outbox_row["exported_unix_ns"]) < 1
                )
            ):
                raise StateVerificationError("audit outbox contradicts authenticated mutation")
        self.__verify_materialized(expected)
        if execution_schema_present(self.__connection):
            from .execution import verify_execution_materialized

            verify_execution_materialized(self, self.__connection, expected)
        return self.__report(VerificationLevel.FULL)

    def __run_verified_read(self, operation: Callable[[], T]) -> T:
        self.__assert_usable()
        if self.__connection.in_transaction:
            return operation()
        with _authority_lock(self.paths, self.config.busy_timeout_ms):
            try:
                self.__connection.execute("BEGIN")
                result = operation()
                self.__connection.commit()
                return result
            except Exception:
                if self.__connection.in_transaction:
                    self.__connection.rollback()
                raise

    def record_envelope(
        self,
        *,
        source_type: str,
        trust: str,
        content_digest: str,
        producing_boundary: str,
        parent_content_ids: Sequence[str] = (),
        ever_untrusted: bool = False,
        sensitive: bool = False,
        suspicious: bool = False,
        findings: Sequence[Mapping[str, Any]] = (),
        provenance: Sequence[str] = (),
        transformations: Sequence[Mapping[str, Any]] = (),
        ancestor_digests: Sequence[str] = (),
        inspection_digest: str | None = None,
        correlation_id: str = "authority-foundation",
    ) -> EnvelopeHandle:
        if not parent_content_ids and trust not in {"EXTERNAL", "UNTRUSTED"}:
            raise TrustedRootIssuanceRequired(
                "TRUSTED/INTERNAL authority requires the explicit host-authoritative root path"
            )
        authority_kind = "DERIVED" if parent_content_ids else "UNTRUSTED_ROOT"
        return self.__record_envelope(
            authority_kind=authority_kind,
            source_type=source_type,
            trust=trust,
            content_digest=content_digest,
            producing_boundary=producing_boundary,
            parent_content_ids=parent_content_ids,
            ever_untrusted=ever_untrusted,
            sensitive=sensitive,
            suspicious=suspicious,
            findings=findings,
            provenance=provenance,
            transformations=transformations,
            ancestor_digests=ancestor_digests,
            inspection_digest=inspection_digest,
            correlation_id=correlation_id,
        )

    def _issue_authoritative_root_for_host(
        self,
        authority_capability: object,
        *,
        source_type: str,
        trust: str,
        content_digest: str,
        producing_boundary: str,
        ever_untrusted: bool = False,
        sensitive: bool = False,
        suspicious: bool = False,
        findings: Sequence[Mapping[str, Any]] = (),
        provenance: Sequence[str] = (),
        transformations: Sequence[Mapping[str, Any]] = (),
        ancestor_digests: Sequence[str] = (),
        inspection_digest: str | None = None,
        correlation_id: str = "authority-foundation",
    ) -> EnvelopeHandle:
        """Host-only issuance seam reserved for a future trusted integration boundary."""

        if authority_capability is not _HOST_ROOT_AUTHORITY_CAPABILITY:
            raise TrustedRootIssuanceRequired("host-authoritative root capability is required")
        if trust not in {"INTERNAL", "TRUSTED"}:
            raise ValueError("host-authoritative roots must be INTERNAL or TRUSTED")
        return self.__record_envelope(
            authority_kind="AUTHORITATIVE_ROOT",
            source_type=source_type,
            trust=trust,
            content_digest=content_digest,
            producing_boundary=producing_boundary,
            ever_untrusted=ever_untrusted,
            sensitive=sensitive,
            suspicious=suspicious,
            findings=findings,
            provenance=provenance,
            transformations=transformations,
            ancestor_digests=ancestor_digests,
            inspection_digest=inspection_digest,
            correlation_id=correlation_id,
        )

    def __record_envelope(
        self,
        *,
        authority_kind: str,
        source_type: str,
        trust: str,
        content_digest: str,
        producing_boundary: str,
        parent_content_ids: Sequence[str] = (),
        ever_untrusted: bool = False,
        sensitive: bool = False,
        suspicious: bool = False,
        findings: Sequence[Mapping[str, Any]] = (),
        provenance: Sequence[str] = (),
        transformations: Sequence[Mapping[str, Any]] = (),
        ancestor_digests: Sequence[str] = (),
        inspection_digest: str | None = None,
        correlation_id: str = "authority-foundation",
    ) -> EnvelopeHandle:
        _validate_envelope_input(
            source_type,
            trust,
            content_digest,
            producing_boundary,
            parent_content_ids,
            findings,
            provenance,
            transformations,
            ancestor_digests,
            inspection_digest,
            correlation_id,
        )
        content_id = _new_id("content")
        event_id = _new_id("event")

        def build(
            connection: sqlite3.Connection, sequence: int, _mutation_id: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], EnvelopeHandle]:
            parents = tuple(sorted(set(parent_content_ids)))
            parent_rows = [
                self.__verified_envelope_row(item, connection=connection) for item in parents
            ]
            effective_trust = trust
            if parent_rows:
                effective_trust = min(
                    (trust, *(str(row["trust"]) for row in parent_rows)),
                    key=_TRUST_ORDER.__getitem__,
                )
            effective_ever = (
                ever_untrusted
                or effective_trust in {"UNTRUSTED", "EXTERNAL"}
                or any(bool(row["ever_untrusted"]) for row in parent_rows)
            )
            effective_sensitive = sensitive or any(bool(row["sensitive"]) for row in parent_rows)
            effective_suspicious = suspicious or any(bool(row["suspicious"]) for row in parent_rows)
            inherited_ancestors = set(ancestor_digests)
            for parent_row in parent_rows:
                inherited_ancestors.add(str(parent_row["content_digest"]))
                inherited_ancestors.update(
                    str(item) for item in _decode_items(str(parent_row["ancestor_digests_json"]))
                )
            if not inherited_ancestors:
                inherited_ancestors.add(content_digest)
            logical = {
                "ancestor_digests": sorted(inherited_ancestors),
                "authority_kind": authority_kind,
                "content_digest": content_digest,
                "content_id": content_id,
                "creation_event_id": event_id,
                "creation_sequence": sequence,
                "deployment_id": self.deployment_id,
                "ever_untrusted": effective_ever,
                "findings": [dict(item) for item in findings],
                "inspection_digest": inspection_digest,
                "instance_id": self.instance_id,
                "key_id": self.key_id,
                "parent_content_ids": list(parents),
                "producing_boundary": producing_boundary,
                "provenance": list(provenance or (f"authority:{self.instance_id}",)),
                "schema_version": SCHEMA_VERSION,
                "sensitive": effective_sensitive,
                "source_type": source_type,
                "suspicious": effective_suspicious,
                "transformations": [dict(item) for item in transformations],
                "trust": effective_trust,
            }
            envelope_mac = record_mac(self.__key, "security_envelope", logical)
            event_logical = _event_logical(
                self,
                event_id=event_id,
                event_type="content_transform",
                correlation_id=correlation_id,
                parent_event_ids=(),
                content_ids=(content_id,),
                attributes={
                    "content_trust": effective_trust,
                    "ever_untrusted": str(effective_ever).lower(),
                    "producing_boundary": producing_boundary,
                },
                sequence=sequence,
            )
            event_mac = record_mac(self.__key, "causal_event", event_logical)
            payload = {
                "changes": [
                    _change("security_envelope", content_id, envelope_mac),
                    _change("causal_event", event_id, event_mac),
                ],
                "operation": (
                    "ISSUE_AUTHORITATIVE_ROOT"
                    if authority_kind == "AUTHORITATIVE_ROOT"
                    else "RECORD_ENVELOPE"
                ),
            }

            def apply(conn: sqlite3.Connection) -> None:
                _insert_envelope(conn, logical, envelope_mac)
                _insert_event(conn, event_logical, event_mac)

            return (
                payload,
                apply,
                EnvelopeHandle(
                    content_id,
                    effective_trust,
                    effective_ever,
                    effective_sensitive,
                    effective_suspicious,
                    content_digest,
                    event_id,
                    sequence,
                ),
            )

        mutation_type = (
            "ISSUE_AUTHORITATIVE_ROOT"
            if authority_kind == "AUTHORITATIVE_ROOT"
            else "RECORD_ENVELOPE"
        )
        return self.__run_mutation(mutation_type, build)

    def record_event(
        self,
        *,
        event_type: str,
        correlation_id: str,
        parent_event_ids: Sequence[str] = (),
        content_ids: Sequence[str] = (),
        attributes: Mapping[str, str] | None = None,
    ) -> EventHandle:
        _validate_event_input(event_type, correlation_id, parent_event_ids, content_ids, attributes)
        event_id = _new_id("event")

        def build(
            connection: sqlite3.Connection, sequence: int, _mutation_id: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], EventHandle]:
            parents = tuple(sorted(set(parent_event_ids)))
            contents = tuple(sorted(set(content_ids)))
            for item in parents:
                self.__verified_event_row(item, connection=connection)
            for item in contents:
                self.__verified_envelope_row(item, connection=connection)
            logical = _event_logical(
                self,
                event_id=event_id,
                event_type=event_type,
                correlation_id=correlation_id,
                parent_event_ids=parents,
                content_ids=contents,
                attributes=dict(attributes or {}),
                sequence=sequence,
            )
            event_mac = record_mac(self.__key, "causal_event", logical)
            payload = {
                "changes": [_change("causal_event", event_id, event_mac)],
                "operation": "RECORD_EVENT",
            }

            def apply(conn: sqlite3.Connection) -> None:
                _insert_event(conn, logical, event_mac)

            return payload, apply, EventHandle(event_id, event_type, correlation_id, sequence)

        return self.__run_mutation("RECORD_EVENT", build)

    def get_event(self, event_id: str) -> VerifiedEventRecord:
        """Return one fully authenticated causal event without exposing SQL."""

        def read() -> VerifiedEventRecord:
            row = self.__verified_event_row(event_id)
            attributes = strict_json_object(str(row["attributes_json"]))
            return VerifiedEventRecord(
                event_id=str(row["event_id"]),
                event_type=str(row["event_type"]),
                correlation_id=str(row["correlation_id"]),
                parent_event_ids=tuple(
                    str(item) for item in _decode_items(str(row["parent_ids_json"]))
                ),
                content_ids=tuple(
                    str(item) for item in _decode_items(str(row["content_ids_json"]))
                ),
                attributes={str(key): str(value) for key, value in attributes.items()},
                mutation_sequence=int(row["creation_sequence"]),
            )

        return self.__run_verified_read(read)

    def get_workflow(self, workflow_id: str) -> WorkflowHandle:
        """Reload the current authenticated workflow head and revision."""

        def read() -> WorkflowHandle:
            row = self.__connection.execute(
                "SELECT * FROM workflow_state WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if row is None:
                raise UnknownAuthorityRecord("workflow does not exist")
            self.__verify_workflow_row(row)
            return _workflow_handle(_workflow_logical_from_row(row))

        return self.__run_verified_read(read)

    def is_consumed(self, *, token_kind: str, token_id: str) -> bool:
        """Authenticate and report persistent one-shot state."""

        def read() -> bool:
            row = self.__connection.execute(
                "SELECT * FROM consumptions "
                "WHERE instance_id = ? AND token_kind = ? AND token_id = ?",
                (self.instance_id, token_kind, token_id),
            ).fetchone()
            if row is None:
                return False
            self.__verify_consumption_row(row)
            return True

        return self.__run_verified_read(read)

    def pending_audit(self, *, limit: int = 100) -> tuple[AuditOutboxRecord, ...]:
        """Return non-authoritative evidence waiting for projection."""

        if limit < 1 or limit > 10_000:
            raise ValueError("audit outbox limit is invalid")

        def read() -> tuple[AuditOutboxRecord, ...]:
            rows = self.__connection.execute(
                "SELECT outbox_id, mutation_sequence, mutation_type, payload_json, created_unix_ns "
                "FROM audit_outbox WHERE exported_unix_ns IS NULL ORDER BY outbox_id LIMIT ?",
                (limit,),
            ).fetchall()
            return tuple(
                AuditOutboxRecord(
                    int(row["outbox_id"]),
                    int(row["mutation_sequence"]),
                    str(row["mutation_type"]),
                    str(row["payload_json"]),
                    int(row["created_unix_ns"]),
                )
                for row in rows
            )

        return self.__run_verified_read(read)

    def mark_audit_exported(self, outbox_id: int) -> None:
        """Mark projected evidence; this never changes live authority."""

        self.__assert_usable()
        with _authority_lock(self.paths, self.config.busy_timeout_ms):
            self.__connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = self.__connection.execute(
                    "UPDATE audit_outbox SET exported_unix_ns = ? "
                    "WHERE outbox_id = ? AND exported_unix_ns IS NULL",
                    (time.time_ns(), outbox_id),
                )
                if cursor.rowcount != 1:
                    raise UnknownAuthorityRecord("audit outbox record is missing or exported")
                self.__connection.commit()
            except Exception:
                self.__connection.rollback()
                raise

    def create_workflow(
        self,
        workflow_id: str,
        *,
        head_event_id: str,
        current_content_id: str,
    ) -> WorkflowHandle:
        _validate_routing_id(workflow_id, "workflow_id")

        def build(
            connection: sqlite3.Connection, sequence: int, _mutation_id: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], WorkflowHandle]:
            if connection.execute(
                "SELECT 1 FROM workflow_state WHERE workflow_id = ?", (workflow_id,)
            ).fetchone():
                raise StateInitializationError("workflow_id already exists", code="DUPLICATE_ID")
            event = self.__verified_event_row(head_event_id, connection=connection)
            self.__verified_envelope_row(current_content_id, connection=connection)
            if current_content_id not in _decode_list(str(event["content_ids_json"])):
                raise StateInitializationError("workflow head does not reference current content")
            logical = _workflow_logical(
                self,
                workflow_id,
                head_event_id,
                current_content_id,
                revision=0,
                status="ACTIVE",
                created_sequence=sequence,
                updated_sequence=sequence,
            )
            workflow_mac = record_mac(self.__key, "workflow_state", logical)
            payload = {
                "changes": [_change("workflow_state", workflow_id, workflow_mac)],
                "operation": "CREATE_WORKFLOW",
            }

            def apply(conn: sqlite3.Connection) -> None:
                _insert_workflow(conn, logical, workflow_mac)

            return payload, apply, _workflow_handle(logical)

        return self.__run_mutation("CREATE_WORKFLOW", build)

    def advance_workflow(
        self,
        workflow_id: str,
        *,
        expected_revision: int,
        expected_head: str,
        new_head: str,
    ) -> WorkflowHandle:
        _validate_routing_id(workflow_id, "workflow_id")
        if expected_revision < 0:
            raise ValueError("expected_revision cannot be negative")

        def build(
            connection: sqlite3.Connection, sequence: int, _mutation_id: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], WorkflowHandle]:
            row = connection.execute(
                "SELECT * FROM workflow_state WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if row is None:
                raise UnknownAuthorityRecord("workflow does not exist")
            self.__verify_workflow_row(row, connection=connection)
            if int(row["revision"]) != expected_revision or row["head_event_id"] != expected_head:
                raise WorkflowCASConflict("workflow head or revision is stale")
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='execution_workflow_barriers'"
            ).fetchone():
                barrier = connection.execute(
                    "SELECT active_intent_id, status FROM execution_workflow_barriers "
                    "WHERE workflow_id=?",
                    (workflow_id,),
                ).fetchone()
                if barrier is not None and (
                    barrier["active_intent_id"] is not None or barrier["status"] != "ACTIVE"
                ):
                    raise WorkflowCASConflict("workflow has an active execution-authority barrier")
            event = self.__verified_event_row(new_head, connection=connection)
            content_ids = _decode_list(str(event["content_ids_json"]))
            current_content_id = (
                str(content_ids[-1]) if content_ids else str(row["current_content_id"])
            )
            logical = _workflow_logical(
                self,
                workflow_id,
                new_head,
                current_content_id,
                revision=expected_revision + 1,
                status=str(row["status"]),
                created_sequence=int(row["created_sequence"]),
                updated_sequence=sequence,
            )
            workflow_mac = record_mac(self.__key, "workflow_state", logical)
            payload = {
                "changes": [_change("workflow_state", workflow_id, workflow_mac)],
                "operation": "ADVANCE_WORKFLOW",
            }

            def apply(conn: sqlite3.Connection) -> None:
                cursor = conn.execute(
                    """UPDATE workflow_state SET head_event_id = ?, current_content_id = ?,
                    revision = ?, updated_sequence = ?, key_id = ?, record_mac = ?
                    WHERE workflow_id = ? AND revision = ? AND head_event_id = ?""",
                    (
                        new_head,
                        current_content_id,
                        expected_revision + 1,
                        sequence,
                        self.key_id,
                        workflow_mac,
                        workflow_id,
                        expected_revision,
                        expected_head,
                    ),
                )
                if cursor.rowcount != 1:
                    raise WorkflowCASConflict("workflow CAS lost during update")

            return payload, apply, _workflow_handle(logical)

        return self.__run_mutation("ADVANCE_WORKFLOW", build)

    def consume_once(
        self,
        *,
        token_kind: str,
        token_id: str,
        consuming_event_id: str,
        action_fingerprint: str | None = None,
    ) -> ConsumptionResult:
        if not _TOKEN_KIND.fullmatch(token_kind):
            raise ValueError("token_kind is not canonical")
        _validate_routing_id(token_id, "token_id")
        if action_fingerprint is not None:
            _validate_digest(action_fingerprint, "action_fingerprint")

        def build(
            connection: sqlite3.Connection, sequence: int, _mutation_id: str
        ) -> tuple[dict[str, Any], Callable[[sqlite3.Connection], None], ConsumptionResult]:
            self.__verify_consumable_source(token_id, connection=connection)
            existing = connection.execute(
                """SELECT consumption_id FROM consumptions
                WHERE instance_id = ? AND token_kind = ? AND token_id = ?""",
                (self.instance_id, token_kind, token_id),
            ).fetchone()
            if existing is not None:
                raise _NoMutation(
                    ConsumptionResult(False, "ALREADY_CONSUMED", token_kind, token_id)
                )
            self.__verified_event_row(consuming_event_id, connection=connection)
            consumption_id = _new_id("consumption")
            logical = {
                "action_fingerprint": action_fingerprint,
                "commit_sequence": sequence,
                "consuming_event_id": consuming_event_id,
                "consumption_id": consumption_id,
                "deployment_id": self.deployment_id,
                "instance_id": self.instance_id,
                "key_id": self.key_id,
                "schema_version": SCHEMA_VERSION,
                "token_id": token_id,
                "token_kind": token_kind,
            }
            consumption_mac = record_mac(self.__key, "consumption", logical)
            entity_id = f"{token_kind}:{token_id}"
            payload = {
                "changes": [_change("consumption", entity_id, consumption_mac)],
                "operation": "CONSUME_ONCE",
            }

            def apply(conn: sqlite3.Connection) -> None:
                conn.execute(
                    """INSERT INTO consumptions VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        consumption_id,
                        self.instance_id,
                        self.deployment_id,
                        SCHEMA_VERSION,
                        token_kind,
                        token_id,
                        consuming_event_id,
                        action_fingerprint,
                        sequence,
                        self.key_id,
                        consumption_mac,
                    ),
                )

            return (
                payload,
                apply,
                ConsumptionResult(
                    True,
                    "CONSUMED",
                    token_kind,
                    token_id,
                    consumption_id,
                    sequence,
                ),
            )

        return self.__run_mutation("CONSUME_ONCE", build)

    def __verify_consumable_source(self, token_id: str, *, connection: sqlite3.Connection) -> None:
        if token_id.startswith("content-"):
            self.__verified_envelope_graph(token_id, connection=connection)
            return
        if token_id.startswith("event-"):
            self.__verified_event_row(token_id, connection=connection)
            return
        if token_id.startswith("mutation-"):
            row = connection.execute(
                "SELECT * FROM state_mutations WHERE mutation_id = ?", (token_id,)
            ).fetchone()
            if row is None:
                raise UnknownAuthorityRecord("consumption source mutation does not exist")
            self.__verify_mutation_row(row)
            return
        raise UnknownAuthorityRecord(
            "consumption token must identify an existing authenticated authority record"
        )

    def get_envelope(self, content_id: str) -> VerifiedEnvelopeRecord:
        self.__assert_usable()
        with _authority_lock(self.paths, self.config.busy_timeout_ms):
            try:
                self.__connection.execute("BEGIN")
                self.verify_full()
                row = self.__verified_envelope_graph(content_id)
                result = _verified_envelope_record(row)
                self.__connection.commit()
                return result
            except Exception:
                if self.__connection.in_transaction:
                    self.__connection.rollback()
                raise

    def _set_failure_injector_for_testing(self, injector: FailureInjector | None) -> None:
        self.__failure_injector = injector

    def __run_mutation(self, mutation_type: str, builder: MutationBuilder[T]) -> T:
        self.__assert_usable()
        prepared_written = False
        committed = False
        with _authority_lock(self.paths, self.config.busy_timeout_ms):
            try:
                self.__connection.execute("BEGIN IMMEDIATE")
                self.verify_full()
                metadata = self.__metadata_row()
                final_anchor = self.__verify_head(require_final=True)
                sequence = int(metadata["latest_sequence"]) + 1
                mutation_id = _new_id("mutation")
                payload, apply, result = builder(self.__connection, sequence, mutation_id)
                mutation = _mutation_payload(
                    self.__key,
                    instance_id=self.instance_id,
                    deployment_id=self.deployment_id,
                    sequence=sequence,
                    mutation_id=mutation_id,
                    mutation_type=mutation_type,
                    payload=payload,
                    previous_mutation_mac=str(metadata["latest_mutation_mac"]),
                    key_id=self.key_id,
                )
                self.__inject("before_prepared_anchor")
                prepared = _prepared_anchor(
                    self.instance_id,
                    self.deployment_id,
                    sequence,
                    str(mutation["mutation_mac"]),
                    int(final_anchor["sequence"]),
                    str(final_anchor["mutation_mac"]),
                    self.key_id,
                )
                _write_anchor(self.paths, self.__key, prepared)
                prepared_written = True
                self.__inject("after_prepared_anchor")
                self.__connection.execute(
                    "INSERT INTO state_mutations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    _mutation_row(mutation),
                )
                apply(self.__connection)
                self.__connection.execute(
                    "INSERT INTO audit_outbox "
                    "(mutation_sequence, mutation_type, payload_json, created_unix_ns) "
                    "VALUES (?, ?, ?, ?)",
                    (sequence, mutation_type, canonical_text(payload), time.time_ns()),
                )
                self.__connection.execute(
                    """UPDATE instance_metadata
                    SET latest_sequence = ?, latest_mutation_mac = ? WHERE singleton = 1""",
                    (sequence, mutation["mutation_mac"]),
                )
                self.__inject("before_sqlite_commit")
                self.__connection.commit()
                committed = True
                self.__inject("after_sqlite_commit")
                persisted = self.__connection.execute(
                    "SELECT mutation_mac FROM state_mutations WHERE sequence = ?", (sequence,)
                ).fetchone()
                if persisted is None or persisted[0] != mutation["mutation_mac"]:
                    raise StateVerificationError("committed mutation does not match preparation")
                self.__inject("before_final_anchor")
                _write_anchor(
                    self.paths,
                    self.__key,
                    _final_anchor(
                        self.instance_id,
                        self.deployment_id,
                        sequence,
                        str(mutation["mutation_mac"]),
                        self.key_id,
                    ),
                )
                self.__inject("after_final_anchor")
                return result
            except _NoMutation as no_mutation:
                if self.__connection.in_transaction:
                    self.__connection.rollback()
                return no_mutation.result
            except Exception:
                if self.__connection.in_transaction:
                    self.__connection.rollback()
                if prepared_written or committed:
                    self.__faulted = True
                raise

    def __inject(self, point: str) -> None:
        if self.__failure_injector is not None:
            self.__failure_injector(point)

    def __assert_usable(self) -> None:
        if self.__faulted:
            raise StateVerificationError(
                "authority store requires close and verified reopen after interrupted mutation",
                code="RECOVERY_REQUIRED",
            )

    def __metadata_row(self) -> sqlite3.Row:
        row = self.__connection.execute(
            "SELECT * FROM instance_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise StateVerificationError("instance metadata is missing")
        return row

    def __verify_metadata(self) -> None:
        try:
            database_info = os.stat(self.paths.database, follow_symlinks=False)
            key_info = os.stat(self.paths.key, follow_symlinks=False)
        except OSError as exc:
            raise StateDirectoryError("authority database or key path is unavailable") from exc
        if (database_info.st_dev, database_info.st_ino) != self.__database_identity:
            raise StateDirectoryError("authority database identity changed after open")
        if (key_info.st_dev, key_info.st_ino) != self.__key_identity:
            raise StateDirectoryError("authority key identity changed after open")
        persisted_key, persisted_key_id = LocalRestrictedFileKeyBackend().load(self.paths.key)
        if persisted_key_id != self.key_id or not secrets.compare_digest(persisted_key, self.__key):
            raise StateAuthenticationError("authority key no longer matches the open store")
        row = self.__metadata_row()
        if (
            row["schema_version"] != SCHEMA_VERSION
            or row["deployment_id"] != self.config.deployment_id
            or row["key_id"] != self.key_id
            or row["key_backend"] != KEY_BACKEND_NAME
        ):
            raise StateVerificationError("instance metadata does not match configured authority")
        logical = {
            "created_unix_ns": int(row["created_unix_ns"]),
            "deployment_id": str(row["deployment_id"]),
            "genesis_nonce": str(row["genesis_nonce"]),
            "instance_id": str(row["instance_id"]),
            "key_backend": str(row["key_backend"]),
            "key_id": str(row["key_id"]),
            "schema_version": str(row["schema_version"]),
        }
        if not verify_record_mac(
            self.__key, "instance_metadata", logical, str(row["metadata_mac"])
        ):
            raise StateAuthenticationError("instance metadata MAC is invalid")

    def __verify_genesis(self) -> None:
        row = self.__connection.execute(
            "SELECT * FROM state_mutations WHERE sequence = 0"
        ).fetchone()
        if row is None:
            raise StateVerificationError("authenticated genesis mutation is missing")
        mutation = self.__verify_mutation_row(row)
        metadata = self.__metadata_row()
        expected_change = _change(
            "instance_metadata", self.instance_id, str(metadata["metadata_mac"])
        )
        if (
            mutation["mutation_type"] != "GENESIS"
            or mutation["previous_mutation_mac"] is not None
            or mutation["payload"] != {"changes": [expected_change], "operation": "GENESIS"}
        ):
            raise StateVerificationError("authenticated genesis semantics are invalid")

    def __verify_head(self, *, require_final: bool = True) -> dict[str, Any]:
        metadata = self.__metadata_row()
        sequence = int(metadata["latest_sequence"])
        row = self.__connection.execute(
            "SELECT * FROM state_mutations WHERE sequence = ?", (sequence,)
        ).fetchone()
        if row is None:
            raise StateVerificationError("latest mutation is missing")
        mutation = self.__verify_mutation_row(row)
        if mutation["mutation_mac"] != metadata["latest_mutation_mac"]:
            raise StateVerificationError("materialized mutation head is inconsistent")
        anchor = _read_and_verify_anchor(self.paths, self.__key)
        if require_final and anchor["state"] != AnchorState.FINAL.value:
            raise StateVerificationError("authority anchor is not FINAL")
        if (
            anchor["instance_id"] != self.instance_id
            or anchor["deployment_id"] != self.deployment_id
            or anchor["key_id"] != self.key_id
            or int(anchor["sequence"]) != sequence
            or anchor.get("mutation_mac") != mutation["mutation_mac"]
        ):
            raise StateRollbackError("database and high-water anchor disagree")
        return anchor

    def __verify_mutation_row(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            payload = strict_json_object(str(row["payload_json"]))
        except CanonicalAuthorityError as exc:
            raise StateVerificationError("mutation payload is not canonical") from exc
        payload_sha = sha256_hex(str(row["payload_json"]).encode("utf-8"))
        if payload_sha != row["payload_sha256"]:
            raise StateVerificationError("mutation payload digest mismatch")
        logical = {
            "deployment_id": str(row["deployment_id"]),
            "instance_id": str(row["instance_id"]),
            "key_id": str(row["key_id"]),
            "mutation_id": str(row["mutation_id"]),
            "mutation_type": str(row["mutation_type"]),
            "payload": payload,
            "payload_sha256": str(row["payload_sha256"]),
            "previous_mutation_mac": row["previous_mutation_mac"],
            "schema_version": str(row["schema_version"]),
            "sequence": int(row["sequence"]),
        }
        if (
            logical["instance_id"] != self.instance_id
            or logical["deployment_id"] != self.deployment_id
            or logical["schema_version"] != SCHEMA_VERSION
            or logical["key_id"] != self.key_id
            or not _AUTHORITY_ID.fullmatch(str(logical["mutation_id"]))
        ):
            raise StateVerificationError("mutation authority fields are invalid")
        if not verify_record_mac(self.__key, "state_mutation", logical, str(row["mutation_mac"])):
            raise StateAuthenticationError("mutation MAC is invalid")
        return {**logical, "mutation_mac": str(row["mutation_mac"])}

    def __verified_envelope_row(
        self, content_id: str, *, connection: sqlite3.Connection | None = None
    ) -> sqlite3.Row:
        conn = connection or self.__connection
        row = conn.execute(
            "SELECT * FROM security_envelopes WHERE content_id = ?", (content_id,)
        ).fetchone()
        if row is None:
            raise UnknownAuthorityRecord(f"unknown envelope: {content_id}")
        logical = _envelope_logical_from_row(row)
        _verify_common_record(self, logical)
        if logical["trust"] not in _TRUST_ORDER:
            raise StateVerificationError("envelope trust classification is invalid")
        if not verify_record_mac(self.__key, "security_envelope", logical, str(row["record_mac"])):
            raise StateAuthenticationError("security envelope MAC is invalid")
        relation = tuple(
            item[0]
            for item in conn.execute(
                """SELECT parent_content_id FROM envelope_parents
                WHERE content_id = ? ORDER BY position""",
                (content_id,),
            )
        )
        if relation != tuple(logical["parent_content_ids"]):
            raise StateVerificationError("envelope parent relationship mismatch")
        authority_kind = str(logical["authority_kind"])
        if authority_kind == "UNTRUSTED_ROOT":
            if relation or logical["trust"] not in {"EXTERNAL", "UNTRUSTED"}:
                raise StateVerificationError("untrusted root authority semantics are invalid")
            if not logical["ever_untrusted"]:
                raise StateVerificationError("untrusted root must retain sticky untrusted state")
        elif authority_kind == "AUTHORITATIVE_ROOT":
            if relation or logical["trust"] not in {"INTERNAL", "TRUSTED"}:
                raise StateVerificationError("host-authoritative root semantics are invalid")
        elif authority_kind == "DERIVED":
            if not relation:
                raise StateVerificationError("derived envelope must bind at least one parent")
        else:
            raise StateVerificationError("envelope authority kind is invalid")
        parent_rows: list[sqlite3.Row] = []
        for parent_id in relation:
            parent_row = conn.execute(
                "SELECT * FROM security_envelopes WHERE content_id = ?", (parent_id,)
            ).fetchone()
            if parent_row is None:
                raise StateVerificationError("envelope parent is missing")
            parent_rows.append(parent_row)
        if parent_rows:
            least_parent_trust = min(
                (str(parent["trust"]) for parent in parent_rows), key=_TRUST_ORDER.__getitem__
            )
            if _TRUST_ORDER[str(logical["trust"])] > _TRUST_ORDER[least_parent_trust]:
                raise StateVerificationError(
                    "derived envelope raises its authenticated trust floor"
                )
            for field in ("ever_untrusted", "sensitive", "suspicious"):
                if any(bool(parent[field]) for parent in parent_rows) and not logical[field]:
                    raise StateVerificationError(f"derived envelope launders sticky {field}")
        creation_event = self.__verified_event_row(
            str(logical["creation_event_id"]), connection=conn
        )
        if content_id not in _decode_list(str(creation_event["content_ids_json"])):
            raise StateVerificationError("envelope creation event does not bind its content")
        return row

    def __verified_envelope_graph(
        self, content_id: str, *, connection: sqlite3.Connection | None = None
    ) -> sqlite3.Row:
        conn = connection or self.__connection
        pending = [content_id]
        verified: dict[str, sqlite3.Row] = {}
        while pending:
            current = pending.pop()
            if current in verified:
                continue
            if len(verified) >= MAX_AUTHORITY_GRAPH_NODES:
                raise StateVerificationError("envelope ancestry exceeds verification node limit")
            row = self.__verified_envelope_row(current, connection=conn)
            verified[current] = row
            pending.extend(str(item) for item in _decode_items(str(row["parent_ids_json"])))
        return verified[content_id]

    def __verified_event_row(
        self, event_id: str, *, connection: sqlite3.Connection | None = None
    ) -> sqlite3.Row:
        conn = connection or self.__connection
        row = conn.execute("SELECT * FROM causal_events WHERE event_id = ?", (event_id,)).fetchone()
        if row is None:
            raise UnknownAuthorityRecord(f"unknown causal event: {event_id}")
        logical = _event_logical_from_row(row)
        _verify_common_record(self, logical)
        if not verify_record_mac(self.__key, "causal_event", logical, str(row["record_mac"])):
            raise StateAuthenticationError("causal event MAC is invalid")
        parents = tuple(
            item[0]
            for item in conn.execute(
                "SELECT parent_event_id FROM event_parents WHERE event_id = ? ORDER BY position",
                (event_id,),
            )
        )
        contents = tuple(
            item[0]
            for item in conn.execute(
                "SELECT content_id FROM event_contents WHERE event_id = ? ORDER BY position",
                (event_id,),
            )
        )
        if parents != tuple(logical["parent_event_ids"]) or contents != tuple(
            logical["content_ids"]
        ):
            raise StateVerificationError("causal event relationship mismatch")
        return row

    def __verify_workflow_row(
        self, row: sqlite3.Row, *, connection: sqlite3.Connection | None = None
    ) -> None:
        logical = _workflow_logical_from_row(row)
        _verify_common_record(self, logical)
        if not verify_record_mac(self.__key, "workflow_state", logical, str(row["record_mac"])):
            raise StateAuthenticationError("workflow state MAC is invalid")
        if int(row["updated_sequence"]) < int(row["created_sequence"]):
            raise StateVerificationError("workflow revision sequence decreased")
        conn = connection or self.__connection
        if (
            conn.execute(
                "SELECT 1 FROM causal_events WHERE event_id = ?", (row["head_event_id"],)
            ).fetchone()
            is None
        ):
            raise StateVerificationError("workflow head event is missing")
        if (
            conn.execute(
                "SELECT 1 FROM security_envelopes WHERE content_id = ?",
                (row["current_content_id"],),
            ).fetchone()
            is None
        ):
            raise StateVerificationError("workflow content is missing")

    def __verify_consumption_row(self, row: sqlite3.Row) -> None:
        logical = _consumption_logical_from_row(row)
        _verify_common_record(self, logical)
        if not verify_record_mac(self.__key, "consumption", logical, str(row["record_mac"])):
            raise StateAuthenticationError("consumption MAC is invalid")

    def __verify_materialized(self, expected: dict[str, dict[str, str]]) -> None:
        metadata = self.__metadata_row()
        actual_instance = {self.instance_id: str(metadata["metadata_mac"])}
        if actual_instance != expected["instance_metadata"]:
            raise StateVerificationError("instance materialized state disagrees with mutations")
        actual_envelopes: dict[str, str] = {}
        for row in self.__connection.execute("SELECT * FROM security_envelopes"):
            self.__verified_envelope_row(str(row["content_id"]))
            actual_envelopes[str(row["content_id"])] = str(row["record_mac"])
        actual_events: dict[str, str] = {}
        for row in self.__connection.execute("SELECT * FROM causal_events"):
            self.__verified_event_row(str(row["event_id"]))
            actual_events[str(row["event_id"])] = str(row["record_mac"])
        actual_workflows: dict[str, str] = {}
        for row in self.__connection.execute("SELECT * FROM workflow_state"):
            self.__verify_workflow_row(row)
            actual_workflows[str(row["workflow_id"])] = str(row["record_mac"])
        actual_consumptions: dict[str, str] = {}
        for row in self.__connection.execute("SELECT * FROM consumptions"):
            self.__verify_consumption_row(row)
            key = f"{row['token_kind']}:{row['token_id']}"
            actual_consumptions[key] = str(row["record_mac"])
        actual = {
            "security_envelope": actual_envelopes,
            "causal_event": actual_events,
            "workflow_state": actual_workflows,
            "consumption": actual_consumptions,
        }
        for entity, records in actual.items():
            if records != expected[entity]:
                raise StateVerificationError(f"{entity} materialized state mismatch")

    def __report(self, level: VerificationLevel) -> VerificationReport:
        metadata = self.__metadata_row()
        count = lambda table: int(  # noqa: E731
            self.__connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        )
        return VerificationReport(
            True,
            level,
            int(metadata["latest_sequence"]),
            count("state_mutations"),
            count("security_envelopes"),
            count("causal_events"),
            count("workflow_state"),
            count("consumptions"),
        )


def _validate_config(config: PersistentStateConfig) -> None:
    if not isinstance(config, PersistentStateConfig):
        raise TypeError("config must be PersistentStateConfig")
    if not _DEPLOYMENT_ID.fullmatch(config.deployment_id):
        raise ValueError("deployment_id must be canonical lowercase local metadata")
    if not 10 <= config.busy_timeout_ms <= 30_000:
        raise ValueError("busy timeout must be between 10 and 30,000 milliseconds")


def _open_connection(
    paths: StatePaths, config: PersistentStateConfig, *, create: bool
) -> tuple[sqlite3.Connection, str]:
    if paths.database.is_symlink():
        raise StateDirectoryError("authority database cannot be a symlink")
    _require_restricted_file(paths.database, "authority database")
    for suffix in ("-wal", "-shm"):
        sidecar = paths.database.with_name(paths.database.name + suffix)
        if os.path.lexists(sidecar):
            _require_restricted_file(sidecar, f"SQLite {suffix[1:].upper()} sidecar")
    before = os.stat(paths.database, follow_symlinks=False)
    mode = "rwc" if create else "rw"
    quoted_path = urllib.parse.quote(paths.database.as_posix(), safe="/")
    uri = f"file:{quoted_path}?mode={mode}"
    try:
        connection = sqlite3.connect(
            uri,
            uri=True,
            isolation_level=None,
            timeout=config.busy_timeout_ms / 1_000,
        )
    except sqlite3.Error as exc:
        raise StateDirectoryError("authority database could not be opened") from exc
    connection.row_factory = sqlite3.Row
    connection.enable_load_extension(False)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute(f"PRAGMA busy_timeout = {config.busy_timeout_ms}")
    connection.execute("PRAGMA trusted_schema = OFF")
    journal = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
    if config.require_wal and journal != "wal":
        connection.close()
        raise StateInitializationError("authority database could not enable required WAL mode")
    foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
    synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
    if foreign_keys != 1 or synchronous < 2:
        connection.close()
        raise StateInitializationError("required SQLite safety configuration is unavailable")
    after = os.stat(paths.database, follow_symlinks=False)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        connection.close()
        raise StateDirectoryError("authority database changed identity while opening")
    if create:
        os.chmod(paths.database, 0o600)
    return connection, journal


@contextlib.contextmanager
def _authority_lock(paths: StatePaths, timeout_ms: int) -> Iterator[None]:
    if _FCNTL is None:
        raise StateDirectoryError("POSIX flock authority locking is unavailable")
    if paths.lock.is_symlink():
        raise StateDirectoryError("authority mutation lock cannot be a symlink")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(paths.lock, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise StateDirectoryError("authority mutation lock is not a regular file")
        if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
            raise StateDirectoryError("authority mutation lock permissions are unsafe")
        if os.fstat(descriptor).st_nlink != 1:
            raise StateDirectoryError("authority mutation lock must not have a hard link")
        deadline = time.monotonic() + timeout_ms / 1_000
        while True:
            try:
                _FCNTL.flock(descriptor, _FCNTL.LOCK_EX | _FCNTL.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StateBusyError("authority mutation lock timed out") from None
                time.sleep(0.01)
        yield
    finally:
        with contextlib.suppress(OSError):
            _FCNTL.flock(descriptor, _FCNTL.LOCK_UN)
        os.close(descriptor)


def _recover_anchor(
    paths: StatePaths,
    config: PersistentStateConfig,
    connection: sqlite3.Connection,
    key: bytes,
    key_id: str,
) -> None:
    metadata = connection.execute("SELECT * FROM instance_metadata WHERE singleton = 1").fetchone()
    if metadata is None:
        raise StateVerificationError("instance metadata is missing")
    if metadata["deployment_id"] != config.deployment_id or metadata["key_id"] != key_id:
        raise StateAuthenticationError("configured deployment/key does not match authority state")
    anchor = _read_and_verify_anchor(paths, key)
    if (
        anchor["instance_id"] != metadata["instance_id"]
        or anchor["deployment_id"] != config.deployment_id
        or anchor["key_id"] != key_id
    ):
        raise StateAuthenticationError("anchor identity does not match authority store")
    latest_sequence = int(metadata["latest_sequence"])
    latest = connection.execute(
        "SELECT mutation_mac FROM state_mutations WHERE sequence = ?", (latest_sequence,)
    ).fetchone()
    if latest is None or latest[0] != metadata["latest_mutation_mac"]:
        raise StateVerificationError("database mutation head is inconsistent")
    if anchor["state"] == AnchorState.FINAL.value:
        if int(anchor["sequence"]) != latest_sequence:
            raise StateRollbackError("FINAL anchor and database sequence disagree")
        if anchor["mutation_mac"] != latest[0]:
            raise StateRollbackError("FINAL anchor and database mutation MAC disagree")
        return
    prepared_sequence = int(anchor["sequence"])
    previous_sequence = int(anchor["previous_final_sequence"])
    previous_mac = str(anchor["previous_final_mac"])
    if prepared_sequence != previous_sequence + 1:
        raise StateRollbackError("PREPARED anchor sequence is not adjacent")
    if latest_sequence == previous_sequence and latest[0] == previous_mac:
        _write_anchor(
            paths,
            key,
            _final_anchor(
                str(metadata["instance_id"]),
                config.deployment_id,
                previous_sequence,
                previous_mac,
                key_id,
            ),
        )
        return
    if latest_sequence == prepared_sequence and latest[0] == anchor["expected_mutation_mac"]:
        _write_anchor(
            paths,
            key,
            _final_anchor(
                str(metadata["instance_id"]),
                config.deployment_id,
                prepared_sequence,
                str(latest[0]),
                key_id,
            ),
        )
        return
    raise StateRollbackError("PREPARED anchor cannot be reconciled with database head")


def _write_anchor(paths: StatePaths, key: bytes, payload: dict[str, Any]) -> None:
    if paths.anchor.is_symlink():
        raise StateDirectoryError("authority anchor cannot be a symlink")
    authenticated = dict(payload)
    authenticated["anchor_mac"] = record_mac(key, "high_water_anchor", payload)
    rendered = canonical_text(authenticated).encode("utf-8") + b"\n"
    temporary = paths.directory / f".authority.anchor.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(rendered)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StateDirectoryError("authority anchor write did not complete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, paths.anchor)
    os.chmod(paths.anchor, 0o600)
    _fsync_directory(paths.directory)


def _read_and_verify_anchor(paths: StatePaths, key: bytes) -> dict[str, Any]:
    if paths.anchor.is_symlink() or not paths.anchor.is_file():
        raise StateDirectoryError("authority anchor is missing or unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(paths.anchor, flags)
        try:
            _require_restricted_descriptor(descriptor, "authority anchor")
            encoded = os.read(descriptor, MAX_ANCHOR_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(encoded) > MAX_ANCHOR_BYTES:
            raise StateVerificationError("authority anchor exceeds byte limit")
        raw = encoded.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise StateDirectoryError("authority anchor is unreadable") from exc
    if not raw.endswith("\n"):
        raise StateVerificationError("authority anchor is truncated")
    try:
        value = strict_json_object(raw[:-1])
    except CanonicalAuthorityError as exc:
        raise StateVerificationError("authority anchor is not canonical") from exc
    claimed = value.pop("anchor_mac", None)
    state = value.get("state")
    final_fields = {
        "anchor_format_version",
        "deployment_id",
        "instance_id",
        "key_id",
        "mutation_mac",
        "sequence",
        "state",
    }
    prepared_fields = {
        "anchor_format_version",
        "deployment_id",
        "expected_mutation_mac",
        "instance_id",
        "key_id",
        "previous_final_mac",
        "previous_final_sequence",
        "sequence",
        "state",
    }
    _require_exact(value, final_fields if state == "FINAL" else prepared_fields, "anchor")
    if value["anchor_format_version"] != ANCHOR_FORMAT_VERSION:
        raise StateVerificationError("unsupported authority anchor format")
    if not verify_record_mac(key, "high_water_anchor", value, str(claimed)):
        raise StateAuthenticationError("authority anchor MAC is invalid")
    if state not in {AnchorState.FINAL.value, AnchorState.PREPARED.value}:
        raise StateVerificationError("authority anchor state is invalid")
    return value


def _final_anchor(
    instance_id: str, deployment_id: str, sequence: int, mutation_mac: str, key_id: str
) -> dict[str, Any]:
    return {
        "anchor_format_version": ANCHOR_FORMAT_VERSION,
        "deployment_id": deployment_id,
        "instance_id": instance_id,
        "key_id": key_id,
        "mutation_mac": mutation_mac,
        "sequence": sequence,
        "state": AnchorState.FINAL.value,
    }


def _prepared_anchor(
    instance_id: str,
    deployment_id: str,
    sequence: int,
    expected_mutation_mac: str,
    previous_sequence: int,
    previous_mac: str,
    key_id: str,
) -> dict[str, Any]:
    return {
        "anchor_format_version": ANCHOR_FORMAT_VERSION,
        "deployment_id": deployment_id,
        "expected_mutation_mac": expected_mutation_mac,
        "instance_id": instance_id,
        "key_id": key_id,
        "previous_final_mac": previous_mac,
        "previous_final_sequence": previous_sequence,
        "sequence": sequence,
        "state": AnchorState.PREPARED.value,
    }


def _mutation_payload(
    key: bytes,
    *,
    instance_id: str,
    deployment_id: str,
    sequence: int,
    mutation_id: str,
    mutation_type: str,
    payload: dict[str, Any],
    previous_mutation_mac: str | None,
    key_id: str,
) -> dict[str, Any]:
    payload_json = canonical_text(payload)
    logical = {
        "deployment_id": deployment_id,
        "instance_id": instance_id,
        "key_id": key_id,
        "mutation_id": mutation_id,
        "mutation_type": mutation_type,
        "payload": payload,
        "payload_sha256": sha256_hex(payload_json.encode("utf-8")),
        "previous_mutation_mac": previous_mutation_mac,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
    }
    return {
        **logical,
        "payload_json": payload_json,
        "mutation_mac": record_mac(key, "state_mutation", logical),
    }


def _mutation_row(mutation: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        mutation["sequence"],
        mutation["mutation_id"],
        mutation["instance_id"],
        mutation["deployment_id"],
        mutation["schema_version"],
        mutation["mutation_type"],
        mutation["payload_json"],
        mutation["payload_sha256"],
        mutation["previous_mutation_mac"],
        mutation["key_id"],
        mutation["mutation_mac"],
    )


def _change(entity: str, identifier: str, mac: str) -> dict[str, str]:
    return {"action": "upsert", "entity": entity, "id": identifier, "record_mac": mac}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _event_logical(
    store: PersistentSecurityState,
    *,
    event_id: str,
    event_type: str,
    correlation_id: str,
    parent_event_ids: Sequence[str],
    content_ids: Sequence[str],
    attributes: Mapping[str, str],
    sequence: int,
) -> dict[str, Any]:
    return {
        "attributes": dict(sorted(attributes.items())),
        "content_ids": list(content_ids),
        "correlation_id": correlation_id,
        "creation_sequence": sequence,
        "deployment_id": store.deployment_id,
        "event_id": event_id,
        "event_type": event_type,
        "instance_id": store.instance_id,
        "key_id": store.key_id,
        "parent_event_ids": list(parent_event_ids),
        "schema_version": SCHEMA_VERSION,
    }


def _workflow_logical(
    store: PersistentSecurityState,
    workflow_id: str,
    head_event_id: str,
    current_content_id: str,
    *,
    revision: int,
    status: str,
    created_sequence: int,
    updated_sequence: int,
) -> dict[str, Any]:
    return {
        "created_sequence": created_sequence,
        "current_content_id": current_content_id,
        "deployment_id": store.deployment_id,
        "head_event_id": head_event_id,
        "instance_id": store.instance_id,
        "key_id": store.key_id,
        "revision": revision,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "updated_sequence": updated_sequence,
        "workflow_id": workflow_id,
    }


def _workflow_handle(logical: Mapping[str, Any]) -> WorkflowHandle:
    return WorkflowHandle(
        str(logical["workflow_id"]),
        str(logical["head_event_id"]),
        str(logical["current_content_id"]),
        int(logical["revision"]),
        str(logical["status"]),
        int(logical["updated_sequence"]),
    )


def _verified_envelope_record(row: sqlite3.Row) -> VerifiedEnvelopeRecord:
    return VerifiedEnvelopeRecord(
        str(row["content_id"]),
        str(row["authority_kind"]),
        str(row["source_type"]),
        str(row["trust"]),
        bool(row["ever_untrusted"]),
        bool(row["sensitive"]),
        bool(row["suspicious"]),
        tuple(dict(item) for item in _decode_items(str(row["findings_json"]))),
        tuple(str(item) for item in _decode_items(str(row["provenance_json"]))),
        tuple(str(item) for item in _decode_items(str(row["parent_ids_json"]))),
        tuple(dict(item) for item in _decode_items(str(row["transformations_json"]))),
        str(row["content_digest"]),
        tuple(str(item) for item in _decode_items(str(row["ancestor_digests_json"]))),
        str(row["inspection_digest"]) if row["inspection_digest"] is not None else None,
        str(row["producing_boundary"]),
        str(row["creation_event_id"]),
        int(row["creation_sequence"]),
    )


def _insert_envelope(connection: sqlite3.Connection, logical: Mapping[str, Any], mac: str) -> None:
    connection.execute(
        """INSERT INTO security_envelopes VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            logical["content_id"],
            logical["instance_id"],
            logical["deployment_id"],
            logical["schema_version"],
            logical["authority_kind"],
            logical["source_type"],
            logical["trust"],
            int(bool(logical["ever_untrusted"])),
            int(bool(logical["sensitive"])),
            int(bool(logical["suspicious"])),
            _encode_items(logical["findings"]),
            _encode_items(logical["provenance"]),
            _encode_items(logical["parent_content_ids"]),
            _encode_items(logical["transformations"]),
            logical["content_digest"],
            _encode_items(logical["ancestor_digests"]),
            logical["inspection_digest"],
            logical["producing_boundary"],
            logical["creation_event_id"],
            logical["creation_sequence"],
            logical["key_id"],
            mac,
        ),
    )
    for position, parent in enumerate(logical["parent_content_ids"]):
        connection.execute(
            "INSERT INTO envelope_parents VALUES (?, ?, ?)",
            (logical["content_id"], parent, position),
        )


def _insert_event(connection: sqlite3.Connection, logical: Mapping[str, Any], mac: str) -> None:
    connection.execute(
        """INSERT INTO causal_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            logical["event_id"],
            logical["instance_id"],
            logical["deployment_id"],
            logical["schema_version"],
            logical["event_type"],
            logical["correlation_id"],
            _encode_items(logical["parent_event_ids"]),
            _encode_items(logical["content_ids"]),
            canonical_text(logical["attributes"]),
            logical["creation_sequence"],
            logical["key_id"],
            mac,
        ),
    )
    for position, parent in enumerate(logical["parent_event_ids"]):
        connection.execute(
            "INSERT INTO event_parents VALUES (?, ?, ?)",
            (logical["event_id"], parent, position),
        )
    for position, content_id in enumerate(logical["content_ids"]):
        connection.execute(
            "INSERT INTO event_contents VALUES (?, ?, ?)",
            (logical["event_id"], content_id, position),
        )


def _insert_workflow(connection: sqlite3.Connection, logical: Mapping[str, Any], mac: str) -> None:
    connection.execute(
        """INSERT INTO workflow_state VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            logical["workflow_id"],
            logical["instance_id"],
            logical["deployment_id"],
            logical["schema_version"],
            logical["head_event_id"],
            logical["current_content_id"],
            logical["revision"],
            logical["status"],
            logical["created_sequence"],
            logical["updated_sequence"],
            logical["key_id"],
            mac,
        ),
    )


def _envelope_logical_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "ancestor_digests": _decode_items(str(row["ancestor_digests_json"])),
        "authority_kind": str(row["authority_kind"]),
        "content_digest": str(row["content_digest"]),
        "content_id": str(row["content_id"]),
        "creation_event_id": str(row["creation_event_id"]),
        "creation_sequence": int(row["creation_sequence"]),
        "deployment_id": str(row["deployment_id"]),
        "ever_untrusted": bool(row["ever_untrusted"]),
        "findings": _decode_items(str(row["findings_json"])),
        "inspection_digest": row["inspection_digest"],
        "instance_id": str(row["instance_id"]),
        "key_id": str(row["key_id"]),
        "parent_content_ids": _decode_items(str(row["parent_ids_json"])),
        "producing_boundary": str(row["producing_boundary"]),
        "provenance": _decode_items(str(row["provenance_json"])),
        "schema_version": str(row["schema_version"]),
        "sensitive": bool(row["sensitive"]),
        "source_type": str(row["source_type"]),
        "suspicious": bool(row["suspicious"]),
        "transformations": _decode_items(str(row["transformations_json"])),
        "trust": str(row["trust"]),
    }


def _event_logical_from_row(row: sqlite3.Row) -> dict[str, Any]:
    attributes = strict_json_object(str(row["attributes_json"]))
    return {
        "attributes": attributes,
        "content_ids": _decode_items(str(row["content_ids_json"])),
        "correlation_id": str(row["correlation_id"]),
        "creation_sequence": int(row["creation_sequence"]),
        "deployment_id": str(row["deployment_id"]),
        "event_id": str(row["event_id"]),
        "event_type": str(row["event_type"]),
        "instance_id": str(row["instance_id"]),
        "key_id": str(row["key_id"]),
        "parent_event_ids": _decode_items(str(row["parent_ids_json"])),
        "schema_version": str(row["schema_version"]),
    }


def _workflow_logical_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "created_sequence": int(row["created_sequence"]),
        "current_content_id": str(row["current_content_id"]),
        "deployment_id": str(row["deployment_id"]),
        "head_event_id": str(row["head_event_id"]),
        "instance_id": str(row["instance_id"]),
        "key_id": str(row["key_id"]),
        "revision": int(row["revision"]),
        "schema_version": str(row["schema_version"]),
        "status": str(row["status"]),
        "updated_sequence": int(row["updated_sequence"]),
        "workflow_id": str(row["workflow_id"]),
    }


def _consumption_logical_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "action_fingerprint": row["action_fingerprint"],
        "commit_sequence": int(row["commit_sequence"]),
        "consuming_event_id": str(row["consuming_event_id"]),
        "consumption_id": str(row["consumption_id"]),
        "deployment_id": str(row["deployment_id"]),
        "instance_id": str(row["instance_id"]),
        "key_id": str(row["key_id"]),
        "schema_version": str(row["schema_version"]),
        "token_id": str(row["token_id"]),
        "token_kind": str(row["token_kind"]),
    }


def _verify_common_record(store: PersistentSecurityState, logical: Mapping[str, Any]) -> None:
    if (
        logical.get("instance_id") != store.instance_id
        or logical.get("deployment_id") != store.deployment_id
        or logical.get("schema_version") != SCHEMA_VERSION
        or logical.get("key_id") != store.key_id
    ):
        raise StateVerificationError("materialized record authority identity mismatch")


def _encode_items(items: Any) -> str:
    return canonical_text({"items": list(items)})


def _decode_items(raw: str) -> list[Any]:
    value = strict_json_object(raw)
    _require_exact(value, {"items"}, "canonical sequence")
    items = value["items"]
    if not isinstance(items, list):
        raise StateVerificationError("canonical sequence payload is malformed")
    return items


def _decode_list(raw: str) -> list[Any]:
    return _decode_items(raw)


def _require_exact(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise StateVerificationError(f"{label} contains unexpected or missing fields")


def _require_restricted_file(path: os.PathLike[str], label: str) -> None:
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise StateDirectoryError(f"{label} cannot be inspected safely") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise StateDirectoryError(f"{label} must be a group/world-inaccessible regular file")
    if info.st_nlink != 1:
        raise StateDirectoryError(f"{label} must not have a hard link")


def _require_restricted_descriptor(descriptor: int, label: str) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise StateDirectoryError(f"{label} must be a group/world-inaccessible regular file")
    if info.st_nlink != 1:
        raise StateDirectoryError(f"{label} must not have a hard link")


def _validate_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")


def _validate_routing_id(value: str, label: str) -> None:
    if not isinstance(value, str) or not _ROUTING_ID.fullmatch(value):
        raise ValueError(f"{label} is not canonical")


def _validate_envelope_input(
    source_type: str,
    trust: str,
    content_digest: str,
    producing_boundary: str,
    parents: Sequence[str],
    findings: Sequence[Mapping[str, Any]],
    provenance: Sequence[str],
    transformations: Sequence[Mapping[str, Any]],
    ancestors: Sequence[str],
    inspection_digest: str | None,
    correlation_id: str,
) -> None:
    if source_type not in _SOURCE_TYPES or trust not in _TRUST_ORDER:
        raise ValueError("source type or trust is invalid")
    _validate_digest(content_digest, "content_digest")
    if inspection_digest is not None:
        _validate_digest(inspection_digest, "inspection_digest")
    for digest in ancestors:
        _validate_digest(digest, "ancestor digest")
    if not producing_boundary or len(producing_boundary) > 200:
        raise ValueError("producing boundary must be bounded")
    _validate_routing_id(correlation_id, "correlation_id")
    if len(parents) > 128 or len(set(parents)) != len(parents):
        raise ValueError("envelope parent set is invalid")
    if any(not _AUTHORITY_ID.fullmatch(item) for item in parents):
        raise ValueError("envelope parent ID is not canonical")
    if any(len(items) > 128 for items in (findings, provenance, transformations, ancestors)):
        raise ValueError("envelope metadata exceeds its bound")
    for item in findings:
        if set(item) != {"detail", "finding_type", "reason_code", "suspicious"}:
            raise ValueError("security finding fields are invalid")
        if (
            not isinstance(item["detail"], str)
            or not isinstance(item["finding_type"], str)
            or not isinstance(item["reason_code"], str)
            or not isinstance(item["suspicious"], bool)
            or any(len(item[field]) > 500 for field in ("detail", "finding_type", "reason_code"))
        ):
            raise ValueError("security finding values are invalid")
    if any(not isinstance(item, str) or not item or len(item) > 500 for item in provenance):
        raise ValueError("provenance entries must be bounded strings")
    for item in transformations:
        if set(item) != {"input_ids", "name", "producer"}:
            raise ValueError("transformation fields are invalid")
        input_ids = item["input_ids"]
        if (
            not isinstance(input_ids, (list, tuple))
            or len(input_ids) > 128
            or any(
                not isinstance(value, str) or not _AUTHORITY_ID.fullmatch(value)
                for value in input_ids
            )
            or not isinstance(item["name"], str)
            or not item["name"]
            or len(item["name"]) > 200
            or not isinstance(item["producer"], str)
            or not item["producer"]
            or len(item["producer"]) > 200
        ):
            raise ValueError("transformation values are invalid")


def _validate_event_input(
    event_type: str,
    correlation_id: str,
    parent_ids: Sequence[str],
    content_ids: Sequence[str],
    attributes: Mapping[str, str] | None,
) -> None:
    if not event_type or len(event_type) > 100 or not _TOKEN_KIND.fullmatch(event_type):
        raise ValueError("event_type is not canonical")
    _validate_routing_id(correlation_id, "correlation_id")
    for values, label in ((parent_ids, "event parent"), (content_ids, "content")):
        if len(values) > 128 or len(set(values)) != len(values):
            raise ValueError(f"{label} IDs are invalid")
        if any(not _AUTHORITY_ID.fullmatch(item) for item in values):
            raise ValueError(f"{label} ID is not canonical")
    if attributes is not None and (
        len(attributes) > 64
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or len(key) > 100
            or len(value) > 500
            for key, value in attributes.items()
        )
    ):
        raise ValueError("event attributes must be bounded string pairs")
