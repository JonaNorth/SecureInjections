"""Deterministic local-only destination used by v0.3c1 security tests."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_text
from .execution import DispatchHandle, ExecutionAuthority, normalize_action
from .models import DestinationQueryObservation, DestinationQueryResult, IdempotencyClass


class FakeDestinationMode(StrEnum):
    FAIL_BEFORE_EFFECT = "FAIL_BEFORE_EFFECT"
    PAUSE_BEFORE_EFFECT = "PAUSE_BEFORE_EFFECT"
    COMMIT_THEN_TIMEOUT = "COMMIT_THEN_TIMEOUT"
    COMMIT_THEN_TERMINATE = "COMMIT_THEN_TERMINATE"
    SUCCESS_WITHOUT_EFFECT = "SUCCESS_WITHOUT_EFFECT"
    REJECT_DUPLICATE_KEY = "REJECT_DUPLICATE_KEY"
    DEDUPLICATE_SAME_KEY = "DEDUPLICATE_SAME_KEY"
    ACCEPT_DUPLICATE_KEY = "ACCEPT_DUPLICATE_KEY"
    QUERY_OPERATION_STATUS = "QUERY_OPERATION_STATUS"
    DELAY_PAST_CLAIM_EXPIRY = "DELAY_PAST_CLAIM_EXPIRY"
    SUCCESS = "SUCCESS"


class FakeDestinationFailure(RuntimeError):
    """Local runner failure with an optional authenticated operation observation."""

    def __init__(self, message: str, *, operation_id: str | None = None) -> None:
        super().__init__(message)
        self.operation_id = operation_id


class FakeDestinationTimeout(FakeDestinationFailure):
    pass


class FakeCallerTermination(FakeDestinationFailure):
    pass


class FakeDestination:
    """SQLite-backed effect recorder. It carries no production authority."""

    def __init__(
        self, path: Path, *, failure_injector: Callable[[str], None] | None = None
    ) -> None:
        self.path = path
        self.failure_injector = failure_injector

    def _ensure_schema(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(
                """CREATE TABLE IF NOT EXISTS requests(
                request_sequence INTEGER PRIMARY KEY AUTOINCREMENT, intent_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL, idempotency_key TEXT, operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL, effect_commit_sequence INTEGER,
                response_sequence INTEGER, duplicate_behavior TEXT NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS operation_unique ON requests(operation_id);
                CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
                INSERT OR IGNORE INTO counters VALUES('effect',0);
                INSERT OR IGNORE INTO counters VALUES('request',0);
                INSERT OR IGNORE INTO counters VALUES('response',0);"""
            )
            connection.commit()
        finally:
            connection.close()

    def invoke(
        self,
        authority: ExecutionAuthority,
        handle: DispatchHandle,
        action: dict[str, Any] | str,
        *,
        mode: FakeDestinationMode = FakeDestinationMode.SUCCESS,
    ) -> dict[str, Any]:
        self._inject("before_fake_destination_invocation")
        if self.path.resolve() == authority.state.paths.database.resolve():
            raise FakeDestinationFailure("fake destination cannot share the authority database")
        self._ensure_schema()
        intent = authority.validate_dispatch_handle(handle)
        _, rendered, digest = normalize_action(action)
        if digest != handle.action_fingerprint:
            raise FakeDestinationFailure("fake request does not match dispatch authority")
        self._record_request()
        if mode is FakeDestinationMode.FAIL_BEFORE_EFFECT:
            raise FakeDestinationFailure("deterministic failure before effect")
        if mode is FakeDestinationMode.PAUSE_BEFORE_EFFECT:
            return {"status": "PAUSED_BEFORE_EFFECT"}
        if mode is FakeDestinationMode.SUCCESS_WITHOUT_EFFECT:
            operation_id = (
                "fake-no-effect-operation-"
                + hashlib.sha256(f"{intent.intent_id}:{handle.attempt_id}".encode()).hexdigest()[
                    :32
                ]
            )
            return {"status": "SUCCESS_WITHOUT_EFFECT", "operation_id": operation_id}
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            self._inject("during_fake_destination_invocation")
            connection.execute("BEGIN IMMEDIATE")
            key = handle.idempotency_key
            previous = None
            if key is not None:
                previous = connection.execute(
                    "SELECT * FROM requests WHERE idempotency_key=? "
                    "ORDER BY request_sequence LIMIT 1",
                    (key,),
                ).fetchone()
            if previous is not None and mode is FakeDestinationMode.REJECT_DUPLICATE_KEY:
                connection.rollback()
                raise FakeDestinationFailure("duplicate idempotency key rejected")
            if previous is not None and mode is FakeDestinationMode.DEDUPLICATE_SAME_KEY:
                previous_effect = previous["effect_commit_sequence"]
                if previous_effect is None:
                    raise FakeDestinationFailure("deduplication record has no committed effect")
                connection.commit()
                return {
                    "status": "DEDUPLICATED",
                    "operation_id": str(previous["operation_id"]),
                    "effect_commit_sequence": cast(int, previous_effect),
                }
            effect = self._increment(connection, "effect")
            operation_id = (
                "fake-operation-"
                + hashlib.sha256(
                    f"{intent.intent_id}:{handle.attempt_id}:{effect}".encode()
                ).hexdigest()[:32]
            )
            behavior = "ACCEPT_DUPLICATE" if previous is not None else "FIRST_KEY_USE"
            cursor = connection.execute(
                """INSERT INTO requests(intent_id,attempt_id,idempotency_key,operation_id,
                request_digest,effect_commit_sequence,response_sequence,duplicate_behavior)
                VALUES(?,?,?,?,?,?,NULL,?)""",
                (
                    intent.intent_id,
                    handle.attempt_id,
                    key,
                    operation_id,
                    hashlib.sha256(rendered.encode()).hexdigest(),
                    effect,
                    behavior,
                ),
            )
            if cursor.lastrowid is None:
                raise FakeDestinationFailure("fake request sequence was not allocated")
            request_sequence = cursor.lastrowid
            connection.commit()
            self._inject("after_fake_effect_commit")
            if mode in {
                FakeDestinationMode.COMMIT_THEN_TIMEOUT,
                FakeDestinationMode.DELAY_PAST_CLAIM_EXPIRY,
            }:
                raise FakeDestinationTimeout(
                    "effect committed before response", operation_id=operation_id
                )
            if mode is FakeDestinationMode.COMMIT_THEN_TERMINATE:
                raise FakeCallerTermination(
                    "caller termination simulated after effect", operation_id=operation_id
                )
            connection.execute("BEGIN IMMEDIATE")
            response = self._increment(connection, "response")
            connection.execute(
                "UPDATE requests SET response_sequence=? WHERE request_sequence=?",
                (response, request_sequence),
            )
            connection.commit()
            return {
                "status": "SUCCEEDED",
                "operation_id": operation_id,
                "effect_commit_sequence": effect,
                "response_sequence": response,
            }
        finally:
            connection.close()

    def query_operation_status(self, operation_id: str) -> dict[str, Any] | None:
        self._ensure_schema()
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT * FROM requests WHERE operation_id=?", (operation_id,)
            ).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def invoke_recovery(
        self,
        authority: Any,
        handle: Any,
        action: dict[str, Any] | str,
        *,
        mode: FakeDestinationMode = FakeDestinationMode.SUCCESS,
    ) -> dict[str, Any]:
        """Consume a c3b recovery dispatch handle in the local fake only."""

        from .recovery import RecoveryAuthority, RecoveryDispatchHandle

        if not isinstance(authority, RecoveryAuthority) or not isinstance(
            handle, RecoveryDispatchHandle
        ):
            raise FakeDestinationFailure("recovery invocation requires recovery authority")
        if self.path.resolve() == authority.state.paths.database.resolve():
            raise FakeDestinationFailure("fake destination cannot share the authority database")
        recovery = authority.validate_recovery_dispatch_handle(handle)
        _, rendered, digest = normalize_action(action)
        if digest != recovery.action_fingerprint:
            raise FakeDestinationFailure("fake recovery request differs from authority")
        recovery_id = recovery.recovery_id
        execution_intent_id = recovery.execution_intent_id
        attempt_id = recovery.attempt_id
        destination_class = recovery.destination_class
        original_idempotency_key = recovery.original_idempotency_key
        original_operation_id = recovery.original_operation_id
        if attempt_id is None:
            raise FakeDestinationFailure("authenticated recovery lacks an attempt ID")
        self._ensure_schema()
        self._record_request()
        if mode is FakeDestinationMode.FAIL_BEFORE_EFFECT:
            raise FakeDestinationFailure("deterministic recovery failure before effect")
        if mode is FakeDestinationMode.PAUSE_BEFORE_EFFECT:
            return {"status": "PAUSED_BEFORE_EFFECT"}
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            self._inject("during_fake_recovery_invocation")
            connection.execute("BEGIN IMMEDIATE")
            previous = None
            if original_idempotency_key is not None:
                previous = connection.execute(
                    "SELECT * FROM requests WHERE idempotency_key=? "
                    "ORDER BY request_sequence LIMIT 1",
                    (original_idempotency_key,),
                ).fetchone()
            if previous is not None:
                if mode is FakeDestinationMode.REJECT_DUPLICATE_KEY:
                    connection.rollback()
                    raise FakeDestinationFailure("duplicate recovery idempotency key rejected")
                if mode is not FakeDestinationMode.ACCEPT_DUPLICATE_KEY:
                    connection.commit()
                    return {
                        "status": "DEDUPLICATED",
                        "operation_id": str(previous["operation_id"]),
                        "effect_commit_sequence": int(previous["effect_commit_sequence"]),
                    }
            operation_id = original_operation_id
            if destination_class is IdempotencyClass.QUERYABLE_OPERATION_ID:
                if operation_id is None:
                    raise FakeDestinationFailure("queryable recovery lacks original operation ID")
                if connection.execute(
                    "SELECT 1 FROM requests WHERE operation_id=?", (operation_id,)
                ).fetchone():
                    raise FakeDestinationFailure("queryable operation already exists")
            else:
                operation_id = (
                    "fake-recovery-operation-"
                    + hashlib.sha256(f"{recovery_id}:{attempt_id}".encode()).hexdigest()[:32]
                )
            effect = self._increment(connection, "effect")
            connection.execute(
                """INSERT INTO requests(intent_id,attempt_id,idempotency_key,operation_id,
                request_digest,effect_commit_sequence,response_sequence,duplicate_behavior)
                VALUES(?,?,?,?,?,?,NULL,?)""",
                (
                    execution_intent_id,
                    attempt_id,
                    original_idempotency_key,
                    operation_id,
                    hashlib.sha256(rendered.encode()).hexdigest(),
                    effect,
                    "RECOVERY",
                ),
            )
            connection.commit()
            self._inject("after_fake_recovery_effect_commit")
            if mode in {
                FakeDestinationMode.COMMIT_THEN_TIMEOUT,
                FakeDestinationMode.COMMIT_THEN_TERMINATE,
            }:
                exception = (
                    FakeDestinationTimeout
                    if mode is FakeDestinationMode.COMMIT_THEN_TIMEOUT
                    else FakeCallerTermination
                )
                raise exception(
                    "recovery effect committed before response", operation_id=operation_id
                )
            return {
                "status": "SUCCEEDED",
                "operation_id": operation_id,
                "effect_commit_sequence": effect,
            }
        finally:
            connection.close()

    @property
    def request_count(self) -> int:
        self._ensure_schema()
        connection = sqlite3.connect(self.path)
        try:
            return int(
                connection.execute("SELECT value FROM counters WHERE name='request'").fetchone()[0]
            )
        finally:
            connection.close()

    @property
    def effect_count(self) -> int:
        self._ensure_schema()
        connection = sqlite3.connect(self.path)
        try:
            return int(
                connection.execute("SELECT value FROM counters WHERE name='effect'").fetchone()[0]
            )
        finally:
            connection.close()

    def _record_request(self) -> None:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._increment(connection, "request")
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _increment(connection: sqlite3.Connection, name: str) -> int:
        connection.execute("UPDATE counters SET value=value+1 WHERE name=?", (name,))
        return int(
            connection.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()[0]
        )

    def _inject(self, point: str) -> None:
        if self.failure_injector is not None:
            self.failure_injector(point)


class FakeDestinationStatusAdapter:
    """Deterministic host adapter that exposes no raw payload to authority state."""

    adapter_identity = "fake-sqlite-status-adapter"
    adapter_version = "v1"

    def __init__(
        self,
        destination: FakeDestination,
        *,
        destination_registry: str,
        destination_name: str,
        destination_contract_digest: str,
    ) -> None:
        self.fake_destination = destination
        self.destination_registry = destination_registry
        self.destination = destination_name
        self.destination_contract_digest = destination_contract_digest

    def query_operation_status(self, operation_id: str) -> DestinationQueryObservation:
        try:
            row = FakeDestination.query_operation_status(self.fake_destination, operation_id)
        except sqlite3.Error as exc:
            digest = hashlib.sha256(type(exc).__name__.encode()).hexdigest()
            return DestinationQueryObservation(DestinationQueryResult.QUERY_FAILED, digest)
        if row is None:
            normalized = DestinationQueryResult.NO_EFFECT_CONFIRMED
            normalized_payload = {"operation_id": operation_id, "present": False}
        elif row.get("effect_commit_sequence") is not None:
            normalized = DestinationQueryResult.EFFECT_CONFIRMED
            normalized_payload = {
                "effect": int(row["effect_commit_sequence"]),
                "operation_id": operation_id,
                "present": True,
            }
        elif row.get("operation_id") == operation_id:
            normalized = DestinationQueryResult.STILL_UNKNOWN
            normalized_payload = {"operation_id": operation_id, "present": True}
        else:
            normalized = DestinationQueryResult.CONFLICT
            normalized_payload = {"operation_id": operation_id, "present": "conflict"}
        digest = hashlib.sha256(canonical_text(normalized_payload).encode()).hexdigest()
        return DestinationQueryObservation(normalized, digest)
