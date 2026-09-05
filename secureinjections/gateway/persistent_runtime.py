"""Restart-safe live authority adapter for the local Gateway runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from contextlib import suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..persistent_state import (
    PersistentSecurityState,
    PersistentStateConfig,
    PersistentStateError,
    StateBusyError,
    StateRollbackError,
    StateVerificationError,
    UnknownAuthorityRecord,
    WorkflowCASConflict,
)
from ..persistent_state.canonical import canonical_text
from ..persistent_state.directory import classify_state, prepare_paths
from ..persistent_state.models import StoreDirectoryState
from ..persistent_state.store import _HOST_ROOT_AUTHORITY_CAPABILITY
from .causal_audit import append_chained_audit_once
from .envelope import (
    _PERSISTENT_REHYDRATION_CAPABILITY,
    ContentEnvelope,
    Transformation,
)
from .memory import MemoryRecord
from .sequence import CausalEventStore, SecurityEvent, SecurityEventType


class RuntimeBackend(StrEnum):
    EPHEMERAL = "EPHEMERAL"
    PERSISTENT = "PERSISTENT"


class PersistentRuntimeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PersistentRuntimeConfig:
    state: PersistentStateConfig
    audit_path: Path | None = None
    max_pending_audit: int = 1_000
    max_pending_audit_age_seconds: float = 300.0
    worker_attach: bool = False
    worker_boot_event_id: str | None = None
    worker_attach_token: str | None = None


_RUNTIME_ADAPTER_CAPABILITY = object()
_MEMORY_RECORD_ID = re.compile(r"memory-record-[0-9a-f]{32}")


def open_persistent_runtime(config: PersistentRuntimeConfig) -> PersistentCausalEventStore:
    """Complete the fail-closed startup gate before returning a usable backend."""

    if (
        config.max_pending_audit < 1
        or config.max_pending_audit > 9_999
        or config.max_pending_audit_age_seconds <= 0
    ):
        raise PersistentRuntimeError(
            "PERSISTENT_STATE_RUNTIME_MISMATCH", "audit backlog bound must be positive"
        )
    if (
        config.worker_attach
        and (config.worker_boot_event_id is None or config.worker_attach_token is None)
    ) or (
        not config.worker_attach
        and (config.worker_boot_event_id is not None or config.worker_attach_token is not None)
    ):
        raise PersistentRuntimeError(
            "PERSISTENT_STATE_RUNTIME_MISMATCH",
            "worker attach requires a current boot event ID and host bootstrap token",
        )
    state: PersistentSecurityState | None = None
    try:
        paths = prepare_paths(config.state.state_directory, create=True)
        directory_state = classify_state(paths)
        if directory_state is StoreDirectoryState.EMPTY_NEW_STORE:
            if config.worker_attach:
                raise PersistentRuntimeError(
                    "PERSISTENT_STATE_UNAVAILABLE",
                    "worker attach requires an existing persistent runtime",
                )
            state = PersistentSecurityState.initialize(config.state)
        elif directory_state is StoreDirectoryState.COMPLETE_EXISTING_STORE:
            state = PersistentSecurityState.open(config.state)
        else:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_UNAVAILABLE", "persistent authority directory is incomplete"
            )
        state.verify_startup()
        state.enable_runtime_v03b()
        backend = PersistentCausalEventStore(_RUNTIME_ADAPTER_CAPABILITY, state, config)
        backend.project_audit()
        backend.enforce_audit_bound(privileged=False)
        return backend
    except PersistentRuntimeError:
        if state is not None:
            state.close()
        raise
    except StateRollbackError as exc:
        if state is not None:
            state.close()
        raise PersistentRuntimeError(
            "PERSISTENT_STATE_ROLLBACK_DETECTED", "persistent authority rollback detected"
        ) from exc
    except StateVerificationError as exc:
        if state is not None:
            state.close()
        raise PersistentRuntimeError(
            "PERSISTENT_STATE_VERIFICATION_FAILED", "persistent authority verification failed"
        ) from exc
    except StateBusyError as exc:
        if state is not None:
            state.close()
        raise PersistentRuntimeError(
            "PERSISTENT_STATE_UNAVAILABLE", "persistent authority store remained busy"
        ) from exc
    except PersistentStateError as exc:
        if state is not None:
            state.close()
        raise PersistentRuntimeError(
            "PERSISTENT_STATE_UNAVAILABLE", "persistent authority store could not open"
        ) from exc


class PersistentCausalEventStore(CausalEventStore):
    """Gateway-facing semantic state backed by authenticated v0.3 authority."""

    PAYLOAD_SCHEMA = "gateway-payload-v0.3b"

    MAX_PAYLOAD_BYTES = 2_100_000

    def __init__(
        self,
        capability: object,
        state: PersistentSecurityState,
        config: PersistentRuntimeConfig,
    ) -> None:
        if capability is not _RUNTIME_ADAPTER_CAPABILITY:
            raise PermissionError("persistent runtime construction requires host authority")
        super().__init__(audit_path=None)
        self.state = state
        self.config = config
        self.payload_directory = state.paths.directory / "runtime-payloads"
        self.memory_directory = state.paths.directory / "runtime-memory"
        for directory in (self.payload_directory, self.memory_directory):
            self._prepare_private_directory(directory)
        self._content_map: dict[str, str] = {}
        self._event_map: dict[str, str] = {}
        self._event_reverse_map: dict[str, str] = {}
        self._workflows: dict[str, Any] = {}
        self.audit_projection_error = False
        if config.worker_attach:
            assert config.worker_boot_event_id is not None
            attached_boot = self.state.get_event(config.worker_boot_event_id)
            if attached_boot.event_type != "runtime_boot":
                raise PersistentRuntimeError(
                    "PERSISTENT_STATE_RUNTIME_MISMATCH",
                    "worker attach boot authority is not a runtime boot",
                )
            self.boot_epoch = attached_boot.event_id
        else:
            created_boot = self.state.record_event(
                event_type="runtime_boot",
                correlation_id="runtime-boot",
                attributes={"nonce": secrets.token_hex(16)},
            )
            self.boot_epoch = created_boot.event_id

    def close(self) -> None:
        self.state.close()

    def register_envelope(self, envelope: ContentEnvelope) -> ContentEnvelope:
        existing = self._content_map.get(envelope.content_id)
        if existing is not None:
            return self.load_envelope(existing)
        try:
            self.state.get_envelope(envelope.content_id)
        except UnknownAuthorityRecord:
            pass
        else:
            self._content_map[envelope.content_id] = envelope.content_id
            return self.load_envelope(envelope.content_id)

        parent_ids = tuple(self._content_map.get(item, item) for item in envelope.parent_ids)
        transformations = tuple(
            Transformation(
                item.name,
                item.producer,
                tuple(self._content_map.get(value, value) for value in item.input_ids),
            )
            for item in envelope.transformations
        )
        kwargs: Any = {
            "source_type": envelope.source_type.value,
            "trust": envelope.trust.value,
            "content_digest": hashlib.sha256(envelope.content.encode("utf-8")).hexdigest(),
            "producing_boundary": envelope.producing_boundary,
            "ever_untrusted": envelope.ever_untrusted,
            "sensitive": any(
                item.finding_type == "SENSITIVE_CONTENT" for item in envelope.security_findings
            ),
            "suspicious": envelope.suspicious_encoded,
            "findings": tuple(item.to_dict() for item in envelope.security_findings),
            "provenance": envelope.provenance,
            "transformations": tuple(item.to_dict() for item in transformations),
            "ancestor_digests": envelope.ancestor_sha256,
            "inspection_digest": envelope.inspection_sha256,
            "correlation_id": "runtime-envelope",
        }
        if parent_ids:
            handle = self.state.record_envelope(parent_content_ids=parent_ids, **kwargs)
        elif envelope.trust.value in {"TRUSTED", "INTERNAL"}:
            handle = self.state._issue_authoritative_root_for_host(  # noqa: SLF001
                _HOST_ROOT_AUTHORITY_CAPABILITY, **kwargs
            )
        else:
            handle = self.state.record_envelope(**kwargs)
        self._content_map[envelope.content_id] = handle.content_id
        persisted = replace(
            envelope,
            content_id=handle.content_id,
            parent_ids=tuple(sorted(set(parent_ids))),
            transformations=transformations,
            ancestor_sha256=tuple(sorted(set(envelope.ancestor_sha256))),
        )
        self._write_payload(handle.content_id, persisted.content)
        self.project_audit()
        return persisted

    def append(self, event: SecurityEvent) -> None:
        parent_ids = tuple(self._event_map.get(item, item) for item in event.causal_parent_ids)
        content_ids = tuple(self._content_map.get(item, item) for item in event.content_ids)
        handle = self.state.record_event(
            event_type=event.event_type.value,
            correlation_id=event.correlation_id,
            parent_event_ids=parent_ids,
            content_ids=content_ids,
            attributes=event.attributes,
        )
        self._event_map[event.event_id] = handle.event_id
        self._event_reverse_map[handle.event_id] = event.event_id
        persisted = SecurityEvent(
            handle.event_id,
            event.correlation_id,
            event.event_type,
            parent_ids,
            content_ids,
            dict(event.attributes),
        )
        for parent_id in parent_ids:
            self.get(parent_id)
        super().append(persisted)
        self._events[event.event_id] = SecurityEvent(
            event.event_id,
            event.correlation_id,
            event.event_type,
            event.causal_parent_ids,
            content_ids,
            dict(event.attributes),
        )
        try:
            self._sync_workflow(persisted)
        except WorkflowCASConflict as exc:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_CAS_CONFLICT", "persistent workflow state is stale"
            ) from exc
        self.project_audit()

    def get(self, event_id: str) -> SecurityEvent | None:
        mapped = self._event_map.get(event_id, event_id)
        try:
            record = self.state.get_event(mapped)
        except UnknownAuthorityRecord:
            return None
        use_runtime_ids = event_id in self._event_map
        returned_id = event_id if use_runtime_ids else record.event_id
        parent_ids = (
            tuple(self._event_reverse_map.get(item, item) for item in record.parent_event_ids)
            if use_runtime_ids
            else record.parent_event_ids
        )
        event = SecurityEvent(
            returned_id,
            record.correlation_id,
            SecurityEventType(record.event_type),
            parent_ids,
            record.content_ids,
            record.attributes,
        )
        self._events[returned_id] = event
        return event

    def ancestry(self, parent_ids: tuple[str, ...]) -> tuple[SecurityEvent, ...]:
        pending = [self._event_map.get(item, item) for item in parent_ids]
        seen: set[str] = set()
        output: list[SecurityEvent] = []
        while pending and len(output) < self.max_ancestry:
            event_id = pending.pop()
            if event_id in seen:
                continue
            seen.add(event_id)
            event = self.get(event_id)
            if event is None:
                continue
            output.append(event)
            pending.extend(event.causal_parent_ids)
        return tuple(output)

    def validate_parent_ids(self, parent_ids: tuple[str, ...]) -> None:
        if len(set(parent_ids)) != len(parent_ids):
            raise ValueError("duplicate causal parent ID")
        if any(self.get(item) is None for item in parent_ids):
            raise ValueError("unknown causal parent ID")

    def consume_once(
        self,
        token_kind: str,
        token_id: str,
        consuming_event_id: str,
        action_fingerprint: str | None = None,
    ) -> str | None:
        token = self._event_map.get(token_id, self._content_map.get(token_id, token_id))
        consuming = self._event_map.get(consuming_event_id, consuming_event_id)
        result = self.state.consume_once(
            token_kind=token_kind,
            token_id=token,
            consuming_event_id=consuming,
            action_fingerprint=action_fingerprint,
        )
        self.project_audit()
        return None if result.consumed else "PERSISTENT_STATE_ALREADY_CONSUMED"

    def persistent_event_id(self, event_id: str) -> str:
        return self._event_map.get(event_id, event_id)

    def persistent_content_id(self, content_id: str) -> str:
        return self._content_map.get(content_id, content_id)

    def workflow_head(self, workflow_id: str) -> tuple[str, int] | None:
        try:
            handle = self.state.get_workflow(workflow_id)
        except UnknownAuthorityRecord:
            return None
        self._workflows[workflow_id] = handle
        return (
            self._event_reverse_map.get(handle.head_event_id, handle.head_event_id),
            handle.revision,
        )

    def workflow_content(self, workflow_id: str) -> ContentEnvelope | None:
        try:
            handle = self.state.get_workflow(workflow_id)
        except UnknownAuthorityRecord:
            return None
        self._workflows[workflow_id] = handle
        return self.load_envelope(handle.current_content_id)

    def load_envelope(self, content_id: str) -> ContentEnvelope:
        record = self.state.get_envelope(content_id)
        content = self._read_payload(content_id)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if digest != record.content_digest:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "runtime payload digest mismatch"
            )
        return ContentEnvelope._from_verified_persistent(
            _PERSISTENT_REHYDRATION_CAPABILITY, content, record
        )

    def store_memory(self, record: MemoryRecord) -> None:
        content_id = self._content_map.get(record.content.content_id, record.content.content_id)
        event_id = self._event_map.get(record.write_event_id, record.write_event_id)
        data = {
            "schema": self.PAYLOAD_SCHEMA,
            "record_id": record.record_id,
            "key": record.key,
            "content_id": content_id,
            "write_event_id": event_id,
            "correlation_id": record.correlation_id,
            "causal_parent_ids": [
                self._event_map.get(item, item) for item in record.causal_parent_ids
            ],
        }
        self._atomic_json(self.memory_directory / f"{record.record_id}.json", data)

    def load_memory(self, record_id: str) -> MemoryRecord:
        if not _MEMORY_RECORD_ID.fullmatch(record_id):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "memory record identifier is invalid"
            )
        data = self._read_json(self.memory_directory / f"{record_id}.json")
        if data.get("schema") != self.PAYLOAD_SCHEMA or data.get("record_id") != record_id:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "memory payload metadata is invalid"
            )
        content = self.load_envelope(str(data["content_id"]))
        event = self.get(str(data["write_event_id"]))
        if event is None or event.event_type is not SecurityEventType.MEMORY_WRITE:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "memory write authority is missing"
            )
        if event.content_ids != (content.content_id,):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "memory metadata authority mismatch"
            )
        causal_parent_ids = tuple(str(item) for item in data.get("causal_parent_ids", ()))
        key = data.get("key")
        correlation_id = data.get("correlation_id")
        if (
            not isinstance(key, str)
            or not isinstance(correlation_id, str)
            or event.attributes.get("record_id") != record_id
            or event.attributes.get("memory_key_sha256")
            != hashlib.sha256(key.encode("utf-8")).hexdigest()
            or event.correlation_id != correlation_id
            or event.causal_parent_ids != causal_parent_ids
        ):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "memory index is not authority-bound"
            )
        return MemoryRecord(
            record_id,
            key,
            content,
            correlation_id,
            causal_parent_ids,
            event.event_id,
        )

    def enforce_audit_bound(self, *, privileged: bool) -> None:
        pending = self.state.pending_audit(limit=self.config.max_pending_audit + 1)
        too_old = bool(
            pending
            and time.time_ns() - pending[0].created_unix_ns
            > int(self.config.max_pending_audit_age_seconds * 1_000_000_000)
        )
        if privileged and (
            self.audit_projection_error or len(pending) > self.config.max_pending_audit or too_old
        ):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_AUDIT_BACKLOG", "persistent audit evidence backlog exceeded"
            )

    def project_audit(self) -> None:
        if self.config.audit_path is None:
            return
        for item in self.state.pending_audit(limit=10_000):
            try:
                append_chained_audit_once(
                    self.config.audit_path,
                    {
                        "schema_version": "persistent-runtime-audit-v0.3b",
                        "authority_instance_id": self.state.instance_id,
                        "outbox_id": item.outbox_id,
                        "mutation_sequence": item.mutation_sequence,
                        "mutation_type": item.mutation_type,
                        "authority_payload": json.loads(item.payload_json),
                        "raw_content_retained": False,
                    },
                    identity_fields=("authority_instance_id", "outbox_id"),
                )
            except (OSError, ValueError, json.JSONDecodeError):
                self.audit_projection_error = True
                return
            self.state.mark_audit_exported(item.outbox_id)
        self.audit_projection_error = False

    def _sync_workflow(self, event: SecurityEvent) -> None:
        try:
            current = self.state.get_workflow(event.correlation_id)
        except UnknownAuthorityRecord:
            if not event.content_ids:
                return
            current = self.state.create_workflow(
                event.correlation_id,
                head_event_id=event.event_id,
                current_content_id=event.content_ids[-1],
            )
        else:
            current = self.state.advance_workflow(
                event.correlation_id,
                expected_revision=current.revision,
                expected_head=current.head_event_id,
                new_head=event.event_id,
            )
        self._workflows[event.correlation_id] = current

    def _write_payload(self, content_id: str, content: str) -> None:
        self._atomic_json(
            self.payload_directory / f"{content_id}.json",
            {"schema": self.PAYLOAD_SCHEMA, "content_id": content_id, "content": content},
        )

    def _read_payload(self, content_id: str) -> str:
        data = self._read_json(self.payload_directory / f"{content_id}.json")
        if data.get("schema") != self.PAYLOAD_SCHEMA or data.get("content_id") != content_id:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "runtime payload metadata is invalid"
            )
        content = data.get("content")
        if not isinstance(content, str):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "runtime payload encoding is invalid"
            )
        return content

    @staticmethod
    def _prepare_private_directory(path: Path) -> None:
        with suppress(FileExistsError):
            path.mkdir(mode=0o700)
        try:
            info = path.lstat()
        except OSError as exc:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "persistent payload directory unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "persistent payload directory is unsafe"
            )

    @classmethod
    def _read_json(cls, path: Path) -> dict[str, Any]:
        descriptor = -1
        try:
            cls._prepare_private_directory(path.parent)
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_size > cls.MAX_PAYLOAD_BYTES
            ):
                raise OSError
            chunks: list[bytes] = []
            remaining = cls.MAX_PAYLOAD_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > cls.MAX_PAYLOAD_BYTES:
                raise OSError
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "persistent runtime payload unavailable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(value, dict):
            raise PersistentRuntimeError(
                "PERSISTENT_STATE_PAYLOAD_MISMATCH", "persistent runtime payload is malformed"
            )
        return value

    @classmethod
    def _atomic_json(cls, path: Path, value: dict[str, Any]) -> None:
        cls._prepare_private_directory(path.parent)
        try:
            existing = path.lstat()
        except FileNotFoundError:
            pass
        else:
            if (
                not stat.S_ISREG(existing.st_mode)
                or existing.st_nlink != 1
                or existing.st_uid != os.getuid()
                or existing.st_mode & 0o077
            ):
                raise PersistentRuntimeError(
                    "PERSISTENT_STATE_PAYLOAD_MISMATCH", "persistent payload target is unsafe"
                )
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            payload = canonical_text(value).encode("utf-8")
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def runtime_action_fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_text(value).encode("utf-8")).hexdigest()
