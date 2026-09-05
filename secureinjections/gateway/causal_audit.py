"""Hash-chained append and deterministic verification for boundary audit records."""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..guard.audit import canonical_json, record_hash


@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool
    record_count: int
    issues: tuple[str, ...]
    final_record_hash: str | None


def append_chained_audit(path: Path, record: Mapping[str, Any]) -> str:
    """Append one record bound to the immediately preceding JSONL record."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        previous_hash = _last_record_hash(descriptor)
        payload = dict(record)
        payload["previous_record_hash"] = previous_hash
        payload["record_hash"] = record_hash(payload)
        os.write(descriptor, canonical_json(payload).encode("utf-8") + b"\n")
        os.fsync(descriptor)
        return str(payload["record_hash"])
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def append_chained_audit_once(
    path: Path,
    record: Mapping[str, Any],
    *,
    identity_fields: tuple[str, ...],
    max_bytes: int = 100_000_000,
) -> tuple[str, bool]:
    """Append once by stable evidence identity while holding the file lock.

    A byte-equivalent logical record already present is reconciled as success. A
    conflicting duplicate identity or invalid chain is rejected.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        size = os.fstat(descriptor).st_size
        if size > max_bytes:
            raise ValueError("audit size limit exceeded")
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = b""
        while len(raw) <= max_bytes:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if len(raw) > max_bytes or (raw and not raw.endswith(b"\n")):
            raise ValueError("cannot append after truncated audit record")
        expected = dict(record)
        identity = tuple(expected.get(field) for field in identity_fields)
        if any(value is None for value in identity):
            raise ValueError("audit idempotency identity is incomplete")
        previous_hash: str | None = None
        for raw_line in raw.splitlines():
            try:
                parsed = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("cannot append after malformed audit record") from exc
            if not isinstance(parsed, dict):
                raise ValueError("cannot append after non-object audit record")
            claimed_hash = parsed.get("record_hash")
            without_hash = dict(parsed)
            without_hash.pop("record_hash", None)
            if (
                not isinstance(claimed_hash, str)
                or parsed.get("previous_record_hash") != previous_hash
                or record_hash(without_hash) != claimed_hash
            ):
                raise ValueError("cannot append after invalid audit chain")
            parsed_identity = tuple(parsed.get(field) for field in identity_fields)
            if parsed_identity == identity:
                logical = dict(parsed)
                logical.pop("record_hash", None)
                logical.pop("previous_record_hash", None)
                if logical != expected:
                    raise ValueError("conflicting audit record has the same identity")
                return claimed_hash, False
            previous_hash = claimed_hash
        payload = expected
        payload["previous_record_hash"] = previous_hash
        payload["record_hash"] = record_hash(payload)
        os.write(descriptor, canonical_json(payload).encode("utf-8") + b"\n")
        os.fsync(descriptor)
        return str(payload["record_hash"]), True
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def verify_causal_audit(
    path: Path,
    *,
    max_bytes: int = 100_000_000,
    expected_final_hash: str | None = None,
) -> AuditVerification:
    """Verify parseability, self-hashes, declared chain links, IDs, and causal parents."""

    raw = path.read_bytes()
    if len(raw) > max_bytes:
        return AuditVerification(False, 0, ("AUDIT_SIZE_LIMIT_EXCEEDED",), None)
    issues: list[str] = []
    if raw and not raw.endswith(b"\n"):
        issues.append("TRUNCATED_FINAL_RECORD")
    seen_ids: dict[str, set[str]] = {"audit_id": set(), "event_id": set()}
    seen_outbox: set[tuple[str, int]] = set()
    seen_mutations: set[tuple[str, int]] = set()
    seen_events: set[str] = set()
    previous_hash: str | None = None
    parsed_count = 0
    for line_number, raw_line in enumerate(raw.splitlines(), 1):
        try:
            parsed = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            issues.append(f"MALFORMED_JSON:{line_number}")
            previous_hash = None
            continue
        if not isinstance(parsed, dict):
            issues.append(f"NON_OBJECT_RECORD:{line_number}")
            previous_hash = None
            continue
        parsed_count += 1
        claimed_hash = parsed.get("record_hash")
        without_hash = dict(parsed)
        without_hash.pop("record_hash", None)
        calculated = record_hash(without_hash)
        if claimed_hash != calculated:
            issues.append(f"RECORD_HASH_MISMATCH:{line_number}")
        if "previous_record_hash" in parsed and parsed["previous_record_hash"] != previous_hash:
            issues.append(f"PREVIOUS_HASH_MISMATCH:{line_number}")
        for identifier_name in ("audit_id", "event_id"):
            identifier = parsed.get(identifier_name)
            if isinstance(identifier, str):
                if identifier in seen_ids[identifier_name]:
                    issues.append(f"DUPLICATE_{identifier_name.upper()}:{line_number}")
                seen_ids[identifier_name].add(identifier)
        authority_instance = parsed.get("authority_instance_id")
        outbox_id = parsed.get("outbox_id")
        mutation_sequence = parsed.get("mutation_sequence")
        if isinstance(authority_instance, str) and isinstance(outbox_id, int):
            outbox_identity = (authority_instance, outbox_id)
            if outbox_identity in seen_outbox:
                issues.append(f"DUPLICATE_PERSISTENT_OUTBOX_ID:{line_number}")
            seen_outbox.add(outbox_identity)
        if isinstance(authority_instance, str) and isinstance(mutation_sequence, int):
            mutation_identity = (authority_instance, mutation_sequence)
            if mutation_identity in seen_mutations:
                issues.append(f"DUPLICATE_PERSISTENT_MUTATION:{line_number}")
            seen_mutations.add(mutation_identity)
        event_id = parsed.get("event_id")
        parent_ids = parsed.get("causal_parent_ids", [])
        if isinstance(parent_ids, list):
            if len(parent_ids) != len(set(item for item in parent_ids if isinstance(item, str))):
                issues.append(f"DUPLICATE_CAUSAL_PARENT:{line_number}")
            for parent_id in parent_ids:
                if isinstance(parent_id, str) and parent_id not in seen_events:
                    issues.append(f"UNKNOWN_CAUSAL_PARENT:{line_number}")
        if isinstance(event_id, str):
            seen_events.add(event_id)
        content_ids = parsed.get("content_ids", [])
        if isinstance(content_ids, list) and len(content_ids) != len(
            set(item for item in content_ids if isinstance(item, str))
        ):
            issues.append(f"DUPLICATE_CONTENT_ID_IN_EVENT:{line_number}")
        previous_hash = claimed_hash if isinstance(claimed_hash, str) else None
    if expected_final_hash is not None and previous_hash != expected_final_hash:
        issues.append("FINAL_HASH_MISMATCH")
    return AuditVerification(not issues, parsed_count, tuple(issues), previous_hash)


def _last_record_hash(descriptor: int) -> str | None:
    size = os.fstat(descriptor).st_size
    if size == 0:
        return None
    window = min(size, 1_000_000)
    os.lseek(descriptor, size - window, os.SEEK_SET)
    tail = os.read(descriptor, window)
    lines = tail.splitlines()
    if not lines:
        return None
    if size > window and not tail.startswith(b"\n"):
        lines = lines[1:]
    if not lines:
        raise ValueError("previous audit record exceeds verification window")
    try:
        parsed = json.loads(lines[-1])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot append after malformed audit record") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("record_hash"), str):
        raise ValueError("previous audit record has no record hash")
    return str(parsed["record_hash"])
