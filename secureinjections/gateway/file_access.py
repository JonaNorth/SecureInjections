"""Production-oriented typed local text-file boundary."""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePath
from typing import Any

from ..guard import Guard, GuardDecision, InspectionRequest, TrustLevel
from .causal_audit import append_chained_audit
from .content_inspection import InspectionLimits, inspect_content
from .envelope import ContentEnvelope, ContentSecurityFinding, ContentSourceType


class FileReadDecision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class FileReadReason(StrEnum):
    ALLOWED = "FILE_READ_ALLOWED"
    UNKNOWN_ROOT = "FILE_UNKNOWN_ALLOWED_ROOT"
    TRAVERSAL = "FILE_PATH_TRAVERSAL"
    OUTSIDE_ROOT = "FILE_OUTSIDE_ALLOWED_ROOT"
    SYMLINK_ESCAPE = "FILE_SYMLINK_ESCAPE"
    NOT_FOUND = "FILE_NOT_FOUND"
    SPECIAL_FILE = "FILE_SPECIAL_TYPE"
    TOO_LARGE = "FILE_TOO_LARGE"
    BINARY = "FILE_BINARY_UNSUPPORTED"
    DECODING = "FILE_TEXT_DECODING_FAILED"
    SENSITIVE = "FILE_SENSITIVE_PATH"
    HIDDEN_CONTENT = "FILE_SUSPICIOUS_HIDDEN_CONTENT"
    POST_READ_POLICY = "FILE_POST_READ_POLICY"
    HARD_LINK = "FILE_HARD_LINK_UNSUPPORTED"
    RACE_DETECTED = "FILE_REPLACEMENT_RACE"


@dataclass(frozen=True, slots=True)
class AllowedRoot:
    root_id: str
    path: Path
    trust: TrustLevel = TrustLevel.INTERNAL


@dataclass(frozen=True, slots=True)
class FileAccessPolicy:
    allowed_roots: tuple[AllowedRoot, ...]
    max_file_size: int = 1_000_000
    allow_sensitive: bool = False
    allow_hard_links: bool = False
    inspection_limits: InspectionLimits = field(default_factory=InspectionLimits)

    def __post_init__(self) -> None:
        if not self.allowed_roots:
            raise ValueError("at least one explicit allowed root is required")
        if self.max_file_size < 1 or self.max_file_size > 100_000_000:
            raise ValueError("max_file_size must be between 1 and 100,000,000 bytes")
        identifiers = [item.root_id for item in self.allowed_roots]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("allowed root IDs must be unique")
        for root in self.allowed_roots:
            resolved = root.path.resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError(f"allowed root is not a directory: {root.root_id}")


@dataclass(frozen=True, slots=True)
class FileReadRequest:
    root_id: str
    path: str
    correlation_id: str
    causal_parent_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.root_id or len(self.root_id) > 100:
            raise ValueError("root_id must be a bounded non-empty string")
        if not self.path or len(self.path) > 2_000 or "\x00" in self.path:
            raise ValueError("path must be a bounded non-empty string without NUL")
        if not self.correlation_id or len(self.correlation_id) > 200:
            raise ValueError("correlation_id must be a bounded non-empty string")


@dataclass(frozen=True, slots=True)
class FileReadResult:
    request_id: str
    correlation_id: str
    requested_path: str
    resolved_path: str | None
    decision: FileReadDecision
    reason_code: FileReadReason
    sensitive: bool
    envelope: ContentEnvelope | None = field(default=None, repr=False)
    withheld_content_metadata: Mapping[str, Any] | None = field(default=None, repr=False)
    audit_id: str = ""
    guard_audit_id: str | None = None
    event_id: str | None = None

    @property
    def content_forwardable(self) -> bool:
        return self.decision is FileReadDecision.ALLOW and self.envelope is not None

    @property
    def content_id(self) -> str | None:
        if self.envelope is not None:
            return self.envelope.content_id
        if self.withheld_content_metadata is not None:
            value = self.withheld_content_metadata.get("content_id")
            return value if isinstance(value, str) else None
        return None

    @property
    def content_was_read(self) -> bool:
        return self.envelope is not None or self.withheld_content_metadata is not None

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "requested_path": self.requested_path,
            "resolved_path": self.resolved_path,
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "sensitive": self.sensitive,
            "audit_id": self.audit_id,
            "guard_audit_id": self.guard_audit_id,
            "event_id": self.event_id,
            "content_forwardable": self.content_forwardable,
            "content": None,
        }
        if self.envelope is not None:
            output["content_envelope"] = self.envelope.metadata_dict()
            if include_content and self.content_forwardable:
                output["content"] = self.envelope.content
        elif self.withheld_content_metadata is not None:
            output["content_envelope"] = dict(self.withheld_content_metadata)
        return output


class SafeFileReader:
    """Resolve, classify, inspect, and audit local text reads before release."""

    def __init__(
        self,
        policy: FileAccessPolicy,
        *,
        guard: Guard,
        audit_path: Path | None = None,
        execution_gate: Callable[[], None] | None = None,
    ) -> None:
        self.policy = policy
        self.guard = guard
        self.audit_path = audit_path
        self._execution_gate = execution_gate
        self._roots = {
            item.root_id: AllowedRoot(item.root_id, item.path.resolve(strict=True), item.trust)
            for item in policy.allowed_roots
        }

    def read(self, request: FileReadRequest) -> FileReadResult:
        if self._execution_gate is not None:
            self._execution_gate()
        request_id = "file-read-" + uuid.uuid4().hex
        root = self._roots.get(request.root_id)
        if root is None:
            return self._finish(
                request_id, request, None, FileReadDecision.BLOCK, FileReadReason.UNKNOWN_ROOT
            )
        relative = PurePath(request.path)
        if relative.is_absolute() or ".." in relative.parts:
            return self._finish(
                request_id, request, None, FileReadDecision.BLOCK, FileReadReason.TRAVERSAL
            )
        unresolved = root.path.joinpath(*relative.parts)
        try:
            resolved = unresolved.resolve(strict=True)
        except FileNotFoundError:
            return self._finish(
                request_id, request, None, FileReadDecision.BLOCK, FileReadReason.NOT_FOUND
            )
        except (OSError, RuntimeError):
            return self._finish(
                request_id, request, None, FileReadDecision.BLOCK, FileReadReason.OUTSIDE_ROOT
            )
        try:
            inside = resolved.is_relative_to(root.path)
        except ValueError:
            inside = False
        if not inside:
            reason = (
                FileReadReason.SYMLINK_ESCAPE
                if unresolved.is_symlink()
                else FileReadReason.OUTSIDE_ROOT
            )
            return self._finish(request_id, request, resolved, FileReadDecision.BLOCK, reason)
        sensitive = _is_sensitive_path(resolved, root.path)
        if sensitive and not self.policy.allow_sensitive:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.SENSITIVE,
                sensitive=True,
            )
        try:
            pre_open_metadata = resolved.stat()
        except OSError:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.SPECIAL_FILE,
                sensitive=sensitive,
            )
        if not stat.S_ISREG(pre_open_metadata.st_mode):
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.SPECIAL_FILE,
                sensitive=sensitive,
            )
        try:
            descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.SPECIAL_FILE,
                sensitive=sensitive,
            )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                return self._finish(
                    request_id,
                    request,
                    resolved,
                    FileReadDecision.BLOCK,
                    FileReadReason.SPECIAL_FILE,
                    sensitive=sensitive,
                )
            if (metadata.st_dev, metadata.st_ino) != (
                pre_open_metadata.st_dev,
                pre_open_metadata.st_ino,
            ):
                return self._finish(
                    request_id,
                    request,
                    resolved,
                    FileReadDecision.BLOCK,
                    FileReadReason.RACE_DETECTED,
                    sensitive=sensitive,
                )
            if metadata.st_nlink > 1 and not self.policy.allow_hard_links:
                return self._finish(
                    request_id,
                    request,
                    resolved,
                    FileReadDecision.BLOCK,
                    FileReadReason.HARD_LINK,
                    sensitive=sensitive,
                )
            if metadata.st_size > self.policy.max_file_size:
                return self._finish(
                    request_id,
                    request,
                    resolved,
                    FileReadDecision.BLOCK,
                    FileReadReason.TOO_LARGE,
                    sensitive=sensitive,
                )
            chunks: list[bytes] = []
            remaining = self.policy.max_file_size + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
        if len(raw) > self.policy.max_file_size:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.TOO_LARGE,
                sensitive=sensitive,
            )
        if b"\x00" in raw:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.BINARY,
                sensitive=sensitive,
            )
        try:
            content = raw.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK,
                FileReadReason.DECODING,
                sensitive=sensitive,
            )
        inspection = inspect_content(content, limits=self.policy.inspection_limits)
        security_findings = inspection.findings
        if sensitive:
            security_findings = (
                *security_findings,
                ContentSecurityFinding(
                    "SENSITIVE_CONTENT",
                    "SENSITIVE_PATH_SOURCE",
                    True,
                    "Content originated from a policy-classified sensitive path.",
                ),
            )
        envelope = ContentEnvelope._create_authoritative(
            content,
            source_type=ContentSourceType.FILE,
            trust=root.trust,
            provenance=(f"file:{resolved}", f"allowed-root:{root.root_id}"),
            producing_boundary="safe_file_reader",
            security_findings=security_findings,
            inspection_sha256=inspection.inspection_sha256,
        )
        if inspection.suspicious:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.REVIEW,
                FileReadReason.HIDDEN_CONTENT,
                sensitive=sensitive,
                envelope=envelope,
            )
        guarded = self.guard.inspect(
            InspectionRequest(
                content,
                "file",
                "model",
                {
                    "request_id": request.correlation_id,
                    "source_trust": root.trust,
                    "metadata": {
                        "content_id": envelope.content_id,
                        "file_request_id": request_id,
                    },
                },
            )
        )
        if guarded.decision is not GuardDecision.ALLOW:
            return self._finish(
                request_id,
                request,
                resolved,
                FileReadDecision.BLOCK
                if guarded.decision is GuardDecision.BLOCK
                else FileReadDecision.REVIEW,
                FileReadReason.POST_READ_POLICY,
                sensitive=sensitive,
                envelope=envelope,
                guard_audit_id=guarded.audit_id,
            )
        return self._finish(
            request_id,
            request,
            resolved,
            FileReadDecision.ALLOW,
            FileReadReason.ALLOWED,
            sensitive=sensitive,
            envelope=envelope,
        )

    def _finish(
        self,
        request_id: str,
        request: FileReadRequest,
        resolved: Path | None,
        decision: FileReadDecision,
        reason: FileReadReason,
        *,
        sensitive: bool = False,
        envelope: ContentEnvelope | None = None,
        guard_audit_id: str | None = None,
    ) -> FileReadResult:
        audit_id = "boundary-audit-" + uuid.uuid4().hex
        record: dict[str, Any] = {
            "schema_version": "file-boundary-audit-v0.1",
            "audit_id": audit_id,
            "request_id": request_id,
            "correlation_id": request.correlation_id,
            "causal_parent_ids": list(request.causal_parent_ids),
            "requested_path": request.path,
            "requested_path_sha256": hashlib.sha256(request.path.encode()).hexdigest(),
            "resolved_path": str(resolved) if resolved is not None else None,
            "allowed_root_id": request.root_id,
            "decision": decision.value,
            "reason_code": reason.value,
            "sensitive": sensitive,
            "content_id": envelope.content_id if envelope else None,
            "content_sha256": envelope.original_sha256 if envelope else None,
            "content_provenance": list(envelope.provenance) if envelope else [],
            "raw_content_retained": False,
            "guard_audit_id": guard_audit_id,
        }
        if self.audit_path is not None:
            append_chained_audit(self.audit_path, record)
        return FileReadResult(
            request_id=request_id,
            correlation_id=request.correlation_id,
            requested_path=request.path,
            resolved_path=str(resolved) if resolved is not None else None,
            decision=decision,
            reason_code=reason,
            sensitive=sensitive,
            envelope=envelope if decision is FileReadDecision.ALLOW else None,
            withheld_content_metadata=(
                envelope.metadata_dict()
                if envelope is not None and decision is not FileReadDecision.ALLOW
                else None
            ),
            audit_id=audit_id,
            guard_audit_id=guard_audit_id,
        )


def _is_sensitive_path(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    lowered = [unicodedata.normalize("NFKC", part).casefold() for part in relative.parts]
    filename = unicodedata.normalize("NFKC", path.name).casefold()
    sensitive_parts = {".ssh", ".aws", ".gnupg", ".kube", "credentials", "secrets"}
    sensitive_names = {
        ".env",
        "id_rsa",
        "id_ed25519",
        "credentials.json",
        "service-account.json",
        "authorized_keys",
    }
    sensitive_suffixes = (".pem", ".key", ".p12", ".pfx")
    return (
        any(part in sensitive_parts for part in lowered)
        or filename in sensitive_names
        or filename.endswith(sensitive_suffixes)
    )
