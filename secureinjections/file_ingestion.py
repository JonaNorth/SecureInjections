"""Product-facing safe file ingestion over the existing Gateway boundary."""

from __future__ import annotations

import os
import stat
import unicodedata
import uuid
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Lock
from typing import Any
from urllib.parse import unquote

from .gateway import ContentEnvelope, FileReadRequest, GuardedToolGateway, LocalToolRegistry
from .guard import Guard, GuardPolicy, TrustLevel

FILE_INGESTION_SCHEMA = "safe-file-ingestion-v0.1"
FILE_INGESTION_ERROR_SCHEMA = "safe-file-ingestion-error-v0.1"
DEFAULT_MAX_FILE_SIZE = 1_000_000

SUPPORTED_FILE_TYPES: dict[str, tuple[str, str]] = {
    ".txt": ("Plain text", "text/plain"),
    ".md": ("Markdown", "text/markdown"),
    ".markdown": ("Markdown", "text/markdown"),
    ".json": ("JSON", "application/json"),
    ".jsonl": ("JSON Lines", "application/x-ndjson"),
    ".csv": ("CSV text", "text/csv"),
    ".log": ("Log", "text/plain"),
    ".py": ("Python source", "text/x-python"),
    ".js": ("JavaScript source", "text/javascript"),
    ".jsx": ("JavaScript JSX source", "text/jsx"),
    ".ts": ("TypeScript source", "text/typescript"),
    ".tsx": ("TypeScript TSX source", "text/tsx"),
    ".java": ("Java source", "text/x-java-source"),
    ".go": ("Go source", "text/x-go"),
    ".rs": ("Rust source", "text/x-rust"),
    ".sh": ("Shell source", "text/x-shellscript"),
    ".sql": ("SQL source", "application/sql"),
    ".yaml": ("YAML", "application/yaml"),
    ".yml": ("YAML", "application/yaml"),
    ".toml": ("TOML", "application/toml"),
    ".ini": ("Configuration", "text/plain"),
    ".cfg": ("Configuration", "text/plain"),
    ".xml": ("XML", "application/xml"),
    ".html": ("HTML source", "text/html"),
    ".css": ("CSS source", "text/css"),
}


class FileIngestionError(ValueError):
    """A product upload cannot safely enter the file boundary."""

    def __init__(self, code: str, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ProductFileMetadata:
    name: str
    extension: str
    type_label: str
    media_type: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "extension": self.extension,
            "type": self.type_label,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
        }


class ProductFileIngestor:
    """Stage uploads under host control and inspect them through SafeFileReader."""

    root_id = "product-upload"

    def __init__(
        self,
        upload_root: Path,
        *,
        guard: Guard | None = None,
        audit_path: Path | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_safe_references: int = 32,
    ) -> None:
        if max_file_size < 1 or max_file_size > 100_000_000:
            raise ValueError("max_file_size must be between 1 and 100,000,000 bytes")
        if upload_root.is_symlink():
            raise ValueError("upload_root must not be a symbolic link")
        upload_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.upload_root = upload_root.resolve(strict=True)
        if not self.upload_root.is_dir():
            raise ValueError("upload_root must be a directory")
        root_metadata = self.upload_root.stat()
        if os.name == "posix":
            if root_metadata.st_uid != os.getuid():
                raise ValueError("upload_root must be owned by the current user")
            if stat.S_IMODE(root_metadata.st_mode) & 0o077:
                raise ValueError("upload_root must not be accessible by group or other users")
        if not 1 <= max_safe_references <= 1_000:
            raise ValueError("max_safe_references must be between 1 and 1,000")
        self.max_file_size = max_file_size
        self.max_safe_references = max_safe_references
        self.guard = guard or Guard(audit_path=audit_path)
        self._references: OrderedDict[str, ContentEnvelope] = OrderedDict()
        self._reference_lock = Lock()

    def _new_gateway(self) -> GuardedToolGateway:
        registry = LocalToolRegistry(
            self.upload_root,
            allowed_roots={self.root_id: self.upload_root},
            allowed_root_trust={self.root_id: TrustLevel.UNTRUSTED},
            max_file_size=self.max_file_size,
        )
        return GuardedToolGateway(self.guard, registry)

    @property
    def policy(self) -> GuardPolicy:
        return self.guard.policy

    def resolve_safe_reference(self, content_id: str) -> ContentEnvelope | None:
        """Resolve only a host-minted, currently retained ALLOW envelope."""

        with self._reference_lock:
            envelope = self._references.get(content_id)
            if envelope is not None:
                self._references.move_to_end(content_id)
            return envelope

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return tuple(SUPPORTED_FILE_TYPES)

    def capabilities(self) -> dict[str, Any]:
        return {
            "schema_version": "safe-file-ingestion-capabilities-v0.1",
            "max_file_size": self.max_file_size,
            "supported_file_types": [
                {
                    "extension": extension,
                    "type": values[0],
                    "media_type": values[1],
                }
                for extension, values in SUPPORTED_FILE_TYPES.items()
            ],
        }

    def ingest(self, encoded_filename: str, content: bytes) -> dict[str, Any]:
        metadata = self._validate_upload(encoded_filename, content)
        correlation_id = "file-ingest-" + uuid.uuid4().hex
        staged_name = f"upload-{uuid.uuid4().hex}{metadata.extension}"
        staged_path = self.upload_root / staged_name
        try:
            descriptor = os.open(
                staged_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                view = memoryview(content)
                written = 0
                while written < len(view):
                    count = os.write(descriptor, view[written:])
                    if count == 0:
                        raise OSError("could not complete the staged upload write")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            with suppress(FileNotFoundError):
                staged_path.unlink()
            raise FileIngestionError(
                "INGESTION_UNAVAILABLE",
                "The local inspection workspace is unavailable. Try again after checking it.",
                status_code=503,
            ) from exc

        try:
            try:
                result = self._new_gateway().read_file(
                    FileReadRequest(self.root_id, staged_name, correlation_id)
                )
            except OSError as exc:
                raise FileIngestionError(
                    "INSPECTION_UNAVAILABLE",
                    "The local inspection service could not complete safely. Try again later.",
                    status_code=503,
                ) from exc
        finally:
            with suppress(FileNotFoundError):
                staged_path.unlink()

        serialized = result.to_dict(include_content=False)
        envelope = serialized.get("content_envelope")
        envelope = envelope if isinstance(envelope, dict) else {}
        raw_findings = envelope.get("security_findings", [])
        findings = [
            {
                "type": item.get("finding_type"),
                "reason_code": item.get("reason_code"),
                "summary": item.get("detail"),
            }
            for item in raw_findings
            if isinstance(item, dict)
        ]
        decision = result.decision.value
        ready = result.content_forwardable
        if ready and result.envelope is not None:
            with self._reference_lock:
                self._references[result.envelope.content_id] = result.envelope
                while len(self._references) > self.max_safe_references:
                    self._references.popitem(last=False)
        payload: dict[str, Any] = {
            "schema_version": FILE_INGESTION_SCHEMA,
            "request_id": result.request_id,
            "correlation_id": result.correlation_id,
            "file": metadata.to_dict(),
            "decision": decision,
            "status": {
                "ALLOW": "Safe to use",
                "REVIEW": "Needs review",
                "BLOCK": "Blocked",
            }[decision],
            "summary": _decision_summary(decision, result.reason_code.value),
            "reason_code": result.reason_code.value,
            "findings": findings,
            "ready": ready,
            "safe_reference": (
                {
                    "content_id": result.content_id,
                    "authoritative": bool(envelope.get("authoritative")),
                    "forwardable": True,
                }
                if ready
                else None
            ),
            "provenance": {
                "source_type": envelope.get("source_type"),
                "trust": envelope.get("trust"),
                "ever_untrusted": envelope.get("ever_untrusted"),
                "producing_boundary": envelope.get("producing_boundary"),
                "raw_content_retained": False,
            },
            "audit": {
                "boundary_audit_id": result.audit_id,
                "guard_audit_id": result.guard_audit_id,
                "event_id": result.event_id,
            },
            "policy": {
                "id": self.policy.policy_id,
                "version": self.policy.version,
                "sha256": self.policy.policy_hash,
            },
            "content": None,
        }
        return payload

    def _validate_upload(self, encoded_filename: str, content: bytes) -> ProductFileMetadata:
        try:
            filename = unicodedata.normalize("NFKC", unquote(encoded_filename, errors="strict"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FileIngestionError("INVALID_FILENAME", "The file name is invalid.") from exc
        if (
            not filename
            or len(filename) > 255
            or "\x00" in filename
            or filename in {".", ".."}
            or PurePosixPath(filename).name != filename
            or PureWindowsPath(filename).name != filename
        ):
            raise FileIngestionError(
                "INVALID_PATH",
                "Choose a file directly; folder paths and path traversal are not accepted.",
            )
        extension = Path(filename).suffix.casefold()
        supported = SUPPORTED_FILE_TYPES.get(extension)
        if supported is None:
            raise FileIngestionError(
                "UNSUPPORTED_TYPE",
                "This file type is not supported for safe text ingestion.",
                status_code=415,
            )
        if not content:
            raise FileIngestionError("EMPTY_FILE", "The selected file is empty.")
        if len(content) > self.max_file_size:
            raise FileIngestionError(
                "FILE_TOO_LARGE",
                f"The file exceeds the {self.max_file_size:,}-byte limit.",
                status_code=413,
            )
        return ProductFileMetadata(filename, extension, supported[0], supported[1], len(content))


def error_payload(error: FileIngestionError) -> dict[str, Any]:
    return {
        "schema_version": FILE_INGESTION_ERROR_SCHEMA,
        "error": {
            "code": error.code,
            "message": str(error),
            "retryable": False,
        },
    }


def _decision_summary(decision: str, reason_code: str) -> str:
    if decision == "ALLOW":
        return "The file passed the current policy and is ready for a safe downstream workflow."
    if decision == "REVIEW":
        return "The file was stopped for review and cannot currently be approved in the product UI."
    if reason_code in {
        "FILE_PATH_TRAVERSAL",
        "FILE_OUTSIDE_ALLOWED_ROOT",
        "FILE_SYMLINK_ESCAPE",
        "FILE_SENSITIVE_PATH",
    }:
        return "The file was blocked by the local file-access policy. Its content was withheld."
    return (
        "SecureInjections prevented this file from entering agent context. "
        "Its content was withheld."
    )
