"""Typed content and provenance contracts for agent reasoning boundaries."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..guard import TrustLevel

_CONTENT_AUTHORITY = object()
_PERSISTENT_REHYDRATION_CAPABILITY = object()
MAX_ENVELOPE_HISTORY = 128


class ContentSourceType(StrEnum):
    FILE = "file"
    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    AGENT_MESSAGE = "agent_message"
    USER = "user"
    MODEL = "model"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class Transformation:
    name: str
    producer: str
    input_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "producer": self.producer, "input_ids": list(self.input_ids)}


@dataclass(frozen=True, slots=True)
class ContentSecurityFinding:
    finding_type: str
    reason_code: str
    suspicious: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "reason_code": self.reason_code,
            "suspicious": self.suspicious,
            "detail": self.detail,
        }


_TRUST_ORDER = {
    TrustLevel.EXTERNAL: 0,
    TrustLevel.UNTRUSTED: 1,
    TrustLevel.INTERNAL: 2,
    TrustLevel.TRUSTED: 3,
}


def least_trusted(levels: tuple[TrustLevel, ...]) -> TrustLevel:
    """Return the deterministic lower trust bound for a set of inputs."""

    if not levels:
        raise ValueError("trust propagation requires at least one trust input")
    return min(levels, key=_TRUST_ORDER.__getitem__)


@dataclass(frozen=True, slots=True)
class ContentEnvelope:
    """Content plus immutable origin and taint metadata.

    ``trust`` is an effective lower bound. Derivation can preserve or lower it, but
    cannot silently raise it above any parent.
    """

    content: str = field(repr=False)
    content_id: str
    source_type: ContentSourceType
    trust: TrustLevel
    provenance: tuple[str, ...]
    producing_boundary: str
    parent_ids: tuple[str, ...] = ()
    transformations: tuple[Transformation, ...] = ()
    security_findings: tuple[ContentSecurityFinding, ...] = ()
    ever_untrusted: bool = False
    original_sha256: str = ""
    ancestor_sha256: tuple[str, ...] = ()
    inspection_sha256: str | None = None
    _authority: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise TypeError("envelope content must be text")
        if len(self.content) > 1_000_000:
            raise ValueError("envelope content exceeds the 1,000,000 character limit")
        if not self.content_id or len(self.content_id) > 200:
            raise ValueError("content_id must be a bounded non-empty string")
        if self.content_id in self.parent_ids:
            raise ValueError("content envelope cannot be its own parent")
        if len(set(self.parent_ids)) != len(self.parent_ids):
            raise ValueError("content envelope parent IDs must be unique")
        if any(
            len(items) > MAX_ENVELOPE_HISTORY
            for items in (
                self.provenance,
                self.transformations,
                self.security_findings,
                self.ancestor_sha256,
            )
        ):
            raise ValueError("content envelope metadata history exceeds its bound")
        if not self.provenance or any(not item or len(item) > 500 for item in self.provenance):
            raise ValueError("provenance must contain bounded non-empty entries")
        digest = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if self.original_sha256 and len(self.original_sha256) != 64:
            raise ValueError("original_sha256 must be a SHA-256 hex digest")
        if not self.original_sha256:
            object.__setattr__(self, "original_sha256", digest)
        if not self.ancestor_sha256:
            object.__setattr__(self, "ancestor_sha256", (self.original_sha256,))
        if self.trust in {TrustLevel.UNTRUSTED, TrustLevel.EXTERNAL} and not self.ever_untrusted:
            object.__setattr__(self, "ever_untrusted", True)
        if self._authority is not _CONTENT_AUTHORITY:
            if self.trust in {TrustLevel.TRUSTED, TrustLevel.INTERNAL}:
                object.__setattr__(self, "trust", TrustLevel.UNTRUSTED)
            object.__setattr__(self, "ever_untrusted", True)

    @property
    def authoritative(self) -> bool:
        return self._authority is _CONTENT_AUTHORITY

    @classmethod
    def create(
        cls,
        content: str,
        *,
        source_type: ContentSourceType,
        trust: TrustLevel,
        provenance: tuple[str, ...],
        producing_boundary: str,
        security_findings: tuple[ContentSecurityFinding, ...] = (),
        inspection_sha256: str | None = None,
        content_id: str | None = None,
    ) -> ContentEnvelope:
        if content_id is not None:
            raise ValueError("caller-supplied content IDs are not accepted")
        return cls(
            content,
            content_id or "content-" + uuid.uuid4().hex,
            source_type,
            trust,
            provenance,
            producing_boundary,
            security_findings=security_findings,
            ever_untrusted=trust in {TrustLevel.UNTRUSTED, TrustLevel.EXTERNAL},
            ancestor_sha256=(hashlib.sha256(content.encode("utf-8")).hexdigest(),),
            inspection_sha256=inspection_sha256,
        )

    @classmethod
    def _create_authoritative(
        cls,
        content: str,
        *,
        source_type: ContentSourceType,
        trust: TrustLevel,
        provenance: tuple[str, ...],
        producing_boundary: str,
        security_findings: tuple[ContentSecurityFinding, ...] = (),
        inspection_sha256: str | None = None,
    ) -> ContentEnvelope:
        return cls(
            content,
            "content-" + uuid.uuid4().hex,
            source_type,
            trust,
            provenance,
            producing_boundary,
            security_findings=security_findings,
            ever_untrusted=trust in {TrustLevel.UNTRUSTED, TrustLevel.EXTERNAL},
            ancestor_sha256=(hashlib.sha256(content.encode("utf-8")).hexdigest(),),
            inspection_sha256=inspection_sha256,
            _authority=_CONTENT_AUTHORITY,
        )

    @classmethod
    def _from_verified_persistent(
        cls, capability: object, content: str, record: Any
    ) -> ContentEnvelope:
        """Rehydrate content only after an authenticated store record and digest check."""

        if capability is not _PERSISTENT_REHYDRATION_CAPABILITY:
            raise PermissionError("persistent envelope rehydration requires host authority")

        return cls(
            content=content,
            content_id=record.content_id,
            source_type=ContentSourceType(record.source_type),
            trust=TrustLevel(record.trust),
            provenance=record.provenance,
            producing_boundary=record.producing_boundary,
            parent_ids=record.parent_content_ids,
            transformations=tuple(
                Transformation(
                    str(item["name"]),
                    str(item["producer"]),
                    tuple(str(value) for value in item["input_ids"]),
                )
                for item in record.transformations
            ),
            security_findings=tuple(
                ContentSecurityFinding(
                    str(item["finding_type"]),
                    str(item["reason_code"]),
                    bool(item["suspicious"]),
                    str(item["detail"]),
                )
                for item in record.findings
            ),
            ever_untrusted=record.ever_untrusted,
            original_sha256=record.content_digest,
            ancestor_sha256=record.ancestor_digests,
            inspection_sha256=record.inspection_digest,
            _authority=_CONTENT_AUTHORITY,
        )

    @classmethod
    def derive(
        cls,
        content: str,
        *,
        parents: tuple[ContentEnvelope, ...],
        source_type: ContentSourceType,
        producing_boundary: str,
        transformation: str,
        producer: str,
        requested_trust: TrustLevel | None = None,
        security_findings: tuple[ContentSecurityFinding, ...] = (),
        inspection_sha256: str | None = None,
        content_id: str | None = None,
    ) -> ContentEnvelope:
        if not parents:
            raise ValueError("derived content requires at least one parent envelope")
        if len(parents) > 128:
            raise ValueError("derived content exceeds the 128-parent limit")
        if content_id is not None:
            raise ValueError("caller-supplied content IDs are not accepted")
        unique_parents = tuple(dict.fromkeys(parent.content_id for parent in parents))
        parents_by_id = {parent.content_id: parent for parent in parents}
        parents = tuple(parents_by_id[parent_id] for parent_id in unique_parents)
        parent_bound = least_trusted(tuple(parent.trust for parent in parents))
        effective = (
            parent_bound
            if requested_trust is None
            else least_trusted((parent_bound, requested_trust))
        )
        parent_ids = tuple(parent.content_id for parent in parents)
        histories = _compact_transformations(
            tuple(item for parent in parents for item in parent.transformations),
            reserve=1,
        )
        finding_union = compact_security_findings(
            tuple(
                dict.fromkeys(
                    (
                        *[item for parent in parents for item in parent.security_findings],
                        *security_findings,
                    )
                )
            )
        )
        provenance = _compact_strings(
            tuple(
                dict.fromkeys(
                    (
                        *[item for parent in parents for item in parent.provenance],
                        producing_boundary,
                    )
                )
            )
        )
        ancestor_hashes = _compact_strings(
            tuple(
                dict.fromkeys(
                    item
                    for parent in parents
                    for item in (*parent.ancestor_sha256, parent.original_sha256)
                )
            )
        )
        return cls(
            content,
            content_id or "content-" + uuid.uuid4().hex,
            source_type,
            effective,
            provenance,
            producing_boundary,
            parent_ids,
            (*histories, Transformation(transformation, producer, parent_ids)),
            finding_union,
            any(parent.ever_untrusted for parent in parents)
            or effective in {TrustLevel.UNTRUSTED, TrustLevel.EXTERNAL},
            hashlib.sha256(content.encode("utf-8")).hexdigest(),
            ancestor_hashes,
            inspection_sha256,
            _CONTENT_AUTHORITY if all(parent.authoritative for parent in parents) else None,
        )

    @property
    def suspicious_encoded(self) -> bool:
        return any(
            finding.suspicious and finding.finding_type.startswith("ENCODED_")
            for finding in self.security_findings
        )

    def metadata_dict(self) -> dict[str, Any]:
        """Serialize security metadata without returning raw content."""

        return {
            "content_id": self.content_id,
            "source_type": self.source_type.value,
            "trust": self.trust.value,
            "provenance": list(self.provenance),
            "producing_boundary": self.producing_boundary,
            "parent_ids": list(self.parent_ids),
            "transformations": [item.to_dict() for item in self.transformations],
            "security_findings": [item.to_dict() for item in self.security_findings],
            "ever_untrusted": self.ever_untrusted,
            "original_sha256": self.original_sha256,
            "ancestor_sha256": list(self.ancestor_sha256),
            "inspection_sha256": self.inspection_sha256,
            "raw_content_retained": False,
            "authoritative": self.authoritative,
        }


def _history_digest(values: tuple[str, ...]) -> str:
    encoded = b"".join(value.encode("utf-8") + b"\0" for value in values)
    return hashlib.sha256(encoded).hexdigest()


def _compact_strings(values: tuple[str, ...]) -> tuple[str, ...]:
    if len(values) <= MAX_ENVELOPE_HISTORY:
        return values
    omitted = values[: -(MAX_ENVELOPE_HISTORY - 1)]
    return (f"compacted:sha256:{_history_digest(omitted)}", *values[-(MAX_ENVELOPE_HISTORY - 1) :])


def _compact_transformations(
    values: tuple[Transformation, ...], *, reserve: int = 0
) -> tuple[Transformation, ...]:
    limit = MAX_ENVELOPE_HISTORY - reserve
    if len(values) <= limit:
        return values
    omitted = values[: -(limit - 1)]
    digest = hashlib.sha256(
        repr(tuple(item.to_dict() for item in omitted)).encode("utf-8")
    ).hexdigest()
    return (
        Transformation("compacted_history", f"sha256:{digest}", ()),
        *values[-(limit - 1) :],
    )


def compact_security_findings(
    values: tuple[ContentSecurityFinding, ...],
) -> tuple[ContentSecurityFinding, ...]:
    unique = tuple(dict.fromkeys(values))
    if len(unique) <= MAX_ENVELOPE_HISTORY:
        return unique
    sensitive = next((item for item in unique if item.finding_type == "SENSITIVE_CONTENT"), None)
    kept = list(unique[-(MAX_ENVELOPE_HISTORY - 2) :])
    if sensitive is not None and sensitive not in kept:
        kept[0] = sensitive
    omitted_digest = hashlib.sha256(
        repr(tuple(item.to_dict() for item in unique if item not in kept)).encode("utf-8")
    ).hexdigest()
    summary = ContentSecurityFinding(
        "COMPACTED_SECURITY_FINDINGS",
        "SECURITY_FINDINGS_COMPACTED",
        any(item.suspicious for item in unique),
        f"Older findings compacted under sha256:{omitted_digest}",
    )
    return (summary, *kept)
