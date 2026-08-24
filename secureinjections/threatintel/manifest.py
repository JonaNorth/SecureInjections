"""Strict signed feed manifest model."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..rules.validator import parse_version
from ..version import FEED_MANIFEST_VERSION, THREAT_RULE_SCHEMA_VERSION

HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}\Z")
ARTIFACT_PATTERN = re.compile(r"artifacts/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip\Z")


class FeedManifestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FeedManifest:
    manifest_version: int
    feed_version: str
    edition: str
    schema_version: int
    created_at: str
    minimum_engine_version: str
    rules_version: str
    semantic_index_version: str | None
    artifact_hashes: dict[str, str]
    signing_key_id: str
    classifier_model_version: str | None = None
    quality_metadata: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> FeedManifest:
        required = {
            "manifest_version",
            "feed_version",
            "edition",
            "schema_version",
            "created_at",
            "minimum_engine_version",
            "rules_version",
            "semantic_index_version",
            "artifact_hashes",
            "signing_key_id",
        }
        optional = {"quality_metadata", "provenance", "classifier_model_version"}
        if not isinstance(raw, dict) or not required <= set(raw) or set(raw) - required - optional:
            raise FeedManifestError("feed manifest fields are invalid")
        if raw["manifest_version"] != FEED_MANIFEST_VERSION:
            raise FeedManifestError("unsupported feed manifest version")
        if raw["schema_version"] != THREAT_RULE_SCHEMA_VERSION:
            raise FeedManifestError("unsupported threat rule schema version")
        for field_name in ("feed_version", "rules_version", "minimum_engine_version"):
            if not isinstance(raw[field_name], str):
                raise FeedManifestError(f"{field_name} must be a string")
            parse_version(raw[field_name])
        if raw["edition"] not in {"community", "commercial", "private"}:
            raise FeedManifestError("invalid feed edition")
        try:
            parsed_date = datetime.fromisoformat(raw["created_at"].replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise FeedManifestError("created_at must be an ISO-8601 timestamp") from exc
        if parsed_date.tzinfo is None:
            raise FeedManifestError("created_at must include a timezone")
        semantic_version = raw["semantic_index_version"]
        if semantic_version is not None:
            if not isinstance(semantic_version, str):
                raise FeedManifestError("semantic_index_version must be a string or null")
            parse_version(semantic_version)
        classifier_version = raw.get("classifier_model_version")
        if classifier_version is not None:
            if not isinstance(classifier_version, str):
                raise FeedManifestError("classifier_model_version must be a string or null")
            parse_version(classifier_version)
        hashes = raw["artifact_hashes"]
        if not isinstance(hashes, dict) or not hashes:
            raise FeedManifestError("artifact_hashes must not be empty")
        if "artifacts/rules.zip" not in hashes:
            raise FeedManifestError("rules artifact is required")
        for name, digest in hashes.items():
            if not isinstance(name, str) or not ARTIFACT_PATTERN.fullmatch(name):
                raise FeedManifestError(f"invalid artifact name: {name!r}")
            if not isinstance(digest, str) or not HASH_PATTERN.fullmatch(digest):
                raise FeedManifestError(f"invalid SHA-256 for artifact: {name}")
        has_semantic_artifact = "artifacts/semantic-index.zip" in hashes
        if has_semantic_artifact != (semantic_version is not None):
            raise FeedManifestError(
                "semantic_index_version and semantic-index artifact must be present together"
            )
        has_classifier_artifact = "artifacts/classifier-model.zip" in hashes
        if has_classifier_artifact != (classifier_version is not None):
            raise FeedManifestError(
                "classifier_model_version and classifier-model artifact must be present together"
            )
        key_id = raw["signing_key_id"]
        if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
            raise FeedManifestError("invalid signing_key_id")
        quality = raw.get("quality_metadata", {})
        provenance = raw.get("provenance", {})
        if not isinstance(quality, dict) or not isinstance(provenance, dict):
            raise FeedManifestError("quality_metadata and provenance must be objects")
        quality_fields = {
            "rules_count",
            "semantic_examples_count",
            "languages",
            "corpus_version",
            "evaluation_version",
            "evaluation_hash",
            "deterministic_fpr",
            "combined_fpr",
            "critical_recall",
            "classifier_validation_recall",
            "classifier_validation_fpr",
        }
        provenance_fields = {
            "rule_database_hash",
            "semantic_corpus_hash",
            "semantic_index_hash",
            "evaluation_report_hash",
            "engine_compatibility",
            "build_tool_version",
            "classifier_model_hash",
        }
        if set(quality) - quality_fields or set(provenance) - provenance_fields:
            raise FeedManifestError("unknown feed quality or provenance field")
        for key in ("evaluation_hash",):
            if key in quality and (
                not isinstance(quality[key], str) or not HASH_PATTERN.fullmatch(quality[key])
            ):
                raise FeedManifestError(f"invalid quality hash: {key}")
        for key in ("rules_count", "semantic_examples_count"):
            if key in quality and (
                not isinstance(quality[key], int)
                or isinstance(quality[key], bool)
                or quality[key] < 0
            ):
                raise FeedManifestError(f"invalid quality count: {key}")
        if "languages" in quality and (
            not isinstance(quality["languages"], list)
            or not all(isinstance(value, str) and value for value in quality["languages"])
        ):
            raise FeedManifestError("invalid quality languages")
        for key in (
            "deterministic_fpr",
            "combined_fpr",
            "critical_recall",
            "classifier_validation_recall",
            "classifier_validation_fpr",
        ):
            if key in quality and (
                isinstance(quality[key], bool)
                or not isinstance(quality[key], int | float)
                or not 0 <= quality[key] <= 1
            ):
                raise FeedManifestError(f"invalid quality rate: {key}")
        for key, value in provenance.items():
            if (
                key.endswith("_hash")
                and value is not None
                and (not isinstance(value, str) or not HASH_PATTERN.fullmatch(value))
            ):
                raise FeedManifestError(f"invalid provenance hash: {key}")
        for key in ("engine_compatibility", "build_tool_version"):
            if key in provenance:
                if not isinstance(provenance[key], str):
                    raise FeedManifestError(f"invalid provenance version: {key}")
                parse_version(provenance[key])
        return cls(
            manifest_version=raw["manifest_version"],
            feed_version=raw["feed_version"],
            edition=raw["edition"],
            schema_version=raw["schema_version"],
            created_at=raw["created_at"],
            minimum_engine_version=raw["minimum_engine_version"],
            rules_version=raw["rules_version"],
            semantic_index_version=semantic_version,
            artifact_hashes=dict(sorted(hashes.items())),
            signing_key_id=key_id,
            classifier_model_version=classifier_version,
            quality_metadata=quality,
            provenance=provenance,
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "manifest_version": self.manifest_version,
            "feed_version": self.feed_version,
            "edition": self.edition,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "minimum_engine_version": self.minimum_engine_version,
            "rules_version": self.rules_version,
            "semantic_index_version": self.semantic_index_version,
            "artifact_hashes": dict(sorted(self.artifact_hashes.items())),
            "signing_key_id": self.signing_key_id,
        }
        if self.quality_metadata:
            result["quality_metadata"] = self.quality_metadata
        if self.provenance:
            result["provenance"] = self.provenance
        if self.classifier_model_version is not None:
            result["classifier_model_version"] = self.classifier_model_version
        return result

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
