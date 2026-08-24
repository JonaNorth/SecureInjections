"""Safe, deterministic NumPy cosine index for threat-example embeddings."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..rules.models import ThreatRule
from ..rules.validator import RULE_ID_PATTERN, SEVERITIES
from ..version import SEMANTIC_INDEX_VERSION

MAX_INDEX_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_INDEX_ENTRIES = 2_000_000


class SemanticIndexError(ValueError):
    pass


class EmbeddingModel(Protocol):
    @property
    def identifier(self) -> str: ...

    def encode(self, texts: Sequence[str]) -> Any: ...


@dataclass(frozen=True, slots=True)
class SemanticIndexEntry:
    rule_id: str
    category: str
    severity: str


@dataclass(frozen=True, slots=True)
class SemanticIndex:
    vectors: Any
    entries: tuple[SemanticIndexEntry, ...]
    model_identifier: str
    content_hash: str
    calibration: dict[str, Any] | None = None

    @staticmethod
    def _numpy() -> Any:
        try:
            import numpy as np
        except ImportError as exc:  # pragma: no cover - optional dependency boundary
            raise RuntimeError(
                "Install secureinjections[semantic] to use local embedding indexes"
            ) from exc
        return np

    @classmethod
    def build(
        cls,
        rules: Sequence[ThreatRule],
        embedding_model: EmbeddingModel,
        output_path: Path,
        calibration: dict[str, Any] | None = None,
    ) -> SemanticIndex:
        np = cls._numpy()
        examples: list[str] = []
        entries: list[SemanticIndexEntry] = []
        for rule in sorted(rules, key=lambda item: item.id):
            if not rule.enabled or rule.status == "deprecated":
                continue
            for example in rule.semantic_examples:
                examples.append(example)
                entries.append(SemanticIndexEntry(rule.id, rule.category, rule.severity))
        if not examples:
            raise SemanticIndexError("no enabled semantic_examples were found")
        encode_documents = getattr(embedding_model, "encode_documents", embedding_model.encode)
        vectors = np.asarray(encode_documents(examples), dtype=np.float32)
        if vectors.ndim != 2 or vectors.shape[0] != len(examples) or vectors.shape[1] < 1:
            raise SemanticIndexError("embedding model returned an invalid matrix shape")
        if not np.isfinite(vectors).all():
            raise SemanticIndexError("embedding matrix contains non-finite values")
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        if np.any(norms == 0):
            raise SemanticIndexError("embedding model returned a zero vector")
        vectors = np.ascontiguousarray(vectors / norms, dtype=np.float32)
        metadata_without_hash = {
            "index_version": SEMANTIC_INDEX_VERSION,
            "model_identifier": embedding_model.identifier,
            "dimension": int(vectors.shape[1]),
            "count": int(vectors.shape[0]),
            "entries": [
                {
                    "rule_id": entry.rule_id,
                    "category": entry.category,
                    "severity": entry.severity,
                }
                for entry in entries
            ],
        }
        if calibration is not None:
            if (
                calibration.get("split") != "validation"
                or calibration.get("holdout_used") is not False
            ):
                raise SemanticIndexError("semantic calibration must use validation data only")
            metadata_without_hash["calibration"] = calibration
        vectors_bytes = vectors.tobytes(order="C")
        canonical = json.dumps(
            metadata_without_hash, sort_keys=True, separators=(",", ":")
        ).encode()
        content_hash = hashlib.sha256(canonical + vectors_bytes).hexdigest()
        metadata = {**metadata_without_hash, "content_hash": content_hash}

        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() or output_path.is_symlink():
            raise SemanticIndexError(f"refusing to overwrite semantic index: {output_path}")
        temporary = Path(tempfile.mkdtemp(prefix=".semantic-index-", dir=output_path.parent))
        try:
            np.save(temporary / "vectors.npy", vectors, allow_pickle=False)
            (temporary / "metadata.json").write_text(
                json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            for name in ("vectors.npy", "metadata.json"):
                with (temporary / name).open("rb") as handle:
                    os.fsync(handle.fileno())
            os.rename(temporary, output_path)
        except Exception:
            for child in temporary.iterdir():
                child.unlink(missing_ok=True)
            temporary.rmdir()
            raise
        return cls(
            vectors,
            tuple(entries),
            embedding_model.identifier,
            content_hash,
            calibration,
        )

    @classmethod
    def load(cls, path: Path) -> SemanticIndex:
        np = cls._numpy()
        metadata_path = path / "metadata.json"
        vectors_path = path / "vectors.npy"
        if path.is_symlink() or metadata_path.is_symlink() or vectors_path.is_symlink():
            raise SemanticIndexError("semantic index symlinks are not accepted")
        if not metadata_path.is_file() or not vectors_path.is_file():
            raise SemanticIndexError("semantic index requires metadata.json and vectors.npy")
        if metadata_path.stat().st_size > MAX_METADATA_BYTES:
            raise SemanticIndexError("semantic index metadata is oversized")
        if vectors_path.stat().st_size > MAX_INDEX_BYTES:
            raise SemanticIndexError("semantic vector file is oversized")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SemanticIndexError(f"invalid semantic index metadata: {exc}") from exc
        required = {
            "index_version",
            "model_identifier",
            "dimension",
            "count",
            "entries",
            "content_hash",
        }
        allowed = required | {"calibration"}
        if (
            not isinstance(metadata, dict)
            or not required <= set(metadata)
            or set(metadata) - allowed
        ):
            raise SemanticIndexError("semantic index metadata fields are invalid")
        if metadata["index_version"] != SEMANTIC_INDEX_VERSION:
            raise SemanticIndexError("unsupported semantic index version")
        count = metadata["count"]
        dimension = metadata["dimension"]
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 < count <= MAX_INDEX_ENTRIES
            or not isinstance(dimension, int)
            or isinstance(dimension, bool)
            or not 0 < dimension <= 65_536
        ):
            raise SemanticIndexError("semantic index dimensions are invalid")
        try:
            vectors = np.load(vectors_path, mmap_mode="r", allow_pickle=False)
        except (OSError, ValueError) as exc:
            raise SemanticIndexError(f"unable to load safe NumPy index: {exc}") from exc
        if vectors.dtype != np.float32 or vectors.shape != (count, dimension):
            raise SemanticIndexError("semantic vector shape or dtype does not match metadata")
        if not np.isfinite(vectors).all():
            raise SemanticIndexError("semantic vectors contain non-finite values")
        raw_entries = metadata["entries"]
        if not isinstance(raw_entries, list) or len(raw_entries) != count:
            raise SemanticIndexError("semantic index entry count does not match vectors")
        try:
            entries = tuple(
                SemanticIndexEntry(
                    rule_id=item["rule_id"],
                    category=item["category"],
                    severity=item["severity"],
                )
                for item in raw_entries
                if isinstance(item, dict) and set(item) == {"rule_id", "category", "severity"}
            )
        except (KeyError, TypeError) as exc:
            raise SemanticIndexError("invalid semantic index entries") from exc
        if len(entries) != count:
            raise SemanticIndexError("invalid semantic index entry metadata")
        if any(
            not isinstance(entry.rule_id, str)
            or not RULE_ID_PATTERN.fullmatch(entry.rule_id)
            or not isinstance(entry.category, str)
            or not entry.category
            or not isinstance(entry.severity, str)
            or entry.severity not in SEVERITIES
            for entry in entries
        ):
            raise SemanticIndexError("semantic index entry values are invalid")
        without_hash = {key: value for key, value in metadata.items() if key != "content_hash"}
        canonical = json.dumps(without_hash, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(canonical + vectors.tobytes(order="C")).hexdigest()
        if not isinstance(metadata["content_hash"], str) or not hmac.compare_digest(
            expected, metadata["content_hash"]
        ):
            raise SemanticIndexError("semantic index content hash mismatch")
        if (
            not isinstance(metadata["model_identifier"], str)
            or not metadata["model_identifier"]
            or len(metadata["model_identifier"]) > 512
        ):
            raise SemanticIndexError("invalid model identifier")
        calibration = metadata.get("calibration")
        if calibration is not None and (
            not isinstance(calibration, dict)
            or calibration.get("split") != "validation"
            or calibration.get("holdout_used") is not False
        ):
            raise SemanticIndexError("semantic index calibration metadata is invalid")
        return cls(vectors, entries, metadata["model_identifier"], expected, calibration)

    def inspect(self) -> dict[str, Any]:
        return {
            "index_version": SEMANTIC_INDEX_VERSION,
            "model_identifier": self.model_identifier,
            "count": len(self.entries),
            "dimension": int(self.vectors.shape[1]),
            "content_hash": self.content_hash,
            "rule_count": len({entry.rule_id for entry in self.entries}),
            "categories": sorted({entry.category for entry in self.entries}),
            "calibration": self.calibration,
        }
