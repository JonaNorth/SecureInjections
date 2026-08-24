"""Optional local sentence-embedding semantic detector."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..semantic_registry import ModelEncodingProfile, model_encoding_profile
from .semantic import (
    SemanticDetector,
    SemanticMatch,
    SemanticResult,
    semantic_context_adjustment,
)
from .semantic_index import EmbeddingModel, SemanticIndex, SemanticIndexError


class SentenceTransformerEmbeddingModel(EmbeddingModel):
    """Load a trusted sentence-transformers model strictly from a local path."""

    def __init__(self, model_path: Path, *, model_id: str | None = None):
        if model_path.expanduser().is_symlink():
            raise ValueError("semantic_model_path may not be a symlink")
        resolved = model_path.expanduser().resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError("semantic_model_path must be a local model directory")
        all_files = tuple(path for path in sorted(resolved.rglob("*")) if path.is_file())
        if len(all_files) > 100_000:
            raise ValueError("local semantic model has too many files")
        if any(path.is_symlink() for path in all_files):
            raise ValueError("semantic model may not contain symlinked files")
        forbidden = {".pkl", ".pickle", ".joblib", ".bin", ".pt", ".pth"}
        if any(path.suffix.casefold() in forbidden for path in all_files):
            raise ValueError("unsafe pickle-capable semantic model artifact is not accepted")
        if not any(path.suffix.casefold() == ".safetensors" for path in all_files):
            raise ValueError("semantic model must use safetensors weights")
        identity = hashlib.sha256()
        identity_files = tuple(
            path
            for path in sorted(resolved.rglob("*"))
            if path.is_file() and path.suffix.lower() in {".json", ".txt"}
        )
        if not identity_files:
            raise ValueError("local semantic model has no identifiable configuration files")
        if len(identity_files) > 10_000:
            raise ValueError("local semantic model has too many configuration files")
        total_identity_bytes = 0
        for path in identity_files:
            if path.is_symlink() or path.stat().st_size > 10 * 1024 * 1024:
                raise ValueError("semantic model configuration contains an unsafe file")
            total_identity_bytes += path.stat().st_size
            if total_identity_bytes > 64 * 1024 * 1024:
                raise ValueError("semantic model configuration is oversized")
            identity.update(str(path.relative_to(resolved)).encode())
            identity.update(path.read_bytes())
            if path.suffix.casefold() == ".json":
                try:
                    configuration = json.loads(path.read_text(encoding="utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError("semantic model contains invalid JSON configuration") from exc
                if isinstance(configuration, dict) and (
                    configuration.get("auto_map") or configuration.get("trust_remote_code")
                ):
                    raise ValueError("semantic model requests remote/custom code")
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dependency boundary
            raise RuntimeError(
                "Install secureinjections[semantic] to use local sentence embeddings"
            ) from exc
        artifact = hashlib.sha256()
        total_artifact_bytes = 0
        for path in all_files:
            artifact.update(str(path.relative_to(resolved)).encode())
            total_artifact_bytes += path.stat().st_size
            if total_artifact_bytes > 20 * 1024 * 1024 * 1024:
                raise ValueError("semantic model artifact exceeds 20 GiB")
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    artifact.update(chunk)
        self._encoding_profile: ModelEncodingProfile | None = (
            model_encoding_profile(model_id) if model_id is not None else None
        )
        self._model = SentenceTransformer(
            str(resolved), local_files_only=True, trust_remote_code=False
        )
        self._identifier = "local:" + identity.hexdigest()[:24]
        if self._encoding_profile is not None:
            profile_hash = hashlib.sha256(
                json.dumps(
                    {
                        "model_id": self._encoding_profile.model_id,
                        "query_prefix": self._encoding_profile.query_prefix,
                        "document_prefix": self._encoding_profile.document_prefix,
                        "normalize_embeddings": self._encoding_profile.normalize_embeddings,
                    },
                    sort_keys=True,
                ).encode()
            ).hexdigest()[:12]
            self._identifier += ":" + profile_hash
        self._artifact_hash = artifact.hexdigest()

    @property
    def identifier(self) -> str:
        return self._identifier

    @property
    def artifact_hash(self) -> str:
        return self._artifact_hash

    def encode(self, texts: Sequence[str]) -> Any:
        """Compatibility path used for index documents."""

        return self.encode_documents(texts)

    def _encode_with_prefix(self, texts: Sequence[str], prefix: str) -> Any:
        values = [prefix + text for text in texts]
        normalize = (
            self._encoding_profile.normalize_embeddings
            if self._encoding_profile is not None
            else False
        )
        return self._model.encode(
            values,
            convert_to_numpy=True,
            normalize_embeddings=normalize,
            show_progress_bar=False,
        )

    def encode_documents(self, texts: Sequence[str]) -> Any:
        prefix = self._encoding_profile.document_prefix if self._encoding_profile else ""
        return self._encode_with_prefix(texts, prefix)

    def encode_queries(self, texts: Sequence[str]) -> Any:
        prefix = self._encoding_profile.query_prefix if self._encoding_profile else ""
        return self._encode_with_prefix(texts, prefix)


class LocalEmbeddingSemanticDetector(SemanticDetector):
    """Cosine similarity against a local index of rule-owned threat examples."""

    def __init__(
        self,
        *,
        index_path: Path | None = None,
        model_path: Path | None = None,
        index: SemanticIndex | None = None,
        embedding_model: EmbeddingModel | None = None,
        model_id: str | None = None,
        similarity_threshold: float | None = None,
        top_k: int = 3,
    ) -> None:
        if similarity_threshold is not None and not 0.0 <= similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be between 0 and 1")
        if top_k < 1:
            raise ValueError("top_k must be positive")
        self.index = index or SemanticIndex.load(index_path or Path())
        self.embedding_model = embedding_model or SentenceTransformerEmbeddingModel(
            model_path or Path(), model_id=model_id
        )
        if self.index.model_identifier != self.embedding_model.identifier:
            raise SemanticIndexError("semantic index model identifier does not match local model")
        calibrated_threshold: float | None = None
        if self.index.calibration is not None:
            recommended = self.index.calibration.get("recommended")
            if isinstance(recommended, dict):
                candidate = recommended.get("threshold")
                if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                    calibrated_threshold = float(candidate)
        self.similarity_threshold = (
            similarity_threshold
            if similarity_threshold is not None
            else calibrated_threshold
            if calibrated_threshold is not None
            else 0.68
        )
        if not 0.0 <= self.similarity_threshold <= 1.0:
            raise SemanticIndexError("semantic index calibration threshold is invalid")
        self.top_k = top_k

    def analyze(self, text: str) -> SemanticResult:
        # The user vector exists only in this stack frame and is never written to disk.
        import numpy as np

        encode_query = getattr(self.embedding_model, "encode_queries", self.embedding_model.encode)
        vector = np.asarray(encode_query((text,)), dtype=np.float32)
        if vector.shape != (1, self.index.vectors.shape[1]) or not np.isfinite(vector).all():
            raise SemanticIndexError("embedding model returned an invalid query vector")
        norm = float(np.linalg.norm(vector[0]))
        if norm == 0:
            return SemanticResult(0, (), "Local semantic similarity found no usable signal.")
        similarities = self.index.vectors @ (vector[0] / norm)
        context_adjustment, context_signals = semantic_context_adjustment(text)
        matches_list: list[SemanticMatch] = []
        seen_rule_ids: set[str] = set()
        for index in np.argsort(-similarities, kind="stable"):
            raw_similarity = float(similarities[int(index)])
            similarity = max(-1.0, min(1.0, raw_similarity + context_adjustment))
            entry = self.index.entries[int(index)]
            if similarity < self.similarity_threshold:
                break
            if entry.rule_id in seen_rule_ids:
                continue
            matches_list.append(
                SemanticMatch(
                    rule_id=entry.rule_id,
                    category=entry.category,
                    similarity=round(similarity, 6),
                )
            )
            seen_rule_ids.add(entry.rule_id)
            if len(matches_list) >= self.top_k:
                break
        matches = tuple(matches_list)
        categories = tuple(sorted({match.category for match in matches}))
        highest = max((match.similarity for match in matches), default=0.0)
        score = min(100, round(highest * 100))
        explanation = (
            "Local embedding similarity found threat-corpus proximity; similarity is not proof."
            if matches
            else (
                "Local embedding similarity found no threat examples above "
                "the configured threshold."
            )
        )
        return SemanticResult(score, categories, explanation, matches, context_signals)
