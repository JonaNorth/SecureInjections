"""Trusted, local semantic-model registry and encoding profiles."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ModelEncodingProfile:
    model_id: str
    model_family: str
    query_prefix: str
    document_prefix: str
    normalize_embeddings: bool


def load_model_registry(path: Path | None = None) -> dict[str, Any]:
    target = path or Path(str(files("secureinjections").joinpath("semantic-models.json")))
    raw = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "models"}:
        raise ValueError("semantic model registry fields are invalid")
    if raw["schema_version"] != 1 or not isinstance(raw["models"], list):
        raise ValueError("unsupported semantic model registry")
    required = {
        "model_id",
        "model_family",
        "query_prefix",
        "document_prefix",
        "normalize_embeddings",
        "expected_dimension",
        "languages",
        "license",
        "trusted_revision",
        "expected_hash",
        "recommended",
        "notes",
    }
    ids: set[str] = set()
    for item in raw["models"]:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("semantic model registry entry fields are invalid")
        if not isinstance(item["model_id"], str) or item["model_id"] in ids:
            raise ValueError("invalid or duplicate semantic model id")
        if not isinstance(item["expected_dimension"], int) or item["expected_dimension"] < 1:
            raise ValueError("invalid expected semantic dimension")
        if item["expected_hash"] is not None and (
            not isinstance(item["expected_hash"], str) or len(item["expected_hash"]) != 64
        ):
            raise ValueError("invalid semantic artifact hash")
        if (
            not isinstance(item["query_prefix"], str)
            or len(item["query_prefix"]) > 512
            or not isinstance(item["document_prefix"], str)
            or len(item["document_prefix"]) > 512
            or not isinstance(item["normalize_embeddings"], bool)
        ):
            raise ValueError("invalid semantic encoding profile")
        ids.add(item["model_id"])
    return raw


def model_encoding_profile(model_id: str, path: Path | None = None) -> ModelEncodingProfile:
    """Return encoding behavior only from the committed registry, never remote model code."""

    registry = load_model_registry(path)
    for item in registry["models"]:
        if item["model_id"] == model_id:
            return ModelEncodingProfile(
                model_id=item["model_id"],
                model_family=item["model_family"],
                query_prefix=item["query_prefix"],
                document_prefix=item["document_prefix"],
                normalize_embeddings=item["normalize_embeddings"],
            )
    raise ValueError(f"semantic model is not present in trusted registry: {model_id}")
