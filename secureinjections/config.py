"""Scanner configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .profiles import PROFILES


@dataclass(frozen=True, slots=True)
class CustomPattern:
    id: str
    name: str
    pattern: str
    category: str = "custom"
    severity: str = "medium"
    description: str = "User-defined suspicious text pattern"


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    profile: str = "general"
    review_threshold: int = 30
    block_threshold: int = 70
    semantic_threshold: int = 45
    semantic_enabled: bool = False
    semantic_scan_all: bool = False
    classifier_enabled: bool = False
    classifier_model_path: Path | None = None
    classifier_weights_sha256: str | None = None
    classifier_routing: str = "all_except_strongly_benign"
    semantic_similarity_threshold: float = 0.68
    semantic_use_index_calibration: bool = True
    semantic_top_k: int = 3
    semantic_model_path: Path | None = None
    semantic_model_id: str | None = None
    semantic_index_path: Path | None = None
    max_input_length: int = 1_000_000
    max_decode_candidates: int = 8
    max_decoded_length: int = 32_768
    rule_paths: tuple[Path, ...] = ()
    custom_patterns: tuple[CustomPattern, ...] = ()
    disabled_rule_ids: frozenset[str] = field(default_factory=frozenset)
    feed_version: str | None = None
    rules_version: str = "bundled-v1"

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise ValueError(f"unknown scanner profile: {self.profile}")
        if not 0 <= self.review_threshold < self.block_threshold <= 100:
            raise ValueError("thresholds must satisfy 0 <= review < block <= 100")
        if not 0 <= self.semantic_threshold <= 100:
            raise ValueError("semantic_threshold must be between 0 and 100")
        if not 0.0 <= self.semantic_similarity_threshold <= 1.0:
            raise ValueError("semantic_similarity_threshold must be between 0 and 1")
        if not isinstance(self.semantic_use_index_calibration, bool):
            raise ValueError("semantic_use_index_calibration must be boolean")
        if self.semantic_top_k < 1:
            raise ValueError("semantic_top_k must be positive")
        if (self.semantic_model_path is None) != (self.semantic_index_path is None):
            raise ValueError(
                "semantic_model_path and semantic_index_path must be configured together"
            )
        if self.semantic_model_id is not None and self.semantic_model_path is None:
            raise ValueError("semantic_model_id requires semantic_model_path")
        if self.classifier_weights_sha256 is not None:
            if self.classifier_model_path is None:
                raise ValueError("classifier_weights_sha256 requires classifier_model_path")
            if len(self.classifier_weights_sha256) != 64:
                raise ValueError("classifier_weights_sha256 must be a SHA-256 hex digest")
            try:
                int(self.classifier_weights_sha256, 16)
            except ValueError as exc:
                raise ValueError("classifier_weights_sha256 must be a SHA-256 hex digest") from exc
        if self.classifier_routing not in {
            "all",
            "deterministic_nontrivial",
            "all_except_strongly_benign",
            "ambiguous",
        }:
            raise ValueError("unknown classifier routing policy")
        if self.max_input_length < 1:
            raise ValueError("max_input_length must be positive")
