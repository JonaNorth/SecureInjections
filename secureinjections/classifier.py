"""Optional, local-only intent classification.

The legacy ``AmbiguityClassifier`` contract is retained for v0.3 compatibility.  The v0.4
``IntentClassifier`` contract receives text only in memory and returns calibrated binary and
family-level evidence.  No implementation in this module downloads, logs, or persists input.
"""

from __future__ import annotations

import hashlib
import json
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .models import Decision, RiskEvidence, ScanContext


# Kept source-compatible with the v0.3 experimental API.
@dataclass(frozen=True, slots=True)
class ClassifierInput:
    provisional_decision: Decision
    risk_score: int
    evidence: tuple[RiskEvidence, ...]
    categories: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClassifierResult:
    decision: Decision
    confidence: float
    explanation: str


class AmbiguityClassifier(ABC):
    """Legacy sanitized-evidence classifier boundary."""

    @abstractmethod
    def classify(self, evidence: ClassifierInput) -> ClassifierResult:
        raise NotImplementedError


class IntentLabel(StrEnum):
    BENIGN_GENERAL = "BENIGN_GENERAL"
    BENIGN_SECURITY_DISCUSSION = "BENIGN_SECURITY_DISCUSSION"
    BENIGN_DEVELOPER_CONTENT = "BENIGN_DEVELOPER_CONTENT"
    BENIGN_QUOTED_ATTACK = "BENIGN_QUOTED_ATTACK"
    ATTACK_DIRECT_INJECTION = "ATTACK_DIRECT_INJECTION"
    ATTACK_INDIRECT_INJECTION = "ATTACK_INDIRECT_INJECTION"
    ATTACK_TOOL_EXECUTION = "ATTACK_TOOL_EXECUTION"
    ATTACK_CREDENTIAL_ACCESS = "ATTACK_CREDENTIAL_ACCESS"
    ATTACK_EXFILTRATION = "ATTACK_EXFILTRATION"
    ATTACK_CROSS_AGENT = "ATTACK_CROSS_AGENT"
    ATTACK_PERSISTENCE = "ATTACK_PERSISTENCE"
    ATTACK_PATH_ACCESS = "ATTACK_PATH_ACCESS"
    ATTACK_METADATA_ACCESS = "ATTACK_METADATA_ACCESS"
    ATTACK_SUPPLY_CHAIN = "ATTACK_SUPPLY_CHAIN"
    AMBIGUOUS = "AMBIGUOUS"


BENIGN_LABELS = frozenset(label for label in IntentLabel if label.name.startswith("BENIGN_"))
ATTACK_LABELS = frozenset(label for label in IntentLabel if label.name.startswith("ATTACK_"))
REQUIRED_LABELS = frozenset(IntentLabel)
CLASSIFIER_METADATA_SCHEMA_VERSION = 1
SAFE_WEIGHT_FILENAMES = frozenset({"model.safetensors"})
UNSAFE_MODEL_SUFFIXES = frozenset({".bin", ".pt", ".pth", ".pkl", ".pickle", ".joblib"})


class ClassifierArtifactError(ValueError):
    """A local model artifact is missing, malformed, unsafe, or fails integrity checks."""


@dataclass(frozen=True, slots=True)
class ClassifierThresholds:
    allow_max: float
    block_min: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.allow_max < self.block_min <= 1.0:
            raise ClassifierArtifactError(
                "classifier thresholds must satisfy 0 <= allow_max < block_min <= 1"
            )


@dataclass(frozen=True, slots=True)
class IntentClassifierResult:
    malicious_probability: float
    benign_probability: float
    predicted_family: IntentLabel
    confidence: float
    uncertain: bool
    inference_duration_ms: float | None = None

    def __post_init__(self) -> None:
        for name in ("malicious_probability", "benign_probability", "confidence"):
            value = getattr(self, name)
            if not isinstance(value, int | float) or isinstance(value, bool) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.malicious_probability + self.benign_probability > 1.000001:
            raise ValueError("malicious and benign probability mass cannot exceed 1")
        if not isinstance(self.predicted_family, IntentLabel):
            raise TypeError("predicted_family must be an IntentLabel")

    def to_dict(self) -> dict[str, object]:
        return {
            "malicious_probability": round(self.malicious_probability, 6),
            "benign_probability": round(self.benign_probability, 6),
            "predicted_family": self.predicted_family.value,
            "confidence": round(self.confidence, 6),
            "uncertain": self.uncertain,
            **(
                {"inference_duration_ms": round(self.inference_duration_ms, 3)}
                if self.inference_duration_ms is not None
                else {}
            ),
        }


class IntentClassifier(Protocol):
    """In-memory local classifier interface used by :class:`Scanner`."""

    @property
    def thresholds(self) -> ClassifierThresholds: ...

    def classify(self, text: str, context: ScanContext) -> IntentClassifierResult: ...


@dataclass(frozen=True, slots=True)
class ClassifierMetadata:
    classifier_version: str
    base_model: str
    base_model_sha256: str
    weights_sha256: str
    labels: tuple[IntentLabel, ...]
    thresholds: ClassifierThresholds
    temperature: float
    max_length: int
    languages: tuple[str, ...]
    training_corpus_sha256: str
    license: str

    @classmethod
    def load(cls, model_path: Path) -> ClassifierMetadata:
        metadata_path = model_path / "classifier.json"
        if metadata_path.is_symlink() or not metadata_path.is_file():
            raise ClassifierArtifactError("classifier.json is missing or unsafe")
        if metadata_path.stat().st_size > 1_000_000:
            raise ClassifierArtifactError("classifier.json is oversized")
        try:
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ClassifierArtifactError("classifier.json is not valid UTF-8 JSON") from exc
        required = {
            "schema_version",
            "classifier_version",
            "base_model",
            "base_model_sha256",
            "weights_sha256",
            "labels",
            "thresholds",
            "temperature",
            "max_length",
            "languages",
            "training_corpus_sha256",
            "license",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise ClassifierArtifactError("classifier metadata fields are invalid")
        if raw["schema_version"] != CLASSIFIER_METADATA_SCHEMA_VERSION:
            raise ClassifierArtifactError("unsupported classifier metadata schema")
        string_fields = ("classifier_version", "base_model", "license")
        if any(not isinstance(raw[name], str) or not raw[name].strip() for name in string_fields):
            raise ClassifierArtifactError("classifier metadata strings are invalid")
        for name in ("base_model_sha256", "weights_sha256", "training_corpus_sha256"):
            value = raw[name]
            if not isinstance(value, str) or len(value) != 64:
                raise ClassifierArtifactError(f"{name} must be a SHA-256 hex digest")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ClassifierArtifactError(f"{name} must be a SHA-256 hex digest") from exc
        if not isinstance(raw["labels"], list) or len(set(raw["labels"])) != len(raw["labels"]):
            raise ClassifierArtifactError("classifier labels must be a unique list")
        try:
            labels = tuple(IntentLabel(value) for value in raw["labels"])
        except (TypeError, ValueError) as exc:
            raise ClassifierArtifactError("classifier labels contain an unknown value") from exc
        if frozenset(labels) != REQUIRED_LABELS:
            raise ClassifierArtifactError(
                "classifier artifact must contain the complete v0.4 taxonomy"
            )
        threshold_raw = raw["thresholds"]
        if not isinstance(threshold_raw, dict) or set(threshold_raw) != {"allow_max", "block_min"}:
            raise ClassifierArtifactError("classifier thresholds are malformed")
        try:
            thresholds = ClassifierThresholds(
                float(threshold_raw["allow_max"]), float(threshold_raw["block_min"])
            )
            temperature = float(raw["temperature"])
        except (TypeError, ValueError) as exc:
            raise ClassifierArtifactError("classifier calibration values are invalid") from exc
        if not math.isfinite(temperature) or temperature <= 0:
            raise ClassifierArtifactError("classifier temperature must be finite and positive")
        max_length = raw["max_length"]
        if (
            not isinstance(max_length, int)
            or isinstance(max_length, bool)
            or not 8 <= max_length <= 8192
        ):
            raise ClassifierArtifactError("classifier max_length is invalid")
        languages = raw["languages"]
        if (
            not isinstance(languages, list)
            or not languages
            or not all(isinstance(value, str) and value for value in languages)
        ):
            raise ClassifierArtifactError("classifier languages are invalid")
        return cls(
            classifier_version=raw["classifier_version"],
            base_model=raw["base_model"],
            base_model_sha256=raw["base_model_sha256"],
            weights_sha256=raw["weights_sha256"],
            labels=labels,
            thresholds=thresholds,
            temperature=temperature,
            max_length=max_length,
            languages=tuple(languages),
            training_corpus_sha256=raw["training_corpus_sha256"],
            license=raw["license"],
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_classifier_artifact(
    model_path: Path, expected_weights_sha256: str | None = None
) -> ClassifierMetadata:
    """Validate a local artifact without importing an ML runtime or executing model code."""
    try:
        resolved = model_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ClassifierArtifactError("classifier model path does not exist locally") from exc
    if model_path.is_symlink() or not resolved.is_dir():
        raise ClassifierArtifactError("classifier model path must be a real local directory")
    symlinks = tuple(item for item in resolved.rglob("*") if item.is_symlink())
    if symlinks:
        raise ClassifierArtifactError(
            f"classifier artifact symlink is forbidden: {symlinks[0].name}"
        )
    unsafe = tuple(
        item
        for item in resolved.rglob("*")
        if item.is_file() and item.suffix.lower() in UNSAFE_MODEL_SUFFIXES
    )
    if unsafe:
        raise ClassifierArtifactError(
            f"unsafe serialized model file is forbidden: {unsafe[0].name}"
        )
    weights = resolved / "model.safetensors"
    if weights.is_symlink() or not weights.is_file():
        raise ClassifierArtifactError("model.safetensors is required")
    metadata = ClassifierMetadata.load(resolved)
    actual_hash = sha256_file(weights)
    if actual_hash != metadata.weights_sha256:
        raise ClassifierArtifactError("classifier weights hash mismatch")
    if expected_weights_sha256 is not None and actual_hash != expected_weights_sha256:
        raise ClassifierArtifactError(
            "classifier weights do not match the administratively pinned hash"
        )
    return metadata


class TransformersIntentClassifier:
    """A local Hugging Face sequence-classification artifact loaded with safe defaults.

    Construction is the only loading point.  ``classify`` does no file or network I/O and retains
    neither input text nor hidden states after returning the small result object.
    """

    def __init__(self, model_path: Path, *, expected_weights_sha256: str | None = None) -> None:
        self._path = model_path.expanduser().resolve(strict=True)
        self.metadata = validate_classifier_artifact(self._path, expected_weights_sha256)
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - depends on optional installation
            raise RuntimeError(
                "local classifier runtime is unavailable; install secureinjections[classifier]"
            ) from exc
        # These flags prohibit hub fallback and repository-supplied Python code.
        self._tokenizer = AutoTokenizer.from_pretrained(
            str(self._path), local_files_only=True, trust_remote_code=False
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            str(self._path),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        self._model.eval()
        self._torch = torch
        configured = getattr(self._model.config, "id2label", {})
        actual_labels = tuple(
            IntentLabel(configured.get(index, configured.get(str(index), label.value)))
            for index, label in enumerate(self.metadata.labels)
        )
        if actual_labels != self.metadata.labels:
            raise ClassifierArtifactError("model label order does not match classifier metadata")

    @property
    def thresholds(self) -> ClassifierThresholds:
        return self.metadata.thresholds

    def classify(self, text: str, context: ScanContext) -> IntentClassifierResult:
        del context  # Metadata only; never serialized or injected into the text.
        import time

        started = time.perf_counter_ns()
        encoded = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self.metadata.max_length,
        )
        with self._torch.inference_mode():
            logits = self._model(**encoded).logits[0] / self.metadata.temperature
            probabilities = self._torch.softmax(logits, dim=-1).detach().cpu().tolist()
        indexed = dict(
            zip(self.metadata.labels, (float(value) for value in probabilities), strict=True)
        )
        predicted = max(indexed, key=indexed.__getitem__)
        malicious = sum(indexed.get(label, 0.0) for label in ATTACK_LABELS)
        benign = sum(indexed.get(label, 0.0) for label in BENIGN_LABELS)
        confidence = indexed[predicted]
        uncertain = (
            predicted is IntentLabel.AMBIGUOUS
            or self.thresholds.allow_max < malicious < self.thresholds.block_min
        )
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        # Explicitly drop tensor-bearing locals before returning. No raw text enters the result.
        del encoded, logits, probabilities, indexed
        return IntentClassifierResult(
            malicious_probability=malicious,
            benign_probability=benign,
            predicted_family=predicted,
            confidence=confidence,
            uncertain=uncertain,
            inference_duration_ms=elapsed,
        )
