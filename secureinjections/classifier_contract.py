"""Lightweight optional-classifier contracts used by the deterministic scanner.

The Community runtime does not ship a trained classifier or a training pipeline. These types
keep the inspectable extension boundary available without importing a scientific ML stack.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .models import Decision, RiskEvidence, ScanContext


class ClassifierArtifactError(ValueError):
    """A local model artifact is missing, malformed, unsafe, or fails integrity checks."""


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
    """Legacy sanitized-evidence classifier extension boundary."""

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
    """In-memory optional classifier interface used by :class:`Scanner`."""

    @property
    def thresholds(self) -> ClassifierThresholds: ...

    def classify(self, text: str, context: ScanContext) -> IntentClassifierResult: ...
