"""Offline, research-only active-learning support for human review.

This module deliberately keeps human gold, pseudo labels, and unresolved pool data in distinct
states.  Bootstrap selection can run without a model; model scores and pseudo labels are only
materialized when genuine local classifier evidence exists.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .classifier_data import (
    CLASSIFIER_CORPUS_SCHEMA_VERSION,
    SUPPORTED_LANGUAGES,
    BinaryLabel,
    ClassifierCase,
    conceptual_groups,
    corpus_hash,
    duplicate_audit,
    load_classifier_corpus,
    split_report,
    validate_group_isolation,
)
from .review_workflow import (
    REVIEW_SCHEMA_VERSION,
    REVIEW_WORKFLOW_VERSION,
    ReviewDecision,
    ReviewDecisionKind,
    active_review_decisions,
    canonical_sha256,
    load_review_export,
    load_review_history,
)

ACTIVE_LEARNING_SCHEMA_VERSION = 1
ACTIVE_LEARNING_VERSION = "bootstrap-concept-diversity-v1"
MIN_RESEARCH_CONCEPTS_PER_CLASS = 4
_SHA256_LENGTH = 64
_PRIORITY_LANGUAGES = ("da", "sv")
_OFFLINE_ENVIRONMENT = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_DATASETS_OFFLINE": "1",
    "WANDB_MODE": "offline",
    "TOKENIZERS_PARALLELISM": "false",
}


class ActiveLearningError(ValueError):
    """An active-learning input or artifact violates the local research contract."""


class DataTrustState(StrEnum):
    TRUSTED_GOLD = "TRUSTED_GOLD"
    PSEUDO_LABELED = "PSEUDO_LABELED"
    PROVISIONAL = "PROVISIONAL"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True, slots=True)
class PseudoLabelRecord:
    """Untrusted model output that can never impersonate human review evidence."""

    case_id: str
    model_id: str
    model_sha256: str
    classifier_version: str
    predicted_label: BinaryLabel
    malicious_probability: float
    confidence: float
    threshold_config: dict[str, float]
    timestamp: str
    source_corpus_sha256: str
    concept_id: str | None
    paraphrase_group: str | None
    translation_group: str | None
    language: str
    family_candidate: str | None

    def __post_init__(self) -> None:
        for name in ("case_id", "model_id", "classifier_version", "timestamp"):
            if not getattr(self, name).strip():
                raise ActiveLearningError(f"{name} is required")
        for name in ("model_sha256", "source_corpus_sha256"):
            value = getattr(self, name)
            if len(value) != _SHA256_LENGTH:
                raise ActiveLearningError(f"{name} must be a SHA-256 digest")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ActiveLearningError(f"{name} must be a SHA-256 digest") from exc
        if self.predicted_label is BinaryLabel.AMBIGUOUS:
            raise ActiveLearningError("pseudo labels must use a binary model prediction")
        for name in ("malicious_probability", "confidence"):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ActiveLearningError(f"{name} must be between zero and one")
        if self.language not in SUPPORTED_LANGUAGES:
            raise ActiveLearningError("pseudo label language is unsupported")
        if not self.threshold_config or any(
            not isinstance(value, int | float) or not math.isfinite(float(value))
            for value in self.threshold_config.values()
        ):
            raise ActiveLearningError("pseudo label threshold configuration is invalid")
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ActiveLearningError("pseudo label timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise ActiveLearningError("pseudo label timestamp must include a timezone")

    @property
    def trust_state(self) -> DataTrustState:
        return DataTrustState.PSEUDO_LABELED

    @property
    def trusted(self) -> bool:
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
            "case_id": self.case_id,
            "trust_state": self.trust_state.value,
            "trusted": False,
            "pseudo_label_status": "PSEUDO_LABELED / UNTRUSTED",
            "model_id": self.model_id,
            "model_sha256": self.model_sha256,
            "classifier_version": self.classifier_version,
            "predicted_label": self.predicted_label.value,
            "malicious_probability": round(self.malicious_probability, 6),
            "confidence": round(self.confidence, 6),
            "threshold_config": dict(sorted(self.threshold_config.items())),
            "timestamp": self.timestamp,
            "source_corpus_sha256": self.source_corpus_sha256,
            "concept_id": self.concept_id,
            "paraphrase_group": self.paraphrase_group,
            "translation_group": self.translation_group,
            "language": self.language,
            "family_candidate": self.family_candidate,
        }


@dataclass(frozen=True, slots=True)
class ActiveLearningScore:
    """Comparable local score for a case when a real classifier result exists."""

    case_id: str
    malicious_probability: float
    allow_max: float
    block_min: float
    deterministic_decision: str
    deterministic_severity: int
    concept_id: str | None
    paraphrase_group: str | None
    translation_group: str | None
    language: str
    family_candidate: str | None
    hard_negative_candidate: bool
    cluster_size: int
    cluster_inconsistent: bool = False

    def __post_init__(self) -> None:
        if not self.case_id or self.language not in SUPPORTED_LANGUAGES:
            raise ActiveLearningError("active-learning score identity is invalid")
        if not 0 <= self.malicious_probability <= 1:
            raise ActiveLearningError("malicious probability must be between zero and one")
        if not 0 <= self.allow_max < self.block_min <= 1:
            raise ActiveLearningError("classifier thresholds are invalid")
        if self.deterministic_decision not in {"allow", "review", "block"}:
            raise ActiveLearningError("deterministic decision is invalid")
        if not 0 <= self.deterministic_severity <= 100 or self.cluster_size < 1:
            raise ActiveLearningError("deterministic severity or cluster size is invalid")

    @property
    def predicted_label(self) -> BinaryLabel:
        return BinaryLabel.MALICIOUS if self.malicious_probability >= 0.5 else BinaryLabel.BENIGN

    @property
    def confidence(self) -> float:
        return max(self.malicious_probability, 1 - self.malicious_probability)

    @property
    def entropy(self) -> float:
        probability = self.malicious_probability
        if probability in {0.0, 1.0}:
            return 0.0
        return -(
            probability * math.log2(probability) + (1 - probability) * math.log2(1 - probability)
        )

    @property
    def margin(self) -> float:
        return abs((2 * self.malicious_probability) - 1)

    @property
    def abstention(self) -> bool:
        return self.allow_max < self.malicious_probability < self.block_min

    @property
    def deterministic_disagreement(self) -> bool:
        return (
            self.deterministic_decision == "block" and self.predicted_label is BinaryLabel.BENIGN
        ) or (
            self.deterministic_decision == "allow" and self.predicted_label is BinaryLabel.MALICIOUS
        )

    @property
    def priority_score(self) -> float:
        score = self.entropy * 45
        score += 20 if self.abstention else 0
        score += 30 if self.deterministic_disagreement else 0
        score += 20 if self.cluster_inconsistent else 0
        score += 12 if self.hard_negative_candidate else 0
        score += 12 if self.language in _PRIORITY_LANGUAGES else 5 if self.language != "en" else 0
        return round(score, 6)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
            "case_id": self.case_id,
            "trust_state": DataTrustState.PROVISIONAL.value,
            "classifier_probability": round(self.malicious_probability, 6),
            "classifier_confidence": round(self.confidence, 6),
            "entropy": round(self.entropy, 6),
            "margin": round(self.margin, 6),
            "predicted_label": self.predicted_label.value,
            "abstention": self.abstention,
            "deterministic_decision": self.deterministic_decision,
            "deterministic_severity": self.deterministic_severity,
            "deterministic_disagreement": self.deterministic_disagreement,
            "concept_id": self.concept_id,
            "paraphrase_group": self.paraphrase_group,
            "translation_group": self.translation_group,
            "language": self.language,
            "family_candidate": self.family_candidate,
            "hard_negative_candidate": self.hard_negative_candidate,
            "cluster_size": self.cluster_size,
            "cluster_inconsistent": self.cluster_inconsistent,
            "priority_score": self.priority_score,
        }


def mark_cluster_inconsistency(
    scores: tuple[ActiveLearningScore, ...],
) -> tuple[ActiveLearningScore, ...]:
    """Flag cross-language/group prediction conflicts without majority-vote relabeling."""
    labels_by_group: dict[str, set[BinaryLabel]] = {}
    for score in scores:
        group = score.translation_group or score.concept_id
        if group:
            labels_by_group.setdefault(group, set()).add(score.predicted_label)
    inconsistent = {group for group, labels in labels_by_group.items() if len(labels) > 1}
    return tuple(
        replace(
            score,
            cluster_inconsistent=(
                score.cluster_inconsistent
                or (score.translation_group or score.concept_id) in inconsistent
            ),
        )
        for score in scores
    )


def enforce_offline_environment() -> dict[str, str]:
    """Force common ML libraries into local-only mode for this process."""
    for name, value in _OFFLINE_ENVIRONMENT.items():
        os.environ[name] = value
    return dict(_OFFLINE_ENVIRONMENT)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ActiveLearningError(f"refusing to overwrite symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise ActiveLearningError(f"temporary output already exists: {temporary}")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json(path: Path, value: object) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, values: list[dict[str, object]]) -> None:
    if not values:
        raise ActiveLearningError("refusing to create a meaningless empty JSONL artifact")
    rendered = "".join(
        json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n" for value in values
    )
    _write_text(path, rendered)


def _case_language(case: dict[str, Any]) -> str:
    metadata = case.get("legacy_metadata")
    value = metadata.get("language") if isinstance(metadata, dict) else None
    return value if isinstance(value, str) else "unknown"


def _unit_summary(unit: dict[str, Any]) -> dict[str, Any]:
    value = unit.get("pilot_summary")
    return value if isinstance(value, dict) else {}


def _unit_label(unit: dict[str, Any]) -> str:
    labels = _unit_summary(unit).get("provisional_binary_labels")
    if isinstance(labels, list) and len(labels) == 1 and labels[0] in {"benign", "malicious"}:
        return str(labels[0])
    return "ambiguous"


def _unit_family(unit: dict[str, Any]) -> str:
    families = _unit_summary(unit).get("candidate_families")
    if isinstance(families, list) and families and isinstance(families[0], str):
        return families[0]
    return "unknown"


def _unit_languages(unit: dict[str, Any]) -> tuple[str, ...]:
    languages = _unit_summary(unit).get("languages")
    if isinstance(languages, list):
        return tuple(sorted(value for value in languages if isinstance(value, str)))
    cases = unit.get("cases")
    if not isinstance(cases, list):
        return ()
    return tuple(sorted({_case_language(case) for case in cases if isinstance(case, dict)}))


def _bootstrap_priority(unit: dict[str, Any]) -> tuple[int, list[str]]:
    summary = _unit_summary(unit)
    label = _unit_label(unit)
    family = _unit_family(unit)
    languages = _unit_languages(unit)
    hard_categories = summary.get("hard_negative_categories")
    hard_negative = isinstance(hard_categories, list) and bool(hard_categories)
    cluster_size = summary.get("rows")
    rows = cluster_size if isinstance(cluster_size, int) else 1
    score = 100 if label == "malicious" else 85 if hard_negative else 35
    reasons = [
        (
            "malicious family acquisition"
            if label == "malicious"
            else "benign hard-negative acquisition"
        )
    ]
    if len(languages) > 1:
        score += 45
        reasons.append("multilingual concept coverage")
    if "da" in languages:
        score += 25
        reasons.append("Danish priority evidence")
    if "sv" in languages:
        score += 25
        reasons.append("Swedish priority evidence")
    topic_tokens = (
        "indirect",
        "agent",
        "override",
        "policy",
        "credential",
        "secret",
        "metadata",
        "tool",
        "log",
        "package",
        "supply",
        "path",
        "traversal",
        "ambiguous",
    )
    matched = sorted({token for token in topic_tokens if token in family.casefold()})
    if matched:
        score += min(30, len(matched) * 10)
        reasons.append("priority threat context: " + ", ".join(matched))
    if hard_negative:
        score += 35
        reasons.append("hard-negative classifier boundary")
    if rows > 20:
        score -= min(60, (rows - 20) // 2)
        reasons.append("large cluster represented by bounded cases")
    return score, reasons


def _representative_cases(
    unit: dict[str, Any], preferred_languages: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    raw_cases = unit.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ActiveLearningError("review pool unit contains no cases")
    cases = [case for case in raw_cases if isinstance(case, dict)]
    if len(cases) != len(raw_cases):
        raise ActiveLearningError("review pool contains a malformed case")
    ordered = sorted(cases, key=lambda case: str(case.get("case_id", "")))
    chosen: list[tuple[dict[str, Any], str]] = []

    def add_for_language(language: str, role: str) -> None:
        candidate = next((case for case in ordered if _case_language(case) == language), None)
        if candidate is not None and all(candidate is not value for value, _role in chosen):
            chosen.append((candidate, role))

    for language in preferred_languages:
        role = (
            "priority_language_representative"
            if language in _PRIORITY_LANGUAGES
            else "language_coverage_representative"
        )
        add_for_language(language, role)
    if not preferred_languages:
        add_for_language("en", "primary_representative")
        for language in _PRIORITY_LANGUAGES:
            add_for_language(language, "priority_language_representative")
    if not chosen:
        chosen.append((ordered[0], "primary_representative"))
    if len({_case_language(case) for case in ordered}) > 1 and len(chosen) == 1:
        non_english = next(
            (case for case in ordered if _case_language(case) != _case_language(chosen[0][0])),
            None,
        )
        if non_english is not None:
            chosen.append((non_english, "non_english_representative"))
    result = []
    for case, role in chosen[:3]:
        copied = copy.deepcopy(case)
        copied["active_learning_review_role"] = role
        copied["active_learning_outlier_status"] = "NOT_AVAILABLE_NO_MODEL"
        result.append(copied)
    return result


def _choose_diverse(
    candidates: list[dict[str, Any]],
    quota: int,
    *,
    validation_priority_labels: frozenset[str] = frozenset(),
    seed: int = 42,
) -> list[dict[str, Any]]:
    def validation_priority(unit: dict[str, Any]) -> int:
        concept = _unit_summary(unit).get("candidate_concept_id")
        if not isinstance(concept, str) or _unit_label(unit) not in validation_priority_labels:
            return 0
        digest = hashlib.sha256(f"research:{seed}:{concept}".encode()).digest()
        value = int.from_bytes(digest[:8], "big") / 2**64
        return 1 if value < 0.25 else 0

    ordered = sorted(
        candidates,
        key=lambda unit: (
            -validation_priority(unit),
            -_bootstrap_priority(unit)[0],
            str(unit.get("review_item_id", "")),
        ),
    )
    chosen: list[dict[str, Any]] = []
    seen_families: set[str] = set()
    multilingual = [unit for unit in ordered if len(_unit_languages(unit)) > 1]
    for unit in multilingual[: min(2, quota)]:
        chosen.append(unit)
        seen_families.add(_unit_family(unit))
    for unit in ordered:
        if unit in chosen:
            continue
        family = _unit_family(unit)
        if family in seen_families:
            continue
        chosen.append(unit)
        seen_families.add(family)
        if len(chosen) == quota:
            return chosen
    for unit in ordered:
        if unit not in chosen:
            chosen.append(unit)
        if len(chosen) == quota:
            break
    return chosen


def _gold_manifest(cases: tuple[ClassifierCase, ...], path: Path) -> dict[str, object]:
    trusted = tuple(case for case in cases if case.trusted)
    if len(trusted) != len(cases):
        raise ActiveLearningError("gold corpus contains a non-human-trusted row")
    labels = Counter(case.effective_binary_label.value for case in trusted)
    concept_labels: dict[str, set[str]] = {}
    for case in trusted:
        concept_labels.setdefault(case.concept_id, set()).add(case.effective_binary_label.value)
    concepts_by_label = Counter(
        next(iter(values)) for values in concept_labels.values() if len(values) == 1
    )
    audit = duplicate_audit(trusted)
    return {
        "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
        "trust_state": DataTrustState.TRUSTED_GOLD.value,
        "source_path": path.resolve().as_posix(),
        "source_file_sha256": _sha256_file(path),
        "corpus_sha256": corpus_hash(trusted),
        "rows": len(trusted),
        "concepts": len({case.concept_id for case in trusted}),
        "malicious": labels[BinaryLabel.MALICIOUS.value],
        "benign": labels[BinaryLabel.BENIGN.value],
        "ambiguous": labels[BinaryLabel.AMBIGUOUS.value],
        "concepts_by_binary_label": dict(sorted(concepts_by_label.items())),
        "mixed_label_concepts": {
            concept: sorted(values)
            for concept, values in sorted(concept_labels.items())
            if len(values) > 1
        },
        "languages": sorted({case.language for case in trusted}),
        "language_counts": dict(sorted(Counter(case.language for case in trusted).items())),
        "classifier_families": sorted({case.label.value for case in trusted}),
        "classifier_family_counts": dict(
            sorted(Counter(case.label.value for case in trusted).items())
        ),
        "candidate_families": sorted({case.attack_family for case in trusted}),
        "hard_negative_rows": sum(case.hard_negative_category is not None for case in trusted),
        "hard_negative_concepts": len(
            {case.concept_id for case in trusted if case.hard_negative_category}
        ),
        "review_ids": sorted({case.review_id for case in trusted if case.review_id}),
        "leakage_audit": audit,
    }


def research_grouped_split_analysis(
    cases: tuple[ClassifierCase, ...],
    *,
    seed: int = 42,
    validation_ratio: float = 0.25,
    minimum_validation_concepts_per_class: int | None = None,
) -> dict[str, object]:
    """Analyze a deterministic research-only two-way group split without writing a corpus."""
    if not 0 < validation_ratio < 1:
        raise ActiveLearningError("validation ratio must be between zero and one")
    if minimum_validation_concepts_per_class is not None and (
        minimum_validation_concepts_per_class < 1
    ):
        raise ActiveLearningError("minimum validation concepts per class must be positive")
    groups = conceptual_groups(cases)
    assignments: dict[str, str] = {}
    if minimum_validation_concepts_per_class is None:
        for group_id in groups:
            digest = hashlib.sha256(f"research:{seed}:{group_id}".encode()).digest()
            value = int.from_bytes(digest[:8], "big") / 2**64
            assignments[group_id] = "validation" if value < validation_ratio else "train"
        strategy = "deterministic-concept-union-two-way-v1"
        meaningful_minimum = 4
    else:
        by_label: dict[BinaryLabel, list[tuple[str, tuple[ClassifierCase, ...]]]] = {
            BinaryLabel.MALICIOUS: [],
            BinaryLabel.BENIGN: [],
        }
        for group_id, members in groups.items():
            labels = {case.effective_binary_label for case in members}
            if len(labels) != 1 or BinaryLabel.AMBIGUOUS in labels:
                raise ActiveLearningError(
                    f"conceptual group {group_id} has mixed or ambiguous binary labels"
                )
            label = next(iter(labels))
            by_label[label].append((group_id, members))
        for label, label_groups in by_label.items():
            total_concepts = len(
                {case.concept_id for _group_id, members in label_groups for case in members}
            )
            minimum_train = minimum_validation_concepts_per_class
            if total_concepts < minimum_validation_concepts_per_class + minimum_train:
                raise ActiveLearningError(
                    f"{label.value} lacks enough concepts for balanced grouped validation"
                )
            target = max(
                math.ceil(total_concepts * validation_ratio),
                minimum_validation_concepts_per_class,
            )
            target = min(target, total_concepts - minimum_train)
            ordered = sorted(
                label_groups,
                key=lambda item: (
                    hashlib.sha256(f"research-balanced:{seed}:{item[0]}".encode()).digest(),
                    item[0],
                ),
            )
            selected_concepts = 0
            for group_id, members in ordered:
                use_validation = selected_concepts < target
                assignments[group_id] = "validation" if use_validation else "train"
                if use_validation:
                    selected_concepts += len({case.concept_id for case in members})
        strategy = "deterministic-class-balanced-concept-union-two-way-v2"
        meaningful_minimum = minimum_validation_concepts_per_class
    assigned = tuple(
        replace(case, split=assignments[group_id])
        for group_id, members in groups.items()
        for case in members
    )
    validate_group_isolation(assigned)
    leakage = duplicate_audit(assigned)
    by_split: dict[str, dict[str, int]] = {}
    for split in ("train", "validation"):
        selected = tuple(case for case in assigned if case.split == split)
        concepts_by_label = {
            label.value: len(
                {
                    case.concept_id
                    for case in selected
                    if case.effective_binary_label is label and case.concept_id
                }
            )
            for label in (BinaryLabel.MALICIOUS, BinaryLabel.BENIGN)
        }
        rows_by_label = Counter(case.effective_binary_label.value for case in selected)
        by_split[split] = {
            "rows": len(selected),
            "concepts": len({case.concept_id for case in selected}),
            "malicious_rows": rows_by_label[BinaryLabel.MALICIOUS.value],
            "benign_rows": rows_by_label[BinaryLabel.BENIGN.value],
            "malicious_concepts": concepts_by_label[BinaryLabel.MALICIOUS.value],
            "benign_concepts": concepts_by_label[BinaryLabel.BENIGN.value],
        }
    structurally_possible = bool(
        leakage["passed"]
        and all(
            by_split[split][f"{label}_concepts"] > 0
            for split in ("train", "validation")
            for label in ("malicious", "benign")
        )
    )
    statistically_meaningful = bool(
        structurally_possible
        and all(
            by_split["validation"][f"{label}_concepts"] >= meaningful_minimum
            for label in ("malicious", "benign")
        )
    )
    return {
        "seed": seed,
        "strategy": strategy,
        "validation_ratio": validation_ratio,
        "split_hash": canonical_sha256(assignments),
        "assignments": dict(sorted(assignments.items())),
        "sizes": by_split,
        "structurally_possible": structurally_possible,
        "statistically_meaningful": statistically_meaningful,
        "minimum_validation_concepts_per_class_for_meaningful_metrics": meaningful_minimum,
        "leakage_passed": leakage["passed"],
        "split_report": split_report(assigned),
    }


def _training_eligibility(
    cases: tuple[ClassifierCase, ...], *, seed: int = 42
) -> dict[str, object]:
    concepts_by_label = {
        label.value: len(
            {
                case.concept_id
                for case in cases
                if case.effective_binary_label is label and case.concept_id
            }
        )
        for label in (BinaryLabel.MALICIOUS, BinaryLabel.BENIGN)
    }
    reasons = []
    for label in (BinaryLabel.MALICIOUS, BinaryLabel.BENIGN):
        if concepts_by_label[label.value] < MIN_RESEARCH_CONCEPTS_PER_CLASS:
            reasons.append(
                f"{label.value} has fewer than {MIN_RESEARCH_CONCEPTS_PER_CLASS} "
                "independent concepts"
            )
    leakage_passed = bool(duplicate_audit(cases)["passed"])
    if not leakage_passed:
        reasons.append("trusted-gold leakage audit failed")
    grouped = research_grouped_split_analysis(cases, seed=seed)
    if not grouped["structurally_possible"]:
        reasons.append("deterministic grouped train/validation lacks both classes in each split")
    if not grouped["statistically_meaningful"]:
        reasons.append("grouped validation is too small for statistically meaningful metrics")
    return {
        "eligible": not reasons,
        "structurally_possible": bool(
            leakage_passed
            and grouped["structurally_possible"]
            and all(
                concepts_by_label[label.value] >= MIN_RESEARCH_CONCEPTS_PER_CLASS
                for label in (BinaryLabel.MALICIOUS, BinaryLabel.BENIGN)
            )
        ),
        "statistically_meaningful": grouped["statistically_meaningful"],
        "minimum_independent_concepts_per_class": MIN_RESEARCH_CONCEPTS_PER_CLASS,
        "concepts_by_label": concepts_by_label,
        "grouped_validation_available": grouped["structurally_possible"],
        "grouped_split": grouped,
        "reasons": reasons,
    }


def _local_model_state(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ActiveLearningError("local model inventory is missing, unsafe, or oversized")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ActiveLearningError("local model inventory is invalid") from exc
    if not isinstance(value, dict):
        raise ActiveLearningError("local model inventory has an invalid shape")
    direct_validation = value.get("validation") == "PASS"
    if direct_validation:
        candidates = [value]
    elif isinstance(value.get("candidates"), list):
        candidates = value["candidates"]
    else:
        raise ActiveLearningError("local model inventory has an invalid shape")
    suitable = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        languages = candidate.get("local_metadata_languages", candidate.get("languages"))
        multilingual = isinstance(languages, list) and (
            "multilingual" in languages or len(set(languages)) > 1
        )
        compatible = candidate.get("compatible_with_current_training_pipeline") is True or (
            candidate.get("classification") == "compatible-multilingual"
            and candidate.get("secureinjections_offline_loadable") is True
        )
        if multilingual and compatible:
            suitable.append(candidate)
    return {
        "inspection_source": path.resolve().as_posix(),
        "inspection_source_sha256": _sha256_file(path),
        "network_used": False,
        "candidate_count": len(candidates),
        "suitable_local_multilingual_candidates": len(suitable),
        "available": bool(suitable),
        "model_identity": (suitable[0].get("name", suitable[0].get("path")) if suitable else None),
        "status": "AVAILABLE" if suitable else "UNAVAILABLE",
        "reason": (
            "suitable compatible local multilingual candidate exists"
            if suitable
            else "no compatible local multilingual encoder/classifier was found"
        ),
    }


def _load_promotion_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ActiveLearningError("promotion manifest is missing, unsafe, or oversized")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ActiveLearningError("promotion manifest is invalid") from exc
    required = {
        "schema_version",
        "workflow_version",
        "history_sha256",
        "active_decisions",
        "trusted_rows",
        "promoted_corpus_sha256",
        "output_path",
        "review_ids",
    }
    optional = {"source_resolution"}
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or set(value) - required - optional
    ):
        raise ActiveLearningError("promotion manifest fields are incompatible")
    if value["schema_version"] != 1 or value["workflow_version"] != REVIEW_WORKFLOW_VERSION:
        raise ActiveLearningError("incompatible promotion schema or workflow version")
    resolution = value.get("source_resolution")
    if resolution is not None:
        resolution_fields = {
            "legacy_corpora",
            "review_exports",
            "resolved_cases",
            "legacy_cases",
            "export_cases",
            "identical_cross_source_cases",
        }
        if not isinstance(resolution, dict) or set(resolution) != resolution_fields:
            raise ActiveLearningError("promotion source resolution is incompatible")
        legacy_corpora = resolution["legacy_corpora"]
        review_exports = resolution["review_exports"]
        counts = (
            resolution["resolved_cases"],
            resolution["legacy_cases"],
            resolution["export_cases"],
            resolution["identical_cross_source_cases"],
        )
        if (
            not isinstance(legacy_corpora, list)
            or any(not isinstance(item, str) or not item for item in legacy_corpora)
            or not isinstance(review_exports, dict)
            or any(
                not isinstance(source, str)
                or not source
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                for source, digest in review_exports.items()
            )
            or any(not isinstance(count, int) or count < 0 for count in counts)
        ):
            raise ActiveLearningError("promotion source resolution fields are invalid")
        for source in legacy_corpora:
            if not Path(source).is_file():
                raise ActiveLearningError("promotion legacy source is missing")
        for source, digest in review_exports.items():
            source_path = Path(source)
            if not source_path.is_file() or _sha256_file(source_path) != digest:
                raise ActiveLearningError("promotion review export binding is stale")
    return value


def _assert_case_matches_active_review(
    case: ClassifierCase, decision: ReviewDecision, *, source_name: str
) -> None:
    if decision.decision is not ReviewDecisionKind.APPROVE or not decision.promotable:
        raise ActiveLearningError(f"{source_name}: active review is not promotable: {case.id}")
    expected = {
        "review_id": decision.review_id,
        "review_record_hash": canonical_sha256(decision.to_dict()),
        "original_content_hash": decision.original_content_hash,
        "original_metadata_hash": decision.original_metadata_hash,
        "binary_label": decision.approved_binary_label,
        "classifier_family": decision.approved_classifier_family,
        "language": decision.approved_language,
        "concept_id": decision.approved_concept_id,
        "paraphrase_group": decision.approved_paraphrase_group,
        "translation_group": decision.approved_translation_group,
        "template_family": decision.approved_template_family,
        "source_family": decision.approved_source_family,
        "generation_method": decision.approved_generation_method,
        "authorship": decision.approved_authorship,
        "provenance_reference": decision.provenance_reference,
        "license_or_usage_basis": decision.license_or_usage_basis,
        "hard_negative_category": decision.hard_negative_category,
        "difficulty": decision.difficulty,
    }
    actual = {
        "review_id": case.review_id,
        "review_record_hash": case.review_record_hash,
        "original_content_hash": case.original_content_hash,
        "original_metadata_hash": case.original_metadata_hash,
        "binary_label": case.effective_binary_label,
        "classifier_family": case.label,
        "language": case.language,
        "concept_id": case.concept_id,
        "paraphrase_group": case.paraphrase_group,
        "translation_group": case.translation_group,
        "template_family": case.template_family,
        "source_family": case.source_family,
        "generation_method": case.generation_method,
        "authorship": case.authorship,
        "provenance_reference": case.provenance_reference,
        "license_or_usage_basis": case.license_or_usage_basis,
        "hard_negative_category": case.hard_negative_category,
        "difficulty": case.difficulty,
    }
    conflicts = [name for name in expected if actual[name] != expected[name]]
    if conflicts:
        raise ActiveLearningError(
            f"{source_name}: trusted row conflicts with active review for {case.id}: "
            + ", ".join(conflicts)
        )
    content_hash = hashlib.sha256(case.text.encode("utf-8")).hexdigest()
    if content_hash != case.original_content_hash:
        raise ActiveLearningError(f"{source_name}: stale trusted content hash: {case.id}")


def _validate_promoted_source(
    corpus_path: Path, history_path: Path, manifest_path: Path
) -> tuple[tuple[ClassifierCase, ...], dict[str, Any]]:
    source_name = corpus_path.name
    source_hash_before = _sha256_file(corpus_path)
    history_hash_before = _sha256_file(history_path)
    manifest_hash_before = _sha256_file(manifest_path)
    manifest = _load_promotion_manifest(manifest_path)
    cases = load_classifier_corpus(corpus_path)
    history = load_review_history(history_path)
    active = active_review_decisions(history)
    if manifest["history_sha256"] != history_hash_before:
        raise ActiveLearningError(f"{source_name}: promotion manifest history hash is stale")
    if manifest["output_path"] != corpus_path.as_posix():
        raise ActiveLearningError(f"{source_name}: promotion output path binding is incompatible")
    if manifest["trusted_rows"] != len(cases) or manifest["active_decisions"] != len(active):
        raise ActiveLearningError(f"{source_name}: promotion counts are stale")
    if manifest["promoted_corpus_sha256"] != corpus_hash(cases):
        raise ActiveLearningError(f"{source_name}: promoted corpus hash is stale")
    manifest_review_ids = manifest["review_ids"]
    if not isinstance(manifest_review_ids, list) or manifest_review_ids != [
        case.review_id for case in cases
    ]:
        raise ActiveLearningError(f"{source_name}: promotion review ID list is stale")
    if len({case.id for case in cases}) != len(cases):
        raise ActiveLearningError(f"{source_name}: duplicate case IDs")
    for case in cases:
        if case.review_status.value not in {"REVIEWED", "VERIFIED"}:
            raise ActiveLearningError(f"{source_name}: non-trusted review status: {case.id}")
        decision = active.get(case.id)
        if decision is None:
            raise ActiveLearningError(f"{source_name}: no active review for trusted row: {case.id}")
        _assert_case_matches_active_review(case, decision, source_name=source_name)
    if set(active) != {case.id for case in cases}:
        raise ActiveLearningError(f"{source_name}: active review/corpus case set mismatch")
    if _sha256_file(corpus_path) != source_hash_before:
        raise ActiveLearningError(f"{source_name}: source corpus changed during validation")
    if _sha256_file(history_path) != history_hash_before:
        raise ActiveLearningError(f"{source_name}: history changed during validation")
    if _sha256_file(manifest_path) != manifest_hash_before:
        raise ActiveLearningError(f"{source_name}: manifest changed during validation")
    return cases, {
        "corpus_path": corpus_path.as_posix(),
        "corpus_file_sha256": source_hash_before,
        "corpus_semantic_sha256": corpus_hash(cases),
        "classifier_schema_version": CLASSIFIER_CORPUS_SCHEMA_VERSION,
        "history_path": history_path.as_posix(),
        "history_sha256": history_hash_before,
        "review_schema_version": REVIEW_SCHEMA_VERSION,
        "promotion_manifest_path": manifest_path.as_posix(),
        "promotion_manifest_sha256": manifest_hash_before,
        "promotion_schema_version": manifest["schema_version"],
        "workflow_version": manifest["workflow_version"],
        "trusted_rows": len(cases),
        "active_reviews": len(active),
    }


def combine_trusted_gold(
    corpus_paths: tuple[Path, ...],
    history_paths: tuple[Path, ...],
    manifest_paths: tuple[Path, ...],
    output_path: Path,
    output_manifest_path: Path,
    *,
    local_model_inventory_path: Path,
    seed: int = 42,
) -> dict[str, Any]:
    """Create an immutable-source, active-review-bound combined trusted-gold view."""
    if not corpus_paths or not (len(corpus_paths) == len(history_paths) == len(manifest_paths)):
        raise ActiveLearningError("corpus, history, and promotion manifest counts must match")
    if output_path in corpus_paths or output_manifest_path in (*corpus_paths, *manifest_paths):
        raise ActiveLearningError("combined outputs must not overwrite a source artifact")
    source_hashes_before = {
        path: _sha256_file(path) for path in (*corpus_paths, *history_paths, *manifest_paths)
    }
    sources = []
    combined_by_case: dict[str, ClassifierCase] = {}
    review_to_case: dict[str, str] = {}
    duplicate_rows_deduplicated = 0
    for corpus_path, history_path, manifest_path in zip(
        corpus_paths, history_paths, manifest_paths, strict=True
    ):
        cases, source = _validate_promoted_source(corpus_path, history_path, manifest_path)
        sources.append(source)
        for case in cases:
            assert case.review_id is not None
            existing_case_id = review_to_case.get(case.review_id)
            if existing_case_id is not None and existing_case_id != case.id:
                raise ActiveLearningError(
                    f"conflicting active review ID {case.review_id}: "
                    f"{existing_case_id} versus {case.id}"
                )
            review_to_case[case.review_id] = case.id
            previous = combined_by_case.get(case.id)
            if previous is None:
                combined_by_case[case.id] = case
                continue
            if previous.effective_binary_label is not case.effective_binary_label:
                raise ActiveLearningError(f"conflicting binary labels for case ID {case.id}")
            if previous.review_id != case.review_id:
                raise ActiveLearningError(f"conflicting active review IDs for case ID {case.id}")
            if previous.to_dict() != case.to_dict():
                raise ActiveLearningError(f"conflicting trusted metadata for case ID {case.id}")
            duplicate_rows_deduplicated += 1
    combined = tuple(sorted(combined_by_case.values(), key=lambda case: case.id))
    if not combined:
        raise ActiveLearningError("combined trusted gold is empty")
    readiness = _training_eligibility(combined, seed=seed)
    model = _local_model_state(local_model_inventory_path)
    leakage = duplicate_audit(combined)
    _write_jsonl(output_path, [case.to_dict() for case in combined])
    gold_manifest = _gold_manifest(combined, output_path)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "classifier_schema_version": CLASSIFIER_CORPUS_SCHEMA_VERSION,
        "review_schema_version": REVIEW_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "seed": seed,
        "trust_state": DataTrustState.TRUSTED_GOLD.value,
        "merge_policy": "case-id-plus-active-review-strict-v1",
        "source_files_mutated": False,
        "source_rows": sum(int(source["trusted_rows"]) for source in sources),
        "duplicate_rows_deduplicated": duplicate_rows_deduplicated,
        "trusted_rows": len(combined),
        "sources": sources,
        "combined_corpus_path": output_path.as_posix(),
        "combined_corpus_file_sha256": None,
        "combined_corpus_semantic_sha256": corpus_hash(combined),
        "review_ids": [case.review_id for case in combined],
        "gold_statistics": gold_manifest,
        "leakage_audit": leakage,
        "research_readiness": readiness,
        "local_model": model,
        "development_shadow_used": False,
        "production_model_selected": None,
        "blind_set_e_burned": False,
    }
    manifest["combined_corpus_file_sha256"] = _sha256_file(output_path)
    _write_json(output_manifest_path, manifest)
    for path, expected_hash in source_hashes_before.items():
        if _sha256_file(path) != expected_hash:
            raise ActiveLearningError(f"source artifact changed during combine: {path}")
    return manifest


def _decision_state(
    decisions_path: Path | tuple[Path, ...], history_path: Path | tuple[Path, ...]
) -> dict[str, object]:
    decision_paths = decisions_path if isinstance(decisions_path, tuple) else (decisions_path,)
    history_paths = history_path if isinstance(history_path, tuple) else (history_path,)
    decisions = tuple(decision for path in decision_paths for decision in load_review_history(path))
    history = tuple(decision for path in history_paths for decision in load_review_history(path))
    active_review_decisions(decisions)
    active_review_decisions(history)
    history_ids = {decision.review_id for decision in history}
    pending = tuple(decision for decision in decisions if decision.review_id not in history_ids)
    return {
        "decisions_paths": [path.resolve().as_posix() for path in decision_paths],
        "decisions_sha256": {
            path.resolve().as_posix(): _sha256_file(path) for path in decision_paths
        },
        "decisions": len(decisions),
        "decision_counts": dict(sorted(Counter(item.decision.value for item in decisions).items())),
        "history_paths": [path.resolve().as_posix() for path in history_paths],
        "history_sha256": {path.resolve().as_posix(): _sha256_file(path) for path in history_paths},
        "history_records": len(history),
        "history_counts": dict(sorted(Counter(item.decision.value for item in history).items())),
        "pending_import_records": len(pending),
        "pending_import_review_ids": [item.review_id for item in pending],
        "all_decided_case_ids": sorted({item.case_id for item in decisions}),
    }


def _build_batch(
    units: tuple[dict[str, Any], ...],
    gold: tuple[ClassifierCase, ...],
    decided_case_ids: set[str],
    batch_size: int,
    *,
    batch_id: str,
    malicious_units: int | None = None,
    validation_priority_labels: frozenset[str] = frozenset(),
    seed: int = 42,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    if not 8 <= batch_size <= 30:
        raise ActiveLearningError(
            "active-learning batch size must be between 8 and 30 review units"
        )
    if malicious_units is not None and not 0 <= malicious_units <= batch_size:
        raise ActiveLearningError("malicious review-unit quota is invalid")
    trusted_concepts = {case.concept_id for case in gold if case.concept_id}
    eligible = []
    source_case_ids: set[str] = set()
    for unit in units:
        summary = _unit_summary(unit)
        concept = summary.get("candidate_concept_id")
        if concept in trusted_concepts:
            continue
        cases = unit.get("cases")
        if not isinstance(cases, list):
            raise ActiveLearningError("review pool contains malformed cases")
        case_ids = {case.get("case_id") for case in cases if isinstance(case, dict)}
        if source_case_ids & case_ids:
            raise ActiveLearningError("review pool repeats case IDs across concept units")
        source_case_ids.update(value for value in case_ids if isinstance(value, str))
        if case_ids and case_ids <= decided_case_ids:
            continue
        eligible.append(unit)
    malicious_quota = (
        malicious_units if malicious_units is not None else math.ceil(batch_size * 0.55)
    )
    benign_quota = batch_size - malicious_quota
    malicious = [unit for unit in eligible if _unit_label(unit) == "malicious"]
    benign = [unit for unit in eligible if _unit_label(unit) == "benign"]
    chosen = _choose_diverse(
        malicious,
        malicious_quota,
        validation_priority_labels=validation_priority_labels,
        seed=seed,
    ) + _choose_diverse(
        benign,
        benign_quota,
        validation_priority_labels=validation_priority_labels,
        seed=seed,
    )
    if len(chosen) < batch_size:
        remaining = [unit for unit in eligible if unit not in chosen]
        chosen.extend(
            _choose_diverse(
                remaining,
                batch_size - len(chosen),
                validation_priority_labels=validation_priority_labels,
                seed=seed,
            )
        )
    if len(chosen) != batch_size:
        raise ActiveLearningError("review pool cannot satisfy the requested concept-diverse batch")
    chosen.sort(
        key=lambda unit: (-_bootstrap_priority(unit)[0], str(unit.get("review_item_id", "")))
    )
    output: list[dict[str, object]] = []
    family_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    languages: set[str] = set()
    hard_negative_units = 0
    source_cluster_rows = 0
    review_rows = 0
    review_languages: set[str] = set()
    source_languages: set[str] = set()
    trusted_languages = {case.language for case in gold}
    language_priority = ("da", "sv", "en", "de", "fr", "es", "no", "nl", "it", "pt", "pl")
    for index, unit in enumerate(chosen):
        copied = copy.deepcopy(unit)
        summary = _unit_summary(copied)
        original_rows = summary.get("rows")
        cluster_size = original_rows if isinstance(original_rows, int) else len(copied["cases"])
        unit_language_set = set(_unit_languages(copied))
        missing_languages = tuple(
            language
            for language in language_priority
            if language in unit_language_set
            and language not in trusted_languages
            and language not in review_languages
        )
        representatives = _representative_cases(copied, missing_languages[:3])
        representative_ids = [str(case["case_id"]) for case in representatives]
        score, reasons = _bootstrap_priority(copied)
        family = _unit_family(copied)
        label = _unit_label(copied)
        unit_languages = _unit_languages(copied)
        hard = summary.get("hard_negative_categories")
        hard_negative = isinstance(hard, list) and bool(hard)
        concept_candidate = summary.get("candidate_concept_id")
        if isinstance(concept_candidate, str) and label in validation_priority_labels:
            digest = hashlib.sha256(f"research:{seed}:{concept_candidate}".encode()).digest()
            if int.from_bytes(digest[:8], "big") / 2**64 < 0.25:
                score += 500
                reasons.insert(0, f"deterministic grouped-validation {label} concept gap")
        family_counts[family] += 1
        label_counts[label] += 1
        languages.update(_case_language(case) for case in representatives)
        review_languages.update(_case_language(case) for case in representatives)
        source_languages.update(unit_languages)
        hard_negative_units += int(hard_negative)
        source_cluster_rows += cluster_size
        review_rows += len(representatives)
        copied["review_unit_index"] = index
        copied["pilot_id"] = batch_id
        copied["case_ids"] = representative_ids
        copied["cases"] = representatives
        copied["priority_score"] = score
        copied["priority_reasons"] = reasons
        copied["machine_suggestion_trusted"] = False
        copied["human_decision"] = None
        copied["instruction"] = (
            "RESEARCH BOOTSTRAP / MACHINE METADATA UNTRUSTED. Review exported representatives "
            "through the hash-bound human workflow. A representative decision does not approve "
            "unexported cluster siblings."
        )
        copied_summary = copy.deepcopy(summary)
        copied_summary["source_cluster_rows"] = cluster_size
        copied_summary["rows"] = len(representatives)
        copied_summary["case_ids"] = representative_ids
        copied["pilot_summary"] = copied_summary
        copied["active_learning"] = {
            "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
            "trust_state": DataTrustState.PROVISIONAL.value,
            "selection_mode": "NO_MODEL_BOOTSTRAP",
            "why_selected": reasons,
            "bootstrap_priority_score": score,
            "uncertainty_score": None,
            "disagreement_status": "NOT_AVAILABLE_NO_MODEL",
            "cross_language_inconsistency": "NOT_AVAILABLE_NO_MODEL",
            "languages": list(unit_languages),
            "review_languages": sorted({_case_language(case) for case in representatives}),
            "family_candidate": family,
            "concept_candidate": summary.get("candidate_concept_id"),
            "cluster_size": cluster_size,
            "representative_cases": representative_ids,
            "representative_status": "BOUNDED_LANGUAGE_DIVERSE_SAMPLE",
            "outlier_status": "NOT_AVAILABLE_NO_MODEL",
            "hard_negative_candidate": hard_negative,
        }
        output.append(copied)
    manifest = {
        "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
        "active_learning_version": ACTIVE_LEARNING_VERSION,
        "batch_id": batch_id,
        "selection_mode": "NO_MODEL_BOOTSTRAP",
        "machine_suggestions_trusted": False,
        "review_units": len(output),
        "review_rows": review_rows,
        "source_pool_rows_represented": source_cluster_rows,
        "concepts": len(output),
        "provisional_label_units": dict(sorted(label_counts.items())),
        "languages": sorted(languages),
        "language_count": len(languages),
        "source_cluster_languages": sorted(source_languages),
        "source_cluster_language_count": len(source_languages),
        "combined_gold_and_batch_languages": sorted(trusted_languages | review_languages),
        "combined_gold_and_batch_language_count": len(trusted_languages | review_languages),
        "candidate_families": dict(sorted(family_counts.items())),
        "candidate_family_count": len(family_counts),
        "hard_negative_units": hard_negative_units,
        "representative_policy": {
            "maximum_cases_per_concept": 3,
            "preferred_languages": ["en", "da", "sv"],
            "outlier_selection": "unavailable without a model",
            "unreviewed_siblings_auto_approved": False,
        },
        "selection_factors": [
            "malicious family diversity",
            "benign hard-negative diversity",
            "Danish and Swedish evidence",
            "other non-English coverage",
            "priority threat contexts",
            "large-cluster redundancy penalty",
            "deterministic grouped-validation class gap",
        ],
        "validation_priority_labels": sorted(validation_priority_labels),
    }
    selected_families = set(family_counts)
    manifest["priority_context_coverage"] = {
        "indirect_injection": any("indirect" in value for value in selected_families),
        "cross_agent": any(
            "agent" in value or "persistence" in value for value in selected_families
        ),
        "override_or_policy": any(
            "override" in value or "policy" in value for value in selected_families
        ),
        "credential_or_secret": any(
            "credential" in value or "secret" in value for value in selected_families
        ),
        "metadata": any("metadata" in value for value in selected_families),
        "tool_execution": any("tool" in value for value in selected_families),
        "log_poisoning": any("log" in value for value in selected_families),
        "supply_chain": any("package" in value or "supply" in value for value in selected_families),
        "path_or_file": any("path" in value or "traversal" in value for value in selected_families),
        "ambiguous": label_counts[BinaryLabel.AMBIGUOUS.value] > 0,
    }
    manifest["eligible_concepts_ranked"] = len(eligible)
    manifest["excluded_trusted_concepts"] = len(units) - len(eligible)
    return output, manifest


def _report(state: dict[str, Any]) -> str:
    gold = state["trusted_gold"]
    model = state["research_model"]
    validation = state["validation"]
    batch = state["next_human_batch"]
    decisions = state["human_review_state"]
    eligibility = state["research_training_eligibility"]
    grouped = eligibility["grouped_split"]
    train_size = grouped["sizes"]["train"]
    validation_size = grouped["sizes"]["validation"]
    grouped_state = "available" if validation["grouped_validation_available"] else "not available"
    structural_state = "possible" if eligibility["structurally_possible"] else "not possible"
    statistical_state = (
        "statistically meaningful"
        if eligibility["statistically_meaningful"]
        else "too small for meaningful metrics"
    )
    training_state = "possible" if model["training_possible"] else "not possible"
    model_reason = str(model["reason"])
    model_reason = model_reason[:1].upper() + model_reason[1:]
    missing_priority_contexts = (
        ", ".join(
            name.replace("_", "-")
            for name, covered in batch["priority_context_coverage"].items()
            if not covered
        )
        or "none"
    )
    return f"""# SecureInjections v0.4.2 — Local Active Learning Iteration {state["iteration"]:02d}

## 1. Actual trusted gold state

The inspected decisions file contains **{decisions["decisions"]}** records and the imported
history contains **{decisions["history_records"]}**. There are
**{decisions["pending_import_records"]}** valid decision records still pending import. Only
promoted, hash-bound human decisions are counted as gold.

- Rows: {gold["rows"]}
- Independent concepts: {gold["concepts"]}
- Benign: {gold["benign"]}
- Malicious: {gold["malicious"]}
- Languages: {", ".join(gold["languages"]) or "none"}
- Classifier families: {", ".join(gold["classifier_families"]) or "none"}
- Hard-negative rows: {gold["hard_negative_rows"]}
- Hard-negative concepts: {gold["hard_negative_concepts"]}

## 2. Class balance and training decision

The gold corpus contains {gold["concepts_by_binary_label"].get("malicious", 0)} malicious and
{gold["concepts_by_binary_label"].get("benign", 0)} benign independent concepts. A leakage-safe
grouped split is structurally **{structural_state}**, but its validation evidence is
**{statistical_state}**. Training was **{training_state}** in this run because
{model["training_blocker"]}. No training was fabricated and the production readiness gate was not
weakened.

## 3. Leakage audit

The promoted-gold audit is **{"PASS" if gold["leakage_audit"]["passed"] else "FAIL"}**. Concept,
paraphrase, translation, template, and lineage groups remain isolated. The audit found
{len(gold["leakage_audit"]["cross_split_leakage"])} cross-split duplicate leaks,
{sum(len(value) for value in gold["leakage_audit"]["group_overlap"].values())} group overlaps,
{len(gold["leakage_audit"]["generation_lineage_overlap"])} lineage crossings, and
{len(gold["leakage_audit"]["conflicting_equivalent_labels"])} conflicting equivalent labels.

## 4. Language and family coverage

Trusted gold currently covers {len(gold["languages"])} of {len(SUPPORTED_LANGUAGES)} supported
languages and {len(gold["classifier_families"])} classifier families. The bootstrap batch covers
{batch["language_count"]} languages and {batch["candidate_family_count"]} provisional candidate
families; combined gold-plus-batch coverage reaches
{batch["combined_gold_and_batch_language_count"]} supported languages. Candidate metadata remains
untrusted until explicit human review.

## 5. Research model

Active-learning model: **{model["status"]}**. {model_reason}. The only locally inventoried
candidate is not a compatible multilingual research classifier. No hosted inference, model
download, Hugging Face contact, or telemetry occurred. Any future model remains research-only:
not production, not selected, not Blind-E eligible, and not a release classifier.

## 6. Grouped validation setup

Grouped validation is **{grouped_state}**.
The deterministic two-way proposal contains {train_size["rows"]} training rows across
{train_size["concepts"]} concepts and {validation_size["rows"]} validation rows across
{validation_size["concepts"]} concepts. Validation has
{validation_size["malicious_rows"]} malicious and {validation_size["benign_rows"]} benign rows,
covering {validation_size["malicious_concepts"]} malicious and
{validation_size["benign_concepts"]} benign concepts. These counts are too small for stable recall
or false-positive-rate claims. Concepts, paraphrases, translations, templates, and lineage remain
isolated. No development shadow exists; validation was not relabeled as shadow.

## 7. Active-learning ranking method

Because no valid classifier exists, no confidence or uncertainty values were invented. Bootstrap
ranking operates at concept level using provisional class balance, family diversity, hard-negative
value, Danish/Swedish and broader multilingual coverage, priority threat contexts, and a
large-cluster redundancy penalty. Each unit exports at most three language-diverse representatives.
Reviewing a representative does not promote its unreviewed siblings.

## 8. Uncertainty analysis

Unavailable: no research classifier was trained. The scores artifact was intentionally not created
rather than emitting a meaningless empty file.

## 9. Deterministic disagreement analysis

Unavailable: classifier/deterministic disagreement requires a classifier prediction. The existing
deterministic scanner remains an independent signal for the first model-backed iteration.

## 10. Multilingual inconsistency

Unavailable: cross-language prediction consistency requires model predictions. The batch uses
language-diverse representatives and does not treat English confidence as a multilingual proxy.

## 11. Pseudo labels

Generated: **0**. Trusted: **0**. Pseudo-label schema support is implemented, but no pseudo-label
file was created because there was no model evidence. Pseudo labels cannot become trusted gold
without the existing explicit hash-bound human review path.

## 12. Next review batch

- Review units: {batch["review_units"]}
- Representative cases exported: {batch["review_rows"]}
- Source-pool rows represented by those concept clusters: {batch["source_pool_rows_represented"]}
- Languages: {batch["language_count"]}
- Candidate families: {batch["candidate_family_count"]}
- Hard-negative units: {batch["hard_negative_units"]}

The batch is directly compatible with `classifier review interactive`.

## 13. Remaining blockers and next iteration

- Review the recommended {batch["review_units"]}-unit batch and promote only explicit human
  approvals.
- Grow grouped validation to at least four independent concepts per class before reporting metrics.
- Acquire a suitable, explicitly trusted local multilingual model without weakening offline policy.
- Construct an independent development shadow from unseen reviewed concepts before model selection.
- Fill current priority-context gaps: {missing_priority_contexts}.

Another **human-review bootstrap iteration is justified**. A model-backed active-learning iteration
is not yet justified. Stop and reconsider the architecture if grouped validation plateaus,
uncertainty stops shrinking, disagreement remains high, multilingual/family coverage stays
structurally weak, or pseudo-label disagreement increases.

Blind Set E was not located, searched, inspected, generated, evaluated, modified, or inferred from.
"""


def run_active_learning_bootstrap(
    gold_corpus_path: Path,
    review_pool_path: Path,
    decisions_path: Path | tuple[Path, ...],
    history_path: Path | tuple[Path, ...],
    local_model_inventory_path: Path,
    output_directory: Path,
    *,
    batch_size: int = 20,
    seed: int = 42,
    iteration: int = 1,
    malicious_units: int | None = None,
) -> dict[str, Any]:
    """Build a truthful no-model bootstrap or report model-backed eligibility."""
    if not 1 <= iteration <= 99:
        raise ActiveLearningError("active-learning iteration must be between 1 and 99")
    offline = enforce_offline_environment()
    gold = load_classifier_corpus(gold_corpus_path)
    gold_manifest = _gold_manifest(gold, gold_corpus_path)
    eligibility = _training_eligibility(gold, seed=seed)
    model_state = _local_model_state(local_model_inventory_path)
    decision_state = _decision_state(decisions_path, history_path)
    pool = load_review_export(review_pool_path)
    decided = decision_state["all_decided_case_ids"]
    assert isinstance(decided, list)
    grouped_readiness = eligibility["grouped_split"]
    assert isinstance(grouped_readiness, dict)
    grouped_sizes = grouped_readiness["sizes"]
    assert isinstance(grouped_sizes, dict)
    validation_sizes = grouped_sizes["validation"]
    assert isinstance(validation_sizes, dict)
    validation_priority_labels = frozenset(
        label for label in ("malicious", "benign") if int(validation_sizes[f"{label}_concepts"]) < 4
    )
    batch_number = f"{iteration:02d}"
    batch_id = f"v0.4.2-active-learning-batch-{batch_number}"
    batch, batch_manifest = _build_batch(
        pool,
        gold,
        set(decided),
        batch_size,
        batch_id=batch_id,
        malicious_units=malicious_units,
        validation_priority_labels=validation_priority_labels,
        seed=seed,
    )

    output_directory = output_directory.resolve()
    iteration_suffix = "" if iteration == 1 else f"-{batch_number}"
    gold_manifest_path = output_directory / f"v0.4.2-gold-corpus-manifest{iteration_suffix}.json"
    state_path = output_directory / f"v0.4.2-active-learning-state{iteration_suffix}.json"
    batch_path = output_directory / f"{batch_id}.jsonl"
    batch_manifest_path = output_directory / f"{batch_id}-manifest.json"
    run_path = output_directory / f"v0.4.2-active-learning-run{iteration_suffix}.json"
    report_name = (
        "v0.4.2-active-learning-bootstrap.md"
        if iteration == 1
        else f"v0.4.2-active-learning-iteration-{batch_number}.md"
    )
    report_path = output_directory / report_name
    scores_path = output_directory / f"v0.4.2-active-learning-scores{iteration_suffix}.jsonl"
    pseudo_path = output_directory / f"v0.4.2-pseudo-labels{iteration_suffix}.jsonl"
    if scores_path.exists() or pseudo_path.exists():
        raise ActiveLearningError(
            "stale score or pseudo-label output exists; preserve and resolve it explicitly"
        )

    _write_json(gold_manifest_path, gold_manifest)
    _write_jsonl(batch_path, batch)
    batch_manifest["source_review_pool_path"] = review_pool_path.resolve().as_posix()
    batch_manifest["source_review_pool_sha256"] = _sha256_file(review_pool_path)
    batch_manifest["batch_sha256"] = _sha256_file(batch_path)
    _write_json(batch_manifest_path, batch_manifest)

    training_possible = bool(eligibility["structurally_possible"] and model_state["available"])
    training_blocker = (
        "no compatible local multilingual model asset is available"
        if not model_state["available"]
        else "the grouped split is not structurally valid"
        if not eligibility["structurally_possible"]
        else "no blocker"
    )
    grouped = eligibility["grouped_split"]
    assert isinstance(grouped, dict)
    pool_case_ids = {
        str(case.get("case_id"))
        for unit in pool
        for case in unit.get("cases", [])
        if isinstance(case, dict) and isinstance(case.get("case_id"), str)
    }
    gold_case_ids = {case.id for case in gold}
    provisional_pool_rows = len(pool_case_ids - gold_case_ids)
    state: dict[str, Any] = {
        "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
        "workflow_version": "0.4.2",
        "active_learning_version": ACTIVE_LEARNING_VERSION,
        "iteration": iteration,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "seed": seed,
        "research_only": True,
        "production_model_selected": None,
        "development_shadow": "NOT AVAILABLE",
        "blind_set_e_burned": False,
        "offline_environment": offline,
        "human_review_state": decision_state,
        "trusted_gold": gold_manifest,
        "trust_counts": {
            DataTrustState.TRUSTED_GOLD.value: gold_manifest["rows"],
            DataTrustState.PSEUDO_LABELED.value: 0,
            DataTrustState.PROVISIONAL.value: provisional_pool_rows,
            DataTrustState.QUARANTINED.value: 0,
        },
        "research_training_eligibility": eligibility,
        "research_model": {
            **model_state,
            "training_possible": training_possible,
            "training_blocker": training_blocker,
            "trained": False,
            "identity": None,
            "research_only": True,
            "production": False,
            "selected": False,
            "blind_e_eligible": False,
            "release_classifier": False,
        },
        "validation": {
            "grouped_validation_available": eligibility["grouped_validation_available"],
            "statistically_meaningful": eligibility["statistically_meaningful"],
            "training_rows": grouped["sizes"]["train"]["rows"],
            "training_concepts": grouped["sizes"]["train"]["concepts"],
            "validation_rows": grouped["sizes"]["validation"]["rows"],
            "validation_concepts": grouped["sizes"]["validation"]["concepts"],
            "validation_malicious_rows": grouped["sizes"]["validation"]["malicious_rows"],
            "validation_benign_rows": grouped["sizes"]["validation"]["benign_rows"],
            "recall": None,
            "benign_fpr": None,
            "non_english_recall": None,
            "split_hash": grouped["split_hash"],
        },
        "active_learning": {
            "untrusted_pool_rows": provisional_pool_rows,
            "untrusted_pool_concepts": len(pool),
            "rows_scored": 0,
            "concepts_ranked_by_model": 0,
            "uncertain_cases": 0,
            "deterministic_disagreements": 0,
            "cross_language_inconsistencies": 0,
            "bootstrap_concepts_ranked": batch_manifest["eligible_concepts_ranked"],
            "scores_artifact": None,
            "scores_not_created_reason": "no valid local research model",
        },
        "pseudo_labels": {
            "generated": 0,
            "trusted": 0,
            "artifact": None,
            "not_created_reason": "no model evidence; empty artifacts are forbidden",
            "training_policy": "HUMAN GOLD ONLY",
        },
        "next_human_batch": batch_manifest,
        "status": "READY",
        "next_rational_action": (
            f"Review the {batch_size}-unit balanced batch, promote only explicit human approvals, "
            "then rerun the grouped validation audit with a suitable local multilingual model."
        ),
    }
    _write_json(state_path, state)
    run = {
        "schema_version": ACTIVE_LEARNING_SCHEMA_VERSION,
        "workflow_version": "0.4.2",
        "iteration": iteration,
        "generated_at": state["generated_at"],
        "seed": seed,
        "status": "READY",
        "outcome": (
            "B: GROUPED SPLIT UNDERPOWERED OR LOCAL MODEL UNAVAILABLE; NEXT REVIEW BATCH GENERATED"
        ),
        "network_used": False,
        "hosted_inference_used": False,
        "model_downloaded": False,
        "model_trained": False,
        "pseudo_labels_generated": 0,
        "blind_set_e_burned": False,
        "artifacts": {
            "state": state_path.as_posix(),
            "gold_manifest": gold_manifest_path.as_posix(),
            "scores": None,
            "pseudo_labels": None,
            "batch": batch_path.as_posix(),
            "batch_manifest": batch_manifest_path.as_posix(),
            "report": report_path.as_posix(),
        },
        "input_hashes": {
            "gold_corpus": _sha256_file(gold_corpus_path),
            "review_pool": _sha256_file(review_pool_path),
            "decisions": decision_state["decisions_sha256"],
            "history": decision_state["history_sha256"],
            "local_model_inventory": _sha256_file(local_model_inventory_path),
        },
        "selection_hash": canonical_sha256([unit["active_learning"] for unit in batch]),
    }
    _write_json(run_path, run)
    _write_text(report_path, _report(state))
    return state
