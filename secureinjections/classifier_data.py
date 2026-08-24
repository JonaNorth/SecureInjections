"""Leakage-resistant corpus models, audits, gates, and statistics.

The v0.4.1 schema distinguishes machine-derived metadata from reviewed evidence.  Merely assigning
a group identifier never promotes a row to trusted training data.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from .classifier import ATTACK_LABELS, BENIGN_LABELS, IntentLabel

CLASSIFIER_CORPUS_SCHEMA_VERSION = 2
CLASSIFIER_SPLITS = ("train", "validation", "development_holdout")
ALL_CLASSIFIER_SPLITS = (*CLASSIFIER_SPLITS, "development_shadow", "candidate_pool", "quarantine")
SUPPORTED_LANGUAGES = ("en", "da", "de", "fr", "es", "sv", "no", "nl", "it", "pt", "pl")
AUTHORSHIP_VALUES = frozenset({"human-authored", "generated", "mixed", "unknown"})
DIFFICULTIES = frozenset({"medium", "hard", "adversarial", "unknown"})
_TOKEN = re.compile(r"\w+", re.UNICODE)
_SYNTHETIC_MARKER = re.compile(
    r"\[(?:synthetic|benign)-case:[^\]]+\]|request_id\s*=\s*synthetic[-\w]*",
    re.IGNORECASE,
)


class ClassifierCorpusError(ValueError):
    pass


class ReviewStatus(StrEnum):
    VERIFIED = "VERIFIED"
    REVIEWED = "REVIEWED"
    PROVISIONAL = "PROVISIONAL"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


TRUSTED_REVIEW_STATES = frozenset({ReviewStatus.VERIFIED, ReviewStatus.REVIEWED})


class BinaryLabel(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    AMBIGUOUS = "ambiguous"


def binary_label_for_family(label: IntentLabel) -> BinaryLabel:
    if label in ATTACK_LABELS:
        return BinaryLabel.MALICIOUS
    if label in BENIGN_LABELS:
        return BinaryLabel.BENIGN
    return BinaryLabel.AMBIGUOUS


@dataclass(frozen=True, slots=True)
class ClassifierCase:
    # Legacy Python attribute names remain source-compatible. Serialized v0.4.1 rows use the
    # explicit case_id/classifier_family names requested by the dataset contract.
    id: str
    text: str
    label: IntentLabel
    language: str
    attack_family: str
    concept_id: str
    template_family: str
    paraphrase_group: str
    source_family: str
    source: str
    license: str
    generation_method: str
    authorship: str
    split: str | None = None
    binary_label: BinaryLabel | None = None
    provenance_reference: str | None = None
    review_status: ReviewStatus = ReviewStatus.PROVISIONAL
    difficulty: str = "unknown"
    hard_negative_category: str | None = None
    translation_group: str | None = None
    parent_case_id: str | None = None
    derived_concept_candidate: str | None = None
    review_id: str | None = None
    review_record_hash: str | None = None
    original_content_hash: str | None = None
    original_metadata_hash: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.text or len(self.text) > 1_000_000:
            raise ClassifierCorpusError("case id and bounded non-empty text are required")
        if self.language not in SUPPORTED_LANGUAGES:
            raise ClassifierCorpusError(f"unsupported language: {self.language}")
        if self.authorship not in AUTHORSHIP_VALUES:
            raise ClassifierCorpusError(f"invalid authorship: {self.authorship}")
        if self.difficulty not in DIFFICULTIES:
            raise ClassifierCorpusError(f"invalid difficulty: {self.difficulty}")
        if self.split is not None and self.split not in ALL_CLASSIFIER_SPLITS:
            raise ClassifierCorpusError(f"invalid split: {self.split}")
        if not isinstance(self.review_status, ReviewStatus):
            raise ClassifierCorpusError("review_status must be a ReviewStatus")
        expected = binary_label_for_family(self.label)
        if self.binary_label is not None and self.binary_label is not expected:
            raise ClassifierCorpusError("binary_label conflicts with classifier_family")

    @property
    def case_id(self) -> str:
        return self.id

    @property
    def classifier_family(self) -> IntentLabel:
        return self.label

    @property
    def effective_binary_label(self) -> BinaryLabel:
        return self.binary_label or binary_label_for_family(self.label)

    @property
    def license_or_usage_basis(self) -> str | None:
        return self.license or None

    @property
    def trusted(self) -> bool:
        return self.review_status in TRUSTED_REVIEW_STATES

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": CLASSIFIER_CORPUS_SCHEMA_VERSION,
            "case_id": self.id,
            "text": self.text,
            "binary_label": self.effective_binary_label.value,
            "classifier_family": self.label.value,
            "language": self.language,
            "attack_family": self.attack_family,
            "concept_id": self.concept_id or None,
            "template_family": self.template_family or None,
            "paraphrase_group": self.paraphrase_group or None,
            "source_family": self.source_family or None,
            "generation_method": self.generation_method or "unknown",
            "authorship": self.authorship,
            "provenance_reference": self.provenance_reference,
            "license_or_usage_basis": self.license_or_usage_basis,
            "review_status": self.review_status.value,
            "split": self.split,
            "difficulty": self.difficulty,
            "hard_negative_category": self.hard_negative_category,
            "translation_group": self.translation_group,
            "parent_case_id": self.parent_case_id,
        }
        if self.derived_concept_candidate is not None:
            value["derived_concept_candidate"] = self.derived_concept_candidate
        for name in (
            "review_id",
            "review_record_hash",
            "original_content_hash",
            "original_metadata_hash",
        ):
            if (field_value := getattr(self, name)) is not None:
                value[name] = field_value
        return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def corpus_hash(cases: Iterable[ClassifierCase]) -> str:
    canonical = b"".join(
        (
            json.dumps(case.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        for case in sorted(cases, key=lambda item: item.id)
    )
    return _sha256_bytes(canonical)


def _nullable_string(raw: dict[str, Any], name: str, location: str) -> str | None:
    value = raw[name]
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ClassifierCorpusError(f"{location}: {name} must be a non-empty string or null")
    return value


def load_classifier_corpus(path: Path) -> tuple[ClassifierCase, ...]:
    files = sorted(path.rglob("*.jsonl")) if path.is_dir() else [path]
    if not files:
        raise ClassifierCorpusError("no classifier JSONL files found")
    cases: list[ClassifierCase] = []
    ids: set[str] = set()
    required = {
        "schema_version",
        "case_id",
        "text",
        "binary_label",
        "classifier_family",
        "language",
        "attack_family",
        "concept_id",
        "template_family",
        "paraphrase_group",
        "source_family",
        "generation_method",
        "authorship",
        "provenance_reference",
        "license_or_usage_basis",
        "review_status",
        "split",
        "difficulty",
        "hard_negative_category",
        "translation_group",
        "parent_case_id",
    }
    optional = {
        "derived_concept_candidate",
        "review_id",
        "review_record_hash",
        "original_content_hash",
        "original_metadata_hash",
    }
    for file in files:
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 64 * 1024 * 1024:
            raise ClassifierCorpusError(f"unsafe or oversized classifier corpus: {file}")
        for line_number, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            location = f"{file}:{line_number}"
            try:
                raw: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ClassifierCorpusError(f"{location}: invalid JSON") from exc
            if not isinstance(raw, dict) or required - set(raw) or set(raw) - required - optional:
                raise ClassifierCorpusError(f"{location}: invalid classifier fields")
            if raw["schema_version"] != CLASSIFIER_CORPUS_SCHEMA_VERSION:
                raise ClassifierCorpusError(f"{location}: unsupported classifier schema")
            case_id = raw["case_id"]
            if not isinstance(case_id, str) or not case_id or case_id in ids:
                raise ClassifierCorpusError(f"{location}: invalid or duplicate case_id")
            text = raw["text"]
            if not isinstance(text, str) or not text or len(text) > 1_000_000:
                raise ClassifierCorpusError(f"{location}: invalid text")
            try:
                label = IntentLabel(raw["classifier_family"])
                binary = BinaryLabel(raw["binary_label"])
                review = ReviewStatus(raw["review_status"])
            except (TypeError, ValueError) as exc:
                raise ClassifierCorpusError(f"{location}: invalid label or review enum") from exc
            if binary is not binary_label_for_family(label):
                raise ClassifierCorpusError(f"{location}: binary and family labels conflict")
            language = raw["language"]
            if language not in SUPPORTED_LANGUAGES:
                raise ClassifierCorpusError(f"{location}: unsupported language")
            string_fields = ("attack_family", "generation_method", "authorship", "difficulty")
            if any(not isinstance(raw[name], str) or not raw[name] for name in string_fields):
                raise ClassifierCorpusError(f"{location}: invalid metadata string")
            if raw["authorship"] not in AUTHORSHIP_VALUES or raw["difficulty"] not in DIFFICULTIES:
                raise ClassifierCorpusError(f"{location}: invalid authorship or difficulty")
            split = raw["split"]
            if split is not None and split not in ALL_CLASSIFIER_SPLITS:
                raise ClassifierCorpusError(f"{location}: invalid split")
            nullable = {
                name: _nullable_string(raw, name, location)
                for name in (
                    "concept_id",
                    "template_family",
                    "paraphrase_group",
                    "source_family",
                    "provenance_reference",
                    "license_or_usage_basis",
                    "hard_negative_category",
                    "translation_group",
                    "parent_case_id",
                )
            }
            derived = raw.get("derived_concept_candidate")
            if derived is not None and (not isinstance(derived, str) or not derived):
                raise ClassifierCorpusError(f"{location}: invalid derived_concept_candidate")
            review_metadata = {
                name: raw.get(name)
                for name in (
                    "review_id",
                    "review_record_hash",
                    "original_content_hash",
                    "original_metadata_hash",
                )
            }
            if any(
                value is not None and (not isinstance(value, str) or not value)
                for value in review_metadata.values()
            ):
                raise ClassifierCorpusError(f"{location}: invalid review integrity metadata")
            ids.add(case_id)
            cases.append(
                ClassifierCase(
                    id=case_id,
                    text=text,
                    label=label,
                    binary_label=binary,
                    language=language,
                    attack_family=raw["attack_family"],
                    concept_id=nullable["concept_id"] or "",
                    template_family=nullable["template_family"] or "",
                    paraphrase_group=nullable["paraphrase_group"] or "",
                    source_family=nullable["source_family"] or "",
                    source=nullable["provenance_reference"] or "unknown",
                    license=nullable["license_or_usage_basis"] or "",
                    generation_method=raw["generation_method"],
                    authorship=raw["authorship"],
                    split=split,
                    provenance_reference=nullable["provenance_reference"],
                    review_status=review,
                    difficulty=raw["difficulty"],
                    hard_negative_category=nullable["hard_negative_category"],
                    translation_group=nullable["translation_group"],
                    parent_case_id=nullable["parent_case_id"],
                    derived_concept_candidate=derived,
                    review_id=review_metadata["review_id"],
                    review_record_hash=review_metadata["review_record_hash"],
                    original_content_hash=review_metadata["original_content_hash"],
                    original_metadata_hash=review_metadata["original_metadata_hash"],
                )
            )
    if not cases:
        raise ClassifierCorpusError("classifier corpus is empty")
    return tuple(cases)


class _Groups:
    def __init__(self, ids: Iterable[str]) -> None:
        self.parent = {value: value for value in ids}

    def find(self, value: str) -> str:
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            value, self.parent[value] = self.parent[value], root
        return root

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _trusted_group_metadata(case: ClassifierCase) -> bool:
    return bool(case.concept_id and case.paraphrase_group and case.source_family)


def conceptual_groups(cases: Iterable[ClassifierCase]) -> dict[str, tuple[ClassifierCase, ...]]:
    """Union concept, template, paraphrase, translation, and direct generation lineage."""
    materialized = tuple(cases)
    groups = _Groups(case.id for case in materialized)
    indexes: tuple[dict[str, str], ...] = ({}, {}, {}, {})
    for case in materialized:
        for value, index in zip(
            (
                case.concept_id,
                case.template_family,
                case.paraphrase_group,
                case.translation_group,
            ),
            indexes,
            strict=True,
        ):
            if not value:
                continue
            if value in index:
                groups.union(case.id, index[value])
            else:
                index[value] = case.id
    known_ids = {case.id for case in materialized}
    for case in materialized:
        if case.parent_case_id in known_ids:
            groups.union(case.id, case.parent_case_id)
    collected: dict[str, list[ClassifierCase]] = defaultdict(list)
    for case in materialized:
        collected[groups.find(case.id)].append(case)
    return {
        min(item.id for item in values): tuple(sorted(values, key=lambda item: item.id))
        for values in collected.values()
    }


def grouped_split(
    cases: Iterable[ClassifierCase],
    *,
    seed: int = 42,
    ratios: tuple[float, float, float] = (0.70, 0.15, 0.15),
) -> tuple[ClassifierCase, ...]:
    materialized = tuple(cases)
    incomplete = [
        case.id for case in materialized if case.trusted and not _trusted_group_metadata(case)
    ]
    if incomplete:
        raise ClassifierCorpusError(
            f"trusted rows lack required grouping metadata: {', '.join(incomplete[:5])}"
        )
    if len(ratios) != 3 or any(value <= 0 for value in ratios) or not math.isclose(sum(ratios), 1):
        raise ValueError("split ratios must contain three positive values summing to one")
    groups = conceptual_groups(materialized)
    assignments: dict[str, str] = {}
    boundaries = (ratios[0], ratios[0] + ratios[1])
    for group_id in groups:
        digest = hashlib.sha256(f"{seed}:{group_id}".encode()).digest()
        value = int.from_bytes(digest[:8], "big") / 2**64
        assignments[group_id] = (
            "train"
            if value < boundaries[0]
            else "validation"
            if value < boundaries[1]
            else "development_holdout"
        )
    output = tuple(
        replace(case, split=assignments[group_id])
        for group_id, members in groups.items()
        for case in members
    )
    validate_group_isolation(output)
    return tuple(sorted(output, key=lambda item: item.id))


def _field_overlap(cases: Iterable[ClassifierCase], field: str) -> list[dict[str, object]]:
    seen: dict[str, set[str]] = defaultdict(set)
    members: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        value = getattr(case, field)
        if not value or case.split is None:
            continue
        seen[value].add(case.split)
        members[value].append(case.id)
    return [
        {"value": value, "splits": sorted(seen[value]), "case_ids": sorted(members[value])}
        for value in sorted(seen)
        if len(seen[value]) > 1
    ]


def generation_lineage_overlap(cases: Iterable[ClassifierCase]) -> list[dict[str, object]]:
    materialized = tuple(cases)
    by_id = {case.id: case for case in materialized}
    overlaps: list[dict[str, object]] = []
    for child in materialized:
        parent = by_id.get(child.parent_case_id or "")
        if parent and child.split != parent.split:
            overlaps.append(
                {
                    "parent_case_id": parent.id,
                    "child_case_id": child.id,
                    "parent_split": parent.split,
                    "child_split": child.split,
                }
            )
    return overlaps


def validate_group_isolation(cases: Iterable[ClassifierCase]) -> None:
    materialized = tuple(cases)
    if any(case.split is None for case in materialized):
        raise ClassifierCorpusError("all classifier cases must have a split")
    for field in ("concept_id", "template_family", "paraphrase_group", "translation_group"):
        overlap = _field_overlap(materialized, field)
        if overlap:
            raise ClassifierCorpusError(f"{field} {overlap[0]['value']!r} crosses dataset splits")
    lineage = generation_lineage_overlap(materialized)
    if lineage:
        raise ClassifierCorpusError("parent/child generation lineage crosses dataset splits")


def normalized_text(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(_TOKEN.findall(value))


def structural_text(text: str) -> str:
    """Remove known non-semantic synthetic identifiers before normalizing."""
    return normalized_text(_SYNTHETIC_MARKER.sub(" ", text))


def _ngrams(value: str, size: int = 4) -> frozenset[str]:
    padded = f"  {value}  "
    return frozenset(
        padded[index : index + size] for index in range(max(1, len(padded) - size + 1))
    )


def _duplicate_pairs(cases: tuple[ClassifierCase, ...], key: Any) -> list[dict[str, object]]:
    groups: dict[str, list[ClassifierCase]] = defaultdict(list)
    for case in cases:
        groups[key(case)].append(case)
    return [
        {
            "left": left.id,
            "right": right.id,
            "cross_split": left.split != right.split,
            "conflicting_labels": left.effective_binary_label is not right.effective_binary_label,
        }
        for values in groups.values()
        if len(values) > 1
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    ]


def duplicate_audit(
    cases: Iterable[ClassifierCase],
    *,
    similarity_threshold: float = 0.86,
    max_near_comparisons: int = 2_000_000,
) -> dict[str, object]:
    """Run bounded offline duplicate, structural, grouping, and label-conflict checks."""
    materialized = tuple(cases)
    exact = _duplicate_pairs(materialized, lambda case: case.text)
    normalized = _duplicate_pairs(materialized, lambda case: normalized_text(case.text))
    structural = _duplicate_pairs(materialized, lambda case: structural_text(case.text))
    grams = {case.id: _ngrams(normalized_text(case.text)) for case in materialized}
    token_index: dict[str, list[int]] = defaultdict(list)
    for index, case in enumerate(materialized):
        for token in set(normalized_text(case.text).split()):
            token_index[token].append(index)
    candidate_pairs: set[tuple[int, int]] = set()
    truncated = False
    for indexes in token_index.values():
        for position, left_position in enumerate(indexes):
            for right_position in indexes[position + 1 :]:
                candidate_pairs.add(
                    (
                        min(left_position, right_position),
                        max(left_position, right_position),
                    )
                )
                if len(candidate_pairs) >= max_near_comparisons:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
    near: list[dict[str, object]] = []
    exact_ids = {(item["left"], item["right"]) for item in exact}
    normalized_ids = {(item["left"], item["right"]) for item in normalized}
    for left_index, right_index in sorted(candidate_pairs):
        left, right = materialized[left_index], materialized[right_index]
        if (left.id, right.id) in exact_ids or (left.id, right.id) in normalized_ids:
            continue
        union = grams[left.id] | grams[right.id]
        similarity = len(grams[left.id] & grams[right.id]) / len(union) if union else 1.0
        if similarity >= similarity_threshold:
            near.append(
                {
                    "left": left.id,
                    "right": right.id,
                    "similarity": round(similarity, 6),
                    "cross_split": left.split != right.split,
                    "conflicting_labels": (
                        left.effective_binary_label is not right.effective_binary_label
                    ),
                }
            )
    overlaps = {
        field: _field_overlap(materialized, field)
        for field in (
            "concept_id",
            "template_family",
            "paraphrase_group",
            "translation_group",
            "source_family",
        )
    }
    lineage = generation_lineage_overlap(materialized)
    suspicious = [case.id for case in materialized if _SYNTHETIC_MARKER.search(case.text)]
    metadata_missing = {
        case.id: [
            field
            for field in (
                "concept_id",
                "template_family",
                "paraphrase_group",
                "source_family",
                "provenance_reference",
                "license_or_usage_basis",
            )
            if not getattr(case, field)
        ]
        for case in materialized
        if any(
            not getattr(case, field)
            for field in (
                "concept_id",
                "template_family",
                "paraphrase_group",
                "source_family",
                "provenance_reference",
                "license_or_usage_basis",
            )
        )
    }
    equivalent = (*exact, *normalized, *structural)
    conflicting = [item for item in (*equivalent, *near) if item["conflicting_labels"]]
    cross_split = [
        {**item, "kind": kind}
        for kind, items in (
            ("exact", exact),
            ("normalized", normalized),
            ("structural", structural),
            ("near", near),
        )
        for item in items
        if item["cross_split"]
    ]
    blocking_group_overlap = any(
        overlaps[field]
        for field in ("concept_id", "template_family", "paraphrase_group", "translation_group")
    )
    return {
        "samples": len(materialized),
        "similarity_threshold": similarity_threshold,
        "near_comparisons": len(candidate_pairs),
        "near_comparison_limit": max_near_comparisons,
        "near_comparison_truncated": truncated,
        "exact_duplicates": exact,
        "normalized_duplicates": normalized,
        "structural_duplicates": structural,
        "near_duplicate_candidates": near,
        "group_overlap": overlaps,
        "generation_lineage_overlap": lineage,
        "conflicting_equivalent_labels": conflicting,
        "suspicious_synthetic_markers": suspicious,
        "metadata_missing": metadata_missing,
        "cross_split_leakage": cross_split,
        "passed": not (
            cross_split or blocking_group_overlap or lineage or conflicting or metadata_missing
        ),
    }


def shadow_independence_audit(cases: Iterable[ClassifierCase]) -> dict[str, object]:
    materialized = tuple(cases)
    development = tuple(case for case in materialized if case.split != "development_shadow")
    shadow = tuple(case for case in materialized if case.split == "development_shadow")
    overlaps: dict[str, list[str]] = {}
    for field in (
        "concept_id",
        "template_family",
        "paraphrase_group",
        "translation_group",
        "source_family",
    ):
        dev_values = {getattr(case, field) for case in development if getattr(case, field)}
        shadow_values = {getattr(case, field) for case in shadow if getattr(case, field)}
        overlaps[field] = sorted(dev_values & shadow_values)
    development_ids = {case.id for case in development}
    shadow_ids = {case.id for case in shadow}
    lineage = [
        case.id
        for case in materialized
        if case.parent_case_id
        and (
            (case.id in development_ids and case.parent_case_id in shadow_ids)
            or (case.id in shadow_ids and case.parent_case_id in development_ids)
        )
    ]
    forbidden = any(
        overlaps[field]
        for field in ("concept_id", "template_family", "paraphrase_group", "translation_group")
    ) or bool(lineage)
    return {
        "development_rows": len(development),
        "shadow_rows": len(shadow),
        "overlap": overlaps,
        "generation_lineage_overlap": lineage,
        "passed": bool(shadow) and not forbidden,
    }


def corpus_readiness(cases: Iterable[ClassifierCase]) -> dict[str, object]:
    materialized = tuple(cases)
    audit = duplicate_audit(materialized)
    shadow = shadow_independence_audit(materialized)
    trusted = tuple(case for case in materialized if case.trusted)
    reasons: list[str] = []
    if not trusted:
        reasons.append("no VERIFIED or REVIEWED classifier rows")
    incomplete = [case.id for case in trusted if not _trusted_group_metadata(case)]
    if incomplete:
        reasons.append("trusted rows have incomplete grouping metadata")
    if any(not case.provenance_reference or not case.license_or_usage_basis for case in trusted):
        reasons.append("trusted rows have incomplete provenance or usage basis")
    if any(
        not case.review_id
        or not case.review_record_hash
        or not case.original_content_hash
        or not case.original_metadata_hash
        for case in trusted
    ):
        reasons.append("trusted rows lack hash-bound human review provenance")
    if any(case.split not in (*CLASSIFIER_SPLITS, "development_shadow") for case in trusted):
        reasons.append("trusted rows are not assigned to an allowed evaluation split")
    if not audit["passed"]:
        reasons.append("leakage audit failed")
    if not shadow["passed"]:
        reasons.append("development shadow is absent or not independent")
    hard_negatives = [case for case in trusted if case.hard_negative_category]
    if not hard_negatives:
        reasons.append("no trusted hard-negative cases")
    represented_languages = {case.language for case in trusted}
    if represented_languages != set(SUPPORTED_LANGUAGES):
        reasons.append("trusted data does not cover all supported languages")
    language_cells = {
        language: {
            "malicious_concepts": len(
                {
                    case.concept_id
                    for case in trusted
                    if case.language == language
                    and case.effective_binary_label is BinaryLabel.MALICIOUS
                }
            ),
            "benign_concepts": len(
                {
                    case.concept_id
                    for case in trusted
                    if case.language == language
                    and case.effective_binary_label is BinaryLabel.BENIGN
                }
            ),
        }
        for language in SUPPORTED_LANGUAGES
    }
    if any(
        cell["malicious_concepts"] < 10 or cell["benign_concepts"] < 10
        for cell in language_cells.values()
    ):
        reasons.append("one or more language/label cells have fewer than 10 trusted concepts")
    missing_parents = [
        case.id
        for case in trusted
        if case.parent_case_id and case.parent_case_id not in {item.id for item in materialized}
    ]
    if missing_parents:
        reasons.append("trusted generation lineage references missing parent cases")
    translations_without_groups = [
        case.id
        for case in trusted
        if "translat" in case.generation_method.casefold() and not case.translation_group
    ]
    if translations_without_groups:
        reasons.append("trusted translated cases lack translation groups")
    return {
        "status": "READY FOR LOCAL MODEL BAKE-OFF"
        if not reasons
        else "NOT READY FOR LOCAL MODEL BAKE-OFF",
        "trusted_rows": len(trusted),
        "provisional_or_quarantined_rows": len(materialized) - len(trusted),
        "leakage_gate": "PASS" if audit["passed"] else "FAIL",
        "shadow_gate": "PASS" if shadow["passed"] else "FAIL",
        "language_cells": language_cells,
        "reasons": reasons,
    }


def split_report(cases: Iterable[ClassifierCase]) -> dict[str, object]:
    materialized = tuple(cases)
    report: dict[str, object] = {}
    groups = conceptual_groups(materialized)
    group_for = {case.id: group_id for group_id, values in groups.items() for case in values}
    for split in ALL_CLASSIFIER_SPLITS:
        selected = tuple(case for case in materialized if case.split == split)
        if not selected:
            continue
        binary_counts = Counter(case.effective_binary_label.value for case in selected)
        provenance_complete = sum(
            bool(case.provenance_reference and case.license_or_usage_basis) for case in selected
        )
        report[split] = {
            "total_rows": len(selected),
            "malicious": binary_counts[BinaryLabel.MALICIOUS.value],
            "benign": binary_counts[BinaryLabel.BENIGN.value],
            "ambiguous": binary_counts[BinaryLabel.AMBIGUOUS.value],
            "unique_concepts": len({case.concept_id for case in selected if case.concept_id}),
            "unique_templates": len(
                {case.template_family for case in selected if case.template_family}
            ),
            "unique_paraphrase_groups": len(
                {case.paraphrase_group for case in selected if case.paraphrase_group}
            ),
            "unique_translation_groups": len(
                {case.translation_group for case in selected if case.translation_group}
            ),
            "transitive_groups": len({group_for[case.id] for case in selected}),
            "attack_families": dict(
                sorted(Counter(case.attack_family for case in selected).items())
            ),
            "languages": dict(sorted(Counter(case.language for case in selected).items())),
            "classifier_families": dict(
                sorted(Counter(case.label.value for case in selected).items())
            ),
            "difficulty": dict(sorted(Counter(case.difficulty for case in selected).items())),
            "source_families": dict(
                sorted(Counter(case.source_family or "unknown" for case in selected).items())
            ),
            "generation_methods": dict(
                sorted(Counter(case.generation_method for case in selected).items())
            ),
            "review_states": dict(
                sorted(Counter(case.review_status.value for case in selected).items())
            ),
            "provenance_complete": provenance_complete,
            "unknown_provenance": len(selected) - provenance_complete,
            "class_balance": {
                key: {"count": value, "denominator": len(selected)}
                for key, value in sorted(binary_counts.items())
            },
        }
    return report


def class_weights(cases: Iterable[ClassifierCase]) -> dict[IntentLabel, float]:
    counts = Counter(case.label for case in cases)
    if not counts:
        raise ClassifierCorpusError("cannot weight an empty classifier corpus")
    total = sum(counts.values())
    return {label: total / (len(counts) * count) for label, count in counts.items()}


def language_sampling_weights(cases: Iterable[ClassifierCase]) -> dict[str, float]:
    materialized = tuple(cases)
    counts = Counter(case.language for case in materialized)
    if not counts:
        raise ClassifierCorpusError("cannot balance an empty classifier corpus")
    total = len(materialized)
    return {language: total / (len(counts) * count) for language, count in counts.items()}


def write_classifier_corpus(cases: Iterable[ClassifierCase], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = "".join(
        json.dumps(case.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
        for case in sorted(cases, key=lambda item: item.id)
    )
    path.write_text(rendered, encoding="utf-8")
