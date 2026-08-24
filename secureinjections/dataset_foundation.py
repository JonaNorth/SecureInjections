"""Offline v0.4.1 legacy inventory and human-review foundation builder."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .classifier_data import SUPPORTED_LANGUAGES, normalized_text, structural_text

FOUNDATION_VERSION = "0.4.1"
NORMALIZATION_VERSION = "classifier-data-v2-nfkc-casefold-structural-markers-v1"
GROUPING_VERSION = "legacy-suggestion-v1-unreviewed"
AUDIT_VERSION = "offline-ngram-jaccard-v2"
SPLIT_VERSION = "no-split-promotion-v1"


class DatasetFoundationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FoundationConfig:
    similarity_threshold: float = 0.86
    max_rows_for_exhaustive_near_audit: int = 5_000
    character_ngram_size: int = 4

    def __post_init__(self) -> None:
        if not 0 < self.similarity_threshold <= 1:
            raise ValueError("similarity_threshold must be between zero and one")
        if self.max_rows_for_exhaustive_near_audit < 1 or self.character_ngram_size < 2:
            raise ValueError("audit bounds are invalid")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _ngrams(value: str, size: int) -> frozenset[str]:
    padded = f"  {value}  "
    return frozenset(
        padded[index : index + size] for index in range(max(1, len(padded) - size + 1))
    )


def _read_legacy(paths: tuple[Path, ...]) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    ids: set[str] = set()
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise DatasetFoundationError(f"unsafe or oversized legacy corpus: {path}")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetFoundationError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise DatasetFoundationError(f"{path}:{line_number}: invalid legacy row")
            if row["id"] in ids:
                raise DatasetFoundationError(f"duplicate legacy id: {row['id']}")
            ids.add(row["id"])
            row = dict(row)
            row["_source_file"] = path.as_posix()
            rows.append(row)
    if not rows:
        raise DatasetFoundationError("legacy corpus selection is empty")
    return tuple(rows)


def _template_candidate(row: dict[str, Any]) -> str:
    return re.sub(r"-\d{2}$", "", str(row["id"]))


def _concept_candidate(row: dict[str, Any]) -> str:
    family = str(row.get("attack_family", "unknown"))
    label = str(row.get("label", "unknown"))
    if family.startswith("multilingual-") or family in {
        "credential-exfiltration-composition",
        "multilingual-security-education",
    }:
        material = f"translation-family:{label}:{family}"
    else:
        material = f"structural:{label}:{family}:{structural_text(str(row.get('text', '')))}"
    return "derived-concept-" + hashlib.sha256(material.encode()).hexdigest()[:16]


def _translation_candidate(row: dict[str, Any]) -> str | None:
    family = str(row.get("attack_family", ""))
    if family.startswith("multilingual-") or family in {
        "credential-exfiltration-composition",
        "multilingual-security-education",
    }:
        material = f"{row.get('label')}:{family}"
        return "derived-translation-" + hashlib.sha256(material.encode()).hexdigest()[:16]
    return None


def _group_cross_split(
    rows: tuple[dict[str, Any], ...], key: Any
) -> tuple[int, int, dict[str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[key(row)].append(row)
    duplicate_groups = {name: values for name, values in groups.items() if len(values) > 1}
    cross = {
        name: values
        for name, values in duplicate_groups.items()
        if len({str(item.get("split")) for item in values}) > 1
    }
    return len(duplicate_groups), len(cross), duplicate_groups


def _near_pairs(
    rows: tuple[dict[str, Any], ...], config: FoundationConfig
) -> list[dict[str, object]]:
    if len(rows) > config.max_rows_for_exhaustive_near_audit:
        raise DatasetFoundationError(
            "legacy corpus exceeds configured exhaustive near-duplicate bound"
        )
    grams = [
        _ngrams(normalized_text(str(row.get("text", ""))), config.character_ngram_size)
        for row in rows
    ]
    pairs = []
    for left_index, left_grams in enumerate(grams):
        for right_index in range(left_index + 1, len(rows)):
            right_grams = grams[right_index]
            union = left_grams | right_grams
            similarity = len(left_grams & right_grams) / len(union) if union else 1.0
            if similarity < config.similarity_threshold:
                continue
            left, right = rows[left_index], rows[right_index]
            pairs.append(
                {
                    "left": left["id"],
                    "right": right["id"],
                    "similarity": round(similarity, 6),
                    "cross_split": left.get("split") != right.get("split"),
                    "conflicting_labels": left.get("label") != right.get("label"),
                }
            )
    return pairs


def _pair_clusters(pairs: list[dict[str, object]]) -> list[list[str]]:
    """Collapse pairwise similarity edges into deterministic review clusters."""
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    for pair in pairs:
        left, right = str(pair["left"]), str(pair["right"])
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root
    clusters: dict[str, list[str]] = defaultdict(list)
    for case_id in sorted(parent):
        clusters[find(case_id)].append(case_id)
    return sorted((sorted(values) for values in clusters.values()), key=lambda values: values[0])


def _language_coverage(rows: tuple[dict[str, Any], ...]) -> dict[str, object]:
    coverage: dict[str, object] = {}
    for language in SUPPORTED_LANGUAGES:
        selected = [row for row in rows if row.get("language") == language]
        malicious = [row for row in selected if row.get("label") == "malicious"]
        benign = [row for row in selected if row.get("label") == "benign"]
        translated = [row for row in selected if _translation_candidate(row)]
        coverage[language] = {
            "legacy_rows": len(selected),
            "malicious_rows": len(malicious),
            "benign_rows": len(benign),
            "derived_malicious_concepts": len({_concept_candidate(row) for row in malicious}),
            "derived_benign_concepts": len({_concept_candidate(row) for row in benign}),
            "translation_candidate_rows": len(translated),
            "native_or_original_seed_rows": 0,
            "native_seed_status": "unknown-unreviewed",
            "trusted_rows": 0,
            "meaningful_classifier_evaluation": False,
            "flags": [
                "no trusted rows",
                "native/original authorship unknown",
                *(["fewer than 10 malicious legacy rows"] if len(malicious) < 10 else []),
                *(["fewer than 10 benign legacy rows"] if len(benign) < 10 else []),
            ],
        }
    return coverage


def build_foundation(
    legacy_paths: tuple[Path, ...],
    output_directory: Path,
    *,
    config: FoundationConfig | None = None,
) -> dict[str, object]:
    """Build deterministic review artifacts. This never emits trusted classifier rows."""
    config = config or FoundationConfig()
    started = time.perf_counter_ns()
    rows = _read_legacy(legacy_paths)
    output_directory.mkdir(parents=True, exist_ok=True)
    source_hashes = {path.as_posix(): _sha256_file(path) for path in legacy_paths}
    input_hash = _canonical_hash(source_hashes)
    generator_code_hash = _sha256_file(Path(__file__))
    reproducibility = {
        "generator": "secureinjections.dataset_foundation.build_foundation",
        "generator_version": FOUNDATION_VERSION,
        "generator_code_sha256": generator_code_hash,
        "input_corpus_hash": input_hash,
        "configuration": {
            "similarity_threshold": config.similarity_threshold,
            "max_rows_for_exhaustive_near_audit": config.max_rows_for_exhaustive_near_audit,
            "character_ngram_size": config.character_ngram_size,
        },
        "random_seed": None,
        "deterministic": True,
        "normalization_version": NORMALIZATION_VERSION,
        "grouping_version": GROUPING_VERSION,
        "audit_version": AUDIT_VERSION,
        "split_version": SPLIT_VERSION,
    }

    exact_groups, exact_cross, _ = _group_cross_split(rows, lambda row: str(row["text"]))
    normalized_groups, normalized_cross, _ = _group_cross_split(
        rows, lambda row: normalized_text(str(row["text"]))
    )
    structural_groups, structural_cross, structural_candidate_groups = _group_cross_split(
        rows, lambda row: structural_text(str(row["text"]))
    )
    concept_groups, concept_cross, concept_candidate_groups = _group_cross_split(
        rows, _concept_candidate
    )
    template_groups, template_cross, template_candidate_groups = _group_cross_split(
        rows, _template_candidate
    )
    paraphrase_groups, paraphrase_cross, paraphrase_candidate_groups = _group_cross_split(
        rows,
        lambda row: (
            "derived-paraphrase-"
            + hashlib.sha256(structural_text(str(row["text"])).encode()).hexdigest()[:16]
        ),
    )
    translation_groups, translation_cross, translation_candidate_groups = _group_cross_split(
        tuple(row for row in rows if _translation_candidate(row)),
        lambda row: str(_translation_candidate(row)),
    )
    near = _near_pairs(rows, config)
    near_cross = [item for item in near if item["cross_split"]]
    near_clusters = _pair_clusters(near)
    conflicting = [item for item in near if item["conflicting_labels"]]
    suspicious = [
        row["id"]
        for row in rows
        if structural_text(str(row["text"])) != normalized_text(str(row["text"]))
    ]

    legacy_languages = Counter(str(row.get("language", "unknown")) for row in rows)
    legacy_labels = Counter(str(row.get("label", "unknown")) for row in rows)
    legacy_families = Counter(str(row.get("attack_family", "unknown")) for row in rows)
    review_queue: list[dict[str, object]] = []
    all_candidate_groups: dict[str, tuple[str, dict[str, list[dict[str, Any]]]]] = {
        "concept": ("proposed_concept_id", concept_candidate_groups),
        "template": ("proposed_template_family", template_candidate_groups),
        "paraphrase": ("proposed_paraphrase_group", paraphrase_candidate_groups),
        "translation": ("proposed_translation_group", translation_candidate_groups),
    }
    for kind, (proposal_field, groups) in all_candidate_groups.items():
        for group_id, members in sorted(groups.items()):
            review_queue.append(
                {
                    "queue_schema_version": 1,
                    "foundation_version": FOUNDATION_VERSION,
                    "input_corpus_hash": input_hash,
                    "generator_code_sha256": generator_code_hash,
                    "review_item_id": f"legacy-{kind}-{group_id}",
                    "review_status": "PROVISIONAL",
                    "review_type": f"proposed_{kind}_grouping",
                    proposal_field: group_id,
                    "case_ids": sorted(str(row["id"]) for row in members),
                    "current_splits": sorted({str(row.get("split")) for row in members}),
                    "labels": sorted({str(row.get("label")) for row in members}),
                    "languages": sorted({str(row.get("language")) for row in members}),
                    "provenance_reference": None,
                    "reviewer": None,
                    "review_notes": None,
                    "required_action": "confirm, edit, or reject the machine-derived grouping",
                }
            )
    row_by_id = {str(row["id"]): row for row in rows}
    for index, case_ids in enumerate(near_clusters):
        members = [row_by_id[case_id] for case_id in case_ids]
        review_queue.append(
            {
                "queue_schema_version": 1,
                "foundation_version": FOUNDATION_VERSION,
                "input_corpus_hash": input_hash,
                "generator_code_sha256": generator_code_hash,
                "review_item_id": f"legacy-near-duplicate-cluster-{index:05d}",
                "review_status": "PROVISIONAL",
                "review_type": "potential_near_duplicate_cluster",
                "case_ids": case_ids,
                "current_splits": sorted({str(row.get("split")) for row in members}),
                "labels": sorted({str(row.get("label")) for row in members}),
                "languages": sorted({str(row.get("language")) for row in members}),
                "provenance_reference": None,
                "reviewer": None,
                "review_notes": None,
                "required_action": "review semantic equivalence, grouping, and labels",
            }
        )
    review_queue.append(
        {
            "queue_schema_version": 1,
            "foundation_version": FOUNDATION_VERSION,
            "input_corpus_hash": input_hash,
            "generator_code_sha256": generator_code_hash,
            "review_item_id": "legacy-provenance-gap-all-rows",
            "review_status": "QUARANTINED",
            "review_type": "missing_classifier_provenance_and_review_metadata",
            "case_ids": sorted(str(row["id"]) for row in rows),
            "provenance_reference": None,
            "reviewer": None,
            "review_notes": None,
            "required_action": (
                "review provenance, usage basis, authorship, generation method, and trust state; "
                "do not bulk-promote"
            ),
        }
    )
    rows_by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_family[str(row.get("attack_family", "unknown"))].append(row)
    for family, members in sorted(rows_by_family.items()):
        review_queue.append(
            {
                "queue_schema_version": 1,
                "foundation_version": FOUNDATION_VERSION,
                "input_corpus_hash": input_hash,
                "generator_code_sha256": generator_code_hash,
                "review_item_id": "legacy-family-"
                + hashlib.sha256(family.encode()).hexdigest()[:16],
                "review_status": "PROVISIONAL",
                "review_type": "classifier_family_mapping_required",
                "legacy_attack_family": family,
                "proposed_classifier_family": None,
                "case_ids": sorted(str(row["id"]) for row in members),
                "labels": sorted({str(row.get("label")) for row in members}),
                "provenance_reference": None,
                "reviewer": None,
                "review_notes": None,
                "required_action": (
                    "assign or reject a broad classifier family after semantic review"
                ),
            }
        )
    for index, pair in enumerate(conflicting):
        review_queue.append(
            {
                "queue_schema_version": 1,
                "foundation_version": FOUNDATION_VERSION,
                "input_corpus_hash": input_hash,
                "generator_code_sha256": generator_code_hash,
                "review_item_id": f"legacy-conflict-{index:05d}",
                "review_status": "QUARANTINED",
                "review_type": "potential_conflicting_near_duplicate_labels",
                "case_ids": [pair["left"], pair["right"]],
                "similarity": pair["similarity"],
                "provenance_reference": None,
                "reviewer": None,
                "review_notes": None,
                "required_action": "review semantic equivalence and labels; do not auto-resolve",
            }
        )

    inventory = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "input_corpus_hash": input_hash,
        "sources": [
            {
                "path": path.as_posix(),
                "sha256": source_hashes[path.as_posix()],
                "rows": sum(row["_source_file"] == path.as_posix() for row in rows),
                "classification": "legacy-research-material",
                "trusted_without_review": 0,
            }
            for path in legacy_paths
        ],
        "total_rows": len(rows),
        "trusted_without_review": 0,
        "quarantined_or_provisional": len(rows),
        "labels": dict(sorted(legacy_labels.items())),
        "languages": dict(sorted(legacy_languages.items())),
        "families": dict(sorted(legacy_families.items())),
        "classifier_schema_rows": 0,
        "development_shadow_rows": 0,
    }
    audit = {
        "schema_version": 1,
        "reproducibility": reproducibility,
        "audit_version": AUDIT_VERSION,
        "normalization_version": NORMALIZATION_VERSION,
        "grouping_version": GROUPING_VERSION,
        "input_corpus_hash": input_hash,
        "rows": len(rows),
        "exact_duplicate_groups": exact_groups,
        "cross_split_exact_duplicate_groups": exact_cross,
        "normalized_duplicate_groups": normalized_groups,
        "cross_split_normalized_duplicate_groups": normalized_cross,
        "structural_duplicate_groups": structural_groups,
        "cross_split_structural_duplicate_groups": structural_cross,
        "near_duplicate_threshold": config.similarity_threshold,
        "near_duplicate_pairs": len(near),
        "near_duplicate_clusters": len(near_clusters),
        "cross_split_near_duplicate_pairs": len(near_cross),
        "potential_conflicting_near_duplicate_labels": len(conflicting),
        "derived_concept_groups": concept_groups,
        "cross_split_derived_concept_groups": concept_cross,
        "derived_template_groups": template_groups,
        "cross_split_derived_template_groups": template_cross,
        "derived_paraphrase_groups": paraphrase_groups,
        "cross_split_derived_paraphrase_groups": paraphrase_cross,
        "derived_translation_groups": translation_groups,
        "cross_split_derived_translation_groups": translation_cross,
        "generation_lineage_overlap": 0,
        "source_family_overlap": "not measurable: source_family absent",
        "suspicious_synthetic_marker_rows": len(suspicious),
        "rows_missing_required_classifier_metadata": len(rows),
        "passed": False,
    }
    hard_negative_families = {
        "security-education",
        "security-guidance",
        "hard-negative-override",
        "hard-negative-policy",
        "hard-negative-shell",
        "hard-negative-research",
        "multilingual-security",
        "multilingual-security-education",
        "network-education",
        "lexical-package",
        "lexical-shell",
        "lexical-sql",
        "lexical-traversal",
        "normal-sql",
        "code-reference",
        "technical-docs",
        "benign-log-security-terminology",
    }
    hard_rows = [
        row
        for row in rows
        if row.get("label") == "benign" and row.get("attack_family") in hard_negative_families
    ]
    classifier_manifest = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "status": "NOT CREATED: no reviewed v0.4.1 classifier rows",
        "trusted_rows": 0,
        "provisional_rows_promoted": 0,
        "legacy_review_seed_rows": len(rows),
        "input_corpus_hash": input_hash,
        "required_schema_version": 2,
        "split_version": SPLIT_VERSION,
    }
    shadow_manifest = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "status": "NOT CREATED: independent reviewed concepts unavailable",
        "rows": 0,
        "trusted_rows": 0,
        "development_shadow_frozen": False,
        "development_shadow_independence": "NOT ESTABLISHED",
        "input_corpus_hash": input_hash,
    }
    hard_manifest = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "status": "LEGACY REVIEW SEEDS ONLY",
        "trusted_cases": 0,
        "legacy_review_seed_cases": len(hard_rows),
        "legacy_family_counts": dict(
            sorted(Counter(str(row["attack_family"]) for row in hard_rows).items())
        ),
        "categories": len({str(row["attack_family"]) for row in hard_rows}),
        "input_corpus_hash": input_hash,
    }
    coverage = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "input_corpus_hash": input_hash,
        "trusted_language_count": 0,
        "claimed_supported_language_count": len(SUPPORTED_LANGUAGES),
        "language_coverage": _language_coverage(rows),
        "family_coverage": {
            family: {
                "legacy_rows": count,
                "trusted_rows": 0,
                "meaningful_classifier_evaluation": False,
            }
            for family, count in sorted(legacy_families.items())
        },
        "adequate_for_classifier_evaluation": False,
    }
    split_audit = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "input_corpus_hash": input_hash,
        "trusted_classifier_rows": 0,
        "legacy_split_audit": audit,
        "development_shadow_rows": 0,
        "development_shadow_concept_overlap": None,
        "development_shadow_template_overlap": None,
        "development_shadow_paraphrase_overlap": None,
        "development_shadow_translation_overlap": None,
        "development_shadow_generation_lineage_overlap": None,
        "split_gate": "FAIL",
        "reasons": [
            "no trusted classifier rows",
            "required grouping and provenance metadata absent",
            "legacy structural and conceptual leakage",
            "independent development shadow absent",
        ],
    }
    readiness = {
        "schema_version": 1,
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "input_corpus_hash": input_hash,
        "status": "NOT READY FOR LOCAL MODEL BAKE-OFF",
        "classifier_training_permitted": False,
        "models_downloaded": 0,
        "models_trained": 0,
        "model_selected": None,
        "blind_set_e_burned": False,
        "gates": {
            "trusted_classifier_data": "FAIL",
            "grouped_validation": "FAIL",
            "independent_development_shadow": "FAIL",
            "trusted_hard_negatives": "FAIL",
            "language_coverage": "FAIL",
            "family_coverage": "FAIL",
            "leakage": "FAIL",
        },
        "reasons": split_audit["reasons"],
    }

    outputs: dict[str, object] = {
        "v0.4.1-dataset-inventory.json": inventory,
        "v0.4.1-legacy-leakage-audit.json": audit,
        "v0.4.1-classifier-corpus-manifest.json": classifier_manifest,
        "v0.4.1-development-shadow-manifest.json": shadow_manifest,
        "v0.4.1-hard-negative-manifest.json": hard_manifest,
        "v0.4.1-split-leakage-audit.json": split_audit,
        "v0.4.1-language-family-coverage.json": coverage,
        "v0.4.1-corpus-readiness.json": readiness,
    }
    for name, value in outputs.items():
        (output_directory / name).write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    review_path = output_directory / "v0.4.1-human-review-queue.jsonl"
    review_path.write_text(
        "".join(
            json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n" for item in review_queue
        ),
        encoding="utf-8",
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    summary = {
        "foundation_version": FOUNDATION_VERSION,
        "reproducibility": reproducibility,
        "rows": len(rows),
        "trusted_rows": 0,
        "quarantined_or_provisional_rows": len(rows),
        "review_queue_items": len(review_queue),
        "cross_split_exact_duplicate_groups": exact_cross,
        "cross_split_structural_duplicate_groups": structural_cross,
        "cross_split_near_duplicate_pairs": len(near_cross),
        "cross_split_concept_groups": concept_cross,
        "cross_split_paraphrase_groups": paraphrase_cross,
        "cross_split_translation_groups": translation_cross,
        "audit_runtime_ms": round(elapsed_ms, 3),
        "input_corpus_hash": input_hash,
        "output_hashes": {
            name: _sha256_file(output_directory / name) for name in (*outputs, review_path.name)
        },
        "status": readiness["status"],
    }
    return summary
