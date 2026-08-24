"""Versioned, fail-closed relationship consensus for Evidence Factory reviews."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

RELATIONSHIP_CONSENSUS_V1 = "relationship-consensus-v1"
RELATIONSHIP_CONSENSUS_V2 = "relationship-consensus-v2"
RELATIONSHIP_CONSENSUS_VERSIONS = frozenset({RELATIONSHIP_CONSENSUS_V1, RELATIONSHIP_CONSENSUS_V2})

RELATIONSHIP_TYPES = (
    "DISTINCT",
    "SAME_CONCEPT",
    "PARAPHRASE",
    "TRANSLATION",
    "TEMPLATE_SIBLING",
    "UNCERTAIN",
)
NON_INDEPENDENT_RELATIONSHIPS = frozenset(
    {"SAME_CONCEPT", "PARAPHRASE", "TRANSLATION", "TEMPLATE_SIBLING"}
)
CANONICAL_SEMANTIC_FIELDS = (
    "semantic_context",
    "primary_target",
    "primary_security_effect",
    "delivery_mechanism",
    "classifier_family",
)
DESCRIPTIVE_AUDIT_FIELDS = (
    "primary_action",
    "proposed_concept_id",
    "paraphrase_relationship",
    "translation_relationship",
    "template_family",
    "semantic_concept_summary",
    "family_selection_basis",
    "independence_basis",
    "rationale",
)


class Compatibility(StrEnum):
    EXACT_AGREEMENT = "EXACT_AGREEMENT"
    COMPATIBLE_NON_INDEPENDENT = "COMPATIBLE_NON_INDEPENDENT"
    MATERIAL_DISAGREEMENT = "MATERIAL_DISAGREEMENT"
    UNCERTAIN = "UNCERTAIN"


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _compatibility(left: str, right: str) -> str:
    if "UNCERTAIN" in {left, right}:
        return Compatibility.UNCERTAIN.value
    if left == right:
        return Compatibility.EXACT_AGREEMENT.value
    if left in NON_INDEPENDENT_RELATIONSHIPS and right in NON_INDEPENDENT_RELATIONSHIPS:
        return Compatibility.COMPATIBLE_NON_INDEPENDENT.value
    return Compatibility.MATERIAL_DISAGREEMENT.value


RELATIONSHIP_COMPATIBILITY_MATRIX: dict[str, dict[str, str]] = {
    left: {right: _compatibility(left, right) for right in RELATIONSHIP_TYPES}
    for left in RELATIONSHIP_TYPES
}

RELATIONSHIP_CONSENSUS_V2_SPEC: dict[str, Any] = {
    "version": RELATIONSHIP_CONSENSUS_V2,
    "relationship_types": list(RELATIONSHIP_TYPES),
    "compatibility_matrix": RELATIONSHIP_COMPATIBILITY_MATRIX,
    "canonical_consensus_critical_fields": [
        "trusted_concept_id",
        "relationship_type",
        *CANONICAL_SEMANTIC_FIELDS,
        "semantic_independence",
        "novelty_evidence",
    ],
    "descriptive_audit_only_fields": list(DESCRIPTIVE_AUDIT_FIELDS),
    "rules": {
        "uncertain_fails_closed": True,
        "distinct_vs_derivative_is_material": True,
        "one_sided_derivative_is_material": True,
        "different_all_distinct_comparison_sets_are_compatible": True,
        "independent_requires_both_reviewers_affirmative_novelty": True,
        "free_form_string_similarity_forbidden": True,
    },
}
RELATIONSHIP_CONSENSUS_V2_HASH = _canonical_hash(RELATIONSHIP_CONSENSUS_V2_SPEC)


def relationship_consensus_version(record: dict[str, Any]) -> str:
    """Treat historical records without an explicit field as exact-string v1."""
    value = record.get("relationship_consensus_version")
    if value is None:
        return RELATIONSHIP_CONSENSUS_V1
    if value in RELATIONSHIP_CONSENSUS_VERSIONS:
        return str(value)
    raise ValueError("unsupported relationship-consensus version")


def _relationships(review: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for item in review.get("trusted_concept_comparisons", []):
        concept_id = str(item["concept_id"])
        if concept_id in result:
            raise ValueError("duplicate trusted concept relationship")
        result[concept_id] = {
            "relationship": str(item["relationship"]),
            "basis": str(item["basis"]),
        }
    return result


def _deterministic_candidate_concept_id(candidate_id: str, left: dict[str, Any]) -> str:
    binding = {
        "candidate_id": candidate_id,
        "semantic_context": left["semantic_context"],
        "primary_target": left["primary_target"],
        "primary_security_effect": left["primary_security_effect"],
        "delivery_mechanism": left["delivery_mechanism"],
        "classifier_family": left["classifier_family"],
    }
    return "candidate-concept-" + _canonical_hash(binding)[:24]


def deterministic_template_id(review: dict[str, Any]) -> str:
    binding = {field: review[field] for field in CANONICAL_SEMANTIC_FIELDS}
    return "structured-template-" + _canonical_hash(binding)[:24]


def structured_relationship_consensus(
    candidate_id: str, left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    """Compare canonical relationships without trusting reviewer-authored display names."""
    left_relationships, right_relationships = _relationships(left), _relationships(right)
    comparison_ids = sorted(set(left_relationships) | set(right_relationships))
    comparisons: list[dict[str, Any]] = []
    reason_codes: set[str] = set()
    compatibility_values: list[str] = []

    for concept_id in comparison_ids:
        left_item, right_item = (
            left_relationships.get(concept_id),
            right_relationships.get(concept_id),
        )
        left_type = left_item["relationship"] if left_item else None
        right_type = right_item["relationship"] if right_item else None
        if left_type is None or right_type is None:
            present = left_type or right_type
            if present == "DISTINCT":
                compatibility = Compatibility.EXACT_AGREEMENT.value
                detail = "one-sided DISTINCT is compatible across different bounded comparison sets"
            elif present == "UNCERTAIN":
                compatibility = Compatibility.UNCERTAIN.value
                detail = "one reviewer supplied an unresolved relationship"
                reason_codes.add("RELATIONSHIP_UNCERTAIN")
            else:
                compatibility = Compatibility.MATERIAL_DISAGREEMENT.value
                detail = "one reviewer detected a derivative relationship the other did not assess"
                reason_codes.add("TRUSTED_CONCEPT_RELATIONSHIP_CONFLICT")
        else:
            compatibility = RELATIONSHIP_COMPATIBILITY_MATRIX[left_type][right_type]
            detail = "both reviewers assessed the same immutable trusted concept"
            if compatibility == Compatibility.UNCERTAIN:
                reason_codes.add("RELATIONSHIP_UNCERTAIN")
            elif compatibility == Compatibility.MATERIAL_DISAGREEMENT:
                reason_codes.add("MATERIAL_RELATIONSHIP_DISAGREEMENT")
        compatibility_values.append(compatibility)
        comparisons.append(
            {
                "trusted_concept_id": concept_id,
                "reviewer_a_relationship": left_type,
                "reviewer_b_relationship": right_type,
                "compatibility": compatibility,
                "detail": detail,
                "reviewer_a_basis": left_item["basis"] if left_item else None,
                "reviewer_b_basis": right_item["basis"] if right_item else None,
            }
        )

    semantic_fields = {
        field: {
            "reviewer_a": left[field],
            "reviewer_b": right[field],
            "agrees": left[field] == right[field],
        }
        for field in CANONICAL_SEMANTIC_FIELDS
    }
    semantic_conflicts = [field for field, value in semantic_fields.items() if not value["agrees"]]
    if semantic_conflicts:
        reason_codes.add("MATERIAL_RELATIONSHIP_DISAGREEMENT")

    left_independence = str(left["semantic_independence"])
    right_independence = str(right["semantic_independence"])
    if left_independence != right_independence:
        reason_codes.add("INDEPENDENCE_DISAGREEMENT")
    elif left_independence == "UNCERTAIN":
        reason_codes.add("RELATIONSHIP_UNCERTAIN")

    both_independent = left_independence == right_independence == "INDEPENDENT"
    novelty_ok = bool(left.get("novelty_evidence")) and bool(right.get("novelty_evidence"))
    all_distinct = bool(comparisons) and all(
        item["reviewer_a_relationship"] in {None, "DISTINCT"}
        and item["reviewer_b_relationship"] in {None, "DISTINCT"}
        for item in comparisons
    )
    if both_independent and (not novelty_ok or not all_distinct):
        reason_codes.add("RELATIONSHIP_UNCERTAIN")

    common_non_independent_ids = sorted(
        concept_id
        for concept_id in set(left_relationships) & set(right_relationships)
        if left_relationships[concept_id]["relationship"] in NON_INDEPENDENT_RELATIONSHIPS
        and right_relationships[concept_id]["relationship"] in NON_INDEPENDENT_RELATIONSHIPS
    )
    compatible_non_independent = (
        left_independence == right_independence == "NOT_INDEPENDENT"
        and bool(common_non_independent_ids)
        and not reason_codes
    )

    if "RELATIONSHIP_UNCERTAIN" in reason_codes:
        status = Compatibility.UNCERTAIN.value
    elif reason_codes:
        status = Compatibility.MATERIAL_DISAGREEMENT.value
    elif compatible_non_independent:
        status = Compatibility.COMPATIBLE_NON_INDEPENDENT.value
        reason_codes.add("STRUCTURED_RELATIONSHIP_AGREEMENT")
    elif both_independent and novelty_ok and all_distinct:
        status = Compatibility.EXACT_AGREEMENT.value
        reason_codes.add("STRUCTURED_RELATIONSHIP_AGREEMENT")
    else:
        status = Compatibility.UNCERTAIN.value
        reason_codes.add("RELATIONSHIP_UNCERTAIN")

    canonical_concept_id = None
    if status == Compatibility.COMPATIBLE_NON_INDEPENDENT:
        canonical_concept_id = common_non_independent_ids[0]
    elif status == Compatibility.EXACT_AGREEMENT and both_independent:
        canonical_concept_id = _deterministic_candidate_concept_id(candidate_id, left)

    core = {
        "status": status,
        "reason_codes": sorted(reason_codes),
        "canonical_concept_id": canonical_concept_id,
        "canonical_template_id": deterministic_template_id(left)
        if not semantic_conflicts
        else None,
        "semantic_fields": semantic_fields,
        "semantic_conflicts": semantic_conflicts,
        "trusted_concept_comparisons": comparisons,
        "independence": {
            "reviewer_a": left_independence,
            "reviewer_b": right_independence,
            "both_affirmative_novelty": novelty_ok,
            "all_observed_relationships_distinct": all_distinct,
        },
        "descriptive_audit_only": {
            "reviewer_a": {field: left.get(field) for field in DESCRIPTIVE_AUDIT_FIELDS},
            "reviewer_b": {field: right.get(field) for field in DESCRIPTIVE_AUDIT_FIELDS},
        },
    }
    return {**core, "structured_relationship_hash": _canonical_hash(core)}
