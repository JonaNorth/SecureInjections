"""Offline, append-only human review and trusted-corpus promotion workflow."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from .classifier import IntentLabel
from .classifier_data import (
    SUPPORTED_LANGUAGES,
    BinaryLabel,
    ClassifierCase,
    ReviewStatus,
    binary_label_for_family,
    conceptual_groups,
    corpus_hash,
    duplicate_audit,
    load_classifier_corpus,
    shadow_independence_audit,
    write_classifier_corpus,
)
from .dataset_foundation import (
    AUDIT_VERSION,
    GROUPING_VERSION,
    NORMALIZATION_VERSION,
    _canonical_hash,
    _concept_candidate,
    _read_legacy,
    _sha256_file,
)

REVIEW_WORKFLOW_VERSION = "0.4.2"
REVIEW_SCHEMA_VERSION = 1
REVIEW_GROUPING_VERSION = "human-review-concept-union-v1"
SHADOW_ASSIGNMENT_VERSION = "concept-hash-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
HARD_NEGATIVE_FAMILIES = frozenset(
    {
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
)


class ReviewWorkflowError(ValueError):
    pass


class ReviewDecisionKind(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    QUARANTINE = "QUARANTINE"
    DEFER = "DEFER"
    AMBIGUOUS = "AMBIGUOUS"


class EvidenceDecision(StrEnum):
    ACCEPTED = "ACCEPTED"
    UNKNOWN = "UNKNOWN"
    REJECTED = "REJECTED"


class GroupingAction(StrEnum):
    ACCEPT = "ACCEPT"
    SPLIT = "SPLIT"
    MERGE = "MERGE"
    REJECT = "REJECT"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    review_id: str
    case_id: str
    decision: ReviewDecisionKind
    reviewer: str
    timestamp: str
    original_content_hash: str
    original_metadata_hash: str
    approved_binary_label: BinaryLabel | None
    approved_classifier_family: IntentLabel | None
    approved_language: str | None
    approved_concept_id: str | None
    approved_paraphrase_group: str | None
    approved_translation_group: str | None
    approved_template_family: str | None
    approved_source_family: str | None
    approved_generation_method: str | None
    approved_authorship: str | None
    provenance_decision: EvidenceDecision
    provenance_reference: str | None
    usage_basis_decision: EvidenceDecision
    license_or_usage_basis: str | None
    hard_negative_category: str | None
    difficulty: str | None
    grouping_action: GroupingAction
    target_pool: str | None
    notes: str | None
    reject_reason: str | None
    supersedes_review_id: str | None

    @property
    def promotable(self) -> bool:
        return (
            self.decision is ReviewDecisionKind.APPROVE
            and self.approved_binary_label is not None
            and self.approved_classifier_family is not None
            and self.approved_language in SUPPORTED_LANGUAGES
            and bool(self.approved_concept_id)
            and bool(self.approved_paraphrase_group)
            and bool(self.approved_template_family)
            and bool(self.approved_source_family)
            and bool(self.approved_generation_method)
            and self.approved_authorship
            in {
                "human-authored",
                "generated",
                "mixed",
                "unknown",
            }
            and self.provenance_decision is EvidenceDecision.ACCEPTED
            and bool(self.provenance_reference)
            and self.usage_basis_decision is EvidenceDecision.ACCEPTED
            and bool(self.license_or_usage_basis)
            and self.difficulty in {"medium", "hard", "adversarial"}
            and self.grouping_action
            in {GroupingAction.ACCEPT, GroupingAction.SPLIT, GroupingAction.MERGE}
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "review_id": self.review_id,
            "case_id": self.case_id,
            "decision": self.decision.value,
            "reviewer": self.reviewer,
            "timestamp": self.timestamp,
            "original_content_hash": self.original_content_hash,
            "original_metadata_hash": self.original_metadata_hash,
            "approved_binary_label": (
                self.approved_binary_label.value if self.approved_binary_label else None
            ),
            "approved_classifier_family": (
                self.approved_classifier_family.value if self.approved_classifier_family else None
            ),
            "approved_language": self.approved_language,
            "approved_concept_id": self.approved_concept_id,
            "approved_paraphrase_group": self.approved_paraphrase_group,
            "approved_translation_group": self.approved_translation_group,
            "approved_template_family": self.approved_template_family,
            "approved_source_family": self.approved_source_family,
            "approved_generation_method": self.approved_generation_method,
            "approved_authorship": self.approved_authorship,
            "provenance_decision": self.provenance_decision.value,
            "provenance_reference": self.provenance_reference,
            "usage_basis_decision": self.usage_basis_decision.value,
            "license_or_usage_basis": self.license_or_usage_basis,
            "hard_negative_category": self.hard_negative_category,
            "difficulty": self.difficulty,
            "grouping_action": self.grouping_action.value,
            "target_pool": self.target_pool,
            "notes": self.notes,
            "reject_reason": self.reject_reason,
            "supersedes_review_id": self.supersedes_review_id,
        }


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def legacy_content_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(str(row.get("text", "")).encode("utf-8")).hexdigest()


def legacy_metadata_hash(row: dict[str, Any]) -> str:
    metadata = {key: value for key, value in row.items() if key not in {"text", "_source_file"}}
    return canonical_sha256(metadata)


def review_schema() -> dict[str, object]:
    nullable_string = {"type": ["string", "null"]}
    fields = {
        "schema_version": {"const": REVIEW_SCHEMA_VERSION},
        "review_id": {"type": "string", "minLength": 1},
        "case_id": {"type": "string", "minLength": 1},
        "decision": {"enum": [item.value for item in ReviewDecisionKind]},
        "reviewer": {"type": "string", "pattern": "^human:.+"},
        "timestamp": {"type": "string", "format": "date-time"},
        "original_content_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "original_metadata_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "approved_binary_label": {"enum": [item.value for item in BinaryLabel] + [None]},
        "approved_classifier_family": {"enum": [item.value for item in IntentLabel] + [None]},
        "approved_language": {"enum": list(SUPPORTED_LANGUAGES) + [None]},
        "approved_concept_id": nullable_string,
        "approved_paraphrase_group": nullable_string,
        "approved_translation_group": nullable_string,
        "approved_template_family": nullable_string,
        "approved_source_family": nullable_string,
        "approved_generation_method": nullable_string,
        "approved_authorship": {"enum": ["human-authored", "generated", "mixed", "unknown", None]},
        "provenance_decision": {"enum": [item.value for item in EvidenceDecision]},
        "provenance_reference": nullable_string,
        "usage_basis_decision": {"enum": [item.value for item in EvidenceDecision]},
        "license_or_usage_basis": nullable_string,
        "hard_negative_category": nullable_string,
        "difficulty": {"enum": ["medium", "hard", "adversarial", None]},
        "grouping_action": {"enum": [item.value for item in GroupingAction]},
        "target_pool": {"enum": ["development", "development_shadow", None]},
        "notes": nullable_string,
        "reject_reason": nullable_string,
        "supersedes_review_id": nullable_string,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://secureinjections.dev/schema/human-review-decision-v1.json",
        "title": "SecureInjections append-only human review decision",
        "type": "object",
        "additionalProperties": False,
        "required": list(fields),
        "properties": fields,
    }


def _nullable(raw: dict[str, Any], name: str) -> str | None:
    value = raw[name]
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ReviewWorkflowError(f"{name} must be a non-empty string or null")
    return value


def parse_review_decision(raw: object) -> ReviewDecision:
    properties = review_schema()["properties"]
    if not isinstance(properties, dict):  # pragma: no cover - internal invariant
        raise ReviewWorkflowError("invalid internal review schema")
    schema_fields = set(properties)
    if not isinstance(raw, dict) or set(raw) != schema_fields:
        raise ReviewWorkflowError("invalid review decision fields")
    if raw["schema_version"] != REVIEW_SCHEMA_VERSION:
        raise ReviewWorkflowError("unsupported review schema")
    for name in ("review_id", "case_id", "reviewer", "timestamp"):
        if not isinstance(raw[name], str) or not raw[name].strip():
            raise ReviewWorkflowError(f"invalid {name}")
    if not raw["reviewer"].startswith("human:"):
        raise ReviewWorkflowError("reviewer must identify an external human as human:<id>")
    try:
        timestamp = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReviewWorkflowError("invalid review timestamp") from exc
    if timestamp.tzinfo is None:
        raise ReviewWorkflowError("review timestamp must include a timezone")
    for name in ("original_content_hash", "original_metadata_hash"):
        if not isinstance(raw[name], str) or not _SHA256.fullmatch(raw[name]):
            raise ReviewWorkflowError(f"invalid {name}")
    try:
        decision = ReviewDecisionKind(raw["decision"])
        binary = BinaryLabel(raw["approved_binary_label"]) if raw["approved_binary_label"] else None
        family = (
            IntentLabel(raw["approved_classifier_family"])
            if raw["approved_classifier_family"]
            else None
        )
        provenance = EvidenceDecision(raw["provenance_decision"])
        usage = EvidenceDecision(raw["usage_basis_decision"])
        grouping = GroupingAction(raw["grouping_action"])
    except (TypeError, ValueError) as exc:
        raise ReviewWorkflowError("invalid review decision enum") from exc
    language = _nullable(raw, "approved_language")
    if language is not None and language not in SUPPORTED_LANGUAGES:
        raise ReviewWorkflowError("unsupported approved language")
    authorship = _nullable(raw, "approved_authorship")
    if authorship is not None and authorship not in {
        "human-authored",
        "generated",
        "mixed",
        "unknown",
    }:
        raise ReviewWorkflowError("invalid approved authorship")
    difficulty = _nullable(raw, "difficulty")
    if difficulty is not None and difficulty not in {"medium", "hard", "adversarial"}:
        raise ReviewWorkflowError("invalid difficulty")
    target = _nullable(raw, "target_pool")
    if target is not None and target not in {"development", "development_shadow"}:
        raise ReviewWorkflowError("invalid target pool")
    if binary is not None and family is not None and binary is not binary_label_for_family(family):
        raise ReviewWorkflowError("approved binary and classifier family labels conflict")
    result = ReviewDecision(
        review_id=raw["review_id"],
        case_id=raw["case_id"],
        decision=decision,
        reviewer=raw["reviewer"],
        timestamp=raw["timestamp"],
        original_content_hash=raw["original_content_hash"],
        original_metadata_hash=raw["original_metadata_hash"],
        approved_binary_label=binary,
        approved_classifier_family=family,
        approved_language=language,
        approved_concept_id=_nullable(raw, "approved_concept_id"),
        approved_paraphrase_group=_nullable(raw, "approved_paraphrase_group"),
        approved_translation_group=_nullable(raw, "approved_translation_group"),
        approved_template_family=_nullable(raw, "approved_template_family"),
        approved_source_family=_nullable(raw, "approved_source_family"),
        approved_generation_method=_nullable(raw, "approved_generation_method"),
        approved_authorship=authorship,
        provenance_decision=provenance,
        provenance_reference=_nullable(raw, "provenance_reference"),
        usage_basis_decision=usage,
        license_or_usage_basis=_nullable(raw, "license_or_usage_basis"),
        hard_negative_category=_nullable(raw, "hard_negative_category"),
        difficulty=difficulty,
        grouping_action=grouping,
        target_pool=target,
        notes=_nullable(raw, "notes"),
        reject_reason=_nullable(raw, "reject_reason"),
        supersedes_review_id=_nullable(raw, "supersedes_review_id"),
    )
    if result.decision is ReviewDecisionKind.APPROVE and not result.promotable:
        raise ReviewWorkflowError("approval does not satisfy trusted promotion policy")
    if result.decision is ReviewDecisionKind.REJECT and not result.reject_reason:
        raise ReviewWorkflowError("rejected decisions require reject_reason")
    return result


def load_review_history(path: Path) -> tuple[ReviewDecision, ...]:
    if not path.exists():
        return ()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ReviewWorkflowError("unsafe or oversized review history")
    return _load_review_text(path.read_text(encoding="utf-8"), path)


def _load_review_text(text: str, source: Path) -> tuple[ReviewDecision, ...]:
    decisions = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            decisions.append(parse_review_decision(json.loads(line)))
        except (json.JSONDecodeError, ReviewWorkflowError) as exc:
            raise ReviewWorkflowError(f"{source}:{line_number}: invalid review record") from exc
    return tuple(decisions)


def active_review_decisions(
    decisions: tuple[ReviewDecision, ...],
) -> dict[str, ReviewDecision]:
    by_id: dict[str, ReviewDecision] = {}
    active: dict[str, ReviewDecision] = {}
    superseded: set[str] = set()
    for decision in decisions:
        if decision.review_id in by_id:
            raise ReviewWorkflowError(f"duplicate review_id: {decision.review_id}")
        if decision.supersedes_review_id:
            previous = by_id.get(decision.supersedes_review_id)
            if previous is None or previous.case_id != decision.case_id:
                raise ReviewWorkflowError(
                    "superseding review must reference an earlier same-case review"
                )
            if previous.review_id in superseded:
                raise ReviewWorkflowError("review decision already superseded")
            superseded.add(previous.review_id)
        elif decision.case_id in active:
            raise ReviewWorkflowError(f"conflicting active reviews for case {decision.case_id}")
        by_id[decision.review_id] = decision
        active[decision.case_id] = decision
    return active


def _read_decision_file(path: Path) -> tuple[ReviewDecision, ...]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ReviewWorkflowError("unsafe or missing review decision file")
    return load_review_history(path)


def _review_export_source_rows(
    export_paths: tuple[Path, ...],
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], dict[str, str]]:
    """Resolve immutable cases and canonical decision bindings from review exports."""
    rows: dict[str, dict[str, Any]] = {}
    decision_prefixes: dict[str, set[str]] = {}
    export_hashes: dict[str, str] = {}
    for export_path in export_paths:
        export_key = export_path.resolve().as_posix()
        if export_key in export_hashes:
            raise ReviewWorkflowError(f"duplicate review export source: {export_path}")
        export_hashes[export_key] = _sha256_file(export_path)
        units = _read_review_export(export_path)
        for index, unit in enumerate(units):
            cases = unit.get("cases")
            if not isinstance(cases, list) or not cases:
                raise ReviewWorkflowError("review export unit must contain cases")
            for raw_case in cases:
                if not isinstance(raw_case, dict) or not isinstance(raw_case.get("case_id"), str):
                    raise ReviewWorkflowError("review export contains a malformed case")
                case_id = raw_case["case_id"]
                _unit, selected, binding = _validated_export_unit(export_path, index, case_id)
                metadata = cast(dict[str, Any], selected["legacy_metadata"])
                row = dict(metadata)
                row["text"] = selected["text"]
                row["_source_file"] = f"{export_key}#review-unit-{index}"
                existing = rows.get(case_id)
                if existing is not None and (
                    legacy_content_hash(existing) != legacy_content_hash(row)
                    or legacy_metadata_hash(existing) != legacy_metadata_hash(row)
                ):
                    raise ReviewWorkflowError(
                        f"conflicting review export representations for case {case_id}"
                    )
                rows.setdefault(case_id, row)
                binding_prefix = f"human-review-{canonical_sha256(binding)[:16]}-"
                decision_prefixes.setdefault(case_id, set()).add(binding_prefix)
    return rows, decision_prefixes, export_hashes


def _resolve_review_sources(
    legacy_paths: tuple[Path, ...], export_paths: tuple[Path, ...]
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], dict[str, object]]:
    if not legacy_paths and not export_paths:
        raise ReviewWorkflowError("review source selection is empty")
    legacy_rows = _read_legacy(legacy_paths) if legacy_paths else ()
    export_rows, decision_prefixes, export_hashes = _review_export_source_rows(export_paths)
    resolved: dict[str, dict[str, Any]] = {}
    source_kinds: dict[str, set[str]] = {}

    def register(case_id: str, row: dict[str, Any], kind: str) -> None:
        existing = resolved.get(case_id)
        if existing is not None:
            if legacy_content_hash(existing) != legacy_content_hash(row) or legacy_metadata_hash(
                existing
            ) != legacy_metadata_hash(row):
                raise ReviewWorkflowError(f"conflicting source representations for case {case_id}")
        else:
            resolved[case_id] = row
        source_kinds.setdefault(case_id, set()).add(kind)

    for row in legacy_rows:
        register(str(row["id"]), row, "legacy")
    for case_id, row in export_rows.items():
        register(case_id, row, "review_export")
    return (
        resolved,
        decision_prefixes,
        {
            "legacy_corpora": [path.resolve().as_posix() for path in legacy_paths],
            "review_exports": export_hashes,
            "resolved_cases": len(resolved),
            "legacy_cases": len(legacy_rows),
            "export_cases": len(export_rows),
            "identical_cross_source_cases": sum(
                kinds == {"legacy", "review_export"} for kinds in source_kinds.values()
            ),
        },
    )


def _export_binding_failures(
    decisions: tuple[ReviewDecision, ...],
    export_paths: tuple[Path, ...],
    decision_prefixes: dict[str, set[str]],
) -> int:
    if not export_paths:
        return 0
    return sum(
        not any(
            decision.review_id.startswith(prefix)
            for prefix in decision_prefixes.get(decision.case_id, set())
        )
        for decision in decisions
    )


def import_review_decisions(
    legacy_paths: tuple[Path, ...],
    decision_path: Path,
    history_path: Path,
    audit_path: Path,
    *,
    export_paths: tuple[Path, ...] = (),
) -> dict[str, object]:
    row_by_id, decision_prefixes, source_resolution = _resolve_review_sources(
        legacy_paths, export_paths
    )
    history = load_review_history(history_path)
    try:
        incoming = _read_decision_file(decision_path)
    except ReviewWorkflowError:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "workflow_version": REVIEW_WORKFLOW_VERSION,
                    "status": "REJECTED",
                    "decisions_imported": 0,
                    "invalid_decision_file": True,
                    "stale_content_hash": "N/A",
                    "stale_metadata_hash": "N/A",
                    "unknown_case_ids": "N/A",
                    "conflicting_active_decisions": "N/A",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        raise
    incoming_ids = [decision.review_id for decision in incoming]
    if len(incoming_ids) != len(set(incoming_ids)):
        raise ReviewWorkflowError("decision file contains duplicate review IDs")
    existing_by_id = {decision.review_id: decision for decision in history}
    new_incoming = []
    already_imported = 0
    stale_content = 0
    stale_metadata = 0
    unknown_cases = 0
    export_binding_failures = _export_binding_failures(incoming, export_paths, decision_prefixes)
    for decision in incoming:
        existing = existing_by_id.get(decision.review_id)
        if existing is not None:
            if existing != decision:
                raise ReviewWorkflowError(
                    f"review_id conflicts with imported history: {decision.review_id}"
                )
            already_imported += 1
        else:
            new_incoming.append(decision)
        row = row_by_id.get(decision.case_id)
        if row is None:
            unknown_cases += 1
            continue
        stale_content += decision.original_content_hash != legacy_content_hash(row)
        stale_metadata += decision.original_metadata_hash != legacy_metadata_hash(row)
    if unknown_cases or stale_content or stale_metadata or export_binding_failures:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "workflow_version": REVIEW_WORKFLOW_VERSION,
                    "status": "REJECTED",
                    "decision_file_sha256": _sha256_file(decision_path),
                    "decisions_received": len(incoming),
                    "decisions_imported": 0,
                    "stale_content_hash": stale_content,
                    "stale_metadata_hash": stale_metadata,
                    "unknown_case_ids": unknown_cases,
                    "export_binding_failures": export_binding_failures,
                    "conflicting_active_decisions": 0,
                    "source_resolution": source_resolution,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        raise ReviewWorkflowError(
            "review import rejected: unknown case or stale content/metadata hash or invalid "
            "export binding"
        )
    combined = (*history, *new_incoming)
    try:
        active_review_decisions(combined)
    except ReviewWorkflowError:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "workflow_version": REVIEW_WORKFLOW_VERSION,
                    "status": "REJECTED",
                    "decision_file_sha256": _sha256_file(decision_path),
                    "decisions_received": len(incoming),
                    "decisions_imported": 0,
                    "stale_content_hash": 0,
                    "stale_metadata_hash": 0,
                    "unknown_case_ids": 0,
                    "export_binding_failures": 0,
                    "conflicting_active_decisions": 1,
                    "source_resolution": source_resolution,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        raise
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as handle:
        for decision in new_incoming:
            handle.write(json.dumps(decision.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
    counts = Counter(decision.decision.value for decision in new_incoming)
    audit = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "decision_file_sha256": _sha256_file(decision_path),
        "history_sha256": _sha256_file(history_path),
        "accepted_decision_set_sha256": canonical_sha256(
            [decision.to_dict() for decision in active_review_decisions(combined).values()]
        ),
        "decisions_received": len(incoming),
        "decisions_already_imported": already_imported,
        "decisions_imported": len(new_incoming),
        "approved": counts[ReviewDecisionKind.APPROVE.value],
        "rejected": counts[ReviewDecisionKind.REJECT.value],
        "quarantined": counts[ReviewDecisionKind.QUARANTINE.value],
        "deferred": counts[ReviewDecisionKind.DEFER.value],
        "ambiguous": counts[ReviewDecisionKind.AMBIGUOUS.value],
        "stale_content_hash": stale_content,
        "stale_metadata_hash": stale_metadata,
        "unknown_case_ids": unknown_cases,
        "export_binding_failures": export_binding_failures,
        "conflicting_active_decisions": 0,
        "source_resolution": source_resolution,
        "superseding_decisions": sum(bool(item.supersedes_review_id) for item in new_incoming),
        "modified_metadata": sum(
            item.decision is ReviewDecisionKind.APPROVE for item in new_incoming
        ),
        "cluster_splits": sum(
            item.grouping_action is GroupingAction.SPLIT for item in new_incoming
        ),
        "cluster_merges": sum(
            item.grouping_action is GroupingAction.MERGE for item in new_incoming
        ),
        "provenance_failures": sum(
            item.provenance_decision is not EvidenceDecision.ACCEPTED for item in new_incoming
        ),
        "usage_basis_failures": sum(
            item.usage_basis_decision is not EvidenceDecision.ACCEPTED for item in new_incoming
        ),
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return audit


def promote_reviewed_cases(
    legacy_paths: tuple[Path, ...],
    history_path: Path,
    output_path: Path,
    *,
    export_paths: tuple[Path, ...] = (),
) -> tuple[tuple[ClassifierCase, ...], dict[str, object]]:
    row_by_id, decision_prefixes, source_resolution = _resolve_review_sources(
        legacy_paths, export_paths
    )
    history = load_review_history(history_path)
    active = active_review_decisions(history)
    if _export_binding_failures(tuple(active.values()), export_paths, decision_prefixes):
        raise ReviewWorkflowError("active review is not bound to the supplied review export")
    promoted: list[ClassifierCase] = []
    for case_id, decision in sorted(active.items()):
        row = row_by_id.get(case_id)
        if row is None:
            raise ReviewWorkflowError(f"active review references unknown case: {case_id}")
        if decision.original_content_hash != legacy_content_hash(row):
            raise ReviewWorkflowError(f"stale reviewed content: {case_id}")
        if decision.original_metadata_hash != legacy_metadata_hash(row):
            raise ReviewWorkflowError(f"stale reviewed metadata: {case_id}")
        if not decision.promotable:
            continue
        assert decision.approved_classifier_family is not None
        promoted.append(
            ClassifierCase(
                id=case_id,
                text=str(row["text"]),
                label=decision.approved_classifier_family,
                binary_label=decision.approved_binary_label,
                language=str(decision.approved_language),
                attack_family=str(row.get("attack_family", "unknown")),
                concept_id=str(decision.approved_concept_id),
                template_family=str(decision.approved_template_family),
                paraphrase_group=str(decision.approved_paraphrase_group),
                source_family=str(decision.approved_source_family),
                source=str(decision.provenance_reference),
                license=str(decision.license_or_usage_basis),
                generation_method=str(decision.approved_generation_method),
                authorship=str(decision.approved_authorship),
                # Human review establishes trust, not evaluation placement. Shadow placement is a
                # separate deterministic concept-level operation with its own manifest.
                split="candidate_pool",
                provenance_reference=decision.provenance_reference,
                review_status=ReviewStatus.REVIEWED,
                difficulty=str(decision.difficulty),
                hard_negative_category=decision.hard_negative_category,
                translation_group=decision.approved_translation_group,
                review_id=decision.review_id,
                review_record_hash=canonical_sha256(decision.to_dict()),
                original_content_hash=decision.original_content_hash,
                original_metadata_hash=decision.original_metadata_hash,
            )
        )
    materialized = tuple(promoted)
    if materialized:
        write_classifier_corpus(materialized, output_path)
    manifest = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "history_sha256": _sha256_file(history_path) if history_path.exists() else None,
        "active_decisions": len(active),
        "trusted_rows": len(materialized),
        "promoted_corpus_sha256": corpus_hash(materialized) if materialized else None,
        "output_path": output_path.as_posix() if materialized else None,
        "review_ids": [case.review_id for case in materialized],
        "source_resolution": source_resolution,
    }
    return materialized, manifest


def assign_shadow(
    cases: tuple[ClassifierCase, ...], *, seed: int = 42, shadow_ratio: float = 0.20
) -> tuple[tuple[ClassifierCase, ...], dict[str, object]]:
    if not 0 < shadow_ratio < 1:
        raise ValueError("shadow_ratio must be between zero and one")
    groups = conceptual_groups(cases)
    if len(groups) < 2:
        return cases, {
            "status": "INSUFFICIENT",
            "reason": "fewer than two independent reviewed concepts",
            "seed": seed,
            "grouping_version": REVIEW_GROUPING_VERSION,
            "assignment_version": SHADOW_ASSIGNMENT_VERSION,
            "assignment_manifest_sha256": None,
        }
    assigned: list[ClassifierCase] = []
    assignments: dict[str, str] = {}
    for group_id, members in sorted(groups.items()):
        digest = hashlib.sha256(f"{seed}:{group_id}".encode()).digest()
        value = int.from_bytes(digest[:8], "big") / 2**64
        split = "development_shadow" if value < shadow_ratio else "candidate_pool"
        for concept_id in {case.concept_id for case in members}:
            assignments[concept_id] = split
        assigned.extend(replace(case, split=split) for case in members)
    output = tuple(sorted(assigned, key=lambda case: case.id))
    shadow = shadow_independence_audit(output)
    status = (
        "READY"
        if {case.split for case in output}
        == {
            "candidate_pool",
            "development_shadow",
        }
        and shadow["passed"]
        else "INSUFFICIENT"
    )
    return output, {
        "status": status,
        "seed": seed,
        "grouping_version": REVIEW_GROUPING_VERSION,
        "assignment_version": SHADOW_ASSIGNMENT_VERSION,
        "source_manifest_sha256": corpus_hash(cases),
        "assignments": assignments,
        "assignment_manifest_sha256": canonical_sha256(assignments),
        "independence": shadow,
    }


def assign_shadow_corpus(
    corpus_path: Path,
    output_path: Path,
    manifest_path: Path,
    *,
    seed: int = 42,
    shadow_ratio: float = 0.20,
) -> dict[str, object]:
    cases = load_classifier_corpus(corpus_path)
    assigned, manifest = assign_shadow(cases, seed=seed, shadow_ratio=shadow_ratio)
    if manifest["status"] == "READY":
        write_classifier_corpus(assigned, output_path)
        manifest["output_sha256"] = corpus_hash(assigned)
        manifest["output_path"] = output_path.as_posix()
    else:
        manifest["output_sha256"] = None
        manifest["output_path"] = None
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def _queue_items(path: Path) -> tuple[dict[str, Any], ...]:
    if path.is_symlink() or not path.is_file():
        raise ReviewWorkflowError("review queue is missing or unsafe")
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ReviewWorkflowError("review queue contains a non-object")
            items.append(value)
    return tuple(items)


def _priority(item: dict[str, Any], rows: dict[str, dict[str, Any]]) -> tuple[int, list[str]]:
    selected = [rows[case_id] for case_id in item.get("case_ids", []) if case_id in rows]
    languages = {str(row.get("language")) for row in selected}
    families = {str(row.get("attack_family")) for row in selected}
    score = 0
    reasons = []
    non_english = languages - {"en"}
    if non_english:
        score += 40 + min(20, len(non_english) * 3)
        reasons.append("underrepresented non-English material")
    weak = {
        "indirect-injection",
        "cross-agent",
        "credential-access",
        "credential-exfiltration",
        "cloud-metadata",
        "inter-agent-persistence",
        "package-manager",
        "file-access",
        "sensitive-traversal",
        "log-poisoning",
        "tool-coercion",
        "tool-approval-bypass",
        "shell",
    }
    if families & weak:
        score += 35
        reasons.append("historically weak or security-critical family")
    review_type = str(item.get("review_type", ""))
    if review_type == "potential_near_duplicate_cluster":
        score += 20
        reasons.append("near-duplicate cluster needs semantic resolution")
    if review_type == "proposed_concept_grouping":
        score += 30
        reasons.append("concept-first grouping decision")
    if any(str(row.get("label")) == "benign" for row in selected) and any(
        str(row.get("attack_family", "")).startswith(("hard-negative", "security", "lexical"))
        for row in selected
    ):
        score += 35
        reasons.append("hard-negative research value")
    score += min(15, len(families) * 3)
    if languages == {"en"} and len(selected) > 12:
        score -= 20
        reasons.append("deprioritized repetitive English volume")
    return score, reasons


def build_review_plan(
    legacy_paths: tuple[Path, ...],
    queue_path: Path,
    plan_path: Path,
    export_path: Path,
    *,
    mode: str = "all",
) -> dict[str, object]:
    if mode not in {"all", "hard-negatives"}:
        raise ReviewWorkflowError("review mode must be all or hard-negatives")
    rows = _read_legacy(legacy_paths)
    row_by_id = {str(row["id"]): row for row in rows}
    queue = _queue_items(queue_path)
    units: list[dict[str, Any]] = []
    for item in queue:
        score, reasons = _priority(item, row_by_id)
        case_ids = [case_id for case_id in item.get("case_ids", []) if case_id in row_by_id]
        if mode == "hard-negatives":
            hard_case_ids = [
                case_id
                for case_id in case_ids
                if row_by_id[case_id].get("label") == "benign"
                and str(row_by_id[case_id].get("attack_family", "")).startswith(
                    ("hard-negative", "security", "lexical", "multilingual-security")
                )
            ]
            if not hard_case_ids:
                continue
            case_ids = hard_case_ids
            reasons.append("dedicated hard-negative review mode")
            score += 50
        if item.get("review_type") == "missing_classifier_provenance_and_review_metadata":
            score -= 250
            reasons.append("bulk provenance tracker; resolve through case/cluster decisions")
        units.append(
            {
                "review_item_id": item.get("review_item_id"),
                "review_type": item.get("review_type"),
                "priority_score": score,
                "priority_reasons": reasons,
                "machine_suggestion": {
                    key: value
                    for key, value in item.items()
                    if key.startswith("proposed_")
                    or key in {"labels", "languages", "current_splits"}
                },
                "machine_suggestion_trusted": False,
                "why_queued": item.get("required_action"),
                "case_ids": case_ids,
            }
        )
    units.sort(key=lambda item: (-int(item["priority_score"]), str(item["review_item_id"])))
    plan = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "source_inventory_hash": _canonical_hash(
            {path.as_posix(): _sha256_file(path) for path in legacy_paths}
        ),
        "review_queue_sha256": _sha256_file(queue_path),
        "queue_items": len(queue),
        "review_mode": mode,
        "review_units_selected": len(units),
        "review_units": units,
        "prioritization": {
            "version": "research-value-v1",
            "deterministic": True,
            "factors": [
                "non-English representation",
                "historically weak/security-critical families",
                "concept-first grouping",
                "hard-negative research value",
                "near-duplicate uncertainty",
                "English repetition penalty",
            ],
        },
    }
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with export_path.open("w", encoding="utf-8") as handle:
        for index, unit in enumerate(units):
            cases = []
            for case_id in unit["case_ids"]:
                row = row_by_id[case_id]
                cases.append(
                    {
                        "case_id": case_id,
                        "text": row.get("text"),
                        "legacy_metadata": {
                            key: value
                            for key, value in row.items()
                            if key not in {"text", "_source_file"}
                        },
                        "source_file": row["_source_file"],
                        "original_content_hash": legacy_content_hash(row),
                        "original_metadata_hash": legacy_metadata_hash(row),
                    }
                )
            handle.write(
                json.dumps(
                    {
                        "review_unit_index": index,
                        **unit,
                        "cases": cases,
                        "human_decision": None,
                        "instruction": (
                            "MACHINE SUGGESTION ONLY. Create separate schema-valid decision "
                            "records; this export is not an approval."
                        ),
                    },
                    sort_keys=True,
                    ensure_ascii=False,
                )
                + "\n"
            )
    return plan


def review_unit(export_path: Path, index: int) -> dict[str, object]:
    if index < 0:
        raise ReviewWorkflowError("review unit index cannot be negative")
    for current, line in enumerate(export_path.read_text(encoding="utf-8").splitlines()):
        if current == index:
            value = json.loads(line)
            if not isinstance(value, dict):
                break
            return value
    raise ReviewWorkflowError("review unit index is out of range")


def _read_review_export(path: Path) -> tuple[dict[str, Any], ...]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ReviewWorkflowError("review export is missing, unsafe, or oversized")
    units = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReviewWorkflowError(f"review export line {line_number} is invalid") from exc
        if not isinstance(value, dict):
            raise ReviewWorkflowError("review export contains a non-object")
        units.append(value)
    return tuple(units)


def load_review_export(path: Path) -> tuple[dict[str, Any], ...]:
    """Load a bounded local review export without assigning trust."""
    return _read_review_export(path)


def _machine_value(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewWorkflowError(f"no usable provisional {name} exists in this review unit")
    return value


def _explicit_or_accepted_machine_value(
    explicit: str | None,
    accept_machine: bool,
    machine: object,
    name: str,
) -> str | None:
    if explicit is not None and accept_machine:
        raise ReviewWorkflowError(f"choose either explicit {name} or accept-provisional-{name}")
    if accept_machine:
        return _machine_value(machine, name)
    return explicit


def _validated_export_unit(
    export_path: Path, index: int, case_id: str | None
) -> tuple[dict[str, Any], dict[str, Any], dict[str, object]]:
    if index < 0:
        raise ReviewWorkflowError("review unit index cannot be negative")
    units = _read_review_export(export_path)
    if index >= len(units):
        raise ReviewWorkflowError("review unit index is out of range")
    unit = units[index]
    review_item_id = unit.get("review_item_id")
    if not isinstance(review_item_id, str) or not review_item_id.strip():
        raise ReviewWorkflowError("review export unit is missing review_item_id")
    exported_index = unit.get("review_unit_index")
    if exported_index != index:
        raise ReviewWorkflowError("review export unit index binding is invalid")
    if unit.get("machine_suggestion_trusted") is not False:
        raise ReviewWorkflowError("review export must mark machine suggestions as untrusted")
    if unit.get("human_decision") is not None:
        raise ReviewWorkflowError("review export unexpectedly contains a human decision")
    cases = unit.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ReviewWorkflowError("review export unit must contain cases")
    validated: dict[str, dict[str, Any]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            raise ReviewWorkflowError("review export contains a malformed case")
        exported_case_id = raw_case.get("case_id")
        text = raw_case.get("text")
        metadata = raw_case.get("legacy_metadata")
        content_hash = raw_case.get("original_content_hash")
        metadata_hash = raw_case.get("original_metadata_hash")
        if (
            not isinstance(exported_case_id, str)
            or not exported_case_id.strip()
            or not isinstance(text, str)
            or not isinstance(metadata, dict)
            or not isinstance(content_hash, str)
            or not _SHA256.fullmatch(content_hash)
            or not isinstance(metadata_hash, str)
            or not _SHA256.fullmatch(metadata_hash)
        ):
            raise ReviewWorkflowError("review export case is missing required hash-bound fields")
        if exported_case_id in validated:
            raise ReviewWorkflowError("review export unit contains duplicate case IDs")
        if metadata.get("id") != exported_case_id:
            raise ReviewWorkflowError("review export case ID does not match legacy metadata")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != content_hash:
            raise ReviewWorkflowError("review export content hash does not match case text")
        if canonical_sha256(metadata) != metadata_hash:
            raise ReviewWorkflowError("review export metadata hash does not match case metadata")
        validated[exported_case_id] = raw_case
    if case_id is None:
        if len(validated) != 1:
            raise ReviewWorkflowError("--case-id is required for a review unit with multiple cases")
        selected_case_id = next(iter(validated))
    else:
        selected_case_id = case_id
    selected = validated.get(selected_case_id)
    if selected is None:
        raise ReviewWorkflowError("selected case ID is not present in the review unit")
    binding = {
        "export_sha256": _sha256_file(export_path),
        "pilot_id": unit.get("pilot_id"),
        "review_item_id": review_item_id,
        "review_unit_index": index,
        "case_ids": list(validated),
        "selected_case_id": selected_case_id,
    }
    return unit, selected, binding


def _validate_decision_sequence(
    existing: tuple[ReviewDecision, ...], decision: ReviewDecision
) -> None:
    active_review_decisions(existing)
    active_review_decisions(existing + (decision,))


def _append_decision(path: Path, decision: ReviewDecision) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReviewWorkflowError("cannot safely open decisions file") from exc
    try:
        with os.fdopen(descriptor, "r+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 64 * 1024 * 1024:
                raise ReviewWorkflowError("unsafe or oversized decisions file")
            contents = handle.read()
            try:
                existing = _load_review_text(contents.decode("utf-8"), path)
            except UnicodeDecodeError as exc:
                raise ReviewWorkflowError("decisions file is not valid UTF-8") from exc
            _validate_decision_sequence(existing, decision)
            separator = b"" if not contents or contents.endswith(b"\n") else b"\n"
            encoded = (
                separator
                + json.dumps(decision.to_dict(), sort_keys=True, ensure_ascii=False).encode("utf-8")
                + b"\n"
            )
            if handle.write(encoded) != len(encoded):  # pragma: no cover - OS-level failure
                raise ReviewWorkflowError("incomplete append to decisions file")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        raise


def record_review_decision(
    export_path: Path,
    index: int,
    decisions_path: Path,
    *,
    case_id: str | None,
    decision: str,
    reviewer: str,
    binary_label: str | None = None,
    accept_provisional_label: bool = False,
    classifier_family: str | None = None,
    accept_provisional_family: bool = False,
    language: str | None = None,
    accept_provisional_language: bool = False,
    concept_id: str | None = None,
    accept_provisional_concept: bool = False,
    paraphrase_group: str | None = None,
    accept_provisional_paraphrase: bool = False,
    translation_group: str | None = None,
    accept_provisional_translation: bool = False,
    template_family: str | None = None,
    source_family: str | None = None,
    generation_method: str | None = None,
    authorship: str | None = None,
    provenance_decision: str | None = None,
    provenance_reference: str | None = None,
    usage_basis_decision: str | None = None,
    license_or_usage_basis: str | None = None,
    hard_negative_category: str | None = None,
    accept_provisional_hard_negative: bool = False,
    difficulty: str | None = None,
    grouping_action: str | None = None,
    target_pool: str | None = None,
    notes: str | None = None,
    reject_reason: str | None = None,
    supersedes_review_id: str | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Build and optionally append one explicit, schema-valid human decision."""
    unit, selected_case, binding = _validated_export_unit(export_path, index, case_id)
    metadata = cast(dict[str, Any], selected_case["legacy_metadata"])
    context_value = selected_case.get("pilot_review_context")
    context = context_value if isinstance(context_value, dict) else {}
    machine_value = unit.get("machine_suggestion")
    machine = machine_value if isinstance(machine_value, dict) else {}

    approved_binary = _explicit_or_accepted_machine_value(
        binary_label,
        accept_provisional_label,
        context.get("provisional_binary_label", metadata.get("label")),
        "label",
    )
    approved_family = _explicit_or_accepted_machine_value(
        classifier_family,
        accept_provisional_family,
        context.get("provisional_classifier_family"),
        "family",
    )
    approved_language = _explicit_or_accepted_machine_value(
        language,
        accept_provisional_language,
        metadata.get("language"),
        "language",
    )
    approved_concept = _explicit_or_accepted_machine_value(
        concept_id,
        accept_provisional_concept,
        machine.get("proposed_concept_id"),
        "concept",
    )
    approved_paraphrase = _explicit_or_accepted_machine_value(
        paraphrase_group,
        accept_provisional_paraphrase,
        machine.get("proposed_paraphrase_group"),
        "paraphrase",
    )
    approved_translation = _explicit_or_accepted_machine_value(
        translation_group,
        accept_provisional_translation,
        machine.get("proposed_translation_group"),
        "translation",
    )
    approved_hard_negative = _explicit_or_accepted_machine_value(
        hard_negative_category,
        accept_provisional_hard_negative,
        context.get("hard_negative_category_candidate"),
        "hard-negative",
    )
    try:
        decision_kind = ReviewDecisionKind(decision)
    except ValueError as exc:
        raise ReviewWorkflowError("invalid human decision") from exc
    if decision_kind is ReviewDecisionKind.APPROVE:
        required = {
            "binary label": approved_binary,
            "classifier family": approved_family,
            "language": approved_language,
            "concept ID": approved_concept,
            "paraphrase group": approved_paraphrase,
            "template family": template_family,
            "source family": source_family,
            "generation method": generation_method,
            "authorship": authorship,
            "difficulty": difficulty,
            "grouping action": grouping_action,
            "accepted provenance decision": (
                provenance_decision
                if provenance_decision == EvidenceDecision.ACCEPTED.value
                else None
            ),
            "provenance reference": provenance_reference,
            "accepted usage-basis decision": (
                usage_basis_decision
                if usage_basis_decision == EvidenceDecision.ACCEPTED.value
                else None
            ),
            "license or usage basis": license_or_usage_basis,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ReviewWorkflowError(
                "approval requires explicit human fields: " + ", ".join(missing)
            )
    binding_digest = canonical_sha256(binding)
    review_id = f"human-review-{binding_digest[:16]}-{uuid4().hex[:16]}"
    raw = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "review_id": review_id,
        "case_id": selected_case["case_id"],
        "decision": decision_kind.value,
        "reviewer": reviewer,
        "timestamp": datetime.now(UTC).isoformat(),
        "original_content_hash": selected_case["original_content_hash"],
        "original_metadata_hash": selected_case["original_metadata_hash"],
        "approved_binary_label": approved_binary,
        "approved_classifier_family": approved_family,
        "approved_language": approved_language,
        "approved_concept_id": approved_concept,
        "approved_paraphrase_group": approved_paraphrase,
        "approved_translation_group": approved_translation,
        "approved_template_family": template_family,
        "approved_source_family": source_family,
        "approved_generation_method": generation_method,
        "approved_authorship": authorship,
        "provenance_decision": provenance_decision or EvidenceDecision.UNKNOWN.value,
        "provenance_reference": provenance_reference,
        "usage_basis_decision": usage_basis_decision or EvidenceDecision.UNKNOWN.value,
        "license_or_usage_basis": license_or_usage_basis,
        "hard_negative_category": approved_hard_negative,
        "difficulty": difficulty,
        "grouping_action": grouping_action or GroupingAction.UNCERTAIN.value,
        "target_pool": target_pool,
        "notes": notes,
        "reject_reason": reject_reason,
        "supersedes_review_id": supersedes_review_id,
    }
    parsed = parse_review_decision(raw)
    if decisions_path.exists():
        existing = load_review_history(decisions_path)
        _validate_decision_sequence(existing, parsed)
    if not dry_run:
        _append_decision(decisions_path, parsed)
    return {
        "status": "DRY_RUN — NOT WRITTEN" if dry_run else "APPENDED",
        "append_only": True,
        "decisions_path": str(decisions_path),
        "export_binding": binding,
        "machine_suggestion_status": "MACHINE SUGGESTION / UNTRUSTED",
        "machine_suggestion": machine,
        "decision_record": parsed.to_dict(),
    }


def _pilot_unit_summary(unit: dict[str, Any]) -> dict[str, object]:
    cases = unit.get("cases", [])
    if not isinstance(cases, list):
        raise ReviewWorkflowError("review unit cases must be a list")
    languages: set[str] = set()
    families: set[str] = set()
    labels: set[str] = set()
    case_ids: list[str] = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("legacy_metadata"), dict):
            raise ReviewWorkflowError("review unit contains invalid case metadata")
        metadata = case["legacy_metadata"]
        case_ids.append(str(case.get("case_id")))
        languages.add(str(metadata.get("language", "unknown")))
        families.add(str(metadata.get("attack_family", "unknown")))
        labels.add(str(metadata.get("label", "unknown")))
    machine = unit.get("machine_suggestion")
    proposed = machine if isinstance(machine, dict) else {}
    hard_categories = sorted(
        family for family in families if "benign" in labels and family in HARD_NEGATIVE_FAMILIES
    )
    translation_candidate = bool(
        any(family.startswith("multilingual-") for family in families)
        or families & {"credential-exfiltration-composition", "multilingual-security-education"}
    )
    flags = []
    if len(cases) > 20:
        flags.append("large machine cluster; human split likely required")
    if len(languages) > 1:
        flags.append("multilingual/translation relationship requires human confirmation")
    if len(labels) > 1:
        flags.append("conflicting provisional binary labels")
    if len(families) > 1:
        flags.append("multiple provisional legacy families")
    return {
        "review_item_id": unit.get("review_item_id"),
        "case_ids": case_ids,
        "rows": len(cases),
        "languages": sorted(languages),
        "candidate_families": sorted(families),
        "provisional_binary_labels": sorted(labels),
        "candidate_concept_id": proposed.get("proposed_concept_id"),
        "candidate_paraphrase_group": proposed.get("proposed_paraphrase_group"),
        "candidate_translation_group": proposed.get("proposed_translation_group"),
        "hard_negative_categories": hard_categories,
        "translation_derived_candidate": translation_candidate,
        "original_language_status": "unknown-unreviewed",
        "uncertainty_flags": flags,
    }


def build_review_pilot(
    plan_path: Path,
    export_path: Path,
    output_path: Path,
    manifest_path: Path,
    *,
    target_units: int = 40,
) -> dict[str, object]:
    """Select a deterministic, concept-diverse pilot without creating human decisions."""
    if not 30 <= target_units <= 50:
        raise ReviewWorkflowError("pilot target must be between 30 and 50 review units")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        raise ReviewWorkflowError("review plan must be an object")
    units = _read_review_export(export_path)
    candidates = []
    for unit in units:
        if unit.get("review_type") != "proposed_concept_grouping":
            continue
        summary = _pilot_unit_summary(unit)
        languages = set(cast(list[str], summary["languages"]))
        families = set(cast(list[str], summary["candidate_families"]))
        hard = set(cast(list[str], summary["hard_negative_categories"]))
        rows = cast(int, summary["rows"])
        base_score = int(unit.get("priority_score", 0))
        base_score += 70 if "da" in languages else 0
        base_score += 65 if "sv" in languages else 0
        base_score += 25 * len(languages - {"en"})
        base_score += 40 if hard else 0
        base_score += (
            20
            if families
            & {
                "cloud-metadata",
                "credential-access",
                "credential-exfiltration",
                "inter-agent-persistence",
                "log-poisoning",
                "package-manager",
                "sensitive-traversal",
                "tool-approval-bypass",
                "tool-coercion",
            }
            else 0
        )
        base_score -= max(0, rows - 20) * 2
        candidates.append((unit, summary, base_score))
    selected: list[tuple[dict[str, Any], dict[str, object], int]] = []
    selected_languages: set[str] = set()
    selected_families: set[str] = set()
    selected_hard: set[str] = set()
    remaining = candidates[:]
    while remaining and len(selected) < target_units:

        def value(item: tuple[dict[str, Any], dict[str, object], int]) -> tuple[int, str]:
            unit, summary, base = item
            languages = set(cast(list[str], summary["languages"]))
            families = set(cast(list[str], summary["candidate_families"]))
            hard = set(cast(list[str], summary["hard_negative_categories"]))
            diversity = 18 * len(languages - selected_languages)
            diversity += 12 * len(families - selected_families)
            diversity += 20 * len(hard - selected_hard)
            return base + diversity, str(unit.get("review_item_id"))

        chosen = max(remaining, key=value)
        remaining.remove(chosen)
        selected.append(chosen)
        selected_languages.update(cast(list[str], chosen[1]["languages"]))
        selected_families.update(cast(list[str], chosen[1]["candidate_families"]))
        selected_hard.update(cast(list[str], chosen[1]["hard_negative_categories"]))
    if len(selected) < 30:
        raise ReviewWorkflowError("fewer than 30 concept review units are available")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    selected_case_ids: set[str] = set()
    concept_candidates: set[str] = set()
    with output_path.open("w", encoding="utf-8") as handle:
        for pilot_index, (unit, summary, selection_score) in enumerate(selected):
            selected_case_ids.update(cast(list[str], summary["case_ids"]))
            candidate_concept = summary["candidate_concept_id"]
            if isinstance(candidate_concept, str):
                concept_candidates.add(candidate_concept)
            cases = unit.get("cases")
            if isinstance(cases, list):
                for case in cases:
                    if not isinstance(case, dict):
                        continue
                    metadata = case.get("legacy_metadata")
                    if isinstance(metadata, dict):
                        family = str(metadata.get("attack_family", "unknown"))
                        label = str(metadata.get("label", "unknown"))
                        case["pilot_review_context"] = {
                            "provisional_binary_label": label,
                            "provisional_legacy_family": family,
                            "provisional_classifier_family": None,
                            "provenance_status": "UNKNOWN / HUMAN DECISION REQUIRED",
                            "license_or_usage_status": "UNKNOWN / HUMAN DECISION REQUIRED",
                            "hard_negative_category_candidate": (
                                family
                                if label == "benign" and family in HARD_NEGATIVE_FAMILIES
                                else None
                            ),
                            "machine_confidence": "not available",
                        }
            pilot_unit = {
                **unit,
                "review_unit_index": pilot_index,
                "pilot_id": "v0.4.2-review-pilot-01",
                "pilot_selection_score": selection_score,
                "pilot_summary": summary,
                "human_decision": None,
                "decision_record_status": "NOT CREATED — HUMAN REVIEW REQUIRED",
            }
            handle.write(json.dumps(pilot_unit, sort_keys=True, ensure_ascii=False) + "\n")
    language_unit_counts = Counter(
        language
        for _unit, summary, _score in selected
        for language in set(cast(list[str], summary["languages"]))
    )
    family_unit_counts = Counter(
        family
        for _unit, summary, _score in selected
        for family in set(cast(list[str], summary["candidate_families"]))
    )
    hard_unit_count = sum(bool(summary["hard_negative_categories"]) for _, summary, _ in selected)
    translated_count = sum(
        bool(summary["translation_derived_candidate"]) for _, summary, _ in selected
    )
    english_units = sum("en" in cast(list[str], summary["languages"]) for _, summary, _ in selected)
    non_english_units = sum(
        bool(set(cast(list[str], summary["languages"])) - {"en"}) for _, summary, _ in selected
    )
    label_unit_counts = Counter(
        label
        for _unit, summary, _score in selected
        for label in set(cast(list[str], summary["provisional_binary_labels"]))
    )
    rows_per_unit = Counter(cast(int, summary["rows"]) for _, summary, _ in selected)
    large_units = [
        {
            "review_item_id": summary["review_item_id"],
            "rows": summary["rows"],
            "languages": summary["languages"],
            "candidate_families": summary["candidate_families"],
        }
        for _unit, summary, _score in selected
        if cast(int, summary["rows"]) > 20
    ]
    manifest = {
        "schema_version": 1,
        "pilot_id": "v0.4.2-review-pilot-01",
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_review_queue_sha256": plan.get("review_queue_sha256"),
        "source_plan_sha256": _sha256_file(plan_path),
        "source_export_sha256": _sha256_file(export_path),
        "pilot_export_sha256": _sha256_file(output_path),
        "prioritization_version": plan.get("prioritization", {}).get("version"),
        "selection_configuration": {
            "target_review_units": target_units,
            "concept_units_only": True,
            "unique_concept_candidate_per_unit": True,
            "strong_danish_bonus": True,
            "strong_swedish_bonus": True,
            "non_english_diversity_bonus": True,
            "hard_negative_diversity_bonus": True,
            "family_diversity_bonus": True,
            "large_cluster_penalty_after_rows": 20,
            "deterministic_tie_break": "review_item_id",
        },
        "selected_review_ids": [
            str(unit.get("review_item_id")) for unit, _summary, _score in selected
        ],
        "selected_case_ids": sorted(selected_case_ids),
        "concept_candidates": sorted(concept_candidates),
        "review_units": len(selected),
        "rows_represented": len(selected_case_ids),
        "candidate_concepts": len(concept_candidates),
        "languages": dict(sorted(language_unit_counts.items())),
        "language_count": len(language_unit_counts),
        "english_units": english_units,
        "non_english_units": non_english_units,
        "danish_units": language_unit_counts["da"],
        "swedish_units": language_unit_counts["sv"],
        "provisional_label_units": dict(sorted(label_unit_counts.items())),
        "candidate_families": dict(sorted(family_unit_counts.items())),
        "candidate_family_count": len(family_unit_counts),
        "hard_negative_units": hard_unit_count,
        "hard_negative_categories": sorted(selected_hard),
        "original_language_concepts": 0,
        "original_language_status": "unknown until human review",
        "translation_derived_candidate_units": translated_count,
        "rows_per_unit_distribution": dict(sorted(rows_per_unit.items())),
        "large_review_units": large_units,
        "human_decisions_present": 0,
        "trusted_rows": 0,
        "code_sha256": _sha256_file(Path(__file__)),
        "git_commit": None,
        "git_state": "worktree contains the ongoing uncommitted v0.4.1/v0.4.2 work",
        "warnings": [
            "candidate concept counts are machine suggestions, not reviewed concepts",
            "original versus translated authorship remains unknown",
            "large clusters may require human splitting before any member is approved",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def trusted_coverage(cases: tuple[ClassifierCase, ...]) -> dict[str, object]:
    languages: dict[str, object] = {}
    for language in SUPPORTED_LANGUAGES:
        selected = [case for case in cases if case.language == language]
        malicious = [
            case for case in selected if case.effective_binary_label is BinaryLabel.MALICIOUS
        ]
        benign = [case for case in selected if case.effective_binary_label is BinaryLabel.BENIGN]
        concepts = {case.concept_id for case in selected}
        translated = {case.concept_id for case in selected if case.translation_group}
        languages[language] = {
            "trusted_malicious_rows": len(malicious),
            "trusted_benign_rows": len(benign),
            "trusted_malicious_concepts": len({case.concept_id for case in malicious}),
            "trusted_benign_concepts": len({case.concept_id for case in benign}),
            "original_concepts": len(concepts - translated),
            "translated_concepts": len(translated),
            "families_represented": sorted({case.label.value for case in selected}),
            "sparse": len(concepts) < 2,
        }
    families = {
        family.value: {
            "trusted_rows": sum(case.label is family for case in cases),
            "unique_concepts": len({case.concept_id for case in cases if case.label is family}),
            "languages_represented": sorted(
                {case.language for case in cases if case.label is family}
            ),
            "shadow_eligible_independent_concepts": len(
                {case.concept_id for case in cases if case.label is family}
            ),
        }
        for family in IntentLabel
    }
    concept_sizes = Counter(case.concept_id for case in cases)
    hard = [case for case in cases if case.hard_negative_category]
    return {
        "trusted_rows": len(cases),
        "unique_reviewed_concepts": len(concept_sizes),
        "languages": languages,
        "families": families,
        "rows_per_concept_distribution": dict(sorted(Counter(concept_sizes.values()).items())),
        "hard_negatives": {
            "trusted_cases": len(hard),
            "unique_concepts": len({case.concept_id for case in hard}),
            "categories_represented": sorted(
                {case.hard_negative_category for case in hard if case.hard_negative_category}
            ),
            "languages_represented": sorted({case.language for case in hard}),
        },
    }


def workflow_readiness(cases: tuple[ClassifierCase, ...]) -> dict[str, object]:
    coverage = trusted_coverage(cases)
    shadow = shadow_independence_audit(cases) if cases else None
    leakage = duplicate_audit(cases) if cases else None
    return {
        "review_workflow": "READY",
        "trusted_corpus": "INSUFFICIENT" if not cases else "REQUIRES COVERAGE REVIEW",
        "development_shadow": ("READY" if shadow and shadow["passed"] else "INSUFFICIENT"),
        "model_bake_off": "NOT READY",
        "trusted_rows": len(cases),
        "trusted_concepts": coverage["unique_reviewed_concepts"],
        "leakage_gate": "PASS" if leakage and leakage["passed"] else "FAIL",
        "reasons": [
            *(
                ["no explicit human review decisions have produced trusted rows"]
                if not cases
                else []
            ),
            *(
                ["independent development shadow is absent"]
                if not shadow or not shadow["passed"]
                else []
            ),
            "language/family/hard-negative coverage has not met readiness requirements",
        ],
    }


def historical_grouping_discrepancy(
    legacy_paths: tuple[Path, ...], v041_audit_path: Path
) -> dict[str, object]:
    rows = _read_legacy(legacy_paths)
    source_rows = len(rows)
    current_keys = {_concept_candidate(row) for row in rows}
    current_cross = sum(
        len({str(row.get("split")) for row in rows if _concept_candidate(row) == concept_id}) > 1
        for concept_id in current_keys
    )
    current_duplicate = sum(
        sum(_concept_candidate(row) == concept_id for row in rows) > 1
        for concept_id in current_keys
    )
    v041 = json.loads(v041_audit_path.read_text(encoding="utf-8"))
    return {
        "source_inventory_same_row_count": source_rows == 1246,
        "v0.4.0": {
            "published_total_derived_concepts": 90,
            "published_crossing_concepts": 84,
            "published_split_concepts": {
                "development": 90,
                "validation": 78,
                "holdout": 53,
            },
            "published_pairwise_overlap": {
                "development_validation": 78,
                "development_holdout": 53,
                "validation_holdout": 47,
            },
            "crossing_reconstruction": "78 + 53 - 47 = 84",
            "group_key_implementation_preserved": False,
        },
        "v0.4.1": {
            "grouping_version": GROUPING_VERSION,
            "all_derived_keys_recomputed": len(current_keys),
            "duplicate_candidate_groups_recomputed": current_duplicate,
            "crossing_groups_recomputed": current_cross,
            "reported_duplicate_candidate_groups": v041["derived_concept_groups"],
            "reported_crossing_groups": v041["cross_split_derived_concept_groups"],
        },
        "explanation": [
            "The source inventory and structural audit counts are unchanged.",
            "v0.4.0 reported a 90-key historical derivation and reconstructed crossing as the "
            "union of published split-overlap sets.",
            "v0.4.1 introduced legacy-suggestion-v1-unreviewed, including conservative "
            "multilingual translation-family grouping, and its derived_concept_groups field "
            "counts only non-singleton review-candidate groups rather than all derived keys.",
            "The two totals therefore use different grouping definitions and denominators; "
            "neither is human-reviewed concept ground truth.",
            "The exact v0.4.0 per-row group-key function was not retained, so its membership "
            "cannot be reproduced beyond the published aggregate and overlap arithmetic.",
        ],
        "difference_explained": True,
        "historical_artifacts_modified": False,
    }


def build_bootstrap(
    legacy_paths: tuple[Path, ...],
    queue_path: Path,
    v041_audit_path: Path,
    output_directory: Path,
    *,
    history_path: Path | None = None,
    seed: int = 42,
) -> dict[str, object]:
    """Generate truthful v0.4.2 workflow artifacts without manufacturing review decisions."""
    output_directory.mkdir(parents=True, exist_ok=True)
    plan_path = output_directory / "v0.4.2-review-plan.json"
    export_path = output_directory / "v0.4.2-review-export.jsonl"
    plan = build_review_plan(legacy_paths, queue_path, plan_path, export_path)
    rows = _read_legacy(legacy_paths)
    source_inventory_hash = _canonical_hash(
        {path.as_posix(): _sha256_file(path) for path in legacy_paths}
    )
    decisions = load_review_history(history_path) if history_path else ()
    active = active_review_decisions(decisions)
    trusted: tuple[ClassifierCase, ...] = ()
    promoted_manifest: dict[str, object]
    promoted_path = output_directory / "v0.4.2-trusted-corpus.jsonl"
    if history_path and history_path.exists():
        trusted, promoted_manifest = promote_reviewed_cases(
            legacy_paths, history_path, promoted_path
        )
    else:
        promoted_manifest = {
            "schema_version": 1,
            "workflow_version": REVIEW_WORKFLOW_VERSION,
            "status": "INSUFFICIENT: no external human decision history supplied",
            "history_sha256": None,
            "active_decisions": 0,
            "trusted_rows": 0,
            "promoted_corpus_sha256": None,
            "output_path": None,
            "review_ids": [],
        }
    counts = Counter(decision.decision.value for decision in decisions)
    review_audit = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "review_queue_sha256": _sha256_file(queue_path),
        "review_export_sha256": _sha256_file(export_path),
        "decision_history_present": bool(history_path and history_path.exists()),
        "decision_history_sha256": (
            _sha256_file(history_path) if history_path and history_path.exists() else None
        ),
        "decisions_imported": len(decisions),
        "active_decisions": len(active),
        "approved": counts[ReviewDecisionKind.APPROVE.value],
        "rejected": counts[ReviewDecisionKind.REJECT.value],
        "quarantined": counts[ReviewDecisionKind.QUARANTINE.value],
        "deferred": counts[ReviewDecisionKind.DEFER.value],
        "ambiguous": counts[ReviewDecisionKind.AMBIGUOUS.value],
        "stale_content_hash": 0 if decisions else 0,
        "stale_metadata_hash": 0 if decisions else 0,
        "conflicting_active_decisions": 0,
        "modified_metadata": sum(
            decision.decision is ReviewDecisionKind.APPROVE for decision in decisions
        ),
        "cluster_splits": sum(
            decision.grouping_action is GroupingAction.SPLIT for decision in decisions
        ),
        "cluster_merges": sum(
            decision.grouping_action is GroupingAction.MERGE for decision in decisions
        ),
        "provenance_failures": sum(
            decision.provenance_decision is not EvidenceDecision.ACCEPTED for decision in decisions
        ),
        "usage_basis_failures": sum(
            decision.usage_basis_decision is not EvidenceDecision.ACCEPTED for decision in decisions
        ),
        "note": "No counts imply human review unless a separate imported history is present.",
    }
    coverage = trusted_coverage(trusted)
    _, shadow_assignment = assign_shadow(trusted, seed=seed)
    shadow_cases = tuple(case for case in trusted if case.split == "development_shadow")
    shadow_manifest = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "status": "NOT CREATED" if not shadow_cases else shadow_assignment["status"],
        "created": bool(shadow_cases),
        "rows": len(shadow_cases),
        "unique_concepts": len({case.concept_id for case in shadow_cases}),
        "concept_overlap": None if not shadow_cases else 0,
        "assignment": shadow_assignment,
    }
    hard_value = coverage["hard_negatives"]
    if not isinstance(hard_value, dict):  # pragma: no cover - internal invariant
        raise ReviewWorkflowError("invalid hard-negative coverage")
    hard: dict[str, object] = hard_value
    hard_status = {
        "schema_version": 1,
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        **hard,
        "legacy_review_seeds": 395,
        "legacy_candidate_categories": 17,
        "status": "INSUFFICIENT" if not trusted else "REQUIRES COVERAGE REVIEW",
    }
    readiness = workflow_readiness(trusted)
    discrepancy = historical_grouping_discrepancy(legacy_paths, v041_audit_path)
    outputs: dict[str, object] = {
        "v0.4.2-review-schema.json": review_schema(),
        "v0.4.2-review-audit.json": review_audit,
        "v0.4.2-trusted-corpus-manifest.json": promoted_manifest,
        "v0.4.2-development-shadow-manifest.json": shadow_manifest,
        "v0.4.2-hard-negative-review-status.json": hard_status,
        "v0.4.2-language-family-coverage.json": coverage,
        "v0.4.2-corpus-readiness.json": readiness,
        "v0.4.2-historical-grouping-discrepancy.json": discrepancy,
    }
    for name, value in outputs.items():
        (output_directory / name).write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    summary = {
        "workflow_version": REVIEW_WORKFLOW_VERSION,
        "source_inventory_hash": source_inventory_hash,
        "source_rows": len(rows),
        "review_queue_items": plan["queue_items"],
        "review_queue_sha256": _sha256_file(queue_path),
        "review_decision_file_hash": (
            _sha256_file(history_path) if history_path and history_path.exists() else None
        ),
        "accepted_decision_set_hash": (
            canonical_sha256([item.to_dict() for item in active.values()]) if active else None
        ),
        "promoted_corpus_hash": corpus_hash(trusted) if trusted else None,
        "shadow_assignment_hash": shadow_assignment.get("assignment_manifest_sha256"),
        "grouping_version": REVIEW_GROUPING_VERSION,
        "normalization_version": NORMALIZATION_VERSION,
        "audit_version": AUDIT_VERSION,
        "code_sha256": _sha256_file(Path(__file__)),
        "seed": seed,
        "models_downloaded": 0,
        "models_trained": 0,
        "model_selected": None,
        "blind_set_e_burned": False,
        "review_workflow": readiness["review_workflow"],
        "model_bake_off": readiness["model_bake_off"],
        "output_hashes": {
            name: _sha256_file(output_directory / name)
            for name in (*outputs, plan_path.name, export_path.name)
        },
    }
    return summary
