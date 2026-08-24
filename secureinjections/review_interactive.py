"""Local stdin/stdout interface for the canonical human-review decision path."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from .classifier import IntentLabel
from .classifier_data import SUPPORTED_LANGUAGES, BinaryLabel
from .review_workflow import (
    EvidenceDecision,
    GroupingAction,
    ReviewDecision,
    ReviewDecisionKind,
    ReviewWorkflowError,
    active_review_decisions,
    canonical_sha256,
    load_review_export,
    load_review_history,
    parse_review_decision,
    record_review_decision,
)

InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]
REUSABLE_SHARED_FIELDS = (
    ("approved_concept_id", "concept_id"),
    ("approved_paraphrase_group", "paraphrase_group"),
    ("approved_translation_group", "translation_group"),
    ("approved_template_family", "template_family"),
    ("approved_source_family", "source_family"),
    ("approved_generation_method", "generation_method"),
)


@dataclass(frozen=True, slots=True)
class CasePosition:
    unit_index: int
    case_index: int
    case_id: str


@dataclass(slots=True)
class SessionCounts:
    decisions: Counter[str] = field(default_factory=Counter)
    superseding: int = 0

    @property
    def reviewed(self) -> int:
        return sum(self.decisions.values())


@dataclass(frozen=True, slots=True)
class TrustedSiblingMetadata:
    source_case_id: str
    source_review_id: str
    values: dict[str, str | None]


def _append_reuse_audit(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReviewWorkflowError("cannot safely open metadata-reuse audit") from exc
    with os.fdopen(descriptor, "r+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        file_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 64 * 1024 * 1024:
            raise ReviewWorkflowError("unsafe or oversized metadata-reuse audit")
        contents = handle.read()
        try:
            decoded = contents.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReviewWorkflowError("metadata-reuse audit is not valid UTF-8") from exc
        existing_ids: set[str] = set()
        for line_number, line in enumerate(decoded.splitlines(), 1):
            if not line.strip():
                continue
            try:
                existing = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReviewWorkflowError(
                    f"metadata-reuse audit line {line_number} is invalid"
                ) from exc
            if not isinstance(existing, dict) or not isinstance(
                existing.get("decision_review_id"), str
            ):
                raise ReviewWorkflowError("metadata-reuse audit contains an invalid record")
            existing_ids.add(existing["decision_review_id"])
        decision_review_id = record.get("decision_review_id")
        if not isinstance(decision_review_id, str) or decision_review_id in existing_ids:
            raise ReviewWorkflowError("duplicate or invalid metadata-reuse audit decision ID")
        separator = b"" if not contents or contents.endswith(b"\n") else b"\n"
        encoded = (
            separator
            + json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
            + b"\n"
        )
        if handle.write(encoded) != len(encoded):  # pragma: no cover - OS-level failure
            raise ReviewWorkflowError("incomplete append to metadata-reuse audit")
        handle.flush()
        os.fsync(handle.fileno())


class InteractiveReviewSession:
    """Human-first UI that delegates every write to record_review_decision()."""

    def __init__(
        self,
        export_path: Path,
        decisions_path: Path,
        reviewer: str,
        *,
        start_index: int | None = None,
        page_size: int = 10,
        legacy_paths: tuple[Path, ...] = (),
        history_path: Path | None = None,
        reuse_audit_path: Path | None = None,
        input_fn: InputFunction = input,
        output_fn: OutputFunction = print,
    ) -> None:
        if not reviewer.startswith("human:") or len(reviewer) <= len("human:"):
            raise ReviewWorkflowError("reviewer must identify an external human as human:<id>")
        if page_size < 1 or page_size > 50:
            raise ReviewWorkflowError("interactive page size must be between 1 and 50")
        self.export_path = export_path
        self.decisions_path = decisions_path
        self.reviewer = reviewer
        self.page_size = page_size
        self.legacy_paths = legacy_paths
        batch_name = decisions_path.stem.removesuffix("-decisions")
        self.history_path = history_path or decisions_path.parent / f"{batch_name}-history.jsonl"
        self.reuse_audit_path = (
            reuse_audit_path or decisions_path.parent / f"{batch_name}-metadata-reuse-audit.jsonl"
        )
        self.input = input_fn
        self.output = output_fn
        self.units = load_review_export(export_path)
        self.positions = self._positions()
        if not self.positions:
            raise ReviewWorkflowError("review export contains no reviewable cases")
        self.trusted_active = active_review_decisions(load_review_history(self.history_path))
        self.active = self._active_decisions()
        self.current = self._initial_position(start_index)
        self.drafts: dict[str, dict[str, Any]] = {}
        self.supersede: dict[str, str] = {}
        self.reused_metadata: dict[str, TrustedSiblingMetadata] = {}
        self.counts = SessionCounts()

    def _positions(self) -> tuple[CasePosition, ...]:
        positions = []
        seen: set[str] = set()
        for unit_index, unit in enumerate(self.units):
            cases = unit.get("cases")
            if not isinstance(cases, list) or not cases:
                raise ReviewWorkflowError("review export unit must contain cases")
            for case_index, case in enumerate(cases):
                if not isinstance(case, dict) or not isinstance(case.get("case_id"), str):
                    raise ReviewWorkflowError("review export contains a malformed case")
                case_id = cast(str, case["case_id"])
                if case_id in seen:
                    raise ReviewWorkflowError("review export contains duplicate case IDs")
                seen.add(case_id)
                positions.append(CasePosition(unit_index, case_index, case_id))
        return tuple(positions)

    def _active_decisions(self) -> dict[str, ReviewDecision]:
        imported = load_review_history(self.history_path)
        pending = load_review_history(self.decisions_path)
        by_id = {decision.review_id: decision for decision in imported}
        combined = list(imported)
        for decision in pending:
            previous = by_id.get(decision.review_id)
            if previous is not None:
                if previous != decision:
                    raise ReviewWorkflowError(
                        f"decision file conflicts with history for review ID {decision.review_id}"
                    )
                continue
            by_id[decision.review_id] = decision
            combined.append(decision)
        return active_review_decisions(tuple(combined))

    def _initial_position(self, start_index: int | None) -> int:
        if start_index is not None:
            if start_index < 0 or start_index >= len(self.units):
                raise ReviewWorkflowError("interactive start index is out of range")
            return next(
                index
                for index, position in enumerate(self.positions)
                if position.unit_index == start_index
            )
        return next(
            (
                index
                for index, position in enumerate(self.positions)
                if position.case_id not in self.active
            ),
            0,
        )

    def _unit_and_case(self) -> tuple[dict[str, Any], dict[str, Any], CasePosition]:
        position = self.positions[self.current]
        unit = self.units[position.unit_index]
        cases = cast(list[dict[str, Any]], unit["cases"])
        return unit, cases[position.case_index], position

    @staticmethod
    def _metadata(case: dict[str, Any]) -> dict[str, Any]:
        value = case.get("legacy_metadata")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _context(case: dict[str, Any]) -> dict[str, Any]:
        value = case.get("pilot_review_context")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _machine(unit: dict[str, Any]) -> dict[str, Any]:
        value = unit.get("machine_suggestion")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _decision_matches_export_case(decision: ReviewDecision, case: dict[str, Any]) -> bool:
        text = case.get("text")
        metadata = case.get("legacy_metadata")
        content_hash = case.get("original_content_hash")
        metadata_hash = case.get("original_metadata_hash")
        if not isinstance(text, str) or not isinstance(metadata, dict):
            return False
        computed_content = hashlib.sha256(text.encode("utf-8")).hexdigest()
        computed_metadata = canonical_sha256(metadata)
        return (
            content_hash == computed_content == decision.original_content_hash
            and metadata_hash == computed_metadata == decision.original_metadata_hash
        )

    def _trusted_sibling_metadata(
        self,
    ) -> tuple[TrustedSiblingMetadata | None, bool]:
        unit, _case, position = self._unit_and_case()
        cases = cast(list[dict[str, Any]], unit["cases"])
        candidates = []
        for sibling in cases:
            sibling_case_id = sibling.get("case_id")
            if not isinstance(sibling_case_id, str) or sibling_case_id == position.case_id:
                continue
            decision = self.trusted_active.get(sibling_case_id)
            if (
                decision is None
                or decision.decision is not ReviewDecisionKind.APPROVE
                or not decision.promotable
                or not self._decision_matches_export_case(decision, sibling)
            ):
                continue
            values = {
                draft_name: cast(str | None, getattr(decision, decision_name))
                for decision_name, draft_name in REUSABLE_SHARED_FIELDS
            }
            candidates.append(
                TrustedSiblingMetadata(
                    source_case_id=sibling_case_id,
                    source_review_id=decision.review_id,
                    values=values,
                )
            )
        if not candidates:
            return None, False
        signatures = {
            tuple(candidate.values[name] for _decision_name, name in REUSABLE_SHARED_FIELDS)
            for candidate in candidates
        }
        if len(signatures) > 1:
            return None, True
        candidates.sort(
            key=lambda candidate: (candidate.source_case_id, candidate.source_review_id)
        )
        return candidates[0], False

    def _offer_trusted_sibling_reuse(self) -> bool:
        _unit, _case, position = self._unit_and_case()
        candidate, conflict = self._trusted_sibling_metadata()
        if conflict:
            self.output("CONFLICTING TRUSTED SIBLING METADATA — MANUAL REVIEW REQUIRED")
            self.reused_metadata.pop(position.case_id, None)
            return False
        if candidate is None:
            return False
        self.output("-" * 50)
        self.output("Trusted sibling metadata available")
        self.output("-" * 50)
        self.output(f"Source case: {candidate.source_case_id}")
        self.output(f"Source review: {candidate.source_review_id}")
        for _decision_name, draft_name in REUSABLE_SHARED_FIELDS:
            self.output(f"{draft_name}: {candidate.values[draft_name]}")
        if self.input("Reuse these shared fields? [y/N]: ").strip().lower() != "y":
            self.output("Trusted sibling metadata was not reused.")
            self.reused_metadata.pop(position.case_id, None)
            return False
        draft = self.drafts.setdefault(position.case_id, {})
        draft.update(candidate.values)
        self.reused_metadata[position.case_id] = candidate
        self.output("REUSED FROM HUMAN-APPROVED SIBLING:")
        self.output(f"Source case: {candidate.source_case_id}")
        self.output(f"Source review: {candidate.source_review_id}")
        for _decision_name, draft_name in REUSABLE_SHARED_FIELDS:
            self.output(f"{draft_name}: {candidate.values[draft_name]}")
        return True

    def progress(self) -> dict[str, int]:
        pilot_ids = {position.case_id for position in self.positions}
        active = [decision for case_id, decision in self.active.items() if case_id in pilot_ids]
        counts = Counter(decision.decision.value for decision in active)
        return {
            "reviewed": len(active),
            "remaining": len(self.positions) - len(active),
            "approved": counts[ReviewDecisionKind.APPROVE.value],
            "rejected": counts[ReviewDecisionKind.REJECT.value],
            "deferred": counts[ReviewDecisionKind.DEFER.value],
            "quarantined": counts[ReviewDecisionKind.QUARANTINE.value],
            "ambiguous": counts[ReviewDecisionKind.AMBIGUOUS.value],
        }

    def _display_current(self) -> None:
        unit, case, position = self._unit_and_case()
        cases = cast(list[dict[str, Any]], unit["cases"])
        metadata = self._metadata(case)
        context = self._context(case)
        machine = self._machine(unit)
        languages = sorted(
            {
                str(self._metadata(member).get("language", "unknown"))
                for member in cases
                if isinstance(member, dict)
            }
        )
        text = str(case.get("text", ""))
        shown_text = text if len(text) <= 1200 else text[:1200] + "… [truncated]"
        self.output("=" * 50)
        self.output(f"Review unit {position.unit_index + 1} / {len(self.units)}")
        self.output("=" * 50)
        self.output(f"REVIEW ITEM\n{unit.get('review_item_id')}")
        self.output(f"CASE\n{position.case_id} ({position.case_index + 1} / {len(cases)} in group)")
        self.output(f"GROUP MEMBERS\n{len(cases)} rows")
        self.output(f"LANGUAGES\n{', '.join(languages)}")
        self.output(f"TEXT / SELECTED CASE\n{shown_text}")
        self.output("MACHINE SUGGESTION / UNTRUSTED")
        provisional_label = context.get("provisional_binary_label", metadata.get("label"))
        self.output(f"Binary label: {provisional_label}")
        self.output(f"Classifier family: {context.get('provisional_classifier_family')}")
        self.output(f"Legacy family: {metadata.get('attack_family')}")
        self.output(f"Concept: {machine.get('proposed_concept_id')}")
        self.output(f"Translation group: {machine.get('proposed_translation_group')}")
        self.output(f"Hard negative: {context.get('hard_negative_category_candidate')}")
        summary = unit.get("pilot_summary")
        if isinstance(summary, dict):
            self.output(f"Original-language status: {summary.get('original_language_status')}")
            self.output(
                "Translation-derived candidate: "
                f"{summary.get('translation_derived_candidate')} (PROVISIONAL)"
            )
        reasons = unit.get("priority_reasons")
        if isinstance(reasons, list):
            self.output("WHY PRIORITIZED\n" + "; ".join(str(reason) for reason in reasons))
        existing = self.active.get(position.case_id)
        if existing:
            self.output(
                "ACTIVE HUMAN DECISION\n"
                f"{existing.decision.value} — {existing.review_id} (not overwritten)"
            )
        draft = self.drafts.get(position.case_id)
        if draft:
            visible = {key: value for key, value in draft.items() if value is not None}
            self.output("CURRENT HUMAN FIELDS\n" + json.dumps(visible, indent=2, sort_keys=True))
        reuse = self.reused_metadata.get(position.case_id)
        if reuse:
            self.output(
                "REUSED FROM HUMAN-APPROVED SIBLING\n"
                f"{reuse.source_case_id} / {reuse.source_review_id}"
            )
        self.output(
            "ACTIONS\n"
            "[A] Approve  [E] Edit metadata  [D] Defer  [Q] Quarantine\n"
            "[R] Reject   [M] Ambiguous     [S] Split grouping\n"
            "[N] Next     [P] Previous      [C] Show cluster\n"
            "[V] View active decision       [U] Supersede active decision\n"
            "[K] Skip to next unresolved    [H] Help  [X] Exit safely"
        )

    def _prompt_value(
        self,
        label: str,
        *,
        current: str | None = None,
        suggestion: object = None,
        choices: tuple[str, ...] | None = None,
        optional: bool = False,
    ) -> str | None:
        while True:
            self.output(f"{label}: HUMAN APPROVED VALUE")
            if current is not None:
                self.output(f"  current human value: {current}")
            if suggestion is not None:
                self.output(f"  MACHINE SUGGESTION / UNTRUSTED: {suggestion}")
            if choices:
                self.output("  choices: " + ", ".join(choices))
            answer = self.input(
                "Enter value, ACCEPT to explicitly accept suggestion, - to clear, "
                "or Enter to keep current: "
            ).strip()
            if not answer:
                return current
            if answer == "-":
                return None
            if answer.upper() == "ACCEPT":
                if isinstance(suggestion, str) and suggestion.strip():
                    answer = suggestion
                elif choices and GroupingAction.ACCEPT.value in choices:
                    answer = GroupingAction.ACCEPT.value
                else:
                    self.output("No usable machine suggestion exists for this field.")
                    continue
            if choices:
                normalized = (
                    answer.upper() if all(item == item.upper() for item in choices) else answer
                )
                if normalized not in choices:
                    self.output("Invalid choice; no value was accepted.")
                    continue
                return normalized
            if answer or optional:
                return answer

    def _edit_metadata(self, *, grouping_only: bool = False, reuse_shared: bool = False) -> None:
        unit, case, position = self._unit_and_case()
        metadata = self._metadata(case)
        context = self._context(case)
        machine = self._machine(unit)
        draft = self.drafts.setdefault(position.case_id, {})

        def edit(
            key: str,
            label: str,
            suggestion: object = None,
            choices: tuple[str, ...] | None = None,
            optional: bool = False,
        ) -> None:
            draft[key] = self._prompt_value(
                label,
                current=draft.get(key),
                suggestion=suggestion,
                choices=choices,
                optional=optional,
            )

        if not grouping_only:
            edit(
                "binary_label",
                "Binary label",
                context.get("provisional_binary_label", metadata.get("label")),
                tuple(item.value for item in BinaryLabel),
            )
            edit(
                "classifier_family",
                "Classifier family",
                context.get("provisional_classifier_family"),
                tuple(item.value for item in IntentLabel),
            )
            edit("language", "Language", metadata.get("language"), SUPPORTED_LANGUAGES)
        if not reuse_shared:
            edit("concept_id", "Concept ID", machine.get("proposed_concept_id"))
            edit(
                "paraphrase_group",
                "Paraphrase group",
                machine.get("proposed_paraphrase_group"),
            )
            edit(
                "translation_group",
                "Translation group (use - for none)",
                machine.get("proposed_translation_group"),
                optional=True,
            )
        if grouping_only:
            draft["grouping_action"] = GroupingAction.SPLIT.value
            self.output("Grouping action explicitly set to SPLIT; no decision has been written.")
            return
        if not reuse_shared:
            edit("template_family", "Template family")
            edit("source_family", "Source family")
            edit("generation_method", "Generation method")
        edit(
            "authorship",
            "Authorship",
            choices=("human-authored", "generated", "mixed", "unknown"),
        )
        edit(
            "provenance_decision",
            "Provenance decision",
            choices=tuple(item.value for item in EvidenceDecision),
        )
        edit("provenance_reference", "Provenance reference", metadata.get("provenance"))
        edit(
            "usage_basis_decision",
            "Usage-basis decision",
            choices=tuple(item.value for item in EvidenceDecision),
        )
        edit(
            "license_or_usage_basis",
            "License or usage basis",
            metadata.get("license"),
        )
        edit(
            "hard_negative_category",
            "Hard-negative category (use - for none)",
            context.get("hard_negative_category_candidate"),
            optional=True,
        )
        edit(
            "difficulty",
            "Difficulty",
            metadata.get("difficulty"),
            ("medium", "hard", "adversarial"),
        )
        edit(
            "grouping_action",
            "Grouping action",
            choices=tuple(item.value for item in GroupingAction),
        )
        edit(
            "target_pool",
            "Target pool (use - for none)",
            metadata.get("split"),
            ("development", "development_shadow"),
            optional=True,
        )
        edit("notes", "Notes (use - for none)", optional=True)

    def _record_kwargs(self, decision: ReviewDecisionKind) -> dict[str, Any]:
        _unit, _case, position = self._unit_and_case()
        draft = dict(self.drafts.get(position.case_id, {}))
        draft.update(
            {
                "case_id": position.case_id,
                "decision": decision.value,
                "reviewer": self.reviewer,
                "supersedes_review_id": self.supersede.get(position.case_id),
            }
        )
        return draft

    def _preview(self, decision: ReviewDecisionKind) -> dict[str, object] | None:
        position = self.positions[self.current]
        try:
            return record_review_decision(
                self.export_path,
                position.unit_index,
                self.decisions_path,
                dry_run=True,
                **self._record_kwargs(decision),
            )
        except ReviewWorkflowError as exc:
            self.output(f"Decision is not valid and was not written: {exc}")
            return None

    def _confirm_and_record(self, decision: ReviewDecisionKind) -> bool:
        position = self.positions[self.current]
        existing = self.active.get(position.case_id)
        if existing and position.case_id not in self.supersede:
            self.output("This case already has an active decision. Use U to supersede explicitly.")
            return False
        preview = self._preview(decision)
        if preview is None:
            return False
        record = cast(dict[str, Any], preview["decision_record"])
        self.output("ABOUT TO WRITE HUMAN DECISION")
        reuse = self.reused_metadata.get(position.case_id)
        if reuse:
            self.output("REUSED FROM HUMAN-APPROVED SIBLING:")
            self.output(f"Source case: {reuse.source_case_id}")
            self.output(f"Source review: {reuse.source_review_id}")
            for _decision_name, draft_name in REUSABLE_SHARED_FIELDS:
                self.output(f"{draft_name}: {reuse.values[draft_name]}")
        summary_fields = (
            "case_id",
            "decision",
            "approved_binary_label",
            "approved_classifier_family",
            "approved_language",
            "approved_concept_id",
            "approved_paraphrase_group",
            "approved_translation_group",
            "provenance_decision",
            "usage_basis_decision",
            "target_pool",
            "supersedes_review_id",
        )
        for name in summary_fields:
            self.output(f"{name}: {record.get(name)}")
        if self.input("Write this append-only decision? [y/N]: ").strip().lower() != "y":
            self.output("No record written.")
            return False
        try:
            result = record_review_decision(
                self.export_path,
                position.unit_index,
                self.decisions_path,
                dry_run=False,
                **self._record_kwargs(decision),
            )
        except ReviewWorkflowError as exc:
            self.output(f"Decision failed closed and was not written: {exc}")
            return False
        appended = cast(dict[str, Any], result["decision_record"])
        parsed = parse_review_decision(appended)
        if reuse:
            audit_record = {
                "schema_version": 1,
                "workflow_version": "0.4.2",
                "decision_review_id": parsed.review_id,
                "decision_case_id": parsed.case_id,
                "decision_timestamp": parsed.timestamp,
                "current_content_hash": parsed.original_content_hash,
                "current_metadata_hash": parsed.original_metadata_hash,
                "metadata_reused_from_review_id": reuse.source_review_id,
                "metadata_reused_from_case_id": reuse.source_case_id,
                "reused_fields": {
                    decision_name: getattr(parsed, decision_name)
                    for decision_name, _draft_name in REUSABLE_SHARED_FIELDS
                },
                "explicit_human_reuse_confirmation": True,
                "decision_record_sha256": canonical_sha256(parsed.to_dict()),
            }
            try:
                _append_reuse_audit(self.reuse_audit_path, audit_record)
            except ReviewWorkflowError as exc:
                self.output(
                    f"WARNING: decision was appended, but metadata-reuse audit append failed: {exc}"
                )
            else:
                self.output(f"Metadata-reuse audit appended to {self.reuse_audit_path}.")
        self.active = self._active_decisions()
        self.counts.decisions[parsed.decision.value] += 1
        if parsed.supersedes_review_id:
            self.counts.superseding += 1
        self.supersede.pop(position.case_id, None)
        self.output(f"Appended {appended['review_id']} for {position.case_id}.")
        return True

    def _simple_decision(self, decision: ReviewDecisionKind) -> bool:
        _unit, _case, position = self._unit_and_case()
        draft = self.drafts.setdefault(position.case_id, {})
        if decision is ReviewDecisionKind.REJECT:
            reason = self._prompt_value(
                "Reject reason", current=draft.get("reject_reason"), optional=False
            )
            if not reason:
                self.output("REJECT requires a reason; no record written.")
                return False
            draft["reject_reason"] = reason
        return self._confirm_and_record(decision)

    def _move(self, delta: int) -> None:
        self.current = min(max(self.current + delta, 0), len(self.positions) - 1)

    def _next_unresolved(self) -> None:
        for offset in range(1, len(self.positions) + 1):
            candidate = (self.current + offset) % len(self.positions)
            if self.positions[candidate].case_id not in self.active:
                self.current = candidate
                return
        self.output("All pilot cases have active decisions.")

    def _view_active(self) -> None:
        case_id = self.positions[self.current].case_id
        decision = self.active.get(case_id)
        if decision is None:
            self.output("This case has no active human decision.")
            return
        self.output(json.dumps(decision.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))

    def _prepare_supersede(self) -> None:
        case_id = self.positions[self.current].case_id
        decision = self.active.get(case_id)
        if decision is None:
            self.output("This case has no active decision to supersede.")
            return
        answer = self.input(
            f"Create an explicit superseding decision for {decision.review_id}? [y/N]: "
        )
        if answer.strip().lower() == "y":
            self.supersede[case_id] = decision.review_id
            self.output("Superseding mode enabled. No record exists until a decision is confirmed.")
        else:
            self.output("Existing decision left unchanged.")

    def _show_cluster(self) -> None:
        unit, _case, position = self._unit_and_case()
        cases = cast(list[dict[str, Any]], unit["cases"])
        page = position.case_index // self.page_size
        while True:
            start = page * self.page_size
            end = min(start + self.page_size, len(cases))
            languages = Counter(str(self._metadata(case).get("language")) for case in cases)
            labels = Counter(str(self._metadata(case).get("label")) for case in cases)
            families = Counter(str(self._metadata(case).get("attack_family")) for case in cases)
            self.output(
                f"CLUSTER PAGE {page + 1} / {(len(cases) - 1) // self.page_size + 1} "
                f"({start + 1}-{end} of {len(cases)})"
            )
            self.output(f"Languages: {dict(sorted(languages.items()))}")
            self.output(f"Provisional labels: {dict(sorted(labels.items()))}")
            self.output(f"Provisional families: {dict(sorted(families.items()))}")
            for item_index in range(start, end):
                member = cases[item_index]
                metadata = self._metadata(member)
                self.output(
                    f"[{item_index + 1}] {member.get('case_id')} | "
                    f"{metadata.get('language')} | {metadata.get('label')} | "
                    f"{metadata.get('attack_family')}"
                )
            command = self.input(
                "Cluster: N next, P previous, /CASE-ID search, S NUMBER select, X close: "
            ).strip()
            lowered = command.lower()
            if lowered == "x" or not command:
                return
            if lowered == "n":
                page = min(page + 1, (len(cases) - 1) // self.page_size)
                continue
            if lowered == "p":
                page = max(0, page - 1)
                continue
            if command.startswith("/"):
                query = command[1:].casefold()
                match = next(
                    (
                        index
                        for index, member in enumerate(cases)
                        if query in str(member.get("case_id", "")).casefold()
                    ),
                    None,
                )
                if match is None:
                    self.output("No matching case ID.")
                else:
                    page = match // self.page_size
                continue
            if lowered.startswith("s "):
                selected = command[2:].strip()
                match = next(
                    (
                        index
                        for index, member in enumerate(cases)
                        if str(member.get("case_id")) == selected
                    ),
                    None,
                )
                if match is None and selected.isdigit():
                    numeric = int(selected) - 1
                    match = numeric if 0 <= numeric < len(cases) else None
                if match is None:
                    self.output("Invalid cluster selection.")
                    continue
                self.current = next(
                    index
                    for index, candidate in enumerate(self.positions)
                    if candidate.unit_index == position.unit_index and candidate.case_index == match
                )
                return
            self.output("Unknown cluster command.")

    def _help(self) -> None:
        self.output(
            "A opens the explicit approval editor and canonical preview. E edits human fields "
            "without writing. D/Q/R/M create only the selected disposition after confirmation. "
            "S prepares an explicit split but writes nothing. One case decision never approves "
            "siblings. Use C for bounded group pages, U before replacing an active decision, "
            "and X for a safe exit. Enter at the action prompt selects the safe DEFER path, "
            "which still requires a y confirmation."
        )

    def _session_summary(self) -> dict[str, object]:
        progress = self.progress()
        self.output("=" * 50)
        self.output("Human Review Session")
        self.output("=" * 50)
        self.output(f"Reviewed this session:            {self.counts.reviewed}")
        self.output(f"Approved:                         {self.counts.decisions['APPROVE']}")
        self.output(f"Rejected:                         {self.counts.decisions['REJECT']}")
        self.output(f"Deferred:                         {self.counts.decisions['DEFER']}")
        self.output(f"Quarantined:                      {self.counts.decisions['QUARANTINE']}")
        self.output(f"Ambiguous:                        {self.counts.decisions['AMBIGUOUS']}")
        self.output(f"Superseding decisions:            {self.counts.superseding}")
        self.output(f"Total active decisions:           {progress['reviewed']}")
        self.output(f"Remaining pilot cases:            {progress['remaining']}")
        self.output(f"Decisions file:\n{self.decisions_path}")
        self.output(f"Metadata-reuse audit:\n{self.reuse_audit_path}")
        self.output("No data imported/promoted automatically.")
        command = "uv run secureinjections classifier review import"
        command += f" \\\n  --export {self.export_path}"
        for path in self.legacy_paths:
            command += f" \\\n  --legacy-corpus {path}"
        batch_name = self.decisions_path.stem.removesuffix("-decisions")
        history_path = self.decisions_path.parent / f"{batch_name}-history.jsonl"
        audit_path = self.decisions_path.parent / f"{batch_name}-import-audit.json"
        command += f" \\\n  --decisions {self.decisions_path}"
        command += f" \\\n  --history {history_path}"
        command += f" \\\n  --audit {audit_path}"
        self.output(f"Next:\n{command}")
        self.output("=" * 50)
        return {
            "reviewed_this_session": self.counts.reviewed,
            "approved": self.counts.decisions["APPROVE"],
            "rejected": self.counts.decisions["REJECT"],
            "deferred": self.counts.decisions["DEFER"],
            "quarantined": self.counts.decisions["QUARANTINE"],
            "ambiguous": self.counts.decisions["AMBIGUOUS"],
            "superseding_decisions": self.counts.superseding,
            "total_active_decisions": progress["reviewed"],
            "remaining_pilot_cases": progress["remaining"],
            "decisions_path": str(self.decisions_path),
        }

    def run(self) -> dict[str, object]:
        progress = self.progress()
        self.output(
            f"Local human review: {len(self.units)} units / {len(self.positions)} cases. "
            f"Reviewed: {progress['reviewed']}; remaining: {progress['remaining']}."
        )
        try:
            while True:
                self._display_current()
                action = self.input("Action [Enter = safe DEFER path]: ").strip().upper() or "D"
                if action == "X":
                    break
                case_id = self.positions[self.current].case_id
                if (
                    action in {"A", "E", "D", "Q", "R", "M", "S"}
                    and case_id in self.active
                    and case_id not in self.supersede
                ):
                    self.output(
                        "This case already has an active decision. Use V to view, K to skip, "
                        "or U to enable explicit supersession."
                    )
                    continue
                if action == "H":
                    self._help()
                elif action == "N":
                    self._move(1)
                elif action == "P":
                    self._move(-1)
                elif action == "K":
                    self._next_unresolved()
                elif action == "C":
                    self._show_cluster()
                elif action == "V":
                    self._view_active()
                elif action == "U":
                    self._prepare_supersede()
                elif action == "E":
                    self._edit_metadata()
                elif action == "S":
                    self._edit_metadata(grouping_only=True)
                elif action == "A":
                    reused = self._offer_trusted_sibling_reuse()
                    self._edit_metadata(reuse_shared=reused)
                    if self._confirm_and_record(ReviewDecisionKind.APPROVE):
                        self._next_unresolved()
                elif action in {"D", "Q", "R", "M"}:
                    decision = {
                        "D": ReviewDecisionKind.DEFER,
                        "Q": ReviewDecisionKind.QUARANTINE,
                        "R": ReviewDecisionKind.REJECT,
                        "M": ReviewDecisionKind.AMBIGUOUS,
                    }[action]
                    if self._simple_decision(decision):
                        self._next_unresolved()
                else:
                    self.output("Unknown action. Press H for help; nothing was written.")
        except (EOFError, KeyboardInterrupt):
            self.output("\nSafe exit: unfinished case left unmodified.")
        return self._session_summary()


def run_interactive_review(
    export_path: Path,
    decisions_path: Path,
    reviewer: str,
    *,
    start_index: int | None = None,
    page_size: int = 10,
    legacy_paths: tuple[Path, ...] = (),
    history_path: Path | None = None,
    reuse_audit_path: Path | None = None,
    input_fn: InputFunction = input,
    output_fn: OutputFunction = print,
) -> dict[str, object]:
    return InteractiveReviewSession(
        export_path,
        decisions_path,
        reviewer,
        start_index=start_index,
        page_size=page_size,
        legacy_paths=legacy_paths,
        history_path=history_path,
        reuse_audit_path=reuse_audit_path,
        input_fn=input_fn,
        output_fn=output_fn,
    ).run()
