"""Auditable, fail-closed automated evidence factory.

The module deliberately does not contain a trained classifier. Model execution is an
orchestration boundary: each isolated pass imports a response JSONL produced from the emitted
candidate-only review envelope. This keeps provider credentials and network behavior outside the
trusted-data process while preserving prompt, configuration, response, and candidate bindings.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .classifier_data import SUPPORTED_LANGUAGES
from .evidence_reviewer_contract import (
    BASE_REVIEW_FIELDS,
    MAX_TRUSTED_COMPARISONS,
    REVIEWER_CONTRACT_V1,
    REVIEWER_CONTRACT_V2,
    REVIEWER_CONTRACT_VERSIONS,
    V2_CONTRACT_SPEC,
    ReviewerContractError,
    record_contract_version,
    required_review_fields,
    validate_v2_response,
)
from .evidence_taxonomy import TAXONOMY_VERSION, validate_label_family
from .relationship_consensus import (
    RELATIONSHIP_CONSENSUS_V1,
    RELATIONSHIP_CONSENSUS_V2,
    RELATIONSHIP_CONSENSUS_V2_HASH,
    RELATIONSHIP_CONSENSUS_VERSIONS,
    deterministic_template_id,
    relationship_consensus_version,
    structured_relationship_consensus,
)
from .safe_yaml import bounded_safe_load

EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_WORKFLOW_VERSION = "0.4.2-evidence-factory-v1"
MAX_SOURCE_BYTES = 2_000_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"\w+", re.UNICODE)
_SECRET = re.compile(
    r"(?:-----BEGIN [A-Z ]+PRIVATE KEY-----|\b(?:api[_-]?key|password|secret)\s*[:=]\s*\S+)",
    re.IGNORECASE,
)


class EvidenceFactoryError(ValueError):
    pass


class TrustTier(StrEnum):
    RAW_CANDIDATE = "RAW_CANDIDATE"
    MODEL_REVIEWED = "MODEL_REVIEWED"
    CONSENSUS_TRUSTED = "CONSENSUS_TRUSTED"
    HUMAN_TRUSTED = "HUMAN_TRUSTED"
    HUMAN_TRUSTED_HOLDOUT = "HUMAN_TRUSTED_HOLDOUT"
    BLIND_EVALUATION = "BLIND_EVALUATION"


class QueueReason(StrEnum):
    LABEL_DISAGREEMENT = "LABEL_DISAGREEMENT"
    FAMILY_DISAGREEMENT = "FAMILY_DISAGREEMENT"
    USAGE_RIGHTS_UNCERTAIN = "USAGE_RIGHTS_UNCERTAIN"
    PRIVACY_UNCERTAIN = "PRIVACY_UNCERTAIN"
    INDEPENDENCE_UNCERTAIN = "INDEPENDENCE_UNCERTAIN"
    TAXONOMY_AMBIGUOUS = "TAXONOMY_AMBIGUOUS"
    HIGH_SIMILARITY_BOUNDARY = "HIGH_SIMILARITY_BOUNDARY"
    PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
    RELATIONSHIP_DISAGREEMENT = "RELATIONSHIP_DISAGREEMENT"
    MATERIAL_RELATIONSHIP_DISAGREEMENT = "MATERIAL_RELATIONSHIP_DISAGREEMENT"
    RELATIONSHIP_UNCERTAIN = "RELATIONSHIP_UNCERTAIN"
    TRUSTED_CONCEPT_RELATIONSHIP_CONFLICT = "TRUSTED_CONCEPT_RELATIONSHIP_CONFLICT"
    INDEPENDENCE_DISAGREEMENT = "INDEPENDENCE_DISAGREEMENT"
    AMBIGUOUS = "AMBIGUOUS"
    DETERMINISTIC_GATE_FAILURE = "DETERMINISTIC_GATE_FAILURE"
    PROTECTED_EVALUATION_OVERLAP = "PROTECTED_EVALUATION_OVERLAP"
    REVIEWER_CONTRACT_MISMATCH = "REVIEWER_CONTRACT_MISMATCH"


# Public compatibility alias: this is the historical Pilot 01/v1 response schema.
REVIEW_FIELDS = BASE_REVIEW_FIELDS


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _mutation_counts(**overrides: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "candidates_processed": 0,
        "consensus_count": 0,
        "human_queue_count": 0,
        "rejected_count": 0,
        "rights_failures": 0,
        "privacy_failures": 0,
        "independence_failures": 0,
        "label_disagreements": 0,
        "family_disagreements": 0,
        "proposed_trust_tier_changes": {},
    }
    report.update(overrides)
    return report


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceFactoryError(f"invalid JSONL at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise EvidenceFactoryError(f"JSONL row must be an object at {path}:{line_number}")
        rows.append(value)
    return rows


def _jsonl_bytes(rows: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        for row in rows
    )


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]], *, append: bool = False) -> None:
    materialized = tuple(rows)
    if not materialized:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "ab" if append else "wb"
    with path.open(mode) as handle:
        handle.write(_jsonl_bytes(materialized))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _metadata_binding(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        key: candidate.get(key)
        for key in (
            "candidate_id",
            "language",
            "source_type",
            "source_publisher",
            "source_title",
            "source_url_or_reference",
            "source_location",
            "publication_date",
            "exact_or_paraphrase",
            "usage_basis",
            "privacy_classification",
            "provenance",
            "stable_source_id",
            "acquisition_method",
            "acquisition_intent",
            "source_hash",
        )
    }


def validate_candidate(candidate: dict[str, Any]) -> None:
    required = {
        "candidate_id",
        "text",
        "language",
        "source_type",
        "source_publisher",
        "source_title",
        "source_url_or_reference",
        "source_location",
        "publication_date",
        "exact_or_paraphrase",
        "usage_basis",
        "privacy_classification",
        "provenance",
        "stable_source_id",
        "content_hash",
        "metadata_hash",
        "source_hash",
        "acquisition_timestamp",
        "acquisition_method",
        "trust_tier",
    }
    missing = sorted(required - candidate.keys())
    if missing:
        raise EvidenceFactoryError(f"candidate missing required fields: {', '.join(missing)}")
    if candidate["trust_tier"] != TrustTier.RAW_CANDIDATE:
        raise EvidenceFactoryError("acquisition may only produce RAW_CANDIDATE")
    if candidate["language"] not in SUPPORTED_LANGUAGES:
        raise EvidenceFactoryError(f"unsupported language: {candidate['language']}")
    if candidate["exact_or_paraphrase"] not in {"exact", "paraphrase"}:
        raise EvidenceFactoryError("exact_or_paraphrase must be exact or paraphrase")
    if candidate["privacy_classification"] not in {"PUBLIC", "SENSITIVE", "UNCERTAIN"}:
        raise EvidenceFactoryError("invalid privacy_classification")
    if candidate["content_hash"] != hashlib.sha256(candidate["text"].encode()).hexdigest():
        raise EvidenceFactoryError("candidate content hash mismatch")
    if candidate["metadata_hash"] != canonical_hash(_metadata_binding(candidate)):
        raise EvidenceFactoryError("candidate metadata hash mismatch")
    source_binding = {
        "stable_source_id": candidate["stable_source_id"],
        "reference": candidate["source_url_or_reference"],
        "location": candidate["source_location"],
        "content_hash": candidate["content_hash"],
    }
    if candidate["source_hash"] != canonical_hash(source_binding):
        raise EvidenceFactoryError("candidate source binding mismatch")


def _candidate_from_input(raw: dict[str, Any], method: str, timestamp: str) -> dict[str, Any]:
    text = raw.get("text")
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > MAX_SOURCE_BYTES:
        raise EvidenceFactoryError("candidate text must be non-empty and bounded")
    language = raw.get("language", "en")
    reference = str(raw.get("source_url_or_reference") or raw.get("source") or "user-supplied")
    location = str(raw.get("source_location") or "whole-record")
    stable_source_id = str(raw.get("stable_source_id") or canonical_hash(reference)[:24])
    content_hash = hashlib.sha256(text.encode()).hexdigest()
    candidate_id = (
        "cand-"
        + canonical_hash(
            {
                "stable_source_id": stable_source_id,
                "location": location,
                "content_hash": content_hash,
            }
        )[:24]
    )
    privacy = raw.get("privacy_classification")
    if privacy is None:
        privacy = "SENSITIVE" if _SECRET.search(text) else "PUBLIC"
    candidate: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "text": text,
        "language": language,
        "source_type": str(raw.get("source_type") or "user-supplied"),
        "source_publisher": str(raw.get("source_publisher") or "unknown"),
        "source_title": str(raw.get("source_title") or "untitled"),
        "source_url_or_reference": reference,
        "source_location": location,
        "publication_date": raw.get("publication_date"),
        "exact_or_paraphrase": str(raw.get("exact_or_paraphrase") or "exact"),
        "usage_basis": str(raw.get("usage_basis") or "unknown"),
        "privacy_classification": privacy,
        "provenance": str(raw.get("provenance") or reference),
        "stable_source_id": stable_source_id,
        "content_hash": content_hash,
        "acquisition_timestamp": timestamp,
        "acquisition_method": method,
        "acquisition_intent": raw.get("acquisition_intent"),
        "trust_tier": TrustTier.RAW_CANDIDATE.value,
    }
    candidate["source_hash"] = canonical_hash(
        {
            "stable_source_id": stable_source_id,
            "reference": reference,
            "location": location,
            "content_hash": content_hash,
        }
    )
    candidate["metadata_hash"] = canonical_hash(_metadata_binding(candidate))
    validate_candidate(candidate)
    return candidate


def _safe_public_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise EvidenceFactoryError("public acquisition requires an http(s) URL")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EvidenceFactoryError(
            f"source hostname cannot be resolved: {parsed.hostname}"
        ) from exc
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise EvidenceFactoryError(
                "private, loopback, link-local, and reserved sources are blocked"
            )


def _acquire_web_source(source: dict[str, Any]) -> dict[str, Any]:
    url = source.get("url")
    if not isinstance(url, str):
        raise EvidenceFactoryError("web source requires url")
    _safe_public_url(url)

    class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            req: urllib.request.Request,
            fp: Any,
            code: int,
            msg: str,
            headers: Any,
            newurl: str,
        ) -> urllib.request.Request | None:
            _safe_public_url(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    request = urllib.request.Request(url, headers={"User-Agent": "SecureInjections/0.4.2 evidence"})
    opener = urllib.request.build_opener(SafeRedirectHandler())
    with opener.open(request, timeout=15) as response:  # noqa: S310 - every hop guarded
        data = response.read(MAX_SOURCE_BYTES + 1)
        final_url = response.geturl()
    if len(data) > MAX_SOURCE_BYTES:
        raise EvidenceFactoryError("source exceeds acquisition size limit")
    if urllib.parse.urlparse(final_url).hostname != urllib.parse.urlparse(url).hostname:
        _safe_public_url(final_url)
    text = data.decode("utf-8", errors="replace")
    return {
        **source,
        "text": text,
        "source_type": source.get("source_type", "public-web"),
        "source_url_or_reference": final_url,
        "stable_source_id": source.get("stable_source_id", canonical_hash(final_url)[:24]),
    }


def acquire(
    *,
    inputs: tuple[Path, ...] = (),
    source_config: Path | None = None,
    output: Path,
    offline: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    raw_rows = [row for path in inputs for row in _read_jsonl(path)]
    if source_config is not None:
        parsed = bounded_safe_load(source_config.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or not isinstance(parsed.get("sources"), list):
            raise EvidenceFactoryError("source config must contain a sources list")
        for source in parsed["sources"]:
            if not isinstance(source, dict):
                raise EvidenceFactoryError("source config entries must be mappings")
            if "url" in source:
                if offline:
                    raise EvidenceFactoryError("network source requested in offline mode")
                raw_rows.append(_acquire_web_source(source))
            elif "path" in source:
                path = Path(str(source["path"]))
                if not path.is_absolute():
                    path = source_config.parent / path
                for row in _read_jsonl(path):
                    raw_rows.append({**source, **row})
            else:
                raise EvidenceFactoryError("source requires url or path")
    timestamp = _utc_now()
    existing = {row.get("candidate_id"): row for row in _read_jsonl(output)}
    acquired: list[dict[str, Any]] = []
    for raw in raw_rows:
        candidate = _candidate_from_input(
            raw, "public-web" if "url" in raw else "local-ingest", timestamp
        )
        prior = existing.get(candidate["candidate_id"])
        if prior:
            validate_candidate(prior)
            if prior["content_hash"] != candidate["content_hash"]:
                raise EvidenceFactoryError("stable candidate id collision")
            continue
        existing[candidate["candidate_id"]] = candidate
        acquired.append(candidate)
    if not dry_run:
        _write_jsonl(output, acquired, append=output.exists())
    return _mutation_counts(
        candidates_processed=len(raw_rows),
        new_raw_candidates=len(acquired),
        existing_candidates=len(raw_rows) - len(acquired),
        proposed_trust_tier_changes={TrustTier.RAW_CANDIDATE.value: len(acquired)},
        dry_run=dry_run,
    )


def _review_prompt(
    candidate: dict[str, Any],
    reviewer_pass: str,
    config: dict[str, Any],
    *,
    reviewer_contract_version: str = REVIEWER_CONTRACT_V1,
    trusted_comparisons: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    # acquisition_intent is deliberately absent. Pass identity prevents prompt reuse across A/B.
    candidate_envelope = {
        key: candidate.get(key)
        for key in (
            "candidate_id",
            "text",
            "language",
            "source_type",
            "source_publisher",
            "source_title",
            "source_url_or_reference",
            "source_location",
            "publication_date",
            "exact_or_paraphrase",
            "usage_basis",
            "privacy_classification",
            "provenance",
            "stable_source_id",
            "content_hash",
            "metadata_hash",
            "source_hash",
        )
    }
    if reviewer_contract_version == REVIEWER_CONTRACT_V1:
        # Keep this historical envelope byte-for-byte reconstructable for Pilot 01.
        return {
            "workflow_version": EVIDENCE_WORKFLOW_VERSION,
            "taxonomy_version": TAXONOMY_VERSION,
            "reviewer_pass": reviewer_pass,
            "instruction": (
                "Classify the text as presented, not merely behavior it describes. Incident "
                "reports and quoted attacks can be benign; operative instructions and payloads "
                "can be malicious."
            ),
            "candidate": candidate_envelope,
            "review_config": config,
            "required_output_fields": sorted(REVIEW_FIELDS),
        }
    if reviewer_contract_version != REVIEWER_CONTRACT_V2:
        raise EvidenceFactoryError("unsupported reviewer semantic contract")
    contract_hash = canonical_hash(V2_CONTRACT_SPEC)
    return {
        "workflow_version": EVIDENCE_WORKFLOW_VERSION,
        "taxonomy_version": TAXONOMY_VERSION,
        "reviewer_pass": reviewer_pass,
        "reviewer_contract_version": REVIEWER_CONTRACT_V2,
        "reviewer_contract_hash": contract_hash,
        "instruction": (
            "Follow the ordered semantic contract. Classify the text as presented. Determine "
            "context, action, target, effect, intent, and target/effect-precedence family before "
            "relationship and independence. INDEPENDENT requires affirmative novelty evidence "
            "against every supplied trusted comparison; absent or conflicting evidence must be "
            "UNCERTAIN."
        ),
        "semantic_contract": V2_CONTRACT_SPEC,
        "candidate": candidate_envelope,
        "trusted_concept_comparisons": trusted_comparisons or [],
        "review_config": config,
        "required_output_fields": sorted(required_review_fields(REVIEWER_CONTRACT_V2)),
    }


def _bounded_trusted_comparisons(
    candidate: dict[str, Any], trusted_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    scored = sorted(
        (
            (_similarity(str(candidate["text"]), str(row.get("text", ""))), row)
            for row in trusted_rows
        ),
        key=lambda item: (-item[0], str(item[1].get("concept_id", ""))),
    )
    comparisons: list[dict[str, Any]] = []
    seen_concepts: set[str] = set()
    for similarity, row in scored:
        concept_id = str(row.get("concept_id", ""))
        if not concept_id or concept_id in seen_concepts:
            continue
        seen_concepts.add(concept_id)
        comparisons.append(
            {
                "case_id": row.get("case_id", row.get("candidate_id")),
                "concept_id": concept_id,
                "binary_label": row.get("binary_label"),
                "classifier_family": row.get("classifier_family"),
                "template_family": row.get("template_family"),
                "paraphrase_group": row.get("paraphrase_group"),
                "translation_group": row.get("translation_group"),
                "source_family": row.get("source_family"),
                "lexical_similarity": round(similarity, 6),
                "comparison_excerpt": str(row.get("text", ""))[:280],
            }
        )
        if len(comparisons) == MAX_TRUSTED_COMPARISONS:
            break
    return comparisons


def review_auto(
    candidates_path: Path,
    responses_path: Path,
    output: Path,
    *,
    reviewer_pass: str,
    reviewer_id: str,
    config: dict[str, Any] | None = None,
    reviewer_contract_version: str = REVIEWER_CONTRACT_V1,
    trusted_corpora: tuple[Path, ...] = (),
    dry_run: bool = False,
) -> dict[str, Any]:
    if reviewer_pass not in {"A", "B"}:
        raise EvidenceFactoryError("reviewer pass must be A or B")
    candidates = {row["candidate_id"]: row for row in _read_jsonl(candidates_path)}
    for candidate in candidates.values():
        validate_candidate(candidate)
    responses = _read_jsonl(responses_path)
    if reviewer_contract_version not in REVIEWER_CONTRACT_VERSIONS:
        raise EvidenceFactoryError("unsupported reviewer semantic contract")
    trusted_rows = [row for path in trusted_corpora for row in _read_jsonl(path)]
    existing = _read_jsonl(output)
    if any(row.get("reviewer_pass") != reviewer_pass for row in existing):
        raise EvidenceFactoryError("review output is bound to a different isolated pass")
    existing_ids = {row.get("review_id") for row in existing}
    by_candidate: dict[str, dict[str, Any]] = {}
    for incoming_response in responses:
        candidate_id = incoming_response.get("candidate_id")
        if candidate_id in by_candidate:
            raise EvidenceFactoryError(f"duplicate response for candidate: {candidate_id}")
        by_candidate[str(candidate_id)] = incoming_response
    config = config or {}
    contract_hash = (
        canonical_hash(V2_CONTRACT_SPEC)
        if reviewer_contract_version == REVIEWER_CONTRACT_V2
        else None
    )
    config_hash = (
        canonical_hash(
            {
                "reviewer_contract_version": reviewer_contract_version,
                "reviewer_contract_hash": contract_hash,
                "review_config": config,
            }
        )
        if reviewer_contract_version == REVIEWER_CONTRACT_V2
        else canonical_hash(config)
    )
    additions: list[dict[str, Any]] = []
    for candidate_id, candidate in sorted(candidates.items()):
        response = by_candidate.get(candidate_id)
        if response is None:
            continue
        trusted_comparisons = _bounded_trusted_comparisons(candidate, trusted_rows)
        fields = required_review_fields(reviewer_contract_version)
        semantic = {key: response.get(key) for key in fields}
        missing = sorted(key for key in fields if key not in response)
        if missing:
            raise EvidenceFactoryError(f"review response missing fields: {', '.join(missing)}")
        for field in (
            "semantic_concept_summary",
            "proposed_concept_id",
            "template_family",
            "source_family",
            "difficulty",
            "rationale",
        ):
            value = semantic[field]
            if not isinstance(value, str) or not value.strip():
                raise EvidenceFactoryError(f"review field must be a non-empty string: {field}")
        for field in ("paraphrase_relationship", "translation_relationship"):
            value = semantic[field]
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise EvidenceFactoryError(f"review relationship must be string or null: {field}")
        if semantic["semantic_independence"] not in {
            "INDEPENDENT",
            "NOT_INDEPENDENT",
            "UNCERTAIN",
        }:
            raise EvidenceFactoryError("invalid semantic_independence assessment")
        if semantic["privacy_assessment"] not in {"ACCEPTABLE", "REJECTED", "UNCERTAIN"}:
            raise EvidenceFactoryError("invalid privacy assessment")
        if semantic["usage_rights_assessment"] not in {
            "ACCEPTABLE",
            "REJECTED",
            "UNCERTAIN",
        }:
            raise EvidenceFactoryError("invalid usage-rights assessment")
        if not isinstance(semantic["ambiguity"], bool):
            raise EvidenceFactoryError("ambiguity must be boolean")
        confidence = semantic["confidence"]
        if (
            not isinstance(confidence, int | float)
            or isinstance(confidence, bool)
            or not 0 <= confidence <= 1
        ):
            raise EvidenceFactoryError("confidence must be between zero and one")
        taxonomy_valid = True
        try:
            validate_label_family(semantic["binary_label"], semantic["classifier_family"])
        except ValueError:
            taxonomy_valid = False
        if reviewer_contract_version == REVIEWER_CONTRACT_V2:
            try:
                validate_v2_response(semantic, trusted_comparisons)
            except ReviewerContractError as exc:
                raise EvidenceFactoryError(str(exc)) from exc
        prompt = _review_prompt(
            candidate,
            reviewer_pass,
            config,
            reviewer_contract_version=reviewer_contract_version,
            trusted_comparisons=trusted_comparisons,
        )
        prompt_hash = canonical_hash(prompt)
        response_hash = canonical_hash(semantic)
        review_id = (
            "review-"
            + canonical_hash(
                {
                    "candidate_id": candidate_id,
                    "pass": reviewer_pass,
                    "reviewer_id": reviewer_id,
                    "prompt_hash": prompt_hash,
                    "response_hash": response_hash,
                    "supersedes_review_id": response.get("supersedes_review_id"),
                }
            )[:24]
        )
        if review_id in existing_ids:
            continue
        review = {
            "schema_version": (
                2 if reviewer_contract_version == REVIEWER_CONTRACT_V2 else EVIDENCE_SCHEMA_VERSION
            ),
            "review_id": review_id,
            "candidate_id": candidate_id,
            "reviewer_pass": reviewer_pass,
            "reviewer_id": reviewer_id,
            "candidate_content_hash": candidate["content_hash"],
            "candidate_metadata_hash": candidate["metadata_hash"],
            "prompt_hash": prompt_hash,
            "config_hash": config_hash,
            "response_hash": response_hash,
            "taxonomy_version": TAXONOMY_VERSION,
            "taxonomy_valid": taxonomy_valid,
            "supersedes_review_id": response.get("supersedes_review_id"),
            "review": semantic,
            "trust_tier": TrustTier.MODEL_REVIEWED.value,
        }
        if reviewer_contract_version == REVIEWER_CONTRACT_V2:
            review.update(
                {
                    "reviewer_contract_version": reviewer_contract_version,
                    "reviewer_contract_hash": contract_hash,
                    "trusted_comparison_set": trusted_comparisons,
                    "trusted_comparison_set_hash": canonical_hash(trusted_comparisons),
                    "trusted_corpora_hashes": [
                        hashlib.sha256(path.read_bytes()).hexdigest() for path in trusted_corpora
                    ],
                }
            )
        review["review_hash"] = canonical_hash(review)
        additions.append(review)
        existing_ids.add(review_id)
    if not dry_run:
        _write_jsonl(output, additions, append=output.exists())
    return _mutation_counts(
        candidates_processed=len(candidates),
        responses_processed=len(responses),
        reviews_appended=len(additions),
        reviews_already_present=len(candidates) - len(additions),
        reviewer_pass=reviewer_pass,
        proposed_trust_tier_changes={TrustTier.MODEL_REVIEWED.value: len(additions)},
        dry_run=dry_run,
    )


def _normalize(text: str) -> str:
    return " ".join(_TOKEN.findall(text.casefold()))


def _structural(text: str) -> str:
    return re.sub(r"\b(?:\d+|[0-9a-f]{8,})\b", "<value>", _normalize(text))


def _similarity(left: str, right: str) -> float:
    left_tokens, right_tokens = set(_normalize(left).split()), set(_normalize(right).split())
    union = left_tokens | right_tokens
    return len(left_tokens & right_tokens) / len(union) if union else 1.0


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    raw = bounded_safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise EvidenceFactoryError("unsupported evidence trust policy")
    auto = raw.get("auto_promote")
    if not isinstance(auto, dict) or auto.get("required_review_passes") != 2:
        raise EvidenceFactoryError("policy must require exactly two isolated review passes")
    required_true = {
        "require_binary_label_agreement",
        "require_classifier_family_agreement",
        "require_independence_agreement",
        "require_privacy_accept",
        "require_usage_rights_accept",
        "require_provenance_complete",
        "require_hash_binding",
        "require_deterministic_leakage_pass",
    }
    if any(auto.get(key) is not True for key in required_true):
        raise EvidenceFactoryError("policy weakens a mandatory machine-trust requirement")
    if any(
        auto.get(key) is not False
        for key in (
            "allow_ambiguous",
            "allow_unknown_usage_rights",
            "allow_privacy_uncertain",
            "allow_reviewer_disagreement",
        )
    ):
        raise EvidenceFactoryError("policy must fail closed on ambiguity and uncertainty")
    near = raw.get("near_duplicate_similarity")
    boundary = raw.get("high_similarity_boundary")
    if (
        not isinstance(near, int | float)
        or isinstance(near, bool)
        or not isinstance(boundary, int | float)
        or isinstance(boundary, bool)
        or not 0 <= boundary < near <= 1
    ):
        raise EvidenceFactoryError(
            "policy similarity boundaries must satisfy 0 <= high < near <= 1"
        )
    return raw, canonical_hash(raw)


def _protected_overlap(
    candidate: dict[str, Any], review: dict[str, Any], rows: list[dict[str, Any]]
) -> list[str]:
    fields = {
        "case_id": candidate["candidate_id"],
        "content_hash": candidate["content_hash"],
        "concept": review.get("proposed_concept_id"),
        "paraphrase": review.get("paraphrase_relationship"),
        "translation": review.get("translation_relationship"),
        "template": review.get("template_family"),
        "lineage": candidate.get("parent_case_id"),
    }
    aliases = {
        "case_id": ("case_id", "candidate_id", "id"),
        "content_hash": ("content_hash", "original_content_hash"),
        "concept": ("concept_id", "proposed_concept_id"),
        "paraphrase": ("paraphrase_group", "paraphrase_relationship"),
        "translation": ("translation_group", "translation_relationship"),
        "template": ("template_family",),
        "lineage": ("parent_case_id", "lineage"),
    }
    overlaps: list[str] = []
    for name, value in fields.items():
        if value and any(value == row.get(alias) for row in rows for alias in aliases[name]):
            overlaps.append(name)
    if any(_similarity(candidate["text"], str(row.get("text", ""))) >= 0.86 for row in rows):
        overlaps.append("near_duplicate")
    return overlaps


def _deterministic_gates(
    candidate: dict[str, Any],
    review: dict[str, Any],
    reference_rows: list[dict[str, Any]],
    protected_rows: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str], bool]:
    gates: dict[str, dict[str, Any]] = {}

    def gate(name: str, passed: bool, detail: object = None) -> None:
        gates[name] = {"passed": passed, "detail": detail}

    try:
        validate_candidate(candidate)
        schema_ok = True
    except EvidenceFactoryError:
        schema_ok = False
    gate("schema_validation", schema_ok)
    gate("trust_tier_validation", candidate.get("trust_tier") == TrustTier.RAW_CANDIDATE)
    gate(
        "content_hash",
        candidate.get("content_hash") == hashlib.sha256(candidate["text"].encode()).hexdigest(),
    )
    gate(
        "metadata_hash",
        candidate.get("metadata_hash") == canonical_hash(_metadata_binding(candidate)),
    )
    expected_source_hash = canonical_hash(
        {
            "stable_source_id": candidate.get("stable_source_id"),
            "reference": candidate.get("source_url_or_reference"),
            "location": candidate.get("source_location"),
            "content_hash": candidate.get("content_hash"),
        }
    )
    gate("source_binding", candidate.get("source_hash") == expected_source_hash)
    provenance = all(
        candidate.get(key) not in (None, "", "unknown")
        for key in (
            "source_type",
            "source_publisher",
            "source_title",
            "source_url_or_reference",
            "source_location",
            "provenance",
            "stable_source_id",
            "usage_basis",
        )
    )
    gate("provenance_completeness", provenance)
    gate(
        "privacy",
        review.get("privacy_assessment") == "ACCEPTABLE"
        and candidate.get("privacy_classification") == "PUBLIC",
    )
    gate(
        "usage_rights",
        review.get("usage_rights_assessment") == "ACCEPTABLE"
        and candidate.get("usage_basis") != "unknown",
    )
    exact = [row for row in reference_rows if row.get("text") == candidate["text"]]
    normalized = [
        row
        for row in reference_rows
        if _normalize(str(row.get("text", ""))) == _normalize(candidate["text"])
    ]
    structural = [
        row
        for row in reference_rows
        if _structural(str(row.get("text", ""))) == _structural(candidate["text"])
    ]
    scores = [
        (_similarity(candidate["text"], str(row.get("text", ""))), row) for row in reference_rows
    ]
    nearest_score, nearest = max(scores, default=(0.0, {}), key=lambda item: item[0])
    near_limit = float(policy.get("near_duplicate_similarity", 0.86))
    boundary = float(policy.get("high_similarity_boundary", 0.72))
    gate(
        "exact_duplicate", not exact, [row.get("case_id", row.get("candidate_id")) for row in exact]
    )
    gate(
        "normalized_duplicate",
        not normalized,
        [row.get("case_id", row.get("candidate_id")) for row in normalized],
    )
    gate(
        "structural_duplicate",
        not structural,
        [row.get("case_id", row.get("candidate_id")) for row in structural],
    )
    gate("near_duplicate", nearest_score < near_limit, round(nearest_score, 6))
    gate(
        "semantic_nearest_neighbor_audit",
        True,
        {
            "similarity": round(nearest_score, 6),
            "id": nearest.get("case_id", nearest.get("candidate_id")),
        },
    )
    relationship_fields = {
        "concept_collision": ("concept_id", review.get("proposed_concept_id")),
        "paraphrase_relation": ("paraphrase_group", review.get("paraphrase_relationship")),
        "translation_relation": ("translation_group", review.get("translation_relationship")),
        "template_relation": ("template_family", review.get("template_family")),
        "lineage_relation": ("parent_case_id", candidate.get("parent_case_id")),
    }
    for gate_name, (field, value) in relationship_fields.items():
        collisions = [
            row.get("case_id", row.get("candidate_id"))
            for row in reference_rows
            if value and row.get(field) == value
        ]
        gate(gate_name, not collisions, collisions)
    conflicting = [
        row
        for row in (*exact, *normalized, *structural)
        if row.get("binary_label") not in (None, review.get("binary_label"))
    ]
    gate(
        "conflicting_label",
        not conflicting,
        [row.get("case_id", row.get("candidate_id")) for row in conflicting],
    )
    protected = _protected_overlap(candidate, review, protected_rows)
    gate("protected_evaluation_contamination", not protected, protected)
    queue_reasons: list[str] = []
    if boundary <= nearest_score < near_limit:
        queue_reasons.append(QueueReason.HIGH_SIMILARITY_BOUNDARY.value)
    if protected:
        queue_reasons.append(QueueReason.PROTECTED_EVALUATION_OVERLAP.value)
    passed = all(item["passed"] for item in gates.values()) and not queue_reasons
    return gates, queue_reasons, passed


def _active_reviews(path: Path, expected_pass: str) -> dict[str, dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _read_jsonl(path):
        if row.get("reviewer_pass") != expected_pass:
            raise EvidenceFactoryError(f"review file contains pass other than {expected_pass}")
        if row.get("trust_tier") != TrustTier.MODEL_REVIEWED:
            raise EvidenceFactoryError("invalid review trust tier")
        if row.get("review_hash") != canonical_hash(
            {key: value for key, value in row.items() if key != "review_hash"}
        ):
            raise EvidenceFactoryError("review hash mismatch")
        try:
            contract_version = record_contract_version(row)
        except ReviewerContractError as exc:
            raise EvidenceFactoryError(str(exc)) from exc
        if contract_version == REVIEWER_CONTRACT_V2:
            comparisons = row.get("trusted_comparison_set")
            if not isinstance(comparisons, list):
                raise EvidenceFactoryError("v2 review is missing its trusted comparison set")
            if row.get("reviewer_contract_hash") != canonical_hash(V2_CONTRACT_SPEC):
                raise EvidenceFactoryError("v2 reviewer contract hash mismatch")
            if row.get("trusted_comparison_set_hash") != canonical_hash(comparisons):
                raise EvidenceFactoryError("v2 trusted comparison set hash mismatch")
            try:
                validate_v2_response(row.get("review", {}), comparisons)
            except ReviewerContractError as exc:
                raise EvidenceFactoryError(str(exc)) from exc
        rows.append(row)
    by_id = {str(row["review_id"]): row for row in rows}
    if len(by_id) != len(rows):
        raise EvidenceFactoryError("duplicate review IDs")
    superseded: set[str] = set()
    for row in rows:
        predecessor_id = row.get("supersedes_review_id")
        if predecessor_id is None:
            continue
        predecessor = by_id.get(str(predecessor_id))
        if predecessor is None:
            raise EvidenceFactoryError("review supersedes an unknown review ID")
        if predecessor["candidate_id"] != row["candidate_id"]:
            raise EvidenceFactoryError("review cannot supersede another candidate")
        superseded.add(str(predecessor_id))
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["review_id"] in superseded:
            continue
        candidate_id = str(row.get("candidate_id"))
        if candidate_id in result:
            raise EvidenceFactoryError(
                f"multiple active pass {expected_pass} reviews for {candidate_id}"
            )
        result[candidate_id] = row
    return result


@dataclass(frozen=True, slots=True)
class ConsensusResult:
    decisions: tuple[dict[str, Any], ...]
    queue: tuple[dict[str, Any], ...]
    audit: dict[str, Any]


def consensus(
    candidates_path: Path,
    review_a_path: Path,
    review_b_path: Path,
    policy_path: Path,
    trusted_corpora: tuple[Path, ...] = (),
    protected_corpora: tuple[Path, ...] = (),
    relationship_consensus_contract: str = RELATIONSHIP_CONSENSUS_V1,
) -> ConsensusResult:
    if relationship_consensus_contract not in RELATIONSHIP_CONSENSUS_VERSIONS:
        raise EvidenceFactoryError("unsupported relationship-consensus version")
    candidates = {row["candidate_id"]: row for row in _read_jsonl(candidates_path)}
    review_a, review_b = _active_reviews(review_a_path, "A"), _active_reviews(review_b_path, "B")
    policy, policy_hash = load_policy(policy_path)
    trusted_rows = [row for path in trusted_corpora for row in _read_jsonl(path)]
    protected_rows = [row for path in protected_corpora for row in _read_jsonl(path)]
    decisions: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []
    metrics: Counter[str] = Counter()
    for candidate_id, candidate in sorted(candidates.items()):
        validate_candidate(candidate)
        left, right = review_a.get(candidate_id), review_b.get(candidate_id)
        reasons: list[str] = []
        if left is None or right is None:
            reasons.append(QueueReason.DETERMINISTIC_GATE_FAILURE.value)
            review = {}
            gates: dict[str, dict[str, Any]] = {}
            gates_passed = False
            structured_relationship: dict[str, Any] | None = None
            canonical_concept_id: str | None = None
        else:
            for item in (left, right):
                if (
                    item["candidate_content_hash"] != candidate["content_hash"]
                    or item["candidate_metadata_hash"] != candidate["metadata_hash"]
                ):
                    raise EvidenceFactoryError("review/candidate hash binding mismatch")
            a, b = left["review"], right["review"]
            review = a
            try:
                left_contract = record_contract_version(left)
                right_contract = record_contract_version(right)
            except ReviewerContractError as exc:
                raise EvidenceFactoryError(str(exc)) from exc
            if left_contract != right_contract:
                reasons.append(QueueReason.REVIEWER_CONTRACT_MISMATCH.value)
            if relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V2 and (
                left_contract != REVIEWER_CONTRACT_V2 or right_contract != REVIEWER_CONTRACT_V2
            ):
                reasons.append(QueueReason.REVIEWER_CONTRACT_MISMATCH.value)
            if not left["taxonomy_valid"] or not right["taxonomy_valid"]:
                reasons.append(QueueReason.TAXONOMY_AMBIGUOUS.value)
                metrics["taxonomy_disagreements"] += 1
            if a["binary_label"] != b["binary_label"]:
                reasons.append(QueueReason.LABEL_DISAGREEMENT.value)
                metrics["label_disagreements"] += 1
            if a["classifier_family"] != b["classifier_family"]:
                reasons.append(QueueReason.FAMILY_DISAGREEMENT.value)
                metrics["family_disagreements"] += 1
            structured_relationship = None
            canonical_concept_id = None
            if relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V1:
                if (
                    a["semantic_independence"] != b["semantic_independence"]
                    or a["semantic_independence"] != "INDEPENDENT"
                ):
                    reasons.append(QueueReason.INDEPENDENCE_UNCERTAIN.value)
                    metrics["independence_failures"] += 1
            else:
                structured_relationship = structured_relationship_consensus(candidate_id, a, b)
                canonical_concept_id = structured_relationship["canonical_concept_id"]
                relationship_codes = set(structured_relationship["reason_codes"])
                relationship_reason_map = {
                    "MATERIAL_RELATIONSHIP_DISAGREEMENT": (
                        QueueReason.MATERIAL_RELATIONSHIP_DISAGREEMENT.value
                    ),
                    "RELATIONSHIP_UNCERTAIN": QueueReason.RELATIONSHIP_UNCERTAIN.value,
                    "TRUSTED_CONCEPT_RELATIONSHIP_CONFLICT": (
                        QueueReason.TRUSTED_CONCEPT_RELATIONSHIP_CONFLICT.value
                    ),
                    "INDEPENDENCE_DISAGREEMENT": QueueReason.INDEPENDENCE_DISAGREEMENT.value,
                }
                reasons.extend(
                    reason
                    for code, reason in relationship_reason_map.items()
                    if code in relationship_codes
                )
                if a["semantic_independence"] != b["semantic_independence"]:
                    metrics["independence_failures"] += 1
                elif a["semantic_independence"] != "INDEPENDENT":
                    reasons.append(QueueReason.INDEPENDENCE_UNCERTAIN.value)
                    metrics["independence_failures"] += 1
            if (
                a["privacy_assessment"] != "ACCEPTABLE"
                or b["privacy_assessment"] != "ACCEPTABLE"
                or candidate["privacy_classification"] != "PUBLIC"
            ):
                reasons.append(QueueReason.PRIVACY_UNCERTAIN.value)
                metrics["privacy_failures"] += 1
            if (
                a["usage_rights_assessment"] != "ACCEPTABLE"
                or b["usage_rights_assessment"] != "ACCEPTABLE"
                or candidate["usage_basis"] == "unknown"
            ):
                reasons.append(QueueReason.USAGE_RIGHTS_UNCERTAIN.value)
                metrics["rights_failures"] += 1
            if candidate["usage_basis"] == "unknown":
                reasons.append(QueueReason.PROVENANCE_INCOMPLETE.value)
            if a["ambiguity"] is not False or b["ambiguity"] is not False:
                reasons.append(QueueReason.AMBIGUOUS.value)
            if relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V1:
                for field in (
                    "proposed_concept_id",
                    "paraphrase_relationship",
                    "translation_relationship",
                    "template_family",
                ):
                    if a.get(field) != b.get(field):
                        reasons.append(QueueReason.RELATIONSHIP_DISAGREEMENT.value)
                        break
                gate_review = review
            else:
                gate_review = {
                    **review,
                    "proposed_concept_id": canonical_concept_id,
                    "paraphrase_relationship": None,
                    "translation_relationship": None,
                    "template_family": (
                        structured_relationship["canonical_template_id"]
                        if structured_relationship
                        else deterministic_template_id(review)
                    ),
                }
            gates, gate_reasons, gates_passed = _deterministic_gates(
                candidate, gate_review, trusted_rows, protected_rows, policy
            )
            reasons.extend(gate_reasons)
            if not gates_passed and not gate_reasons:
                reasons.append(QueueReason.DETERMINISTIC_GATE_FAILURE.value)
        reasons = sorted(set(reasons))
        consensus_core = {
            "candidate_id": candidate_id,
            "candidate_content_hash": candidate["content_hash"],
            "candidate_metadata_hash": candidate["metadata_hash"],
            "reviewer_pass_a_id": left.get("review_id") if left else None,
            "reviewer_pass_b_id": right.get("review_id") if right else None,
            "review_a_hash": left.get("review_hash") if left else None,
            "review_b_hash": right.get("review_hash") if right else None,
            "policy_hash": policy_hash,
            "source_hash": candidate["source_hash"],
            "gates": gates,
            "queue_reasons": reasons,
            "eligible_for_machine_promotion": not reasons and gates_passed,
        }
        if relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V2:
            consensus_core.update(
                {
                    "relationship_consensus_version": RELATIONSHIP_CONSENSUS_V2,
                    "relationship_consensus_hash": RELATIONSHIP_CONSENSUS_V2_HASH,
                    "structured_relationship_consensus": structured_relationship,
                    "canonical_concept_id": canonical_concept_id,
                }
            )
        consensus_hash = canonical_hash(consensus_core)
        agreed_review = review if not reasons else None
        if (
            agreed_review is not None
            and relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V2
        ):
            assert structured_relationship is not None
            agreed_review = {
                **agreed_review,
                "proposed_concept_id": canonical_concept_id,
                "paraphrase_relationship": None,
                "translation_relationship": None,
                "template_family": structured_relationship["canonical_template_id"],
            }
        row = {
            "schema_version": (
                2
                if relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V2
                else EVIDENCE_SCHEMA_VERSION
            ),
            "consensus_id": "consensus-" + consensus_hash[:24],
            **consensus_core,
            "consensus_hash": consensus_hash,
            "candidate": candidate,
            "agreed_review": agreed_review,
            "trust_tier": TrustTier.MODEL_REVIEWED.value,
            "proposed_trust_tier": TrustTier.CONSENSUS_TRUSTED.value
            if not reasons and gates_passed
            else None,
        }
        decisions.append(row)
        if reasons:
            queue.append(row)
    processed = len(decisions)
    eligible = sum(bool(row["eligible_for_machine_promotion"]) for row in decisions)
    audit_core = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "workflow_version": EVIDENCE_WORKFLOW_VERSION,
        "policy_hash": policy_hash,
        "input_hashes": {
            "candidates": hashlib.sha256(candidates_path.read_bytes()).hexdigest(),
            "review_a": hashlib.sha256(review_a_path.read_bytes()).hexdigest(),
            "review_b": hashlib.sha256(review_b_path.read_bytes()).hexdigest(),
            "trusted_corpora": [
                hashlib.sha256(path.read_bytes()).hexdigest() for path in trusted_corpora
            ],
            "protected_corpora": [
                hashlib.sha256(path.read_bytes()).hexdigest() for path in protected_corpora
            ],
        },
        "candidates_processed": processed,
        "consensus_count": eligible,
        "human_queue_count": len(queue),
        "rejected_count": sum(
            QueueReason.PROTECTED_EVALUATION_OVERLAP.value in row["queue_reasons"] for row in queue
        ),
        "rights_failures": metrics["rights_failures"],
        "privacy_failures": metrics["privacy_failures"],
        "independence_failures": metrics["independence_failures"],
        "label_disagreements": metrics["label_disagreements"],
        "family_disagreements": metrics["family_disagreements"],
        "taxonomy_disagreements": metrics["taxonomy_disagreements"],
        "agreement_rate": eligible / processed if processed else 0.0,
        "human_escalation_rate": len(queue) / processed if processed else 0.0,
        "proposed_trust_tier_changes": {TrustTier.CONSENSUS_TRUSTED.value: eligible},
    }
    if relationship_consensus_contract == RELATIONSHIP_CONSENSUS_V2:
        audit_core.update(
            {
                "relationship_consensus_version": RELATIONSHIP_CONSENSUS_V2,
                "relationship_consensus_hash": RELATIONSHIP_CONSENSUS_V2_HASH,
                "structured_relationship_agreements": sum(
                    row.get("structured_relationship_consensus", {}).get("status")
                    in {"EXACT_AGREEMENT", "COMPATIBLE_NON_INDEPENDENT"}
                    for row in decisions
                ),
                "material_relationship_disagreements": sum(
                    QueueReason.MATERIAL_RELATIONSHIP_DISAGREEMENT.value in row["queue_reasons"]
                    for row in decisions
                ),
                "relationship_uncertainties": sum(
                    QueueReason.RELATIONSHIP_UNCERTAIN.value in row["queue_reasons"]
                    for row in decisions
                ),
            }
        )
    audit = {**audit_core, "audit_hash": canonical_hash(audit_core)}
    return ConsensusResult(tuple(decisions), tuple(queue), audit)


def write_consensus(
    result: ConsensusResult, decisions: Path, queue: Path, audit: Path, *, dry_run: bool = False
) -> None:
    if dry_run:
        return
    _write_jsonl(decisions, result.decisions)
    _write_jsonl(queue, result.queue)
    _write_json(audit, result.audit)


def promote_machine(consensus_path: Path, output: Path, *, dry_run: bool = False) -> dict[str, Any]:
    decisions = _read_jsonl(consensus_path)
    try:
        consensus_versions = {relationship_consensus_version(row) for row in decisions}
    except ValueError as exc:
        raise EvidenceFactoryError(str(exc)) from exc
    if len(consensus_versions) > 1:
        raise EvidenceFactoryError("mixed relationship-consensus versions cannot be promoted")
    consensus_version = next(iter(consensus_versions), RELATIONSHIP_CONSENSUS_V1)
    if consensus_version == RELATIONSHIP_CONSENSUS_V2:
        for decision in decisions:
            if decision.get("relationship_consensus_hash") != RELATIONSHIP_CONSENSUS_V2_HASH:
                raise EvidenceFactoryError("relationship-consensus v2 hash mismatch")
    existing = _read_jsonl(output)
    promoted_ids = {row.get("consensus_id") for row in existing}
    promoted_bindings = {
        (row.get("candidate_id", row.get("case_id")), row.get("content_hash")) for row in existing
    }
    additions: list[dict[str, Any]] = []
    for decision in decisions:
        if not decision.get("eligible_for_machine_promotion"):
            continue
        if decision.get("proposed_trust_tier") != TrustTier.CONSENSUS_TRUSTED:
            raise EvidenceFactoryError("consensus decision is not bound for machine trust")
        core = {
            key: decision[key]
            for key in (
                "candidate_id",
                "candidate_content_hash",
                "candidate_metadata_hash",
                "reviewer_pass_a_id",
                "reviewer_pass_b_id",
                "review_a_hash",
                "review_b_hash",
                "consensus_hash",
                "policy_hash",
                "source_hash",
            )
        }
        if not all(item.get("passed") for item in decision.get("gates", {}).values()):
            raise EvidenceFactoryError("machine promotion requires every deterministic gate")
        candidate_binding = (decision["candidate_id"], decision["candidate_content_hash"])
        if decision["consensus_id"] in promoted_ids or candidate_binding in promoted_bindings:
            continue
        candidate, review = decision["candidate"], decision["agreed_review"]
        record = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "case_id": candidate["candidate_id"],
            "text": candidate["text"],
            "language": candidate["language"],
            "binary_label": review["binary_label"],
            "classifier_family": review["classifier_family"],
            "concept_id": (
                decision.get("canonical_concept_id")
                if consensus_version == RELATIONSHIP_CONSENSUS_V2
                else review["proposed_concept_id"]
            ),
            "paraphrase_group": review["paraphrase_relationship"],
            "translation_group": review["translation_relationship"],
            "template_family": review["template_family"],
            "source_family": review["source_family"],
            "hard_negative_category": review["hard_negative_category"],
            "difficulty": review["difficulty"],
            "provenance": {
                key: candidate.get(key)
                for key in (
                    "source_type",
                    "source_publisher",
                    "source_title",
                    "source_url_or_reference",
                    "source_location",
                    "publication_date",
                    "exact_or_paraphrase",
                    "usage_basis",
                    "privacy_classification",
                    "provenance",
                    "stable_source_id",
                    "acquisition_timestamp",
                    "acquisition_method",
                )
            },
            **core,
            "consensus_id": decision["consensus_id"],
            "content_hash": candidate["content_hash"],
            "metadata_hash": candidate["metadata_hash"],
            "promotion_timestamp": _utc_now(),
            "workflow_version": EVIDENCE_WORKFLOW_VERSION,
            "trust_tier": TrustTier.CONSENSUS_TRUSTED.value,
            "deterministic_gates": decision["gates"],
            "deterministic_gates_hash": canonical_hash(decision["gates"]),
        }
        if consensus_version == RELATIONSHIP_CONSENSUS_V2:
            record.update(
                {
                    "relationship_consensus_version": RELATIONSHIP_CONSENSUS_V2,
                    "relationship_consensus_hash": RELATIONSHIP_CONSENSUS_V2_HASH,
                    "structured_relationship_consensus_hash": decision[
                        "structured_relationship_consensus"
                    ]["structured_relationship_hash"],
                }
            )
        record["promotion_record_hash"] = canonical_hash(record)
        additions.append(record)
        promoted_ids.add(decision["consensus_id"])
        promoted_bindings.add(candidate_binding)
    if not dry_run:
        _write_jsonl(output, additions, append=output.exists())
    return {
        "candidates_processed": len(_read_jsonl(consensus_path)),
        "consensus_count": len(additions),
        "human_queue_count": 0,
        "rejected_count": 0,
        "rights_failures": 0,
        "privacy_failures": 0,
        "independence_failures": 0,
        "label_disagreements": 0,
        "family_disagreements": 0,
        "proposed_trust_tier_changes": {TrustTier.CONSENSUS_TRUSTED.value: len(additions)},
        "dry_run": dry_run,
    }


def queue_human(queue_path: Path, output: Path, *, dry_run: bool = False) -> dict[str, Any]:
    units: list[dict[str, Any]] = []
    for index, row in enumerate(_read_jsonl(queue_path)):
        candidate = row["candidate"]
        source_binding = f"{output.resolve().as_posix()}#review-unit-{index}"
        legacy_metadata = {
            "id": candidate["candidate_id"],
            "language": candidate["language"],
            "provenance": candidate["source_url_or_reference"],
            "license": candidate["usage_basis"],
            "trust_tier": TrustTier.RAW_CANDIDATE.value,
            "_source_file": source_binding,
        }
        units.append(
            {
                "review_unit_index": index,
                "review_item_id": "evidence-queue-" + row["consensus_id"],
                "pilot_id": "automated-evidence-factory",
                "priority_reasons": row["queue_reasons"],
                "machine_suggestion_trusted": False,
                "machine_suggestion": {
                    "proposed_concept_id": None,
                    "proposed_paraphrase_group": None,
                    "proposed_translation_group": None,
                },
                "cases": [
                    {
                        "case_id": candidate["candidate_id"],
                        "text": candidate["text"],
                        "legacy_metadata": legacy_metadata,
                        "source_file": source_binding,
                        "original_content_hash": hashlib.sha256(
                            candidate["text"].encode()
                        ).hexdigest(),
                        "original_metadata_hash": canonical_hash(legacy_metadata),
                        "pilot_review_context": {
                            "provisional_binary_label": None,
                            "provisional_classifier_family": None,
                            "hard_negative_category_candidate": None,
                        },
                    }
                ],
                "human_decision": None,
            }
        )
    if not dry_run:
        _write_jsonl(output, units)
    return _mutation_counts(
        candidates_processed=len(units),
        human_queue_count=len(units),
        canonical_review_export=str(output),
        dry_run=dry_run,
    )


def select_training_data(
    inputs: tuple[Path, ...], output: Path, *, dry_run: bool = False
) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for path in inputs:
        for row in _read_jsonl(path):
            tier = row.get("trust_tier")
            if tier is None and row.get("review_status") in {"REVIEWED", "VERIFIED"}:
                tier = TrustTier.HUMAN_TRUSTED.value
            if tier not in {TrustTier.HUMAN_TRUSTED.value, TrustTier.CONSENSUS_TRUSTED.value}:
                continue
            key = (
                str(row.get("case_id", row.get("id"))),
                str(row.get("content_hash", row.get("original_content_hash", ""))),
            )
            if key in seen:
                continue
            seen.add(key)
            selected.append({**row, "trust_tier": tier})
            counts[tier] += 1
    if not dry_run:
        _write_jsonl(output, selected)
    return _mutation_counts(
        candidates_processed=sum(counts.values()),
        training_rows=len(selected),
        counts_by_trust_tier=dict(sorted(counts.items())),
        dry_run=dry_run,
    )


def status(paths: tuple[Path, ...]) -> dict[str, Any]:
    tiers: Counter[str] = Counter()
    queue_reasons: Counter[str] = Counter()
    consensus_rows: list[dict[str, Any]] = []
    for path in paths:
        for row in _read_jsonl(path):
            tier = row.get("trust_tier")
            if tier is None and row.get("review_status") in {"REVIEWED", "VERIFIED"}:
                tier = TrustTier.HUMAN_TRUSTED.value
            if tier:
                tiers[str(tier)] += 1
            if row.get("consensus_id") and "queue_reasons" in row:
                consensus_rows.append(row)
                queue_reasons.update(row["queue_reasons"])
    total = len(consensus_rows)
    escalated = sum(bool(row.get("queue_reasons")) for row in consensus_rows)
    return {
        "tiers": {tier.value: tiers[tier.value] for tier in TrustTier},
        "HUMAN_QUEUE": escalated,
        "agreement_rate": (total - escalated) / total if total else 0.0,
        "human_escalation_rate": escalated / total if total else 0.0,
        "rights_failure_rate": queue_reasons[QueueReason.USAGE_RIGHTS_UNCERTAIN.value] / total
        if total
        else 0.0,
        "privacy_failure_rate": queue_reasons[QueueReason.PRIVACY_UNCERTAIN.value] / total
        if total
        else 0.0,
        "taxonomy_disagreement_rate": queue_reasons[QueueReason.TAXONOMY_AMBIGUOUS.value] / total
        if total
        else 0.0,
        "independence_disagreement_rate": queue_reasons[QueueReason.INDEPENDENCE_UNCERTAIN.value]
        / total
        if total
        else 0.0,
    }
