"""Authoritative deterministic Guard runtime."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .audit import append_audit, record_hash
from .detectors import (
    DETECTOR_HASH,
    classify_context,
    detect_text,
    suspicious_url_finding,
    tool_call_content,
)
from .models import (
    Certainty,
    ClassifierFamily,
    ContentContext,
    DestinationType,
    EvidenceSpan,
    FindingType,
    GuardFinding,
    InspectionContext,
    InspectionRequest,
    InspectionResult,
    RiskLevel,
    Severity,
    SourceType,
    ToolCallRequest,
    TrustLevel,
)
from .normalization import normalize_content
from .policy import GuardPolicy

Clock = Callable[[], datetime]


class Guard:
    """Offline deterministic protection for text and proposed tool calls.

    The decision path is normalization -> trust context -> deterministic detectors -> policy ->
    audit. No model, reviewer, network, telemetry, dynamic code, or evidence corpus is loaded.
    """

    def __init__(
        self,
        policy: GuardPolicy | None = None,
        *,
        policy_path: Path | str | None = None,
        audit_path: Path | str | None = None,
        clock: Clock | None = None,
    ) -> None:
        if policy is not None and policy_path is not None:
            raise ValueError("provide policy or policy_path, not both")
        self.policy = policy or (
            GuardPolicy.from_path(Path(policy_path))
            if policy_path is not None
            else GuardPolicy.default()
        )
        self.audit_path = Path(audit_path) if audit_path is not None else None
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def detector_count(self) -> int:
        from .detectors import RULES

        return len(RULES) + 1  # structured suspicious-URL detector

    def inspect(self, request: InspectionRequest, *, dry_run: bool = False) -> InspectionResult:
        normalized = normalize_content(request.content)
        context_object = cast(InspectionContext, request.context)
        source_type = cast(SourceType, request.source)
        destination_type = cast(DestinationType, request.destination)
        source_trust = context_object.source_trust or self.policy.source_trust[source_type]
        destination_trust = (
            context_object.destination_trust or self.policy.destination_trust[destination_type]
        )
        context = classify_context(request)
        findings = detect_text(request, context, source_trust)
        return self._decide(
            request,
            findings,
            normalized.sha256,
            source_trust,
            destination_trust,
            context,
            dry_run=dry_run,
        )

    def inspect_tool_output(
        self,
        content: str,
        *,
        destination: DestinationType | str = DestinationType.MODEL,
        context: InspectionContext | Mapping[str, Any] | None = None,
        dry_run: bool = False,
    ) -> InspectionResult:
        return self.inspect(
            InspectionRequest(
                content=content,
                source=SourceType.TOOL_OUTPUT,
                destination=destination,
                context=context or InspectionContext(),
            ),
            dry_run=dry_run,
        )

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        source: SourceType | str = SourceType.MODEL,
        destination: DestinationType | str = DestinationType.TOOL,
        context: InspectionContext | Mapping[str, Any] | None = None,
        dry_run: bool = False,
    ) -> InspectionResult:
        tool_request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            source=source,
            destination=destination,
            context=context or InspectionContext(presentation=ContentContext.OPERATIVE),
        )
        content = tool_call_content(tool_request)
        request = InspectionRequest(
            content=content,
            source=tool_request.source,
            destination=tool_request.destination,
            context=tool_request.context,
        )
        normalized = normalize_content(content)
        context_object = cast(InspectionContext, request.context)
        source_type = cast(SourceType, request.source)
        destination_type = cast(DestinationType, request.destination)
        source_trust = context_object.source_trust or self.policy.source_trust[source_type]
        destination_trust = (
            context_object.destination_trust or self.policy.destination_trust[destination_type]
        )
        findings = list(detect_text(request, ContentContext.OPERATIVE, source_trust))
        url_finding = suspicious_url_finding(content)
        if url_finding is not None:
            findings.append(url_finding)
        lowered = content.casefold()
        tool_lower = tool_name.casefold()
        if any(
            token in tool_lower for token in ("shell", "exec", "terminal", "command")
        ) and not any(item.finding_type is FindingType.TOOL_EXECUTION for item in findings):
            findings.append(
                _structured_finding(
                    "GUARD-TOOL-CALL-001",
                    FindingType.TOOL_EXECUTION,
                    ClassifierFamily.ATTACK_TOOL_EXECUTION,
                    Severity.HIGH,
                    "TOOL_EXECUTION",
                    "Proposed call targets a command-execution tool.",
                )
            )
        credential_target = any(
            token in tool_lower for token in ("credential", "secret", "token", "password")
        ) and any(token in tool_lower for token in ("read", "get", "fetch", "access"))
        if credential_target and not any(
            item.finding_type is FindingType.CREDENTIAL_ACCESS for item in findings
        ):
            findings.append(
                _structured_finding(
                    "GUARD-TOOL-CREDENTIAL-001",
                    FindingType.CREDENTIAL_ACCESS,
                    ClassifierFamily.ATTACK_CREDENTIAL_ACCESS,
                    Severity.CRITICAL,
                    "CREDENTIAL_ACCESS",
                    "Proposed tool targets credential or secret material.",
                )
            )
        sensitive = any(
            token in lowered
            for token in (
                "secret",
                "credential",
                "token",
                "password",
                "private_key",
                "document",
                "file_content",
            )
        )
        transfer = request.destination is DestinationType.EXTERNAL or any(
            token in tool_lower for token in ("upload", "send", "post", "webhook", "transfer")
        )
        if (
            sensitive
            and transfer
            and not any(item.finding_type is FindingType.EXFILTRATION for item in findings)
        ):
            findings.append(
                _structured_finding(
                    "GUARD-TOOL-EXFIL-001",
                    FindingType.EXFILTRATION,
                    ClassifierFamily.ATTACK_EXFILTRATION,
                    Severity.CRITICAL,
                    "EXFILTRATION",
                    "Tool call proposes transferring sensitive-looking content externally.",
                )
            )
        persistence = request.destination is DestinationType.MEMORY or any(
            token in tool_lower for token in ("memory", "profile", "persist", "store_state")
        )
        behavioral = any(
            token in lowered
            for token in ("instruction", "always", "ignore", "override", "from now on", "behavior")
        )
        if (
            persistence
            and behavioral
            and not any(item.finding_type is FindingType.PERSISTENCE for item in findings)
        ):
            findings.append(
                _structured_finding(
                    "GUARD-TOOL-MEMORY-001",
                    FindingType.PERSISTENCE,
                    ClassifierFamily.ATTACK_PERSISTENCE,
                    Severity.CRITICAL,
                    "PERSISTENCE",
                    "Tool call attempts to persist behavioral instructions.",
                )
            )
        return self._decide(
            request,
            tuple(findings),
            normalized.sha256,
            source_trust,
            destination_trust,
            ContentContext.OPERATIVE,
            dry_run=dry_run,
        )

    def _decide(
        self,
        request: InspectionRequest,
        findings: tuple[GuardFinding, ...],
        normalized_hash: str,
        source_trust: TrustLevel,
        destination_trust: TrustLevel,
        content_context: ContentContext,
        *,
        dry_run: bool,
    ) -> InspectionResult:
        decision, actions, binding = self.policy.evaluate(
            request, findings, source_trust, content_context
        )
        timestamp = self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        context_object = cast(InspectionContext, request.context)
        source_type = cast(SourceType, request.source)
        destination_type = cast(DestinationType, request.destination)
        request_id = context_object.request_id
        audit_seed = f"{timestamp}:{request_id or ''}:{normalized_hash}:{uuid.uuid4().hex}"
        audit_id = "guard-audit-" + hashlib.sha256(audit_seed.encode()).hexdigest()[:24]
        risk = _risk(findings)
        record: dict[str, Any] = {
            "schema_version": "guard-audit-v0.1",
            "audit_id": audit_id,
            "timestamp": timestamp,
            "request_id": request_id,
            "source": source_type.value,
            "destination": destination_type.value,
            "source_trust": source_trust.value,
            "destination_trust": destination_trust.value,
            "content_context": content_context.value,
            "normalized_content_hash": normalized_hash,
            "policy": binding.to_dict(),
            "detector_hash": DETECTOR_HASH,
            "findings": [_audit_finding(finding) for finding in findings],
            "decision": decision.value,
            "risk": risk.value,
            "actions": [action.value for action in actions],
            "dry_run": dry_run,
            "raw_content_retained": False,
            "context_metadata_keys": sorted(context_object.metadata),
            "advisory_authoritative": False,
        }
        digest = record_hash(record)
        record["record_hash"] = digest
        if self.audit_path is not None and not dry_run:
            append_audit(self.audit_path, record)
        return InspectionResult(
            decision,
            risk,
            findings,
            actions,
            binding,
            audit_id,
            dry_run,
            content_context,
            source_trust,
            destination_trust,
            normalized_hash,
            DETECTOR_HASH,
            digest,
            (),
        )


def _audit_finding(finding: GuardFinding) -> dict[str, Any]:
    """Project a finding without persisting the matched source excerpt."""

    payload = finding.to_dict()
    evidence = payload["evidence"]
    payload["evidence"] = {
        "start": evidence["start"],
        "end": evidence["end"],
        "excerpt_sha256": hashlib.sha256(evidence["excerpt"].encode("utf-8")).hexdigest(),
        "raw_excerpt_retained": False,
    }
    return payload


def _structured_finding(
    rule_id: str,
    finding_type: FindingType,
    family: ClassifierFamily,
    severity: Severity,
    reason_code: str,
    reason: str,
) -> GuardFinding:
    return GuardFinding(
        rule_id,
        finding_type,
        family,
        severity,
        Certainty.DEFINITE,
        EvidenceSpan(0, 0, "[STRUCTURED_TOOL_CALL]"),
        reason_code,
        reason,
    )


def _risk(findings: tuple[GuardFinding, ...]) -> RiskLevel:
    if not findings:
        return RiskLevel.LOW
    maximum = max(
        findings,
        key=lambda item: {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }[item.severity],
    ).severity
    return {
        Severity.LOW: RiskLevel.LOW,
        Severity.MEDIUM: RiskLevel.MEDIUM,
        Severity.HIGH: RiskLevel.HIGH,
        Severity.CRITICAL: RiskLevel.CRITICAL,
    }[maximum]
