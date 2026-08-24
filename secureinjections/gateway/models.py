"""Typed contracts for the guarded local agent/tool gateway."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..guard import InspectionResult


class GatewayStatus(StrEnum):
    PROCEEDED = "PROCEEDED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"


class BoundaryStage(StrEnum):
    INGRESS = "ingress"
    RETRIEVAL = "retrieval"
    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"
    MEMORY = "memory"
    EXTERNAL = "external"
    EGRESS = "egress"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class GuardSummary:
    decision: str
    risk: str
    finding_types: tuple[str, ...]
    reason_codes: tuple[str, ...]
    actions: tuple[str, ...]
    audit_id: str
    policy_hash: str

    @classmethod
    def from_result(cls, result: InspectionResult) -> GuardSummary:
        reason_codes = tuple(
            dict.fromkeys(
                [result.policy.reason_code, *(finding.reason_code for finding in result.findings)]
            )
        )
        return cls(
            result.decision.value,
            result.risk.value,
            tuple(dict.fromkeys(finding.finding_type.value for finding in result.findings)),
            reason_codes,
            tuple(action.value for action in result.actions),
            result.audit_id,
            result.policy.policy_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "risk": self.risk,
            "finding_types": list(self.finding_types),
            "reason_codes": list(self.reason_codes),
            "actions": list(self.actions),
            "audit_id": self.audit_id,
            "policy_hash": self.policy_hash,
        }


@dataclass(frozen=True, slots=True)
class GatewayResult:
    workflow_id: str
    status: GatewayStatus
    stage: BoundaryStage
    guard: GuardSummary
    operation: Mapping[str, Any]
    tool_executed: bool
    side_effect_performed: bool
    audit_ids: tuple[str, ...]
    safe_message: str
    value: Any = field(default=None, repr=False)

    def to_dict(self, *, include_value: bool = False) -> dict[str, Any]:
        output = {
            "workflow_id": self.workflow_id,
            "status": self.status.value,
            "stage": self.stage.value,
            "guard": self.guard.to_dict(),
            "operation": dict(self.operation),
            "tool_executed": self.tool_executed,
            "side_effect_performed": self.side_effect_performed,
            "audit_ids": list(self.audit_ids),
            "safe_message": self.safe_message,
        }
        if include_value and self.status is GatewayStatus.PROCEEDED:
            output["value"] = self.value
        return output


@dataclass(frozen=True, slots=True)
class BoundaryAuditEvent:
    workflow_id: str
    stage: BoundaryStage
    audit_id: str
    status: GatewayStatus
    decision: str
    reason_codes: tuple[str, ...]
    operation_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "stage": self.stage.value,
            "audit_id": self.audit_id,
            "status": self.status.value,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "operation_type": self.operation_type,
        }


@dataclass(frozen=True, slots=True)
class ProposedToolCall:
    tool_name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AgentPlan:
    retrieved_content: tuple[str, ...] = ()
    tool_calls: tuple[ProposedToolCall, ...] = ()
    memory_write: Mapping[str, Any] | None = None
    external_send: Mapping[str, Any] | None = None
    final_response: str = "Completed locally."


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    workflow_id: str
    status: GatewayStatus
    stopped_at: BoundaryStage
    boundary_results: tuple[GatewayResult, ...]
    final_response: str | None
    audit_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "status": self.status.value,
            "stopped_at": self.stopped_at.value,
            "boundary_results": [result.to_dict() for result in self.boundary_results],
            "final_response": self.final_response,
            "audit_ids": list(self.audit_ids),
        }
