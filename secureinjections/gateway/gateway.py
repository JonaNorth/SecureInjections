"""Reusable guarded boundary gateway for local tool-using workflows."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any, cast

from ..guard import Guard, GuardDecision, InspectionRequest, InspectionResult
from .models import (
    BoundaryAuditEvent,
    BoundaryStage,
    GatewayResult,
    GatewayStatus,
    GuardSummary,
)
from .tools import LocalToolRegistry, ToolRegistryError, _GatewayCapability


class GuardedToolGateway:
    """The only workflow-facing path to protected local tools and side effects."""

    def __init__(self, guard: Guard, tools: LocalToolRegistry) -> None:
        self.guard = guard
        self.__tools = tools
        self.__capability: _GatewayCapability = tools._gateway_capability()
        self.__events: dict[str, list[BoundaryAuditEvent]] = {}

    @staticmethod
    def new_workflow_id() -> str:
        return "gateway-run-" + uuid.uuid4().hex

    def inspect_user_input(
        self, content: str, *, workflow_id: str | None = None, dry_run: bool = False
    ) -> GatewayResult:
        return self._inspect_boundary(
            content,
            source="user",
            destination="model",
            stage=BoundaryStage.INGRESS,
            operation_type="forward_user_input",
            workflow_id=workflow_id or self.new_workflow_id(),
            dry_run=dry_run,
        )

    def inspect_retrieved_content(
        self, content: str, *, workflow_id: str, dry_run: bool = False
    ) -> GatewayResult:
        return self._inspect_boundary(
            content,
            source="retrieved_content",
            destination="model",
            stage=BoundaryStage.RETRIEVAL,
            operation_type="forward_retrieved_content",
            workflow_id=workflow_id,
            dry_run=dry_run,
        )

    def process_tool_output(
        self, output: Any, *, workflow_id: str, dry_run: bool = False
    ) -> GatewayResult:
        content = _render_value(output)
        guard_result = self.guard.inspect_tool_output(
            content,
            context={"request_id": workflow_id},
            dry_run=dry_run,
        )
        return self._result(
            guard_result,
            workflow_id,
            BoundaryStage.POST_TOOL,
            "forward_tool_output",
            value=output,
        )

    def inspect_model_output(
        self, content: str, *, workflow_id: str, dry_run: bool = False
    ) -> GatewayResult:
        return self._inspect_boundary(
            content,
            source="model",
            destination="user",
            stage=BoundaryStage.EGRESS,
            operation_type="release_model_output",
            workflow_id=workflow_id,
            dry_run=dry_run,
        )

    def dispatch_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        workflow_id: str,
        dry_run: bool = False,
    ) -> GatewayResult:
        pre = self.guard.inspect_tool_call(
            tool_name,
            arguments,
            source="model",
            destination="tool",
            context={"request_id": workflow_id},
            dry_run=dry_run,
        )
        pre_result = self._result(
            pre,
            workflow_id,
            BoundaryStage.PRE_TOOL,
            "dispatch_tool_call",
            operation={"type": "tool_call", "tool_name": tool_name},
        )
        if pre_result.status is not GatewayStatus.PROCEEDED or dry_run:
            return pre_result
        try:
            output = self.__tools._dispatch(self.__capability, tool_name, arguments)
        except ToolRegistryError as exc:
            return GatewayResult(
                workflow_id,
                GatewayStatus.BLOCKED,
                BoundaryStage.PRE_TOOL,
                pre_result.guard,
                {
                    "type": "tool_call",
                    "tool_name": tool_name,
                    "local_rejection": type(exc).__name__,
                },
                False,
                False,
                pre_result.audit_ids,
                "Local tool rejected the operation.",
            )
        post = self.process_tool_output(output, workflow_id=workflow_id)
        audit_ids = (*pre_result.audit_ids, *post.audit_ids)
        if post.status is not GatewayStatus.PROCEEDED:
            return GatewayResult(
                workflow_id,
                post.status,
                BoundaryStage.POST_TOOL,
                post.guard,
                {"type": "tool_call", "tool_name": tool_name, "output_forwarded": False},
                True,
                False,
                audit_ids,
                post.safe_message,
            )
        return GatewayResult(
            workflow_id,
            GatewayStatus.PROCEEDED,
            BoundaryStage.POST_TOOL,
            post.guard,
            {"type": "tool_call", "tool_name": tool_name, "output_forwarded": True},
            True,
            False,
            audit_ids,
            "Tool call and output passed security inspection.",
            output,
        )

    def write_memory(
        self,
        record: Mapping[str, Any],
        *,
        workflow_id: str,
        dry_run: bool = False,
    ) -> GatewayResult:
        content = "write memory record\n" + _render_value(record)
        guard_result = self.guard.inspect(
            InspectionRequest(
                content,
                "model",
                "memory",
                {"request_id": workflow_id},
            ),
            dry_run=dry_run,
        )
        result = self._result(
            guard_result,
            workflow_id,
            BoundaryStage.MEMORY,
            "memory_write",
            operation={"type": "memory_write"},
        )
        if result.status is not GatewayStatus.PROCEEDED or dry_run:
            return result
        stored = self.__tools._write_memory(self.__capability, record)
        return GatewayResult(
            workflow_id,
            result.status,
            result.stage,
            result.guard,
            result.operation,
            False,
            True,
            result.audit_ids,
            "Memory write passed security inspection.",
            stored,
        )

    def send_external(
        self,
        transfer: Mapping[str, Any],
        *,
        workflow_id: str,
        dry_run: bool = False,
    ) -> GatewayResult:
        content = "send " + _render_value(transfer) + "\nto external destination"
        guard_result = self.guard.inspect(
            InspectionRequest(
                content,
                "model",
                "external",
                {"request_id": workflow_id},
            ),
            dry_run=dry_run,
        )
        result = self._result(
            guard_result,
            workflow_id,
            BoundaryStage.EXTERNAL,
            "external_transfer",
            operation={"type": "external_transfer", "simulated": True},
        )
        if result.status is not GatewayStatus.PROCEEDED or dry_run:
            return result
        receipt = self.__tools._send_external_simulated(self.__capability, transfer)
        return GatewayResult(
            workflow_id,
            result.status,
            result.stage,
            result.guard,
            result.operation,
            False,
            True,
            result.audit_ids,
            "Simulated external transfer passed security inspection.",
            receipt,
        )

    def reconstruct_audit_chain(self, workflow_id: str) -> tuple[BoundaryAuditEvent, ...]:
        return tuple(self.__events.get(workflow_id, ()))

    def _inspect_boundary(
        self,
        content: str,
        *,
        source: str,
        destination: str,
        stage: BoundaryStage,
        operation_type: str,
        workflow_id: str,
        dry_run: bool,
    ) -> GatewayResult:
        guard_result = self.guard.inspect(
            InspectionRequest(
                content,
                source,
                destination,
                {"request_id": workflow_id},
            ),
            dry_run=dry_run,
        )
        return self._result(
            guard_result,
            workflow_id,
            stage,
            operation_type,
            value=content,
        )

    def _result(
        self,
        guard_result: InspectionResult,
        workflow_id: str,
        stage: BoundaryStage,
        operation_type: str,
        *,
        operation: Mapping[str, Any] | None = None,
        value: Any = None,
    ) -> GatewayResult:
        decision = cast(GuardDecision, guard_result.decision)
        status = {
            GuardDecision.ALLOW: GatewayStatus.PROCEEDED,
            GuardDecision.REVIEW: GatewayStatus.REVIEW_REQUIRED,
            GuardDecision.BLOCK: GatewayStatus.BLOCKED,
        }[decision]
        summary = GuardSummary.from_result(guard_result)
        safe_message = {
            GatewayStatus.PROCEEDED: "Operation passed security inspection.",
            GatewayStatus.REVIEW_REQUIRED: "Operation requires security review.",
            GatewayStatus.BLOCKED: "Operation blocked by security policy.",
        }[status]
        result = GatewayResult(
            workflow_id,
            status,
            stage,
            summary,
            operation or {"type": operation_type},
            False,
            False,
            (summary.audit_id,),
            safe_message,
            value if status is GatewayStatus.PROCEEDED else None,
        )
        self.__events.setdefault(workflow_id, []).append(
            BoundaryAuditEvent(
                workflow_id,
                stage,
                summary.audit_id,
                status,
                summary.decision,
                summary.reason_codes,
                operation_type,
            )
        )
        return result


def _render_value(value: Any, *, depth: int = 0) -> str:
    if depth > 12:
        raise ValueError("gateway value exceeds maximum nesting depth")
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    if isinstance(value, Mapping):
        if len(value) > 1_000:
            raise ValueError("gateway mapping is too large")
        parts = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError("gateway mapping keys must be strings")
            parts.append(f"{key}={_render_value(value[key], depth=depth + 1)}")
        return "\n".join(parts)
    if isinstance(value, (list, tuple)):
        if len(value) > 1_000:
            raise ValueError("gateway sequence is too large")
        return "\n".join(_render_value(item, depth=depth + 1) for item in value)
    raise TypeError("gateway values must be bounded JSON-like data")
