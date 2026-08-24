"""Replaceable deterministic planner adapter and guarded workflow runner."""

from __future__ import annotations

from typing import Protocol

from .gateway import GuardedToolGateway
from .models import AgentPlan, BoundaryStage, GatewayResult, GatewayStatus, WorkflowResult


class AgentPlanner(Protocol):
    def plan(self, user_content: str) -> AgentPlan: ...


class FixturePlanner:
    """Transparent planner used by local evaluation; it is not presented as an AI model."""

    def __init__(self, plan: AgentPlan) -> None:
        self._plan = plan

    def plan(self, user_content: str) -> AgentPlan:
        del user_content
        return self._plan


class GuardedAgentWorkflow:
    """Sequential workflow whose protected operations are available only through the gateway."""

    def __init__(self, gateway: GuardedToolGateway, planner: AgentPlanner) -> None:
        self.__gateway = gateway
        self.__planner = planner

    def run(self, user_content: str, *, dry_run: bool = False) -> WorkflowResult:
        workflow_id = self.__gateway.new_workflow_id()
        results = []
        ingress = self.__gateway.inspect_user_input(
            user_content, workflow_id=workflow_id, dry_run=dry_run
        )
        results.append(ingress)
        stopped = _stop(workflow_id, results, ingress)
        if stopped is not None:
            return stopped

        plan = self.__planner.plan(user_content)
        for content in plan.retrieved_content:
            retrieval = self.__gateway.inspect_retrieved_content(
                content, workflow_id=workflow_id, dry_run=dry_run
            )
            results.append(retrieval)
            stopped = _stop(workflow_id, results, retrieval)
            if stopped is not None:
                return stopped

        for call in plan.tool_calls:
            tool = self.__gateway.dispatch_tool_call(
                call.tool_name,
                call.arguments,
                workflow_id=workflow_id,
                dry_run=dry_run,
            )
            results.append(tool)
            stopped = _stop(workflow_id, results, tool)
            if stopped is not None:
                return stopped

        if plan.memory_write is not None:
            memory = self.__gateway.write_memory(
                plan.memory_write, workflow_id=workflow_id, dry_run=dry_run
            )
            results.append(memory)
            stopped = _stop(workflow_id, results, memory)
            if stopped is not None:
                return stopped

        if plan.external_send is not None:
            external = self.__gateway.send_external(
                plan.external_send, workflow_id=workflow_id, dry_run=dry_run
            )
            results.append(external)
            stopped = _stop(workflow_id, results, external)
            if stopped is not None:
                return stopped

        audit_ids = tuple(audit for result in results for audit in result.audit_ids)
        return WorkflowResult(
            workflow_id,
            GatewayStatus.PROCEEDED,
            BoundaryStage.COMPLETE,
            tuple(results),
            plan.final_response,
            audit_ids,
        )


def _stop(
    workflow_id: str, results: list[GatewayResult], current: GatewayResult
) -> WorkflowResult | None:
    status = current.status
    if status is GatewayStatus.PROCEEDED:
        return None
    audit_ids = tuple(audit for result in results for audit in result.audit_ids)
    return WorkflowResult(
        workflow_id,
        status,
        current.stage,
        tuple(results),
        None,
        audit_ids,
    )
