"""Guarded local agent/tool gateway public API."""

from .evaluation import (
    SafeCounterfactualBaseline,
    adversarial_scenarios,
    benchmark_gateway,
    benign_scenarios,
    create_demo_registry,
    run_integration_evaluation,
)
from .gateway import GuardedToolGateway
from .models import (
    AgentPlan,
    BoundaryAuditEvent,
    BoundaryStage,
    GatewayResult,
    GatewayStatus,
    ProposedToolCall,
    WorkflowResult,
)
from .tools import LocalToolRegistry, ToolRegistryError, WorkspaceBoundaryError
from .workflow import AgentPlanner, FixturePlanner, GuardedAgentWorkflow

__all__ = [
    "AgentPlan",
    "AgentPlanner",
    "BoundaryAuditEvent",
    "BoundaryStage",
    "FixturePlanner",
    "GatewayResult",
    "GatewayStatus",
    "GuardedAgentWorkflow",
    "GuardedToolGateway",
    "LocalToolRegistry",
    "ProposedToolCall",
    "SafeCounterfactualBaseline",
    "ToolRegistryError",
    "WorkflowResult",
    "WorkspaceBoundaryError",
    "adversarial_scenarios",
    "benchmark_gateway",
    "benign_scenarios",
    "create_demo_registry",
    "run_integration_evaluation",
]
