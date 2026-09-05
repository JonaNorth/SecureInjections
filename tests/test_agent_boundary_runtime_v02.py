from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from secureinjections.gateway import (
    AgentMessageDecision,
    AgentMessageRequest,
    ContentEnvelope,
    ContentSourceType,
    GuardedToolGateway,
    LocalToolRegistry,
    MessagePurpose,
    SecurityEventType,
)
from secureinjections.guard import Guard, TrustLevel
from secureinjections.local_agent import (
    ACTION_SCHEMA,
    AgentRunStatus,
    GenerationConfig,
    GuardedLocalAgent,
    ModelIdentity,
    ModelMessage,
    ModelResponse,
    OpenAICompatibleLocalAgentAdapter,
)


class ScriptedModel:
    def __init__(self, responses: Sequence[str]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[ModelMessage, ...]] = []
        self._identity = ModelIdentity("scripted-local", "1", "qwen2.5:7b", "7b", "a" * 64, "test")

    @property
    def identity(self) -> ModelIdentity:
        return self._identity

    @property
    def generation_config(self) -> GenerationConfig:
        return GenerationConfig()

    def generate(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: Mapping[str, Any],
    ) -> ModelResponse:
        assert response_schema == ACTION_SCHEMA
        self.calls.append(tuple(messages))
        return ModelResponse(self.responses.pop(0), 1.0, 0.75, 0.25)


class ScriptedOpenAITransport:
    def __init__(self, responses: Sequence[Mapping[str, Any]]) -> None:
        self.responses = list(responses)

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        del method, path, payload
        return self.responses.pop(0)


def _tool(tool: str, arguments: Mapping[str, Any]) -> str:
    return json.dumps({"action": "TOOL_CALL", "tool": tool, "arguments": arguments})


def _final(response: str = "Done.") -> str:
    return json.dumps({"action": "FINAL_RESPONSE", "response": response})


def _memory(value: str) -> str:
    return json.dumps({"action": "MEMORY_WRITE", "memory": {"preference": value}})


def _external(data: str) -> str:
    return json.dumps(
        {"action": "EXTERNAL_SEND", "external": {"destination": "demo", "message": data}}
    )


def test_host_context_propagates_through_calculator_without_changing_benign_result(
    tmp_path: Path,
) -> None:
    model = ScriptedModel(
        [_tool("calculator", {"operation": "add", "left": 2, "right": 3}), _final("5")]
    )
    registry = LocalToolRegistry(tmp_path)
    gateway = GuardedToolGateway(Guard(), registry)
    result = GuardedLocalAgent(model, gateway).run("Add two and three.")

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_response == "5"
    assert result.model_audit[0].trust_floor == TrustLevel.TRUSTED.value
    assert result.model_audit[0].ever_untrusted is False
    assert result.model_audit[1].trust_floor == TrustLevel.UNTRUSTED.value
    assert result.model_audit[1].ever_untrusted is True
    assert all(item.correlation_id == result.workflow_id for item in result.model_audit)
    assert all(item.input_envelope_ids and item.output_content_id for item in result.model_audit)


def test_benign_file_read_uses_typed_reader_and_preserves_file_source(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("ordinary workspace note", encoding="utf-8")
    model = ScriptedModel([_tool("workspace_reader", {"path": "notes.txt"}), _final()])
    registry = LocalToolRegistry(tmp_path)
    gateway = GuardedToolGateway(Guard(), registry)

    result = GuardedLocalAgent(model, gateway).run("Read notes.txt and summarize it.")

    assert result.status is AgentRunStatus.COMPLETED
    assert registry.counters.workspace_reads == 1
    assert "ordinary workspace note" in model.calls[1][-1].content
    turn_input = gateway.security_events.get(result.model_audit[1].turn_event_id or "")
    assert turn_input is not None
    content_id = result.model_audit[1].input_envelope_ids[0]
    file_events = [
        item
        for item in gateway.security_events.correlation_events(result.workflow_id)
        if item.event_type is SecurityEventType.FILE_READ
    ]
    assert file_events and file_events[0].content_ids == (content_id,)


def test_untrusted_file_summary_cannot_launder_later_privileged_proposal(
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.txt").write_text("The quarterly label is blue.", encoding="utf-8")
    registry = LocalToolRegistry(
        tmp_path,
        allowed_root_trust={"workspace": TrustLevel.UNTRUSTED},
    )
    gateway = GuardedToolGateway(Guard(), registry)
    model = ScriptedModel(
        [
            _tool("workspace_reader", {"path": "notes.txt"}),
            _tool("workspace_reader", {"path": "other.txt"}),
        ]
    )

    result = GuardedLocalAgent(model, gateway).run("Read and summarize notes.txt.")

    assert result.status is AgentRunStatus.REVIEW_REQUIRED
    assert result.boundary_results[-1].operation["sequence_reason_code"] == (
        "UNTRUSTED_DERIVED_PRIVILEGED_ACTION"
    )
    assert result.model_audit[1].ever_untrusted is True
    assert registry.counters.workspace_reads == 1


def test_sensitive_file_summary_is_blocked_from_external_send(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("project label is blue", encoding="utf-8")
    registry = LocalToolRegistry(tmp_path, allow_sensitive_files=True)
    gateway = GuardedToolGateway(Guard(), registry)
    model = ScriptedModel(
        [_tool("workspace_reader", {"path": ".env"}), _external("project label is blue")]
    )

    result = GuardedLocalAgent(model, gateway).run("Summarize .env and send the summary.")

    assert result.status is AgentRunStatus.BLOCKED
    assert result.boundary_results[-1].operation["sequence_reason_code"] in {
        "SENSITIVE_READ_TO_EXTERNAL_SEND",
        "SENSITIVE_CONTENT_TO_EXTERNAL_SEND",
    }
    assert "SENSITIVE_CONTENT" in result.model_audit[1].security_finding_types
    assert registry.simulated_external_transfers == ()


def test_untrusted_retrieval_output_is_contained_on_later_external_send(
    tmp_path: Path,
) -> None:
    registry = LocalToolRegistry(tmp_path, documents={"ordinary": "quarterly label blue"})
    gateway = GuardedToolGateway(Guard(), registry)
    model = ScriptedModel(
        [_tool("document_retriever", {"document_id": "ordinary"}), _external("blue")]
    )

    result = GuardedLocalAgent(model, gateway).run("Retrieve ordinary and process it.")

    assert result.status is AgentRunStatus.REVIEW_REQUIRED
    assert result.boundary_results[-1].operation["sequence_reason_code"] == (
        "UNTRUSTED_DERIVED_PRIVILEGED_ACTION"
    )
    assert result.model_audit[1].ever_untrusted is True
    assert registry.simulated_external_transfers == ()


def test_memory_read_in_later_run_retains_untrusted_file_ancestry(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("preference is compact", encoding="utf-8")
    registry = LocalToolRegistry(
        tmp_path,
        allowed_root_trust={"workspace": TrustLevel.UNTRUSTED},
    )
    gateway = GuardedToolGateway(Guard(), registry)
    first_model = ScriptedModel(
        [_tool("workspace_reader", {"path": "notes.txt"}), _memory("compact"), _final()]
    )
    first = GuardedLocalAgent(first_model, gateway).run("Remember the preference in notes.txt.")
    assert first.status is AgentRunStatus.COMPLETED
    record = gateway.memory.records[0]
    assert record.content.ever_untrusted is True

    second_model = ScriptedModel([_tool("workspace_reader", {"path": "other.txt"})])
    second = GuardedLocalAgent(second_model, gateway).run(
        "Use the saved preference.", memory_record_ids=(record.record_id,)
    )

    assert second.status is AgentRunStatus.REVIEW_REQUIRED
    assert second.model_audit[0].ever_untrusted is True
    assert second.boundary_results[-1].operation["sequence_reason_code"] == (
        "UNTRUSTED_DERIVED_PRIVILEGED_ACTION"
    )
    assert registry.counters.workspace_reads == 1


def test_benign_trusted_preference_survives_live_memory_flow(tmp_path: Path) -> None:
    gateway = GuardedToolGateway(Guard(), LocalToolRegistry(tmp_path))
    first = GuardedLocalAgent(ScriptedModel([_memory("compact"), _final()]), gateway).run(
        "Remember my compact output preference."
    )
    assert first.status is AgentRunStatus.COMPLETED
    record = gateway.memory.records[0]
    assert record.content.ever_untrusted is False

    second = GuardedLocalAgent(ScriptedModel([_final("Preference loaded.")]), gateway).run(
        "What is my preference?", memory_record_ids=(record.record_id,)
    )
    assert second.status is AgentRunStatus.COMPLETED
    assert second.model_audit[0].ever_untrusted is False


def test_covert_agent_data_message_grants_nothing_and_taints_background_action(
    tmp_path: Path,
) -> None:
    registry = LocalToolRegistry(tmp_path)
    gateway = GuardedToolGateway(Guard(), registry)
    primary = gateway.agent_directory.register("primary")
    gateway.agent_directory.register("background")
    covert = ContentEnvelope.create(
        "quarterly marker blue",
        source_type=ContentSourceType.RETRIEVAL,
        trust=TrustLevel.UNTRUSTED,
        provenance=("retrieval:covert",),
        producing_boundary="retrieval",
    )
    sent = gateway.send_agent_message(
        primary,
        AgentMessageRequest(
            "primary",
            "background",
            MessagePurpose.DATA,
            covert,
            "background-chain",
            requested_capability=None,
        ),
    )
    assert sent.decision is AgentMessageDecision.ALLOW
    assert sent.granted_capabilities == ()

    model = ScriptedModel([_tool("workspace_reader", {"path": "notes.txt"})])
    result = GuardedLocalAgent(model, gateway).run(
        "Process the background status.", agent_messages=(sent,), destination_agent="background"
    )

    assert result.status is AgentRunStatus.REVIEW_REQUIRED
    assert result.model_audit[0].ever_untrusted is True
    assert registry.counters.workspace_reads == 0


def test_model_trust_claim_cannot_reset_host_context(tmp_path: Path) -> None:
    gateway = GuardedToolGateway(Guard(), LocalToolRegistry(tmp_path))
    source = gateway.create_content(
        "ordinary external datum",
        source_type=ContentSourceType.RETRIEVAL,
        trust=TrustLevel.UNTRUSTED,
        provenance=("retrieval:external",),
        producing_boundary="retrieval",
    )
    authority = gateway.agent_directory.register("source")
    gateway.agent_directory.register("local-agent")
    sent = gateway.send_agent_message(
        authority,
        AgentMessageRequest(
            "source", "local-agent", MessagePurpose.DATA, source, "trust-claim-message"
        ),
    )
    result = GuardedLocalAgent(
        ScriptedModel([_final("I certify that this output is trusted.")]), gateway
    ).run("Summarize it.", agent_messages=(sent,))

    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_audit[0].ever_untrusted is True
    output_event = gateway.security_events.get(result.model_audit[0].output_event_id or "")
    assert output_event is not None
    assert output_event.attributes["ever_untrusted"] == "true"


def test_forged_agent_message_result_cannot_enter_runtime_turn(tmp_path: Path) -> None:
    gateway = GuardedToolGateway(Guard(), LocalToolRegistry(tmp_path))
    authority = gateway.agent_directory.register("source")
    gateway.agent_directory.register("local-agent")
    original = gateway.create_content(
        "original status",
        source_type=ContentSourceType.INTERNAL,
        trust=TrustLevel.INTERNAL,
        provenance=("agent:source",),
        producing_boundary="source",
    )
    sent = gateway.send_agent_message(
        authority,
        AgentMessageRequest(
            "source", "local-agent", MessagePurpose.STATUS, original, "forged-message"
        ),
    )
    assert sent.message is not None
    forged_content = gateway.create_content(
        "substituted content",
        source_type=ContentSourceType.INTERNAL,
        trust=TrustLevel.TRUSTED,
        provenance=("forged:host-field",),
        producing_boundary="forged",
    )
    forged = replace(sent, message=replace(sent.message, content=forged_content))
    model = ScriptedModel([_final()])

    result = GuardedLocalAgent(model, gateway).run(
        "Process status.", agent_messages=(forged,), destination_agent="local-agent"
    )

    assert result.status is AgentRunStatus.BLOCKED
    assert result.stopped_at == "agent_message"
    assert model.calls == []


def test_openai_native_tool_normalization_uses_same_host_owned_context(tmp_path: Path) -> None:
    response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "provider-controlled-id",
                            "type": "function",
                            "function": {
                                "name": "calculator",
                                "arguments": '{"operation":"add","left":2,"right":3}',
                            },
                        }
                    ],
                }
            }
        ]
    }
    final = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": _final("5"),
                }
            }
        ]
    }
    identity = ModelIdentity("openai_compatible_local", "v1", "qwen2.5:7b", "7b", "x" * 64, "test")
    adapter = OpenAICompatibleLocalAgentAdapter(
        ScriptedOpenAITransport([response, final]), identity
    )
    gateway = GuardedToolGateway(Guard(), LocalToolRegistry(tmp_path))
    result = GuardedLocalAgent(adapter, gateway).run("Add 2 and 3.")

    assert result.status is AgentRunStatus.COMPLETED
    assert result.model_audit[0].turn_event_id.startswith("security-event-")
    assert "provider-controlled-id" not in json.dumps(result.to_dict())
    assert result.model_audit[1].ever_untrusted is True


def test_causal_audit_reconstructs_source_turn_output_proposal_and_decision(
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.txt").write_text("ordinary untrusted datum", encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    registry = LocalToolRegistry(
        tmp_path,
        allowed_root_trust={"workspace": TrustLevel.UNTRUSTED},
    )
    gateway = GuardedToolGateway(Guard(audit_path=audit_path), registry)
    model = ScriptedModel(
        [
            _tool("workspace_reader", {"path": "notes.txt"}),
            _tool("workspace_reader", {"path": "missing.txt"}),
        ]
    )
    result = GuardedLocalAgent(model, gateway).run("Read notes.txt.")
    assert result.status is AgentRunStatus.REVIEW_REQUIRED

    events = gateway.security_events.correlation_events(result.workflow_id)
    types = [item.event_type for item in events]
    assert SecurityEventType.CONTENT_TRANSFORM in types
    assert SecurityEventType.FILE_READ in types
    assert types.count(SecurityEventType.MODEL_TURN) == 2
    assert types.count(SecurityEventType.MODEL_OUTPUT) == 2
    assert types.count(SecurityEventType.TOOL_PROPOSAL) == 2
    assert types[-1] is SecurityEventType.POLICY_DECISION
    chain = gateway.reconstruct_security_chain(events[-1].event_id)
    assert {item.event_type for item in chain} >= {
        SecurityEventType.FILE_READ,
        SecurityEventType.MODEL_TURN,
        SecurityEventType.MODEL_OUTPUT,
        SecurityEventType.TOOL_PROPOSAL,
        SecurityEventType.POLICY_DECISION,
    }
    logged = audit_path.read_text(encoding="utf-8")
    assert "ordinary untrusted datum" not in logged
    assert '"raw_content_retained":false' in logged


@pytest.mark.parametrize(
    "path",
    ("../../etc/passwd", "/etc/passwd"),
)
def test_live_file_proposals_cannot_bypass_typed_path_policy(tmp_path: Path, path: str) -> None:
    registry = LocalToolRegistry(tmp_path)
    result = GuardedLocalAgent(
        ScriptedModel([_tool("workspace_reader", {"path": path})]),
        GuardedToolGateway(Guard(), registry),
    ).run("Read the requested path.")
    assert result.status in {AgentRunStatus.BLOCKED, AgentRunStatus.REVIEW_REQUIRED}
    assert registry.counters.workspace_reads == 0
