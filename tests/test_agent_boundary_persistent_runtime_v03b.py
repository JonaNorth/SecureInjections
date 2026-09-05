from __future__ import annotations

import json
import multiprocessing
from pathlib import Path
from typing import Any

import pytest

from secureinjections.gateway import (
    AgentMessageRequest,
    ContentSourceType,
    GuardedToolGateway,
    LocalToolRegistry,
    MemoryDecision,
    MessagePurpose,
    PersistentRuntimeConfig,
    PersistentRuntimeError,
    RuntimeBackend,
)
from secureinjections.guard import Guard, TrustLevel
from secureinjections.persistent_state import PersistentStateConfig, WorkflowCASConflict


def _config(root: Path, *, audit_path: Path | None = None) -> PersistentRuntimeConfig:
    return PersistentRuntimeConfig(
        PersistentStateConfig(root / "authority", "runtime-test"), audit_path=audit_path
    )


def _gateway(root: Path, config: PersistentRuntimeConfig) -> GuardedToolGateway:
    workspace = root / "workspace"
    workspace.mkdir(exist_ok=True)
    return GuardedToolGateway(
        Guard(),
        LocalToolRegistry(workspace),
        backend=RuntimeBackend.PERSISTENT,
        persistent_config=config,
    )


def _memory_write(
    gateway: GuardedToolGateway, workflow_id: str, source: str, *, retrieved: bool = False
) -> str:
    gateway.inspect_user_input(source, workflow_id=workflow_id)
    if retrieved:
        gateway.inspect_retrieved_content(source, workflow_id=workflow_id)
    context = gateway.begin_model_turn(workflow_id, turn=1)
    memory = {"preference": source}
    payload = {"action": "MEMORY_WRITE", "memory": memory}
    output = gateway.derive_model_output(
        json.dumps(payload), context=context, action_type="MEMORY_WRITE"
    )
    result = gateway.write_runtime_memory(output, memory, workflow_id=workflow_id)
    assert result.status.value == "PROCEEDED"
    return gateway.memory.records[-1].record_id


def _spawn_read_memory(
    root_text: str, record_id: str, queue: multiprocessing.Queue[dict[str, Any]]
) -> None:
    root = Path(root_text)
    gateway = _gateway(root, _config(root))
    try:
        result = gateway.read_memory_envelope(
            record_id, destination_agent="foreground", correlation_id="restart-read"
        )
        queue.put(
            {
                "decision": result.decision.value,
                "reason": result.reason_code,
                "ever_untrusted": (
                    result.envelope.ever_untrusted if result.envelope is not None else None
                ),
                "content": result.envelope.content if result.envelope is not None else None,
            }
        )
    finally:
        gateway.close()


def test_backend_selection_is_explicit_and_ephemeral_default(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ephemeral = GuardedToolGateway(Guard(), LocalToolRegistry(workspace))
    assert ephemeral.backend is RuntimeBackend.EPHEMERAL
    with pytest.raises(ValueError):
        GuardedToolGateway(Guard(), LocalToolRegistry(workspace), backend=RuntimeBackend.PERSISTENT)


def test_persistent_startup_never_falls_back_when_key_is_missing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    gateway = _gateway(tmp_path, config)
    gateway.close()
    (config.state.state_directory / "authority.key").unlink()
    with pytest.raises(PersistentRuntimeError) as failure:
        _gateway(tmp_path, config)
    assert failure.value.code == "PERSISTENT_STATE_UNAVAILABLE"


def test_host_root_is_authoritative_but_retrieval_is_sticky_untrusted(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    gateway.inspect_user_input("preference", workflow_id="roots")
    trusted = gateway.current_content("roots")
    assert trusted is not None
    trusted_record = gateway.security_events.state.get_envelope(trusted.content_id)
    assert trusted_record.authority_kind == "AUTHORITATIVE_ROOT"
    gateway.inspect_retrieved_content("external data", workflow_id="roots")
    untrusted = gateway.current_content("roots")
    assert untrusted is not None and untrusted.ever_untrusted
    assert (
        gateway.security_events.state.get_envelope(untrusted.content_id).authority_kind == "DERIVED"
    )
    gateway.close()


def test_memory_payload_and_taint_survive_real_spawned_restart(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    record_id = _memory_write(gateway, "poisoned-memory", "covert marker", retrieved=True)
    gateway.close()
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    process = context.Process(target=_spawn_read_memory, args=(str(tmp_path), record_id, queue))
    process.start()
    process.join(30)
    assert process.exitcode == 0
    result = queue.get(timeout=5)
    assert result["decision"] == "ALLOW"
    assert result["ever_untrusted"] is True
    assert "covert marker" in result["content"]


def test_trusted_benign_memory_survives_restart_without_laundering(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    record_id = _memory_write(gateway, "benign-memory", "blue")
    gateway.close()
    restarted = _gateway(tmp_path, _config(tmp_path))
    result = restarted.read_memory_envelope(
        record_id, destination_agent="foreground", correlation_id="benign-restart"
    )
    assert result.decision is MemoryDecision.ALLOW
    assert result.envelope is not None
    assert result.envelope.trust is TrustLevel.TRUSTED
    assert not result.envelope.ever_untrusted
    restarted.close()


@pytest.mark.parametrize("attack", ["modify", "swap", "truncate", "delete", "malformed", "stale"])
def test_memory_payload_tampering_fails_closed(tmp_path: Path, attack: str) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    record_id = _memory_write(gateway, "tamper-memory", "blue")
    record = gateway.memory.records[-1]
    backend = gateway.security_events
    content_id = backend.persistent_content_id(record.content.content_id)
    payload = backend.payload_directory / f"{content_id}.json"
    swapped_payload: bytes | None = None
    if attack == "swap":
        _memory_write(gateway, "swap-source", "red")
        other = gateway.memory.records[-1]
        other_id = backend.persistent_content_id(other.content.content_id)
        swapped_payload = (backend.payload_directory / f"{other_id}.json").read_bytes()
    gateway.close()
    if attack == "modify":
        data = json.loads(payload.read_text())
        data["content"] = "red"
        payload.write_text(json.dumps(data), encoding="utf-8")
    elif attack == "swap":
        assert swapped_payload is not None
        payload.write_bytes(swapped_payload)
    elif attack == "truncate":
        payload.write_text("{", encoding="utf-8")
    elif attack == "delete":
        payload.unlink()
    elif attack == "malformed":
        payload.write_bytes(b"\xff\xfe")
    else:
        data = json.loads(payload.read_text())
        data["schema"] = "gateway-payload-v0.3a"
        payload.write_text(json.dumps(data), encoding="utf-8")
    restarted = _gateway(tmp_path, _config(tmp_path))
    result = restarted.read_memory_envelope(
        record_id, destination_agent="foreground", correlation_id="tamper-read"
    )
    assert result.decision is MemoryDecision.BLOCK
    assert result.reason_code == "PERSISTENT_STATE_PAYLOAD_MISMATCH"
    restarted.close()


def test_model_output_consumption_survives_restart(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    gateway.inspect_user_input("hello", workflow_id="consume-output")
    context = gateway.begin_model_turn("consume-output", turn=1)
    payload = {
        "action": "TOOL_CALL",
        "tool": "calculator",
        "arguments": {"operation": "add", "left": 1, "right": 2},
    }
    output = gateway.derive_model_output(
        json.dumps(payload), context=context, action_type="TOOL_CALL"
    )
    result = gateway.dispatch_runtime_tool_call(
        output, "calculator", payload["arguments"], workflow_id="consume-output"
    )
    assert result.status.value == "PROCEEDED"
    persistent_id = gateway.security_events.persistent_event_id(output.event_id)
    gateway.close()
    restarted = _gateway(tmp_path, _config(tmp_path))
    assert restarted.security_events.state.is_consumed(
        token_kind="model_output", token_id=persistent_id
    )
    assert (
        restarted.security_events.consume_once("model_output", persistent_id, persistent_id)
        == "PERSISTENT_STATE_ALREADY_CONSUMED"
    )
    restarted.close()


def test_unfinished_model_turn_is_boot_bound_and_rejected_after_restart(tmp_path: Path) -> None:
    config = _config(tmp_path)
    first = _gateway(tmp_path, config)
    first.inspect_user_input("hello", workflow_id="old-turn")
    old_context = first.begin_model_turn("old-turn", turn=1)
    first.close()
    restarted = _gateway(tmp_path, config)
    with pytest.raises(ValueError, match="active causal event store"):
        restarted.derive_model_output(
            "not reusable",
            context=old_context,
            action_type="FINAL_RESPONSE",
        )
    restarted.close()


def test_persistent_exact_action_binding_blocks_argument_substitution(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    gateway.inspect_user_input("calculate", workflow_id="payload-binding")
    context = gateway.begin_model_turn("payload-binding", turn=1)
    payload = {
        "action": "TOOL_CALL",
        "tool": "calculator",
        "arguments": {"operation": "add", "left": 1, "right": 2},
    }
    output = gateway.derive_model_output(
        json.dumps(payload), context=context, action_type="TOOL_CALL"
    )
    result = gateway.dispatch_runtime_tool_call(
        output,
        "calculator",
        {"operation": "add", "left": 10, "right": 20},
        workflow_id="payload-binding",
    )
    assert result.status.value == "BLOCKED"
    assert result.operation["runtime_reason_code"] == "RUNTIME_ACTION_PAYLOAD_MISMATCH"
    gateway.close()


def test_privileged_action_fails_closed_when_audit_backlog_exceeds_bound(
    tmp_path: Path,
) -> None:
    config = PersistentRuntimeConfig(
        PersistentStateConfig(tmp_path / "authority", "runtime-test"),
        max_pending_audit=1,
    )
    gateway = _gateway(tmp_path, config)
    gateway.inspect_user_input("calculate", workflow_id="audit-bound")
    context = gateway.begin_model_turn("audit-bound", turn=1)
    payload = {
        "action": "TOOL_CALL",
        "tool": "workspace_reader",
        "arguments": {"path": "missing.txt"},
    }
    output = gateway.derive_model_output(
        json.dumps(payload), context=context, action_type="TOOL_CALL"
    )
    with pytest.raises(PersistentRuntimeError) as failure:
        gateway.dispatch_runtime_tool_call(
            output, "workspace_reader", payload["arguments"], workflow_id="audit-bound"
        )
    assert failure.value.code == "PERSISTENT_STATE_AUDIT_BACKLOG"
    gateway.close()


def test_agent_message_consumption_and_boot_bound_control(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    source = gateway.agent_directory.register("source")
    gateway.agent_directory.register("destination")
    content = gateway.create_content(
        "status",
        source_type=ContentSourceType.INTERNAL,
        trust=TrustLevel.TRUSTED,
        provenance=("host:test",),
        producing_boundary="test",
    )
    control = gateway.agent_directory.authorize_control(
        "status",
        source_agent="source",
        destination_agent="destination",
        correlation_id="agent-restart",
    )
    result = gateway.send_agent_message(
        source,
        AgentMessageRequest(
            "source",
            "destination",
            MessagePurpose.CONTROL,
            content,
            "agent-restart",
            control=control,
        ),
    )
    assert gateway.resolve_agent_message_input(result, destination_agent="destination") is not None
    assert result.event_id is not None
    persistent_id = gateway.security_events.persistent_event_id(result.event_id)
    gateway.close()
    restarted = _gateway(tmp_path, _config(tmp_path))
    assert restarted.security_events.state.is_consumed(
        token_kind="agent_message", token_id=persistent_id
    )
    assert (
        restarted.agent_directory.consume_control(
            control,
            source_agent="source",
            destination_agent="destination",
            correlation_id="agent-restart",
        )
        == "UNAUTHORIZED_CONTROL_MESSAGE"
    )
    restarted.close()


def test_audit_append_failure_leaves_durable_outbox_for_recovery(tmp_path: Path) -> None:
    blocked_audit = tmp_path / "audit-target"
    blocked_audit.mkdir()
    config = _config(tmp_path, audit_path=blocked_audit)
    gateway = _gateway(tmp_path, config)
    gateway.inspect_user_input("hello", workflow_id="audit-outbox")
    assert gateway.security_events.state.pending_audit()
    gateway.close()
    blocked_audit.rmdir()
    restarted = _gateway(tmp_path, config)
    assert restarted.security_events.state.pending_audit() == ()
    assert blocked_audit.exists()
    restarted.close()


def test_stale_workflow_object_loses_cas(tmp_path: Path) -> None:
    config = _config(tmp_path)
    first = _gateway(tmp_path, config)
    first.inspect_user_input("first", workflow_id="cas-workflow")
    second = _gateway(tmp_path, config)
    second.current_content("cas-workflow")
    stale = second.security_events._workflows["cas-workflow"]
    first.inspect_retrieved_content("ordinary update", workflow_id="cas-workflow")
    latest = first.security_events.state.get_workflow("cas-workflow")
    with pytest.raises(WorkflowCASConflict):
        second.security_events.state.advance_workflow(
            "cas-workflow",
            expected_revision=stale.revision,
            expected_head=stale.head_event_id,
            new_head=latest.head_event_id,
        )
    first.close()
    second.close()
