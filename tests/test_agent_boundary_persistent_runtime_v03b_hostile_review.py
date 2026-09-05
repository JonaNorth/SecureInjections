from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from secureinjections.gateway import (
    ContentEnvelope,
    GuardedToolGateway,
    LocalToolRegistry,
    PersistentRuntimeConfig,
    RuntimeBackend,
)
from secureinjections.gateway.causal_audit import (
    append_chained_audit,
    append_chained_audit_once,
    verify_causal_audit,
)
from secureinjections.gateway.persistent_runtime import PersistentCausalEventStore
from secureinjections.guard import Guard
from secureinjections.persistent_state import PersistentStateConfig, PersistentStateError


def _config(root: Path) -> PersistentRuntimeConfig:
    return PersistentRuntimeConfig(
        PersistentStateConfig(root / "authority", "runtime-hostile-review")
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


def _write_memory(gateway: GuardedToolGateway, workflow_id: str, value: str) -> str:
    gateway.inspect_user_input(value, workflow_id=workflow_id)
    context = gateway.begin_model_turn(workflow_id, turn=1)
    memory = {"preference": value}
    output = gateway.derive_model_output(
        json.dumps({"action": "MEMORY_WRITE", "memory": memory}),
        context=context,
        action_type="MEMORY_WRITE",
    )
    result = gateway.write_runtime_memory(output, memory, workflow_id=workflow_id)
    assert result.status.value == "PROCEEDED"
    return gateway.memory.records[-1].record_id


def test_persistent_workflow_reload_does_not_prefer_stale_local_cache(tmp_path: Path) -> None:
    config = _config(tmp_path)
    first = _gateway(tmp_path, config)
    first.inspect_user_input("first", workflow_id="shared")
    assert first.current_content("shared").content == "first"  # type: ignore[union-attr]

    second = _gateway(tmp_path, config)
    assert second.current_content("shared") is not None
    second.inspect_retrieved_content("second", workflow_id="shared")

    refreshed = first.current_content("shared")
    assert refreshed is not None and refreshed.content == "second"
    first.close()
    second.close()


def test_cached_event_cannot_mask_authenticated_store_tampering(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    gateway.inspect_user_input("hello", workflow_id="cached-event")
    event_id = gateway.current_causal_parent_ids("cached-event")[0]
    assert gateway.security_events.get(event_id) is not None

    database = gateway.security_events.state.paths.database
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE causal_events SET event_type = 'external_send' WHERE event_id = ?",
            (gateway.security_events.persistent_event_id(event_id),),
        )
        connection.commit()

    with pytest.raises(PersistentStateError):
        gateway.security_events.get(event_id)
    gateway.close()


def test_memory_index_cannot_redirect_one_record_to_another_authority(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    first_id = _write_memory(gateway, "memory-a", "blue")
    second_id = _write_memory(gateway, "memory-b", "red")
    backend = gateway.security_events
    first_path = backend.memory_directory / f"{first_id}.json"
    second_path = backend.memory_directory / f"{second_id}.json"
    first = json.loads(first_path.read_text(encoding="utf-8"))
    second = json.loads(second_path.read_text(encoding="utf-8"))
    for field in ("key", "content_id", "write_event_id", "correlation_id", "causal_parent_ids"):
        first[field] = second[field]
    first_path.write_text(json.dumps(first), encoding="utf-8")
    gateway.close()

    restarted = _gateway(tmp_path, _config(tmp_path))
    result = restarted.read_memory_envelope(
        first_id, destination_agent="foreground", correlation_id="redirect-read"
    )
    assert result.decision.value == "BLOCK"
    assert result.reason_code == "PERSISTENT_STATE_PAYLOAD_MISMATCH"
    restarted.close()


def test_duplicate_random_boot_nonce_cannot_reuse_previous_boot_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "secureinjections.gateway.persistent_runtime.secrets.token_hex", lambda _size: "0" * 32
    )
    config = _config(tmp_path)
    first = _gateway(tmp_path, config)
    first_epoch = first.security_events.boot_epoch
    first.close()
    second = _gateway(tmp_path, config)
    second_epoch = second.security_events.boot_epoch
    second.close()
    assert first_epoch != second_epoch


def test_backend_enum_cannot_be_bypassed_with_string_value(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises((TypeError, ValueError)):
        GuardedToolGateway(
            Guard(),
            LocalToolRegistry(workspace),
            backend="PERSISTENT",  # type: ignore[arg-type]
        )


def test_future_runtime_schema_fails_at_top_level_constructor(tmp_path: Path) -> None:
    config = _config(tmp_path)
    gateway = _gateway(tmp_path, config)
    database = gateway.security_events.state.paths.database
    gateway.close()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE runtime_extensions SET runtime_schema_version = ? WHERE singleton = 1",
            ("gateway-persistent-runtime-v9",),
        )
        connection.commit()
    with pytest.raises(Exception) as failure:
        _gateway(tmp_path, config)
    assert getattr(failure.value, "code", None) == "PERSISTENT_STATE_VERIFICATION_FAILED"


def test_wrong_deployment_fails_without_ephemeral_fallback(tmp_path: Path) -> None:
    config = _config(tmp_path)
    gateway = _gateway(tmp_path, config)
    gateway.close()
    wrong = PersistentRuntimeConfig(
        PersistentStateConfig(config.state.state_directory, "other-deployment")
    )
    with pytest.raises(Exception) as failure:
        _gateway(tmp_path, wrong)
    assert getattr(failure.value, "code", "").startswith("PERSISTENT_STATE_")


def test_admitted_output_object_is_stale_after_restart(tmp_path: Path) -> None:
    config = _config(tmp_path)
    first = _gateway(tmp_path, config)
    first.inspect_user_input("calculate", workflow_id="stale-output")
    context = first.begin_model_turn("stale-output", turn=1)
    payload = {
        "action": "TOOL_CALL",
        "tool": "calculator",
        "arguments": {"operation": "add", "left": 1, "right": 2},
    }
    output = first.derive_model_output(
        json.dumps(payload), context=context, action_type="TOOL_CALL"
    )
    first.close()
    restarted = _gateway(tmp_path, config)
    result = restarted.dispatch_runtime_tool_call(
        output, "calculator", payload["arguments"], workflow_id="stale-output"
    )
    assert result.status.value == "BLOCKED"
    assert result.operation["runtime_reason_code"] in {
        "RUNTIME_EVENT_NOT_FOUND",
        "RUNTIME_OUTPUT_CONTEXT_MISMATCH",
    }
    restarted.close()


def test_memory_record_identifier_cannot_traverse_payload_directory(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    result = gateway.read_memory_envelope(
        "../../forged", destination_agent="foreground", correlation_id="traversal"
    )
    assert result.decision.value == "BLOCK"
    assert result.reason_code == "PERSISTENT_STATE_PAYLOAD_MISMATCH"
    gateway.close()


@pytest.mark.parametrize(
    "model_json",
    [
        '{"action":"TOOL_CALL","tool":"calculator","tool":"calculator",'
        '"arguments":{"operation":"add","left":1,"right":2}}',
        '{"action":"TOOL_CALL","tool":"calculator",'
        '"arguments":{"operation":"add","left":true,"right":2}}',
        '{"action":"TOOL_CALL","tool":"calculator",'
        '"arguments":{"operation":"add","left":1.0,"right":2}}',
    ],
)
def test_action_binding_rejects_duplicate_keys_and_type_substitution(
    tmp_path: Path, model_json: str
) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    gateway.inspect_user_input("calculate", workflow_id="strict-json")
    context = gateway.begin_model_turn("strict-json", turn=1)
    output = gateway.derive_model_output(model_json, context=context, action_type="TOOL_CALL")
    result = gateway.dispatch_runtime_tool_call(
        output,
        "calculator",
        {"operation": "add", "left": 1, "right": 2},
        workflow_id="strict-json",
    )
    assert result.status.value == "BLOCKED"
    assert result.operation["runtime_reason_code"] == "RUNTIME_ACTION_PAYLOAD_MISMATCH"
    gateway.close()


def test_persistent_envelope_rehydration_rejects_caller_created_record() -> None:
    with pytest.raises(PermissionError):
        ContentEnvelope._from_verified_persistent(object(), "payload", object())


def test_low_level_persistent_adapter_rejects_direct_construction(tmp_path: Path) -> None:
    with pytest.raises(PermissionError):
        PersistentCausalEventStore(object(), object(), _config(tmp_path))  # type: ignore[arg-type]


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "fifo", "oversize", "permissions"])
def test_payload_special_file_and_size_attacks_fail_closed(tmp_path: Path, attack: str) -> None:
    gateway = _gateway(tmp_path, _config(tmp_path))
    record_id = _write_memory(gateway, "path-attacks", "blue")
    record = gateway.memory.records[-1]
    backend = gateway.security_events
    content_id = backend.persistent_content_id(record.content.content_id)
    payload = backend.payload_directory / f"{content_id}.json"
    original = payload.read_bytes()
    payload.unlink()
    if attack == "symlink":
        target = tmp_path / "target.json"
        target.write_bytes(original)
        payload.symlink_to(target)
    elif attack == "hardlink":
        target = tmp_path / "target.json"
        target.write_bytes(original)
        os.link(target, payload)
    elif attack == "fifo":
        os.mkfifo(payload, 0o600)
    elif attack == "oversize":
        payload.write_bytes(b"{" + b" " * (backend.MAX_PAYLOAD_BYTES + 1))
    else:
        payload.write_bytes(original)
        payload.chmod(0o644)
    result = gateway.read_memory_envelope(
        record_id, destination_agent="foreground", correlation_id="path-attack-read"
    )
    assert result.decision.value == "BLOCK"
    assert result.reason_code == "PERSISTENT_STATE_PAYLOAD_MISMATCH"
    gateway.close()


def test_audit_projection_reconciles_append_before_export_marker(tmp_path: Path) -> None:
    audit_path = tmp_path / "runtime-audit.jsonl"
    config = PersistentRuntimeConfig(
        PersistentStateConfig(tmp_path / "authority", "runtime-hostile-review"),
        audit_path=audit_path,
    )
    gateway = _gateway(tmp_path, config)
    backend = gateway.security_events
    backend.state.record_event(event_type="policy_decision", correlation_id="outbox-crash")
    item = backend.state.pending_audit()[0]
    logical = {
        "schema_version": "persistent-runtime-audit-v0.3b",
        "authority_instance_id": backend.state.instance_id,
        "outbox_id": item.outbox_id,
        "mutation_sequence": item.mutation_sequence,
        "mutation_type": item.mutation_type,
        "authority_payload": json.loads(item.payload_json),
        "raw_content_retained": False,
    }
    append_chained_audit_once(
        audit_path,
        logical,
        identity_fields=("authority_instance_id", "outbox_id"),
    )
    before = len(audit_path.read_text(encoding="utf-8").splitlines())
    backend.project_audit()
    after = len(audit_path.read_text(encoding="utf-8").splitlines())
    assert before == after
    assert backend.state.pending_audit() == ()
    gateway.close()


def test_audit_verifier_detects_duplicated_persistent_mutation(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    base = {
        "schema_version": "persistent-runtime-audit-v0.3b",
        "authority_instance_id": "instance-a",
        "mutation_sequence": 7,
        "raw_content_retained": False,
    }
    append_chained_audit(path, {**base, "outbox_id": 10})
    append_chained_audit(path, {**base, "outbox_id": 11})
    verification = verify_causal_audit(path)
    assert not verification.valid
    assert "DUPLICATE_PERSISTENT_MUTATION:2" in verification.issues


def test_audit_projector_rejects_conflict_and_truncated_tail(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    record = {"authority_instance_id": "instance-a", "outbox_id": 1, "value": "safe"}
    append_chained_audit_once(path, record, identity_fields=("authority_instance_id", "outbox_id"))
    with pytest.raises(ValueError, match="conflicting"):
        append_chained_audit_once(
            path,
            {**record, "value": "changed"},
            identity_fields=("authority_instance_id", "outbox_id"),
        )
    with path.open("ab") as stream:
        stream.write(b"{")
    with pytest.raises(ValueError, match="truncated"):
        append_chained_audit_once(
            path,
            {"authority_instance_id": "instance-a", "outbox_id": 2},
            identity_fields=("authority_instance_id", "outbox_id"),
        )


def test_oldest_audit_age_blocks_privilege_but_not_benign_checks(tmp_path: Path) -> None:
    config = PersistentRuntimeConfig(
        PersistentStateConfig(tmp_path / "authority", "runtime-hostile-review"),
        max_pending_audit=9_999,
        max_pending_audit_age_seconds=1e-9,
    )
    gateway = _gateway(tmp_path, config)
    gateway.security_events.enforce_audit_bound(privileged=False)
    with pytest.raises(Exception) as failure:
        gateway.security_events.enforce_audit_bound(privileged=True)
    assert getattr(failure.value, "code", None) == "PERSISTENT_STATE_AUDIT_BACKLOG"
    gateway.close()


def test_crash_before_memory_index_publish_cannot_create_readable_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    gateway = _gateway(tmp_path, config)
    gateway.inspect_user_input("blue", workflow_id="memory-crash")
    context = gateway.begin_model_turn("memory-crash", turn=1)
    memory = {"preference": "blue"}
    output = gateway.derive_model_output(
        json.dumps({"action": "MEMORY_WRITE", "memory": memory}),
        context=context,
        action_type="MEMORY_WRITE",
    )
    original = PersistentCausalEventStore._atomic_json

    def fail_memory_index(
        cls: type[PersistentCausalEventStore], path: Path, value: dict[str, object]
    ) -> None:
        if path.parent.name == "runtime-memory":
            raise OSError("injected crash before memory index rename")
        original(path, value)

    monkeypatch.setattr(PersistentCausalEventStore, "_atomic_json", classmethod(fail_memory_index))
    with pytest.raises(OSError, match="injected crash"):
        gateway.write_runtime_memory(output, memory, workflow_id="memory-crash")
    record_id = gateway.memory.records[-1].record_id
    gateway.close()
    monkeypatch.undo()

    restarted = _gateway(tmp_path, config)
    result = restarted.read_memory_envelope(
        record_id, destination_agent="foreground", correlation_id="after-crash"
    )
    assert result.decision.value == "BLOCK"
    assert result.reason_code == "PERSISTENT_STATE_PAYLOAD_MISMATCH"
    restarted.close()


def test_untrusted_taint_and_policy_survive_five_memory_restart_generations(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    gateway = _gateway(tmp_path, config)
    gateway.inspect_user_input("begin", workflow_id="generation-0")
    gateway.inspect_retrieved_content("ordinary covert marker", workflow_id="generation-0")
    record_id = ""
    for generation in range(6):
        workflow_id = f"generation-{generation}"
        if generation:
            read = gateway.read_memory_envelope(
                record_id,
                destination_agent="background",
                correlation_id=workflow_id,
            )
            assert read.envelope is not None and read.envelope.ever_untrusted
            input_envelopes = (read.envelope,)
        else:
            input_envelopes = ()
        context = gateway.begin_model_turn(
            workflow_id, input_envelopes=input_envelopes, turn=generation + 1
        )
        memory = {"summary": "ordinary covert marker"}
        output = gateway.derive_model_output(
            json.dumps({"action": "MEMORY_WRITE", "memory": memory}),
            context=context,
            action_type="MEMORY_WRITE",
        )
        result = gateway.write_runtime_memory(output, memory, workflow_id=workflow_id)
        assert result.status.value == "PROCEEDED", result
        record = gateway.memory.records[-1]
        assert record.content.ever_untrusted
        record_id = record.record_id
        gateway.close()
        gateway = _gateway(tmp_path, config)

    final_read = gateway.read_memory_envelope(
        record_id, destination_agent="background", correlation_id="privileged-after-restarts"
    )
    assert final_read.envelope is not None and final_read.envelope.ever_untrusted
    context = gateway.begin_model_turn(
        "privileged-after-restarts", input_envelopes=(final_read.envelope,), turn=7
    )
    payload = {
        "action": "TOOL_CALL",
        "tool": "workspace_reader",
        "arguments": {"path": "secret.txt"},
    }
    output = gateway.derive_model_output(
        json.dumps(payload), context=context, action_type="TOOL_CALL"
    )
    blocked = gateway.dispatch_runtime_tool_call(
        output,
        "workspace_reader",
        payload["arguments"],
        workflow_id="privileged-after-restarts",
    )
    assert blocked.status.value != "PROCEEDED"
    assert not blocked.tool_executed
    assert not blocked.side_effect_performed
    gateway.close()
