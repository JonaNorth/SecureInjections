from __future__ import annotations

import json
import multiprocessing
import threading
from pathlib import Path
from queue import Queue
from typing import Any

import pytest

from secureinjections.gateway import (
    AgentAuthority,
    AgentDirectory,
    FileReadRequest,
    GatewayExecutionError,
    GuardedToolGateway,
    LocalToolRegistry,
    MemoryWriteRequest,
    PersistentRuntimeConfig,
    PersistentRuntimeError,
    RuntimeBackend,
)
from secureinjections.gateway.execution import _PolicyAuthorization
from secureinjections.guard import Guard
from secureinjections.persistent_state import (
    ExecutionAuthority,
    ExecutionState,
    ExecutionStateConflict,
    IdempotencyClass,
    PersistentSecurityState,
    PersistentStateConfig,
)
from secureinjections.persistent_state.execution import _HOST_EXECUTION_AUTHORITY_CAPABILITY
from secureinjections.persistent_state.fake_destination import FakeDestination


def _setup(
    root: Path, *, capabilities: tuple[str, ...] = ("execute:fake",)
) -> tuple[GuardedToolGateway, AgentAuthority, Any]:
    workspace = root / "workspace"
    workspace.mkdir(exist_ok=True)
    directory = AgentDirectory()
    agent = directory.register("agent", capabilities=capabilities)
    gateway = GuardedToolGateway(
        Guard(),
        LocalToolRegistry(workspace),
        agent_directory=directory,
        backend=RuntimeBackend.PERSISTENT,
        persistent_config=PersistentRuntimeConfig(
            PersistentStateConfig(root / "authority", "gateway-v03c2-hostile")
        ),
    )
    control = gateway._execution_control_for_host()
    gateway.register_fake_execution_destination(
        control,
        destination_id="fake",
        action_types=("TOOL_CALL", "EXTERNAL_SEND"),
        runner=FakeDestination(root / "fake.sqlite3"),
        runner_identity="fake-v1",
        configuration={"version": 1},
        idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
        required_capability="execute:fake",
    )
    return gateway, agent, control


def _derive(
    gateway: GuardedToolGateway,
    workflow_id: str,
    action: dict[str, Any],
    *,
    user: str = "perform the requested action",
) -> Any:
    gateway.inspect_user_input(user, workflow_id=workflow_id)
    context = gateway.begin_model_turn(workflow_id, turn=1)
    return gateway.derive_model_output(
        json.dumps(action, sort_keys=True, separators=(",", ":")),
        context=context,
        action_type=str(action["action"]),
    )


def _action(expression: str = "2+2") -> dict[str, Any]:
    return {
        "action": "TOOL_CALL",
        "arguments": {"expression": expression},
        "tool": "calculator",
    }


def _advance_shared_security_configuration(root_text: str, output: Any) -> None:
    state = PersistentSecurityState.open(
        PersistentStateConfig(Path(root_text) / "authority", "gateway-v03c2-hostile")
    )
    try:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        current = authority.get_security_configuration()
        assert current is not None
        updated = authority.update_security_configuration(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            expected_epoch=current.epoch,
            configuration_digest="f" * 64,
            worker_attach_digest=current.worker_attach_digest,
        )
        output.put(updated.epoch)
    finally:
        state.close()


def _integrated_worker_process(
    root_text: str,
    boot_event_id: str,
    worker_attach_token: str,
    intent_id: str,
    gate: Any,
    output: Any,
) -> None:
    root = Path(root_text)
    directory = AgentDirectory()
    agent = directory.register("agent", capabilities=("execute:fake",))
    gateway: GuardedToolGateway | None = None
    try:
        gateway = GuardedToolGateway(
            Guard(),
            LocalToolRegistry(root / "workspace"),
            agent_directory=directory,
            backend=RuntimeBackend.PERSISTENT,
            persistent_config=PersistentRuntimeConfig(
                PersistentStateConfig(root / "authority", "gateway-v03c2-hostile"),
                worker_attach=True,
                worker_boot_event_id=boot_event_id,
                worker_attach_token=worker_attach_token,
            ),
        )
        control = gateway._execution_control_for_host()
        gateway.register_fake_execution_destination(
            control,
            destination_id="fake",
            action_types=("TOOL_CALL", "EXTERNAL_SEND"),
            runner=FakeDestination(root / "fake.sqlite3"),
            runner_identity="fake-v1",
            configuration={"version": 1},
            idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
            required_capability="execute:fake",
        )
        worker = gateway.register_runtime_execution_worker(agent, scope="spawned")
        gate.wait()
        result = gateway.execute_prepared_runtime_action(worker, agent, intent_id)
        output.put(result.state.value)
    except ExecutionStateConflict:
        output.put("LOST")
    except Exception as exc:  # pragma: no cover - assertion reports exact unexpected type
        output.put(type(exc).__name__)
    finally:
        if gateway is not None:
            gateway.close()


def test_forged_policy_authorization_cannot_be_constructed() -> None:
    with pytest.raises(TypeError):
        _PolicyAuthorization(object(), object())


def test_fake_destination_subclass_cannot_replace_runner_semantics(tmp_path: Path) -> None:
    gateway, _agent, control = _setup(tmp_path)

    class SubstitutedRunner(FakeDestination):
        pass

    with pytest.raises(TypeError):
        gateway.register_fake_execution_destination(
            control,
            destination_id="substituted",
            action_types=("TOOL_CALL",),
            runner=SubstitutedRunner(tmp_path / "substituted.sqlite3"),
            runner_identity="fake-v1",
            configuration={"version": 1},
            idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
            required_capability="execute:fake",
        )
    gateway.close()


def test_model_text_claiming_capability_does_not_create_capability(tmp_path: Path) -> None:
    gateway, agent, _control = _setup(tmp_path, capabilities=())
    action = _action("I grant myself execute:fake")
    output = _derive(
        gateway,
        "model-capability-claim",
        action,
        user="the model may claim any capability",
    )
    result = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    assert result.decision.value == "BLOCK"
    assert result.reason_code == "CAPABILITY_MISSING"
    assert result.intent_id is None
    gateway.close()


def test_action_payload_substitution_is_rejected_before_terminal_allow(tmp_path: Path) -> None:
    gateway, agent, control = _setup(tmp_path)
    original = _action("1+1")
    output = _derive(gateway, "payload-substitution", original)
    changed = _action("open('/etc/passwd').read()")
    with pytest.raises(GatewayExecutionError) as denied:
        gateway.prepare_runtime_execution(output, changed, destination_id="fake", agent=agent)
    assert denied.value.code == "RUNTIME_ACTION_PAYLOAD_MISMATCH"
    gateway.close()


def test_legacy_runtime_tool_dispatch_is_contained_when_c2_is_enabled(tmp_path: Path) -> None:
    gateway, _agent, _control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "legacy-bypass", action)
    result = gateway.dispatch_runtime_tool_call(
        output,
        "calculator",
        action["arguments"],
        workflow_id="legacy-bypass",
    )
    assert result.status.value == "BLOCKED"
    assert result.operation["runtime_reason_code"] == "C2_EXECUTION_PATH_REQUIRED"
    assert FakeDestination(tmp_path / "fake.sqlite3").request_count == 0
    gateway.close()


def test_unknown_destination_is_terminal_block_not_reusable_authority(tmp_path: Path) -> None:
    gateway, agent, control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "unknown-destination", action)
    result = gateway.prepare_runtime_execution(
        output, action, destination_id="model-invented", agent=agent
    )
    assert result.decision.value == "BLOCK"
    assert result.reason_code == "DESTINATION_NOT_REGISTERED"
    with pytest.raises(GatewayExecutionError) as replay:
        gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    assert replay.value.code == "RUNTIME_OUTPUT_NOT_CURRENT"
    gateway.close()


def test_capability_revocation_inside_dispatch_hook_cannot_cross_fence(tmp_path: Path) -> None:
    gateway, agent, control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "capability-toctou", action)
    prepared = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    worker = gateway.register_runtime_execution_worker(agent, scope="foreground")
    fired = False

    def revoke(point: str) -> None:
        nonlocal fired
        if point == "before_dispatch_fence_mutation" and not fired:
            fired = True
            gateway.replace_execution_capabilities(control, agent.agent_id, ())

    gateway.security_events.state._set_failure_injector_for_testing(revoke)
    outcome = gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
    assert fired
    assert outcome.state is ExecutionState.CANCELLED
    assert outcome.reason_code == "AUTHORIZATION_STALE"
    assert FakeDestination(tmp_path / "fake.sqlite3").request_count == 0
    gateway.close()


def test_destination_change_inside_dispatch_hook_cannot_cross_fence(tmp_path: Path) -> None:
    gateway, agent, control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "destination-toctou", action)
    prepared = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    worker = gateway.register_runtime_execution_worker(agent, scope="foreground")
    fired = False

    def replace(point: str) -> None:
        nonlocal fired
        if point == "before_dispatch_fence_mutation" and not fired:
            fired = True
            gateway.register_fake_execution_destination(
                control,
                destination_id="fake",
                action_types=("TOOL_CALL",),
                runner=FakeDestination(tmp_path / "fake-v2.sqlite3"),
                runner_identity="fake-v2",
                configuration={"version": 2},
                idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
                required_capability="execute:fake",
            )

    gateway.security_events.state._set_failure_injector_for_testing(replace)
    outcome = gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
    assert fired
    assert outcome.state is ExecutionState.CANCELLED
    assert outcome.reason_code == "AUTHORIZATION_STALE"
    assert not (tmp_path / "fake-v2.sqlite3").exists()
    gateway.close()


def test_policy_change_inside_dispatch_hook_cannot_cross_fence(tmp_path: Path) -> None:
    gateway, agent, control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "policy-toctou", action)
    prepared = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    worker = gateway.register_runtime_execution_worker(agent, scope="foreground")
    fired = False

    def tighten(point: str) -> None:
        nonlocal fired
        if point == "before_dispatch_fence_mutation" and not fired:
            fired = True
            gateway.advance_execution_policy_revision(control)

    gateway.security_events.state._set_failure_injector_for_testing(tighten)
    outcome = gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
    assert fired
    assert outcome.state is ExecutionState.CANCELLED
    assert outcome.reason_code == "AUTHORIZATION_STALE"
    gateway.close()


def test_cross_thread_worker_authority_fails_before_store_access(tmp_path: Path) -> None:
    gateway, agent, _control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "cross-thread", action)
    prepared = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    worker = gateway.register_runtime_execution_worker(agent, scope="foreground")
    results: Queue[str] = Queue()

    def misuse() -> None:
        try:
            gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
        except GatewayExecutionError as exc:
            results.put(exc.code)

    thread = threading.Thread(target=misuse)
    thread.start()
    thread.join()
    assert results.get_nowait() == "WORKER_AUTHORITY_INVALID"
    gateway.close()


def test_audit_backlog_blocks_preparation_before_source_consumption(tmp_path: Path) -> None:
    gateway, agent, _control = _setup(tmp_path)
    action = _action()
    output = _derive(gateway, "audit-backlog", action)
    gateway.security_events.audit_projection_error = True
    with pytest.raises(PersistentRuntimeError) as blocked:
        gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    assert blocked.value.code == "PERSISTENT_STATE_AUDIT_BACKLOG"
    gateway.security_events.audit_projection_error = False
    prepared = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    assert prepared.intent_id is not None
    gateway.close()


def test_audit_projection_failure_after_effect_forces_unknown(tmp_path: Path) -> None:
    gateway, agent, control = _setup(tmp_path)

    def break_projection(point: str) -> None:
        if point == "after_fake_effect_commit":
            gateway.security_events.audit_projection_error = True

    gateway.register_fake_execution_destination(
        control,
        destination_id="fake",
        action_types=("TOOL_CALL",),
        runner=FakeDestination(
            tmp_path / "fake-with-audit-failure.sqlite3",
            failure_injector=break_projection,
        ),
        runner_identity="fake-audit-failure",
        configuration={"version": 2},
        idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
        required_capability="execute:fake",
    )
    action = _action()
    output = _derive(gateway, "audit-outcome", action)
    prepared = gateway.prepare_runtime_execution(output, action, destination_id="fake", agent=agent)
    worker = gateway.register_runtime_execution_worker(agent, scope="foreground")
    outcome = gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
    assert outcome.state is ExecutionState.OUTCOME_UNKNOWN
    assert outcome.reason_code == "AUDIT_BACKLOG_OUTCOME_UNKNOWN"
    assert gateway.security_events.state.get_workflow("audit-outcome").status == "BLOCKED_UNKNOWN"
    gateway.close()


def test_provider_specific_ids_do_not_change_normalized_authority(tmp_path: Path) -> None:
    gateway, agent, _control = _setup(tmp_path)
    action = _action()
    ollama = _derive(gateway, "ollama", action)
    first = gateway.prepare_runtime_execution(ollama, action, destination_id="fake", agent=agent)
    openai = _derive(gateway, "openai-compatible", dict(reversed(tuple(action.items()))))
    second = gateway.prepare_runtime_execution(openai, action, destination_id="fake", agent=agent)
    assert first.action_fingerprint == second.action_fingerprint
    gateway.close()


@pytest.mark.parametrize("workers", [2, 6])
def test_spawned_integrated_workers_produce_one_dispatch_fence(
    tmp_path: Path, workers: int
) -> None:
    gateway, agent, control = _setup(tmp_path)
    action = _action()
    output_event = _derive(gateway, f"spawn-race-{workers}", action)
    prepared = gateway.prepare_runtime_execution(
        output_event, action, destination_id="fake", agent=agent
    )
    boot_event_id = gateway.security_events.boot_epoch
    worker_attach_token = gateway.issue_execution_worker_attach_token(control)
    gateway.close()
    context = multiprocessing.get_context("spawn")
    gate, output = context.Event(), context.Queue()
    processes = [
        context.Process(
            target=_integrated_worker_process,
            args=(
                str(tmp_path),
                boot_event_id,
                worker_attach_token,
                prepared.intent_id,
                gate,
                output,
            ),
        )
        for _ in range(workers)
    ]
    for process in processes:
        process.start()
    gate.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    results = [output.get(timeout=5) for _ in processes]
    assert results.count("COMPLETED") == 1, results
    assert results.count("LOST") == workers - 1, results
    assert FakeDestination(tmp_path / "fake.sqlite3").request_count == 1


def test_spawned_host_update_invalidates_stale_worker_before_fence(tmp_path: Path) -> None:
    gateway, agent, _control = _setup(tmp_path)
    action = _action()
    prepared = gateway.prepare_runtime_execution(
        _derive(gateway, "cross-process-revoke", action),
        action,
        destination_id="fake",
        agent=agent,
    )
    worker = gateway.register_runtime_execution_worker(agent, scope="foreground")
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(
        target=_advance_shared_security_configuration,
        args=(str(tmp_path), output),
    )
    process.start()
    process.join(30)
    assert process.exitcode == 0
    assert output.get(timeout=5) >= 2
    result = gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
    assert result.state is ExecutionState.CANCELLED
    assert result.reason_code == "AUTHORIZATION_STALE"
    assert FakeDestination(tmp_path / "fake.sqlite3").request_count == 0
    gateway.close()


def test_c2_required_mode_survives_restart_without_registry(tmp_path: Path) -> None:
    gateway, _agent, _control = _setup(tmp_path)
    gateway.close()
    restarted = GuardedToolGateway(
        Guard(),
        LocalToolRegistry(tmp_path / "workspace"),
        backend=RuntimeBackend.PERSISTENT,
        persistent_config=PersistentRuntimeConfig(
            PersistentStateConfig(tmp_path / "authority", "gateway-v03c2-hostile")
        ),
    )
    action = _action()
    output = _derive(restarted, "restart-downgrade", action)
    result = restarted.dispatch_runtime_tool_call(
        output,
        "calculator",
        action["arguments"],
        workflow_id="restart-downgrade",
    )
    assert result.operation["runtime_reason_code"] == "C2_EXECUTION_PATH_REQUIRED"
    restarted.close()


def test_direct_gateway_side_effect_api_is_blocked_in_c2_mode(tmp_path: Path) -> None:
    gateway, _agent, _control = _setup(tmp_path)
    gateway.inspect_user_input("calculate", workflow_id="direct-bypass")
    with pytest.raises(GatewayExecutionError) as denied:
        gateway.dispatch_tool_call("calculator", {"expression": "1+1"}, workflow_id="direct-bypass")
    assert denied.value.code == "C2_EXECUTION_PATH_REQUIRED"
    with pytest.raises(GatewayExecutionError):
        gateway.file_reader.read(FileReadRequest("workspace", "missing.txt", "direct-bypass"))
    source = gateway.current_content("direct-bypass")
    assert source is not None
    with pytest.raises(GatewayExecutionError):
        gateway.memory.write(
            MemoryWriteRequest(
                "key",
                source,
                "direct-bypass",
            )
        )
    gateway.close()


def test_background_worker_cannot_claim_foreground_action(tmp_path: Path) -> None:
    gateway, agent, _control = _setup(tmp_path)
    action = _action()
    prepared = gateway.prepare_runtime_execution(
        _derive(gateway, "scope-confusion", action),
        action,
        destination_id="fake",
        agent=agent,
    )
    worker = gateway.register_runtime_execution_worker(agent, scope="background")
    result = gateway.execute_prepared_runtime_action(worker, agent, prepared.intent_id)
    assert result.state is ExecutionState.CANCELLED
    assert result.reason_code == "WORKER_SCOPE_MISMATCH"
    assert FakeDestination(tmp_path / "fake.sqlite3").request_count == 0
    gateway.close()


def test_worker_attach_requires_out_of_band_host_token(tmp_path: Path) -> None:
    gateway, _agent, _control = _setup(tmp_path)
    boot_event_id = gateway.security_events.boot_epoch
    gateway.close()
    with pytest.raises(PersistentRuntimeError) as missing:
        GuardedToolGateway(
            Guard(),
            LocalToolRegistry(tmp_path / "workspace"),
            backend=RuntimeBackend.PERSISTENT,
            persistent_config=PersistentRuntimeConfig(
                PersistentStateConfig(tmp_path / "authority", "gateway-v03c2-hostile"),
                worker_attach=True,
                worker_boot_event_id=boot_event_id,
            ),
        )
    assert missing.value.code == "PERSISTENT_STATE_RUNTIME_MISMATCH"
    with pytest.raises(GatewayExecutionError) as denied:
        GuardedToolGateway(
            Guard(),
            LocalToolRegistry(tmp_path / "workspace"),
            backend=RuntimeBackend.PERSISTENT,
            persistent_config=PersistentRuntimeConfig(
                PersistentStateConfig(tmp_path / "authority", "gateway-v03c2-hostile"),
                worker_attach=True,
                worker_boot_event_id=boot_event_id,
                worker_attach_token="not-the-host-token",
            ),
        )
    assert denied.value.code == "WORKER_ATTACH_AUTHORITY_INVALID"


def test_worker_attach_open_is_stable_for_one_hundred_cycles(tmp_path: Path) -> None:
    gateway, _agent, control = _setup(tmp_path)
    boot_event_id = gateway.security_events.boot_epoch
    token = gateway.issue_execution_worker_attach_token(control)
    gateway.close()
    for _ in range(100):
        directory = AgentDirectory()
        directory.register("agent", capabilities=("execute:fake",))
        attached = GuardedToolGateway(
            Guard(),
            LocalToolRegistry(tmp_path / "workspace"),
            agent_directory=directory,
            backend=RuntimeBackend.PERSISTENT,
            persistent_config=PersistentRuntimeConfig(
                PersistentStateConfig(tmp_path / "authority", "gateway-v03c2-hostile"),
                worker_attach=True,
                worker_boot_event_id=boot_event_id,
                worker_attach_token=token,
            ),
        )
        attached_control = attached._execution_control_for_host()
        attached.register_fake_execution_destination(
            attached_control,
            destination_id="fake",
            action_types=("TOOL_CALL", "EXTERNAL_SEND"),
            runner=FakeDestination(tmp_path / "fake.sqlite3"),
            runner_identity="fake-v1",
            configuration={"version": 1},
            idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
            required_capability="execute:fake",
        )
        attached.close()
