from __future__ import annotations

import hashlib
import multiprocessing
import os
import pickle
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from secureinjections.persistent_state import (
    ExecutionAuthority,
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionState,
    ExecutionStateConflict,
    IdempotencyClass,
    PersistentSecurityState,
    PersistentStateConfig,
    StateVerificationError,
    WorkflowCASConflict,
)
from secureinjections.persistent_state.execution import (
    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
    normalize_action,
)
from secureinjections.persistent_state.fake_destination import (
    FakeCallerTermination,
    FakeDestination,
    FakeDestinationFailure,
    FakeDestinationMode,
    FakeDestinationTimeout,
)
from secureinjections.persistent_state.store import _HOST_ROOT_AUTHORITY_CAPABILITY


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(path: Path) -> PersistentStateConfig:
    return PersistentStateConfig(path, "execution-test", busy_timeout_ms=10_000)


def _seed(path: Path, workflow_id: str = "workflow-main") -> dict[str, str]:
    action = {"action": "TOOL_CALL", "arguments": {"left": 1, "right": 2}, "tool": "sum"}
    _, _, fingerprint = normalize_action(action)
    with PersistentSecurityState.initialize(_config(path)) as state:
        content = state._issue_authoritative_root_for_host(
            _HOST_ROOT_AUTHORITY_CAPABILITY,
            source_type="internal",
            trust="TRUSTED",
            content_digest=_digest("model-output"),
            producing_boundary="v03c1-test",
        )
        turn = state.record_event(
            event_type="model_turn",
            correlation_id=workflow_id,
            content_ids=(content.content_id,),
        )
        output = state.record_event(
            event_type="model_output",
            correlation_id=workflow_id,
            parent_event_ids=(turn.event_id,),
            content_ids=(content.content_id,),
            attributes={"action_fingerprint": fingerprint},
        )
        proposal = state.record_event(
            event_type="tool_proposal",
            correlation_id=workflow_id,
            parent_event_ids=(output.event_id,),
            content_ids=(content.content_id,),
            attributes={"action_fingerprint": fingerprint},
        )
        state.create_workflow(
            workflow_id, head_event_id=proposal.event_id, current_content_id=content.content_id
        )
        boot = state.record_event(
            event_type="runtime_boot", correlation_id="runtime-boot", attributes={"nonce": "a"}
        )
    return {
        "workflow": workflow_id,
        "content": content.content_id,
        "turn": turn.event_id,
        "output": output.event_id,
        "proposal": proposal.event_id,
        "boot": boot.event_id,
        "fingerprint": fingerprint,
    }


def _prepare(authority: ExecutionAuthority, ids: dict[str, str]) -> str:
    decision = authority.prepare_execution(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        workflow_id=ids["workflow"],
        expected_head_event_id=ids["proposal"],
        expected_revision=0,
        source_turn_event_id=ids["turn"],
        source_output_event_id=ids["output"],
        proposal_event_id=ids["proposal"],
        action={"tool": "sum", "arguments": {"right": 2, "left": 1}, "action": "TOOL_CALL"},
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-config-v1"),
        idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
        ancestry_event_ids=(ids["turn"], ids["output"], ids["proposal"]),
        content_digests=(_digest("model-output"),),
        policy_config_digest=_digest("policy-v1"),
    )
    assert decision.intent_id is not None
    return decision.intent_id


def _claim_process(path: str, boot: str, intent: str, gate: Any, queue: Any) -> None:
    gate.wait()
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
            worker = authority.register_worker(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                boot_event_id=boot,
                metadata={"role": "background"},
            )
            claim = authority.claim_execution(worker, intent, lease_seconds=10)
            queue.put(("claimed", claim.generation, claim.claim_id))
    except ExecutionStateConflict as exc:
        queue.put(("lost", exc.code))
    except Exception as exc:  # pragma: no cover - parent reports details
        queue.put(("error", type(exc).__name__, str(exc)))


def _claim_dispatch_process(
    path: str, ids: dict[str, str], intent: str, gate: Any, queue: Any
) -> None:
    gate.wait()
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
            worker = authority.register_worker(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                boot_event_id=ids["boot"],
                metadata={"role": "foreground"},
            )
            claim = authority.claim_execution(worker, intent, lease_seconds=10)
            dispatch = authority.begin_dispatch(
                claim,
                action={
                    "action": "TOOL_CALL",
                    "tool": "sum",
                    "arguments": {"left": 1, "right": 2},
                },
                destination_registry="local-test-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
            )
            queue.put(("dispatched", dispatch.generation, dispatch.claim_id))
    except ExecutionStateConflict as exc:
        queue.put(("lost", exc.code))
    except Exception as exc:  # pragma: no cover - parent reports details
        queue.put(("error", type(exc).__name__, str(exc)))


def _prepare_process(path: str, ids: dict[str, str], gate: Any, queue: Any) -> None:
    gate.wait()
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
            queue.put(("prepared", _prepare(authority, ids)))
    except ExecutionStateConflict as exc:
        queue.put(("lost", exc.code))
    except Exception as exc:  # pragma: no cover - parent reports details
        queue.put(("error", type(exc).__name__, str(exc)))


def _crash_prepare_process(path: str, ids: dict[str, str], point: str) -> None:
    with PersistentSecurityState.open(_config(Path(path))) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)

        def terminate(seen: str) -> None:
            if seen == point:
                os._exit(71)

        state._set_failure_injector_for_testing(terminate)
        _prepare(authority, ids)


def _crash_claim_process(path: str, ids: dict[str, str], intent_id: str, point: str) -> None:
    with PersistentSecurityState.open(_config(Path(path))) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )

        def terminate(seen: str) -> None:
            if seen == point:
                os._exit(72)

        state._set_failure_injector_for_testing(terminate)
        authority.claim_execution(worker, intent_id, lease_seconds=0.001)


def _crash_dispatch_process(path: str, ids: dict[str, str], intent_id: str, point: str) -> None:
    with PersistentSecurityState.open(_config(Path(path))) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = authority.claim_execution(worker, intent_id)

        def terminate(seen: str) -> None:
            if seen == point:
                os._exit(73)

        state._set_failure_injector_for_testing(terminate)
        authority.begin_dispatch(
            claim,
            action={
                "action": "TOOL_CALL",
                "tool": "sum",
                "arguments": {"left": 1, "right": 2},
            },
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )


def _run_claim_race(root: Path, workers: int) -> tuple[int, int]:
    ids = _seed(root)
    with PersistentSecurityState.open(_config(root)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
    context = multiprocessing.get_context("spawn")
    gate, queue = context.Event(), context.Queue()
    processes = [
        context.Process(
            target=_claim_process, args=(str(root), ids["boot"], intent_id, gate, queue)
        )
        for _ in range(workers)
    ]
    for process in processes:
        process.start()
    gate.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    assert all(result[0] in {"claimed", "lost"} for result in results), results
    return sum(result[0] == "claimed" for result in results), sum(
        result[0] == "lost" for result in results
    )


def test_prepare_claim_dispatch_complete_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        intent = authority.get_intent(intent_id)
        assert intent.state is ExecutionState.READY
        assert intent.idempotency_key is not None and len(intent.idempotency_key) == 64
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = authority.claim_execution(worker, intent_id)
        dispatch = authority.begin_dispatch(
            claim,
            action={"action": "TOOL_CALL", "tool": "sum", "arguments": {"left": 1, "right": 2}},
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )
        with pytest.raises(ExecutionAuthorityError):
            authority.begin_dispatch(
                claim,
                action={
                    "action": "TOOL_CALL",
                    "tool": "sum",
                    "arguments": {"left": 1, "right": 2},
                },
                destination_registry="local-test-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
            )
        destination = FakeDestination(tmp_path / "fake.sqlite3")
        response = destination.invoke(
            authority,
            dispatch,
            {"action": "TOOL_CALL", "tool": "sum", "arguments": {"left": 1, "right": 2}},
        )
        completed = authority.complete_execution(
            dispatch,
            result_digest=_digest("result"),
            destination_operation_id=response["operation_id"],
        )
        assert completed.state is ExecutionState.COMPLETED
        with pytest.raises(ExecutionStateConflict):
            authority.validate_dispatch_handle(dispatch)
        assert state.verify_full().valid


def test_one_shot_terminal_decision_cannot_be_revived(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        decision = authority.record_nonexecutable_decision(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=ids["workflow"],
            source_output_event_id=ids["output"],
            proposal_event_id=ids["proposal"],
            decision="BLOCK",
            reason_code="POLICY_BLOCK",
        )
        assert decision.intent_id is None
        with pytest.raises(ExecutionStateConflict):
            _prepare(authority, ids)
        assert state.is_consumed(token_kind="model_output", token_id=ids["output"])


def test_exact_binding_and_handle_attacks_fail(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = authority.claim_execution(worker, intent_id)
        with pytest.raises(ExecutionBindingError):
            authority.begin_dispatch(
                claim,
                action={
                    "action": "TOOL_CALL",
                    "tool": "sum",
                    "arguments": {"left": 1, "right": 2},
                },
                destination_registry="forged-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
            )
        with pytest.raises(ExecutionBindingError):
            authority.begin_dispatch(
                claim,
                action={
                    "action": "TOOL_CALL",
                    "tool": "sum",
                    "arguments": {"left": True, "right": 2},
                },
                destination_registry="local-test-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
            )
        with pytest.raises(TypeError):
            pickle.dumps(claim)
        with pytest.raises(AttributeError):
            claim._capability = object()
        dispatch = authority.begin_dispatch(
            claim,
            action={"action": "TOOL_CALL", "tool": "sum", "arguments": {"left": 1, "right": 2}},
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )
        assert dispatch.intent_id == intent_id


@pytest.mark.parametrize("workers", [2, 6])
def test_spawned_workers_have_one_current_claim(tmp_path: Path, workers: int) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
    context = multiprocessing.get_context("spawn")
    gate, queue = context.Event(), context.Queue()
    processes = [
        context.Process(
            target=_claim_process, args=(str(path), ids["boot"], intent_id, gate, queue)
        )
        for _ in range(workers)
    ]
    for process in processes:
        process.start()
    gate.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    assert sum(result[0] == "claimed" for result in results) == 1, results
    assert all(result[0] in {"claimed", "lost"} for result in results), results


def test_repeated_spawned_claim_races(tmp_path: Path) -> None:
    for iteration in range(100):
        assert _run_claim_race(tmp_path / f"two-{iteration}", 2) == (1, 1)
    for iteration in range(20):
        assert _run_claim_race(tmp_path / f"six-{iteration}", 6) == (1, 5)


@pytest.mark.parametrize("workers", [2, 6])
def test_spawned_workers_have_one_dispatch_fence_winner(tmp_path: Path, workers: int) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
    context = multiprocessing.get_context("spawn")
    gate, queue = context.Event(), context.Queue()
    processes = [
        context.Process(
            target=_claim_dispatch_process, args=(str(path), ids, intent_id, gate, queue)
        )
        for _ in range(workers)
    ]
    for process in processes:
        process.start()
    gate.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    assert sum(result[0] == "dispatched" for result in results) == 1, results
    assert all(result[0] in {"dispatched", "lost"} for result in results), results


def test_spawned_same_output_preparation_has_one_intent(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    context = multiprocessing.get_context("spawn")
    gate, queue = context.Event(), context.Queue()
    processes = [
        context.Process(target=_prepare_process, args=(str(path), ids, gate, queue))
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    gate.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    assert sum(result[0] == "prepared" for result in results) == 1, results
    with PersistentSecurityState.open(_config(path)) as state:
        assert state.verify_full().valid
    connection = sqlite3.connect(path / "authority.sqlite3")
    assert connection.execute("SELECT COUNT(*) FROM execution_intents").fetchone()[0] == 1
    connection.close()


def test_expired_claim_reclaims_generation_and_stale_claim_fails(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        first_worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        first = authority.claim_execution(first_worker, intent_id, lease_seconds=0.001)
        time.sleep(0.003)
        second_worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        second = authority.claim_execution(second_worker, intent_id)
        assert second.generation == first.generation + 1
        with pytest.raises(ExecutionStateConflict):
            authority.begin_dispatch(
                first,
                action={"action": "TOOL_CALL", "tool": "sum", "arguments": {"left": 1, "right": 2}},
                destination_registry="local-test-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
            )


def test_old_boot_worker_cannot_claim(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        old_worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        state.record_event(
            event_type="runtime_boot",
            correlation_id="runtime-boot",
            attributes={"nonce": "new"},
        )
        with pytest.raises(ExecutionAuthorityError):
            authority.claim_execution(old_worker, intent_id)


@pytest.mark.parametrize(
    ("point", "committed"),
    [
        ("before_intent_mutation", False),
        ("during_intent_mutation", False),
        ("after_intent_commit", True),
    ],
)
def test_real_process_termination_around_intent_commit(
    tmp_path: Path, point: str, committed: bool
) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_crash_prepare_process, args=(str(path), ids, point))
    process.start()
    process.join(30)
    assert process.exitcode == 71
    with PersistentSecurityState.open(_config(path)) as state:
        assert state.verify_full().valid
    connection = sqlite3.connect(path / "authority.sqlite3")
    count = connection.execute("SELECT COUNT(*) FROM execution_intents").fetchone()[0]
    connection.close()
    assert bool(count) is committed


@pytest.mark.parametrize(
    ("point", "claimed"),
    [
        ("before_claim_mutation", False),
        ("during_claim_mutation", False),
        ("after_claim_mutation", True),
    ],
)
def test_real_process_termination_around_claim(tmp_path: Path, point: str, claimed: bool) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_claim_process, args=(str(path), ids, intent_id, point)
    )
    process.start()
    process.join(30)
    assert process.exitcode == 72
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        assert authority.get_intent(intent_id).state is (
            ExecutionState.CLAIMED if claimed else ExecutionState.READY
        )
        assert state.verify_full().valid


@pytest.mark.parametrize(
    ("point", "dispatching"),
    [
        ("before_dispatch_fence_mutation", False),
        ("during_dispatch_fence_mutation", False),
        ("after_dispatch_fence_mutation", True),
    ],
)
def test_real_process_termination_around_dispatch_fence(
    tmp_path: Path, point: str, dispatching: bool
) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_dispatch_process, args=(str(path), ids, intent_id, point)
    )
    process.start()
    process.join(30)
    assert process.exitcode == 73
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent = authority.get_intent(intent_id)
        assert intent.state is (
            ExecutionState.DISPATCHING if dispatching else ExecutionState.CLAIMED
        )
        if dispatching:
            unknown = authority.mark_abandoned_dispatch_unknown(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY, intent_id
            )
            assert unknown.state is ExecutionState.OUTCOME_UNKNOWN
            with pytest.raises(ExecutionStateConflict):
                authority.retry_failed_no_effect(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                    intent_id,
                    reason_code="NOT_PROVED_SAFE",
                )
        assert state.verify_full().valid


@pytest.mark.parametrize(
    "mode", [FakeDestinationMode.COMMIT_THEN_TIMEOUT, FakeDestinationMode.COMMIT_THEN_TERMINATE]
)
def test_dispatch_ambiguity_is_conservatively_unknown(
    tmp_path: Path, mode: FakeDestinationMode
) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = authority.claim_execution(worker, intent_id)
        action = {"action": "TOOL_CALL", "tool": "sum", "arguments": {"left": 1, "right": 2}}
        dispatch = authority.begin_dispatch(
            claim,
            action=action,
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )
        destination = FakeDestination(tmp_path / "fake.sqlite3")
        expected = (
            FakeDestinationTimeout
            if mode is FakeDestinationMode.COMMIT_THEN_TIMEOUT
            else FakeCallerTermination
        )
        with pytest.raises(expected):
            destination.invoke(authority, dispatch, action, mode=mode)
        unknown = authority.mark_outcome_unknown(dispatch)
        assert unknown.state is ExecutionState.OUTCOME_UNKNOWN
        with pytest.raises(ExecutionStateConflict):
            authority.claim_execution(worker, intent_id)
        assert destination.request_count == 1


def test_failed_no_effect_is_only_terminal_state_with_safe_retry(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    action = {
        "action": "TOOL_CALL",
        "tool": "sum",
        "arguments": {"left": 1, "right": 2},
    }
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = authority.claim_execution(worker, intent_id)
        dispatch = authority.begin_dispatch(
            claim,
            action=action,
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )
        failed = authority.fail_no_effect(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            dispatch,
            result_digest=_digest("no-effect"),
        )
        assert failed.state is ExecutionState.FAILED_NO_EFFECT
        ready = authority.retry_failed_no_effect(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            intent_id,
            reason_code="PROVED_NO_EFFECT",
        )
        assert ready.state is ExecutionState.READY
        next_claim = authority.claim_execution(worker, intent_id)
        assert next_claim.generation == claim.generation + 1
        cancelled = authority.cancel_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            intent_id,
            reason_code="HOST_CANCELLED",
        )
        assert cancelled.state is ExecutionState.CANCELLED
        with pytest.raises(ExecutionStateConflict):
            authority.claim_execution(worker, intent_id)
        assert state.verify_full().valid


def test_fake_destination_modes_and_idempotency_are_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    action = {
        "action": "TOOL_CALL",
        "tool": "sum",
        "arguments": {"left": 1, "right": 2},
    }
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        dispatch = authority.begin_dispatch(
            authority.claim_execution(worker, intent_id),
            action=action,
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )
        destination = FakeDestination(tmp_path / "fake.sqlite3")
        first = destination.invoke(authority, dispatch, action)
        with pytest.raises(FakeDestinationFailure):
            destination.invoke(
                authority, dispatch, action, mode=FakeDestinationMode.REJECT_DUPLICATE_KEY
            )
        duplicate = destination.invoke(
            authority, dispatch, action, mode=FakeDestinationMode.DEDUPLICATE_SAME_KEY
        )
        accepted = destination.invoke(
            authority, dispatch, action, mode=FakeDestinationMode.ACCEPT_DUPLICATE_KEY
        )
        assert duplicate["operation_id"] == first["operation_id"]
        assert accepted["operation_id"] != first["operation_id"]
        assert destination.query_operation_status(first["operation_id"]) is not None
        assert destination.request_count == 4


@pytest.mark.parametrize(
    ("point", "effect_rows"),
    [
        ("before_fake_destination_invocation", 0),
        ("during_fake_destination_invocation", 0),
        ("after_fake_effect_commit", 1),
    ],
)
def test_fake_destination_failure_injection(tmp_path: Path, point: str, effect_rows: int) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    action = {
        "action": "TOOL_CALL",
        "tool": "sum",
        "arguments": {"left": 1, "right": 2},
    }
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        dispatch = authority.begin_dispatch(
            authority.claim_execution(worker, intent_id),
            action=action,
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-config-v1"),
        )

        def fail(seen: str) -> None:
            if seen == point:
                raise RuntimeError(point)

        destination_path = tmp_path / "fake.sqlite3"
        destination = FakeDestination(destination_path, failure_injector=fail)
        with pytest.raises(RuntimeError, match=point):
            destination.invoke(authority, dispatch, action)
        connection = sqlite3.connect(destination_path)
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'"
        ).fetchone()
        actual_rows = (
            connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0] if exists else 0
        )
        assert actual_rows == effect_rows
        connection.close()


@pytest.mark.parametrize(
    ("point", "completed"),
    [
        ("before_completion_mutation", False),
        ("during_completion_mutation", False),
        ("after_completion_mutation", True),
    ],
)
def test_completion_failure_injection_recovers_exact_commit_state(
    tmp_path: Path, point: str, completed: bool
) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    action = {
        "action": "TOOL_CALL",
        "tool": "sum",
        "arguments": {"left": 1, "right": 2},
    }
    state = PersistentSecurityState.open(_config(path))
    authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
    intent_id = _prepare(authority, ids)
    worker = authority.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
    )
    dispatch = authority.begin_dispatch(
        authority.claim_execution(worker, intent_id),
        action=action,
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-config-v1"),
    )

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        authority.complete_execution(dispatch, result_digest=_digest("result"))
    state.close()
    with PersistentSecurityState.open(_config(path)) as reopened:
        recovered = ExecutionAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, reopened
        ).get_intent(intent_id)
        assert recovered.state is (
            ExecutionState.COMPLETED if completed else ExecutionState.DISPATCHING
        )
        assert reopened.verify_full().valid


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execution_intents SET state='COMPLETED'",
        "UPDATE execution_intents SET claim_generation=99",
        "UPDATE execution_workflow_barriers SET active_intent_id=NULL",
        "UPDATE execution_lifecycle SET transition='COMPLETED' WHERE transition='READY'",
        "UPDATE execution_intents SET destination='forged'",
        "UPDATE execution_intents SET idempotency_class='TRANSACTIONALLY_LOCAL'",
    ],
)
def test_execution_tampering_is_detected(tmp_path: Path, statement: str) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        _prepare(authority, ids)
    connection = sqlite3.connect(path / "authority.sqlite3")
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises(StateVerificationError), PersistentSecurityState.open(_config(path)):
        pass


def test_workflow_stale_head_and_active_barrier_rejected(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        with pytest.raises(WorkflowCASConflict):
            authority.prepare_execution(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                workflow_id=ids["workflow"],
                expected_head_event_id=ids["output"],
                expected_revision=0,
                source_turn_event_id=ids["turn"],
                source_output_event_id=ids["output"],
                proposal_event_id=ids["proposal"],
                action={"action": "TOOL_CALL", "tool": "sum", "arguments": {"left": 1, "right": 2}},
                destination_registry="local-test-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
                idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
                policy_config_digest=_digest("policy-v1"),
            )
        _prepare(authority, ids)
        with pytest.raises(ExecutionStateConflict):
            _prepare(authority, ids)
