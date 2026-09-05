from __future__ import annotations

import copy
import multiprocessing
import os
import queue
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
from test_execution_authority_v03c1 import (
    _claim_dispatch_process,
    _config,
    _digest,
    _prepare,
    _seed,
)

from secureinjections.persistent_state import (
    ExecutionAuthority,
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionStateConflict,
    IdempotencyClass,
    PersistentSecurityState,
    WorkflowCASConflict,
)
from secureinjections.persistent_state.canonical import CanonicalAuthorityError
from secureinjections.persistent_state.execution import (
    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
    normalize_action,
)
from secureinjections.persistent_state.fake_destination import (
    FakeDestination,
    FakeDestinationFailure,
)

ACTION = {
    "action": "TOOL_CALL",
    "tool": "sum",
    "arguments": {"left": 1, "right": 2},
}


def _claimed(path: Path):
    ids = _seed(path)
    state = PersistentSecurityState.open(_config(path))
    authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
    intent_id = _prepare(authority, ids)
    worker = authority.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
    )
    claim = authority.claim_execution(worker, intent_id)
    return ids, state, authority, intent_id, claim


def _dispatch(authority: ExecutionAuthority, claim):
    return authority.begin_dispatch(
        claim,
        action=ACTION,
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-config-v1"),
    )


def _decision_process(
    path: str, ids: dict[str, str], decision: str, gate: Any, output: Any
) -> None:
    gate.wait()
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
            if decision == "ALLOW":
                _prepare(authority, ids)
            else:
                authority.record_nonexecutable_decision(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                    workflow_id=ids["workflow"],
                    source_output_event_id=ids["output"],
                    proposal_event_id=ids["proposal"],
                    decision=decision,
                    reason_code=f"HOST_{decision}",
                )
            output.put("won")
    except ExecutionStateConflict:
        output.put("lost")
    except Exception as exc:  # pragma: no cover - asserted in parent
        output.put(type(exc).__name__)


def _run_decision_race(root: Path, decisions: tuple[str, ...]) -> tuple[int, int, int]:
    ids = _seed(root)
    context = multiprocessing.get_context("spawn")
    gate, output = context.Event(), context.Queue()
    processes = [
        context.Process(target=_decision_process, args=(str(root), ids, item, gate, output))
        for item in decisions
    ]
    for process in processes:
        process.start()
    gate.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    results = [output.get(timeout=5) for _ in processes]
    assert all(item in {"won", "lost"} for item in results), results
    connection = sqlite3.connect(root / "authority.sqlite3")
    decision_count = connection.execute("SELECT COUNT(*) FROM execution_decisions").fetchone()[0]
    intent_count = connection.execute("SELECT COUNT(*) FROM execution_intents").fetchone()[0]
    connection.close()
    return results.count("won"), int(decision_count), int(intent_count)


def _run_dispatch_race(root: Path, workers: int) -> tuple[int, int]:
    ids = _seed(root)
    with PersistentSecurityState.open(_config(root)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent_id = _prepare(authority, ids)
    context = multiprocessing.get_context("spawn")
    gate, output = context.Event(), context.Queue()
    processes = [
        context.Process(
            target=_claim_dispatch_process,
            args=(str(root), ids, intent_id, gate, output),
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
    assert all(item[0] in {"dispatched", "lost"} for item in results), results
    return sum(item[0] == "dispatched" for item in results), sum(
        item[0] == "lost" for item in results
    )


def test_active_execution_barrier_blocks_base_workflow_advance(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        _prepare(authority, ids)
        new_head = state.record_event(
            event_type="hostile_branch",
            correlation_id=ids["workflow"],
            content_ids=(ids["content"],),
        )
        with pytest.raises(WorkflowCASConflict):
            state.advance_workflow(
                ids["workflow"],
                expected_revision=0,
                expected_head=ids["proposal"],
                new_head=new_head.event_id,
            )


def test_dispatch_handle_is_immutable_and_not_copyable(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, _intent, claim = _claimed(path)
    try:
        dispatch = _dispatch(authority, claim)
        with pytest.raises((AttributeError, TypeError)):
            dispatch.action_fingerprint = _digest("forged")
        with pytest.raises((TypeError, copy.Error)):
            copy.copy(dispatch)
        with pytest.raises((TypeError, copy.Error)):
            copy.deepcopy(dispatch)
        object.__setattr__(dispatch, "action_fingerprint", _digest("forged"))
        with pytest.raises(ExecutionStateConflict):
            authority.validate_dispatch_handle(dispatch)
    finally:
        state.close()


def test_failed_no_effect_requires_host_authority(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, _intent, claim = _claimed(path)
    try:
        dispatch = _dispatch(authority, claim)
        with pytest.raises(PermissionError):
            authority.fail_no_effect(object(), dispatch, result_digest=_digest("no-effect"))
        failed = authority.fail_no_effect(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            dispatch,
            result_digest=_digest("no-effect"),
        )
        assert failed.state.value == "FAILED_NO_EFFECT"
    finally:
        state.close()


def test_prepare_requires_proposal_to_descend_from_source_and_be_head(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        unrelated = state.record_event(
            event_type="tool_proposal",
            correlation_id=ids["workflow"],
            content_ids=(ids["content"],),
            attributes={"action_fingerprint": ids["fingerprint"]},
        )
        state.advance_workflow(
            ids["workflow"],
            expected_revision=0,
            expected_head=ids["proposal"],
            new_head=unrelated.event_id,
        )
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        with pytest.raises(ExecutionBindingError):
            authority.prepare_execution(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                workflow_id=ids["workflow"],
                expected_head_event_id=unrelated.event_id,
                expected_revision=1,
                source_turn_event_id=ids["turn"],
                source_output_event_id=ids["output"],
                proposal_event_id=unrelated.event_id,
                action=ACTION,
                destination_registry="local-test-registry",
                destination="fake-destination",
                destination_config_digest=_digest("fake-config-v1"),
                idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
                policy_config_digest=_digest("policy-v2"),
            )


def test_fake_destination_refuses_authority_database_path(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, _intent, claim = _claimed(path)
    try:
        dispatch = _dispatch(authority, claim)
        destination = FakeDestination(state.paths.database)
        with pytest.raises(FakeDestinationFailure):
            destination.invoke(authority, dispatch, ACTION)
    finally:
        state.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork is unavailable")
def test_forked_child_cannot_use_inherited_claim_or_dispatch(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, _intent, claim = _claimed(path)
    dispatch = _dispatch(authority, claim)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child result is asserted by parent
        os.close(read_fd)
        outcomes = []
        for handle in (claim, dispatch):
            try:
                if handle is claim:
                    _dispatch(authority, claim)
                else:
                    authority.validate_dispatch_handle(dispatch)
            except ExecutionAuthorityError:
                outcomes.append("blocked")
            else:
                outcomes.append("allowed")
        os.write(write_fd, ",".join(outcomes).encode())
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 100).decode()
    os.close(read_fd)
    waited, status = os.waitpid(pid, 0)
    state.close()
    assert waited == pid and os.waitstatus_to_exitcode(status) == 0
    assert result == "blocked,blocked"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork is unavailable")
def test_forked_child_cannot_use_inherited_worker(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    state = PersistentSecurityState.open(_config(path))
    authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
    intent = _prepare(authority, ids)
    worker = authority.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
    )
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child result is asserted by parent
        os.close(read_fd)
        try:
            authority.claim_execution(worker, intent)
        except ExecutionAuthorityError:
            result = b"blocked"
        else:
            result = b"allowed"
        os.write(write_fd, result)
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 100)
    os.close(read_fd)
    os.waitpid(pid, 0)
    state.close()
    assert result == b"blocked"


def test_handle_is_bound_to_issuing_thread(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, _intent, claim = _claimed(path)
    results: queue.Queue[str] = queue.Queue()

    def use_claim() -> None:
        try:
            _dispatch(authority, claim)
        except ExecutionAuthorityError:
            results.put("blocked")
        else:  # pragma: no cover - security failure
            results.put("allowed")

    thread = threading.Thread(target=use_claim)
    thread.start()
    thread.join(10)
    state.close()
    assert results.get(timeout=1) == "blocked"


@pytest.mark.parametrize(
    "decisions",
    [
        ("ALLOW", "ALLOW"),
        ("ALLOW", "BLOCK"),
        ("ALLOW", "REVIEW"),
        ("BLOCK", "REVIEW"),
        ("ALLOW", "BLOCK", "REVIEW", "REJECT", "ALLOW", "BLOCK"),
    ],
)
def test_mixed_terminal_decision_races(tmp_path: Path, decisions: tuple[str, ...]) -> None:
    for iteration in range(5):
        winners, decision_count, intent_count = _run_decision_race(
            tmp_path / f"race-{len(decisions)}-{iteration}", decisions
        )
        assert winners == decision_count == 1
        assert intent_count in {0, 1}


def test_repeated_two_worker_dispatch_races(tmp_path: Path) -> None:
    for iteration in range(100):
        assert _run_dispatch_race(tmp_path / f"dispatch-{iteration}", 2) == (1, 1)


def test_repeated_six_worker_dispatch_races(tmp_path: Path) -> None:
    for iteration in range(20):
        assert _run_dispatch_race(tmp_path / f"dispatch-six-{iteration}", 6) == (1, 5)


@pytest.mark.parametrize("lease", [True, float("nan"), float("inf"), -1.0, 0.0, 301.0])
def test_malformed_or_out_of_range_leases_fail(tmp_path: Path, lease: float) -> None:
    path = tmp_path / "authority"
    ids = _seed(path)
    with PersistentSecurityState.open(_config(path)) as state:
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        intent = _prepare(authority, ids)
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        with pytest.raises(ValueError):
            authority.claim_execution(worker, intent, lease_seconds=lease)


def test_claim_handle_cannot_complete_and_conflicting_outcome_loses(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, _intent, claim = _claimed(path)
    try:
        with pytest.raises(ExecutionAuthorityError):
            authority.complete_execution(
                claim,
                result_digest=_digest("forged"),  # type: ignore[arg-type]
            )
        dispatch = _dispatch(authority, claim)
        authority.complete_execution(dispatch, result_digest=_digest("result"))
        with pytest.raises(ExecutionStateConflict):
            authority.mark_outcome_unknown(dispatch)
    finally:
        state.close()


def test_lifecycle_bound_rejects_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.execution as execution

    monkeypatch.setattr(execution, "MAX_LIFECYCLE_RECORDS", 3)
    path = tmp_path / "authority"
    _ids, state, authority, intent, claim = _claimed(path)
    try:
        dispatch = _dispatch(authority, claim)
        with pytest.raises(ExecutionStateConflict, match="history bound"):
            authority.fail_no_effect(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                dispatch,
                result_digest=_digest("no-effect"),
            )
        assert authority.get_intent(intent).state.value == "DISPATCHING"
        assert state.verify_full().valid
    finally:
        state.close()


def test_action_canonicalization_rejects_ambiguity_and_binds_semantics() -> None:
    first = {"action": "X", "nested": {"a": 1, "b": [1, 2]}, "optional": None}
    reordered = {"optional": None, "nested": {"b": [1, 2], "a": 1}, "action": "X"}
    assert normalize_action(first)[2] == normalize_action(reordered)[2]
    assert (
        normalize_action({"action": "X", "value": 1})[2]
        != normalize_action({"action": "X", "value": True})[2]
    )
    assert (
        normalize_action({"action": "X", "value": [1, 2]})[2]
        != normalize_action({"action": "X", "value": [2, 1]})[2]
    )
    assert (
        normalize_action({"action": "X"})[2]
        != normalize_action({"action": "X", "optional": None})[2]
    )
    assert (
        normalize_action({"action": "X", "value": "é"})[2]
        != normalize_action({"action": "X", "value": "e\u0301"})[2]
    )
    for raw in (
        '{"action":"X","action":"Y"}',
        '{"action":"X","nested":{"a":1,"a":2}}',
        '{"action":"X", "value":1}',
        '{"action":"X","value":1.0}',
    ):
        with pytest.raises(CanonicalAuthorityError):
            normalize_action(raw)
    with pytest.raises(CanonicalAuthorityError):
        normalize_action({"action": "X", "nested": {"value": 1.0}})
    with pytest.raises((CanonicalAuthorityError, ValueError)):
        normalize_action({"action": "X", "value": "x" * 70_000})


def test_each_authority_mutation_has_one_outbox_record(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    _ids, state, authority, intent, claim = _claimed(path)
    dispatch = _dispatch(authority, claim)
    authority.complete_execution(dispatch, result_digest=_digest("result"))
    connection = sqlite3.connect(path / "authority.sqlite3")
    mutation_sequences = {
        row[0]
        for row in connection.execute("SELECT sequence FROM state_mutations WHERE sequence>0")
    }
    outbox_sequences = {
        row[0] for row in connection.execute("SELECT mutation_sequence FROM audit_outbox")
    }
    connection.close()
    assert outbox_sequences == mutation_sequences
    first = state.pending_audit(limit=1)[0]
    state.mark_audit_exported(first.outbox_id)
    assert authority.get_intent(intent).state.value == "COMPLETED"
    state.close()
