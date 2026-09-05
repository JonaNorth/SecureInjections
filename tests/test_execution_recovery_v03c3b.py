from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import os
import pickle
import queue
import sqlite3
import threading
from pathlib import Path

import pytest

from secureinjections.persistent_state import (
    DestinationQueryObservation,
    DestinationQueryResult,
    ExecutionAuthority,
    ExecutionAuthorityError,
    ExecutionBindingError,
    ExecutionState,
    ExecutionStateConflict,
    IdempotencyClass,
    PersistentSecurityState,
    PersistentStateConfig,
    ReconciliationAuthority,
    ReconciliationEvidenceCategory,
    RecoveryAuthority,
    RecoveryState,
    StateVerificationError,
)
from secureinjections.persistent_state.execution import (
    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
    normalize_action,
)
from secureinjections.persistent_state.fake_destination import (
    FakeDestination,
    FakeDestinationMode,
    FakeDestinationStatusAdapter,
    FakeDestinationTimeout,
)
from secureinjections.persistent_state.recovery import (
    QueryAuthorityCapability,
    RecoveryDecisionCapability,
)
from secureinjections.persistent_state.store import (
    _EXECUTION_EXTENSION_CAPABILITY,
    _HOST_ROOT_AUTHORITY_CAPABILITY,
)

_ACTION = {"action": "TOOL_CALL", "arguments": {"value": 1}, "tool": "effect"}
_REGISTRY = "local-test-registry"
_DESTINATION = "fake-destination"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(path: Path, deployment: str = "recovery-test") -> PersistentStateConfig:
    return PersistentStateConfig(path / "authority", deployment, busy_timeout_ms=10_000)


def _setup_unknown(
    path: Path,
    destination_class: IdempotencyClass,
    *,
    original_effect: bool = False,
    workflow: str = "recovery-workflow",
) -> dict[str, str]:
    contract = _digest("fake-contract-v1")
    policy = _digest("policy-v1")
    _, _, fingerprint = normalize_action(_ACTION)
    fake = FakeDestination(path / "fake-destination.sqlite")
    with PersistentSecurityState.initialize(_config(path)) as state:
        content = state._issue_authoritative_root_for_host(
            _HOST_ROOT_AUTHORITY_CAPABILITY,
            source_type="internal",
            trust="TRUSTED",
            content_digest=_digest("recovery-source" + workflow),
            producing_boundary="v03c3b-test",
        )
        turn = state.record_event(
            event_type="model_turn",
            correlation_id=workflow,
            content_ids=(content.content_id,),
        )
        output = state.record_event(
            event_type="model_output",
            correlation_id=workflow,
            parent_event_ids=(turn.event_id,),
            content_ids=(content.content_id,),
            attributes={"action_fingerprint": fingerprint},
        )
        proposal = state.record_event(
            event_type="tool_proposal",
            correlation_id=workflow,
            parent_event_ids=(output.event_id,),
            content_ids=(content.content_id,),
            attributes={"action_fingerprint": fingerprint},
        )
        state.create_workflow(
            workflow,
            head_event_id=proposal.event_id,
            current_content_id=content.content_id,
        )
        boot = state.record_event(event_type="runtime_boot", correlation_id="boot")
        execution = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        decision = execution.prepare_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=workflow,
            expected_head_event_id=proposal.event_id,
            expected_revision=0,
            source_turn_event_id=turn.event_id,
            source_output_event_id=output.event_id,
            proposal_event_id=proposal.event_id,
            action=_ACTION,
            destination_registry=_REGISTRY,
            destination=_DESTINATION,
            destination_config_digest=contract,
            idempotency_class=destination_class,
            policy_config_digest=policy,
        )
        assert decision.intent_id is not None
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=boot.event_id
        )
        claim = execution.claim_execution(worker, decision.intent_id)
        dispatch = execution.begin_dispatch(
            claim,
            action=_ACTION,
            destination_registry=_REGISTRY,
            destination=_DESTINATION,
            destination_config_digest=contract,
        )
        operation_id: str | None = None
        if destination_class is IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY:
            if original_effect:
                with pytest.raises(FakeDestinationTimeout):
                    fake.invoke(
                        execution,
                        dispatch,
                        _ACTION,
                        mode=FakeDestinationMode.COMMIT_THEN_TIMEOUT,
                    )
            else:
                fake.invoke(
                    execution,
                    dispatch,
                    _ACTION,
                    mode=FakeDestinationMode.PAUSE_BEFORE_EFFECT,
                )
        elif destination_class is IdempotencyClass.QUERYABLE_OPERATION_ID:
            if original_effect:
                response = fake.invoke(execution, dispatch, _ACTION)
                operation_id = str(response["operation_id"])
            else:
                operation_id = "query-operation-no-effect"
        execution.mark_outcome_unknown(dispatch, destination_operation_id=operation_id)
        reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        capability = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="c3b-reconciler",
            identity_class="HOST_OPERATOR",
        )
        current = reconciliation.begin_reconciliation(
            capability,
            decision.intent_id,
            destination_contract_digest=contract,
        )
        assert current.reconciliation_id is not None
        return {
            "boot": boot.event_id,
            "contract": contract,
            "fingerprint": fingerprint,
            "intent": decision.intent_id,
            "operation": operation_id or "",
            "output": output.event_id,
            "policy": policy,
            "reconciliation": current.reconciliation_id,
            "workflow": workflow,
        }


def _authorities(
    state: PersistentSecurityState,
) -> tuple[ExecutionAuthority, RecoveryAuthority]:
    execution = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
    recovery = RecoveryAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, execution)
    return execution, recovery


def _decision(recovery: RecoveryAuthority, identity: str = "recovery-operator"):
    return recovery.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity=identity,
        identity_class="HOST_OPERATOR",
    )


def _adapter(
    recovery: RecoveryAuthority, path: Path, contract: str
) -> FakeDestinationStatusAdapter:
    adapter = FakeDestinationStatusAdapter(
        FakeDestination(path / "fake-destination.sqlite"),
        destination_registry=_REGISTRY,
        destination_name=_DESTINATION,
        destination_contract_digest=contract,
    )
    recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, adapter)
    return adapter


def _propose_and_authorize(
    recovery: RecoveryAuthority,
    ids: dict[str, str],
    *,
    query_evidence_id: str | None = None,
):
    proposer = _decision(recovery, "recovery-proposer")
    proposal = recovery.propose_recovery(
        proposer,
        ids["intent"],
        destination_contract_digest=ids["contract"],
        policy_config_digest=ids["policy"],
        query_evidence_id=query_evidence_id,
    )
    authorizer = _decision(recovery, "recovery-authorizer")
    return recovery.authorize_recovery(
        authorizer,
        proposal.proposal_id,
        proposal_digest=proposal.proposal_digest,
        destination_contract_digest=ids["contract"],
        policy_config_digest=ids["policy"],
    )


def _claim_and_dispatch(
    execution: ExecutionAuthority,
    recovery: RecoveryAuthority,
    ids: dict[str, str],
    recovery_id: str,
):
    worker = execution.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
    )
    claim = recovery.claim_recovery(worker, recovery_id)
    return recovery.begin_recovery_dispatch(
        claim,
        action=_ACTION,
        destination_registry=_REGISTRY,
        destination=_DESTINATION,
        destination_contract_digest=ids["contract"],
        policy_config_digest=ids["policy"],
    )


def _create_recovery_process(path: str, ids: dict[str, str], gate: object, queue: object) -> None:
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            _, recovery = _authorities(state)
            capability = _decision(recovery, f"creator-{os.getpid()}")
            gate.wait()  # type: ignore[attr-defined]
            proposal = recovery.propose_recovery(
                capability,
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
            record = recovery.authorize_recovery(
                capability,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
            queue.put(("won", record.recovery_id))  # type: ignore[attr-defined]
    except (ExecutionBindingError, ExecutionStateConflict) as exc:
        queue.put(("lost", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover - parent reports detail
        queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]


def _claim_and_fence_process(
    path: str,
    ids: dict[str, str],
    recovery_id: str,
    gate: object,
    queue: object,
) -> None:
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            execution, recovery = _authorities(state)
            worker = execution.register_worker(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                boot_event_id=ids["boot"],
                metadata={"pid": os.getpid()},
            )
            gate.wait()  # type: ignore[attr-defined]
            claim = recovery.claim_recovery(worker, recovery_id)
            dispatch = recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
            queue.put(("won", dispatch.dispatch_authorization_id))  # type: ignore[attr-defined]
    except (ExecutionAuthorityError, ExecutionBindingError, ExecutionStateConflict) as exc:
        queue.put(("lost", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover - parent reports detail
        queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]


def _use_inherited_capability_process(
    recovery: RecoveryAuthority,
    capability: RecoveryDecisionCapability,
    ids: dict[str, str],
    result_queue: object,
) -> None:
    try:
        recovery.propose_recovery(
            capability,
            ids["intent"],
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )
    except ExecutionAuthorityError as exc:
        result_queue.put(("rejected", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover - parent reports detail
        result_queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]
    else:  # pragma: no cover - security failure asserted by parent
        result_queue.put(("accepted",))  # type: ignore[attr-defined]


def test_no_idempotency_cannot_create_recovery_authority(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.NO_IDEMPOTENCY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        with pytest.raises(ExecutionAuthorityError):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="no-idempotency-query",
            identity_class="HOST_ADAPTER",
        )
        with pytest.raises(ExecutionAuthorityError):
            recovery.query_destination_status(
                query,
                ids["intent"],
                adapter=_adapter(recovery, tmp_path, ids["contract"]),
            )
        with pytest.raises(ExecutionStateConflict):
            execution.retry_failed_no_effect(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                ids["intent"],
                reason_code="NO_IDEMPOTENCY_ESCAPE",
            )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_same_host_generated_key_recovers_no_effect_once(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        result = fake.invoke_recovery(recovery, dispatch, _ACTION)
        terminal = recovery.complete_recovery(
            dispatch,
            result_digest=_digest("recovery-success"),
            destination_operation_id=str(result["operation_id"]),
        )
        assert terminal.state is RecoveryState.COMPLETED
        assert execution.get_intent(ids["intent"]).state is ExecutionState.COMPLETED
        assert fake.effect_count == 1
        assert state.is_consumed(token_kind="model_output", token_id=ids["output"])
        state.verify_full()


def test_duplicate_same_key_delivery_has_one_fake_effect(tmp_path: Path) -> None:
    ids = _setup_unknown(
        tmp_path,
        IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
        original_effect=True,
    )
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    assert fake.effect_count == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        result = fake.invoke_recovery(recovery, dispatch, _ACTION)
        assert result["status"] == "DEDUPLICATED"
        assert fake.effect_count == 1
        recovery.complete_recovery(
            dispatch,
            result_digest=_digest("deduplicated-recovery"),
            destination_operation_id=str(result["operation_id"]),
        )
        assert fake.effect_count == 1


def test_query_effect_confirmed_never_authorizes_redispatch(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID, original_effect=True)
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        assert evidence.normalized_result is DestinationQueryResult.EFFECT_CONFIRMED
        with pytest.raises(ExecutionBindingError):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
                query_evidence_id=evidence.query_evidence_id,
            )
        assert fake.effect_count == 1


def test_query_no_effect_allows_exact_operation_recovery(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        assert evidence.normalized_result is DestinationQueryResult.NO_EFFECT_CONFIRMED
        record = _propose_and_authorize(recovery, ids, query_evidence_id=evidence.query_evidence_id)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        assert dispatch.original_operation_id == ids["operation"]
        result = fake.invoke_recovery(recovery, dispatch, _ACTION)
        assert result["operation_id"] == ids["operation"]
        recovery.complete_recovery(
            dispatch,
            result_digest=_digest("queryable-recovery"),
            destination_operation_id=ids["operation"],
        )
        assert fake.effect_count == 1
        state.verify_full()


@pytest.mark.parametrize(
    "result",
    [
        DestinationQueryResult.STILL_UNKNOWN,
        DestinationQueryResult.CONFLICT,
        DestinationQueryResult.QUERY_FAILED,
    ],
)
def test_unsafe_query_results_remain_unresolved(
    tmp_path: Path, result: DestinationQueryResult
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)

    class Adapter(FakeDestinationStatusAdapter):
        def query_operation_status(self, operation_id: str) -> DestinationQueryObservation:
            return DestinationQueryObservation(result, _digest(operation_id + result.value))

    adapter = Adapter(
        FakeDestination(tmp_path / "fake-destination.sqlite"),
        destination_registry=_REGISTRY,
        destination_name=_DESTINATION,
        destination_contract_digest=ids["contract"],
    )
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, adapter)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(query, ids["intent"], adapter=adapter)
        with pytest.raises(ExecutionBindingError):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
                query_evidence_id=evidence.query_evidence_id,
            )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    "failure", ["exception", "timeout", "arbitrary_text", "partial", "impossible_enum"]
)
def test_query_adapter_exception_or_malformed_result_fails_closed(
    tmp_path: Path, failure: str
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)

    class Adapter(FakeDestinationStatusAdapter):
        def query_operation_status(self, operation_id: str) -> DestinationQueryObservation:
            if failure == "exception":
                raise RuntimeError("adapter failed")
            if failure == "timeout":
                raise TimeoutError("adapter timed out")
            if failure == "arbitrary_text":
                return "EFFECT_CONFIRMED"  # type: ignore[return-value]
            if failure == "partial":
                return {"result": "NO_EFFECT_CONFIRMED"}  # type: ignore[return-value]
            return DestinationQueryObservation(  # type: ignore[arg-type]
                "IMPOSSIBLE", _digest(operation_id)
            )

    adapter = Adapter(
        FakeDestination(tmp_path / "fake-destination.sqlite"),
        destination_registry=_REGISTRY,
        destination_name=_DESTINATION,
        destination_contract_digest=ids["contract"],
    )
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, adapter)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        expected = (
            (RuntimeError, TimeoutError)
            if failure in {"exception", "timeout"}
            else ExecutionBindingError
        )
        with pytest.raises(expected):
            recovery.query_destination_status(query, ids["intent"], adapter=adapter)
        connection = state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        assert (
            connection.execute("SELECT COUNT(*) FROM execution_query_evidence").fetchone()[0] == 0
        )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_query_response_after_security_configuration_change_is_rejected(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        initial = execution.update_security_configuration(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            expected_epoch=0,
            configuration_digest=_digest("query-security-v1"),
            worker_attach_digest=_digest("query-worker-v1"),
        )

        class Adapter(FakeDestinationStatusAdapter):
            def query_operation_status(self, operation_id: str) -> DestinationQueryObservation:
                execution.update_security_configuration(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                    expected_epoch=initial.epoch,
                    configuration_digest=_digest("query-security-v2"),
                    worker_attach_digest=_digest("query-worker-v2"),
                )
                return DestinationQueryObservation(
                    DestinationQueryResult.NO_EFFECT_CONFIRMED, _digest(operation_id)
                )

        adapter = Adapter(
            FakeDestination(tmp_path / "fake-destination.sqlite"),
            destination_registry=_REGISTRY,
            destination_name=_DESTINATION,
            destination_contract_digest=ids["contract"],
        )
        recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, adapter)
        capability = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-config-race",
            identity_class="HOST_ADAPTER",
        )
        with pytest.raises(ExecutionBindingError, match="configuration changed"):
            recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
        connection = state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        assert (
            connection.execute("SELECT COUNT(*) FROM execution_query_evidence").fetchone()[0] == 0
        )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_query_evidence_before_security_configuration_change_cannot_authorize_recovery(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        initial = execution.update_security_configuration(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            expected_epoch=0,
            configuration_digest=_digest("evidence-security-v1"),
            worker_attach_digest=_digest("evidence-worker-v1"),
        )
        adapter = _adapter(recovery, tmp_path, ids["contract"])
        capability = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="stale-evidence-query",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
        execution.update_security_configuration(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            expected_epoch=initial.epoch,
            configuration_digest=_digest("evidence-security-v2"),
            worker_attach_digest=_digest("evidence-worker-v2"),
        )
        with pytest.raises(ExecutionBindingError, match="configuration changed"):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
                query_evidence_id=evidence.query_evidence_id,
            )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_query_target_is_derived_and_wrong_adapter_is_rejected(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    wrong = FakeDestinationStatusAdapter(
        FakeDestination(tmp_path / "other.sqlite"),
        destination_registry=_REGISTRY,
        destination_name="other-destination",
        destination_contract_digest=ids["contract"],
    )
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, wrong)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        with pytest.raises(ExecutionBindingError):
            recovery.query_destination_status(query, ids["intent"], adapter=wrong)


def test_unregistered_or_mutated_query_adapter_cannot_launder_evidence(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    adapter = FakeDestinationStatusAdapter(
        FakeDestination(tmp_path / "fake-destination.sqlite"),
        destination_registry=_REGISTRY,
        destination_name=_DESTINATION,
        destination_contract_digest=ids["contract"],
    )
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        with pytest.raises(ExecutionAuthorityError):
            recovery.query_destination_status(query, ids["intent"], adapter=adapter)
        recovery.register_query_adapter(_HOST_EXECUTION_AUTHORITY_CAPABILITY, adapter)
        adapter.destination = "mutated-destination"
        with pytest.raises(ExecutionAuthorityError):
            recovery.query_destination_status(query, ids["intent"], adapter=adapter)


def test_query_evidence_is_nonportable_between_intents(tmp_path: Path) -> None:
    first = _setup_unknown(
        tmp_path / "first",
        IdempotencyClass.QUERYABLE_OPERATION_ID,
        workflow="first-workflow",
    )
    second = _setup_unknown(
        tmp_path / "second",
        IdempotencyClass.QUERYABLE_OPERATION_ID,
        workflow="second-workflow",
    )
    with PersistentSecurityState.open(_config(tmp_path / "first")) as state:
        _, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(
            query,
            first["intent"],
            adapter=_adapter(recovery, tmp_path / "first", first["contract"]),
        )
    with PersistentSecurityState.open(_config(tmp_path / "second")) as state:
        _, recovery = _authorities(state)
        with pytest.raises((ExecutionBindingError, ExecutionStateConflict)):
            recovery.propose_recovery(
                _decision(recovery),
                second["intent"],
                destination_contract_digest=second["contract"],
                policy_config_digest=second["policy"],
                query_evidence_id=evidence.query_evidence_id,
            )


def test_recovery_requires_exact_two_step_digest(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        capability = _decision(recovery)
        proposal = recovery.propose_recovery(
            capability,
            ids["intent"],
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )
        with pytest.raises(ExecutionBindingError):
            recovery.authorize_recovery(
                capability,
                proposal.proposal_id,
                proposal_digest=_digest("forged-proposal"),
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_only_one_recovery_generation_can_exist(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        assert record.recovery_generation == 1
        with pytest.raises(ExecutionStateConflict):
            recovery.propose_recovery(
                _decision(recovery, "second-proposer"),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_dispatch_authorization_is_single_use(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = recovery.claim_recovery(worker, record.recovery_id)
        recovery.begin_recovery_dispatch(
            claim,
            action=_ACTION,
            destination_registry=_REGISTRY,
            destination=_DESTINATION,
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )
        with pytest.raises((ExecutionAuthorityError, ExecutionStateConflict)):
            recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recovery_id", "recovery-" + "0" * 32),
        ("execution_intent_id", "intent-" + "0" * 32),
        ("recovery_generation", 2),
        ("claim_generation", 2),
        ("claim_id", "recovery-claim-" + "0" * 32),
        ("worker_id", "worker-" + "0" * 32),
        ("boot_event_id", "event-" + "0" * 32),
        ("attempt_id", "recovery-attempt-" + "0" * 32),
        ("action_fingerprint", "0" * 64),
        ("destination_registry", "substituted-registry"),
        ("destination", "substituted-destination"),
        ("destination_contract_digest", "1" * 64),
        ("destination_class", IdempotencyClass.NO_IDEMPOTENCY),
        ("original_idempotency_key", "rotated-key"),
        ("original_operation_id", "substituted-operation"),
        ("dispatch_authorization_id", "forged-dispatch-authorization"),
    ],
)
def test_mutated_recovery_dispatch_handle_cannot_report_outcome(
    tmp_path: Path, field: str, value: object
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        object.__setattr__(dispatch, field, value)
        with pytest.raises((ExecutionAuthorityError, ExecutionStateConflict)):
            recovery.complete_recovery(
                dispatch,
                result_digest=_digest("forged-result"),
                destination_operation_id="forged-operation",
            )


def test_recovery_dispatch_handles_are_noncopyable_and_nonserializable(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(dispatch)


def test_queryable_completion_cannot_substitute_operation_id(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        record = _propose_and_authorize(recovery, ids, query_evidence_id=evidence.query_evidence_id)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        with pytest.raises(ExecutionBindingError):
            recovery.complete_recovery(
                dispatch,
                result_digest=_digest("forged-result"),
                destination_operation_id="substituted-operation",
            )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("identity", "forged-identity"),
        ("identity_class", "MODEL_SUPPLIED"),
        ("boot_event_id", "forged-boot"),
    ],
)
def test_recovery_capability_rejects_low_level_mutation(
    tmp_path: Path, field: str, value: str
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        capability = _decision(recovery)
        object.__setattr__(capability, field, value)
        with pytest.raises(ExecutionAuthorityError):
            recovery.propose_recovery(
                capability,
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_recovery_capabilities_are_nonconstructable_noncopyable_and_nonserializable(
    tmp_path: Path,
) -> None:
    _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        capability = _decision(recovery)
        with pytest.raises(TypeError):
            RecoveryDecisionCapability(
                object(),
                recovery,
                object(),
                boot_event_id="boot",
                identity="forged",
                identity_class="FORGED",
            )
        with pytest.raises(TypeError):
            QueryAuthorityCapability(
                object(),
                recovery,
                object(),
                boot_event_id="boot",
                identity="forged",
                identity_class="FORGED",
            )
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(capability)


def test_policy_and_destination_substitution_fail_closed(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        for contract, policy in (
            (_digest("changed-contract"), ids["policy"]),
            (ids["contract"], _digest("changed-policy")),
        ):
            with pytest.raises(ExecutionBindingError):
                recovery.propose_recovery(
                    _decision(recovery),
                    ids["intent"],
                    destination_contract_digest=contract,
                    policy_config_digest=policy,
                )


def test_abandoned_reconciliation_does_not_revive_recovery(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        capability = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="abandoner",
            identity_class="HOST_OPERATOR",
        )
        evidence = reconciliation.record_reconciliation_evidence(
            capability,
            ids["reconciliation"],
            category=ReconciliationEvidenceCategory.ABANDONED,
            evidence_digest=_digest("abandonment-evidence"),
            verification_mechanism="host-abandonment",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
        )
        reconciliation.abandon_reconciliation(
            capability,
            ids["reconciliation"],
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionStateConflict):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_abandoned_query_is_diagnostic_only_and_has_zero_dispatch_authority(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="diagnostic-abandoner",
            identity_class="HOST_OPERATOR",
        )
        abandoned = reconciliation.record_reconciliation_evidence(
            decision,
            ids["reconciliation"],
            category=ReconciliationEvidenceCategory.ABANDONED,
            evidence_digest=_digest("diagnostic-abandonment"),
            verification_mechanism="host-abandonment",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
        )
        reconciliation.abandon_reconciliation(
            decision,
            ids["reconciliation"],
            abandoned.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="diagnostic-query",
            identity_class="HOST_ADAPTER",
        )
        evidence = recovery.query_destination_status(
            query,
            ids["intent"],
            adapter=_adapter(recovery, tmp_path, ids["contract"]),
        )
        assert evidence.normalized_result is DestinationQueryResult.NO_EFFECT_CONFIRMED
        with pytest.raises(ExecutionStateConflict):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
                query_evidence_id=evidence.query_evidence_id,
            )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_restart_preserves_recovery_and_source_consumption(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        persisted = recovery.get_recovery(record.recovery_id)
        assert persisted.state is RecoveryState.READY
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        assert state.is_consumed(token_kind="model_output", token_id=ids["output"])
        state.verify_full()


def test_restart_rejects_old_dispatch_handle_without_redispatch(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        with pytest.raises(ExecutionAuthorityError):
            recovery.complete_recovery(
                dispatch,
                result_digest=_digest("post-restart-result"),
                destination_operation_id="post-restart-operation",
            )
        persisted = recovery.get_recovery(record.recovery_id)
        assert persisted.state is RecoveryState.DISPATCHING
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        state.verify_full()


def test_recovery_unknown_never_becomes_retryable(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        unknown = recovery.mark_recovery_outcome_unknown(dispatch)
        assert unknown.state is RecoveryState.OUTCOME_UNKNOWN
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        with pytest.raises(ExecutionStateConflict):
            recovery.claim_recovery(
                execution.register_worker(
                    _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
                ),
                record.recovery_id,
            )
        with pytest.raises(ExecutionStateConflict):
            recovery.propose_recovery(
                _decision(recovery, "second-generation-attempt"),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_recovery_completion_handle_cannot_be_reused_after_unknown(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        recovery.mark_recovery_outcome_unknown(dispatch)
        with pytest.raises(ExecutionStateConflict):
            recovery.complete_recovery(
                dispatch,
                result_digest=_digest("late-completion"),
                destination_operation_id="late-operation",
            )


def test_two_process_recovery_creation_has_one_winner(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_create_recovery_process,
            args=(str(tmp_path), ids, gate, queue),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert [item[0] for item in results].count("won") == 1
    assert [item[0] for item in results].count("lost") == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        state.verify_full()


def test_two_process_claim_and_fence_produce_one_authorization(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_claim_and_fence_process,
            args=(str(tmp_path), ids, record.recovery_id, gate, queue),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert [item[0] for item in results].count("won") == 1
    assert [item[0] for item in results].count("lost") == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        assert recovery.get_recovery(record.recovery_id).state is RecoveryState.DISPATCHING
        state.verify_full()


def test_new_boot_invalidates_recovery_capability_and_claim(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        decision = _decision(recovery)
        record = _propose_and_authorize(recovery, ids)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = recovery.claim_recovery(worker, record.recovery_id)
        state.record_event(event_type="runtime_boot", correlation_id="replacement-boot")
        with pytest.raises(ExecutionAuthorityError):
            recovery.propose_recovery(
                decision,
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        with pytest.raises(ExecutionAuthorityError):
            recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_replacement_worker_only_claims_at_or_after_exact_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.recovery as module

    class Clock:
        now = 1_000_000

        @classmethod
        def monotonic_ns(cls) -> int:
            return cls.now

        @staticmethod
        def time_ns() -> int:
            return 1_000_000

    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        first_worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        replacement = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        monkeypatch.setattr(module, "time", Clock)
        first = recovery.claim_recovery(first_worker, record.recovery_id, lease_seconds=1e-9)
        with pytest.raises(ExecutionStateConflict):
            recovery.claim_recovery(replacement, record.recovery_id)
        Clock.now += 1
        second = recovery.claim_recovery(replacement, record.recovery_id)
        assert second.claim_generation == first.claim_generation + 1
        with pytest.raises((ExecutionAuthorityError, ExecutionStateConflict)):
            recovery.begin_recovery_dispatch(
                first,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        recovery.begin_recovery_dispatch(
            second,
            action=_ACTION,
            destination_registry=_REGISTRY,
            destination=_DESTINATION,
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )


def test_security_configuration_change_blocks_recovery_fence(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        initial = execution.update_security_configuration(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            expected_epoch=0,
            configuration_digest=_digest("security-config-v1"),
            worker_attach_digest=_digest("worker-attach-v1"),
        )
        record = _propose_and_authorize(recovery, ids)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = recovery.claim_recovery(worker, record.recovery_id)
        execution.update_security_configuration(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            expected_epoch=initial.epoch,
            configuration_digest=_digest("security-config-v2"),
            worker_attach_digest=_digest("worker-attach-v2"),
        )
        with pytest.raises(ExecutionBindingError):
            recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_new_query_evidence_invalidates_queryable_recovery_fence(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        first = recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        record = _propose_and_authorize(recovery, ids, query_evidence_id=first.query_evidence_id)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = recovery.claim_recovery(worker, record.recovery_id)
        recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        with pytest.raises(ExecutionBindingError):
            recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_new_query_evidence_after_fence_cannot_revoke_spent_dispatch_authority(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        adapter = _adapter(recovery, tmp_path, ids["contract"])
        no_effect = recovery.query_destination_status(query, ids["intent"], adapter=adapter)
        record = _propose_and_authorize(
            recovery, ids, query_evidence_id=no_effect.query_evidence_id
        )
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        later_no_effect = recovery.query_destination_status(query, ids["intent"], adapter=adapter)
        assert later_no_effect.normalized_result is DestinationQueryResult.NO_EFFECT_CONFIRMED
        result = fake.invoke_recovery(recovery, dispatch, _ACTION)
        completed = recovery.complete_recovery(
            dispatch,
            result_digest=_digest("spent-fence-completion"),
            destination_operation_id=str(result["operation_id"]),
        )
        assert completed.state is RecoveryState.COMPLETED
        assert fake.effect_count == 1


def test_active_recovery_blocks_terminal_c3a_confirmation(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        record = _propose_and_authorize(recovery, ids)
        assert record.state is RecoveryState.READY
        c3a = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="c3a-operator",
            identity_class="HOST_OPERATOR",
        )
        evidence = reconciliation.record_reconciliation_evidence(
            c3a,
            ids["reconciliation"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
            evidence_digest=_digest("late-completion-evidence"),
            verification_mechanism="host-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
        )
        proposal = reconciliation.propose_reconciliation_completed(
            c3a,
            ids["reconciliation"],
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionStateConflict):
            reconciliation.confirm_reconciliation_decision(
                c3a,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
            )


def test_terminal_c3a_confirmation_invalidates_pending_recovery_proposal(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        recovery_capability = _decision(recovery)
        recovery_proposal = recovery.propose_recovery(
            recovery_capability,
            ids["intent"],
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )
        reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        c3a = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="c3a-winner",
            identity_class="HOST_OPERATOR",
        )
        evidence = reconciliation.record_reconciliation_evidence(
            c3a,
            ids["reconciliation"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
            evidence_digest=_digest("c3a-winner-evidence"),
            verification_mechanism="host-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
        )
        proposal = reconciliation.propose_reconciliation_completed(
            c3a,
            ids["reconciliation"],
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        reconciliation.confirm_reconciliation_decision(
            c3a,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionStateConflict):
            recovery.authorize_recovery(
                recovery_capability,
                recovery_proposal.proposal_id,
                proposal_digest=recovery_proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )


def test_active_recovery_blocks_c3a_abandonment(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        assert record.state is RecoveryState.READY
        reconciliation = ReconciliationAuthority._for_host(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
        )
        c3a = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="abandoner",
            identity_class="HOST_OPERATOR",
        )
        evidence = reconciliation.record_reconciliation_evidence(
            c3a,
            ids["reconciliation"],
            category=ReconciliationEvidenceCategory.ABANDONED,
            evidence_digest=_digest("abandon-active-recovery"),
            verification_mechanism="host-abandonment",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionStateConflict):
            reconciliation.abandon_reconciliation(
                c3a,
                ids["reconciliation"],
                evidence.evidence_id,
                destination_contract_digest=ids["contract"],
            )


def test_fake_effect_then_timeout_leaves_recovery_unknown_without_redispatch(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        with pytest.raises(FakeDestinationTimeout):
            fake.invoke_recovery(
                recovery,
                dispatch,
                _ACTION,
                mode=FakeDestinationMode.COMMIT_THEN_TIMEOUT,
            )
        recovery.mark_recovery_outcome_unknown(dispatch)
        assert fake.effect_count == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        assert recovery.get_recovery(record.recovery_id).state is RecoveryState.OUTCOME_UNKNOWN
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        assert fake.effect_count == 1
        state.verify_full()


def test_late_original_dispatch_cannot_overwrite_recovery_completion(
    tmp_path: Path,
) -> None:
    contract = _digest("fake-contract-v1")
    policy = _digest("policy-v1")
    _, _, fingerprint = normalize_action(_ACTION)
    state = PersistentSecurityState.initialize(_config(tmp_path))
    content = state._issue_authoritative_root_for_host(
        _HOST_ROOT_AUTHORITY_CAPABILITY,
        source_type="internal",
        trust="TRUSTED",
        content_digest=_digest("late-original-source"),
        producing_boundary="v03c3b-test",
    )
    turn = state.record_event(
        event_type="model_turn",
        correlation_id="late-original",
        content_ids=(content.content_id,),
    )
    output = state.record_event(
        event_type="model_output",
        correlation_id="late-original",
        parent_event_ids=(turn.event_id,),
        content_ids=(content.content_id,),
        attributes={"action_fingerprint": fingerprint},
    )
    proposal_event = state.record_event(
        event_type="tool_proposal",
        correlation_id="late-original",
        parent_event_ids=(output.event_id,),
        content_ids=(content.content_id,),
        attributes={"action_fingerprint": fingerprint},
    )
    state.create_workflow(
        "late-original",
        head_event_id=proposal_event.event_id,
        current_content_id=content.content_id,
    )
    boot = state.record_event(event_type="runtime_boot", correlation_id="boot")
    execution = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
    decision = execution.prepare_execution(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        workflow_id="late-original",
        expected_head_event_id=proposal_event.event_id,
        expected_revision=0,
        source_turn_event_id=turn.event_id,
        source_output_event_id=output.event_id,
        proposal_event_id=proposal_event.event_id,
        action=_ACTION,
        destination_registry=_REGISTRY,
        destination=_DESTINATION,
        destination_config_digest=contract,
        idempotency_class=IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
        policy_config_digest=policy,
    )
    assert decision.intent_id is not None
    original_worker = execution.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=boot.event_id
    )
    original_claim = execution.claim_execution(original_worker, decision.intent_id)
    original_dispatch = execution.begin_dispatch(
        original_claim,
        action=_ACTION,
        destination_registry=_REGISTRY,
        destination=_DESTINATION,
        destination_config_digest=contract,
    )
    fake = FakeDestination(tmp_path / "fake-destination.sqlite")
    fake.invoke(
        execution,
        original_dispatch,
        _ACTION,
        mode=FakeDestinationMode.PAUSE_BEFORE_EFFECT,
    )
    execution.mark_outcome_unknown(original_dispatch)
    reconciliation = ReconciliationAuthority._for_host(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
    )
    c3a = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="late-original-reconciler",
        identity_class="HOST_OPERATOR",
    )
    reconciliation.begin_reconciliation(
        c3a, decision.intent_id, destination_contract_digest=contract
    )
    recovery = RecoveryAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, execution)
    ids = {
        "boot": boot.event_id,
        "contract": contract,
        "intent": decision.intent_id,
        "policy": policy,
    }
    record = _propose_and_authorize(recovery, ids)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            original_dispatch,
            result_digest=_digest("late-original-before-recovery-fence"),
            destination_operation_id="late-original-operation",
        )
    recovery_dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            original_dispatch,
            result_digest=_digest("late-original-after-recovery-fence"),
            destination_operation_id="late-original-operation",
        )
    result = fake.invoke_recovery(recovery, recovery_dispatch, _ACTION)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            original_dispatch,
            result_digest=_digest("late-original-after-recovery-effect"),
            destination_operation_id="late-original-operation",
        )
    recovery.complete_recovery(
        recovery_dispatch,
        result_digest=_digest("recovery-won"),
        destination_operation_id=str(result["operation_id"]),
    )
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            original_dispatch,
            result_digest=_digest("late-original-result"),
            destination_operation_id="late-original-operation",
        )
    assert execution.get_intent(decision.intent_id).state is ExecutionState.COMPLETED
    state.verify_full()
    state.close()


def test_recovery_capability_is_thread_and_store_bound(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path / "first", IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    other = _setup_unknown(
        tmp_path / "second",
        IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY,
        workflow="other-workflow",
    )
    with (
        PersistentSecurityState.open(_config(tmp_path / "first")) as state,
        PersistentSecurityState.open(_config(tmp_path / "second")) as other_state,
    ):
        _, recovery = _authorities(state)
        _, other_recovery = _authorities(other_state)
        capability = _decision(recovery)
        with pytest.raises(ExecutionAuthorityError):
            other_recovery.propose_recovery(
                capability,
                other["intent"],
                destination_contract_digest=other["contract"],
                policy_config_digest=other["policy"],
            )
        outcomes: queue.Queue[type[BaseException]] = queue.Queue()

        def cross_thread() -> None:
            try:
                recovery.propose_recovery(
                    capability,
                    ids["intent"],
                    destination_contract_digest=ids["contract"],
                    policy_config_digest=ids["policy"],
                )
            except BaseException as exc:  # pragma: no branch - asserted below
                outcomes.put(type(exc))

        thread = threading.Thread(target=cross_thread)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert outcomes.get_nowait() is ExecutionAuthorityError


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(),
    reason="fork process context is unavailable",
)
def test_recovery_capability_is_rejected_in_forked_process(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    context = multiprocessing.get_context("fork")
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        capability = _decision(recovery)
        result_queue = context.Queue()
        process = context.Process(
            target=_use_inherited_capability_process,
            args=(recovery, capability, ids, result_queue),
        )
        process.start()
        process.join(timeout=20)
        assert not process.is_alive()
        assert process.exitcode == 0
        assert result_queue.get(timeout=5) == ("rejected", "EXECUTION_AUTHORITY_DENIED")


def test_query_evidence_bound_exhaustion_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.recovery as module

    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        monkeypatch.setattr(module, "MAX_QUERY_EVIDENCE_PER_INTENT", 1)
        with pytest.raises(ExecutionStateConflict, match="bound"):
            recovery.query_destination_status(
                query,
                ids["intent"],
                adapter=_adapter(recovery, tmp_path, ids["contract"]),
            )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_pending_recovery_and_audit_bounds_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.recovery as module

    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        monkeypatch.setattr(module, "MAX_PENDING_AUDIT", 0)
        with pytest.raises(ExecutionStateConflict, match="audit"):
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


@pytest.mark.parametrize(("pending", "allowed"), [(127, True), (128, False), (129, False)])
def test_pending_recovery_exact_127_128_129_boundaries(
    tmp_path: Path, pending: int, allowed: bool
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        connection = state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        schema_version = connection.execute(
            "SELECT schema_version FROM instance_metadata WHERE singleton=1"
        ).fetchone()[0]
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.executemany(
                """INSERT INTO execution_recovery_proposals(
                proposal_id,instance_id,deployment_id,schema_version,execution_intent_id,
                reconciliation_id,reconciliation_generation,recovery_generation,
                action_fingerprint,destination_registry,destination,destination_contract_digest,
                destination_class,policy_config_digest,proposer_identity,proposer_class,
                proposal_digest,mutation_sequence,key_id,record_mac)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        f"pending-bound-{position}",
                        state.instance_id,
                        state.deployment_id,
                        schema_version,
                        f"pending-intent-{position}",
                        f"pending-reconciliation-{position}",
                        1,
                        1,
                        _digest(f"pending-action-{position}"),
                        _REGISTRY,
                        _DESTINATION,
                        ids["contract"],
                        IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY.value,
                        ids["policy"],
                        "boundary-proposer",
                        "HOST_TEST",
                        _digest(f"pending-proposal-{position}"),
                        0,
                        state.key_id,
                        "0" * 64,
                    )
                    for position in range(pending)
                ],
            )
            if allowed:
                recovery._require_pending_recovery_capacity(connection)
            else:
                with pytest.raises(ExecutionStateConflict, match="pending recovery bound"):
                    recovery._require_pending_recovery_capacity(connection)
        finally:
            connection.rollback()
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        state.verify_full()


def test_audit_backlog_exhaustion_blocks_dispatch_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.recovery as module

    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        claim = recovery.claim_recovery(worker, record.recovery_id)
        monkeypatch.setattr(module, "MAX_PENDING_AUDIT", 0)
        with pytest.raises(ExecutionStateConflict, match="audit"):
            recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        assert recovery.get_recovery(record.recovery_id).state is RecoveryState.CLAIMED
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN


def test_fake_recovery_delivery_uses_authenticated_key_snapshot_after_validation(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    dispatch_holder: dict[str, object] = {}

    def mutate_after_validation(point: str) -> None:
        if point == "during_fake_recovery_invocation":
            object.__setattr__(
                dispatch_holder["dispatch"], "original_idempotency_key", "attacker-key"
            )

    fake = FakeDestination(
        tmp_path / "fake-destination.sqlite", failure_injector=mutate_after_validation
    )
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        original_key = record.original_idempotency_key
        assert original_key is not None
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        dispatch_holder["dispatch"] = dispatch
        fake.invoke_recovery(recovery, dispatch, _ACTION)
        connection = sqlite3.connect(fake.path)
        try:
            persisted_key = connection.execute(
                "SELECT idempotency_key FROM requests ORDER BY request_sequence DESC LIMIT 1"
            ).fetchone()[0]
        finally:
            connection.close()
        assert persisted_key == original_key


def test_recovery_identity_exact_byte_boundaries(tmp_path: Path) -> None:
    _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        for length in (255, 256):
            capability = recovery.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity="i" * length,
                identity_class="HOST_OPERATOR",
            )
            assert len(capability.identity.encode()) == length
        with pytest.raises(ValueError, match="bound"):
            recovery.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity="i" * 257,
                identity_class="HOST_OPERATOR",
            )


@pytest.mark.parametrize(
    ("lease_seconds", "accepted"),
    [(299.999999999, True), (300.0, True), (300.000000001, False)],
)
def test_recovery_lease_exact_boundaries(
    tmp_path: Path, lease_seconds: float, accepted: bool
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        if accepted:
            assert (
                recovery.claim_recovery(
                    worker, record.recovery_id, lease_seconds=lease_seconds
                ).claim_generation
                == 1
            )
        else:
            with pytest.raises(ValueError, match="lease"):
                recovery.claim_recovery(worker, record.recovery_id, lease_seconds=lease_seconds)
            assert recovery.get_recovery(record.recovery_id).state is RecoveryState.READY


def test_query_evidence_exact_31_32_33_boundaries(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        capability = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="boundary-query-host",
            identity_class="HOST_ADAPTER",
        )
        adapter = _adapter(recovery, tmp_path, ids["contract"])
        for _ in range(31):
            recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
        connection = state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        assert (
            connection.execute("SELECT COUNT(*) FROM execution_query_evidence").fetchone()[0] == 31
        )
        recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
        assert (
            connection.execute("SELECT COUNT(*) FROM execution_query_evidence").fetchone()[0] == 32
        )
        with pytest.raises(ExecutionStateConflict, match="bound"):
            recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
        assert (
            connection.execute("SELECT COUNT(*) FROM execution_query_evidence").fetchone()[0] == 32
        )
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        state.verify_full()


def test_recovery_lifecycle_exact_31_32_33_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.recovery as module

    class Clock:
        now = 10_000

        @classmethod
        def monotonic_ns(cls) -> int:
            return cls.now

        @staticmethod
        def time_ns() -> int:
            return 10_000

    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
        monkeypatch.setattr(module, "time", Clock)
        for _ in range(30):
            recovery.claim_recovery(worker, record.recovery_id, lease_seconds=1e-9)
            Clock.now += 1
        connection = state._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        count = connection.execute(
            "SELECT COUNT(*) FROM execution_recovery_lifecycle WHERE recovery_id=?",
            (record.recovery_id,),
        ).fetchone()[0]
        assert count == 31
        recovery.claim_recovery(worker, record.recovery_id, lease_seconds=1e-9)
        Clock.now += 1
        count = connection.execute(
            "SELECT COUNT(*) FROM execution_recovery_lifecycle WHERE recovery_id=?",
            (record.recovery_id,),
        ).fetchone()[0]
        assert count == 32
        with pytest.raises(ExecutionStateConflict, match="lifecycle bound"):
            recovery.claim_recovery(worker, record.recovery_id, lease_seconds=1e-9)
        count = connection.execute(
            "SELECT COUNT(*) FROM execution_recovery_lifecycle WHERE recovery_id=?",
            (record.recovery_id,),
        ).fetchone()[0]
        assert count == 32
        assert execution.get_intent(ids["intent"]).state is ExecutionState.OUTCOME_UNKNOWN
        state.verify_full()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execution_recovery_proposals SET proposal_digest='" + "1" * 64 + "'",
        "UPDATE execution_recovery_proposals SET proposer_identity='model-forged'",
        "UPDATE execution_recovery_proposals SET destination_class='NO_IDEMPOTENCY'",
        "UPDATE execution_recovery_proposals SET policy_config_digest='" + "3" * 64 + "'",
        "UPDATE execution_recovery_authorizations SET authorizer_identity='model-forged'",
        "UPDATE execution_recoveries SET original_idempotency_key='rotated-key'",
        "UPDATE execution_recoveries SET original_operation_id='substituted-operation'",
        "UPDATE execution_recoveries SET action_fingerprint='" + "2" * 64 + "'",
        "UPDATE execution_recoveries SET destination_registry='substituted-registry'",
        "UPDATE execution_recovery_lifecycle SET transition='DISPATCHING'",
        "UPDATE execution_recovery_heads SET state='COMPLETED'",
        "UPDATE execution_recovery_heads SET current_recovery_id='recovery-" + "4" * 32 + "'",
        "DELETE FROM execution_recovery_lifecycle",
        "DELETE FROM execution_recovery_authorizations",
        "DELETE FROM execution_recovery_heads",
    ],
)
def test_recovery_materialized_tamper_is_rejected(tmp_path: Path, statement: str) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        _propose_and_authorize(recovery, ids)
        database = state.paths.database
    connection = sqlite3.connect(database)
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises(StateVerificationError):
        PersistentSecurityState.open(_config(tmp_path))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execution_query_evidence SET normalized_result='EFFECT_CONFIRMED'",
        "UPDATE execution_query_evidence SET original_operation_id='substituted-operation'",
        "UPDATE execution_query_evidence SET adapter_version='stale-version'",
        "UPDATE execution_query_evidence SET observation_digest='" + "5" * 64 + "'",
        "UPDATE execution_query_evidence SET security_configuration_epoch=999",
        "UPDATE execution_query_authorizations SET adapter_identity='laundered-adapter'",
        "UPDATE execution_query_authorizations SET querier_identity='model-forged'",
        "UPDATE execution_query_authorizations SET original_operation_id='other-operation'",
        "DELETE FROM execution_query_evidence",
        "DELETE FROM execution_query_authorizations",
    ],
)
def test_query_materialized_tamper_is_rejected(tmp_path: Path, statement: str) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        query = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-host",
            identity_class="HOST_ADAPTER",
        )
        recovery.query_destination_status(
            query, ids["intent"], adapter=_adapter(recovery, tmp_path, ids["contract"])
        )
        database = state.paths.database
    connection = sqlite3.connect(database)
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises(StateVerificationError):
        PersistentSecurityState.open(_config(tmp_path))


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM audit_outbox WHERE outbox_id=(SELECT MAX(outbox_id) FROM audit_outbox)",
        "UPDATE audit_outbox SET mutation_type='FORGED_RECOVERY_AUTHORITY' "
        "WHERE outbox_id=(SELECT MAX(outbox_id) FROM audit_outbox)",
        "UPDATE audit_outbox SET payload_json='{}' "
        "WHERE outbox_id=(SELECT MAX(outbox_id) FROM audit_outbox)",
    ],
)
def test_recovery_audit_outbox_tamper_is_rejected(tmp_path: Path, statement: str) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        _propose_and_authorize(recovery, ids)
        database = state.paths.database
    connection = sqlite3.connect(database)
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises(StateVerificationError):
        PersistentSecurityState.open(_config(tmp_path))


@pytest.mark.parametrize(
    ("point", "committed"),
    [
        ("before_prepared_anchor", False),
        ("after_prepared_anchor", False),
        ("before_sqlite_commit", False),
        ("after_sqlite_commit", True),
        ("before_final_anchor", True),
        ("after_final_anchor", True),
    ],
)
def test_recovery_authorization_anchor_crash_is_all_or_nothing(
    tmp_path: Path, point: str, committed: bool
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    state = PersistentSecurityState.open(_config(tmp_path))
    _, recovery = _authorities(state)
    capability = _decision(recovery)
    proposal = recovery.propose_recovery(
        capability,
        ids["intent"],
        destination_contract_digest=ids["contract"],
        policy_config_digest=ids["policy"],
    )

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        recovery.authorize_recovery(
            capability,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        connection = reopened._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        count = int(connection.execute("SELECT COUNT(*) FROM execution_recoveries").fetchone()[0])
        assert count == int(committed)
        reopened.verify_full()


@pytest.mark.parametrize("stage", ["proposal", "claim", "dispatch", "completion", "unknown"])
@pytest.mark.parametrize(
    ("point", "committed"),
    [
        ("before_prepared_anchor", False),
        ("after_prepared_anchor", False),
        ("before_sqlite_commit", False),
        ("after_sqlite_commit", True),
        ("before_final_anchor", True),
        ("after_final_anchor", True),
    ],
)
def test_recovery_mutation_anchor_crashes_are_all_or_nothing(
    tmp_path: Path, stage: str, point: str, committed: bool
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    state = PersistentSecurityState.open(_config(tmp_path))
    execution, recovery = _authorities(state)
    record = None
    worker = None
    claim = None
    dispatch = None
    if stage != "proposal":
        record = _propose_and_authorize(recovery, ids)
    if stage in {"claim", "dispatch", "completion", "unknown"}:
        worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=ids["boot"]
        )
    if stage in {"dispatch", "completion", "unknown"}:
        assert record is not None and worker is not None
        claim = recovery.claim_recovery(worker, record.recovery_id)
    if stage in {"completion", "unknown"}:
        assert claim is not None
        dispatch = recovery.begin_recovery_dispatch(
            claim,
            action=_ACTION,
            destination_registry=_REGISTRY,
            destination=_DESTINATION,
            destination_contract_digest=ids["contract"],
            policy_config_digest=ids["policy"],
        )

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        if stage == "proposal":
            recovery.propose_recovery(
                _decision(recovery),
                ids["intent"],
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        elif stage == "claim":
            assert record is not None and worker is not None
            recovery.claim_recovery(worker, record.recovery_id)
        elif stage == "dispatch":
            assert claim is not None
            recovery.begin_recovery_dispatch(
                claim,
                action=_ACTION,
                destination_registry=_REGISTRY,
                destination=_DESTINATION,
                destination_contract_digest=ids["contract"],
                policy_config_digest=ids["policy"],
            )
        elif stage == "completion":
            assert dispatch is not None
            recovery.complete_recovery(
                dispatch,
                result_digest=_digest("crash-completion"),
                destination_operation_id="crash-recovery-operation",
            )
        else:
            assert dispatch is not None
            recovery.mark_recovery_outcome_unknown(dispatch)
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        connection = reopened._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        if stage == "proposal":
            count = int(
                connection.execute("SELECT COUNT(*) FROM execution_recovery_proposals").fetchone()[
                    0
                ]
            )
            assert count == int(committed)
        else:
            assert record is not None
            persisted = connection.execute(
                "SELECT state FROM execution_recoveries WHERE recovery_id=?",
                (record.recovery_id,),
            ).fetchone()
            expected = {
                "claim": RecoveryState.CLAIMED.value if committed else RecoveryState.READY.value,
                "dispatch": (
                    RecoveryState.DISPATCHING.value if committed else RecoveryState.CLAIMED.value
                ),
                "completion": (
                    RecoveryState.COMPLETED.value if committed else RecoveryState.DISPATCHING.value
                ),
                "unknown": (
                    RecoveryState.OUTCOME_UNKNOWN.value
                    if committed
                    else RecoveryState.DISPATCHING.value
                ),
            }[stage]
            assert persisted is not None and persisted["state"] == expected
        reopened.verify_full()


@pytest.mark.parametrize(
    ("point", "committed"),
    [
        ("before_prepared_anchor", False),
        ("after_prepared_anchor", False),
        ("before_sqlite_commit", False),
        ("after_sqlite_commit", True),
        ("before_final_anchor", True),
        ("after_final_anchor", True),
    ],
)
def test_query_evidence_anchor_crash_is_all_or_nothing(
    tmp_path: Path, point: str, committed: bool
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    state = PersistentSecurityState.open(_config(tmp_path))
    _, recovery = _authorities(state)
    capability = recovery.issue_query_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="crash-query-host",
        identity_class="HOST_ADAPTER",
    )
    adapter = _adapter(recovery, tmp_path, ids["contract"])

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        connection = reopened._execution_connection(_EXECUTION_EXTENSION_CAPABILITY)
        count = int(
            connection.execute("SELECT COUNT(*) FROM execution_query_evidence").fetchone()[0]
        )
        authorizations = int(
            connection.execute("SELECT COUNT(*) FROM execution_query_authorizations").fetchone()[0]
        )
        assert count == authorizations == int(committed)
        reopened.verify_full()


def test_c3b_mutations_are_bound_to_authenticated_audit_outbox(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        dispatch = _claim_and_dispatch(execution, recovery, ids, record.recovery_id)
        recovery.mark_recovery_outcome_unknown(dispatch)
        mutations = {record.mutation_type for record in state.pending_audit(limit=200)}
        assert {
            "PROPOSE_RECOVERY",
            "AUTHORIZE_RECOVERY",
            "CLAIM_RECOVERY",
            "BEGIN_RECOVERY_DISPATCH",
            "RECOVERY_OUTCOME_UNKNOWN",
        }.issubset(mutations)


def test_query_authorization_and_result_share_authenticated_audit_mutation(
    tmp_path: Path,
) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.QUERYABLE_OPERATION_ID)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        adapter = _adapter(recovery, tmp_path, ids["contract"])
        capability = recovery.issue_query_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="query-auditor",
            identity_class="HOST_INTERNAL",
        )
        recovery.query_destination_status(capability, ids["intent"], adapter=adapter)
        audit = next(
            record
            for record in state.pending_audit(limit=200)
            if record.mutation_type == "QUERY_DESTINATION_STATUS"
        )
        entities = {change["entity"] for change in json.loads(audit.payload_json)["changes"]}
        assert entities == {"execution_query_authorization", "execution_query_evidence"}


def test_host_recovery_rejection_is_authenticated_as_cancellation(tmp_path: Path) -> None:
    ids = _setup_unknown(tmp_path, IdempotencyClass.CALLER_SUPPLIED_IDEMPOTENCY_KEY)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, recovery = _authorities(state)
        record = _propose_and_authorize(recovery, ids)
        cancelled = recovery.cancel_recovery(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            record.recovery_id,
            reason_code="HOST_REJECTED",
        )
        assert cancelled.state is RecoveryState.CANCELLED
        assert "CANCEL_RECOVERY" in {
            audit.mutation_type for audit in state.pending_audit(limit=200)
        }


def test_recovery_methods_are_not_gateway_or_model_surfaces() -> None:
    from secureinjections import gateway
    from secureinjections.local_agent.protocol import ALLOWED_MODEL_TOOLS

    forbidden = {
        "authorize_recovery",
        "begin_recovery_dispatch",
        "claim_recovery",
        "complete_recovery",
        "propose_recovery",
        "query_destination_status",
    }
    assert forbidden.isdisjoint(vars(gateway))
    assert forbidden.isdisjoint(ALLOWED_MODEL_TOOLS)
    package = Path(__file__).parents[1] / "secureinjections"
    exposed_roots = (
        package / "gateway",
        package / "local_agent",
        package / "guard_proxy",
        package / "integrations",
    )
    for root in exposed_roots:
        for source in root.rglob("*.py"):
            text = source.read_text(encoding="utf-8")
            assert "RecoveryAuthority" not in text, source
            assert all(f".{method}(" not in text for method in forbidden), source
