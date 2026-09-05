from __future__ import annotations

import copy
import hashlib
import multiprocessing
import os
import pickle
import sqlite3
import threading
from pathlib import Path

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
    ReconciliationAuthority,
    ReconciliationDisposition,
    ReconciliationEvidenceCategory,
    StateAuthenticationError,
    StateVerificationError,
    UnknownAuthorityRecord,
)
from secureinjections.persistent_state.execution import (
    _HOST_EXECUTION_AUTHORITY_CAPABILITY,
    normalize_action,
)
from secureinjections.persistent_state.store import _HOST_ROOT_AUTHORITY_CAPABILITY


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(path: Path, deployment_id: str = "reconciliation-test") -> PersistentStateConfig:
    return PersistentStateConfig(path, deployment_id, busy_timeout_ms=10_000)


def _unknown(
    path: Path,
    workflow: str = "reconciliation-workflow",
    deployment_id: str = "reconciliation-test",
) -> tuple[dict[str, str], str]:
    action = {"action": "TOOL_CALL", "arguments": {"value": 1}, "tool": "effect"}
    _, _, fingerprint = normalize_action(action)
    with PersistentSecurityState.initialize(_config(path, deployment_id)) as state:
        content = state._issue_authoritative_root_for_host(
            _HOST_ROOT_AUTHORITY_CAPABILITY,
            source_type="internal",
            trust="TRUSTED",
            content_digest=_digest("reconciliation-source"),
            producing_boundary="v03c3a-test",
        )
        turn = state.record_event(
            event_type="model_turn", correlation_id=workflow, content_ids=(content.content_id,)
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
            workflow, head_event_id=proposal.event_id, current_content_id=content.content_id
        )
        boot = state.record_event(event_type="runtime_boot", correlation_id="boot")
        authority = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
        decision = authority.prepare_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=workflow,
            expected_head_event_id=proposal.event_id,
            expected_revision=0,
            source_turn_event_id=turn.event_id,
            source_output_event_id=output.event_id,
            proposal_event_id=proposal.event_id,
            action=action,
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-contract-v1"),
            idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
            policy_config_digest=_digest("policy-v1"),
        )
        assert decision.intent_id is not None
        worker = authority.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=boot.event_id
        )
        claim = authority.claim_execution(worker, decision.intent_id)
        dispatch = authority.begin_dispatch(
            claim,
            action=action,
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=_digest("fake-contract-v1"),
        )
        authority.mark_outcome_unknown(dispatch, destination_operation_id="external-operation-1")
        return {
            "workflow": workflow,
            "output": output.event_id,
            "attempt": dispatch.attempt_id,
            "contract": _digest("fake-contract-v1"),
            "fingerprint": fingerprint,
        }, decision.intent_id


def _authorities(
    state: PersistentSecurityState,
) -> tuple[ExecutionAuthority, ReconciliationAuthority]:
    execution = ExecutionAuthority._for_host(_HOST_EXECUTION_AUTHORITY_CAPABILITY, state)
    return execution, ReconciliationAuthority._for_host(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, execution
    )


def _begin_process(path: str, intent_id: str, contract: str, gate: object, queue: object) -> None:
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            _, reconciliation = _authorities(state)
            capability = reconciliation.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity=f"process-{os.getpid()}",
                identity_class="HOST_PROCESS",
            )
            gate.wait()  # type: ignore[attr-defined]
            record = reconciliation.begin_reconciliation(
                capability, intent_id, destination_contract_digest=contract
            )
            queue.put(("won", record.generation, record.reconciliation_id))  # type: ignore[attr-defined]
    except ExecutionStateConflict as exc:
        queue.put(("lost", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover - parent reports details
        queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]


def _proposal_process(
    path: str,
    reconciliation_id: str,
    evidence_id: str,
    contract: str,
    proposal_type: str,
    gate: object,
    queue: object,
) -> None:
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            _, reconciliation = _authorities(state)
            capability = reconciliation.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity=f"process-{os.getpid()}",
                identity_class="HOST_PROCESS",
            )
            gate.wait()  # type: ignore[attr-defined]
            operation = (
                reconciliation.propose_reconciliation_completed
                if proposal_type == "COMPLETED"
                else reconciliation.propose_reconciliation_no_effect
            )
            proposal = operation(
                capability,
                reconciliation_id,
                evidence_id,
                destination_contract_digest=contract,
            )
            queue.put(("won", proposal.proposal_type.value, proposal.proposal_id))  # type: ignore[attr-defined]
    except (ExecutionStateConflict, ExecutionBindingError) as exc:
        queue.put(("lost", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover
        queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]


def _confirm_process(
    path: str,
    proposal_id: str,
    proposal_digest: str,
    contract: str,
    gate: object,
    queue: object,
) -> None:
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            _, reconciliation = _authorities(state)
            capability = reconciliation.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity=f"confirmer-{os.getpid()}",
                identity_class="HOST_PROCESS",
            )
            gate.wait()  # type: ignore[attr-defined]
            result = reconciliation.confirm_reconciliation_decision(
                capability,
                proposal_id,
                proposal_digest=proposal_digest,
                destination_contract_digest=contract,
            )
            queue.put(("won", result.state.value))  # type: ignore[attr-defined]
    except (ExecutionStateConflict, ExecutionBindingError) as exc:
        queue.put(("lost", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover
        queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]


def _abandon_process(
    path: str,
    reconciliation_id: str,
    evidence_id: str,
    contract: str,
    gate: object,
    queue: object,
) -> None:
    try:
        with PersistentSecurityState.open(_config(Path(path))) as state:
            _, reconciliation = _authorities(state)
            capability = reconciliation.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity=f"abandoner-{os.getpid()}",
                identity_class="HOST_PROCESS",
            )
            gate.wait()  # type: ignore[attr-defined]
            result = reconciliation.abandon_reconciliation(
                capability,
                reconciliation_id,
                evidence_id,
                destination_contract_digest=contract,
            )
            queue.put(("won", result.disposition.value))  # type: ignore[attr-defined]
    except (ExecutionStateConflict, ExecutionBindingError) as exc:
        queue.put(("lost", exc.code))  # type: ignore[attr-defined]
    except BaseException as exc:  # pragma: no cover
        queue.put(("error", type(exc).__name__, str(exc)))  # type: ignore[attr-defined]


def _begin_and_evidence(
    reconciliation: ReconciliationAuthority,
    intent_id: str,
    contract: str,
    *,
    category: ReconciliationEvidenceCategory,
):
    decision = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="operator-one",
        identity_class="HOST_OPERATOR",
    )
    current = reconciliation.begin_reconciliation(
        decision, intent_id, destination_contract_digest=contract
    )
    assert current.reconciliation_id is not None
    evidence = reconciliation.record_reconciliation_evidence(
        decision,
        current.reconciliation_id,
        category=category,
        evidence_digest=_digest("bounded-external-evidence"),
        verification_mechanism="manual-ledger",
        verification_version="v1",
        destination_contract_digest=contract,
        external_operation_id="external-operation-1",
    )
    return decision, current, evidence


@pytest.mark.parametrize(
    ("category", "target"),
    [
        (ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED, ExecutionState.COMPLETED),
        (
            ReconciliationEvidenceCategory.OPERATOR_VERIFIED_NO_EFFECT,
            ExecutionState.FAILED_NO_EFFECT,
        ),
    ],
)
def test_two_step_confirmation_is_terminal_and_atomic(
    tmp_path: Path, category: ReconciliationEvidenceCategory, target: ExecutionState
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        proposer, current, evidence = _begin_and_evidence(
            reconciliation, intent_id, ids["contract"], category=category
        )
        proposal = (
            reconciliation.propose_reconciliation_completed(
                proposer,
                current.reconciliation_id or "",
                evidence.evidence_id,
                destination_contract_digest=ids["contract"],
            )
            if target is ExecutionState.COMPLETED
            else reconciliation.propose_reconciliation_no_effect(
                proposer,
                current.reconciliation_id or "",
                evidence.evidence_id,
                destination_contract_digest=ids["contract"],
            )
        )
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN
        confirmer = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="operator-two",
            identity_class="HOST_OPERATOR",
        )
        terminal = reconciliation.confirm_reconciliation_decision(
            confirmer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        assert terminal.state is target
        assert state.get_workflow(ids["workflow"]).status == "ACTIVE"
        assert execution.get_intent(intent_id).source_output_event_id == ids["output"]
        state.verify_full()


def test_inspection_is_redacted_and_read_only(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        inspection = reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        record = reconciliation.inspect_execution(inspection, intent_id)
        assert record.reconciliation_id is None
        assert record.action_fingerprint == ids["fingerprint"]
        assert not hasattr(record, "normalized_action")
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN


def test_proposal_digest_and_contract_are_exact_confirmation_bindings(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionBindingError):
            reconciliation.confirm_reconciliation_decision(
                decision,
                proposal.proposal_id,
                proposal_digest=_digest("forged-proposal"),
                destination_contract_digest=ids["contract"],
            )
        with pytest.raises(ExecutionBindingError):
            reconciliation.confirm_reconciliation_decision(
                decision,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=_digest("changed-contract"),
            )


def test_host_bound_proposer_and_confirmer_identities_are_persisted_separately(
    tmp_path: Path,
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        proposer = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="host-proposer",
            identity_class="HOST_OPERATOR",
        )
        current = reconciliation.begin_reconciliation(
            proposer, intent_id, destination_contract_digest=ids["contract"]
        )
        assert current.reconciliation_id is not None
        evidence = reconciliation.record_reconciliation_evidence(
            proposer,
            current.reconciliation_id,
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
            evidence_digest=_digest("identity-separation-evidence"),
            verification_mechanism="manual-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )
        proposal = reconciliation.propose_reconciliation_completed(
            proposer,
            current.reconciliation_id,
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        confirmer = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="host-confirmer",
            identity_class="HOST_SERVICE",
        )
        reconciliation.confirm_reconciliation_decision(
            confirmer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        state.verify_full()

    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    verifier = connection.execute(
        "SELECT verifier_identity,verifier_class FROM execution_reconciliation_evidence"
    ).fetchone()
    persisted_proposer = connection.execute(
        "SELECT proposer_identity,proposer_class FROM execution_reconciliation_proposals"
    ).fetchone()
    persisted_confirmer = connection.execute(
        "SELECT confirmation_identity,confirmation_class "
        "FROM execution_reconciliation_confirmations"
    ).fetchone()
    connection.close()
    assert verifier == ("host-proposer", "HOST_OPERATOR")
    assert persisted_proposer == ("host-proposer", "HOST_OPERATOR")
    assert persisted_confirmer == ("host-confirmer", "HOST_SERVICE")


@pytest.mark.parametrize("reuse_capability", [False, True])
def test_same_host_identity_remains_permitted_without_four_eyes_policy(
    tmp_path: Path, reuse_capability: bool
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        proposer, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            proposer,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        confirmer = (
            proposer
            if reuse_capability
            else reconciliation.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity="operator-one",
                identity_class="HOST_OPERATOR",
            )
        )
        terminal = reconciliation.confirm_reconciliation_decision(
            confirmer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        assert terminal.state is ExecutionState.COMPLETED
        assert execution.get_intent(intent_id).state is ExecutionState.COMPLETED
        state.verify_full()


def test_confirmation_requires_persisted_proposal_and_rejects_replay(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="host-confirmer",
            identity_class="HOST_OPERATOR",
        )
        with pytest.raises(UnknownAuthorityRecord):
            reconciliation.confirm_reconciliation_decision(
                decision,
                "reconciliation-proposal-not-persisted",
                proposal_digest=_digest("fabricated-proposal"),
                destination_contract_digest=ids["contract"],
            )
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN

        proposer, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            proposer,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        reconciliation.confirm_reconciliation_decision(
            decision,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionStateConflict):
            reconciliation.confirm_reconciliation_decision(
                decision,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
            )
        state.verify_full()


def test_post_proposal_conflict_evidence_invalidates_confirmation(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        reconciliation.record_reconciliation_evidence(
            decision,
            current.reconciliation_id or "",
            category=ReconciliationEvidenceCategory.CONFLICT,
            evidence_digest=_digest("post-proposal-conflict"),
            verification_mechanism="manual-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )
        with pytest.raises(ExecutionBindingError):
            reconciliation.confirm_reconciliation_decision(
                decision,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
            )
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN
        state.verify_full()


def test_no_effect_requires_no_effect_category(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        with pytest.raises(ExecutionBindingError):
            reconciliation.propose_reconciliation_no_effect(
                decision,
                current.reconciliation_id or "",
                evidence.evidence_id,
                destination_contract_digest=ids["contract"],
            )


def test_abandonment_preserves_unknown_and_blocks_workflow(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.ABANDONED,
        )
        result = reconciliation.abandon_reconciliation(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        assert result.disposition is ReconciliationDisposition.ABANDONED
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN
        assert state.get_workflow(ids["workflow"]).status == "BLOCKED_UNKNOWN_ABANDONED"
        with pytest.raises(ExecutionStateConflict):
            reconciliation.begin_reconciliation(
                decision, intent_id, destination_contract_digest=ids["contract"]
            )
        state.verify_full()


def test_conflict_closes_generation_but_permits_monotonic_new_generation(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, first, _evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.CONFLICT,
        )
        second = reconciliation.begin_reconciliation(
            decision, intent_id, destination_contract_digest=ids["contract"]
        )
        assert second.generation == first.generation + 1
        state.verify_full()


def test_capabilities_are_opaque_noncopyable_and_role_separated(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        inspection = reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="operator",
            identity_class="HOST_OPERATOR",
        )
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(decision)
        with pytest.raises(ExecutionAuthorityError):
            reconciliation.inspect_execution(decision, intent_id)  # type: ignore[arg-type]
        with pytest.raises(ExecutionAuthorityError):
            reconciliation.begin_reconciliation(  # type: ignore[arg-type]
                inspection, intent_id, destination_contract_digest=ids["contract"]
            )


def test_reconciliation_decision_capability_rejects_low_level_identity_mutation(
    tmp_path: Path,
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="host-issued-operator",
            identity_class="HOST_OPERATOR",
        )
        current = reconciliation.begin_reconciliation(
            decision, intent_id, destination_contract_digest=ids["contract"]
        )
        assert current.reconciliation_id is not None

        object.__setattr__(decision, "identity", "caller-forged-operator")
        object.__setattr__(decision, "identity_class", "CALLER_FORGED")

        with pytest.raises(ExecutionAuthorityError):
            reconciliation.record_reconciliation_evidence(
                decision,
                current.reconciliation_id,
                category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
                evidence_digest=_digest("identity-mutation-evidence"),
                verification_mechanism="manual-ledger",
                verification_version="v1",
                destination_contract_digest=ids["contract"],
                external_operation_id="external-operation-1",
            )


def test_capability_is_thread_bound(tmp_path: Path) -> None:
    _ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        inspection = reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        errors: list[BaseException] = []

        def misuse() -> None:
            try:
                reconciliation.inspect_execution(inspection, intent_id)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=misuse)
        thread.start()
        thread.join()
        assert len(errors) == 1
        assert isinstance(errors[0], ExecutionAuthorityError)


def test_sqlite_evidence_tamper_is_rejected(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        _decision, _current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
    database = tmp_path / "authority.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE execution_reconciliation_evidence "
        "SET evidence_category='OPERATOR_VERIFIED_NO_EFFECT' WHERE evidence_id=?",
        (evidence.evidence_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(StateAuthenticationError):
        PersistentSecurityState.open(_config(tmp_path))


def test_c3a_exposes_no_retry_or_query_surface(tmp_path: Path) -> None:
    _ids, _intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        for forbidden in (
            "query_external_status",
            "authorize_retry",
            "retry_anyway",
            "claim_recovery",
            "begin_recovery_dispatch",
            "resolve_unknown",
        ):
            assert not hasattr(reconciliation, forbidden)


@pytest.mark.parametrize("workers", [2, 6])
def test_reconciliation_generation_process_race_has_one_winner(
    tmp_path: Path, workers: int
) -> None:
    ids, intent_id = _unknown(tmp_path)
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_begin_process,
            args=(str(tmp_path), intent_id, ids["contract"], gate, queue),
        )
        for _ in range(workers)
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    assert sum(result[0] == "won" for result in results) == 1
    assert all(result[0] in {"won", "lost"} for result in results)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        state.verify_full()


def test_conflicting_proposal_process_race_has_one_winner(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, completed = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        no_effect = reconciliation.record_reconciliation_evidence(
            decision,
            current.reconciliation_id or "",
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_NO_EFFECT,
            evidence_digest=_digest("contradictory-no-effect-evidence"),
            verification_mechanism="manual-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    inputs = ((completed.evidence_id, "COMPLETED"), (no_effect.evidence_id, "NO_EFFECT"))
    processes = [
        context.Process(
            target=_proposal_process,
            args=(
                str(tmp_path),
                current.reconciliation_id,
                evidence_id,
                ids["contract"],
                proposal_type,
                gate,
                queue,
            ),
        )
        for evidence_id, proposal_type in inputs
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    assert sum(result[0] == "won" for result in results) == 1
    assert sum(result[0] == "lost" for result in results) == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        state.verify_full()


def test_confirmation_process_race_has_one_terminal_history(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_confirm_process,
            args=(
                str(tmp_path),
                proposal.proposal_id,
                proposal.proposal_digest,
                ids["contract"],
                gate,
                queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    assert sum(result[0] == "won" for result in results) == 1
    assert sum(result[0] == "lost" for result in results) == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, _ = _authorities(state)
        assert execution.get_intent(intent_id).state is ExecutionState.COMPLETED
        state.verify_full()


def test_confirmation_vs_abandonment_race_has_one_winner(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, completed = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
        )
        abandonment = reconciliation.record_reconciliation_evidence(
            decision,
            current.reconciliation_id or "",
            category=ReconciliationEvidenceCategory.ABANDONED,
            evidence_digest=_digest("operator-abandonment"),
            verification_mechanism="operator-decision",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            completed.evidence_id,
            destination_contract_digest=ids["contract"],
        )
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_confirm_process,
            args=(
                str(tmp_path),
                proposal.proposal_id,
                proposal.proposal_digest,
                ids["contract"],
                gate,
                queue,
            ),
        ),
        context.Process(
            target=_abandon_process,
            args=(
                str(tmp_path),
                current.reconciliation_id,
                abandonment.evidence_id,
                ids["contract"],
                gate,
                queue,
            ),
        ),
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    assert sum(result[0] == "won" for result in results) == 1
    assert sum(result[0] == "lost" for result in results) == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, _ = _authorities(state)
        assert execution.get_intent(intent_id).state in {
            ExecutionState.COMPLETED,
            ExecutionState.OUTCOME_UNKNOWN,
        }
        state.verify_full()


def test_restart_between_proposal_and_confirmation(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        confirmer = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="restart-confirmer",
            identity_class="HOST_OPERATOR",
        )
        result = reconciliation.confirm_reconciliation_decision(
            confirmer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        assert result.state is ExecutionState.COMPLETED
        assert execution.get_intent(intent_id).state is ExecutionState.COMPLETED
        state.verify_full()


def test_stale_proposal_rejected_after_new_generation(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, completed = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            completed.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        reconciliation.record_reconciliation_evidence(
            decision,
            current.reconciliation_id or "",
            category=ReconciliationEvidenceCategory.CONFLICT,
            evidence_digest=_digest("later-conflict"),
            verification_mechanism="manual-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )
        replacement = reconciliation.begin_reconciliation(
            decision, intent_id, destination_contract_digest=ids["contract"]
        )
        assert replacement.generation == current.generation + 1
        with pytest.raises(ExecutionBindingError):
            reconciliation.confirm_reconciliation_decision(
                decision,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
            )


def test_reconciled_no_effect_cannot_use_legacy_retry_authority(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        proposer, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_NO_EFFECT,
        )
        proposal = reconciliation.propose_reconciliation_no_effect(
            proposer,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        reconciliation.confirm_reconciliation_decision(
            proposer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
        with pytest.raises(ExecutionStateConflict):
            execution.retry_failed_no_effect(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                intent_id,
                reason_code="C3A_RETRY_FORBIDDEN",
            )
        assert execution.get_intent(intent_id).state is ExecutionState.FAILED_NO_EFFECT


@pytest.mark.parametrize(
    ("point", "terminal"),
    [
        ("before_prepared_anchor", False),
        ("after_prepared_anchor", False),
        ("before_sqlite_commit", False),
        ("after_sqlite_commit", True),
        ("before_final_anchor", True),
        ("after_final_anchor", True),
    ],
)
def test_confirmation_anchor_crash_is_all_or_nothing(
    tmp_path: Path, point: str, terminal: bool
) -> None:
    ids, intent_id = _unknown(tmp_path)
    state = PersistentSecurityState.open(_config(tmp_path))
    _, reconciliation = _authorities(state)
    proposer, current, evidence = _begin_and_evidence(
        reconciliation,
        intent_id,
        ids["contract"],
        category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
    )
    proposal = reconciliation.propose_reconciliation_completed(
        proposer,
        current.reconciliation_id or "",
        evidence.evidence_id,
        destination_contract_digest=ids["contract"],
    )

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        reconciliation.confirm_reconciliation_decision(
            proposer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        execution, _ = _authorities(reopened)
        expected = ExecutionState.COMPLETED if terminal else ExecutionState.OUTCOME_UNKNOWN
        assert execution.get_intent(intent_id).state is expected
        assert reopened.get_workflow(ids["workflow"]).status == (
            "ACTIVE" if terminal else "BLOCKED_UNKNOWN"
        )
        reopened.verify_full()


@pytest.mark.parametrize("stage", ["generation", "evidence", "proposal"])
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
def test_preterminal_mutation_crashes_are_all_or_nothing(
    tmp_path: Path, stage: str, point: str, committed: bool
) -> None:
    ids, intent_id = _unknown(tmp_path)
    state = PersistentSecurityState.open(_config(tmp_path))
    _, reconciliation = _authorities(state)
    decision = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="crash-operator",
        identity_class="HOST_OPERATOR",
    )
    current = None
    evidence = None
    if stage != "generation":
        current = reconciliation.begin_reconciliation(
            decision, intent_id, destination_contract_digest=ids["contract"]
        )
    if stage == "proposal":
        assert current is not None and current.reconciliation_id is not None
        evidence = reconciliation.record_reconciliation_evidence(
            decision,
            current.reconciliation_id,
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
            evidence_digest=_digest("crash-evidence"),
            verification_mechanism="manual-ledger",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        if stage == "generation":
            reconciliation.begin_reconciliation(
                decision, intent_id, destination_contract_digest=ids["contract"]
            )
        elif stage == "evidence":
            assert current is not None and current.reconciliation_id is not None
            reconciliation.record_reconciliation_evidence(
                decision,
                current.reconciliation_id,
                category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
                evidence_digest=_digest("crash-evidence"),
                verification_mechanism="manual-ledger",
                verification_version="v1",
                destination_contract_digest=ids["contract"],
                external_operation_id="external-operation-1",
            )
        else:
            assert current is not None and current.reconciliation_id is not None
            assert evidence is not None
            reconciliation.propose_reconciliation_completed(
                decision,
                current.reconciliation_id,
                evidence.evidence_id,
                destination_contract_digest=ids["contract"],
            )
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        reopened.verify_full()
    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    table = {
        "generation": "execution_reconciliations",
        "evidence": "execution_reconciliation_evidence",
        "proposal": "execution_reconciliation_proposals",
    }[stage]
    count = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    connection.close()
    assert count == int(committed)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execution_reconciliation_heads SET current_generation=99",
        "UPDATE execution_reconciliations SET destination_contract_digest='" + "0" * 64 + "'",
        "UPDATE execution_reconciliations SET ambiguous_attempt_id='attempt-forged'",
        "UPDATE execution_reconciliations SET intent_id='intent-forged'",
        "UPDATE execution_reconciliation_evidence SET evidence_digest='" + "1" * 64 + "'",
        "UPDATE execution_reconciliation_evidence "
        "SET evidence_category='OPERATOR_VERIFIED_NO_EFFECT'",
        "UPDATE execution_reconciliation_evidence SET external_operation_id='wrong-operation'",
        "UPDATE execution_reconciliation_proposals SET proposal_type='FAILED_NO_EFFECT'",
        "UPDATE execution_reconciliation_proposals SET proposal_digest='" + "2" * 64 + "'",
        "UPDATE execution_reconciliation_proposals SET proposer_identity='forged-operator'",
        "UPDATE execution_reconciliation_confirmations "
        "SET confirmation_identity='forged-confirmer'",
        "UPDATE execution_reconciliation_heads SET disposition='ABANDONED'",
        "UPDATE workflow_state SET status='BLOCKED_UNKNOWN'",
    ],
)
def test_reconciliation_tamper_is_rejected(tmp_path: Path, statement: str) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        proposer, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            proposer,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        confirmer = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="tamper-confirmer",
            identity_class="HOST_OPERATOR",
        )
        reconciliation.confirm_reconciliation_decision(
            confirmer,
            proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            destination_contract_digest=ids["contract"],
        )
    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises((StateAuthenticationError, ExecutionBindingError)):
        PersistentSecurityState.open(_config(tmp_path))


def test_stale_capability_after_new_boot_is_rejected(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        inspection = reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="stale-operator",
            identity_class="HOST_OPERATOR",
        )
        state.record_event(event_type="runtime_boot", correlation_id="replacement-boot")
        with pytest.raises(ExecutionAuthorityError):
            reconciliation.inspect_execution(inspection, intent_id)
        with pytest.raises(ExecutionAuthorityError):
            reconciliation.begin_reconciliation(
                decision, intent_id, destination_contract_digest=ids["contract"]
            )


def test_capability_cannot_cross_authority_or_store(tmp_path: Path) -> None:
    _ids, intent_id = _unknown(tmp_path)
    other_path = tmp_path / "other"
    other_ids, other_intent_id = _unknown(
        other_path,
        workflow="other-workflow",
        deployment_id="other-reconciliation-test",
    )
    with (
        PersistentSecurityState.open(_config(tmp_path)) as state,
        PersistentSecurityState.open(
            _config(other_path, "other-reconciliation-test")
        ) as other_state,
    ):
        _, reconciliation = _authorities(state)
        _, other = _authorities(other_state)
        inspection = reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="store-bound-operator",
            identity_class="HOST_OPERATOR",
        )
        with pytest.raises(ExecutionAuthorityError):
            other.inspect_execution(inspection, intent_id)
        with pytest.raises(ExecutionAuthorityError):
            other.begin_reconciliation(
                decision,
                other_intent_id,
                destination_contract_digest=other_ids["contract"],
            )


def test_audit_backlog_blocks_dangerous_mutation_but_not_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.reconciliation as module

    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        inspection = reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        decision = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="operator",
            identity_class="HOST_OPERATOR",
        )
        monkeypatch.setattr(module, "MAX_PENDING_AUDIT", 0)
        assert reconciliation.inspect_execution(inspection, intent_id).intent_id == intent_id
        with pytest.raises(ExecutionAuthorityError, match="audit backlog"):
            reconciliation.begin_reconciliation(
                decision, intent_id, destination_contract_digest=ids["contract"]
            )


def test_evidence_bound_exhaustion_remains_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secureinjections.persistent_state.reconciliation as module

    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        decision, current, _evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        monkeypatch.setattr(module, "MAX_EVIDENCE_PER_INTENT", 1)
        with pytest.raises(ExecutionStateConflict, match="bound"):
            reconciliation.record_reconciliation_evidence(
                decision,
                current.reconciliation_id or "",
                category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
                evidence_digest=_digest("second-evidence"),
                verification_mechanism="manual-ledger",
                verification_version="v1",
                destination_contract_digest=ids["contract"],
            )
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN


def test_late_original_dispatch_response_cannot_overwrite_reconciliation(
    tmp_path: Path,
) -> None:
    action = {"action": "TOOL_CALL", "arguments": {"value": 1}, "tool": "effect"}
    _, _, fingerprint = normalize_action(action)
    state = PersistentSecurityState.initialize(_config(tmp_path))
    content = state._issue_authoritative_root_for_host(
        _HOST_ROOT_AUTHORITY_CAPABILITY,
        source_type="internal",
        trust="TRUSTED",
        content_digest=_digest("late-response-source"),
        producing_boundary="v03c3a-test",
    )
    turn = state.record_event(
        event_type="model_turn",
        correlation_id="late-response",
        content_ids=(content.content_id,),
    )
    output = state.record_event(
        event_type="model_output",
        correlation_id="late-response",
        parent_event_ids=(turn.event_id,),
        content_ids=(content.content_id,),
        attributes={"action_fingerprint": fingerprint},
    )
    proposal_event = state.record_event(
        event_type="tool_proposal",
        correlation_id="late-response",
        parent_event_ids=(output.event_id,),
        content_ids=(content.content_id,),
        attributes={"action_fingerprint": fingerprint},
    )
    state.create_workflow(
        "late-response",
        head_event_id=proposal_event.event_id,
        current_content_id=content.content_id,
    )
    boot = state.record_event(event_type="runtime_boot", correlation_id="boot")
    execution, reconciliation = _authorities(state)
    decision = execution.prepare_execution(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        workflow_id="late-response",
        expected_head_event_id=proposal_event.event_id,
        expected_revision=0,
        source_turn_event_id=turn.event_id,
        source_output_event_id=output.event_id,
        proposal_event_id=proposal_event.event_id,
        action=action,
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-contract-v1"),
        idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
        policy_config_digest=_digest("policy-v1"),
    )
    assert decision.intent_id is not None
    worker = execution.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=boot.event_id
    )
    original_dispatch = execution.begin_dispatch(
        execution.claim_execution(worker, decision.intent_id),
        action=action,
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-contract-v1"),
    )
    execution.mark_outcome_unknown(original_dispatch, destination_operation_id="late-operation")
    host = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="late-response-operator",
        identity_class="HOST_OPERATOR",
    )
    current = reconciliation.begin_reconciliation(
        host,
        decision.intent_id,
        destination_contract_digest=_digest("fake-contract-v1"),
    )
    evidence = reconciliation.record_reconciliation_evidence(
        host,
        current.reconciliation_id or "",
        category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
        evidence_digest=_digest("late-response-evidence"),
        verification_mechanism="external-ledger",
        verification_version="v1",
        destination_contract_digest=_digest("fake-contract-v1"),
        external_operation_id="late-operation",
    )
    terminal_proposal = reconciliation.propose_reconciliation_completed(
        host,
        current.reconciliation_id or "",
        evidence.evidence_id,
        destination_contract_digest=_digest("fake-contract-v1"),
    )
    reconciliation.confirm_reconciliation_decision(
        host,
        terminal_proposal.proposal_id,
        proposal_digest=terminal_proposal.proposal_digest,
        destination_contract_digest=_digest("fake-contract-v1"),
    )
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            original_dispatch,
            result_digest=_digest("late-original-result"),
            destination_operation_id="late-operation",
        )
    assert execution.get_intent(decision.intent_id).state is ExecutionState.COMPLETED
    state.verify_full()
    state.close()


def _live_unknown(state: PersistentSecurityState, workflow: str):
    action = {"action": "TOOL_CALL", "arguments": {"value": 1}, "tool": "effect"}
    _, _, fingerprint = normalize_action(action)
    content = state._issue_authoritative_root_for_host(
        _HOST_ROOT_AUTHORITY_CAPABILITY,
        source_type="internal",
        trust="TRUSTED",
        content_digest=_digest(f"{workflow}-source"),
        producing_boundary="v03c3a-hostile-test",
    )
    turn = state.record_event(
        event_type="model_turn", correlation_id=workflow, content_ids=(content.content_id,)
    )
    output = state.record_event(
        event_type="model_output",
        correlation_id=workflow,
        parent_event_ids=(turn.event_id,),
        content_ids=(content.content_id,),
        attributes={"action_fingerprint": fingerprint},
    )
    proposal_event = state.record_event(
        event_type="tool_proposal",
        correlation_id=workflow,
        parent_event_ids=(output.event_id,),
        content_ids=(content.content_id,),
        attributes={"action_fingerprint": fingerprint},
    )
    state.create_workflow(
        workflow,
        head_event_id=proposal_event.event_id,
        current_content_id=content.content_id,
    )
    boot = state.record_event(event_type="runtime_boot", correlation_id=f"{workflow}-boot")
    authorities = _authorities(state)
    execution = authorities[0]
    reconciliation = authorities[1]
    decision = execution.prepare_execution(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        workflow_id=workflow,
        expected_head_event_id=proposal_event.event_id,
        expected_revision=0,
        source_turn_event_id=turn.event_id,
        source_output_event_id=output.event_id,
        proposal_event_id=proposal_event.event_id,
        action=action,
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-contract-v1"),
        idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
        policy_config_digest=_digest("policy-v1"),
    )
    assert decision.intent_id is not None
    worker = execution.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY, boot_event_id=boot.event_id
    )
    dispatch = execution.begin_dispatch(
        execution.claim_execution(worker, decision.intent_id),
        action=action,
        destination_registry="local-test-registry",
        destination="fake-destination",
        destination_config_digest=_digest("fake-contract-v1"),
    )
    execution.mark_outcome_unknown(
        dispatch, destination_operation_id=f"{workflow}-external-operation"
    )
    return {
        "action": action,
        "boot": boot.event_id,
        "contract": _digest("fake-contract-v1"),
        "dispatch": dispatch,
        "execution": execution,
        "intent_id": decision.intent_id,
        "output": output.event_id,
        "proposal_event": proposal_event.event_id,
        "reconciliation": reconciliation,
        "turn": turn.event_id,
        "worker": worker,
        "workflow": workflow,
    }


def _terminal_reconciliation(live: dict[str, object], outcome: ExecutionState) -> None:
    reconciliation = live["reconciliation"]
    assert isinstance(reconciliation, ReconciliationAuthority)
    capability = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="hostile-review-operator",
        identity_class="HOST_OPERATOR",
    )
    current = reconciliation.begin_reconciliation(
        capability,
        str(live["intent_id"]),
        destination_contract_digest=str(live["contract"]),
    )
    assert current.reconciliation_id is not None
    category = (
        ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED
        if outcome is ExecutionState.COMPLETED
        else ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_NO_EFFECT
    )
    evidence = reconciliation.record_reconciliation_evidence(
        capability,
        current.reconciliation_id,
        category=category,
        evidence_digest=_digest(f"{live['workflow']}-{outcome.value}-evidence"),
        verification_mechanism="deterministic-hostile-test",
        verification_version="v1",
        destination_contract_digest=str(live["contract"]),
        external_operation_id=f"{live['workflow']}-external-operation",
    )
    propose = (
        reconciliation.propose_reconciliation_completed
        if outcome is ExecutionState.COMPLETED
        else reconciliation.propose_reconciliation_no_effect
    )
    proposal = propose(
        capability,
        current.reconciliation_id,
        evidence.evidence_id,
        destination_contract_digest=str(live["contract"]),
    )
    reconciliation.confirm_reconciliation_decision(
        capability,
        proposal.proposal_id,
        proposal_digest=proposal.proposal_digest,
        destination_contract_digest=str(live["contract"]),
    )


def test_duplicate_no_effect_confirmations_process_race_has_one_terminal_history(
    tmp_path: Path,
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_NO_EFFECT,
        )
        proposal = reconciliation.propose_reconciliation_no_effect(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_confirm_process,
            args=(
                str(tmp_path),
                proposal.proposal_id,
                proposal.proposal_digest,
                ids["contract"],
                gate,
                queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    assert sum(result[0] == "won" for result in results) == 1
    assert sum(result[0] == "lost" for result in results) == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, _ = _authorities(state)
        assert execution.get_intent(intent_id).state is ExecutionState.FAILED_NO_EFFECT
        state.verify_full()


def test_no_effect_confirmation_vs_abandonment_race_has_one_winner(
    tmp_path: Path,
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, no_effect = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_NO_EFFECT,
        )
        abandonment = reconciliation.record_reconciliation_evidence(
            decision,
            current.reconciliation_id or "",
            category=ReconciliationEvidenceCategory.ABANDONED,
            evidence_digest=_digest("no-effect-race-abandonment"),
            verification_mechanism="operator-decision",
            verification_version="v1",
            destination_contract_digest=ids["contract"],
            external_operation_id="external-operation-1",
        )
        proposal = reconciliation.propose_reconciliation_no_effect(
            decision,
            current.reconciliation_id or "",
            no_effect.evidence_id,
            destination_contract_digest=ids["contract"],
        )
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_confirm_process,
            args=(
                str(tmp_path),
                proposal.proposal_id,
                proposal.proposal_digest,
                ids["contract"],
                gate,
                queue,
            ),
        ),
        context.Process(
            target=_abandon_process,
            args=(
                str(tmp_path),
                current.reconciliation_id,
                abandonment.evidence_id,
                ids["contract"],
                gate,
                queue,
            ),
        ),
    ]
    for process in processes:
        process.start()
    gate.set()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    assert sum(result[0] == "won" for result in results) == 1
    assert sum(result[0] == "lost" for result in results) == 1
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, _ = _authorities(state)
        assert execution.get_intent(intent_id).state in {
            ExecutionState.FAILED_NO_EFFECT,
            ExecutionState.OUTCOME_UNKNOWN,
        }
        state.verify_full()


def test_late_original_completion_cannot_override_pending_reconciliation(
    tmp_path: Path,
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, "late-pending")
    reconciliation = live["reconciliation"]
    assert isinstance(reconciliation, ReconciliationAuthority)
    capability = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="pending-operator",
        identity_class="HOST_OPERATOR",
    )
    reconciliation.begin_reconciliation(
        capability,
        str(live["intent_id"]),
        destination_contract_digest=str(live["contract"]),
    )
    execution = live["execution"]
    assert isinstance(execution, ExecutionAuthority)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            live["dispatch"],  # type: ignore[arg-type]
            result_digest=_digest("late-pending-result"),
            destination_operation_id="late-pending-external-operation",
        )
    assert execution.get_intent(str(live["intent_id"])).state is ExecutionState.OUTCOME_UNKNOWN
    state.verify_full()
    state.close()


@pytest.mark.parametrize("outcome", [ExecutionState.COMPLETED, ExecutionState.FAILED_NO_EFFECT])
def test_late_original_completion_cannot_override_reconciled_terminal_truth(
    tmp_path: Path, outcome: ExecutionState
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, f"late-terminal-{outcome.value.lower()}")
    _terminal_reconciliation(live, outcome)
    execution = live["execution"]
    assert isinstance(execution, ExecutionAuthority)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            live["dispatch"],  # type: ignore[arg-type]
            result_digest=_digest("late-terminal-result"),
            destination_operation_id=f"{live['workflow']}-external-operation",
        )
    assert execution.get_intent(str(live["intent_id"])).state is outcome
    state.verify_full()
    state.close()


def test_late_original_completion_cannot_override_abandonment(
    tmp_path: Path,
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, "late-abandoned")
    reconciliation = live["reconciliation"]
    assert isinstance(reconciliation, ReconciliationAuthority)
    capability = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="abandonment-operator",
        identity_class="HOST_OPERATOR",
    )
    current = reconciliation.begin_reconciliation(
        capability,
        str(live["intent_id"]),
        destination_contract_digest=str(live["contract"]),
    )
    assert current.reconciliation_id is not None
    evidence = reconciliation.record_reconciliation_evidence(
        capability,
        current.reconciliation_id,
        category=ReconciliationEvidenceCategory.ABANDONED,
        evidence_digest=_digest("late-abandonment-evidence"),
        verification_mechanism="operator-decision",
        verification_version="v1",
        destination_contract_digest=str(live["contract"]),
        external_operation_id="late-abandoned-external-operation",
    )
    reconciliation.abandon_reconciliation(
        capability,
        current.reconciliation_id,
        evidence.evidence_id,
        destination_contract_digest=str(live["contract"]),
    )
    execution = live["execution"]
    assert isinstance(execution, ExecutionAuthority)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            live["dispatch"],  # type: ignore[arg-type]
            result_digest=_digest("late-abandoned-result"),
            destination_operation_id="late-abandoned-external-operation",
        )
    assert execution.get_intent(str(live["intent_id"])).state is ExecutionState.OUTCOME_UNKNOWN
    assert state.get_workflow("late-abandoned").status == "BLOCKED_UNKNOWN_ABANDONED"
    state.verify_full()
    state.close()


def test_original_dispatch_handle_is_rejected_after_restart(tmp_path: Path) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, "late-restart")
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        execution, _ = _authorities(reopened)
        with pytest.raises(ExecutionAuthorityError):
            execution.complete_execution(
                live["dispatch"],  # type: ignore[arg-type]
                result_digest=_digest("late-restart-result"),
                destination_operation_id="late-restart-external-operation",
            )
        assert execution.get_intent(str(live["intent_id"])).state is ExecutionState.OUTCOME_UNKNOWN
        reopened.verify_full()


def test_late_original_completion_rejected_after_new_reconciliation_generation(
    tmp_path: Path,
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, "late-generation")
    reconciliation = live["reconciliation"]
    assert isinstance(reconciliation, ReconciliationAuthority)
    capability = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="generation-operator",
        identity_class="HOST_OPERATOR",
    )
    first = reconciliation.begin_reconciliation(
        capability,
        str(live["intent_id"]),
        destination_contract_digest=str(live["contract"]),
    )
    assert first.reconciliation_id is not None
    reconciliation.record_reconciliation_evidence(
        capability,
        first.reconciliation_id,
        category=ReconciliationEvidenceCategory.CONFLICT,
        evidence_digest=_digest("late-generation-conflict"),
        verification_mechanism="deterministic-hostile-test",
        verification_version="v1",
        destination_contract_digest=str(live["contract"]),
        external_operation_id="late-generation-external-operation",
    )
    second = reconciliation.begin_reconciliation(
        capability,
        str(live["intent_id"]),
        destination_contract_digest=str(live["contract"]),
    )
    assert second.generation == first.generation + 1
    execution = live["execution"]
    assert isinstance(execution, ExecutionAuthority)
    with pytest.raises(ExecutionStateConflict):
        execution.complete_execution(
            live["dispatch"],  # type: ignore[arg-type]
            result_digest=_digest("late-generation-result"),
            destination_operation_id="late-generation-external-operation",
        )
    assert execution.get_intent(str(live["intent_id"])).state is ExecutionState.OUTCOME_UNKNOWN
    state.verify_full()
    state.close()


def test_reconciled_no_effect_grants_no_claim_dispatch_or_source_reuse(
    tmp_path: Path,
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, "no-effect-escape")
    _terminal_reconciliation(live, ExecutionState.FAILED_NO_EFFECT)
    execution = live["execution"]
    assert isinstance(execution, ExecutionAuthority)
    intent_id = str(live["intent_id"])
    with pytest.raises(ExecutionStateConflict):
        execution.claim_execution(live["worker"], intent_id)  # type: ignore[arg-type]
    replacement_worker = execution.register_worker(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        boot_event_id=str(live["boot"]),
    )
    with pytest.raises(ExecutionStateConflict):
        execution.claim_execution(replacement_worker, intent_id)
    with pytest.raises(ExecutionStateConflict):
        execution.begin_dispatch(
            live["dispatch"],  # type: ignore[arg-type]
            action=live["action"],  # type: ignore[arg-type]
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=str(live["contract"]),
        )
    try:
        replay = execution.prepare_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id="no-effect-escape",
            expected_head_event_id=str(live["proposal_event"]),
            expected_revision=0,
            source_turn_event_id=str(live["turn"]),
            source_output_event_id=str(live["output"]),
            proposal_event_id=str(live["proposal_event"]),
            action=live["action"],  # type: ignore[arg-type]
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=str(live["contract"]),
            idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
            policy_config_digest=_digest("policy-v1"),
        )
    except (ExecutionStateConflict, ExecutionBindingError):
        pass
    else:
        assert replay.intent_id == intent_id
    assert execution.get_intent(intent_id).state is ExecutionState.FAILED_NO_EFFECT
    state.verify_full()
    state.close()
    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    assert connection.execute("SELECT COUNT(*) FROM execution_intents").fetchone()[0] == 1
    connection.close()


@pytest.mark.parametrize(
    "terminal",
    [ExecutionState.COMPLETED, ExecutionState.FAILED_NO_EFFECT, "ABANDONED"],
)
def test_original_source_remains_consumed_after_reconciliation_disposition(
    tmp_path: Path, terminal: ExecutionState | str
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, f"consumed-{str(terminal).lower()}")
    if terminal == "ABANDONED":
        reconciliation = live["reconciliation"]
        assert isinstance(reconciliation, ReconciliationAuthority)
        capability = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="consumption-operator",
            identity_class="HOST_OPERATOR",
        )
        current = reconciliation.begin_reconciliation(
            capability,
            str(live["intent_id"]),
            destination_contract_digest=str(live["contract"]),
        )
        assert current.reconciliation_id is not None
        evidence = reconciliation.record_reconciliation_evidence(
            capability,
            current.reconciliation_id,
            category=ReconciliationEvidenceCategory.ABANDONED,
            evidence_digest=_digest("consumption-abandonment"),
            verification_mechanism="operator-decision",
            verification_version="v1",
            destination_contract_digest=str(live["contract"]),
            external_operation_id=f"{live['workflow']}-external-operation",
        )
        reconciliation.abandon_reconciliation(
            capability,
            current.reconciliation_id,
            evidence.evidence_id,
            destination_contract_digest=str(live["contract"]),
        )
    else:
        assert isinstance(terminal, ExecutionState)
        _terminal_reconciliation(live, terminal)
    execution = live["execution"]
    assert isinstance(execution, ExecutionAuthority)
    try:
        replay = execution.prepare_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=str(live["workflow"]),
            expected_head_event_id=str(live["proposal_event"]),
            expected_revision=0,
            source_turn_event_id=str(live["turn"]),
            source_output_event_id=str(live["output"]),
            proposal_event_id=str(live["proposal_event"]),
            action=live["action"],  # type: ignore[arg-type]
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=str(live["contract"]),
            idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
            policy_config_digest=_digest("policy-v1"),
        )
    except (ExecutionStateConflict, ExecutionBindingError):
        pass
    else:
        assert replay.intent_id == live["intent_id"]
    state.verify_full()
    state.close()
    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    assert connection.execute("SELECT COUNT(*) FROM execution_intents").fetchone()[0] == 1
    connection.close()


def test_evidence_cannot_cross_unknown_intents_or_operation_ids(
    tmp_path: Path,
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    first = _live_unknown(state, "evidence-first")
    second = _live_unknown(state, "evidence-second")
    _, reconciliation = _authorities(state)
    capability = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="evidence-operator",
        identity_class="HOST_OPERATOR",
    )
    first_current = reconciliation.begin_reconciliation(
        capability,
        str(first["intent_id"]),
        destination_contract_digest=str(first["contract"]),
    )
    second_current = reconciliation.begin_reconciliation(
        capability,
        str(second["intent_id"]),
        destination_contract_digest=str(second["contract"]),
    )
    assert first_current.reconciliation_id is not None
    assert second_current.reconciliation_id is not None
    first_evidence = reconciliation.record_reconciliation_evidence(
        capability,
        first_current.reconciliation_id,
        category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
        evidence_digest=_digest("first-only-evidence"),
        verification_mechanism="deterministic-hostile-test",
        verification_version="v1",
        destination_contract_digest=str(first["contract"]),
        external_operation_id="evidence-first-external-operation",
    )
    with pytest.raises(ExecutionBindingError):
        reconciliation.propose_reconciliation_completed(
            capability,
            second_current.reconciliation_id,
            first_evidence.evidence_id,
            destination_contract_digest=str(second["contract"]),
        )
    with pytest.raises(ExecutionBindingError):
        reconciliation.record_reconciliation_evidence(
            capability,
            second_current.reconciliation_id,
            category=ReconciliationEvidenceCategory.EXTERNALLY_VERIFIED_COMPLETED,
            evidence_digest=_digest("wrong-operation-evidence"),
            verification_mechanism="deterministic-hostile-test",
            verification_version="v1",
            destination_contract_digest=str(second["contract"]),
            external_operation_id="evidence-first-external-operation",
        )
    state.verify_full()
    state.close()


def test_exact_reconciliation_generation_bound_remains_unknown(
    tmp_path: Path,
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        capability = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="generation-bound-operator",
            identity_class="HOST_OPERATOR",
        )
        for generation in range(1, 33):
            current = reconciliation.begin_reconciliation(
                capability, intent_id, destination_contract_digest=ids["contract"]
            )
            assert current.generation == generation
            assert current.reconciliation_id is not None
            reconciliation.record_reconciliation_evidence(
                capability,
                current.reconciliation_id,
                category=ReconciliationEvidenceCategory.CONFLICT,
                evidence_digest=_digest(f"generation-bound-{generation}"),
                verification_mechanism="deterministic-hostile-test",
                verification_version="v1",
                destination_contract_digest=ids["contract"],
                external_operation_id="external-operation-1",
            )
        with pytest.raises(ExecutionStateConflict, match="bound"):
            reconciliation.begin_reconciliation(
                capability, intent_id, destination_contract_digest=ids["contract"]
            )
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN
        assert state.get_workflow(ids["workflow"]).status == "BLOCKED_UNKNOWN"
        state.verify_full()


def test_exact_evidence_bound_remains_unknown(tmp_path: Path) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        execution, reconciliation = _authorities(state)
        capability = reconciliation.issue_decision_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            identity="evidence-bound-operator",
            identity_class="HOST_OPERATOR",
        )
        current = reconciliation.begin_reconciliation(
            capability, intent_id, destination_contract_digest=ids["contract"]
        )
        assert current.reconciliation_id is not None
        for position in range(64):
            reconciliation.record_reconciliation_evidence(
                capability,
                current.reconciliation_id,
                category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
                evidence_digest=_digest(f"evidence-bound-{position}"),
                verification_mechanism="deterministic-hostile-test",
                verification_version="v1",
                destination_contract_digest=ids["contract"],
                external_operation_id="external-operation-1",
            )
        with pytest.raises(ExecutionStateConflict, match="bound"):
            reconciliation.record_reconciliation_evidence(
                capability,
                current.reconciliation_id,
                category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
                evidence_digest=_digest("evidence-bound-overflow"),
                verification_mechanism="deterministic-hostile-test",
                verification_version="v1",
                destination_contract_digest=ids["contract"],
                external_operation_id="external-operation-1",
            )
        assert execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN
        assert state.get_workflow(ids["workflow"]).status == "BLOCKED_UNKNOWN"
        state.verify_full()


def test_confirmation_rejects_stale_or_unauthenticated_workflow_barrier(
    tmp_path: Path,
) -> None:
    ids, intent_id = _unknown(tmp_path)
    with PersistentSecurityState.open(_config(tmp_path)) as state:
        _, reconciliation = _authorities(state)
        decision, current, evidence = _begin_and_evidence(
            reconciliation,
            intent_id,
            ids["contract"],
            category=ReconciliationEvidenceCategory.OPERATOR_VERIFIED_COMPLETED,
        )
        proposal = reconciliation.propose_reconciliation_completed(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
        connection = sqlite3.connect(tmp_path / "authority.sqlite3")
        connection.execute(
            "UPDATE execution_workflow_barriers "
            "SET expected_revision=expected_revision+1 WHERE workflow_id=?",
            (ids["workflow"],),
        )
        connection.commit()
        connection.close()
        with pytest.raises(StateAuthenticationError):
            reconciliation.confirm_reconciliation_decision(
                decision,
                proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                destination_contract_digest=ids["contract"],
            )


def _abandon_live_unknown(live: dict[str, object]) -> None:
    reconciliation = live["reconciliation"]
    assert isinstance(reconciliation, ReconciliationAuthority)
    capability = reconciliation.issue_decision_capability(
        _HOST_EXECUTION_AUTHORITY_CAPABILITY,
        identity="restart-abandonment-operator",
        identity_class="HOST_OPERATOR",
    )
    current = reconciliation.begin_reconciliation(
        capability,
        str(live["intent_id"]),
        destination_contract_digest=str(live["contract"]),
    )
    assert current.reconciliation_id is not None
    evidence = reconciliation.record_reconciliation_evidence(
        capability,
        current.reconciliation_id,
        category=ReconciliationEvidenceCategory.ABANDONED,
        evidence_digest=_digest(f"{live['workflow']}-restart-abandonment"),
        verification_mechanism="operator-decision",
        verification_version="v1",
        destination_contract_digest=str(live["contract"]),
        external_operation_id=f"{live['workflow']}-external-operation",
    )
    reconciliation.abandon_reconciliation(
        capability,
        current.reconciliation_id,
        evidence.evidence_id,
        destination_contract_digest=str(live["contract"]),
    )


def _attempt_original_source_reuse(
    execution: ExecutionAuthority,
    live: dict[str, object],
    *,
    policy_config_digest: str,
) -> None:
    try:
        replay = execution.prepare_execution(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            workflow_id=str(live["workflow"]),
            expected_head_event_id=str(live["proposal_event"]),
            expected_revision=0,
            source_turn_event_id=str(live["turn"]),
            source_output_event_id=str(live["output"]),
            proposal_event_id=str(live["proposal_event"]),
            action=live["action"],  # type: ignore[arg-type]
            destination_registry="local-test-registry",
            destination="fake-destination",
            destination_config_digest=str(live["contract"]),
            idempotency_class=IdempotencyClass.NO_IDEMPOTENCY,
            policy_config_digest=policy_config_digest,
        )
    except (ExecutionStateConflict, ExecutionBindingError):
        return
    assert replay.intent_id == live["intent_id"]


@pytest.mark.parametrize(
    "disposition",
    [ExecutionState.COMPLETED, ExecutionState.FAILED_NO_EFFECT, "ABANDONED"],
)
def test_original_source_and_execution_authority_remain_consumed_after_restart(
    tmp_path: Path, disposition: ExecutionState | str
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, f"restart-consumed-{str(disposition).lower()}")
    if disposition == "ABANDONED":
        _abandon_live_unknown(live)
    else:
        assert isinstance(disposition, ExecutionState)
        _terminal_reconciliation(live, disposition)
    state.verify_full()
    state.close()

    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        restart_boot = reopened.record_event(
            event_type="runtime_boot",
            correlation_id=f"{live['workflow']}-restart-boot",
        )
        execution, reconciliation = _authorities(reopened)
        replacement_worker = execution.register_worker(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY,
            boot_event_id=restart_boot.event_id,
        )
        with pytest.raises(ExecutionStateConflict):
            execution.claim_execution(replacement_worker, str(live["intent_id"]))
        _attempt_original_source_reuse(
            execution,
            live,
            policy_config_digest=_digest("policy-v1"),
        )
        _attempt_original_source_reuse(
            execution,
            live,
            policy_config_digest=_digest("post-restart-loosened-policy"),
        )
        if disposition == "ABANDONED":
            decision = reconciliation.issue_decision_capability(
                _HOST_EXECUTION_AUTHORITY_CAPABILITY,
                identity="restart-abandonment-reviewer",
                identity_class="HOST_OPERATOR",
            )
            with pytest.raises(ExecutionStateConflict):
                reconciliation.begin_reconciliation(
                    decision,
                    str(live["intent_id"]),
                    destination_contract_digest=str(live["contract"]),
                )
            assert (
                execution.get_intent(str(live["intent_id"])).state is ExecutionState.OUTCOME_UNKNOWN
            )
            assert (
                reopened.get_workflow(str(live["workflow"])).status == "BLOCKED_UNKNOWN_ABANDONED"
            )
        else:
            assert execution.get_intent(str(live["intent_id"])).state is disposition
            assert reopened.get_workflow(str(live["workflow"])).status == "ACTIVE"
        reopened.verify_full()

    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    assert connection.execute("SELECT COUNT(*) FROM execution_intents").fetchone()[0] == 1
    connection.close()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE workflow_state SET status='ACTIVE'",
        "UPDATE execution_workflow_barriers SET status='ACTIVE'",
        "UPDATE execution_workflow_barriers SET active_intent_id=NULL",
        "UPDATE execution_intents SET state='CANCELLED'",
        "UPDATE execution_intents SET state='COMPLETED'",
        "UPDATE execution_intents SET state='FAILED_NO_EFFECT'",
    ],
)
def test_abandonment_cannot_be_reinterpreted_by_workflow_or_intent_mutation(
    tmp_path: Path, statement: str
) -> None:
    state = PersistentSecurityState.initialize(_config(tmp_path))
    live = _live_unknown(state, "abandonment-mutation")
    _abandon_live_unknown(live)
    state.verify_full()
    state.close()
    connection = sqlite3.connect(tmp_path / "authority.sqlite3")
    connection.execute(statement)
    connection.commit()
    connection.close()
    with pytest.raises((StateAuthenticationError, StateVerificationError)):
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
def test_abandonment_anchor_crash_is_all_or_nothing(
    tmp_path: Path, point: str, committed: bool
) -> None:
    ids, intent_id = _unknown(tmp_path)
    state = PersistentSecurityState.open(_config(tmp_path))
    _execution, reconciliation = _authorities(state)
    decision, current, evidence = _begin_and_evidence(
        reconciliation,
        intent_id,
        ids["contract"],
        category=ReconciliationEvidenceCategory.ABANDONED,
    )

    def fail(seen: str) -> None:
        if seen == point:
            raise RuntimeError(point)

    state._set_failure_injector_for_testing(fail)
    with pytest.raises(RuntimeError, match=point):
        reconciliation.abandon_reconciliation(
            decision,
            current.reconciliation_id or "",
            evidence.evidence_id,
            destination_contract_digest=ids["contract"],
        )
    state.close()
    with PersistentSecurityState.open(_config(tmp_path)) as reopened:
        reopened_execution, reopened_reconciliation = _authorities(reopened)
        inspection = reopened_reconciliation.issue_inspection_capability(
            _HOST_EXECUTION_AUTHORITY_CAPABILITY
        )
        current_state = reopened_reconciliation.inspect_execution(inspection, intent_id)
        assert reopened_execution.get_intent(intent_id).state is ExecutionState.OUTCOME_UNKNOWN
        assert reopened.get_workflow(ids["workflow"]).status == (
            "BLOCKED_UNKNOWN_ABANDONED" if committed else "BLOCKED_UNKNOWN"
        )
        assert current_state.disposition is (
            ReconciliationDisposition.ABANDONED if committed else ReconciliationDisposition.ACTIVE
        )
        reopened.verify_full()
