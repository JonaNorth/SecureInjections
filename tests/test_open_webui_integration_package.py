from __future__ import annotations

import copy
import json
import signal
import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

from secureinjections.community_cli import main
from secureinjections.integrations.open_webui import (
    INTEGRATION_CLASS,
    INTEGRATION_IDENTITY,
    SMOKE_SCHEMA_VERSION,
    IntegrationProfileError,
    IntegrationSmokeError,
    OpenWebUIIntegrationProfile,
    OwnedProcess,
    _allocate_loopback_port,
    _assert_port_available,
    _start_open_webui,
    integration_status,
    run_open_webui_smoke,
    validate_open_webui_smoke_report,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/integrations/open-webui.yaml"


def _profile_data() -> dict[str, Any]:
    loaded = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_profile(tmp_path: Path, data: dict[str, Any] | None = None) -> Path:
    profile = tmp_path / "open-webui.yaml"
    value = copy.deepcopy(data or _profile_data())
    value["proxy"]["config"] = str(ROOT / "examples/secureinjections.proxy.yaml")
    profile.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return profile


def _passing_report() -> dict[str, Any]:
    scenarios = []
    for identifier in (
        "benign-ordinary",
        "benign-quoted-security",
        "adversarial-direct-injection",
        "adversarial-poisoned-tool",
        "downstream-unsafe-tool",
    ):
        scenarios.append(
            {
                "id": identifier,
                "outcome": "PASS",
                "actual_guard_decision": "ALLOW" if identifier.startswith("benign") else "BLOCK",
                "upstream_reached": identifier.startswith("benign")
                or identifier.startswith("downstream"),
                "downstream_released": identifier.startswith("benign"),
                "audit_correlation_id": f"proxy-run-{identifier}",
            }
        )
    return {
        "schema_version": SMOKE_SCHEMA_VERSION,
        "integration": {
            "identity": INTEGRATION_IDENTITY,
            "open_webui_version": "0.11.0",
            "integration_class": INTEGRATION_CLASS,
        },
        "topology": {
            "classification": "loopback-only",
            "enforcement_mode": "ENFORCE",
            "streaming": "OFF",
            "native_ollama_provider": "DISABLED",
        },
        "source_integrity": {"modified_by_secureinjections": False},
        "scenarios": scenarios,
        "bypass": {
            "evaluated_model_requests": 5,
            "proxy_observed_requests": 5,
            "unexpected_direct_bypasses": 0,
        },
        "privacy": {"raw_content_logging": False},
        "safety": {
            "unsafe_passed": 0,
            "external_transfer": False,
            "shell_execution": False,
            "model_download": False,
            "cloud_model_api": False,
            "existing_user_process_terminated": False,
        },
    }


def test_official_profile_is_exact_hash_bound_and_loopback() -> None:
    first = OpenWebUIIntegrationProfile.from_path(EXAMPLE)
    second = OpenWebUIIntegrationProfile.from_path(EXAMPLE)

    assert first.integration_hash == second.integration_hash
    assert first.expected_version == "0.11.0"
    assert first.open_webui_host == "127.0.0.1"
    assert first.open_webui_port == 0
    assert first.proxy_port == 0
    assert first.expected_proxy_mode == "ENFORCE"
    assert first.upstream_base_url == "http://127.0.0.1:11434/v1"
    assert first.fixtures[-1] == "downstream-unsafe-tool"


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    (
        ("open_webui", "expected_version", "0.12.0", "0.11.0 exactly"),
        ("open_webui", "host", "0.0.0.0", "loopback"),
        ("open_webui", "streaming_required_off", False, "must be true"),
        ("proxy", "expected_mode", "OBSERVE", "must be ENFORCE"),
        ("upstream", "base_url", "https://api.openai.com/v1", "loopback"),
    ),
)
def test_profile_fails_closed_for_unsupported_contract(
    tmp_path: Path, section: str, key: str, value: Any, message: str
) -> None:
    data = _profile_data()
    data[section][key] = value
    with pytest.raises(IntegrationProfileError, match=message):
        OpenWebUIIntegrationProfile.from_path(_write_profile(tmp_path, data))


def test_registry_and_cli_status_are_static(capsys: pytest.CaptureFixture[str]) -> None:
    report = integration_status()
    integration = report["integrations"][0]
    assert integration["identity"] == INTEGRATION_IDENTITY
    assert integration["validated_versions"] == ["0.11.0"]
    assert integration["status"] == "VALIDATED_LIMITED_LOCAL"

    assert main(["integrations"]) == 0
    output = capsys.readouterr().out
    assert "VALIDATED — LIMITED LOCAL INTEGRATION" in output
    assert "0.11.0" in output


def test_ephemeral_port_is_loopback_and_available() -> None:
    port = _allocate_loopback_port()
    assert 1 <= port <= 65_535
    _assert_port_available("127.0.0.1", port)


def test_port_collision_preserves_existing_listener() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = int(listener.getsockname()[1])
    try:
        with pytest.raises(IntegrationSmokeError, match="occupied"):
            _assert_port_available("127.0.0.1", port)
        assert listener.getsockname()[1] == port
    finally:
        listener.close()


class _FakeProcess:
    pid = 43210

    def __init__(self) -> None:
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float) -> int:
        del timeout
        assert self.returncode is not None
        return self.returncode


def test_owned_process_terminates_only_its_recorded_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    calls: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr("secureinjections.integrations.open_webui.os.getpgid", lambda pid: pid)

    def killpg(pid: int, sent_signal: signal.Signals) -> None:
        calls.append((pid, sent_signal))
        process.returncode = 0

    monkeypatch.setattr("secureinjections.integrations.open_webui.os.killpg", killpg)
    owned = OwnedProcess(  # type: ignore[arg-type]
        process,
        "fixture",
        12345,
        "smoke-owned-fixture",
        "2026-08-24T00:00:00Z",
    )
    owned.terminate()

    assert calls == [(process.pid, signal.SIGTERM)]
    assert owned.to_dict()["owned_by_smoke"] is True


def test_open_webui_process_uses_isolated_data_directory_as_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "venv/bin/open-webui"
    executable.parent.mkdir(parents=True)
    executable.touch()
    data_directory = tmp_path / "isolated-data"
    captured: dict[str, Any] = {}

    class FakePopen:
        pid = 43211

        def __init__(self, command: list[str], **kwargs: Any) -> None:
            captured.update({"command": command, **kwargs})

    monkeypatch.setattr("secureinjections.integrations.open_webui.subprocess.Popen", FakePopen)
    owned = _start_open_webui(
        executable,
        host="127.0.0.1",
        port=12345,
        data_directory=data_directory,
        proxy_port=12346,
        timeout_seconds=30,
        log_path=tmp_path / "open-webui.log",
    )

    assert owned.process.pid == 43211
    assert captured["cwd"] == data_directory
    assert captured["env"]["DATA_DIR"] == str(data_directory)
    assert not (tmp_path / ".webui_secret_key").exists()


def test_smoke_artifact_pass_contract_covers_benign_attack_bypass_and_privacy() -> None:
    report = _passing_report()
    accepted, failures = validate_open_webui_smoke_report(report)

    assert accepted is True
    assert failures == []
    scenarios = {item["id"]: item for item in report["scenarios"]}
    assert scenarios["benign-ordinary"]["downstream_released"] is True
    assert scenarios["benign-quoted-security"]["actual_guard_decision"] == "ALLOW"
    assert scenarios["adversarial-direct-injection"]["downstream_released"] is False
    assert scenarios["adversarial-poisoned-tool"]["upstream_reached"] is False
    assert scenarios["downstream-unsafe-tool"]["downstream_released"] is False


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    (
        (("integration", "open_webui_version"), "0.12.0", "OPEN_WEBUI_VERSION"),
        (("topology", "streaming"), "ON", "STREAMING"),
        (("topology", "classification"), "public", "LOOPBACK_TOPOLOGY"),
        (("source_integrity", "modified_by_secureinjections"), True, "SOURCE_INTEGRITY"),
        (("bypass", "unexpected_direct_bypasses"), 1, "BYPASS_ACCOUNTING"),
        (("privacy", "raw_content_logging"), True, "RAW_LOGGING"),
        (("safety", "unsafe_passed"), 1, "SAFETY"),
    ),
)
def test_smoke_acceptance_fails_closed(path: tuple[str, str], value: Any, reason: str) -> None:
    report = _passing_report()
    report[path[0]][path[1]] = value

    accepted, failures = validate_open_webui_smoke_report(report)

    assert accepted is False
    assert reason in failures


def test_missing_open_webui_prerequisite_writes_safe_failure_artifact(tmp_path: Path) -> None:
    profile = OpenWebUIIntegrationProfile.from_path(_write_profile(tmp_path))
    output = tmp_path / "smoke.json"

    report = run_open_webui_smoke(
        profile,
        output=output,
        open_webui_executable=str(tmp_path / "missing-open-webui"),
    )

    assert report["result"] == "FAIL"
    assert report["failure"]["error_type"] == "IntegrationSmokeError"
    assert report["cleanup"] == []
    assert json.loads(output.read_text(encoding="utf-8")) == report
