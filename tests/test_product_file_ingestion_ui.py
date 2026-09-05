from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from secureinjections.file_ingestion import ProductFileIngestor
from secureinjections.guard import Guard
from secureinjections.service import create_app


def _client(tmp_path: Path) -> TestClient:
    ingestor = ProductFileIngestor(tmp_path / "uploads", guard=Guard())
    return TestClient(create_app(guard=Guard(), file_ingestor=ingestor))


def test_product_page_contains_file_selection_and_all_result_states(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    for copy in (
        "Choose a file",
        "drag and drop",
        "Inspecting file",
        "File inspected and ready",
        "Advanced details",
    ):
        assert copy in response.text


def test_ui_script_has_allow_review_block_malformed_and_stale_request_handling(
    tmp_path: Path,
) -> None:
    response = _client(tmp_path).get("/assets/file-ingestion.js")
    script = response.text
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert '["ALLOW", "REVIEW", "BLOCK"]' in script
    assert "malformed inspection result" in script
    assert "generation !== requestGeneration" in script
    assert 'showView("loading-view")' in script
    assert "textContent" in script
    assert "innerHTML" not in script


def test_ui_offers_only_the_real_safe_reference_agent_handoff(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/")
    script = _client(tmp_path).get("/assets/file-ingestion.js").text
    assert "Use in agent" in response.text
    assert 'fetch("/v1/agent/run"' in script
    assert "safe_reference: reference" in script
    assert "body: file" not in script.split('fetch("/v1/agent/run"', 1)[1]
    assert "The safe reference lasts for this product session" in response.text
    assert "malformed guarded-agent result" in script
    assert "payload.response !== null" in script
    assert "Test connection" in script
