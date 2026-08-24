"""Optional FastAPI scanning service."""

from typing import Any

from .detectors.semantic import KeywordSemanticDetector
from .guard import Guard, InspectionRequest
from .scanner import Scanner
from .version import ENGINE_VERSION


def create_app(scanner: Scanner | None = None, guard: Guard | None = None) -> Any:
    try:
        from fastapi import FastAPI
        from pydantic import BaseModel, Field
    except ImportError as exc:  # pragma: no cover - exercised without optional dependency
        raise RuntimeError("Install secureinjections[service] to use the HTTP service") from exc

    active_scanner = scanner or Scanner(semantic_detector=KeywordSemanticDetector())
    active_guard = guard or Guard()
    app = FastAPI(title="SecureInjections", version=ENGINE_VERSION)

    class ScanRequest(BaseModel):
        text: str = Field(max_length=active_scanner.config.max_input_length)
        deep_scan: bool = False

    class GuardInspectRequest(BaseModel):
        content: str = Field(max_length=1_000_000)
        source: str
        destination: str
        context: dict[str, Any] = Field(default_factory=dict)
        dry_run: bool = False

    @app.post("/scan")
    def scan(request: ScanRequest) -> dict[str, Any]:
        result = active_scanner.scan(request.text, deep_scan=request.deep_scan)
        return {
            "decision": result.decision.value,
            "risk_score": result.risk_score,
            "categories": list(result.detected_categories),
            "matches": [match.to_dict() for match in result.matched_rules],
            "explanation": result.explanation,
            "scan_duration_ms": result.scan_duration_ms,
        }

    @app.post("/v1/inspect")
    def inspect(request: GuardInspectRequest) -> dict[str, Any]:
        result = active_guard.inspect(
            InspectionRequest(
                content=request.content,
                source=request.source,
                destination=request.destination,
                context=request.context,
            ),
            dry_run=request.dry_run,
        )
        return result.to_dict()

    return app


app = create_app()
