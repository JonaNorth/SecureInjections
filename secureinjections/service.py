"""Optional FastAPI scanning and safe-file-ingestion service."""

import hmac
import os
import secrets
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import Any

from .detectors.semantic import KeywordSemanticDetector
from .file_ingestion import FileIngestionError, ProductFileIngestor, error_payload
from .guard import Guard, InspectionRequest
from .product_agent import ProductAgentError, ProductAgentRuntime, product_agent_error_payload
from .product_protection import (
    ProductProtectionState,
    ProductRuntimeConfig,
    ProductRuntimeError,
)
from .product_runtime import ProductInstallation
from .scanner import Scanner
from .version import ENGINE_VERSION


def create_app(
    scanner: Scanner | None = None,
    guard: Guard | None = None,
    file_ingestor: ProductFileIngestor | None = None,
    runtime_config: ProductRuntimeConfig | None = None,
    protection_state: ProductProtectionState | None = None,
    product_agent: ProductAgentRuntime | None = None,
    installation: ProductInstallation | None = None,
) -> Any:
    try:
        from fastapi import FastAPI, Request
        from pydantic import BaseModel, Field
        from starlette.responses import HTMLResponse, JSONResponse, Response
    except ImportError as exc:  # pragma: no cover - exercised without optional dependency
        raise RuntimeError("Install secureinjections[service] to use the HTTP service") from exc

    active_scanner = scanner or Scanner(semantic_detector=KeywordSemanticDetector())
    configured_upload_root = runtime_config.file_ingest_root if runtime_config else None
    active_guard = guard
    if file_ingestor is None:
        upload_root = configured_upload_root or _default_upload_root()
        active_guard = active_guard or Guard(audit_path=upload_root / "audit.jsonl")
        active_file_ingestor = ProductFileIngestor(upload_root, guard=active_guard)
    else:
        active_file_ingestor = file_ingestor
        active_guard = active_guard or file_ingestor.guard
    app = FastAPI(title="SecureInjections Community", version=ENGINE_VERSION)
    app.state.file_ingestor = active_file_ingestor
    config = runtime_config or ProductRuntimeConfig.from_environment(
        activity_path=upload_root / "product-activity.jsonl"
        if file_ingestor is None
        else active_file_ingestor.upload_root / "product-activity.jsonl"
    )
    active_protection = protection_state or ProductProtectionState(config, active_guard)
    active_agent = product_agent or ProductAgentRuntime(config.local_profile, active_file_ingestor)
    product_session_secret = secrets.token_urlsafe(32)
    configured_host = (
        f"[{config.listen_host}]" if config.listen_host == "::1" else config.listen_host
    )
    product_origin = f"http://{configured_host}:{config.listen_port}"
    app.state.protection_state = active_protection

    class ScanRequest(BaseModel):
        text: str = Field(max_length=active_scanner.config.max_input_length)
        deep_scan: bool = False

    class GuardInspectRequest(BaseModel):
        content: str = Field(max_length=1_000_000)
        source: str
        destination: str
        context: dict[str, Any] = Field(default_factory=dict)
        dry_run: bool = False

    class ProductAgentRequest(BaseModel):
        prompt: str = Field(min_length=1, max_length=64_000)
        safe_reference: str | None = Field(default=None, max_length=200)

    class OnboardingRequest(BaseModel):
        completed: bool

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
        if not request.dry_run:
            active_protection.record_activity(
                surface=_inspection_surface(request.source, request.destination),
                decision=result.decision.value,
                reason=result.policy.reason_code,
                correlation_id=request.context.get("request_id"),
                audit_reference=result.audit_id,
            )
        return result.to_dict()

    @app.get("/v1/protection/status")
    def protection_status() -> dict[str, Any]:
        return active_protection.status()

    @app.get("/v1/activity")
    def protection_activity(limit: int = 50) -> dict[str, Any]:
        return active_protection.activity(limit=limit)

    @app.get("/v1/product/doctor")
    def product_doctor() -> dict[str, Any]:
        if installation is None:
            return {
                "schema_version": "secureinjections-product-doctor-v0.1",
                "result": "WARN",
                "supported_platform": "macOS Apple Silicon",
                "checks": [],
                "cloud_calls_performed": False,
                "raw_content_retained": False,
                "message": "Installed-product readiness is unavailable in developer mode.",
            }
        return installation.doctor()

    @app.get("/v1/product/onboarding")
    def product_onboarding() -> dict[str, Any]:
        if installation is None:
            return {
                "schema_version": "secureinjections-onboarding-state-v0.1",
                "completed": True,
                "completed_at": None,
                "product_version": ENGINE_VERSION,
                "state_classification": "DEVELOPER_MODE_NOT_AUTHORITY",
                "error": None,
            }
        return installation.onboarding()

    @app.post("/v1/product/onboarding/complete")
    def complete_product_onboarding(
        onboarding_request: OnboardingRequest, request: Request
    ) -> Response:
        denied = _mutation_denied(request, product_session_secret, product_origin)
        if denied is not None:
            return JSONResponse(denied, status_code=403)
        if installation is None or onboarding_request.completed is not True:
            return JSONResponse(
                _product_action_error("Onboarding completion is unavailable."), status_code=409
            )
        return JSONResponse(installation.write_onboarding(completed=True))

    @app.post("/v1/integrations/guard-proxy/start")
    def start_guard_proxy(request: Request) -> Response:
        denied = _mutation_denied(request, product_session_secret, product_origin)
        if denied is not None:
            return JSONResponse(denied, status_code=403)
        try:
            state = active_protection.proxy_lifecycle.start()
        except ProductRuntimeError as error:
            return JSONResponse(_product_action_error(str(error)), status_code=error.status_code)
        active_protection.record_activity(
            surface="ai_traffic",
            decision="ALLOW",
            reason="GUARD_PROXY_STARTED",
            correlation_id=None,
            audit_reference=None,
        )
        return JSONResponse({"schema_version": "guard-proxy-action-v0.1", **state})

    @app.post("/v1/integrations/guard-proxy/stop")
    def stop_guard_proxy(request: Request) -> Response:
        denied = _mutation_denied(request, product_session_secret, product_origin)
        if denied is not None:
            return JSONResponse(denied, status_code=403)
        try:
            state = active_protection.proxy_lifecycle.stop()
        except ProductRuntimeError as error:
            return JSONResponse(_product_action_error(str(error)), status_code=error.status_code)
        active_protection.record_activity(
            surface="ai_traffic",
            decision="ALLOW",
            reason="GUARD_PROXY_STOPPED",
            correlation_id=None,
            audit_reference=None,
        )
        return JSONResponse({"schema_version": "guard-proxy-action-v0.1", **state})

    @app.get("/v1/agent/capabilities")
    def product_agent_capabilities() -> dict[str, Any]:
        return active_agent.capabilities()

    @app.post("/v1/agent/run")
    def run_product_agent(agent_request: ProductAgentRequest, request: Request) -> Response:
        denied = _mutation_denied(request, product_session_secret, product_origin)
        if denied is not None:
            return JSONResponse(denied, status_code=403)
        try:
            payload = active_agent.run(
                agent_request.prompt, safe_reference=agent_request.safe_reference
            )
        except ProductAgentError as error:
            return JSONResponse(product_agent_error_payload(error), status_code=error.status_code)
        if payload["file_handoff"]["used"]:
            active_protection.record_activity(
                surface="files",
                decision="ALLOW",
                reason="SAFE_FILE_HANDOFF",
                correlation_id=payload["workflow_id"],
                audit_reference=payload["audit"]["session_record_hash"],
            )
        return JSONResponse(payload)

    @app.get("/v1/files/capabilities")
    def file_capabilities() -> dict[str, Any]:
        return active_file_ingestor.capabilities()

    @app.post("/v1/files/ingest")
    async def ingest_file(request: Request) -> Response:
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
            != "application/octet-stream"
        ):
            error = FileIngestionError(
                "UNSUPPORTED_MEDIA_TYPE",
                "Send the file as an application/octet-stream body.",
                status_code=415,
            )
            return JSONResponse(error_payload(error), status_code=error.status_code)
        encoded_filename = request.headers.get("x-secureinjections-filename", "")
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = -1
            if declared_size < 0:
                error = FileIngestionError("INVALID_SIZE", "The upload size is invalid.")
                return JSONResponse(error_payload(error), status_code=error.status_code)
            if declared_size > active_file_ingestor.max_file_size:
                error = FileIngestionError(
                    "FILE_TOO_LARGE",
                    f"The file exceeds the {active_file_ingestor.max_file_size:,}-byte limit.",
                    status_code=413,
                )
                return JSONResponse(error_payload(error), status_code=error.status_code)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > active_file_ingestor.max_file_size:
                error = FileIngestionError(
                    "FILE_TOO_LARGE",
                    f"The file exceeds the {active_file_ingestor.max_file_size:,}-byte limit.",
                    status_code=413,
                )
                return JSONResponse(error_payload(error), status_code=error.status_code)
            body.extend(chunk)
        try:
            payload = active_file_ingestor.ingest(encoded_filename, bytes(body))
            active_protection.record_activity(
                surface="files",
                decision=payload["decision"],
                reason=payload["reason_code"],
                correlation_id=payload["correlation_id"],
                audit_reference=payload["audit"]["boundary_audit_id"],
            )
            return JSONResponse(payload)
        except FileIngestionError as error:
            return JSONResponse(error_payload(error), status_code=error.status_code)

    @app.get("/", response_class=HTMLResponse)
    def product_ui(response: Response) -> str:
        response.set_cookie(
            "secureinjections_product_session",
            product_session_secret,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
        )
        return _product_asset("index.html")

    @app.get("/assets/file-ingestion.js")
    def product_javascript() -> Response:
        return Response(
            _product_asset("file-ingestion.js"),
            media_type="text/javascript",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/assets/file-ingestion.css")
    def product_styles() -> Response:
        return Response(
            _product_asset("file-ingestion.css"),
            media_type="text/css",
            headers={"Cache-Control": "no-store"},
        )

    @app.on_event("shutdown")
    def stop_owned_runtime() -> None:
        active_protection.proxy_lifecycle.close()

    return app


def _default_upload_root() -> Path:
    configured = os.environ.get("SECUREINJECTIONS_FILE_INGEST_ROOT")
    user_identifier = str(os.getuid()) if hasattr(os, "getuid") else "current-user"
    upload_root = (
        Path(configured)
        if configured
        else Path(tempfile.gettempdir()) / f"secureinjections-file-ingest-{user_identifier}"
    )
    upload_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return upload_root


def _product_asset(name: str) -> str:
    return files("secureinjections.product_ui").joinpath(name).read_text(encoding="utf-8")


app = create_app()


def _inspection_surface(source: str, destination: str) -> str:
    if source == "file":
        return "files"
    if "memory" in {source, destination}:
        return "memory"
    if destination == "tool" or source in {"tool_input", "tool_output"}:
        return "tool_actions"
    if destination == "external" or source == "external":
        return "external_actions"
    return "ai_traffic"


def _mutation_denied(
    request: Any, session_secret: str, product_origin: str
) -> dict[str, Any] | None:
    origin = request.headers.get("origin")
    supplied = request.cookies.get("secureinjections_product_session", "")
    if origin != product_origin or not hmac.compare_digest(supplied, session_secret):
        return _product_action_error(
            "This action requires the current same-origin product session."
        )
    return None


def _product_action_error(message: str) -> dict[str, Any]:
    return {
        "schema_version": "product-action-error-v0.1",
        "error": {"code": "ACTION_NOT_AUTHORIZED", "message": message},
    }
