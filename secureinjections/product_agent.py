"""Session-scoped safe-file handoff to the existing guarded local agent."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .file_ingestion import ProductFileIngestor
from .local_agent import AgentRunStatus, LocalAgentModel
from .local_profile import (
    LocalGuardProfile,
    LocalProfileError,
    ProfileAgentRun,
    run_profile_agent,
)

PRODUCT_AGENT_SCHEMA = "product-guarded-agent-run-v0.1"


class ProductAgentError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


ModelFactory = Callable[[LocalGuardProfile], LocalAgentModel]


class ProductAgentRuntime:
    """Resolve host-held file references and run one bounded guarded-agent request."""

    def __init__(
        self,
        profile_path: Path | None,
        file_ingestor: ProductFileIngestor,
        *,
        model_factory: ModelFactory | None = None,
    ) -> None:
        self.profile_path = profile_path
        self.file_ingestor = file_ingestor
        self._model_factory = model_factory

    def capabilities(self) -> dict[str, Any]:
        profile, error = self._profile()
        return {
            "schema_version": "product-guarded-agent-capabilities-v0.1",
            "available": profile is not None,
            "provider": profile.runtime.provider if profile is not None else None,
            "model": profile.runtime.model if profile is not None else None,
            "safe_file_handoff": profile is not None,
            "reference_lifetime": "product-session",
            "review_approval_available": False,
            "message": error,
        }

    def run(self, prompt: str, *, safe_reference: str | None = None) -> dict[str, Any]:
        if not prompt or len(prompt.encode("utf-8")) > 64_000:
            raise ProductAgentError(
                "INVALID_PROMPT", "Enter a prompt up to 64,000 bytes.", status_code=400
            )
        profile, error = self._profile()
        if profile is None:
            raise ProductAgentError(
                "AGENT_NOT_CONFIGURED",
                error or "Configure a native Ollama guarded-agent profile first.",
                status_code=409,
            )
        envelope = None
        if safe_reference is not None:
            if not safe_reference or len(safe_reference) > 200:
                raise ProductAgentError(
                    "INVALID_SAFE_REFERENCE", "The safe file reference is invalid.", status_code=400
                )
            envelope = self.file_ingestor.resolve_safe_reference(safe_reference)
            if envelope is None:
                raise ProductAgentError(
                    "SAFE_REFERENCE_EXPIRED",
                    "The safe file reference expired or does not belong to this product session.",
                    status_code=410,
                )
        try:
            model = self._model_factory(profile) if self._model_factory is not None else None
            run = run_profile_agent(
                profile,
                prompt,
                model=model,
                safe_file_envelopes=(envelope,) if envelope is not None else (),
            )
        except (LocalProfileError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ProductAgentError(
                "AGENT_PROVIDER_UNAVAILABLE",
                f"The configured local agent failed safely ({type(exc).__name__}).",
                status_code=503,
            ) from exc
        attached = envelope is not None and run.result.stopped_at != "ingress"
        return _run_payload(
            run,
            safe_reference=envelope.content_id if envelope is not None else None,
            file_attached=attached,
        )

    def _profile(self) -> tuple[LocalGuardProfile | None, str | None]:
        if self.profile_path is None:
            return None, "A local guarded-agent profile is not configured."
        try:
            return LocalGuardProfile.from_path(self.profile_path), None
        except (LocalProfileError, OSError, ValueError):
            return None, "The local guarded-agent profile needs attention."


def _run_payload(
    run: ProfileAgentRun, *, safe_reference: str | None, file_attached: bool
) -> dict[str, Any]:
    result = run.result
    decision = (
        "ALLOW"
        if result.status is AgentRunStatus.COMPLETED
        else "REVIEW"
        if result.status is AgentRunStatus.REVIEW_REQUIRED
        else "BLOCK"
    )
    return {
        "schema_version": PRODUCT_AGENT_SCHEMA,
        "status": result.status.value,
        "decision": decision,
        "response": result.final_response if result.status is AgentRunStatus.COMPLETED else None,
        "safe_message": result.safe_message,
        "workflow_id": result.workflow_id,
        "model": run.identity.to_dict(),
        "file_handoff": {
            "requested": safe_reference is not None,
            "used": file_attached,
            "safe_reference": safe_reference,
            "reference_lifetime": "product-session",
            "raw_file_reuploaded": False,
        },
        "audit": {
            "guard_events": len(result.audit_ids),
            "audit_ids": list(result.audit_ids),
            "session_record_hash": run.session_record_hash,
        },
        "raw_content_retained": False,
    }


def product_agent_error_payload(error: ProductAgentError) -> dict[str, Any]:
    return {
        "schema_version": "product-guarded-agent-error-v0.1",
        "error": {"code": error.code, "message": str(error), "retryable": False},
    }
