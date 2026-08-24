"""Flask input screening extension."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..models import Decision
from ..quarantine.base import QuarantineBackend
from ..scanner import Scanner

if TYPE_CHECKING:
    from flask import Flask


class InputShieldFlask:
    def __init__(
        self,
        app: Flask | None = None,
        *,
        scanner: Scanner | None = None,
        quarantine: QuarantineBackend | None = None,
        max_body_bytes: int = 1_000_000,
    ) -> None:
        self.scanner = scanner or Scanner()
        self.quarantine = quarantine
        self.max_body_bytes = max_body_bytes
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        from flask import jsonify, request

        @app.before_request
        def secureinjections_screen() -> Any:
            if request.method not in {"POST", "PUT", "PATCH"}:
                return None
            raw = request.get_data(cache=True)
            if len(raw) > self.max_body_bytes:
                return jsonify(decision="block", detail="request body too large"), 413
            text = raw.decode("utf-8", errors="replace")
            result = self.scanner.scan(text)
            payload: dict[str, Any] = {
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "categories": list(result.detected_categories),
                "matches": [match.to_dict() for match in result.matched_rules],
                "scan_duration_ms": result.scan_duration_ms,
            }
            if result.decision is Decision.BLOCK:
                return jsonify(payload), 403
            if result.decision is Decision.REVIEW:
                record_id = None
                if self.quarantine is not None:
                    record = self.quarantine.submit(
                        text,
                        result,
                        metadata={"method": request.method, "path": request.path},
                    )
                    record_id = record.id
                payload["quarantine_id"] = record_id
                return jsonify(payload), 202
            return None
