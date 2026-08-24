"""Dependency-free ASGI input screening middleware."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from ..models import Decision, ScanResult
from ..quarantine.base import QuarantineBackend
from ..scanner import Scanner

ASGIApp = Callable[[dict[str, Any], Callable[..., Awaitable], Callable[..., Awaitable]], Awaitable]


class InputShieldASGIMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        scanner: Scanner | None = None,
        quarantine: QuarantineBackend | None = None,
        max_body_bytes: int = 1_000_000,
        scan_methods: tuple[str, ...] = ("POST", "PUT", "PATCH"),
    ) -> None:
        self.app = app
        self.scanner = scanner or Scanner()
        self.quarantine = quarantine
        self.max_body_bytes = max_body_bytes
        self.scan_methods = frozenset(scan_methods)

    @staticmethod
    async def _respond(
        send: Callable[..., Awaitable], status: int, payload: dict[str, Any]
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or scope.get("method") not in self.scan_methods:
            await self.app(scope, receive, send)
            return

        messages: list[dict[str, Any]] = []
        chunks: list[bytes] = []
        total = 0
        more = True
        while more:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_body_bytes:
                await self._respond(
                    send, 413, {"decision": "block", "detail": "request body too large"}
                )
                return
            chunks.append(chunk)
            more = bool(message.get("more_body"))

        body = b"".join(chunks)
        text = body.decode("utf-8", errors="replace")
        result = self.scanner.scan(text)
        if result.decision is Decision.BLOCK:
            await self._respond(send, 403, self._payload(result))
            return
        if result.decision is Decision.REVIEW:
            quarantine_id = None
            if self.quarantine is not None:
                record = self.quarantine.submit(
                    text,
                    result,
                    metadata={"method": scope.get("method"), "path": scope.get("path")},
                )
                quarantine_id = record.id
            payload = self._payload(result)
            payload["quarantine_id"] = quarantine_id
            await self._respond(send, 202, payload)
            return

        cursor = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal cursor
            if cursor < len(messages):
                message = messages[cursor]
                cursor += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _payload(result: ScanResult) -> dict[str, Any]:
        return {
            "decision": result.decision.value,
            "risk_score": result.risk_score,
            "categories": list(result.detected_categories),
            "matches": [match.to_dict() for match in result.matched_rules],
            "scan_duration_ms": result.scan_duration_ms,
        }
