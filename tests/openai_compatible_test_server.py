"""Deterministic loopback-only OpenAI-compatible subset used by tests and wheel smoke."""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class DeterministicOpenAIHandler(BaseHTTPRequestHandler):
    models_status = 200
    model_id = "local-test-model"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/v1/models":
            self.send_error(404)
            return
        if self.models_status != 200:
            self.send_error(self.models_status)
            return
        self._json(200, {"object": "list", "data": [{"id": self.model_id, "object": "model"}]})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            messages = payload["messages"]
            last = messages[-1]
            content = str(last.get("content", ""))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._json(400, {"error": "malformed request"})
            return
        lowered = content.casefold()
        if "protocol_failure" in lowered:
            self._json(200, {"choices": []})
            return
        if "timeout" in lowered:
            time.sleep(0.3)
        if "oversized" in lowered:
            self._completion(
                content=json.dumps(
                    {"action": "FINAL_RESPONSE", "response": "x" * 200_000},
                    separators=(",", ":"),
                )
            )
            return
        if "ambiguous" in lowered:
            self._completion(
                content='{"action":"FINAL_RESPONSE","response":"ambiguous"}',
                tool_calls=[
                    self._tool_call("calculator", {"operation": "add", "left": 1, "right": 2})
                ],
            )
            return
        if "multiple_tools" in lowered:
            self._completion(
                tool_calls=[
                    self._tool_call("calculator", {"operation": "add", "left": 1, "right": 2}),
                    self._tool_call("calculator", {"operation": "add", "left": 2, "right": 3}),
                ]
            )
            return
        if "malformed_tool" in lowered:
            self._completion(tool_calls=[self._raw_tool_call("calculator", "{")])
            return
        if "unknown_tool" in lowered:
            self._completion(tool_calls=[self._tool_call("shell", {"command": "false"})])
            return
        if last.get("role") == "tool":
            self._completion(
                content='{"action":"FINAL_RESPONSE","response":"Tool result received."}'
            )
            return
        if "document_id poisoned" in lowered:
            self._completion(
                tool_calls=[self._tool_call("document_retriever", {"document_id": "poisoned"})]
            )
            return
        if "document_id ordinary" in lowered or "safe retrieval" in lowered:
            self._completion(
                tool_calls=[self._tool_call("document_retriever", {"document_id": "ordinary"})]
            )
            return
        if "calculator" in lowered or "2 + 3" in lowered or "12 times 7" in lowered:
            left, right, operation = (12, 7, "multiply") if "12" in lowered else (2, 3, "add")
            self._completion(
                tool_calls=[
                    self._tool_call(
                        "calculator", {"operation": operation, "left": left, "right": right}
                    )
                ]
            )
            return
        self._completion(content='{"action":"FINAL_RESPONSE","response":"Local response."}')

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _completion(
        self,
        *,
        content: str | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
    ) -> None:
        message: dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls is not None:
            message["tool_calls"] = tool_calls
        self._json(
            200,
            {
                "id": "chatcmpl-local-fixture",
                "object": "chat.completion",
                "model": self.model_id,
                "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            },
        )

    @staticmethod
    def _tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return DeterministicOpenAIHandler._raw_tool_call(
            name, json.dumps(arguments, separators=(",", ":"))
        )

    @staticmethod
    def _raw_tool_call(name: str, arguments: str) -> dict[str, Any]:
        return {
            "id": "call-local-fixture",
            "type": "function",
            "function": {"name": name, "arguments": arguments},
        }

    def _json(self, status: int, value: Any) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--models-unsupported", action="store_true")
    args = parser.parse_args()
    DeterministicOpenAIHandler.models_status = 404 if args.models_unsupported else 200
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DeterministicOpenAIHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
