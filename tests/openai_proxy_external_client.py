"""External-style OpenAI-compatible client fixture; deliberately no SecureInjections imports."""

from __future__ import annotations

import json
import urllib.request
from typing import Any


def chat(base_url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Request-ID": "external-client-1"},
        method="POST",
    )
    try:
        response = urllib.request.urlopen(request, timeout=5)  # noqa: S310
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read()), dict(response.headers)
