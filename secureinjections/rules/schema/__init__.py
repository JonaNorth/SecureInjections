"""Machine-readable rule schemas."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def threat_rule_schema() -> dict[str, Any]:
    resource = files("secureinjections.rules.schema").joinpath("rule-v1.schema.json")
    return json.loads(resource.read_text(encoding="utf-8"))


__all__ = ["threat_rule_schema"]
