"""Versioned data-driven context profiles for deterministic score policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any


@dataclass(frozen=True, slots=True)
class ProfilePolicy:
    review_adjustment: int = 0
    block_adjustment: int = 0
    technical_context_discount: float = 1.0
    indirect_instruction_multiplier: float = 1.0


def _load_profiles() -> dict[str, ProfilePolicy]:
    path = files("secureinjections").joinpath("scanner-profiles.json")
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "profiles"}:
        raise RuntimeError("scanner profile data is invalid")
    if raw["schema_version"] != 1 or not isinstance(raw["profiles"], dict):
        raise RuntimeError("unsupported scanner profile data")
    expected = {
        "review_adjustment",
        "block_adjustment",
        "technical_context_discount",
        "indirect_instruction_multiplier",
    }
    result: dict[str, ProfilePolicy] = {}
    for name, values in raw["profiles"].items():
        if not isinstance(name, str) or not isinstance(values, dict) or set(values) != expected:
            raise RuntimeError("scanner profile entry is invalid")
        result[name] = ProfilePolicy(**values)
    return result


PROFILES = _load_profiles()
