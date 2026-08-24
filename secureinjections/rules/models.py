"""Stable SecureInjections Threat Rule v1 model."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ThreatRule:
    schema_version: int
    id: str
    name: str
    description: str
    category: str
    severity: str
    confidence: float
    status: str
    created: str
    updated: str
    author: str
    license: str
    attack_patterns: tuple[str, ...] = ()
    regex_patterns: tuple[str, ...] = ()
    literal_patterns: tuple[str, ...] = ()
    semantic_examples: tuple[str, ...] = ()
    negative_examples: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ("any",)
    languages: tuple[str, ...] = ("en",)
    minimum_engine_version: str = "0.2.0"
    enabled: bool = True
    taxonomy: str | None = None
    legacy_id: str | None = None
    indicator_strength: str = "moderate"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for key, item in tuple(value.items()):
            if isinstance(item, tuple):
                value[key] = list(item)
        return value

    @property
    def content_hash(self) -> str:
        canonical = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hashlib.sha256(canonical).hexdigest()
