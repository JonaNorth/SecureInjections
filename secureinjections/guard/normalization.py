"""Bounded, deterministic Guard normalization."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NormalizedContent:
    text: str
    sha256: str


def normalize_content(content: str) -> NormalizedContent:
    """Normalize representation without executing, decoding, or resolving content."""

    text = unicodedata.normalize("NFKC", content).replace("\x00", "")
    text = re.sub(r"\r\n?", "\n", text)
    return NormalizedContent(text=text, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())
