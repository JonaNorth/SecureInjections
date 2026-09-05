"""Bounded inspection helpers for common encoded and hidden text carriers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from .envelope import ContentSecurityFinding


@dataclass(frozen=True, slots=True)
class InspectionLimits:
    max_input_chars: int = 1_000_000
    max_candidates: int = 8
    max_decoded_bytes: int = 8_192
    max_depth: int = 2


@dataclass(frozen=True, slots=True)
class ContentInspection:
    original_sha256: str
    inspection_sha256: str
    normalized_text: str
    decoded_representations: tuple[str, ...]
    findings: tuple[ContentSecurityFinding, ...]

    @property
    def suspicious(self) -> bool:
        return any(item.suspicious for item in self.findings)


_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\u2061-\u2064\ufeff]")
_CONTROLS = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{14,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_INSTRUCTION = re.compile(
    r"\b(?:ignore|override|bypass|execute|invoke|upload|send|read|reveal|exfiltrat\w*|"
    r"system\s+prompt|from\s+now\s+on|when\s+you\s+see)\b",
    re.IGNORECASE,
)
_CONFUSABLES = frozenset("\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u04cf\u0501")


def inspect_content(content: str, *, limits: InspectionLimits | None = None) -> ContentInspection:
    limits = limits or InspectionLimits()
    if len(content) > limits.max_input_chars:
        raise ValueError("inspection input exceeds configured size limit")
    original_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    normalized = unicodedata.normalize("NFKC", content).replace("\x00", "")
    if len(normalized) > limits.max_input_chars:
        raise ValueError("normalized inspection input exceeds configured size limit")
    findings: list[ContentSecurityFinding] = []
    if _ZERO_WIDTH.search(normalized):
        stripped = _ZERO_WIDTH.sub("", normalized)
        findings.append(
            _finding(
                "HIDDEN_ZERO_WIDTH",
                "ZERO_WIDTH_UNICODE",
                _instruction_like(stripped),
                "Invisible Unicode characters were present.",
            )
        )
        normalized = stripped
    if _CONTROLS.search(normalized):
        findings.append(
            _finding(
                "HIDDEN_CONTROL",
                "SUSPICIOUS_UNICODE_CONTROL",
                True,
                "Bidirectional or isolate control characters were present.",
            )
        )
        normalized = _CONTROLS.sub("", normalized)
    scripts = {_script(character) for character in normalized if character.isalpha()}
    if "LATIN" in scripts and "CYRILLIC" in scripts and any(c in _CONFUSABLES for c in normalized):
        findings.append(
            _finding(
                "HIDDEN_CONFUSABLE",
                "MIXED_SCRIPT_CONFUSABLE",
                False,
                "Mixed Latin/Cyrillic text contains common confusable characters.",
            )
        )

    decoded: list[str] = []
    frontier = [normalized]
    seen = {normalized}
    for _depth in range(limits.max_depth):
        next_frontier: list[str] = []
        for text in frontier:
            for kind, candidate in _decode_candidates(text, limits):
                if candidate in seen or len(decoded) >= limits.max_candidates:
                    continue
                seen.add(candidate)
                decoded.append(candidate)
                next_frontier.append(candidate)
                suspicious = _instruction_like(candidate)
                findings.append(
                    _finding(
                        f"ENCODED_{kind}",
                        f"{kind}_TEXT_PAYLOAD",
                        suspicious,
                        f"Bounded {kind} decoding produced printable text"
                        + (" with instruction-like language." if suspicious else "."),
                    )
                )
            if len(decoded) >= limits.max_candidates:
                break
        frontier = next_frontier
        if not frontier or len(decoded) >= limits.max_candidates:
            break

    defragmented = re.sub(r"(?<=\b[A-Za-z])[\s._-]+(?=[A-Za-z]\b)", "", normalized)
    if defragmented != normalized and _instruction_like(defragmented):
        findings.append(
            _finding(
                "HIDDEN_FRAGMENTED",
                "FRAGMENTED_INSTRUCTION_TEXT",
                True,
                "Unusually fragmented text normalizes to instruction-like language.",
            )
        )
        decoded.append(defragmented[: limits.max_decoded_bytes])

    inspection_text = "\n".join((normalized, *decoded))
    return ContentInspection(
        original_hash,
        hashlib.sha256(inspection_text.encode("utf-8")).hexdigest(),
        normalized,
        tuple(decoded),
        tuple(dict.fromkeys(findings)),
    )


def _decode_candidates(text: str, limits: InspectionLimits) -> tuple[tuple[str, str], ...]:
    output: list[tuple[str, str]] = []
    for match in _BASE64.finditer(text):
        if len(output) >= limits.max_candidates:
            return tuple(output)
        token = match.group(0)
        if len(token) > limits.max_decoded_bytes * 2:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _printable_text(raw, limits.max_decoded_bytes)
        if decoded is not None:
            output.append(("BASE64", decoded))
    for match in _HEX.finditer(text):
        if len(output) >= limits.max_candidates:
            return tuple(output)
        token = match.group(0)
        if len(token) > limits.max_decoded_bytes * 2:
            continue
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        decoded = _printable_text(raw, limits.max_decoded_bytes)
        if decoded is not None:
            output.append(("HEX", decoded))
    for match in _PERCENT.finditer(text):
        if len(output) >= limits.max_candidates:
            return tuple(output)
        token = match.group(0)
        if len(token) > limits.max_decoded_bytes * 3:
            continue
        decoded = _printable_text(unquote_to_bytes(token), limits.max_decoded_bytes)
        if decoded is not None:
            output.append(("PERCENT", decoded))
    return tuple(output)


def _printable_text(raw: bytes, maximum: int) -> str | None:
    if not raw or len(raw) > maximum:
        return None
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    return text if printable / len(text) >= 0.9 else None


def _instruction_like(text: str) -> bool:
    return bool(_INSTRUCTION.search(text))


def _script(character: str) -> str:
    name = unicodedata.name(character, "")
    return name.split(" ", 1)[0] if name else "UNKNOWN"


def _finding(kind: str, reason: str, suspicious: bool, detail: str) -> ContentSecurityFinding:
    return ContentSecurityFinding(kind, reason, suspicious, detail)
