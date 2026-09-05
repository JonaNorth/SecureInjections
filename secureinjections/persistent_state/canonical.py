"""Canonical authenticated serialization for persistent security authority."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

AUTHENTICATION_DOMAIN = b"SECUREINJECTIONS-STATE-v1\x00"
MAX_AUTHORITY_JSON_BYTES = 1_048_576
MAX_AUTHORITY_STRING_BYTES = 16_384
MIN_AUTHORITY_INTEGER = -(2**63)
MAX_AUTHORITY_INTEGER = 2**63 - 1


class CanonicalAuthorityError(ValueError):
    """Raised when authority data is ambiguous or unsupported."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalAuthorityError(f"duplicate logical key: {key}")
        result[key] = value
    return result


def _validate(value: Any, *, depth: int = 0) -> None:
    if depth > 16:
        raise CanonicalAuthorityError("authority record exceeds nesting limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise CanonicalAuthorityError("authority string is not valid UTF-8") from exc
        if len(encoded) > MAX_AUTHORITY_STRING_BYTES:
            raise CanonicalAuthorityError("authority string exceeds byte limit")
        return
    if isinstance(value, int):
        if not MIN_AUTHORITY_INTEGER <= value <= MAX_AUTHORITY_INTEGER:
            raise CanonicalAuthorityError("authority integer exceeds signed 64-bit range")
        return
    if isinstance(value, float):
        raise CanonicalAuthorityError("floats are not supported in authority records")
    if isinstance(value, list | tuple):
        if len(value) > 512:
            raise CanonicalAuthorityError("authority sequence exceeds size limit")
        for item in value:
            _validate(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 512:
            raise CanonicalAuthorityError("authority object exceeds size limit")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 200:
                raise CanonicalAuthorityError("authority keys must be bounded strings")
            _validate(item, depth=depth + 1)
        return
    raise CanonicalAuthorityError(f"unsupported authority value: {type(value).__name__}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON after rejecting ambiguous value types."""

    _validate(value)
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalAuthorityError("authority record cannot be serialized") from exc
    try:
        encoded = rendered.encode("utf-8")
    except UnicodeError as exc:
        raise CanonicalAuthorityError("authority JSON is not valid UTF-8") from exc
    if len(encoded) > MAX_AUTHORITY_JSON_BYTES:
        raise CanonicalAuthorityError("canonical authority JSON exceeds byte limit")
    return encoded


def canonical_text(value: Mapping[str, Any]) -> str:
    return canonical_bytes(value).decode("utf-8")


def strict_json_object(raw: str) -> dict[str, Any]:
    try:
        raw_bytes = raw.encode("utf-8")
    except UnicodeError as exc:
        raise CanonicalAuthorityError("authority JSON is not valid UTF-8") from exc
    if len(raw_bytes) > MAX_AUTHORITY_JSON_BYTES:
        raise CanonicalAuthorityError("authority JSON exceeds byte limit")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise CanonicalAuthorityError("authority JSON is malformed") from exc
    if not isinstance(value, dict):
        raise CanonicalAuthorityError("authority JSON must be an object")
    _validate(value)
    if canonical_text(value) != raw:
        raise CanonicalAuthorityError("authority JSON is not canonical")
    return value


def record_mac(key: bytes, record_type: str, payload: Mapping[str, Any]) -> str:
    if len(key) != 32:
        raise CanonicalAuthorityError("authority key must contain exactly 32 bytes")
    if (
        not record_type
        or len(record_type) > 100
        or "\x00" in record_type
        or not record_type.isascii()
    ):
        raise CanonicalAuthorityError("record type is not canonical")
    message = (
        AUTHENTICATION_DOMAIN + record_type.encode("ascii") + b"\x00" + canonical_bytes(payload)
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_record_mac(
    key: bytes, record_type: str, payload: Mapping[str, Any], expected: str
) -> bool:
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    return hmac.compare_digest(record_mac(key, record_type, payload), expected)


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
