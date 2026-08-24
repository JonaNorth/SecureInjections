"""Ed25519 signing and exact-key verification; no custom cryptography."""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from pathlib import Path
from typing import Any


class SignatureError(ValueError):
    pass


def _crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - optional dependency boundary
        raise RuntimeError("Install secureinjections[feed] to verify signed feeds") from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def load_keyring(path: Path) -> dict[str, bytes]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1_048_576:
            raise SignatureError("keyring must be a regular JSON file no larger than 1 MiB")
        handle = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = -1
        with handle:
            raw = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignatureError(f"invalid keyring: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(raw, dict) or set(raw) != {"keys"} or not isinstance(raw["keys"], dict):
        raise SignatureError("keyring must contain exactly one keys object")
    result = {}
    for key_id, encoded in raw["keys"].items():
        if not isinstance(key_id, str) or not isinstance(encoded, str):
            raise SignatureError("keyring entries must map string IDs to Base64 keys")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SignatureError(f"invalid Base64 public key for {key_id}") from exc
        if len(key) != 32:
            raise SignatureError(f"Ed25519 public key {key_id} must be 32 bytes")
        result[key_id] = key
    return result


def verify_ed25519(message: bytes, signature: bytes, public_key: bytes) -> None:
    _, public_type, invalid_signature = _crypto()
    if len(signature) != 64 or len(public_key) != 32:
        raise SignatureError("invalid Ed25519 key or signature length")
    try:
        public_type.from_public_bytes(public_key).verify(signature, message)
    except invalid_signature as exc:
        raise SignatureError("feed manifest signature verification failed") from exc


def sign_ed25519(message: bytes, private_key: bytes) -> bytes:
    private_type, _, _ = _crypto()
    if len(private_key) != 32:
        raise SignatureError("Ed25519 private key seed must be exactly 32 bytes")
    return private_type.from_private_bytes(private_key).sign(message)
