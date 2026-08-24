"""Privacy-preserving append-only Guard audit records."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


def append_audit(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(record).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
