"""Quarantine backend contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..models import ScanResult


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    id: str
    created_at: datetime
    content_sha256: str
    result: ScanResult
    metadata: dict[str, Any]
    review_metadata: dict[str, Any]
    text: str | None = None


class QuarantineBackend(ABC):
    """A non-global quarantine queue. Each suspicious request is submitted independently."""

    @abstractmethod
    def submit(
        self, text: str, result: ScanResult, metadata: dict[str, Any] | None = None
    ) -> QuarantineRecord:
        pass

    @abstractmethod
    def get(self, record_id: str) -> QuarantineRecord | None:
        pass

    @abstractmethod
    def list(self) -> tuple[QuarantineRecord, ...]:
        pass

    @abstractmethod
    def release(self, record_id: str) -> QuarantineRecord | None:
        pass
