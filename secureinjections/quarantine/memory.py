"""Thread-safe, process-local quarantine backend."""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from ..models import ScanResult
from .base import QuarantineBackend, QuarantineRecord


class InMemoryQuarantine(QuarantineBackend):
    def __init__(self, *, store_raw_text: bool = False, max_records: int = 10_000):
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self.store_raw_text = store_raw_text
        self.max_records = max_records
        self._records: dict[str, QuarantineRecord] = {}
        self._lock = threading.Lock()

    def submit(
        self, text: str, result: ScanResult, metadata: dict[str, Any] | None = None
    ) -> QuarantineRecord:
        record = QuarantineRecord(
            id=uuid.uuid4().hex,
            created_at=datetime.now(UTC),
            content_sha256=hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            result=result,
            metadata=dict(metadata or {}),
            review_metadata={
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "categories": list(result.detected_categories),
                "rule_ids": [match.rule_id for match in result.matched_rules],
                "semantic_rule_ids": (
                    list(result.semantic_analysis.get("matched_rule_ids", []))
                    if result.semantic_analysis
                    else []
                ),
                "source_type": (result.context or {}).get("source"),
                "content_fingerprint": hashlib.sha256(
                    text.encode("utf-8", errors="replace")
                ).hexdigest(),
                "raw_input_stored": self.store_raw_text,
            },
            text=text if self.store_raw_text else None,
        )
        with self._lock:
            if len(self._records) >= self.max_records:
                oldest = next(iter(self._records))
                del self._records[oldest]
            self._records[record.id] = record
        return record

    def get(self, record_id: str) -> QuarantineRecord | None:
        with self._lock:
            return self._records.get(record_id)

    def list(self) -> tuple[QuarantineRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def release(self, record_id: str) -> QuarantineRecord | None:
        with self._lock:
            return self._records.pop(record_id, None)
