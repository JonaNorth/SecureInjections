"""Optional quarantine backends."""

from .base import QuarantineBackend, QuarantineRecord
from .memory import InMemoryQuarantine

__all__ = ["InMemoryQuarantine", "QuarantineBackend", "QuarantineRecord"]
