"""Harmless, deterministic local tools behind a gateway-only capability."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..guard.audit import append_audit
from ..guard.models import TrustLevel
from .file_access import AllowedRoot, FileAccessPolicy


class ToolRegistryError(ValueError):
    pass


class WorkspaceBoundaryError(ToolRegistryError):
    pass


class _GatewayCapability:
    """Unexported identity token required by every registry side-effect method."""


@dataclass(slots=True)
class RegistryCounters:
    tool_calls: int = 0
    workspace_reads: int = 0
    memory_writes: int = 0
    external_transfers: int = 0


class LocalToolRegistry:
    """Local-only registry. Callers receive no public dispatch or storage method."""

    def __init__(
        self,
        workspace_root: Path,
        *,
        documents: Mapping[str, str] | None = None,
        memory_path: Path | None = None,
        allowed_roots: Mapping[str, Path] | None = None,
        allowed_root_trust: Mapping[str, TrustLevel] | None = None,
        max_file_size: int = 1_000_000,
        allow_sensitive_files: bool = False,
        allow_hard_links: bool = False,
    ) -> None:
        self._workspace_root = workspace_root.resolve()
        if not self._workspace_root.is_dir():
            raise ToolRegistryError("workspace sandbox root must be an existing directory")
        self._documents = dict(documents or {})
        self._memory_path = memory_path
        configured_roots = (
            {"workspace": self._workspace_root} if allowed_roots is None else allowed_roots
        )
        configured_trust = dict(allowed_root_trust or {})
        if set(configured_trust) - set(configured_roots):
            raise ToolRegistryError("trust was configured for an unknown allowed root")
        self._file_policy = FileAccessPolicy(
            tuple(
                AllowedRoot(
                    root_id,
                    Path(path),
                    configured_trust.get(root_id, TrustLevel.INTERNAL),
                )
                for root_id, path in configured_roots.items()
            ),
            max_file_size=max_file_size,
            allow_sensitive=allow_sensitive_files,
            allow_hard_links=allow_hard_links,
        )
        self._memory: list[dict[str, Any]] = []
        self._external_sink: list[dict[str, Any]] = []
        self._capability = _GatewayCapability()
        self._capability_claimed = False
        self.counters = RegistryCounters()

    def _gateway_capability(self) -> _GatewayCapability:
        if self._capability_claimed:
            raise PermissionError("gateway capability has already been claimed")
        self._capability_claimed = True
        return self._capability

    def _gateway_file_policy(self, capability: _GatewayCapability) -> FileAccessPolicy:
        self._require(capability)
        return self._file_policy

    def _record_workspace_read(self, capability: _GatewayCapability) -> None:
        self._require(capability)
        self.counters.workspace_reads += 1

    @property
    def memory_records(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(dict(item) for item in self._memory)

    @property
    def simulated_external_transfers(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(dict(item) for item in self._external_sink)

    def _require(self, capability: _GatewayCapability) -> None:
        if capability is not self._capability:
            raise PermissionError("tool registry operations require the owning gateway capability")

    def _dispatch(
        self,
        capability: _GatewayCapability,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Any:
        self._require(capability)
        self.counters.tool_calls += 1
        if tool_name == "calculator":
            return self._calculator(arguments)
        if tool_name == "workspace_reader":
            return self._workspace_reader(arguments)
        if tool_name == "document_retriever":
            return self._document_retriever(arguments)
        raise ToolRegistryError(f"unknown local tool: {tool_name}")

    def _write_memory(
        self, capability: _GatewayCapability, record: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self._require(capability)
        stored = dict(record)
        if self._memory_path is not None:
            append_audit(
                self._memory_path,
                {"schema_version": "local-profile-memory-v0.1", "record": stored},
            )
        self._memory.append(stored)
        self.counters.memory_writes += 1
        return dict(stored)

    def _send_external_simulated(
        self, capability: _GatewayCapability, transfer: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self._require(capability)
        recorded = dict(transfer)
        self._external_sink.append(recorded)
        self.counters.external_transfers += 1
        return {"simulated": True, "recorded": True}

    @staticmethod
    def _calculator(arguments: Mapping[str, Any]) -> float:
        operation = arguments.get("operation")
        left = arguments.get("left")
        right = arguments.get("right")
        if operation not in {"add", "multiply"}:
            raise ToolRegistryError("calculator operation must be add or multiply")
        if (
            not isinstance(left, (int, float))
            or isinstance(left, bool)
            or not isinstance(right, (int, float))
            or isinstance(right, bool)
        ):
            raise ToolRegistryError("calculator operands must be numbers")
        return float(left + right if operation == "add" else left * right)

    def _workspace_reader(self, arguments: Mapping[str, Any]) -> str:
        relative = arguments.get("path")
        if not isinstance(relative, str) or not relative or len(relative) > 500:
            raise ToolRegistryError("workspace_reader path must be a bounded string")
        candidate = (self._workspace_root / relative).resolve()
        if not candidate.is_relative_to(self._workspace_root):
            raise WorkspaceBoundaryError("workspace_reader path escapes the allowed root")
        if not candidate.is_file():
            raise ToolRegistryError("workspace_reader target must be an existing file")
        self.counters.workspace_reads += 1
        return candidate.read_text(encoding="utf-8")

    def _document_retriever(self, arguments: Mapping[str, Any]) -> str:
        document_id = arguments.get("document_id")
        if not isinstance(document_id, str) or document_id not in self._documents:
            raise ToolRegistryError("unknown local document fixture")
        return self._documents[document_id]
