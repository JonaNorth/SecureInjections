"""Resource-bounded PyYAML SafeLoader for trusted-adjacent rule configuration."""

from __future__ import annotations

from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.events import AliasEvent


class BoundedSafeLoader(yaml.SafeLoader):
    max_aliases = 64
    max_depth = 64
    max_nodes = 100_000

    def __init__(self, stream: Any):
        super().__init__(stream)
        self._alias_count = 0
        self._compose_depth = 0
        self._node_count = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            self._alias_count += 1
            if self._alias_count > self.max_aliases:
                raise ComposerError(
                    None, None, "YAML alias limit exceeded", self.peek_event().start_mark
                )
        self._compose_depth += 1
        self._node_count += 1
        try:
            if self._compose_depth > self.max_depth:
                raise ComposerError(
                    None, None, "YAML nesting limit exceeded", self.peek_event().start_mark
                )
            if self._node_count > self.max_nodes:
                raise ComposerError(
                    None, None, "YAML node limit exceeded", self.peek_event().start_mark
                )
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1


def bounded_safe_load(text: str) -> Any:
    return yaml.load(text, Loader=BoundedSafeLoader)
