from __future__ import annotations

from pathlib import Path

import pytest

from secureinjections.rule_engine import RuleValidationError, bundled_rules_path, load_rules


def test_bundled_rules_are_valid_and_unique() -> None:
    rules = load_rules()
    assert len(rules) >= 30
    assert len({rule.id for rule in rules}) == len(rules)
    assert {rule.category for rule in rules} >= {
        "prompt_injection",
        "secret_leakage",
        "ssrf",
        "sql_injection",
        "path_traversal",
        "shell_command",
    }
    assert bundled_rules_path().is_dir()


def test_invalid_rule_file_is_rejected(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("version: 1\nrules:\n  - id: nope\n", encoding="utf-8")
    with pytest.raises(RuleValidationError):
        load_rules((invalid,))
