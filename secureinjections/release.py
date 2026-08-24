"""Versioned release regression gates based on validation data only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .corpus import load_corpus, mutate_cases
from .evaluation import evaluate_cases
from .models import Decision, ScanContext
from .rules.models import ThreatRule
from .scanner import Scanner


def load_release_config(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "deterministic_benign_fpr_max",
        "combined_benign_fpr_max",
        "critical_attack_recall_min",
        "deterministic_recall_min",
        "mutation_detection_rate_min",
        "deterministic_p95_latency_ms_max",
        "required_test_groups",
    }
    if not isinstance(raw, dict) or set(raw) != required or raw["schema_version"] != 1:
        raise ValueError("release quality configuration is invalid")
    for field in required - {"schema_version", "required_test_groups"}:
        if not isinstance(raw[field], int | float) or isinstance(raw[field], bool):
            raise ValueError(f"release quality threshold is invalid: {field}")
    return raw


def run_release_gate(
    scanner: Scanner,
    rules: tuple[ThreatRule, ...],
    corpus_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    config = load_release_config(config_path)
    cases = tuple(
        case for case in load_corpus(corpus_path, split="validation") if case.parent_case_id is None
    )
    report = evaluate_cases(scanner, cases, reveal_failures=True)
    critical_ids = {rule.id for rule in rules if rule.severity == "critical"}
    critical = [case for case in cases if critical_ids.intersection(case.expected_rule_ids)]
    critical_hits = sum(
        scanner.scan(
            case.text,
            context=ScanContext(source=case.source_type, trust_level="untrusted"),
        ).decision
        is not Decision.ALLOW
        for case in critical
    )
    critical_recall = critical_hits / len(critical) if critical else 0.0
    base_malicious = tuple(case for case in cases if case.label == "malicious")
    mutations = mutate_cases(base_malicious, seed=42)
    mutation_hits = sum(
        scanner.scan(
            case.text,
            context=ScanContext(source=case.source_type, trust_level="untrusted"),
        ).decision
        is not Decision.ALLOW
        for case in mutations
    )
    mutation_rate = mutation_hits / len(mutations) if mutations else 0.0
    checks = {
        "deterministic_benign_fpr": {
            "actual": report["false_positive_rate"],
            "target": config["deterministic_benign_fpr_max"],
            "passed": report["false_positive_rate"] <= config["deterministic_benign_fpr_max"],
        },
        "deterministic_recall": {
            "actual": report["recall"],
            "target": config["deterministic_recall_min"],
            "passed": report["recall"] >= config["deterministic_recall_min"],
        },
        "critical_attack_recall": {
            "actual": round(critical_recall, 6),
            "target": config["critical_attack_recall_min"],
            "passed": critical_recall >= config["critical_attack_recall_min"],
        },
        "mutation_detection_rate": {
            "actual": round(mutation_rate, 6),
            "target": config["mutation_detection_rate_min"],
            "passed": mutation_rate >= config["mutation_detection_rate_min"],
        },
        "deterministic_p95_latency_ms": {
            "actual": report["latency_ms"]["p95"],
            "target": config["deterministic_p95_latency_ms_max"],
            "passed": report["latency_ms"]["p95"] <= config["deterministic_p95_latency_ms_max"],
        },
    }
    return {
        "passed": all(item["passed"] for item in checks.values()),
        "split": "validation",
        "checks": checks,
        "required_external_test_groups": config["required_test_groups"],
        "combined_semantic": "not tested; provide a calibrated local model separately",
    }
