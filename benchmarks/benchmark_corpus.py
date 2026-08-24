"""Bounded normalization and deterministic-path performance corpus benchmark."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from secureinjections import Scanner
from secureinjections.detectors.patterns import text_variants


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def timings(callable_, iterations: int) -> dict[str, float]:
    values = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        callable_()
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "p50": round(statistics.median(values), 6),
        "p95": round(percentile(values, 0.95), 6),
        "p99": round(percentile(values, 0.99), 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).with_name("performance-corpus.json"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    specification = json.loads(args.corpus.read_text(encoding="utf-8"))
    scanner = Scanner()
    report = {"benchmark": "deterministic and normalization; no embedding inference"}
    cases = {}
    for case in specification["cases"]:
        repetitions = case["target_bytes"] // len(case["seed"].encode()) + 1
        text = (
            (case["seed"] * repetitions)
            .encode()[: case["target_bytes"]]
            .decode("utf-8", errors="ignore")
        )
        cases[case["id"]] = {
            "bytes": len(text.encode()),
            "iterations": case["iterations"],
            "normalization_ms": timings(
                lambda value=text: text_variants(value), case["iterations"]
            ),
            "deterministic_scan_ms": timings(
                lambda value=text: scanner.scan(value), case["iterations"]
            ),
        }
    report["cases"] = cases
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
