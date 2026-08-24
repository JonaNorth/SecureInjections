# Performance

Initialize one `Scanner` per configuration and reuse it. YAML parsing and expression compilation
happen during initialization, not on the scan path. Each scan performs bounded normalization,
local matching, scoring, and safe result construction without network or filesystem I/O.

Run:

```bash
secureinjections benchmark --iterations 10000
python benchmarks/benchmark_scanner.py --iterations 10000
```

The reported median and p95 are microbenchmarks, not production capacity promises. Benchmark on
the target Python version and hardware with representative input lengths and custom signatures.
Also load-test middleware with realistic concurrency and body-size distributions.

Performance contributions should report the environment, sample corpus, warmup, iteration count,
median, p95, and any rule-count change. The test suite includes a deliberately generous median
latency guard for short benign input.

Measure three paths independently:

- deterministic: `secureinjections benchmark`;
- semantic: `secureinjections semantic benchmark --index ... --model ...`;
- combined: corpus evaluation with `--include-semantic` and configured local model/index.

Reports include median, p95, p99, and throughput. Semantic inference is expected to be slower. Keep
it behind deterministic thresholds unless policy intentionally requires it for every request.
