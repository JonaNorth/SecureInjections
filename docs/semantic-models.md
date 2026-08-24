# Local semantic models

Semantic similarity is optional and disabled by default. Normal scanning never downloads a model.
The loader accepts an explicit local directory, sets `local_files_only=True` and
`trust_remote_code=False`, rejects symlinks and pickle-capable weights, and requires safetensors.
The index is bounded NumPy data loaded with `allow_pickle=False` and validated for shape, count,
dimension, finite values, metadata mapping, version, size, and SHA-256 content hash.

The registry lists candidates but recommends none without project-specific evidence. Run
`semantic evaluate-model` for model-load time, full embedding p50/p95/p99, batch throughput,
memory high-water delta, artifact size, retrieval accuracy, malicious/benign separation, and
multilingual performance. Run `semantic calibrate` on validation only and attach its metadata when
building an index. Never report vector-kernel timing as embedding inference latency.
