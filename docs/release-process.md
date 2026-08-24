# Release process

## Public release candidate v0.5.0-rc1

The RC uses human-readable version `v0.5.0-rc1` and PEP 440 package version `0.5.0rc1`. Build both
wheel and sdist, audit both archives locally, install the wheel into a fresh Python 3.11
environment, and execute commands from outside the source checkout. PyPI publication is not
assumed or performed by release preparation.

Required RC blockers are listed in
[`release-blockers-v0.5.0-rc1.md`](release-blockers-v0.5.0-rc1.md). The release manifest must record
the actual Git HEAD as a base identifier, dirty state honestly, and exact artifact hashes. No
commit, tag, or publication occurs without explicit human approval.

### Scoped release-input hash

The manifest's `release_input_set_sha256` uses `release-input-selection-v2`:

1. Select the root files `CHANGELOG.md`, `LICENSE`, `README.md`, `SECURITY.md`,
   `pyproject.toml`, and `uv.lock`, plus every regular file recursively below `docs/`,
   `examples/`, `secureinjections/`, `tests/`, and `tools/`.
2. Exclude any path containing `__pycache__`, files ending in `.pyc` or `.pyo`, the internal local
   modules `secureinjections/phase3_adaptation.py` and
   `secureinjections/pilot_human_audit.py`, and generated files below an `audit/`, `logs/`, or
   `state/` directory within `examples/`. Static `.gitkeep` and `README.md` placeholders are
   retained. Files may be tracked or untracked; a selected path that disappears before hashing is
   an error.
3. Normalize each selected path to its repository-relative POSIX form and sort paths by their
   UTF-8 encoded bytes.
4. For each path, hash the file bytes with SHA-256. Feed this exact row to the aggregate SHA-256:
   UTF-8 path bytes, one NUL byte, the 64 lowercase ASCII hexadecimal hash bytes, and one LF byte.
5. Concatenate the rows without a header or trailing material. File paths are therefore bound as
   well as contents. The release manifest and `dist/` are not inputs, avoiding circularity.

`tools/generate_release_manifest.py` implements this rule. The release test reconstructs the hash
independently from the documented selection and serialization.

The versioned `release-quality.json` defines realistic regression tolerances. Before release run:

```bash
pytest
ruff check .
ruff format --check .
mypy secureinjections
python -m build
secureinjections rules quality-gate --path secureinjections/rules/canonical
secureinjections evaluate --corpus corpus --split validation
secureinjections evaluate --corpus corpus --split holdout
secureinjections rules metrics --path secureinjections/rules/canonical --corpus corpus
secureinjections release-gate --corpus corpus
python benchmarks/benchmark_corpus.py
secureinjections classifier audit --corpus classifier-corpus.jsonl
secureinjections classifier evaluate --model /local/classifier --corpus classifier-corpus.jsonl \
  --split validation --routing-experiments
```

Feed builds include hashes for the rule database and optional semantic index plus engine/build-tool
compatibility. Evaluation and corpus hashes may be added when those signed artifacts are present.
Signed quality metadata is provenance, not a runtime guarantee; local validation remains required.

An optional signed classifier archive has its own version and hashes. Installing it only stages a
verified local artifact; activation remains an explicit administrative choice. Before a v0.4
blind reveal, record the generator, seed, content, evaluator, engine, classifier, training corpus,
rules, and threshold hashes. Do not tune after reveal.
