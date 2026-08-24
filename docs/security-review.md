# Security-focused implementation review

This review covers the SecureInjections 0.2 local semantic and signed-feed extension. It records
implemented controls and residual limitations; it is not an independent audit.

| Area | Implemented control | Residual consideration |
|---|---|---|
| Malicious YAML/JSON | PyYAML safe constructors, 1 MiB files, bounded aliases/depth/nodes, strict fields and types | Administrators must still treat rule repositories as code-reviewed supply-chain input |
| Regex denial of service | 4,096-character expressions, suspicious-pattern lint, bounded scanner input, false-positive and latency regressions | Python `re` has no execution timeout; reject ambiguous nested repetition during review |
| Archive traversal | Reject absolute paths, `..`, backslashes, NULs, duplicate names; verify resolved staging parents | New archive formats must use the same defensive extraction contract |
| Symlink/special-file attacks | Reject bundle, keyring, rule, index, and archive symlinks; staging starts empty | Feed-root parent directories remain an operating-system permission concern |
| Decompression bombs | Limits on bundle/artifact/member counts, compressed/uncompressed bytes, and compression ratio | Limits should be tuned downward for constrained deployments |
| Feed downgrade | Semantic-version comparison refuses duplicate and older installs; rollback is explicit | Pre-release versions with the same base tuple are conservatively treated as equal |
| Unsigned manifests | Ed25519 verification is mandatory before artifact trust | Public-key distribution and rotation are operator trust decisions |
| Signing-key confusion | Manifest key ID must exactly match a pinned keyring entry; unknown IDs fail | Protect keyrings from unauthorized local replacement |
| Corrupted downloads | Signed canonical manifest plus SHA-256 for every declared artifact; undeclared members fail | Transport security remains recommended even though authenticity is content-verified |
| TOCTOU | Bundle/keyring opened with file descriptors and `O_NOFOLLOW` where available; feed activation uses staging, immutable release rename, fsynced atomic pointers, and an install lock | Cross-process advisory locking is POSIX-specific; Windows retains process locking plus atomic replacement |
| Failed update | Verification and full staged validation precede activation; active pointer is unchanged on failure | Operators should monitor disk capacity before large updates |
| Semantic index | JSON + float32 `.npy`, `allow_pickle=False`, exact fields/dtype/shape, finite values, size/count limits, content hash | NumPy and model runtime remain third-party dependencies |
| Untrusted pickle/model | Pickles and object arrays are rejected; sentence-transformers uses a configured local path, `local_files_only=True`, `trust_remote_code=False`, bounded configuration identity | Only load models from reviewed provenance; ML libraries are executable software |
| User-data persistence | Scanner and semantic detector write no request text/vector; output omits fragments and stored threat examples | Applications can explicitly add storage or raw quarantine and own that privacy impact |
| Logging and telemetry | Scanner emits no logs or telemetry and has no analytics dependency | Surrounding middleware/application logging must also avoid raw payloads |
| Network access | `scan()` and semantic inference have no network path; model is local; feed operations are explicit | A future updater must remain an administrative command and reuse verification |
| Input execution | Text is never evaluated, executed, imported, followed as a URL, or interpolated into a command | An allow result cannot make unsafe downstream handling safe |

The test suite exercises malformed YAML, alias amplification, duplicate/invalid rules, suspicious
regex linting, corrupt and pickle indexes, archive traversal, symlink members, compression bombs,
unknown and incorrect signing keys, invalid signatures, hash corruption, compatibility failures,
downgrades, rollback, atomic failure behavior, concurrent scanning, no-network scanning, redaction,
and semantic non-persistence.
