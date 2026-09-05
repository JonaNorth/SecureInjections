# Privacy guarantees

## Validated Guard, Gateway, and proxy defaults

Raw prompt logging, raw model-response logging, and raw tool-argument logging are off in the
validated Level 1 Community path. Guard and proxy audit retains bounded metadata: timestamps,
source/destination types, decisions, reason and finding codes, correlation IDs, normalized
content/request/response hashes, profile/policy hashes, upstream-dispatch state, timings, and
record hashes. It does not retain blocked excerpts, API credentials, or client request IDs.

The validated Local Guard and proxy profiles reject raw-content logging. SecureInjections emits no
telemetry and has no cloud-inference fallback. Applications and third-party tools can still create
their own logs; operators must audit those separately.

Default scanning is entirely offline. SecureInjections makes no external request, calls no hosted
model, emits no telemetry, persists no scanned text or request embeddings, and logs neither raw
input nor matched secret values.

Scanned data is never executed, evaluated, resolved as a URL, interpolated into a shell command,
used to run a package manager, imported as code, or treated as a local resource path. Normalization
and decoding operate only on bounded in-memory strings.

Community does not include threat-feed administration, trained classifiers, embedding models,
or research pipelines.

Applications can explicitly opt into a quarantine backend that stores raw text, or build their own
logging/storage around results. Those choices are outside the scanner's default guarantees and must
have access controls, encryption, minimization, and retention policies.
