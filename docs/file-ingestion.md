# Safe file ingestion

SecureInjections includes a local browser experience backed by the real Gateway file boundary.
The browser sends the selected file to the local FastAPI service; it never sends file content to a
model. The service stages the upload under a host-owned random name, invokes `SafeFileReader`
through `GuardedToolGateway`, and deletes the staged file after inspection.

## Run locally

Install the service dependencies and start the loopback server:

```bash
python -m pip install -e '.[service]'
uvicorn secureinjections.service:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`, choose a supported UTF-8 text or source file, and select **Inspect
file**. Do not expose this unauthenticated local-development service beyond loopback.

The default staging/audit directory is the current user's temporary directory under
`secureinjections-file-ingest-<uid>`. Set `SECUREINJECTIONS_FILE_INGEST_ROOT` before starting the
service to choose a host-owned directory. The directory must be owned by the service user, must not
be a symlink, and must not grant access to group or other users. A new directory is created with
owner-only permissions where supported.

## API contract

`POST /v1/files/ingest` accepts an `application/octet-stream` body and a percent-encoded original
filename in `X-SecureInjections-Filename`. The server derives the real byte size and supported type;
clients cannot supply trust, provenance, decisions, audit IDs, content IDs, or allowed roots.

Successful inspections return `safe-file-ingestion-v0.1`. `ALLOW` includes a host-created safe
reference; `REVIEW` and `BLOCK` include no forwardable reference. All decisions return sanitized
metadata, safe findings, policy identity, provenance summary, and audit correlation. Raw file
content is never returned by this endpoint and is not written to the audit log.

`GET /v1/files/capabilities` returns the supported extensions and current byte limit used by the
UI. PDF, office documents, images, and archives are intentionally unsupported in v0.1.

There is no product-facing downstream agent action in Phase 1. An allowed result therefore says
“File inspected and ready”; a later phase must consume the host-held envelope directly rather than
rereading the upload or trusting browser state.
