# Log poisoning and indirect prompt injection

Indirect injection places instructions in data that a separate AI processes later. Sources include
HTTP query parameters, URL paths, User-Agent strings, custom headers, search fields, form values,
JSON bodies, errors, support tickets, database rows, retrieved pages, email, and tool output.

Use the `log_ingestion`, `rag_document`, or `agent_input` profile and pass accurate `ScanContext`
source metadata. Scan before the record becomes model context. Keep raw quarantine content disabled
unless a separately controlled review process truly requires it. Scanning does not replace safe
prompt construction, content/data separation, tool authorization, or sandboxing.
