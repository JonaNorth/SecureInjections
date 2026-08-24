# Threat taxonomy

Taxonomy identifiers are stable, machine-readable metadata alongside backwards-compatible output
categories. Current families are:

- `PI.DIRECT`, `PI.INDIRECT`, `PI.SYSTEM_OVERRIDE`, `PI.POLICY_EXTRACTION`;
- `AGENT.TOOL_MANIPULATION`, `AGENT.CREDENTIAL_ACCESS`, `AGENT.FILE_ACCESS`,
  `AGENT.NETWORK_ACCESS`, `AGENT.PERSISTENCE`, `AGENT.INTER_AGENT_MESSAGE`;
- `SECRET.API_KEY`, `SECRET.JWT`, `SECRET.PRIVATE_KEY`;
- `NET.SSRF`, `NET.METADATA`, `NET.PRIVATE_ADDRESS`;
- `EXEC.SHELL`, `EXEC.POWERSHELL`, `EXEC.PACKAGE_MANAGER`;
- `INJECTION.SQL`, `TRAVERSAL.PATH`;
- `OBFUSCATION.BASE64`, `OBFUSCATION.UNICODE`, `OBFUSCATION.ZERO_WIDTH`.

New leaf categories may be added within Threat Rule v1. Renaming or changing an existing category's
meaning requires aliases, migration notes, and a compatibility release. External OWASP, CWE,
MITRE, paper, and incident references are included only where the mapping is accurate.
