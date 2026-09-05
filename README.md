# SecureInjections Community

Local AI security for supported workflows routed through SecureInjections.

SecureInjections Community is an inspectable enforcement product for evaluating how untrusted
prompts, model responses, files, retrieval content, tool calls, memory writes, and agent actions
cross an AI security boundary. It applies `ALLOW`, `REVIEW`, or `BLOCK` before protected traffic
or side effects continue.

> Detection is best effort. SecureInjections does not protect every AI application, scan your
> whole Mac, prevent every prompt injection, or control operations that bypass its documented
> boundaries.

## Community candidate status

`v0.6.0-rc1` is the first installable SecureInjections Community product candidate. Jonathan
completed manual RC runtime validation: PASS. This documentation-corrected candidate is publication-ready,
subject to separate publication authorization. It has not
yet been published. It is intended for supported local evaluation, with the limitations below.

## What Community includes

- Deterministic Guard inspection and policy enforcement
- Capability-separated Gateway boundaries
- OpenAI-compatible Guard Proxy for explicitly configured loopback traffic
- Manual one-file-at-a-time inspection through SafeFileReader-backed enforcement
- A basic protected local-agent interaction using host-owned safe references
- Basic privacy-bounded Activity
- A minimal browser product shell
- `start`, `status`, `doctor`, `inspect`, and integration-scope commands
- A supported local Ollama evaluation path using `qwen2.5:7b`
- Exact Open WebUI 0.11.0 guidance with streaming off through Guard Proxy

`REVIEW` means the operation stopped. Community has no “continue anyway” authorization path.

## Community and planned Pro

| Community candidate | Planned Pro product |
| --- | --- |
| Manual, explicit file and prompt workflows | Continuous and managed protection workflows |
| One file selected and inspected at a time | Level 2 selected-folder/workspace monitoring |
| Basic loopback product lifecycle | Native/background/autostart lifecycle |
| Manual Guard Proxy activation | Automated integration setup and orchestration |
| Basic bounded Activity | Advanced history, search, reporting, and policy management |
| One validated local setup | Additional supported integrations and managed deployment |
| Local evaluation and security transparency | Commercial updates and future team/enterprise controls |

Pro capabilities are planned; they are not included or advertised as shipped in this candidate.
Community has no scan counters, time limits, or artificial local feature flags.

## Supported scope

- Platform: macOS Apple Silicon
- Python: 3.11 or newer
- Local runtime: Ollama on loopback
- Validated model: `qwen2.5:7b`
- Primary traffic route: Guard Proxy to local Ollama
- Open WebUI: exactly 0.11.0, streaming off, native Ollama provider disabled for the protected
  model, routed through Guard Proxy
- Generic OpenAI-compatible local runtimes: experimental

Windows and Linux are unvalidated. Ollama, Open WebUI, and model weights are not bundled or
downloaded automatically.

## Install the Community prerelease

There is no PyPI release for this candidate. After the GitHub prerelease is published, download
the wheel from its assets and verify its SHA-256 against the release notes. Install the downloaded
wheel with the service extra:

```console
python3 -m venv .venv
.venv/bin/python -m pip install './secureinjections-0.6.0rc1-py3-none-any.whl[service]'
.venv/bin/secureinjections --version
.venv/bin/secureinjections doctor
```

Run these commands from the directory containing the downloaded wheel. Activate the environment
with `source .venv/bin/activate` before using the commands below. Install Ollama and
`qwen2.5:7b` separately; SecureInjections does not download them automatically.

## Start and evaluate

```console
secureinjections start
```

The browser shell opens on a loopback URL. It reports real service and integration state; loading
the UI does not make an integration active.

Useful commands:

```console
secureinjections status
secureinjections doctor
secureinjections inspect --text 'ordinary question' --source user --destination model
secureinjections integrations
```

In the browser:

1. Use **Files** to select and inspect one local file.
2. Use **Protection** for a basic guarded prompt interaction.
3. Use **Integrations** to activate the owned Guard Proxy when local Ollama is ready.
4. Use **Activity** to inspect bounded decisions without raw prompt or file content.

Stop the product with `Ctrl-C`. Only product-owned child processes are stopped.

## Privacy and local data

Normal product state lives under:

```text
~/Library/Application Support/SecureInjections/
```

Persisted state includes safe configuration, onboarding preference, and bounded audit/activity
metadata. Safe file references, Guard Proxy process ownership, and agent workflow state are
session-only. Raw prompts, model output, and blocked file content are not retained by the normal
privacy-bounded activity path.

## Security model

The key invariants are:

- Text is not authority.
- Peer data is not host authority.
- File content is not execution authority.
- Model output is not host authorization.
- Browser state is not a security capability.
- A listening port is not proof that SecureInjections owns or trusts a process.

Read [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md),
[privacy](docs/privacy.md), and [supported integrations](docs/supported-integrations.md).

## Current limitations

- Only explicitly routed, supported workflows are protected.
- REVIEW stops and cannot currently be approved in the product UI.
- Streaming Guard Proxy responses are unsupported.
- Open WebUI support is exact to the tested 0.11.0 topology.
- Detection may produce false positives and false negatives.
- No native installer, autostart daemon, automatic updater, or Level 2 workspace monitoring is
  included.

## Development and security reporting

The project repository is [JonaNorth/SecureInjections](https://github.com/JonaNorth/SecureInjections).
Report security issues through the private security-advisory process described in
[SECURITY.md](SECURITY.md); do not include real credentials, private data, or customer prompts.

## License status

Community is free and prepared under Apache-2.0; see [LICENSE](LICENSE) and the scoped
[NOTICE](NOTICE). Historical grants remain unchanged. Planned paid Pro source remains private.
Only the explicit Community boundary is included in this candidate.
