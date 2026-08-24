# Public command reference

| Command | Purpose |
| --- | --- |
| `secureinjections --version` | Show the installed package/runtime version |
| `secureinjections guard inspect` | Inspect one typed content boundary |
| `secureinjections guard doctor` | Validate a Local Guard Profile and local runtime |
| `secureinjections guard local-agent` | Run one guarded local-agent request |
| `secureinjections guard demo-local-agent` | Run the safe local-agent demonstration |
| `secureinjections guard proxy-doctor` | Validate a Guard Proxy profile and upstream |
| `secureinjections guard proxy` | Start the loopback OpenAI-compatible Guard Proxy |
| `secureinjections integrations list` | List the static validated-integration registry |
| `secureinjections integrations open-webui status` | Show the Open WebUI support contract |
| `secureinjections integrations open-webui smoke` | Run the isolated Open WebUI 0.11.0 smoke |

Examples:

```bash
secureinjections guard inspect \
  --source retrieved_content --destination model \
  --text "untrusted content"
secureinjections guard doctor --config examples/secureinjections.local.yaml
secureinjections guard proxy-doctor --config examples/secureinjections.proxy.yaml
secureinjections integrations open-webui smoke \
  --config examples/integrations/open-webui.yaml
```

The `classifier` namespace contains advanced research workflows and is not required for product
runtime setup.
