# @aauth/praca

The user's AAuth agent in MCP form. Praca is an MCP stdio server that brokers
discovery to AAuth resources, holds the user's agent identity (via
[`@aauth/local-keys`](../local-keys)), and relays interactions between
resources and the Person Server. The LLM sees a fixed eight-tool meta-surface;
new resources and operations are surfaced through the same tools regardless of
scale.

Design: see [`design.md`](./design.md).

## Install

```sh
npm install @aauth/praca
```

## v1 tool surface

```
find_resources(query)               → search the registry for discoverable resources
add_resource(host_or_url)           → fetch well-known, validate, add to your local set
list_resources()                    → your added resources
remove_resource(resource)           → praca-local unregister (does NOT revoke PS grants)
connect(resource)                   → pre-authorize (no-op for agent-token resources)
list_operations(resource, query?)   → free-text or path-prefix search over ops
get_operations(resource, op_ids[])  → batch fetch full schemas
invoke(resource, op_id, args)       → execute; surfaces an auth URL if needed
```

State lives at `~/.aauth/praca/`:

| Path | What |
|---|---|
| `resources.json` | added resources (L1) |
| `catalog/registry.json` | cached registry list (L2) |
| `catalog/{host}/{vocab}.json` | (future) cached vocab docs (L3) |
| `connections/{host}.json` | per-resource session state |

## Claude Code

Add to `.mcp.json` (or your Claude Code MCP config):

```json
{
  "mcpServers": {
    "praca": {
      "command": "npx",
      "args": ["-y", "@aauth/praca"]
    }
  }
}
```

Then ask Claude to e.g. "add `api-hubapi-com.hello-proxy.net`" → "list my
HubSpot contacts". Claude finds the resource via `find_resources` (or you
hand it the URL directly via `add_resource`), then runs `list_operations` /
`invoke`. The first invoke against an unauthorized `aauth-access-token`
resource returns a consent URL for you to open.

The MCP server stays up even with no identity configured and surfaces a
bootstrap message to the LLM on first tool call when `@aauth/bootstrap` hasn't
been run yet.

## Configuration

Identity comes from `@aauth/local-keys` (`~/.aauth/`) bootstrapped via
`npx @aauth/bootstrap`. Praca reads it lazily on first tool call. Override
hooks (all optional):

| Var | What |
|---|---|
| `PRACA_REGISTRY_URL` | registry URL (default `https://registry.aauth.dev`) |
| `PRACA_PS_URL` | Person Server URL (default: from local-keys agent config) |
| `PRACA_AGENT_URL` | agent provider URL (default: first configured) |
| `PRACA_AGENT_TOKEN` + `PRACA_AGENT_PRIVATE_JWK` (or `PRACA_AGENT_KEY_FILE`) | software-identity override that bypasses local-keys; intended for tests |

## Programmatic use

`@aauth/praca` is also importable as a library — useful for building tooling
on top of the same agent flow:

```ts
import {
  fetchResource,
  toL1Entry,
  invokeAtResource,
  buildConfigFromLocalKeys,
} from '@aauth/praca'

const cfg = await buildConfigFromLocalKeys()
const resource = toL1Entry(await fetchResource('api-hubapi-com.hello-proxy.net'))
const result = await invokeAtResource(cfg, resource, 'get-/crm/v3/objects/contacts_getPage', {})
```

## License

MIT
