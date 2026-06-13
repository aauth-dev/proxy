# @aauth/praca

MCP stdio server that represents you as an agent in the [AAuth](https://github.com/DickHardt/AAuth) protocol. The LLM sees a fixed eight-tool surface; new resources and operations are surfaced through the same tools, regardless of how many you add.

Your AAuth signing key is bound to this machine via [`@aauth/local-keys`](https://www.npmjs.com/package/@aauth/local-keys) — non-extractable when a Secure Enclave, TPM, or YubiKey is available; software-backed otherwise. Praca holds no upstream service credentials.

Design and protocol details: [`design.md`](./design.md).

## Prerequisites

- Node ≥ 22.
- An AAuth identity on this machine. If none exists, praca's MCP server still starts; the first tool call returns a bootstrap prompt that points the LLM at [`@aauth/bootstrap`](https://www.npmjs.com/package/@aauth/bootstrap). Praca picks the identity up on the next call — no restart.

```sh
npx @aauth/bootstrap setup
```

## Install

### Claude Code

```json
{
  "mcpServers": {
    "praca": { "command": "npx", "args": ["-y", "@aauth/praca"] }
  }
}
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "praca": { "command": "npx", "args": ["-y", "@aauth/praca"] }
  }
}
```

### Cursor

Settings → MCP → Add new server, then add:

```json
{
  "praca": { "command": "npx", "args": ["-y", "@aauth/praca"] }
}
```

### Other MCP hosts

Any stdio MCP host: `npx -y @aauth/praca`.

## CLI flags

| Flag | Purpose |
|---|---|
| `--log` | Tee JSON-RPC frames to `~/.aauth/praca/logs/<ISO>.jsonl` for debugging. |

## Environment variables

All optional; sensible defaults come from `@aauth/local-keys`.

| Var | Default | Purpose |
|---|---|---|
| `PRACA_REGISTRY_URL` | `https://registry.aauth.dev` | AAuth resource registry |
| `PRACA_PS_URL` | from local-keys | Person Server URL |
| `PRACA_AGENT_URL` | first configured | Agent provider URL |
| `PRACA_AGENT_TOKEN` + `PRACA_AGENT_PRIVATE_JWK` (or `PRACA_AGENT_KEY_FILE`) | — | Test-only software-identity override that bypasses local-keys |

## License

MIT
