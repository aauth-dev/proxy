# Migrating to @aauth/proxy 3.0

3.0.0 moves `@aauth/proxy` from `@modelcontextprotocol/sdk` 1.x to the MCP TypeScript SDK v2 packages (`@modelcontextprotocol/server` 2.x). The tool surface, `ProxyDeps`, the storage/identity ports, and every non-MCP export are unchanged. What changes is the server object you hand to `buildProxyTools`.

## Dependencies

| 2.x | 3.0 |
|-----|-----|
| `@modelcontextprotocol/sdk ^1.29` | `@modelcontextprotocol/server ^2.0.0` |
| `zod ^4.0` | `zod ^4.2` (v2 converts schemas through zod's own `~standard.jsonSchema`; zod 4.0–4.1 falls back to the SDK's bundled zod and drops `.describe()` text) |

Remove `@modelcontextprotocol/sdk` from your package unless something else in your app still needs it. The two coexist under different names, but a v1 `McpServer` cannot be passed to 3.0.

## `buildProxyTools(server, deps)`

`server` must now be a v2 `McpServer`:

```ts
// 2.x
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
// 3.0
import { McpServer } from '@modelcontextprotocol/server'
```

Tools are registered with `z.object()`-wrapped input schemas (the v2 form). Wire-visible JSON Schema for each tool is unchanged.

## `ProxyDeps.agentLocal`

```ts
// 2.x
agentLocal?: () => string | undefined
// 3.0
agentLocal?: (hint: { clientName?: string }) => string | undefined
```

The proxy now passes the MCP client's self-reported name (from the 2026-07-28 per-request `_meta` envelope, or from the 2025-era `initialize` handshake) instead of expecting you to read `server.server.getClientVersion()`, which is deprecated in v2 and returns `undefined` on 2026-era connections. A zero-argument function still typechecks and keeps working.

## Hosting

- **stdio (`aauth-proxy` bin):** now served through `serveStdio` from `@modelcontextprotocol/server/stdio`. Both the 2025-era `initialize` handshake and the 2026-07-28 `server/discover` opening are accepted. No consumer change.
- **HTTP hosts:** `createMcpHandler` from `@modelcontextprotocol/server` builds one server per request from a factory. Call `buildProxyTools` inside the factory:

  ```ts
  import { createMcpHandler, McpServer } from '@modelcontextprotocol/server'

  const handler = createMcpHandler(async (ctx) => {
    const server = new McpServer({ name: 'my-host', version: '1.0.0' })
    await buildProxyTools(server, deps)   // deps may be derived from ctx.authInfo
    return server
  })
  // web-standard runtimes: return handler.fetch(request, { authInfo })
  ```

  `buildProxyTools` reads the L1 store once per call to embed the resource snapshot in tool descriptions, so under a per-request factory that read happens per request.

- **URL elicitation.** `onInteraction` implementations that throw `UrlElicitationRequiredError` should import it from `@modelcontextprotocol/server`. Under `createMcpHandler`'s default stateless legacy serving there is no server→client channel, so `server.server.createElicitationCompletionNotifier()` throws (client capabilities are unknown per request) — fall back to returning from `onInteraction`, which makes `invoke` return the authorization URL and QR code as text. The 2026-07-28 replacement is an `inputRequired(...)` result; `@aauth/proxy` does not yet emit one.

## Node

`@modelcontextprotocol/server` 2.x requires Node 20+. `@aauth/proxy` keeps `engines.node >=22`.
