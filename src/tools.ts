// The eight-tool v1 discovery surface (design.md §"Tool surface"), built against
// an injected dependency bundle so both the stdio bin and any HTTP host share
// one core. Each tool's description embeds the L1 snapshot taken at build time
// so the common path needs no extra round-trip.
//
// Transport-agnostic: no fs, no stdio, no child_process. The stdio bin
// (server.ts) supplies fs/local-keys deps + a browser-launch onInteraction;
// other hosts supply their own backends and surface interaction URLs however
// their transport allows.

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import { invokeAtResource, invokeAtResourceComplete } from './agent.js'
import type { ProxyConfig } from './agent.js'
import { canonicalizeHost } from './host.js'
import type { IdentityProvider } from './identity.js'
import { fetchRegistry } from './registry.js'
import type { RegistryCache } from './registry.js'
import {
  fetchResource,
  getOperationsForResource,
  listOperationsForResource,
  toL1Entry,
} from './resource.js'
import type { DocCache } from './resource.js'
import type { L1Entry, L1Store } from './store.js'

export interface ProxyDeps {
  l1: L1Store
  registryCache: RegistryCache
  identity: IdentityProvider
  // Optional shared/persistent L3 vocab-doc cache. Defaults (inside resource.ts)
  // to a process-wide in-memory cache when omitted.
  docCache?: DocCache
  // Side-channel for interaction URLs (e.g. open the OS browser). The URL is
  // also returned as text for the LLM regardless, so this is best-effort.
  onInteraction?: (url: string, code: string) => void
  // Supplies the local-part hint for the agent id. The stdio bin derives it
  // from the MCP client's name; omitted by hosts that allocate their own.
  agentLocal?: () => string | undefined
  // How `invoke` handles a required interaction.
  //   'surface' (default): non-blocking — return the interaction URL as text and
  //     let the caller drive it + re-invoke (stdio / browser behavior).
  //   'await': block — relay the interaction (onInteraction), poll until terminal
  //     (heartbeat each round via onPoll), and return the completed result on the
  //     original call. For HTTP hosts that hold a long-running tool call open.
  //
  // The callbacks receive an InteractionContext bound to THIS invoke request, so
  // the host can push messages to the client over the held connection (e.g. emit
  // an MCP progress notification carrying the interaction URL, and heartbeats).
  interaction?: {
    mode?: 'surface' | 'await'
    onInteraction?: (url: string, code: string, ctx: InteractionContext) => void | Promise<void>
    onPoll?: (elapsedMs: number, ctx: InteractionContext) => void | Promise<void>
    pollTimeoutMs?: number
  }
}

// Per-request hooks the host can use to talk to the client during an awaited
// interaction. `sendNotification` writes a JSON-RPC notification to the active
// transport; `progressToken` (if the client supplied one) correlates
// notifications/progress frames to this call.
export interface InteractionContext {
  sendNotification: (n: { method: string; params?: Record<string, unknown> }) => Promise<void>
  progressToken?: string | number
}

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] })
const json = (v: unknown) => text(JSON.stringify(v, null, 2))

const BOOTSTRAP_GUIDANCE = `The agent proxy has no AAuth identity on this machine yet.

To set one up, run:

  npx @aauth/bootstrap list

…then follow the setup skill:

  npx @aauth/bootstrap skill setup

That guide walks through generating a keypair (Secure Enclave / YubiKey / software),
binding a Person Server, and publishing the JWKS. When it's done, call this tool again.`

// Registers the agent proxy's eight tools on `server`. Async because the L1 snapshot
// embedded in tool descriptions is read once at build time from the (possibly
// async) store.
export async function buildProxyTools(server: McpServer, deps: ProxyDeps): Promise<void> {
  const { l1, registryCache, identity, docCache } = deps

  // Identity is resolved lazily per call; the provider owns any caching (which
  // must be per-principal — a shared process-global cache would leak identities
  // across tenants in a multi-user host).
  async function getConfig(): Promise<{ ok: true; cfg: ProxyConfig } | { ok: false }> {
    const status = await identity.resolve({ local: deps.agentLocal?.() })
    if (status.kind === 'needsBootstrap') return { ok: false }
    return { ok: true, cfg: status.cfg }
  }

  // Snapshot of L1 for tool descriptions, taken once at registration. Keeps the
  // always-loaded context cheap; list_resources is the authoritative fresh view.
  const snapshot = (await l1.list()).map((e) => e.resource)
  const l1Snapshot = snapshot.length === 0 ? 'no resources added yet' : snapshot.join(', ')
  const describeWithL1 = (base: string): string =>
    `${base}\n\nCurrently added resources: ${l1Snapshot}`

  async function requireL1(
    resource: string,
  ): Promise<{ ok: true; l1: L1Entry } | { ok: false; msg: string }> {
    const canonical = canonicalizeHost(resource)
    if (!canonical) return { ok: false, msg: `Invalid resource host: ${resource}` }
    const entry = await l1.get(canonical.host)
    if (!entry)
      return {
        ok: false,
        msg: `Resource not added: ${canonical.host}. Call add_resource("${canonical.host}") first.`,
      }
    return { ok: true, l1: entry }
  }

  // Surface an interaction: hand it to the side-channel (e.g. open a browser)
  // and return the URL as text so the LLM can relay it regardless of transport.
  function surfaceInteraction(url: string, code: string, retryTool: string) {
    const full = `${url}?code=${code}`
    deps.onInteraction?.(url, code)
    return text(
      `Authorization required. Open this URL to continue (your client may open it automatically), then call ${retryTool} again:\n${full}`,
    )
  }

  // ── Resource lifecycle ──

  server.registerTool(
    'find_resources',
    {
      description: describeWithL1(
        'Search the AAuth registry for discoverable resources by free-text query against name/description. Returns each result tagged `added: true` if already in your local resource set.',
      ),
      inputSchema: { query: z.string().optional() },
    },
    async ({ query }) => {
      const c = await getConfig()
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      try {
        const index = await fetchRegistry(c.cfg, registryCache)
        const q = (query ?? '').trim().toLowerCase()
        const added = new Set((await l1.list()).map((e) => e.resource))
        const filtered = index.resources
          .filter((r) => {
            if (!q) return true
            return (
              r.name.toLowerCase().includes(q) ||
              r.description.toLowerCase().includes(q) ||
              r.issuer.toLowerCase().includes(q)
            )
          })
          .map((r) => {
            const host = canonicalizeHost(r.issuer)?.host ?? r.issuer
            return {
              resource: host,
              name: r.name,
              description: r.description,
              access_mode: r.access_mode,
              added: added.has(host),
              ...(r.logo_uri ? { logo_uri: r.logo_uri } : {}),
            }
          })
        return json(filtered)
      } catch (err) {
        return text(`registry error: ${(err as Error).message}`)
      }
    },
  )

  server.registerTool(
    'add_resource',
    {
      description: describeWithL1(
        'Add an AAuth resource to your local set. Pass a bare host, host:port, or full URL — the agent proxy canonicalizes. Fetches the resource\'s well-known doc, validates, picks supported vocabularies. After adding: agent-token resources are immediately invokable; auth-token resources need `connect` or a first `invoke` that surfaces the auth URL.',
      ),
      inputSchema: { resource: z.string() },
    },
    async ({ resource }) => {
      try {
        const fetched = await fetchResource(resource)
        const entry = toL1Entry(fetched)
        await l1.upsert(entry)
        return json({
          added: entry.resource,
          access_mode: entry.access_mode,
          vocabularies: entry.picked_vocabs.map((v) => v.vocabUri),
          connect_required: entry.access_mode !== 'agent-token',
        })
      } catch (err) {
        return text(`add_resource error: ${(err as Error).message}`)
      }
    },
  )

  server.registerTool(
    'list_resources',
    {
      description:
        'Return your locally added resources with name, description, access_mode, last_used, and how many vocabularies the agent proxy picked. Cheap; safe to call anytime.',
    },
    async () => {
      const entries = (await l1.list()).map((e) => ({
        resource: e.resource,
        name: e.name,
        description: e.description,
        access_mode: e.access_mode,
        vocabularies: e.picked_vocabs.map((v) => v.vocabUri),
        added: e.added,
        last_used: e.last_used,
      }))
      return json(entries)
    },
  )

  server.registerTool(
    'remove_resource',
    {
      description: describeWithL1(
        'Remove a resource from your local set. Agent-proxy-local only — does NOT revoke any user grants at the Person Server; re-adding picks up existing grants transparently.',
      ),
      inputSchema: { resource: z.string() },
    },
    async ({ resource }) => {
      const canonical = canonicalizeHost(resource)
      if (!canonical) return text(`invalid host: ${resource}`)
      const removed = await l1.remove(canonical.host)
      return text(removed ? `removed ${canonical.host}` : `not found: ${canonical.host}`)
    },
  )

  server.registerTool(
    'connect',
    {
      description: describeWithL1(
        'Pre-authorize a resource — trigger a Person Server consent step if needed. No-op for agent-token resources. For auth-token resources, invokes a probe operation to surface the auth URL; returns "already connected" if the auth succeeds.',
      ),
      inputSchema: { resource: z.string() },
    },
    async ({ resource }) => {
      const c = await getConfig()
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      const { l1: entry } = found
      if (entry.access_mode === 'agent-token') {
        return text(`${entry.resource}: already connected (agent-token access mode)`)
      }
      const ops = await listOperationsForResource(entry, undefined, docCache)
      const probe = ops.find((o) => o.kind === 'sync.request' && o.method === 'GET')
      if (!probe) return text(`${entry.resource}: no probe operation available for connect`)
      const result = await invokeAtResource(c.cfg, entry, probe.opId, {})
      if (result.kind === 'interaction') {
        return surfaceInteraction(result.interaction.url, result.interaction.code, 'connect')
      }
      if (result.status >= 200 && result.status < 300) {
        await l1.touch(entry.resource)
        return text(`${entry.resource}: connected.`)
      }
      return text(
        `${entry.resource}: connect probe returned ${result.status} — ${JSON.stringify(result.body)}`,
      )
    },
  )

  // ── Operations ──

  server.registerTool(
    'list_operations',
    {
      description: describeWithL1(
        'List operations a resource exposes. Optional `query` is either free-text (matched against opId/summary/tags) or an OpenAPI path prefix (e.g. "/crm/v3/objects/contacts/*"). Returns summaries only — schemas are fetched via get_operations to keep token cost flat. Each op carries `kind` (sync.request/async.send/async.receive).',
      ),
      inputSchema: { resource: z.string(), query: z.string().optional() },
    },
    async ({ resource, query }) => {
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      try {
        const ops = await listOperationsForResource(found.l1, query, docCache)
        return json(ops)
      } catch (err) {
        return text(`list_operations error: ${(err as Error).message}`)
      }
    },
  )

  server.registerTool(
    'get_operations',
    {
      description: describeWithL1(
        'Batch fetch full schemas (params, request body, response) for one or more operations on a resource. Separate from list_operations because schemas dominate token cost.',
      ),
      inputSchema: { resource: z.string(), op_ids: z.array(z.string()) },
    },
    async ({ resource, op_ids }) => {
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      try {
        const details = await getOperationsForResource(found.l1, op_ids, docCache)
        return json(details)
      } catch (err) {
        return text(`get_operations error: ${(err as Error).message}`)
      }
    },
  )

  server.registerTool(
    'invoke',
    {
      description: describeWithL1(
        'Invoke an operation on a resource. Pass `path_params`, `query`, `body` (object) as needed. On first call to an unauthorized auth-token resource, returns an auth URL — open it, then call invoke again. async.receive operations return `subscribe_requires_subagent` (v.next).',
      ),
      inputSchema: {
        resource: z.string(),
        op_id: z.string(),
        path_params: z.record(z.string(), z.string()).optional(),
        query: z.string().optional(),
        body: z.record(z.string(), z.unknown()).optional(),
      },
    },
    async ({ resource, op_id, path_params, query, body }, extra) => {
      const c = await getConfig()
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      const invokeArgs = { pathParams: path_params, query, body }
      try {
        // 'await' mode: block — relay + poll the interaction to completion, return
        // the result on this original call. (HTTP hosts holding a long call open.)
        if (deps.interaction?.mode === 'await') {
          const inter = deps.interaction
          // Per-request context so host callbacks can push to the client (e.g.
          // emit notifications/progress carrying the interaction URL + heartbeats).
          const ctx: InteractionContext = {
            sendNotification: (n) => extra.sendNotification(n as never),
            progressToken: extra._meta?.progressToken,
          }
          const completed = await invokeAtResourceComplete(
            c.cfg,
            found.l1,
            op_id,
            (url, code) => inter.onInteraction?.(url, code, ctx),
            invokeArgs,
            5,
            inter.pollTimeoutMs ?? 180_000,
            (elapsedMs) => inter.onPoll?.(elapsedMs, ctx),
          )
          if (completed.status >= 200 && completed.status < 300) await l1.touch(found.l1.resource)
          return json(completed)
        }

        // 'surface' mode (default): non-blocking — return the URL as text.
        const result = await invokeAtResource(c.cfg, found.l1, op_id, invokeArgs)
        if (result.kind === 'interaction') {
          return surfaceInteraction(result.interaction.url, result.interaction.code, 'invoke')
        }
        if (result.status >= 200 && result.status < 300) await l1.touch(found.l1.resource)
        return json({ status: result.status, body: result.body })
      } catch (err) {
        return text(`invoke error: ${(err as Error).message}`)
      }
    },
  )
}
