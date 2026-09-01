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
import { renderUnicodeCompact } from 'uqr'
import { z } from 'zod'
import { planAccessMode } from './access-mode.js'
import type { AgentSetup } from './access-mode.js'
import { deleteAtAdmin, invokeAtResource } from './agent.js'
import type { InvokeResult, ProxyConfig } from './agent.js'
import { canonicalizeHost } from './host.js'
import { agentTokenPs } from './jwt.js'
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
  // Called when invoke encounters an interaction (authorization URL). May throw to
  // initiate a native protocol-level flow (e.g. MCP URL elicitation for cloud hosts).
  // For stdio hosts: open the OS browser and return; invoke falls back to returning
  // the URL as text. onComplete is called by the host when authorization finishes,
  // resolving any waiters registered via authPending.
  onInteraction?: (url: string, code: string, pollUrl: string, onComplete?: () => void | Promise<void>) => void | Promise<void>
  // Tracks in-flight authorization per resource. Implementations should survive
  // across MCP session DO instances (e.g. backed by a longer-lived UserStore DO).
  // checkAndWait blocks up to timeoutMs; register/resolve bracket the auth flow.
  authPending?: {
    checkAndWait(resource: string, timeoutMs: number): Promise<'ready' | 'waiting'>
    register(resource: string): Promise<void>
    resolve(resource: string): Promise<void>
  }
  // Supplies the local-part hint for the agent id. The stdio bin derives it
  // from the MCP client's name; omitted by hosts that allocate their own.
  agentLocal?: () => string | undefined
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

  // What this agent's setup can complete. An agent token with no `ps` claim has
  // no person server, so nothing beyond `agent-token` and `session-token` is
  // reachable — the listing tools say so up front instead of letting the LLM
  // plan against a resource that will 401.
  //
  // Peek only: a listing tool must not provoke an enclave signature to mint an
  // agent token. When nothing is resolved yet the annotation is simply omitted —
  // it is advisory, and `invoke` still refuses an unsatisfiable mode outright.
  function peekSetup(): AgentSetup | undefined {
    const cfg = identity.peek?.()
    return cfg ? { hasPersonServer: agentTokenPs(cfg.agentToken) !== undefined } : undefined
  }

  // The `skip_reason` field on a listed resource: present only when this agent
  // cannot complete the mode the resource declares. Advisory — an unrecognized
  // or absent access_mode never produces one.
  function skipReason(accessMode: string | undefined, setup: AgentSetup | undefined): string | undefined {
    if (!setup) return undefined
    const plan = planAccessMode(accessMode, setup)
    return plan.kind === 'unsatisfiable' ? plan.reason : undefined
  }

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

  // ── Resource lifecycle ──

  server.registerTool(
    'find_resources',
    {
      description: describeWithL1(
        'Search the AAuth registry for discoverable resources by free-text query against name/description. Returns each result tagged `added: true` if already in your local resource set. A result carrying `skip_reason` declares an access_mode this agent cannot complete — do not add or plan against it.',
      ),
      inputSchema: { query: z.string().optional() },
    },
    async ({ query }) => {
      const c = await getConfig()
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const setup: AgentSetup = { hasPersonServer: agentTokenPs(c.cfg.agentToken) !== undefined }
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
            const reason = skipReason(r.access_mode, setup)
            return {
              resource: host,
              name: r.name,
              description: r.description,
              access_mode: r.access_mode,
              added: added.has(host),
              ...(reason ? { skip_reason: reason } : {}),
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
        'Add an AAuth resource to your local set. Pass a bare host, host:port, or full URL — the agent proxy canonicalizes. Fetches the resource\'s well-known doc, validates, picks supported vocabularies. After adding: agent-token resources are immediately invokable; auth-token resources start an authorization flow on the first `invoke`.',
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
        'Return your locally added resources with name, description, access_mode, last_used, and how many vocabularies the agent proxy picked. A resource carrying `skip_reason` declares an access_mode this agent cannot complete — invoke will refuse it without calling out. Cheap; safe to call anytime.',
    },
    async () => {
      const setup = peekSetup()
      const entries = (await l1.list()).map((e) => {
        const reason = skipReason(e.access_mode, setup)
        return {
          resource: e.resource,
          name: e.name,
          description: e.description,
          access_mode: e.access_mode,
          vocabularies: e.picked_vocabs.map((v) => v.vocabUri),
          added: e.added,
          last_used: e.last_used,
          ...(reason ? { skip_reason: reason } : {}),
        }
      })
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

  // ── Operations ──

  server.registerTool(
    'list_operations',
    {
      description: describeWithL1(
        'List operations a resource exposes. Optional `query` is either free-text (matched against opId/summary/tags) or an OpenAPI path prefix (e.g. "/crm/v3/objects/contacts/*"). Returns summaries only — schemas are fetched via get_operation_schemas to keep token cost flat.\n\n' +
          'Each op carries `kind` (sync.request/async.send/async.receive) and `access_mode`, the credential that operation needs — read it before you plan:\n' +
          '- `agent-token` — no authorization step; the agent already holds what it needs.\n' +
          '- `person-token` — one call to the person server first; no user prompt in the common case.\n' +
          '- `session-token` — the resource runs its own login/consent flow once.\n' +
          '- `auth-token` — an authorization round trip through the person server; may prompt the user.\n' +
          '- `per-call` — the resource authorizes each invocation against that call\'s parameters. It WILL block on a person every time. Do not plan unattended work around these.\n\n' +
          '`budget: true` means invoking the operation draws down a spending budget. All of this is advisory — the resource may still challenge at runtime.',
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
    'get_operation_schemas',
    {
      description: describeWithL1(
        'Batch fetch full schemas (params, request body, response) for one or more operations on a resource. Separate from list_operations because schemas dominate token cost. Each detail also carries the operation\'s `access_mode` and `budget`, as list_operations returns them.',
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
        return text(`get_operation_schemas error: ${(err as Error).message}`)
      }
    },
  )

  server.registerTool(
    'invoke',
    {
      description: describeWithL1(
        'Invoke an operation on a resource. Pass `path_params`, `query`, `body` (object) as needed. If authorization is required, the client opens the auth URL automatically — call invoke again after authorization completes. async.receive operations return `subscribe_requires_subagent` (v.next). An operation whose access_mode this agent cannot complete is refused without any request being made, with the reason stated.',
      ),
      inputSchema: {
        resource: z.string(),
        op_id: z.string(),
        path_params: z.record(z.string(), z.string()).optional(),
        query: z.string().optional(),
        body: z.record(z.string(), z.unknown()).optional(),
      },
    },
    async ({ resource, op_id, path_params, query, body }) => {
      const c = await getConfig()
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      const invokeArgs = { pathParams: path_params, query, body }

      // If there's an in-flight authorization for this resource, wait up to 30s
      // for it to complete before hitting the resource/PS again. This avoids
      // creating new temporal state (codes, pending interactions) on every retry.
      if (await deps.authPending?.checkAndWait(found.l1.resource, 30_000) === 'waiting') {
        return text(
          `Authorization for ${found.l1.resource} is still in progress.\n\n` +
          `The user has not yet completed authorization. Try again in a moment.`,
        )
      }

      let result: InvokeResult
      try {
        result = await invokeAtResource(c.cfg, found.l1, op_id, invokeArgs)
      } catch (err) {
        return text(`invoke error: ${(err as Error).message}`)
      }

      // Case (c) of the access_mode plan: recognized, and this agent cannot
      // complete it. No request was made and none will be — say why and let the
      // LLM route around the resource rather than retry into a 401.
      if (result.kind === 'skipped') {
        return text(
          `Skipped ${result.resource} / ${result.opId}: ${result.reason}.\n\n` +
            `This operation's access_mode is "${result.mode}". Retrying will not help. ` +
            `Use a different resource or operation, or bootstrap an agent identity bound to a person server.`,
        )
      }

      if (result.kind === 'interaction') {
        // onComplete resolves the UserStore pending-auth waiter when the poll finishes.
        const onComplete = () => deps.authPending?.resolve(found.l1.resource)

        // onInteraction may throw (cloud: MCP URL elicitation) or return (stdio/fallback).
        await deps.onInteraction?.(result.interaction.url, result.interaction.code, result.interaction.pollUrl, onComplete)

        // Only reached if onInteraction returned (fallback path, not elicitation).
        await deps.authPending?.register(found.l1.resource)

        const authUrl = `${result.interaction.url}?code=${result.interaction.code}`
        const qr = renderUnicodeCompact(authUrl)
        return text(
          `Authorization required for ${found.l1.resource}.\n\n` +
          `IMPORTANT: You MUST do all of the following in your response:\n` +
          `1. Display the QR code below verbatim so the user can scan it.\n` +
          `2. Show the authorization URL so the user can open it.\n` +
          `3. Offer to open the URL using browser tools if available.\n` +
          `4. After showing the URL and QR code, automatically retry invoke — the server will wait up to 30 seconds for authorization to complete before responding.\n\n` +
          `Authorization URL: ${authUrl}\n\n` +
          `QR code:\n\n` +
          `\`\`\`\n${qr}\n\`\`\`\n\n` +
          `Retry invoke now.`,
        )
      }

      if (result.status >= 200 && result.status < 300) await l1.touch(found.l1.resource)
      return json({ status: result.status, body: result.body })
    },
  )

  server.registerTool(
    'reset_tokens',
    {
      description: describeWithL1(
        'Clear all stored upstream OAuth tokens for a resource. Use during testing to force a fresh upstream OAuth flow without touching PS consent state.',
      ),
      inputSchema: { resource: z.string() },
    },
    async ({ resource }) => {
      const c = await getConfig()
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      try {
        const res = await deleteAtAdmin(c.cfg, found.l1, '/admin/tokens')
        if (!res.ok) return text(`reset_tokens failed: ${res.status}`)
        const body = (await res.json()) as { cleared: number }
        return text(`Cleared ${body.cleared} token(s) for ${found.l1.resource}.`)
      } catch (err) {
        return text(`reset_tokens error: ${(err as Error).message}`)
      }
    },
  )
}
