// The eight-tool v1 discovery surface (design.md §"Tool surface"), built against
// an injected dependency bundle so both the stdio bin and any HTTP host share
// one core. Each tool's description embeds the L1 snapshot taken at build time
// so the common path needs no extra round-trip.
//
// 4.0.0 (ONBOARDING-PLAN.md, Track N): `add_resource` became `connect_resource`
// and `remove_resource` became `delete_resource` — the rename is the fix for a
// name that sounded free acquiring a credential-granting side effect (D9).
// Connecting BLOCKS (D8): it returns when the flow succeeds, times out, or
// fails; there is no queued outcome. The agent is the picker (D7): it asks in
// chat which services and which accounts, then calls connect once per
// (resource × account).
//
// Transport-agnostic: no fs, no stdio, no child_process. The stdio bin
// (server.ts) supplies fs/local-keys deps + a browser-launch onInteraction;
// other hosts supply their own backends and surface interaction URLs however
// their transport allows.

import type { McpServer, ServerContext } from '@modelcontextprotocol/server'
import { renderUnicodeCompact } from 'uqr'
import { z } from 'zod'
import { planAccessMode } from './access-mode.js'
import type { AgentSetup } from './access-mode.js'
import { connectAtResource, deleteAtAdmin, disconnectAll, invokeAtResource, listConnections, pollConnection } from './agent.js'
import type { ConnectOutcome, Interaction, InvokeResult, ProxyConfig } from './agent.js'
import { canonicalizeHost } from './host.js'
import { agentTokenPs } from './jwt.js'
import type { IdentityProvider } from './identity.js'
import { fetchRegistry } from './registry.js'
import type { RegistryCache, RegistryEntry } from './registry.js'
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
  // Called when invoke or connect encounters an interaction (authorization
  // URL). May throw to initiate a native protocol-level flow (e.g. MCP URL
  // elicitation for cloud hosts). For stdio hosts: open the OS browser and
  // return; the tool falls back to returning the URL as text. onComplete is
  // called by the host when authorization finishes, resolving any waiters
  // registered via authPending.
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
  // from the MCP client's name (passed in `hint.clientName` when the client
  // identified itself); omitted by hosts that allocate their own.
  agentLocal?: (hint: { clientName?: string }) => string | undefined
  // The registry watermark (N5/H2): what `find_resources` compares the
  // catalog against to report `new_since_last_seen`. Stored per USER by the
  // host; advanced on every read. Omitted → the field is not reported.
  lastSeen?: {
    get(): Promise<string | undefined>
    set(value: string): Promise<void>
  }
  // The bounded-blocking slice (D14 B2): how long connect_resource waits on
  // the PS before answering `still_pending`. MCP clients commonly time a tool
  // call out around 60 s, so the default stays well inside that.
  connectBudgetMs?: number
  // In-flight connects, per resource host, so a repeat connect_resource call
  // resumes the same PS pending record instead of starting a new flow. A host
  // that builds a fresh server per request (the hosted MCP) MUST back this
  // with per-user storage that outlives the request; the default is an
  // in-memory map per ProxyConfig (one process, one principal).
  connectState?: {
    get(host: string): Promise<ConnectFlight | undefined>
    set(host: string, flight: ConnectFlight): Promise<void>
    clear(host: string): Promise<void>
  }
}

export interface ConnectFlight {
  interaction: Interaction
  account?: string
  startedAt: number
}

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] })
const json = (v: unknown) => text(JSON.stringify(v, null, 2))

const DEFAULT_CONNECT_BUDGET_MS = 30_000
// A connect that has been in flight this long is abandoned (the PS pending
// record has a TTL of that order): `timed_out`, and the next call starts over.
const CONNECT_MAX_MS = 10 * 60_000

const BOOTSTRAP_GUIDANCE = `The agent proxy has no AAuth identity on this machine yet.

To set one up, run:

  npx @aauth/bootstrap list

…then follow the setup skill:

  npx @aauth/bootstrap skill setup

That guide walks through generating a keypair (Secure Enclave / YubiKey / software),
binding a Person Server, and publishing the JWKS. When it's done, call this tool again.`

// In-flight connects, per ProxyConfig (i.e. per principal — a process-global
// map would let one tenant resume another's flow in a multi-user host). The
// default when the host injects no connectState.
type InFlight = ConnectFlight
type FlightStore = NonNullable<ProxyDeps['connectState']>
const inflightByConfig = new WeakMap<ProxyConfig, Map<string, InFlight>>()
function memoryFlights(cfg: ProxyConfig): FlightStore {
  let m = inflightByConfig.get(cfg)
  if (!m) {
    m = new Map()
    inflightByConfig.set(cfg, m)
  }
  const map = m
  return {
    async get(host) {
      return map.get(host)
    },
    async set(host, flight) {
      map.set(host, flight)
    },
    async clear(host) {
      map.delete(host)
    },
  }
}

function interactionText(interaction: Interaction): string {
  const authUrl = `${interaction.url}?code=${interaction.code}`
  return (
    `Authorization URL: ${authUrl}\n\n` +
    `QR code:\n\n\`\`\`\n${renderUnicodeCompact(authUrl)}\n\`\`\``
  )
}

// Registers the agent proxy's eight tools on `server`. Async because the L1 snapshot
// embedded in tool descriptions is read once at build time from the (possibly
// async) store.
export async function buildProxyTools(server: McpServer, deps: ProxyDeps): Promise<void> {
  const { l1, registryCache, identity, docCache } = deps
  const budgetMs = deps.connectBudgetMs ?? DEFAULT_CONNECT_BUDGET_MS

  // Identity is resolved lazily per call; the provider owns any caching (which
  // must be per-principal — a shared process-global cache would leak identities
  // across tenants in a multi-user host).
  async function getConfig(ctx: ServerContext): Promise<{ ok: true; cfg: ProxyConfig } | { ok: false }> {
    const status = await identity.resolve({ local: deps.agentLocal?.({ clientName: clientName(ctx) }) })
    if (status.kind === 'needsBootstrap') return { ok: false }
    return { ok: true, cfg: status.cfg }
  }

  // The MCP client's self-reported name. 2026-07-28 requests carry it in the
  // per-request _meta envelope; 2025-era connections learned it at initialize.
  // Display/hint use only — never a security decision.
  function clientName(ctx: ServerContext): string | undefined {
    const envelope = ctx.mcpReq.envelope as { clientInfo?: { name?: string } } | undefined
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return envelope?.clientInfo?.name ?? server.server.getClientVersion()?.name
  }

  // Snapshot of L1 for tool descriptions, taken once at registration. Keeps the
  // always-loaded context cheap; list_resources is the authoritative fresh view.
  const snapshot = (await l1.list()).map((e) => e.resource)
  const l1Snapshot = snapshot.length === 0 ? 'no resources connected yet' : snapshot.join(', ')
  const describeWithL1 = (base: string): string =>
    `${base}\n\nCurrently connected resources: ${l1Snapshot}`

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
        msg: `Resource not connected: ${canonical.host}. Call connect_resource("${canonical.host}") first.`,
      }
    return { ok: true, l1: entry }
  }

  // The catalog view of one registry entry, tagged with whether it is already
  // in this person's set and whether this agent could complete its mode.
  function catalogRow(r: RegistryEntry, added: Set<string>, setup: AgentSetup) {
    const host = canonicalizeHost(r.issuer)?.host ?? r.issuer
    const reason = skipReason(r.access_mode, setup)
    return {
      resource: host,
      name: r.name,
      description: r.description,
      access_mode: r.access_mode,
      added: r.added,
      connected: added.has(host),
      ...(reason ? { skip_reason: reason } : {}),
      ...(r.logo_uri ? { logo_uri: r.logo_uri } : {}),
    }
  }

  // Re-read this person's connections from the resource and cache them on L1.
  async function refreshConnections(cfg: ProxyConfig, entry: L1Entry): Promise<L1Entry> {
    if (!entry.connection) return entry
    const listed = await listConnections(cfg, entry).catch(() => undefined)
    if (!listed || listed.kind !== 'rows') return entry
    const next = { ...entry, connections: listed.rows }
    await l1.upsert(next)
    return next
  }

  // ── Resource lifecycle ──

  server.registerTool(
    'find_resources',
    {
      description: describeWithL1(
        'Search the AAuth registry for discoverable resources by free-text query against name/description. With no query, returns the whole catalog plus `new_since_last_seen` — resources added since you last looked. Each result is tagged `connected: true` if already in your set. A result carrying `skip_reason` declares an access_mode this agent cannot complete — do not connect or plan against it.',
      ),
      inputSchema: z.object({ query: z.string().optional() }),
    },
    async ({ query }, ctx) => {
      const c = await getConfig(ctx)
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const setup: AgentSetup = { hasPersonServer: agentTokenPs(c.cfg.agentToken) !== undefined }
      try {
        const index = await fetchRegistry(c.cfg, registryCache)
        const q = (query ?? '').trim().toLowerCase()
        const added = new Set((await l1.list()).map((e) => e.resource))
        if (q) {
          const resources = index.resources
            .filter((r) => r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q) || r.issuer.toLowerCase().includes(q))
            .map((r) => catalogRow(r, added, setup))
          return json({ resources })
        }
        // The catalog, and what is new since this person last looked (N5/H2):
        // the watermark is the index's own `updated` stamp, kept by the host.
        const lastSeen = await deps.lastSeen?.get()
        const resources = index.resources.map((r) => catalogRow(r, added, setup))
        const fresh = lastSeen ? index.resources.filter((r) => r.added > lastSeen).map((r) => catalogRow(r, added, setup)) : undefined
        if (deps.lastSeen && index.updated) await deps.lastSeen.set(index.updated)
        return json({ resources, ...(fresh ? { new_since_last_seen: fresh } : {}) })
      } catch (err) {
        return text(`registry error: ${(err as Error).message}`)
      }
    },
  )

  server.registerTool(
    'connect_resource',
    {
      description: describeWithL1(
        'Connect an AAuth resource for this person. Pass a bare host, host:port, or full URL — the agent proxy canonicalizes. Fetches the resource\'s well-known doc, validates, picks supported vocabularies, and — when the resource fronts an upstream account the person must link — runs the link flow through their Person Server.\n\n' +
          'BLOCKS: returns `connected` when the flow completes, `still_pending` when the bounded wait elapses (call again to keep waiting), `timed_out` when it is abandoned, or an error. Never queues.\n\n' +
          'Before calling: ask the person which services and which accounts. When the resource declares `account_description`, you MUST pass `account` (the identifier it describes — a Google email, a GitHub username); when it does not, you MUST NOT (the account is chosen in the provider\'s own UI). Call once per (resource × account); a repeat on an already-linked account answers `ready` immediately. `scopes` optionally narrows or widens the request within the resource\'s declared `connection.scopes[]` (defaults are the read set; write scopes ride the first write). Agent-token resources need no link and answer `ready`.',
      ),
      inputSchema: z.object({
        resource: z.string(),
        account: z.string().optional(),
        scopes: z.array(z.string()).optional(),
      }),
    },
    async ({ resource, account, scopes }, ctx) => {
      const canonical = canonicalizeHost(resource)
      if (!canonical) return text(`invalid host: ${resource}`)
      let entry: L1Entry | undefined
      try {
        entry = await l1.get(canonical.host)
        if (!entry) {
          entry = toL1Entry(await fetchResource(resource))
          await l1.upsert(entry)
        }
      } catch (err) {
        return text(`connect_resource error: ${(err as Error).message}`)
      }
      const base = {
        resource: entry.resource,
        access_mode: entry.access_mode,
        vocabularies: entry.picked_vocabs.map((v) => v.vocabUri),
      }
      if (!entry.connection) return json({ ...base, outcome: 'ready', reason: 'no_connection_needed' })

      const c = await getConfig(ctx)
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const cfg = c.cfg
      const host = entry.resource
      const inflight = deps.connectState ?? memoryFlights(cfg)

      const finish = async (outcome: ConnectOutcome, flight?: InFlight) => {
        switch (outcome.kind) {
          case 'connected': {
            await inflight.clear(host)
            await deps.authPending?.resolve(host)
            const refreshed = await refreshConnections(cfg, entry as L1Entry)
            return json({ ...base, outcome: 'connected', ...(flight?.account ?? outcome.account ? { account: flight?.account ?? outcome.account } : {}), connections: refreshed.connections ?? [] })
          }
          case 'ready': {
            const refreshed = await refreshConnections(cfg, entry as L1Entry)
            return json({ ...base, outcome: 'ready', reason: outcome.reason, ...(outcome.account ? { account: outcome.account } : {}), ...(outcome.scopes ? { scopes: outcome.scopes } : {}), connections: refreshed.connections ?? [] })
          }
          case 'still_pending':
            await inflight.set(host, flight ?? { interaction: outcome.interaction, ...(account ? { account } : {}), startedAt: Date.now() })
            return text(
              `Connection to ${host} is still pending — the person has not finished at ${entry!.connection!.upstream_name ?? 'the upstream'} yet.\n\n` +
                `Call connect_resource("${host}"${account ? `, account: "${account}"` : ''}) again to keep waiting. If they need the link:\n\n` +
                interactionText(outcome.interaction),
            )
          case 'error':
            await inflight.clear(host)
            return json({ ...base, outcome: 'error', status: outcome.status, body: outcome.body })
          case 'interaction':
            // Reached only through the surfacing path below.
            return text(interactionText(outcome.interaction))
        }
      }

      // Resume an in-flight connect (D8: blocking governs what the agent sees;
      // the flow itself lives at the PS). The next slice of waiting, or give up.
      const existing = await inflight.get(host)
      if (existing) {
        if (Date.now() - existing.startedAt > CONNECT_MAX_MS) {
          await inflight.clear(host)
          await deps.authPending?.resolve(host)
          return json({ ...base, outcome: 'timed_out', detail: 'the person did not finish; call connect_resource again to start over' })
        }
        return finish(await pollConnection(cfg, existing.interaction, budgetMs), existing)
      }

      let outcome: ConnectOutcome
      try {
        outcome = await connectAtResource(cfg, entry, { ...(account ? { account } : {}), ...(scopes ? { scopes } : {}) })
      } catch (err) {
        return text(`connect_resource error: ${(err as Error).message}`)
      }
      if (outcome.kind !== 'interaction') return finish(outcome)

      // The PS wants the person. Hand the URL to the host (B3: may throw a
      // native elicitation; stdio: opens a browser), then wait the bounded
      // slice (B2) before answering. The PS also reaches an open wallet tab
      // on its own; the poll sees the result either way.
      const { interaction } = outcome
      const flight: InFlight = { interaction, ...(account ? { account } : {}), startedAt: Date.now() }
      await inflight.set(host, flight)
      await deps.onInteraction?.(interaction.url, interaction.code, interaction.pollUrl, () => deps.authPending?.resolve(host))
      await deps.authPending?.register(host)
      const waited = await pollConnection(cfg, interaction, budgetMs)
      if (waited.kind === 'still_pending') {
        return text(
          `Connecting ${host} needs the person to act.\n\n` +
            `IMPORTANT: You MUST do all of the following in your response:\n` +
            `1. Display the QR code below verbatim so the user can scan it.\n` +
            `2. Show the authorization URL so the user can open it.\n` +
            `3. Offer to open the URL using browser tools if available.\n` +
            `4. Then call connect_resource("${host}"${account ? `, account: "${account}"` : ''}) again — it waits up to ${Math.round(budgetMs / 1000)} seconds for them to finish.\n\n` +
            interactionText(interaction),
        )
      }
      return finish(waited, flight)
    },
  )

  server.registerTool(
    'list_resources',
    {
      inputSchema: z.object({}),
      description:
        'Return your connected resources with name, description, access_mode, last_used, how many vocabularies the agent proxy picked, and — for resources that front an upstream account — the person\'s `connections` (account, effective scopes, connected_at, status) as the resource reports them, plus the `connection` hint (`upstream_name`, `account_description`). CHECK THIS BEFORE PLANNING: if it is empty, ask the person which services and accounts to connect. A resource carrying `skip_reason` declares an access_mode this agent cannot complete — invoke will refuse it without calling out.',
    },
    async (_args: Record<string, never>, ctx: ServerContext) => {
      const setup = peekSetup()
      const c = await getConfig(ctx).catch(() => ({ ok: false as const }))
      const entries = await Promise.all(
        (await l1.list()).map(async (e) => {
          const fresh = c.ok ? await refreshConnections(c.cfg, e) : e
          const reason = skipReason(fresh.access_mode, setup)
          return {
            resource: fresh.resource,
            name: fresh.name,
            description: fresh.description,
            access_mode: fresh.access_mode,
            vocabularies: fresh.picked_vocabs.map((v) => v.vocabUri),
            added: fresh.added,
            last_used: fresh.last_used,
            ...(fresh.connection
              ? {
                  connection: {
                    ...(fresh.connection.upstream_name ? { upstream_name: fresh.connection.upstream_name } : {}),
                    ...(fresh.connection.account_description ? { account_description: fresh.connection.account_description } : {}),
                  },
                  connections: fresh.connections ?? [],
                }
              : {}),
            ...(reason ? { skip_reason: reason } : {}),
          }
        }),
      )
      return json(entries)
    },
  )

  server.registerTool(
    'delete_resource',
    {
      description: describeWithL1(
        'Delete a resource from your set: disconnects every upstream account the resource holds for this person (revoking the grant at the provider where the resource can — the result says what happened at each, and when the person must revoke at the provider themselves), then forgets the resource locally. Consents recorded at the Person Server are not touched.',
      ),
      inputSchema: z.object({ resource: z.string() }),
    },
    async ({ resource }, ctx) => {
      const canonical = canonicalizeHost(resource)
      if (!canonical) return text(`invalid host: ${resource}`)
      const entry = await l1.get(canonical.host)
      if (!entry) return text(`not found: ${canonical.host}`)
      let disconnected: Awaited<ReturnType<typeof disconnectAll>> = []
      if (entry.connection) {
        const c = await getConfig(ctx)
        if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
        await (deps.connectState ?? memoryFlights(c.cfg)).clear(canonical.host)
        try {
          disconnected = await disconnectAll(c.cfg, entry)
        } catch (err) {
          return text(`delete_resource error: ${(err as Error).message}`)
        }
      }
      await l1.remove(canonical.host)
      return json({ deleted: canonical.host, disconnected })
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
      inputSchema: z.object({ resource: z.string(), query: z.string().optional() }),
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
      inputSchema: z.object({ resource: z.string(), op_ids: z.array(z.string()) }),
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
        'Invoke an operation on a resource. Pass `path_params`, `query`, `body` (object) as needed. Pass `account` when the person has more than one account connected at the resource (list_resources shows them) — the resource refuses an unbound call with `account_required` naming the candidates. If authorization is required, the client opens the auth URL automatically — call invoke again after authorization completes. async.receive operations return `subscribe_requires_subagent` (v.next). An operation whose access_mode this agent cannot complete is refused without any request being made, with the reason stated.',
      ),
      inputSchema: z.object({
        resource: z.string(),
        op_id: z.string(),
        path_params: z.record(z.string(), z.string()).optional(),
        query: z.string().optional(),
        body: z.record(z.string(), z.unknown()).optional(),
        account: z.string().optional(),
      }),
    },
    async ({ resource, op_id, path_params, query, body, account }, ctx) => {
      const c = await getConfig(ctx)
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
        result = await invokeAtResource(c.cfg, found.l1, op_id, invokeArgs, account ? { account } : {})
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

        return text(
          `Authorization required for ${found.l1.resource}.\n\n` +
          `IMPORTANT: You MUST do all of the following in your response:\n` +
          `1. Display the QR code below verbatim so the user can scan it.\n` +
          `2. Show the authorization URL so the user can open it.\n` +
          `3. Offer to open the URL using browser tools if available.\n` +
          `4. After showing the URL and QR code, automatically retry invoke — the server will wait up to 30 seconds for authorization to complete before responding.\n\n` +
          interactionText(result.interaction) + `\n\nRetry invoke now.`,
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
      inputSchema: z.object({ resource: z.string() }),
    },
    async ({ resource }, ctx) => {
      const c = await getConfig(ctx)
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
