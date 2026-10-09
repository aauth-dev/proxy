// The eight-tool v1 discovery surface (design.md §"Tool surface"), built against
// an injected dependency bundle so both the stdio bin and any HTTP host share
// one core. Each tool's description embeds the L1 snapshot taken at build time
// so the common path needs no extra round-trip.
//
// 4.0.0 (ONBOARDING-PLAN.md, Track N): `add_resource` became `connect_resource`
// and `remove_resource` became `delete_resource` — the rename is the fix for a
// name that sounded free acquiring a credential-granting side effect (D9).
// The agent is still the picker (D7): it asks in chat which services and which
// accounts.
//
// 4.1.0: `connect_resource` became `connect_resources` and takes a LIST. One
// call per (resource × account) meant the next request was only created after a
// model round trip, and the Person Server's consent clock used to start at
// creation — so a request made while another was waiting could expire before the
// person ever saw it (beta, 2026-09-11: a Gmail connect created behind two
// others was never surfaced). The list starts every item up front so the PS
// queues them in order and the wallet can show a depth. Each item still answers
// for itself; the call blocks for the bounded slice and the agent calls again
// with the same items to keep waiting.
//
// 5.2.0: a client that sends a progressToken gets ONE call for the whole list,
// kept alive by progress notifications; the bounded slice remains for clients
// that do not. Two items are live at a time, finished items are answered from
// connectState instead of the resource, and a URL is handed over once, at once.
//
// 5.7.0: one URL per person server per connect. Both live items are started
// before any URL goes out (the host's onInteraction no longer ends the call by
// throwing), the head's URL is handed over, and the other live codes are
// covered by it — the PS queues them for the person and the wallet tab works
// through the queue. A covered code gets its own URL only when the PS
// re-advertises it or no browser has taken it from the head of the queue.
// invoke hands its URL over natively too.
//
// 5.8.0 (MRTR-PLAN.md; first published as 5.8.1): answer the client only when the person has a URL to
// open that the client has not been handed, or when the work is finished.
// invoke holds a call with a progressToken until the authorization settles,
// as connect_resources already did. A declined or cancelled URL ends the wait
// at once. A 2025-era client that declared URL elicitation on `initialize`
// gets the -32042 error even when this server never saw that initialize (the
// host remembers it: `clientCapabilities`). A 2026-07-28 client that sends no
// progressToken is held across keepalive rounds — `input_required` with a
// `requestState` and nothing to fulfil — instead of `next` text. Every event
// on that path is logged (log.ts), so production says which clients follow it.
//
// Transport-agnostic: no fs, no stdio, no child_process. The stdio bin
// (server.ts) supplies fs/local-keys deps + a browser-launch onInteraction;
// other hosts supply their own backends and surface interaction URLs however
// their transport allows.

import { CLIENT_CAPABILITIES_META_KEY, UrlElicitationRequiredError, inputRequired } from '@modelcontextprotocol/server'
import type { ClientCapabilities, Icon, InputRequiredResult, McpServer, RegisteredTool, ServerContext, StandardSchemaWithJSON, ToolAnnotations, ToolCallback } from '@modelcontextprotocol/server'
import { renderUnicodeCompact } from 'uqr'
import { z } from 'zod'
import { planAccessMode } from './access-mode.js'
import type { AgentSetup } from './access-mode.js'
import { adoptSettled, connectAtResource, deleteAtAdmin, disconnectAll, forgetTokens, invokeAtResource, listConnections, listTokens, pollConnection } from './agent.js'
import type { ConnectOutcome, Interaction, InvokeResult, ProxyConfig } from './agent.js'
import { canonicalizeHost } from './host.js'
import { agentTokenPs } from './jwt.js'
import type { IdentityProvider } from './identity.js'
import { toolFields } from './log.js'
import type { ProxyLog } from './log.js'
import { MAX_MRTR_ROUNDS, inputResponseActions, readState, urlAction } from './mrtr.js'
import type { MrtrCodec, MrtrState } from './mrtr.js'
import { fetchRegistry, findEntry, isComing, orderCatalog } from './registry.js'
import type { RegistryCache, RegistryEntry, RegistryIndex } from './registry.js'
import {
  fetchResource,
  refreshResourceEntry,
  getOperationsForResource,
  listOperationsForResource,
  loadResourceContext,
  toL1Entry,
} from './resource.js'
import type { DocCache } from './resource.js'
import type { ScopePolicy } from './scope.js'
import type { L1Entry, L1Store } from './store.js'
import { isLive, operationName } from './tokens.js'
import type { TokenRecord, TokenStore } from './tokens.js'

export interface ProxyDeps {
  l1: L1Store
  registryCache: RegistryCache
  identity: IdentityProvider
  // Optional shared/persistent L3 vocab-doc cache. Defaults (inside resource.ts)
  // to a process-wide in-memory cache when omitted.
  docCache?: DocCache
  // Called when invoke or connect_resources hands an authorization URL to the
  // person — once per URL handed over, not once per code minted
  // (connect_resources covers the codes queued behind it). The tool then hands
  // it to the client itself: an MCP URL elicitation when the client declared
  // one, else the URL and a QR code as text. For stdio hosts: open the OS
  // browser and return. For cloud hosts: arm whatever runs in the background
  // and return. onComplete is called by the host when authorization finishes,
  // resolving any waiters registered via authPending.
  //
  // Before 5.7.0 a cloud host threw a URL elicitation from here. A throw is
  // still passed through (the URL is recorded as handed over first), but the
  // tool's own elicitation is the supported path.
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
  // The bounded-blocking slice (D14 B2): how long connect_resources waits on
  // the PS before answering `still_pending`, for a client that sent no
  // progressToken. Such a client may time a tool call out around 60 s, so the
  // default stays well inside that.
  connectBudgetMs?: number
  // How long one connect_resources call may wait when the client sent a
  // progressToken. The call walks the whole list and reports progress as items
  // land; this only bounds a runaway (each item already times out on its own).
  connectProgressBudgetMs?: number
  // How long an item covered by another item's URL may sit at the head of the
  // person's queue with no browser holding it before its own URL is handed
  // over. Default DEFAULT_CONNECT_DRAIN_MS; tests shorten it.
  connectDrainMs?: number
  // In-flight connects, per resource host, so a repeat connect_resources call
  // resumes the same PS pending record instead of starting a new flow. A host
  // that builds a fresh server per request (the hosted MCP) MUST back this
  // with per-user storage that outlives the request; the default is an
  // in-memory map per ProxyConfig (one process, one principal).
  //
  // getDone/setDone keep the items that finished recently, per host, so a
  // repeat call with the same items answers them without asking the resource
  // again. Optional: without them every repeat call re-POSTs finished items.
  connectState?: {
    get(host: string): Promise<ConnectFlight | undefined>
    set(host: string, flight: ConnectFlight): Promise<void>
    clear(host: string): Promise<void>
    getDone?(host: string): Promise<ConnectDone[]>
    setDone?(host: string, done: ConnectDone[]): Promise<void>
  }
  // Every token the agent holds (tokens.ts): person, auth and session tokens,
  // one per key. A host that builds a fresh server per request (the hosted MCP)
  // MUST back this with per-agent storage that outlives the request, or every
  // call obtains its tokens again. Copied onto the resolved ProxyConfig when
  // the identity provider left `cfg.tokens` unset; the default is an in-memory
  // store per ProxyConfig.
  tokens?: TokenStore
  // Which operations to declare at an authorization endpoint beyond the ones a
  // call needs (scope.ts). Copied onto the ProxyConfig like `tokens`. Default:
  // none — start with the operation, grow on demand.
  scopePolicy?: ScopePolicy
  // Event sink (log.ts): one `tool.call` per invocation of these tools, and the
  // AAuth exchange underneath — every signed request, resource metadata fetch,
  // person-token cache hit. The host logs the MCP boundary itself; this is the
  // other side of it. Copied onto the resolved ProxyConfig when the identity
  // provider left `cfg.log` unset.
  log?: ProxyLog
  // What the client declared on `initialize`, for a request that carries no
  // 2026-07-28 envelope (5.8.0). A host that builds a fresh server per
  // request never saw that initialize, so a 2025-era client that declared URL
  // elicitation got its URL back as text (Codex, opencode). Consulted before
  // the server's own getClientCapabilities(), never on a 2026-07-28 request —
  // the envelope is authoritative there. A declared `elicitation.url` sends
  // the URL as the -32042 URL elicitation error. Answer undefined when unsure: a
  // wrong "yes" turns a link into an error the person never sees, a wrong
  // "no" only costs a model turn.
  clientCapabilities?: (ctx: ServerContext) => Promise<ClientCapabilities | undefined>
  // The `requestState` codec: createRequestStateCodec<MrtrState>() from the
  // SDK (5.8.0). The host MUST pass the same codec's `verify` as
  // ServerOptions.requestState.verify on the McpServer, and the key must
  // reach every instance that may serve a retry. With it, every
  // `input_required` carries a state that counts rounds, and a 2026-07-28
  // client that sent no progressToken is held across keepalive rounds
  // (`input_required` with only a `requestState`) instead of answered with
  // `next`, up to MAX_MRTR_ROUNDS. Without it, neither.
  requestStateCodec?: MrtrCodec
}

export interface ConnectFlight {
  pollUrl: string
  /** Absent while the PS is reaching the person by its own channels. */
  interaction?: Interaction
  account?: string
  /** The scopes the item asked for, when it asked for any. */
  scopes?: string[]
  startedAt: number
  /** The interaction code last handed back to the client, so a resumed call does not hand it back again. */
  surfaced?: string
  /**
   * The code of another item's URL, already handed over, that reaches this
   * one too: the PS queues every pending interaction per person, and the
   * wallet tab that URL opens works through the queue. This item's own URL is
   * handed over only if the PS re-advertises it, or it reaches the head of the
   * queue and no browser picks it up (`headAt`).
   */
  coveredBy?: string
  /** When a poll first found this covered item at the head of the person's queue, not yet held by a browser. */
  headAt?: number
  /**
   * When this item's URL went to a 2025-era client as the -32042 error, and
   * from which tool. The next call that resumes the flight logs
   * `legacy.followup` and clears it: whether those clients retry is not known.
   */
  urlErrorAt?: number
  urlErrorTool?: string
}

// An item that finished connecting: `connected`, or the resource said it
// already was. Matched on account and scopes; both absent means the item named
// neither.
export interface ConnectDone {
  account?: string
  scopes?: string[]
  at: number
}

type ConnectItem = { resource: string; account?: string; scopes?: string[] }

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] })
const json = (v: unknown) => text(JSON.stringify(v, null, 2))

const DEFAULT_CONNECT_BUDGET_MS = 30_000
// One call walks the whole list when the client asked for progress (5.2.0).
// Returning after a 30 s slice made the model the scheduler: nothing started
// the next item until it called again, and each repeat call re-POSTed every
// item that had finished (prod, 2026-09-25: 13 Google resources, 12 calls, 22
// approvals — the resource answered "not connected" for an item it had stored
// seconds before, and the person connected it twice).
const DEFAULT_CONNECT_PROGRESS_BUDGET_MS = 30 * 60_000
// How long one poll may hold one live item before the loop turns to the other
// live item and reports progress. Also the heartbeat: Claude Code aborts an
// HTTP tool call that sends no progress for five minutes.
const POLL_SLICE_MS = 25_000
// A connect that has been in flight this long is abandoned (the PS pending
// record has a TTL of that order): `timed_out`, and the next call starts over.
const CONNECT_MAX_MS = 10 * 60_000
// How long a finished item answers `connected` from connectState instead of
// asking the resource again. Long enough to cover a repeat call in the same
// connect; short enough that a later deliberate reconnect reaches the upstream.
const CONNECT_DONE_TTL_MS = CONNECT_MAX_MS
// Ceiling on one connect_resources call. The whole fleet is ~45 resources and a
// person with two accounts at the Google family is already past 30 items; the
// cap is a guard against a runaway list, not a design limit.
const MAX_CONNECT_ITEMS = 64
// The live window (D14 revised, 2026-09-12; narrowed to one 2026-09-15; two
// since 5.2.0). How many connects may hold a PS interaction at once. The
// original design started the whole list up front on the premise that a queued
// PS pending cannot expire while it waits — but the resource-side interaction
// code carries its OWN few-minute life the PS queue does not govern, so a long
// list minted a pile of codes that expired before the person reached them (prod
// incident: 29 queued, the tail dead on arrival). Two live means the next item
// is already waiting at the PS when the person finishes the one in front of
// them, and at most one code counts down behind it.
const MAX_LIVE_CONNECTS = 2
// One URL per person server per connect (5.7.0). The PS queues every pending
// interaction for the person and drains the queue into the tab the first URL
// opened, so a second URL is a second tab for codes the first already holds
// (prod, 2026-09-28: four items, two URL elicitations, the wallet tab already
// held both codes). An item covered by a URL gets its own only when the PS
// re-advertises it, or when it has been at the head of the queue this long
// with no browser holding it (poll `status: 'pending'`, not `'interacting'`).
// The PS sends a waiting tab every queued code when it connects and the tab
// acks them within a second (16:17:19.8 → 16:17:20 in that incident), but a
// poll held open by `Prefer: wait=20` answers with the record as it was when
// the poll arrived — up to 20 s old. Thirty seconds after first seeing the item
// at the head, a `pending` answer is from at least ten seconds after it got
// there: long enough for an open tab to have taken it.
const DEFAULT_CONNECT_DRAIN_MS = 30_000

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
const inflightByConfig = new WeakMap<ProxyConfig, { flights: Map<string, InFlight>; done: Map<string, ConnectDone[]> }>()
function memoryFlights(cfg: ProxyConfig): FlightStore {
  let m = inflightByConfig.get(cfg)
  if (!m) {
    m = { flights: new Map(), done: new Map() }
    inflightByConfig.set(cfg, m)
  }
  const { flights, done } = m
  return {
    async get(host) {
      return flights.get(host)
    },
    async set(host, flight) {
      flights.set(host, flight)
    },
    async clear(host) {
      flights.delete(host)
    },
    async getDone(host) {
      return done.get(host) ?? []
    },
    async setDone(host, marks) {
      if (marks.length) done.set(host, marks)
      else done.delete(host)
    },
  }
}

const sameScopes = (a: string[] | undefined, b: string[] | undefined): boolean =>
  (a ?? []).length === (b ?? []).length && (a ?? []).every((s) => (b ?? []).includes(s))

// The recent finish that answers this item, if any.
function doneFor(marks: ConnectDone[], item: ConnectItem, now: number): ConnectDone | undefined {
  return marks.find((m) => now - m.at < CONNECT_DONE_TTL_MS && m.account === item.account && sameScopes(m.scopes, item.scopes))
}

// The auth tokens held at one resource, as list_resources shows them: what each
// grants and how much of it is left. Never the token itself.
function authorizationsAt(held: TokenRecord[], resource: string): { authorizations?: unknown[] } {
  const now = Math.floor(Date.now() / 1000)
  const rows = held
    .filter((t) => t.kind === 'auth' && t.resource === resource && isLive(t, now))
    .map((t) => ({
      ...(t.account ? { account: t.account } : {}),
      ...(t.granted ? { operations: t.granted.operations.map(operationName) } : {}),
      ...(t.per_call ? { per_call: t.per_call.operations.map(operationName) } : {}),
      ...(!t.granted && !t.per_call && t.scope ? { scope: t.scope } : {}),
      ...(t.budget
        ? { budget: { ...(t.budget.remaining !== undefined ? { remaining: t.budget.remaining } : {}), amount: t.budget.amount, unit: t.budget.unit } }
        : {}),
      ...(t.exp !== undefined ? { expires_in: t.exp - now } : {}),
    }))
  return rows.length ? { authorizations: rows } : {}
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
  const progressBudgetMs = deps.connectProgressBudgetMs ?? DEFAULT_CONNECT_PROGRESS_BUDGET_MS
  const drainMs = deps.connectDrainMs ?? DEFAULT_CONNECT_DRAIN_MS
  const codec = deps.requestStateCodec

  // Identity is resolved lazily per call; the provider owns any caching (which
  // must be per-principal — a shared process-global cache would leak identities
  // across tenants in a multi-user host).
  async function getConfig(ctx: ServerContext): Promise<{ ok: true; cfg: ProxyConfig } | { ok: false }> {
    const status = await identity.resolve({ local: deps.agentLocal?.({ clientName: clientName(ctx) }) })
    if (status.kind === 'needsBootstrap') return { ok: false }
    // In place, not a copy: the default token and in-flight stores are WeakMaps
    // keyed on the config object's identity, so a spread here would lose them.
    if (deps.log && !status.cfg.log) status.cfg.log = deps.log
    if (deps.tokens && !status.cfg.tokens) status.cfg.tokens = deps.tokens
    if (deps.scopePolicy && !status.cfg.scopePolicy) status.cfg.scopePolicy = deps.scopePolicy
    return { ok: true, cfg: status.cfg }
  }

  // Every tool goes through here so each call is reported once, with the
  // identifiers it named and how it ended — including the URL-elicitation
  // throw, which is a normal outcome (the client opens the URL), not a fault.
  // Mirrors McpServer.registerTool's primary (Standard Schema) signature —
  // the method is overloaded, so a plain `typeof` alias would not type-check.
  function registerTool<OutputArgs extends StandardSchemaWithJSON, InputArgs extends StandardSchemaWithJSON | undefined = undefined>(
    name: string,
    config: {
      title?: string
      description?: string
      inputSchema?: InputArgs
      outputSchema?: OutputArgs
      annotations?: ToolAnnotations
      icons?: Icon[]
      _meta?: Record<string, unknown>
    },
    handler: ToolCallback<InputArgs>,
  ): RegisteredTool {
    const wrapped = async (...cbArgs: unknown[]) => {
      const started = Date.now()
      const fields = toolFields(name, cbArgs.length > 1 ? cbArgs[0] : undefined)
      try {
        const result = (await (handler as (...a: unknown[]) => unknown)(...cbArgs)) as { isError?: boolean; resultType?: string }
        deps.log?.('tool.call', {
          ...fields,
          ok: !result?.isError,
          // A URL elicitation on the 2026-07-28 revision: the client opens it and calls again.
          ...(result?.resultType === 'input_required' ? { outcome: 'input_required' } : {}),
          duration_ms: Date.now() - started,
        })
        return result
      } catch (e) {
        const error = e instanceof UrlElicitationRequiredError ? 'url_elicitation' : ((e as Error)?.name ?? 'error')
        deps.log?.('tool.call', { ...fields, ok: false, error, duration_ms: Date.now() - started })
        throw e
      }
    }
    return server.registerTool(name, config, wrapped as unknown as ToolCallback<InputArgs>)
  }

  // The MCP client's self-reported name. 2026-07-28 requests carry it in the
  // per-request _meta envelope; 2025-era connections learned it at initialize.
  // Display/hint use only — never a security decision.
  function clientName(ctx: ServerContext): string | undefined {
    const envelope = ctx.mcpReq.envelope as { clientInfo?: { name?: string } } | undefined
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return envelope?.clientInfo?.name ?? server.server.getClientVersion()?.name
  }

  // Snapshot of L1 for tool descriptions, taken once at registration and never
  // refreshed: connect_resources and delete_resource do not rewrite
  // descriptions (a tools/list_changed would reload every tool and drop the
  // client's prompt cache). Labelled as a snapshot so the model does not trust
  // it after a connect; list_resources is the authoritative fresh view.
  const snapshot = (await l1.list()).map((e) => e.resource)
  const l1Snapshot = snapshot.length === 0 ? 'none' : snapshot.join(', ')
  const describeWithL1 = (base: string): string =>
    `${base}\n\nConnected when this session started: ${l1Snapshot}. Call list_resources for the current set.`

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
        msg: `Resource not connected: ${canonical.host}. Call connect_resources({ items: [{ resource: "${canonical.host}" }] }) first.`,
      }
    return { ok: true, l1: await refreshEntry(entry) }
  }

  // The stored entry while its metadata is fresh, otherwise re-read from the
  // resource's well-known per its Cache-Control (resource.ts
  // refreshResourceEntry). An entry with no picked vocabularies is re-read
  // whatever its age: that is what a resource added before this build supported
  // its vocabulary looks like.
  async function refreshEntry(entry: L1Entry): Promise<L1Entry> {
    const { entry: next, changed } = await refreshResourceEntry(entry, { log: deps.log })
    if (changed) await l1.upsert(next)
    return next
  }

  // The catalog view of one registry entry, tagged with whether it is already
  // in this person's set and whether this agent could complete its mode.
  //
  // A coming entry (registry `availability` set) is listed for what it is —
  // a resource that does not exist yet, or is built but gated by its provider
  // — with the reason verbatim and how many people have registered interest.
  // Its access_mode is not planned against, so it carries no skip_reason.
  function catalogRow(r: RegistryEntry, setup: AgentSetup) {
    const host = catalogHost(r)
    const coming = isComing(r)
    const reason = coming ? undefined : skipReason(r.access_mode, setup)
    return {
      resource: host,
      name: r.name,
      description: r.description,
      access_mode: r.access_mode,
      added: r.added,
      // So the first connect names the account instead of learning it from an
      // `account_required` 400 (2026-09-25: 13 Google connects, all refused).
      ...(r.account_description ? { account_description: r.account_description } : {}),
      ...(r.upstream ? { upstream: r.upstream } : {}),
      ...(coming
        ? { availability: r.availability, interest_count: r.interest_count ?? 0 }
        : {}),
      ...(reason ? { skip_reason: reason } : {}),
      ...(r.logo_uri ? { logo_uri: r.logo_uri } : {}),
    }
  }

  const catalogHost = (r: RegistryEntry): string => canonicalizeHost(r.issuer)?.host ?? r.issuer

  // Connected: in this agent's set and callable. A resource that needs no
  // upstream link is callable once added; one that needs a link is callable
  // once the person has one on record. A resource added by a connect that did
  // not finish is not connected, so find_resources still offers it.
  const isConnected = (e: L1Entry): boolean => !e.connection || (e.connections?.length ?? 0) > 0

  // A resource's `{"error":"account_required"}` refusal: what the account
  // must be, from the body or else the resource's metadata. Undefined when
  // neither says, and the refusal stays an `error` with its body.
  const accountRequired = (body: unknown, e: L1Entry): string | undefined => {
    const b = body as { error?: unknown; account_description?: unknown } | undefined
    if (!b || typeof b !== 'object' || b.error !== 'account_required') return undefined
    if (typeof b.account_description === 'string') return b.account_description
    return e.connection?.account_description
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

  // ── One call's waits (5.8.0) ──
  //
  // What a tool call that may hold carries across its waits: the progress it
  // has sent, the round it is on, and whether the client has stopped
  // listening. `waiting` brackets a hold or a poll, so an abort inside one is
  // logged as `call.aborted` — how long each client lets a call run is not
  // known, and this is how it is measured.
  type Call = Awaited<ReturnType<typeof beginCall>>
  async function beginCall(tool: string, ctx: ServerContext) {
    const started = Date.now()
    const progressToken = ctx.mcpReq._meta?.progressToken
    const state = await readState(ctx, codec, tool)
    if (state) {
      const actions = inputResponseActions(ctx)
      deps.log?.('mrtr.retry', {
        tool,
        round: state.round,
        ms_since_previous: started - state.at,
        ...(actions ? { input_responses: actions } : {}),
      })
    }
    let sent = 0
    let lastSentAt: number | undefined
    let waitingOn: string[] | undefined
    ctx.mcpReq.signal?.addEventListener(
      'abort',
      () => {
        if (!waitingOn) return
        const now = Date.now()
        deps.log?.('call.aborted', {
          tool,
          hosts: waitingOn,
          ms_since_start: now - started,
          progress_sent: sent,
          ...(lastSentAt !== undefined ? { last_progress_ms_ago: now - lastSentAt } : {}),
        })
      },
      { once: true },
    )
    return {
      tool,
      ctx,
      started,
      progressToken,
      // A 2026-07-28 request: it carries the per-request envelope.
      modern: ctx.mcpReq.envelope !== undefined,
      state,
      // The round an `input_required` returned now would be.
      round: (state?.round ?? 0) + 1,
      get sent() {
        return sent
      },
      // Progress, for a client that asked for it. `progress` counts
      // notifications, not items: the spec requires it to increase with
      // every notification, and a heartbeat moves no item.
      async report(message: string): Promise<void> {
        if (progressToken === undefined) return
        sent += 1
        lastSentAt = Date.now()
        await ctx.mcpReq.notify({ method: 'notifications/progress', params: { progressToken, progress: sent, message } }).catch(() => {})
      },
      waiting(hosts: string[] | undefined): void {
        waitingOn = hosts
      },
      aborted: (): boolean => ctx.mcpReq.signal?.aborted === true,
    }
  }

  // A 2026-07-28 client that sent no progressToken has no way to keep a call
  // open past its own timeout; a keepalive round ends the HTTP request but not
  // the call — its MCP client retries at once with the state.
  const keepsAlive = (call: Call): boolean =>
    codec !== undefined && call.modern && call.progressToken === undefined && call.round <= MAX_MRTR_ROUNDS

  // The state an `input_required` returned now carries.
  async function mint(call: Call, hosts: string[], codes: string[], kind: 'url' | 'keepalive'): Promise<string | undefined> {
    if (!codec) return undefined
    const now = Date.now()
    const startedAt = call.state?.started_at ?? now
    const state: MrtrState = { tool: call.tool, hosts, codes, round: call.round, started_at: startedAt, at: now }
    deps.log?.('mrtr.input_required', { tool: call.tool, kind, round: call.round, hosts, codes, ms_since_round_1: now - startedAt })
    return codec.mint(state, call.ctx)
  }

  // The keepalive round: nothing for the client to fulfil, only the state.
  async function keepalive(call: Call, hosts: string[], codes: string[]): Promise<InputRequiredResult> {
    const requestState = (await mint(call, hosts, codes, 'keepalive')) as string
    return inputRequired({ requestState })
  }

  // A later call resumed a flight whose URL went out as -32042: the client
  // came back. Logged once per flight.
  async function followup(call: Call, inflight: FlightStore, host: string, flight: InFlight): Promise<InFlight> {
    if (flight.urlErrorAt === undefined) return flight
    deps.log?.('legacy.followup', {
      tool: call.tool,
      hosts: [host],
      ms_since_url_error: Date.now() - flight.urlErrorAt,
      same_tool: flight.urlErrorTool === call.tool,
    })
    const { urlErrorAt: _a, urlErrorTool: _t, ...rest } = flight
    await inflight.set(host, rest)
    return rest
  }

  // invoke's wait on an in-flight authorization. Held, for a client that sent
  // a progressToken: a slice at a time with progress after each, until the
  // pending settles, the PS advertises a code the client has not been handed
  // (a new URL for the person), CONNECT_MAX_MS from the flight's start, or the
  // client goes away. Otherwise one bounded slice, as before 5.8.0.
  async function waitOnFlight(
    call: Call,
    cfg: ProxyConfig,
    inflight: FlightStore,
    host: string,
    flight: InFlight,
  ): Promise<{ kind: 'outcome'; outcome: ConnectOutcome } | { kind: 'timed_out' } | { kind: 'aborted' }> {
    call.waiting([host])
    try {
      if (call.progressToken === undefined) {
        return { kind: 'outcome', outcome: await pollConnection(cfg, flight.interaction ?? flight.pollUrl, budgetMs, undefined, { signal: call.ctx.mcpReq.signal }) }
      }
      const started = Date.now()
      let slices = 0
      let end = 'settled'
      deps.log?.('hold.start', { tool: call.tool, hosts: [host], progress_token: true })
      try {
        let current = flight
        for (;;) {
          if (call.aborted()) {
            end = 'aborted'
            return { kind: 'aborted' }
          }
          const remaining = current.startedAt + CONNECT_MAX_MS - Date.now()
          if (remaining <= 0) {
            end = 'timed_out'
            return { kind: 'timed_out' }
          }
          // Stop early on an advertised code the client has not been handed.
          // A PS may re-advertise a handed-over code on every poll, and that
          // is not a new URL.
          const handed = !!current.interaction && current.surfaced === current.interaction.code
          const polled = await pollConnection(cfg, current.interaction ?? current.pollUrl, Math.min(remaining, POLL_SLICE_MS), undefined, {
            stopOnAdvertise: true,
            ...(handed ? { except: current.surfaced } : {}),
            signal: call.ctx.mcpReq.signal,
          })
          slices += 1
          if (polled.kind !== 'still_pending') {
            end = polled.kind === 'connected' ? 'settled' : 'gone'
            return { kind: 'outcome', outcome: polled }
          }
          if (polled.advertised && polled.interaction && polled.interaction.code !== current.surfaced) {
            end = 'url'
            return { kind: 'outcome', outcome: polled }
          }
          current = { ...current, pollUrl: polled.pollUrl, ...(polled.interaction ? { interaction: polled.interaction } : {}) }
          await inflight.set(host, current)
          await call.report(`Waiting for the person to authorize ${host}`)
        }
      } finally {
        deps.log?.('hold.end', { tool: call.tool, hosts: [host], slices, progress_sent: call.sent, outcome: end, duration_ms: Date.now() - started })
      }
    } finally {
      call.waiting(undefined)
    }
  }

  // Hand an authorization URL to the client as a native prompt, or answer
  // undefined to let the caller fall back to text + QR.
  //
  // Which mechanism is available depends on the era AND on what the client
  // declared, and the two gates are not the same:
  //   * 2026-07-28 (the request carries a `_meta` envelope) has no server→client
  //     request channel. An elicitation rides an `input_required` result, and
  //     the SDK refuses it with -32021 unless the client declared
  //     `elicitation.url`. A refusal is worse than text — the person would see
  //     an error instead of a link — so check first and fall back instead.
  //     The result carries a `requestState` that counts the round; past
  //     MAX_MRTR_ROUNDS the URL goes back as text, inside the client's cap.
  //   * 2025-era connections still take the push model: the SDK rethrows
  //     UrlElicitationRequiredError (-32042) unmodified, with no capability
  //     gate of its own. Clients that implement -32042 handle it even when they
  //     under-declare (Claude Code 2.1.268 ships the retry loop while declaring
  //     a bare `elicitation:{}`), so a declared `elicitation` key is enough.
  //     What was declared comes from the host's `clientCapabilities` (it
  //     remembers `initialize` for a server built per request), else from this
  //     server's own initialize. A remembered declaration counts only with
  //     `elicitation.url`. The error's message carries the URL and code, so a
  //     client that only shows the error still gives the model a link.
  // Form mode is deliberately not attempted: it is gated on `elicitation.form`
  // the same way, and handing over a link is not what form mode is for.
  async function surfaceNatively(
    call: Call,
    inflight: FlightStore,
    host: string,
    interaction: Interaction,
    message: string,
  ): Promise<InputRequiredResult | undefined> {
    const { ctx } = call
    const url = `${interaction.url}?code=${interaction.code}`
    if (call.modern) {
      // On 2026-07-28 the request's own envelope says what the client
      // declared. serveStdio does not backfill the instance from it (the stdio
      // bin saw `undefined` here and fell back to text); createMcpHandler does.
      const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined
      const caps = envelope?.[CLIENT_CAPABILITIES_META_KEY] as ClientCapabilities | undefined
      if ((caps?.elicitation as { url?: unknown } | undefined)?.url === undefined) return undefined
      if (codec && call.round > MAX_MRTR_ROUNDS) return undefined
      const requestState = await mint(call, [host], [interaction.code], 'url')
      return inputRequired({
        inputRequests: { connect: inputRequired.elicitUrl({ message, url }) },
        ...(requestState ? { requestState } : {}),
      })
    }
    // Remembered by the host: only a declared `elicitation.url` counts. The
    // record may be a client that declared form mode only (Cursor), and a
    // -32042 it does not handle is a link the person never sees.
    const remembered = await deps.clientCapabilities?.(ctx)
    if (remembered !== undefined) {
      if ((remembered.elicitation as { url?: unknown } | undefined)?.url === undefined) return undefined
    } else {
      // This server's own initialize. Deprecated accessor, but the supported
      // per-request one otherwise.
      let caps: ClientCapabilities | undefined
      try {
        caps = server.server.getClientCapabilities()
      } catch {
        return undefined
      }
      if (!caps?.elicitation) return undefined
    }
    const flight = await inflight.get(host)
    if (flight) await inflight.set(host, { ...flight, urlErrorAt: Date.now(), urlErrorTool: call.tool })
    deps.log?.('legacy.url_error', { tool: call.tool, hosts: [host], code: interaction.code, caps_source: 'initialize' })
    throw new UrlElicitationRequiredError(
      [{ mode: 'url' as const, message, elicitationId: crypto.randomUUID(), url }],
      `${message} URL: ${url} (code ${interaction.code})`,
    )
  }

  // ── Resource lifecycle ──

  registerTool(
    'find_resources',
    {
      description: describeWithL1(
        'Search the AAuth registry for resources you are not connected to yet, by free-text query against name, description, host and `upstream` (the API a resource fronts, e.g. api.github.com). With no query, returns the whole catalog plus `new_since_last_seen` — resources added since you last looked. Resources you are connected to (in your set and callable) are left out: list_resources shows those. A result carrying `account_description` needs an account named on connect: ask the person for it (a Google email, a GitHub username) and pass it as `account` in connect_resources. A result carrying `skip_reason` declares an access_mode this agent cannot complete — do not connect or plan against it.\n\nAvailable resources come first. A result carrying `availability` is COMING: not yet public — unbuilt, or built but gated by its provider — and `availability` says why, verbatim. Read this freely — before telling the person a service is impossible, check whether it is listed as coming, including by `upstream`. Do not register interest or send feedback on the person\'s behalf unless they actually asked for that resource.',
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
        const connected = new Set((await l1.list()).filter(isConnected).map((e) => e.resource))
        const ordered = orderCatalog(index.resources).filter((r) => !connected.has(catalogHost(r)))
        if (q) {
          const resources = ordered
            .filter(
              (r) =>
                r.name.toLowerCase().includes(q) ||
                r.description.toLowerCase().includes(q) ||
                r.issuer.toLowerCase().includes(q) ||
                (r.upstream?.toLowerCase().includes(q) ?? false),
            )
            .map((r) => catalogRow(r, setup))
          return json({ resources })
        }
        // The catalog, and what is new since this person last looked (N5/H2):
        // the watermark is the index's own `updated` stamp, kept by the host.
        const lastSeen = await deps.lastSeen?.get()
        const resources = ordered.map((r) => catalogRow(r, setup))
        const fresh = lastSeen ? ordered.filter((r) => r.added > lastSeen).map((r) => catalogRow(r, setup)) : undefined
        if (deps.lastSeen && index.updated) await deps.lastSeen.set(index.updated)
        return json({ resources, ...(fresh ? { new_since_last_seen: fresh } : {}) })
      } catch (err) {
        return text(`registry error: ${(err as Error).message}`)
      }
    },
  )

  registerTool(
    'connect_resources',
    {
      description: describeWithL1(
        'Connect one or more AAuth resources for this person in ONE call. Pass `items`, each `{resource, account?, scopes?}` — a bare host, host:port, or full URL; the agent proxy canonicalizes.\n\n' +
          'ONE CALL, ONE RESULT (D14): the call waits until every item has finished, reporting progress as each lands. The person works through connections one at a time in their wallet, so the proxy keeps two live at once and starts the next as each finishes — a long list does not mint many short-lived codes that expire before the person reaches them. Each item answers `connected`, `ready`, `account_required`, `still_pending`, `queued` (accepted, waiting for a live slot), `declined` (the person declined or cancelled the authorization URL — do not include it again unless they ask), `timed_out` or `error`. The call returns early in two cases: the person must open a URL (show it, then call again with the SAME items), or the wait ran out (the result carries `next`: call again with the SAME items). A repeat call resumes live items, starts queued ones, and answers finished ones without asking the resource again. Do not invoke these resources until the call has returned; if your client moves a long call to the background, wait for its result.\n\n' +
          'Before calling: ask the person which services and which accounts. When a resource declares `account_description` (find_resources shows it), you MUST pass `account` for that item (the identifier it describes — a Google email, a GitHub username); when it does not, you MUST NOT (the account is chosen in the provider\'s own UI). An item without `account` at a resource that needs one answers `account_required` with its `account_description`, and nothing is started: call again with `account` on that item — the account the person named, or ask them which. One item per (resource × account); an already-linked account answers `ready`. `scopes` optionally narrows or widens within the resource\'s declared `connection.scopes[]` (defaults are the read set; write scopes ride the first write). Agent-token resources need no link and answer `ready`. A resource the registry lists as coming (`availability` in find_resources) is still tried; its row carries `availability`, the likely reason if it fails or if calls are later refused.',
      ),
      inputSchema: z.object({
        items: z
          .array(
            z.object({
              resource: z.string(),
              account: z.string().optional(),
              scopes: z.array(z.string()).optional(),
            }),
          )
          .min(1)
          .max(MAX_CONNECT_ITEMS),
      }),
    },
    async ({ items }, ctx) => {
      const c = await getConfig(ctx)
      if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
      const cfg = c.cfg
      const inflight = deps.connectState ?? memoryFlights(cfg)
      const call = await beginCall('connect_resources', ctx)
      // A client that sent a progressToken gets one call for the whole list:
      // the progress notifications keep it from abandoning the call. One that
      // did not gets the bounded slice, then a keepalive round (2026-07-28,
      // with a codec) or `next`.
      const progressToken = call.progressToken
      const deadline = Date.now() + (progressToken === undefined ? budgetMs : progressBudgetMs)

      // One row per item, in the order asked. `waiting` holds the items that
      // took a live slot, so the second pass can poll them; the row itself is
      // what the agent reads.
      type Slot = { host: string; item: ConnectItem; row: Record<string, unknown>; entry: L1Entry }
      const rows: Record<string, unknown>[] = []
      const waiting: Slot[] = []
      // Items started or polled in this call: only these can need a URL. A
      // resumed flight's stored code can die before CONNECT_MAX_MS, so it is
      // not handed over until a poll in this call shows it is still pending.
      const seen = new Set<string>()
      // The deferred-response status of each item's last poll in this call.
      const lastStatus = new Map<string, string | undefined>()

      const rowFor = (entry: L1Entry, account?: string): Record<string, unknown> => ({
        resource: entry.resource,
        access_mode: entry.access_mode,
        vocabularies: entry.picked_vocabs.map((v) => v.vocabUri),
        ...(account ? { account } : {}),
      })

      // Progress, for a client that asked for it. The message carries the
      // count of finished items.
      const report = (message: string): Promise<void> => call.report(message)
      const status = (): string => {
        const finished = rows.filter((r) => r.outcome !== 'still_pending' && r.outcome !== 'queued').length
        const on = waiting.find((w) => w.row.outcome === 'still_pending')
        return `${finished} of ${items.length} finished${on ? ` — waiting on ${on.host}` : ''}`
      }

      // Remember a finished item, so a repeat call answers it without asking
      // the resource again. A resource's answer can lag what it has stored (the
      // hosted fleet reads its account index from an eventually consistent
      // store), and in that window a re-POST starts a second connection for an
      // account the person has just connected.
      const markDone = async (host: string, item: ConnectItem): Promise<void> => {
        if (!inflight.getDone || !inflight.setDone) return
        const now = Date.now()
        const kept = (await inflight.getDone(host)).filter(
          (m) => now - m.at < CONNECT_DONE_TTL_MS && !(m.account === item.account && sameScopes(m.scopes, item.scopes)),
        )
        await inflight.setDone(host, [
          ...kept,
          { ...(item.account ? { account: item.account } : {}), ...(item.scopes ? { scopes: item.scopes } : {}), at: now },
        ])
      }

      const settle = async (
        row: Record<string, unknown>,
        entry: L1Entry,
        item: ConnectItem,
        outcome: ConnectOutcome,
        flight?: InFlight,
      ): Promise<void> => {
        const host = entry.resource
        switch (outcome.kind) {
          case 'connected': {
            await inflight.clear(host)
            await deps.authPending?.resolve(host)
            await markDone(host, item)
            const refreshed = await refreshConnections(cfg, entry)
            row.outcome = 'connected'
            const account = (flight?.account ?? outcome.account) as string | undefined
            if (account) row.account = account
            row.connections = refreshed.connections ?? []
            return
          }
          case 'ready': {
            if (outcome.reason === 'already_connected') await markDone(host, item)
            const refreshed = await refreshConnections(cfg, entry)
            row.outcome = 'ready'
            row.reason = outcome.reason
            if (outcome.account) row.account = outcome.account
            if (outcome.scopes) row.scopes = outcome.scopes
            row.connections = refreshed.connections ?? []
            return
          }
          case 'still_pending': {
            const next: InFlight = {
              ...(flight ?? {
                ...(item.account ? { account: item.account } : {}),
                ...(item.scopes ? { scopes: item.scopes } : {}),
                startedAt: Date.now(),
              }),
              pollUrl: outcome.pollUrl,
              ...(outcome.interaction ? { interaction: outcome.interaction } : {}),
            }
            if (outcome.advertised) {
              // The PS could not reach the person with this code (its reach
              // fallback, or the tab that held it went away) and wants its URL
              // opened: no other URL covers it now.
              delete next.coveredBy
              delete next.headAt
            } else if (next.coveredBy && notHeld(outcome.status) && atHead(host, outcome.queuePosition)) {
              next.headAt ??= Date.now()
            }
            seen.add(host)
            lastStatus.set(host, outcome.status)
            await inflight.set(host, next)
            row.outcome = 'still_pending'
            row.waiting_on = entry.connection?.upstream_name ?? 'the upstream'
            return
          }
          case 'error': {
            await inflight.clear(host)
            const needed = item.account ? undefined : accountRequired(outcome.body, entry)
            if (needed) {
              row.outcome = 'account_required'
              row.account_description = needed
              return
            }
            row.outcome = 'error'
            row.status = outcome.status
            row.body = outcome.body
            return
          }
          case 'interaction':
            // Never settled here: the caller converts it to a flight first.
            row.outcome = 'still_pending'
            return
        }
      }

      // No browser holds the code. A PS that sends no deferred-response status
      // gives no evidence one does, so a covered code there gets its own URL
      // after the bound instead of waiting out CONNECT_MAX_MS.
      const notHeld = (status: string | undefined): boolean => status === undefined || status === 'pending'

      // Whether a covered item is at the head of the person's queue: from the
      // PS's queue_position when it sends one, else no live item of this call
      // is ahead of it.
      const atHead = (host: string, queuePosition: number | undefined): boolean => {
        if (queuePosition !== undefined) return queuePosition <= 1
        const at = waiting.findIndex((w) => w.host === host)
        return !waiting.slice(0, Math.max(at, 0)).some((w) => w.row.outcome === 'still_pending')
      }

      // The code of a URL already out at this interaction endpoint (one person
      // server) that a new code there is covered by: a live item's own handed-
      // over URL, or the one covering it.
      const coveringCode = async (url: string, except: string): Promise<string | undefined> => {
        for (const w of waiting) {
          if (w.host === except || w.row.outcome !== 'still_pending') continue
          const f = await inflight.get(w.host)
          if (!f?.interaction || f.interaction.url !== url) continue
          if (f.surfaced === f.interaction.code) return f.interaction.code
          if (f.coveredBy) return f.coveredBy
        }
        return undefined
      }

      // Whether the person needs this item's own URL now. Not when the client
      // has it already, nor while another URL covers it — unless it has sat at
      // the head of the queue for drainMs with no browser holding it.
      const needsUrl = (host: string, f: InFlight | undefined): f is InFlight & { interaction: Interaction } => {
        if (!f?.interaction || !seen.has(host)) return false
        if (f.surfaced === f.interaction.code) return false
        if (!f.coveredBy) return true
        return notHeld(lastStatus.get(host)) && f.headAt !== undefined && Date.now() - f.headAt >= drainMs
      }

      // The first live item, in list order, whose URL the person needs.
      const nextUrl = async (): Promise<{ host: string; interaction: Interaction } | undefined> => {
        for (const w of waiting) {
          if (w.row.outcome !== 'still_pending') continue
          const f = await inflight.get(w.host)
          if (needsUrl(w.host, f)) return { host: w.host, interaction: f.interaction }
        }
        return undefined
      }

      // Record a URL as handed over, and every other live code at the same
      // person server as covered by it: the wallet tab it opens is handed the
      // rest of the person's queue.
      const handOver = async (host: string, interaction: Interaction): Promise<void> => {
        const own = await inflight.get(host)
        if (own) {
          const { coveredBy: _c, headAt: _h, ...rest } = own
          await inflight.set(host, { ...rest, surfaced: interaction.code })
        }
        for (const w of waiting) {
          if (w.host === host || w.row.outcome !== 'still_pending') continue
          const f = await inflight.get(w.host)
          if (!f?.interaction || f.interaction.url !== interaction.url || f.surfaced === f.interaction.code) continue
          const { headAt: _h, ...rest } = f
          await inflight.set(w.host, { ...rest, coveredBy: interaction.code })
        }
      }

      // A live item whose own URL the client was handed: what the person is on.
      const handedLive = async (): Promise<{ resource: string; url: string } | undefined> => {
        for (const w of waiting) {
          if (w.row.outcome !== 'still_pending') continue
          const f = await inflight.get(w.host)
          if (f?.interaction && f.surfaced === f.interaction.code) return { resource: w.host, url: `${f.interaction.url}?code=${f.interaction.code}` }
        }
        return undefined
      }

      // Start one connect and account for it. Returns true when the item now
      // holds a live slot (the person, or the PS reaching the person, still has
      // to act) and has been added to `waiting`; false when it settled on the
      // spot (ready / connected / error).
      const start = async (item: ConnectItem, entry: L1Entry, row: Record<string, unknown>): Promise<boolean> => {
        const host = entry.resource
        let outcome: ConnectOutcome
        try {
          outcome = await connectAtResource(cfg, entry, {
            ...(item.account ? { account: item.account } : {}),
            ...(item.scopes ? { scopes: item.scopes } : {}),
          })
        } catch (err) {
          row.outcome = 'error'
          row.detail = (err as Error).message
          return false
        }

        if (outcome.kind === 'interaction') {
          // Not handed over here: pass 1 starts every live item first, and the
          // call hands over one URL at the end (5.7.0). A code started while a
          // URL at the same person server is out is covered by it.
          const { interaction } = outcome
          const cover = await coveringCode(interaction.url, host)
          await inflight.set(host, {
            pollUrl: interaction.pollUrl,
            interaction,
            ...(item.account ? { account: item.account } : {}),
            ...(item.scopes ? { scopes: item.scopes } : {}),
            startedAt: Date.now(),
            ...(cover ? { coveredBy: cover } : {}),
          })
          await deps.authPending?.register(host)
          seen.add(host)
          row.outcome = 'still_pending'
          row.waiting_on = entry.connection?.upstream_name ?? 'the upstream'
          waiting.push({ host, item, row, entry })
          return true
        }

        await settle(row, entry, item, outcome)
        if (row.outcome !== 'still_pending') return false
        // A bare 202 — the PS reaching the person by its own channels, no
        // interaction advertised yet — holds a slot exactly like an advertised
        // interaction does. This is the path the wallet takes; not counting it
        // is what let a 27-item list start every item at once (2026-09-15).
        waiting.push({ host, item, row, entry })
        return true
      }

      // Pass 0 — the person declined or cancelled the URL the last round
      // handed over (2026-07-28 `inputResponses`). Every live item that URL
      // covered ends here, `declined`: its flight is dropped and nothing waits
      // on it. The round's state names the code it handed over; without
      // state, every live item whose URL went out, or is covered by one, is
      // taken as declined. The other items continue.
      const declined = new Set<string>()
      const action = urlAction(ctx, 'connect')
      if (action === 'decline' || action === 'cancel') {
        for (const item of items) {
          const host = canonicalizeHost(item.resource)?.host
          if (!host || declined.has(host)) continue
          const f = await inflight.get(host)
          if (!f?.interaction) continue
          const codes = call.state?.codes
          const covered = codes
            ? codes.includes(f.interaction.code) || (f.coveredBy !== undefined && codes.includes(f.coveredBy))
            : f.surfaced === f.interaction.code || f.coveredBy !== undefined
          if (!covered) continue
          await inflight.clear(host)
          await deps.authPending?.resolve(host)
          declined.add(host)
        }
        deps.log?.('connect.declined', { tool: call.tool, hosts: [...declined], action, round: call.state?.round ?? 0 })
      }

      // Pass 1 — resolve trivial items, answer finished ones, resume live ones,
      // and start new connects only up to MAX_LIVE_CONNECTS. Beyond the window
      // an item is accepted but marked `queued` and NOT started, so its
      // interaction code is not minted until a slot frees — the person never
      // accrues a pile of codes counting down at once (D14 revised).
      let live = 0
      const held: Slot[] = []

      // The registry's word on a host, read once per call and only when a
      // host needs it. A coming entry is still tried: the person may be one
      // the provider lets in (a test user of an unverified app, the
      // operator). Its row carries `availability`, which explains a failure —
      // or a connect that succeeds only to answer every call with an access
      // error. A registry that cannot be reached blocks nothing.
      let indexPromise: Promise<RegistryIndex | undefined> | undefined
      const comingEntry = async (host: string): Promise<RegistryEntry | undefined> => {
        indexPromise ??= fetchRegistry(cfg, registryCache).catch(() => undefined)
        const index = await indexPromise
        const found = index ? findEntry(index, host) : undefined
        return found && isComing(found) ? found : undefined
      }

      for (const item of items) {
        const canonical = canonicalizeHost(item.resource)
        if (!canonical) {
          rows.push({ resource: item.resource, outcome: 'error', detail: `invalid host: ${item.resource}` })
          continue
        }
        const coming = await comingEntry(canonical.host)
        const availability = coming ? { availability: coming.availability } : {}
        let entry: L1Entry | undefined
        try {
          entry = await l1.get(canonical.host)
          if (!entry) {
            entry = toL1Entry(await fetchResource(item.resource, { log: deps.log }))
            await l1.upsert(entry)
          } else {
            entry = await refreshEntry(entry)
          }
        } catch (err) {
          rows.push({ resource: canonical.host, outcome: 'error', detail: (err as Error).message, ...availability })
          continue
        }

        const row: Record<string, unknown> = { ...rowFor(entry, item.account), ...availability }
        rows.push(row)
        if (!entry.connection) {
          row.outcome = 'ready'
          row.reason = 'no_connection_needed'
          continue
        }

        // The resource's own metadata says a connect must name an account, and
        // this item names none: answer that here instead of starting a connect
        // the resource can only refuse. The registry copy of
        // account_description can lag the resource's (2026-09-28: 13 Google
        // items sent without one, all refused with account_required).
        if (!item.account && entry.connection.account_description) {
          row.outcome = 'account_required'
          row.account_description = entry.connection.account_description
          continue
        }

        const host = entry.resource
        if (declined.has(host)) {
          row.outcome = 'declined'
          row.detail = 'the person declined the authorization URL; include this item again only if they ask'
          continue
        }
        // Finished recently — answered from connectState, not the resource,
        // whose own answer may not have caught up with what it stored.
        if (inflight.getDone && doneFor(await inflight.getDone(host), item, Date.now())) {
          row.outcome = 'connected'
          row.connections = entry.connections ?? []
          continue
        }

        const stored = await inflight.get(host)
        const existing = stored && (await followup(call, inflight, host, stored))
        if (existing) {
          if (Date.now() - existing.startedAt > CONNECT_MAX_MS) {
            await inflight.clear(host)
            await deps.authPending?.resolve(host)
            row.outcome = 'timed_out'
            row.detail = 'the person did not finish; include this item again to start over'
            continue
          }
          // Resume a live connect — it holds a slot. Do NOT re-POST, and do
          // NOT pre-surface its stored interaction: a code can die before this
          // timer-based bound, and surfacing a dead one is exactly what
          // stranded the person (grokbot, 2026-09-12 — "the proxy resumes dead
          // interactions instead of starting new ones"). Pass 2 polls it;
          // settle() surfaces it only once a poll confirms it is still pending,
          // and clears it (so the next call starts fresh) if the PS says it is
          // gone.
          live += 1
          row.outcome = 'still_pending'
          row.waiting_on = entry.connection.upstream_name ?? 'the upstream'
          waiting.push({ host, item, row, entry })
          continue
        }

        // Over the live window: accept this item but hold it back rather than
        // mint another interaction code that would start expiring behind the
        // ones ahead of it. It starts as soon as a slot frees.
        if (live >= MAX_LIVE_CONNECTS) {
          row.outcome = 'queued'
          row.waiting_on = entry.connection.upstream_name ?? 'the upstream'
          held.push({ host, item, row, entry })
          continue
        }

        if (await start(item, entry, row)) live += 1
      }

      // Start held items while a slot is free. An item that settles on the spot
      // (ready, connected, error) frees its slot at once, so keep going.
      const fill = async (): Promise<void> => {
        while (live < MAX_LIVE_CONNECTS && held.length > 0 && Date.now() < deadline) {
          const next = held.shift() as Slot
          delete next.row.waiting_on
          if (await start(next.item, next.entry, next.row)) live += 1
        }
      }

      // Pass 2 — wait on the live items until the list is finished, the
      // deadline passes, or the person has a URL to open that the client has
      // not been handed. Each live item is polled for at most a slice, in turn,
      // so a stuck head does not starve the item behind it and progress goes
      // out at least once a slice. Each item that lands frees its slot for the
      // next held item without a round trip through the model. A retry after a
      // URL was handed over waits here, on the codes that URL covers.
      const liveHosts = (): string[] => waiting.filter((w) => w.row.outcome === 'still_pending').map((w) => w.host)
      const holdStarted = Date.now()
      let holding = false
      let slices = 0
      while (!(await nextUrl()) && Date.now() < deadline && !call.aborted()) {
        const active = waiting.filter((w) => w.row.outcome === 'still_pending')
        if (active.length === 0) break
        if (!holding) {
          holding = true
          deps.log?.('hold.start', { tool: call.tool, hosts: liveHosts(), progress_token: progressToken !== undefined })
        }
        call.waiting(liveHosts())
        for (const { host, item, row, entry } of active) {
          const remaining = deadline - Date.now()
          if (remaining <= 0 || call.aborted()) break
          const flight = await inflight.get(host)
          if (!flight || Date.now() - flight.startedAt > CONNECT_MAX_MS) {
            // Gone (cleared elsewhere, or dropped by the store's own TTL) or
            // abandoned: free the slot. Including the item again starts over.
            if (flight) await inflight.clear(host)
            await deps.authPending?.resolve(host)
            row.outcome = 'timed_out'
            row.detail = 'the person did not finish; include this item again to start over'
            delete row.waiting_on
          } else {
            // Stop early on an advertised code the client has not been
            // handed: a covered code the PS advertises needs its URL now, and
            // so does a new code in place of a handed-over one (5.8.0). The
            // handed-over code advertised again is not a reason to stop.
            // A covered code is polled in shorter slices: the drain bound is
            // judged from poll answers, and a 25 s slice would push the second
            // URL rounds past it.
            const handed = !!flight.interaction && flight.surfaced === flight.interaction.code
            const slice = flight.coveredBy && !handed ? Math.min(POLL_SLICE_MS, drainMs / 2) : POLL_SLICE_MS
            const polled = await pollConnection(cfg, flight.interaction ?? flight.pollUrl, Math.min(remaining, slice), undefined, {
              stopOnAdvertise: true,
              ...(handed ? { except: flight.surfaced } : {}),
              signal: ctx.mcpReq.signal,
            })
            slices += 1
            await settle(row, entry, item, polled, flight)
          }
          if (row.outcome !== 'still_pending') {
            // This one landed (or failed): it no longer holds a slot.
            live -= 1
            await fill()
            await report(`${host}: ${row.outcome as string}. ${status()}`)
          }
          // A newly started item, a re-advertised code, or a covered code no
          // browser took may need the person at a URL: hand it over now.
          if (await nextUrl()) break
        }
        await report(status())
      }
      call.waiting(undefined)

      const pending = rows.filter((r) => r.outcome === 'still_pending').length
      // Accepted but not started yet — held out of the live window. They still
      // need a later call to start, so they keep `next` alive even when nothing
      // is live right now.
      const queued = rows.filter((r) => r.outcome === 'queued').length
      const summary = {
        results: rows,
        pending,
        ...(queued > 0 ? { queued } : {}),
        ...(pending > 0 || queued > 0
          ? { next: 'call connect_resources again with the same items to keep waiting — live items resume, queued ones start, finished ones are not asked again' }
          : {}),
      }

      const surface = pending > 0 ? await nextUrl() : undefined
      if (holding) {
        deps.log?.('hold.end', {
          tool: call.tool,
          hosts: waiting.map((w) => w.host),
          slices,
          progress_sent: call.sent,
          outcome: call.aborted() ? 'aborted' : surface ? 'url' : pending > 0 || queued > 0 ? 'deadline' : 'finished',
          duration_ms: Date.now() - holdStarted,
        })
      }
      // The client has gone: nothing is handed over that it will not see, so
      // the next call hands the URL over itself.
      if (call.aborted()) return json(summary)
      if (!surface) {
        // Nothing new for the person to open: everything landed, the PS is
        // reaching them by its own channels (an open wallet tab, a device), or
        // the URL is out already — then it rides along for reference rather
        // than as an instruction.
        //
        // Still waiting, for a 2026-07-28 client that sent no progressToken:
        // a keepalive round instead of `next`. Its MCP client retries the
        // same call at once and this call resumes the live items — the model
        // never sees the wait. Up to MAX_MRTR_ROUNDS, then `next`.
        if ((pending > 0 || queued > 0) && keepsAlive(call)) {
          const hosts = rows.filter((r) => r.outcome === 'still_pending' || r.outcome === 'queued').map((r) => r.resource as string)
          const codes: string[] = []
          for (const w of waiting) {
            if (w.row.outcome !== 'still_pending') continue
            const code = (await inflight.get(w.host))?.interaction?.code
            if (code) codes.push(code)
          }
          return keepalive(call, hosts, codes)
        }
        const awaiting = pending > 0 ? await handedLive() : undefined
        return json(awaiting ? { ...summary, awaiting } : summary)
      }

      // The person must open a URL. Hand it over once, and cover the other
      // live codes at the same person server with it: the next call waits on
      // them instead of handing over another.
      const { host: surfaceHost, interaction: toSurface } = surface
      await handOver(surfaceHost, toSurface)
      // The host's hook: stdio opens a browser; a cloud host arms its
      // background poll. A host that throws its own elicitation ends the call
      // here, with the URL already recorded as handed over.
      await deps.onInteraction?.(toSurface.url, toSurface.code, toSurface.pollUrl, () => deps.authPending?.resolve(surfaceHost))

      const native = await surfaceNatively(call, inflight, surfaceHost, toSurface, `Authorize ${surfaceHost} — open this URL to connect, then the agent continues.`)
      if (native) return native

      return text(
        `${JSON.stringify(summary, null, 2)}\n\n` +
          `Connecting ${surfaceHost} needs the person to act${pending + queued > 1 ? ` (${pending + queued - 1} more queued behind it)` : ''}.\n\n` +
          `IMPORTANT: You MUST do all of the following in your response:\n` +
          `1. Display the QR code below verbatim so the user can scan it.\n` +
          `2. Show the authorization URL so the user can open it.\n` +
          `3. Offer to open the URL using browser tools if available.\n` +
          `4. Then call connect_resources again with the same items — it waits until they have all finished.\n\n` +
          interactionText(toSurface),
      )
    },
  )

  registerTool(
    'list_resources',
    {
      inputSchema: z.object({}),
      description:
        'Return your connected resources with name, description, access_mode, last_used, how many vocabularies the agent proxy picked, and — for resources that front an upstream account — the person\'s `connections` (account, effective scopes, connected_at, status) as the resource reports them, plus the `connection` hint (`upstream_name`, `account_description`). `authorizations` lists the auth tokens this agent holds at a resource: the operations each grants, what is left of its budget, and `expires_in` seconds. invoke reuses them; calling an operation none grants first authorizes for it. CHECK THIS BEFORE PLANNING: if it is empty, ask the person which services and accounts to connect. A resource carrying `skip_reason` declares an access_mode this agent cannot complete — invoke will refuse it without calling out.',
    },
    async (_args: Record<string, never>, ctx: ServerContext) => {
      const setup = peekSetup()
      const c = await getConfig(ctx).catch(() => ({ ok: false as const }))
      const held = c.ok ? await listTokens(c.cfg).catch(() => [] as TokenRecord[]) : []
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
            ...authorizationsAt(held, fresh.issuer),
          }
        }),
      )
      return json(entries)
    },
  )

  registerTool(
    'delete_resource',
    {
      description: describeWithL1(
        'Delete a resource from your set: asks the resource to disconnect every upstream account it holds for this person, then forgets the resource locally. The proxy revokes nothing at the provider. Each row in `disconnected` carries the resource\'s own `detail` — relay it to the person: it says whether the grant is still active at the provider and where to revoke it. Consents recorded at the Person Server are not touched.',
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
        const flights = deps.connectState ?? memoryFlights(c.cfg)
        await flights.clear(canonical.host)
        await flights.setDone?.(canonical.host, [])
        try {
          disconnected = await disconnectAll(c.cfg, entry)
        } catch (err) {
          return text(`delete_resource error: ${(err as Error).message}`)
        }
      }
      await l1.remove(canonical.host)
      const c = await getConfig(ctx).catch(() => ({ ok: false as const }))
      if (c.ok) await forgetTokens(c.cfg, entry.issuer).catch(() => {})
      return json({ deleted: canonical.host, disconnected })
    },
  )

  // ── Operations ──

  registerTool(
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

  registerTool(
    'get_operation_schemas',
    {
      description: describeWithL1(
        'Batch fetch full schemas (params, request body, response) for one or more operations on a resource. Separate from list_operations because schemas dominate token cost. Returns `{ context?, context_url?, operations }`. `context`, when present, is the resource\'s own guide to using it (from its `documentation_uri`): read it before you invoke. It comes once per response, not per operation. Each entry in `operations` also carries the operation\'s `access_mode` and `budget`, as list_operations returns them.',
      ),
      inputSchema: z.object({ resource: z.string(), op_ids: z.array(z.string()) }),
    },
    async ({ resource, op_ids }) => {
      const found = await requireL1(resource)
      if (!found.ok) return text(found.msg)
      try {
        const [operations, context] = await Promise.all([
          getOperationsForResource(found.l1, op_ids, docCache),
          loadResourceContext(found.l1, docCache),
        ])
        return json({ ...context, operations })
      } catch (err) {
        return text(`get_operation_schemas error: ${(err as Error).message}`)
      }
    },
  )

  registerTool(
    'invoke',
    {
      description: describeWithL1(
        'Invoke an operation on a resource. Pass `path_params`, `query`, `body` (object) as needed; an MCP tool takes its arguments as `body` (its `bodySchema` in get_operation_schemas). Pass `account` when the person has more than one account connected at the resource (list_resources shows them) — the resource refuses an unbound call with `account_required` naming the candidates. If authorization is required, the client opens the auth URL automatically — call invoke again after authorization completes. async.receive operations return `subscribe_requires_subagent` (v.next). An operation whose access_mode this agent cannot complete is refused without any request being made, with the reason stated. When the resource meters the call, the result carries `budget` (from the AAuth-Budget header): `remaining` on this auth token and, when known, `cost` of this call.',
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
      const host = found.l1.resource
      const inflight = deps.connectState ?? memoryFlights(c.cfg)
      const call = await beginCall('invoke', ctx)

      // The person declined or cancelled the URL the last round handed over:
      // nothing is waited on, and the call ends here (5.8.0). Before, the
      // retry waited out the slice on a refused flight.
      const action = urlAction(ctx, 'connect')
      if (action === 'decline' || action === 'cancel') {
        if (await inflight.get(host)) await inflight.clear(host)
        await deps.authPending?.resolve(host)
        deps.log?.('invoke.declined', { tool: call.tool, hosts: [host], action, round: call.state?.round ?? 0 })
        return text(`The person declined authorization for ${host}. Do not retry unless they ask.`)
      }

      // Hand the person a URL they have not been handed: recorded on the
      // flight first, so the retry finds it, then natively or as text.
      const handOverUrl = async (interaction: Interaction, startedAt: number): Promise<InputRequiredResult | ReturnType<typeof text>> => {
        await inflight.set(host, { pollUrl: interaction.pollUrl, interaction, startedAt, surfaced: interaction.code })
        // onComplete resolves the UserStore pending-auth waiter when the poll finishes.
        const onComplete = () => deps.authPending?.resolve(host)
        await deps.onInteraction?.(interaction.url, interaction.code, interaction.pollUrl, onComplete)
        await deps.authPending?.register(host)

        const native = await surfaceNatively(call, inflight, host, interaction, `Authorize ${host} — open this URL, then call invoke again.`)
        if (native) return native

        return text(
          `Authorization required for ${host}.\n\n` +
          `IMPORTANT: You MUST do all of the following in your response:\n` +
          `1. Display the QR code below verbatim so the user can scan it.\n` +
          `2. Show the authorization URL so the user can open it.\n` +
          `3. Offer to open the URL using browser tools if available.\n` +
          `4. After showing the URL and QR code, automatically retry invoke — the server will wait up to 30 seconds for authorization to complete before responding.\n\n` +
          interactionText(interaction) + `\n\nRetry invoke now.`,
        )
      }

      // Resume before re-requesting. A flight for this host means the PS (or
      // the resource) is already waiting on the person for it — the same
      // store connect_resources uses, so a connect and an invoke never race
      // each other for one host. Poll that pending instead of calling again:
      // every fresh call minted a new interaction code (four for one
      // approval, 2026-09-14), and the code the person was looking at died
      // under them.
      //
      // A client that sent a progressToken is held until the pending settles
      // (5.8.0): polled a slice at a time with progress after each, up to
      // CONNECT_MAX_MS from the flight's start. It is answered early only
      // when the PS advertises a code the client has not been handed — a new
      // URL for the person. Without a progressToken, one bounded slice.
      //
      // Twice at most: a pending the call below leaves is held the same way.
      let resumedAuthToken: string | undefined
      for (let pass = 0; pass < 2; pass += 1) {
        const stored = await inflight.get(host)
        const existing = stored && (await followup(call, inflight, host, stored))
        if (existing) {
          if (Date.now() - existing.startedAt > CONNECT_MAX_MS) {
            deps.log?.('invoke.resume', { resource: host, op_id, outcome: 'abandoned', age_ms: Date.now() - existing.startedAt })
            await inflight.clear(host)
            await deps.authPending?.resolve(host)
          } else {
            const held = await waitOnFlight(call, c.cfg, inflight, host, existing)
            if (held.kind === 'aborted') return text(`The call was cancelled while authorization for ${host} was in progress.`)
            if (held.kind === 'timed_out') {
              deps.log?.('invoke.resume', { resource: host, op_id, outcome: 'abandoned', age_ms: Date.now() - existing.startedAt })
              await inflight.clear(host)
              await deps.authPending?.resolve(host)
              return text(`The person did not finish authorizing ${host}. Call invoke again to start over.`)
            }
            const polled = held.outcome
            if (polled.kind === 'still_pending') {
              deps.log?.('invoke.resume', { resource: host, op_id, outcome: 'still_pending' })
              const next: InFlight = {
                ...(await inflight.get(host) ?? existing),
                pollUrl: polled.pollUrl,
                ...(polled.interaction ? { interaction: polled.interaction } : {}),
              }
              // The PS advertises a code the client was not handed: the person
              // needs its URL now.
              if (polled.advertised && next.interaction && next.interaction.code !== next.surfaced) {
                return handOverUrl(next.interaction, next.startedAt)
              }
              await inflight.set(host, next)
              return text(
                `Authorization for ${host} is still in progress.\n\n` +
                  (next.interaction
                    ? `The person has not finished yet. Show them the SAME authorization URL and QR code again — do not start over.\n\n${interactionText(next.interaction)}\n\nRetry invoke after they approve.`
                    : `The person server is reaching the person directly. Retry invoke in a moment.`),
              )
            }
            // Approved, or the pending is gone (declined, expired): either way
            // the wait is over. On approval the poll response IS the delivery —
            // keep the token it carries, or the call below asks the PS again and
            // Hellō answers with a new code (4.5.0, 2026-09-15: every approval
            // produced another). A dead pending starts a fresh one below.
            if (polled.kind === 'connected') {
              const { adopted, authToken } = await adoptSettled(c.cfg, found.l1, polled)
              resumedAuthToken = authToken
              deps.log?.('invoke.resume', { resource: host, op_id, outcome: 'settled', adopted })
            } else {
              deps.log?.('invoke.resume', { resource: host, op_id, outcome: 'gone', ...(polled.kind === 'error' ? { status: polled.status } : {}) })
            }
            await inflight.clear(host)
            await deps.authPending?.resolve(host)
          }
        }

        // Belt and braces for hosts without a durable flight store: an in-memory
        // pending marker registered by the fallback path below.
        if (await deps.authPending?.checkAndWait(host, 30_000) === 'waiting') {
          return text(
            `Authorization for ${host} is still in progress.\n\n` +
            `The user has not yet completed authorization. Try again in a moment.`,
          )
        }

        let result: InvokeResult
        try {
          result = await invokeAtResource(c.cfg, found.l1, op_id, invokeArgs, {
            ...(account ? { account } : {}),
            ...(resumedAuthToken ? { authToken: resumedAuthToken } : {}),
          })
        } catch (err) {
          return text(`invoke error: ${(err as Error).message}`)
        }
        resumedAuthToken = undefined

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

        if (result.kind === 'pending') {
          // The PS is reaching the person itself and had not answered in the
          // in-call wait. Record the flight so the retry polls this pending —
          // it delivers the token, and it re-advertises the interaction code
          // if the PS falls back to one. A call that is held waits on it here.
          await inflight.set(host, { pollUrl: result.pollUrl, startedAt: Date.now() })
          if (call.progressToken !== undefined && pass === 0) continue
          return text(
            `Authorization for ${host} is in progress.\n\n` +
              `The person server is asking the person directly (an open wallet tab or a device). Retry invoke now; if the person server falls back to a link, the retry returns the authorization URL to show them.`,
          )
        }

        if (result.kind === 'interaction') return handOverUrl(result.interaction, Date.now())

        if (result.status >= 200 && result.status < 300) await l1.touch(found.l1.resource)
        // budget before body: the balance stays readable when the body is large.
        return json({ status: result.status, ...(result.budget ? { budget: result.budget } : {}), body: result.body })
      }
      // Unreachable: the second pass returns on every branch.
      return text(`Authorization for ${host} is still in progress. Retry invoke in a moment.`)
    },
  )

  registerTool(
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
