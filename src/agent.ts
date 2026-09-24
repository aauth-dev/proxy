// agent proxy — the user's AAuth agent. The invoke flow against an AAuth
// resource, obtaining person tokens and auth tokens at the PS.
//
// The shape of the flow is the one the protocol describes: pick an opening
// credential from what the resource declared, make the request, read any
// AAuth-Requirement, satisfy it, retry. The declaration only saves round trips —
// the runtime requirement is authoritative and can escalate at any point.
//
// invoke() is non-blocking: when an interaction is required (PS consent, a person
// token the PS wants the user to approve, or the resource's own OAuth bootstrap)
// it RETURNS the interaction (url + code + poll URL) rather than completing it,
// so a caller — the MCP server — can surface the URL to the user.
// invokeComplete() drives it to completion for programmatic use, performing the
// interaction via a callback and polling.
//
// Built directly on @hellocoop/httpsig (the @aauth/agent package is
// 401-challenge-driven and has no authorize-first path, mirroring the
// resource-side finding).

import { fetch as signedFetch } from '@hellocoop/httpsig'
import { planAccessMode } from './access-mode.js'
import type { AccessModePlan, KnownAccessMode } from './access-mode.js'
import { agentTokenPs, decodeJwtPayload, jwkThumbprint, jwtExp } from './jwt.js'
import { loggedFetch, logUrl } from './log.js'
import type { ProxyLog } from './log.js'
import { listOperationsForResource, routeOperation } from './resource.js'
import type { RoutedOperation } from './resource.js'
import { minimalScope } from './scope.js'
import type { ScopePolicy } from './scope.js'
import type { ConnectionRow, L1Entry } from './store.js'
import {
  authTokenRecord,
  createMemoryTokenStore,
  grantsOperation,
  grantsAtLeast,
  isDueForRefresh,
  isLive,
  jtiOf,
  wasInUse,
  operationName,
  uniqueOperations,
} from './tokens.js'
import type { TokenKey, TokenRecord, TokenStore } from './tokens.js'
import { jsonRpcFromSse } from './vocab/mcp.js'

export type AgentSigningKey = Parameters<typeof signedFetch>[1]['signingKey']

/**
 * Optional hints forwarded verbatim as extra body parameters in every POST to
 * the PS auth token endpoint (protocol §Auth Token Request). All fields are
 * optional; include only those the host has learned about the user.
 *
 * The person token endpoint gets the subset that says WHO the token is for and
 * how to ask them (`PERSON_TOKEN_HINTS`): a PS that binds one agent to several
 * accounts needs `login_hint` there too, or it issues for whichever binding it
 * finds first. `upstream_token` and `subagent_token` are not hints on that
 * endpoint — they are request parameters with their own semantics (§Person
 * Token Endpoint) and are not forwarded from here.
 */
export interface PSTokenHints {
  login_hint?: string // user identifier hint (e.g. Hello wallet sub or email)
  domain_hint?: string // DNS domain for B2B PS routing
  tenant?: string // tenant identifier scoped to the PS
  justification?: string // Markdown: why access is being requested (shown to user)
  platform?: string // runtime platform identifier
  device?: string // short human-readable device / browser name
  upstream_token?: string // auth token for call chaining
  subagent_token?: string // parent agent requesting auth on behalf of a sub-agent
  prompt?: string // space-delimited; controls reauthentication / consent prompts
  capabilities?: string[] // overrides the default ['interaction'] sent to the PS
}

/** The hints a person token request carries (see `PSTokenHints`). */
const PERSON_TOKEN_HINTS = ['login_hint', 'domain_hint', 'tenant', 'prompt', 'justification'] as const

function personTokenHints(cfg: ProxyConfig): Partial<PSTokenHints> {
  const out: Partial<PSTokenHints> = {}
  for (const k of PERSON_TOKEN_HINTS) {
    const v = cfg.psHints?.[k]
    if (v !== undefined) out[k] = v
  }
  return out
}

export interface ProxyConfig {
  psUrl: string
  agentPrivateJwk: AgentSigningKey // the agent's private JWK
  agentToken: string // aa-agent+jwt (cnf = agent pubkey, ps = psUrl)
  /**
   * The mission this agent is operating under, as the base64url SHA-256 of the
   * approved mission JSON. Forwarded to the PS's person token endpoint, which
   * stamps it into the person token; from there the resource copies it into the
   * resource token and the PS into the auth token. No PS implements
   * `mission_endpoint` yet — the claim path is built regardless.
   */
  missionS256?: string
  /** Extra parameters forwarded to every PS auth token endpoint request. */
  psHints?: PSTokenHints
  /**
   * Every token the agent holds — person, auth, and session tokens, and the
   * host's agent token if it keeps it here (tokens.ts). One record per key;
   * flushed whole when the agent's signing key changes. Defaults to a
   * per-config in-memory store.
   */
  tokens?: TokenStore
  /**
   * Which operations to declare at a resource's authorization endpoint beyond
   * the ones the call needs (scope.ts). Defaults to `minimalScope`: none.
   */
  scopePolicy?: ScopePolicy
  /**
   * Called with each auth_token received from the PS before it is used.
   * Hosts can use this to record or validate the PS sub across exchanges.
   */
  onAuthToken?: (token: string) => void | Promise<void>
  /**
   * Event sink for the AAuth exchange this config drives (see log.ts). A host
   * that builds tools with `buildProxyTools` can set `ProxyDeps.log` instead;
   * the tools copy it here when the identity provider left it unset.
   */
  log?: ProxyLog
}

export interface InvokeArgs {
  pathParams?: Record<string, string>
  query?: string
  body?: unknown // string or object; vocab adapters serialize non-string bodies as JSON.
  contentType?: string // defaults to application/json when a body is present
}

export interface InvokeOptions {
  /** Overrides ProxyConfig.missionS256 for this call. */
  missionS256?: string
  /**
   * Which of the person's connected upstream accounts this call is for (the
   * AAuth `account` extension). Sent on the authorization request; the PS
   * binds it into the auth token and the resource routes on it. Required by
   * the resource when the person holds two or more connections — its
   * `account_required` error names the candidates.
   */
  account?: string
  /**
   * An auth token a settled pending delivered (`adoptSettled`). Presented as
   * the opening credential instead of acquiring one; the requirement loop
   * still handles any challenge it draws.
   */
  authToken?: string
}

export interface Interaction {
  url: string
  code: string
  pollUrl: string
}

export type InvokeResult =
  | { kind: 'result'; status: number; body: unknown; budget?: BudgetStatus }
  | { kind: 'interaction'; interaction: Interaction }
  /**
   * The PS is reaching the person by its own channels (`requirement=approval`)
   * and had not answered within the in-call wait. The caller keeps `pollUrl`
   * and polls it on the retry: the pending delivers the token, and a fresh
   * request would mint a new one.
   */
  | { kind: 'pending'; pollUrl: string }
  /**
   * The resource (or this operation) declares an access mode this agent's setup
   * cannot complete — typically `auth-token` or `person-token` at an agent whose
   * agent token carries no `ps` claim. No request was made. Case (c) of the
   * three-way access_mode plan: the agent learns this before planning rather
   * than at a 401.
   */
  | { kind: 'skipped'; resource: string; opId: string; mode: KnownAccessMode; reason: string }

export type InteractionHandler = (url: string, code: string) => Promise<void> | void

// ── Credentials and signing ──
//
// Exactly one credential is presented per request, via Signature-Key, except in
// resource-managed mode where the agent token identifies the agent and the
// session token rides in Authorization: AAuth (and MUST be covered by the
// signature, protocol §AAuth-Access Response Header).

type Credential =
  | { kind: 'agent' }
  | { kind: 'person'; jwt: string }
  | { kind: 'auth'; jwt: string }
  | { kind: 'session'; token: string }

interface SignedRequestInit {
  method?: string
  headers?: Record<string, string>
  body?: string
}

// The AAuth HTTP Message Signatures profile's base covered components. httpsig
// applies these itself when no list is passed; we pass an explicit list whenever
// something must be added to it.
const BASE_GET = ['@method', '@authority', '@path', 'signature-key']
const BASE_BODY = ['@method', '@authority', '@path', 'content-type', 'signature-key']

function components(opts: {
  hasBody: boolean
  authorization?: boolean
  /** PS and AS endpoints: a body MUST additionally be covered by content-digest. */
  psOrAs?: boolean
}): string[] | undefined {
  const base = opts.hasBody ? [...BASE_BODY] : [...BASE_GET]
  let extended = false
  if (opts.hasBody && opts.psOrAs) {
    base.splice(base.indexOf('content-type') + 1, 0, 'content-digest')
    extended = true
  }
  if (opts.authorization) {
    base.splice(base.length - 1, 0, 'authorization')
    extended = true
  }
  return extended ? base : undefined
}

function signWith(cfg: ProxyConfig, cred: Credential, opts: { psOrAs?: boolean } = {}) {
  return (url: string, init: SignedRequestInit = {}): Promise<Response> => {
    const headers = { ...(init.headers ?? {}) }
    if (cred.kind === 'session') headers.authorization = `AAuth ${cred.token}`
    const jwt =
      cred.kind === 'person' || cred.kind === 'auth' ? cred.jwt : cfg.agentToken
    const list = components({
      hasBody: init.body !== undefined,
      authorization: cred.kind === 'session',
      psOrAs: opts.psOrAs,
    })
    return loggedFetch(cfg.log, 'aauth.request', { credential: cred.kind, method: init.method ?? 'GET', url: logUrl(url) }, () =>
      signedFetch(url, {
        ...init,
        headers,
        signingKey: cfg.agentPrivateJwk,
        signatureKey: { type: 'jwt', jwt },
        ...(list ? { components: list } : {}),
      }),
    )
  }
}

type SignedFetch = ReturnType<typeof signWith>

export function makeAgentPoll(cfg: ProxyConfig): (url: string) => Promise<Response> {
  return (url: string) =>
    signWith(cfg, { kind: 'agent' })(url, { method: 'GET', headers: { Prefer: 'wait=20' } })
}

// ── AAuth-Requirement ──

interface ParsedRequirement {
  requirement: string
  resourceToken?: string
  url?: string
  code?: string
  // draft-hardt-aauth-budgets §reason-parameter: `budget-exhausted` (grant fully
  // spent) or `insufficient-budget` (this request alone does not fit). Advisory —
  // re-authorizing without reading it is always correct; we surface it so the
  // LLM can request a larger budget with justification, or shrink the call.
  reason?: string
}

// Parses the AAuth-Requirement header. Unrecognized `requirement=` values are
// returned as-is: the caller decides, and treats anything it cannot satisfy as a
// terminal response rather than guessing.
function parseRequirement(headerValue: string | null): ParsedRequirement | undefined {
  if (!headerValue) return undefined
  const requirement = /requirement=([A-Za-z0-9_-]+)/.exec(headerValue)?.[1]
  if (!requirement) return undefined
  return {
    requirement,
    resourceToken: /resource-token="([^"]+)"/.exec(headerValue)?.[1],
    url: /url="([^"]+)"/.exec(headerValue)?.[1],
    code: /code="([^"]+)"/.exec(headerValue)?.[1],
    reason: /reason=([A-Za-z0-9_-]+)/.exec(headerValue)?.[1],
  }
}

/**
 * The resource's `AAuth-Budget` response header (draft-hardt-aauth-budgets
 * §AAuth-Budget Response Header): what is left of the auth token's budget and,
 * when known, what this request cost. Integers are in the granted scale.
 */
export interface BudgetStatus {
  remaining?: number
  cost?: number
  reserved?: number
  required?: number
  unit?: string
  decimals?: number
}

// An RFC 9651 Dictionary, read for the members this agent uses: Integer and
// String values. Unrecognized members and other value types are ignored, as
// the draft requires of recipients.
export function parseBudget(headerValue: string | null): BudgetStatus | undefined {
  if (!headerValue) return undefined
  const out: BudgetStatus = {}
  const re = /([a-z*][a-z0-9_.*-]*)\s*=\s*(-?\d+|"(?:[^"\\]|\\.)*")/g
  for (const [, key, raw] of headerValue.matchAll(re)) {
    const value = raw.startsWith('"') ? raw.slice(1, -1).replace(/\\(.)/g, '$1') : Number(raw)
    switch (key) {
      case 'remaining':
      case 'cost':
      case 'reserved':
      case 'required':
      case 'decimals':
        if (typeof value === 'number') out[key] = value
        break
      case 'unit':
        if (typeof value === 'string') out.unit = value
        break
    }
  }
  return Object.keys(out).length > 0 ? out : undefined
}

function withBudget(res: Response): { budget?: BudgetStatus } {
  const budget = parseBudget(res.headers.get('aauth-budget'))
  return budget ? { budget } : {}
}

// A terminal challenge response, annotated with the challenge's `reason` when
// one was sent so the caller (ultimately the LLM) sees `budget-exhausted` /
// `insufficient-budget` instead of a bare status.
async function terminalChallenge(res: Response, req: ParsedRequirement): Promise<InvokeResult> {
  const body = await safeBody(res)
  return {
    kind: 'result',
    status: res.status,
    body: req.reason ? { error: req.reason, detail: body } : body,
    ...withBudget(res),
  }
}

// An interaction needs `code` and the poll URL. The page the person is sent
// to is a published property of whoever issued the 202 — the resource's
// `interaction_endpoint` (L1) or the PS's (ONBOARDING-PLAN-2.md §2): the
// header carries the code only and the agent composes
// `{interaction_endpoint}?code=`. A `url=` parameter is still honoured when a
// 2.x-era issuer sends one. Neither → not an interaction this agent can drive.
function interactionFrom(res: Response, publishedUrl?: string): Interaction | undefined {
  const parsed = parseRequirement(res.headers.get('aauth-requirement'))
  const pollUrl = res.headers.get('location') ?? ''
  if (parsed?.requirement !== 'interaction' || !parsed.code || !pollUrl) return undefined
  const url = parsed.url ?? publishedUrl
  return url ? { url, code: parsed.code, pollUrl } : undefined
}

// A 202 that advertises an interaction code. The URL may still come from
// metadata; this is only whether to stop polling and surface it.
function advertisesInteraction(res: Response): boolean {
  const parsed = parseRequirement(res.headers.get('aauth-requirement'))
  return parsed?.requirement === 'interaction' && !!parsed.code
}

// A 202 that carries no interaction code: the PS is reaching the person by
// its own channels (an open wallet tab, a registered device) and the agent
// has only the poll URL — `requirement=approval`. Poll it; a later poll may
// re-advertise `requirement=interaction; code=` if the person is not reached.
function pendingFrom(res: Response): string | undefined {
  if (res.status !== 202) return undefined
  return res.headers.get('location') ?? undefined
}

// Poll a PS pending URL on the agent's behalf. Terminal 2xx → the body; a 202
// that advertises an interaction → the interaction to surface, at once — the
// PS falls back from approval to interaction ~10 s in, and the person needs
// the URL before the client gives up on the tool call (issue #21); a 202 at
// the deadline → still pending; anything else → the result.
async function drivePending(
  cfg: ProxyConfig,
  pollUrl: string,
  publishedUrl: string | undefined,
  timeoutMs: number,
): Promise<{ kind: 'done'; body: unknown; res: Response } | { kind: 'interaction'; interaction: Interaction } | { kind: 'pending' } | { kind: 'result'; status: number; body: unknown }> {
  const res = await pollUntilDone(makeAgentPoll(cfg), pollUrl, timeoutMs, undefined, advertisesInteraction)
  if (res.status === 202) {
    const interaction = interactionFrom(res, publishedUrl)
    return interaction ? { kind: 'interaction', interaction } : { kind: 'pending' }
  }
  if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }
  return { kind: 'done', body: await safeBody(res), res }
}

// Media types whose bodies are text. Anything else is read as bytes and handed
// back base64-encoded: decoding bytes as UTF-8 replaces every invalid sequence
// and the original cannot be recovered (ciphertext, images, archives).
const TEXTUAL = /^(text\/|application\/([\w.-]+\+)?(json|xml)(\s*;|$)|application\/(x-www-form-urlencoded|javascript|ecmascript)(\s*;|$)|image\/svg\+xml)/i

/** A response body for the caller: parsed JSON, text, or `{content_type, size, base64}` for bytes. */
export async function safeBody(res: Response): Promise<unknown> {
  const contentType = (res.headers.get('content-type') ?? '').trim()
  if (contentType && !TEXTUAL.test(contentType)) {
    const bytes = new Uint8Array(await res.arrayBuffer())
    let bin = ''
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
    return { content_type: contentType, size: bytes.byteLength, base64: btoa(bin) }
  }
  const text = await res.text()
  // An MCP server may answer tools/call as an SSE stream; the caller wants the
  // JSON-RPC response in it, not the framing.
  if ((res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')) {
    const msg = jsonRpcFromSse(text)
    if (msg !== undefined) return msg
  }
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

// ── PS metadata ──

interface PSMetadata {
  /** Renamed from `token_endpoint` in -11. */
  auth_token_endpoint: string
  /** New in -11, REQUIRED. */
  person_token_endpoint?: string
  interaction_endpoint?: string
  mission_endpoint?: string
}

async function psMetadata(psUrl: string): Promise<PSMetadata> {
  return (await (
    await fetch(`${psUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`)
  ).json()) as PSMetadata
}

// ── The token store ──
//
// Keyed on the ProxyConfig object, which the identity provider resolves
// per-principal. A process-global store would leak tokens across tenants in a
// multi-user host.

const defaultTokens = new WeakMap<ProxyConfig, TokenStore>()

function tokenStore(cfg: ProxyConfig): TokenStore {
  if (cfg.tokens) return cfg.tokens
  let store = defaultTokens.get(cfg)
  if (!store) {
    store = createMemoryTokenStore()
    defaultTokens.set(cfg, store)
  }
  return store
}

const jktByConfig = new WeakMap<ProxyConfig, Promise<string>>()

/** Thumbprint of the key this config signs with — what every held token's `cnf` must bind. */
function agentJkt(cfg: ProxyConfig): Promise<string> {
  let jkt = jktByConfig.get(cfg)
  if (!jkt) {
    jkt = jwkThumbprint(cfg.agentPrivateJwk as { kty?: string })
    jktByConfig.set(cfg, jkt)
  }
  return jkt
}

const tokenLogFields = (key: TokenKey) => ({
  kind: key.kind,
  ...(key.resource ? { resource: key.resource } : {}),
  ...(key.account !== undefined ? { account: true } : {}),
  ...(key.mission_s256 ? { mission: true } : {}),
})

/**
 * The record held for `key` if it can still be presented. A record bound to
 * another agent key means the key rotated: nothing held survives that, so the
 * whole store is flushed.
 */
async function liveToken(cfg: ProxyConfig, key: TokenKey): Promise<TokenRecord | undefined> {
  const store = tokenStore(cfg)
  const rec = await store.get(key)
  if (!rec) return undefined
  if (rec.agent_jkt && rec.agent_jkt !== (await agentJkt(cfg))) {
    await store.flush()
    cfg.log?.('token.drop', { ...tokenLogFields(key), reason: 'key_rotated', flushed: true })
    return undefined
  }
  return isLive(rec) ? rec : undefined
}

async function keepToken(cfg: ProxyConfig, rec: TokenRecord, reason: string): Promise<void> {
  await tokenStore(cfg).put(rec)
  cfg.log?.('token.put', {
    ...tokenLogFields(rec),
    reason,
    ...(rec.jti ? { jti: rec.jti } : {}),
    ...(rec.exp !== undefined ? { expires_in: rec.exp - rec.obtained_at } : {}),
    ...(rec.granted ? { operations: rec.granted.operations.map(operationName) } : {}),
    ...(rec.budget ? { budget: rec.budget.amount } : {}),
  })
}

async function dropToken(cfg: ProxyConfig, key: TokenKey, jti: string | undefined, reason: string): Promise<void> {
  await tokenStore(cfg).drop(key, jti)
  cfg.log?.('token.drop', { ...tokenLogFields(key), reason, ...(jti ? { jti } : {}) })
}

/**
 * Drop every token the agent holds. Call when the agent's signing key rotates —
 * every token binds the key through `cnf`, so none of them survive. The store
 * also detects a rotation on its own (`liveToken`); this is the explicit hook
 * for a host that knows one happened.
 */
export async function flushTokens(cfg: ProxyConfig): Promise<void> {
  await tokenStore(cfg).flush()
}

/** Drop every token held for one resource (its issuer URL) — the resource was deleted. */
export async function forgetTokens(cfg: ProxyConfig, resource: string): Promise<void> {
  const store = tokenStore(cfg)
  for (const rec of await store.list()) {
    if (rec.resource === resource) await dropToken(cfg, rec, rec.jti, 'resource_deleted')
  }
}

/** Every token the agent holds, expired ones included. */
export async function listTokens(cfg: ProxyConfig): Promise<TokenRecord[]> {
  return tokenStore(cfg).list()
}

const personKey = (resource: string, missionS256?: string): TokenKey => ({
  kind: 'person',
  resource,
  ...(missionS256 ? { mission_s256: missionS256 } : {}),
})

const sessionKey = (resource: string): TokenKey => ({ kind: 'session', resource })

async function heldSession(cfg: ProxyConfig, l1: L1Entry): Promise<string | undefined> {
  return (await liveToken(cfg, sessionKey(l1.issuer)))?.value
}

async function keepSession(cfg: ProxyConfig, l1: L1Entry, value: string): Promise<void> {
  await tokenStore(cfg).put({ ...sessionKey(l1.issuer), value, obtained_at: Math.floor(Date.now() / 1000) })
}

// ── Person tokens ──

type PersonTokenOutcome =
  | { kind: 'token'; personToken: string }
  | { kind: 'interaction'; interaction: Interaction }
  | { kind: 'pending'; pollUrl: string }
  | { kind: 'result'; status: number; body: unknown }

/**
 * Obtain a person token for one resource, from cache or from the PS.
 *
 * A resource MUST have verified a person token before it issues a resource token,
 * and the agent MUST present one on every authorization endpoint request
 * (protocol §Person Token, §Authorization Endpoint Request) — so this sits in
 * front of the whole authorize-first path, not only of `person-token` resources.
 *
 * The PS MAY require the user to approve the agent acting at this resource before
 * issuing, and answers `202` with `requirement=interaction`. That is surfaced
 * like any other interaction; the caller drives it and retries, and the second
 * request gets a `200`.
 */
export async function obtainPersonToken(
  cfg: ProxyConfig,
  ps: PSMetadata,
  resource: string,
  missionS256?: string,
): Promise<PersonTokenOutcome> {
  if (!ps.person_token_endpoint) {
    return {
      kind: 'result',
      status: 0,
      body: {
        error: 'ps_missing_person_token_endpoint',
        error_description: `${cfg.psUrl} publishes no person_token_endpoint; AAuth -11 requires one`,
      },
    }
  }

  const key = personKey(resource, missionS256)

  // A held person token inside the refresh margin is replaced rather than
  // presented when a replacement can live longer: every auth token obtained
  // with it is capped at its `exp` (protocol §Refresh Margin), so refreshing
  // from the top of the chain is what buys a full-length auth token. When the
  // refresh fails, the held token is still good until it expires — and the
  // person is not asked to act for a token the agent already has.
  const held = await liveToken(cfg, key)
  if (held && !isDueForRefresh(held, jwtExp(cfg.agentToken))) {
    cfg.log?.('token.hit', { kind: 'person', resource })
    return { kind: 'token', personToken: held.value }
  }
  const outcome = await requestPersonToken(cfg, ps, ps.person_token_endpoint, key, missionS256, held ? 'refresh' : 'initial')
  if (outcome.kind === 'token' || !held) return outcome
  cfg.log?.('token.refresh_failed', { kind: 'person', resource, outcome: outcome.kind, ...(outcome.kind === 'result' ? { status: outcome.status } : {}) })
  return { kind: 'token', personToken: held.value }
}

async function requestPersonToken(
  cfg: ProxyConfig,
  ps: PSMetadata,
  endpoint: string,
  key: TokenKey,
  missionS256: string | undefined,
  reason: 'initial' | 'refresh',
): Promise<PersonTokenOutcome> {
  const resource = key.resource!
  // `capabilities` tells the PS this agent can put a URL in front of the
  // person (§Person Token Request): without it a first binding at a PS that
  // cannot reach them another way (no open wallet tab, no push device) is
  // refused with user_unreachable instead of a 202 interaction.
  //
  // The person-identifying hints (login_hint, tenant, …) go here as well as on
  // the auth token exchange: the person token is where the PS first decides
  // WHICH account the agent acts for, and a PS bound to more than one has
  // nothing else to choose by.
  const res = await signWith(cfg, { kind: 'agent' }, { psOrAs: true })(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      resource,
      capabilities: cfg.psHints?.capabilities ?? ['interaction'],
      ...(missionS256 ? { mission_s256: missionS256 } : {}),
      ...personTokenHints(cfg),
    }),
  })

  let body: { person_token?: string; expires_in?: number }
  if (res.status === 202) {
    const interaction = interactionFrom(res, ps.interaction_endpoint)
    if (interaction) return { kind: 'interaction', interaction }
    const pollUrl = pendingFrom(res)
    if (!pollUrl) return { kind: 'result', status: res.status, body: await safeBody(res) }
    // The PS is reaching the person itself; wait here.
    const driven = await drivePending(cfg, pollUrl, ps.interaction_endpoint, PS_REACH_TIMEOUT_MS)
    if (driven.kind === 'interaction') return driven
    if (driven.kind === 'pending') return { kind: 'pending', pollUrl }
    if (driven.kind === 'result') return driven
    body = driven.body as typeof body
  } else {
    if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }
    body = (await res.json()) as typeof body
  }

  const { person_token, expires_in } = body
  if (!person_token) {
    return { kind: 'result', status: res.status, body: { error: 'ps_returned_no_person_token' } }
  }
  await keepToken(cfg, await personRecord(cfg, key, person_token, expires_in), reason)
  return { kind: 'token', personToken: person_token }
}

async function personRecord(cfg: ProxyConfig, key: TokenKey, token: string, expiresIn?: number): Promise<TokenRecord> {
  const now = Math.floor(Date.now() / 1000)
  const jti = jtiOf(token)
  // The token's own `exp` when it is a JWT that carries one; the PS's
  // `expires_in` otherwise.
  const exp = jwtExp(token) ?? now + (expiresIn ?? 3600)
  return {
    ...key,
    value: token,
    agent_jkt: await agentJkt(cfg),
    ...(jti ? { jti } : {}),
    exp,
    obtained_at: now,
  }
}

type Poller = (url: string) => Promise<Response>

// Poll a deferred (202) Location until terminal. The poll MUST be signed — the
// PS pending endpoint verifies the agent signature (an unsigned poll gets 401,
// which would look like an instant terminal response).
//
// `onPoll` (optional) is invoked once per poll iteration with elapsed ms — a
// heartbeat hook for hosts that hold a request open (e.g. emit progress
// notifications over a long-running tool call). `stop` (optional) ends the
// wait early on a 202 the caller wants to act on.
export async function pollUntilDone(
  poll: Poller,
  locationUrl: string,
  timeoutMs = 180_000,
  onPoll?: (elapsedMs: number) => void | Promise<void>,
  stop?: (res: Response) => boolean,
): Promise<Response> {
  const start = Date.now()
  const deadline = start + timeoutMs
  let res = await poll(locationUrl)
  while (res.status === 202 && Date.now() < deadline && !stop?.(res)) {
    await onPoll?.(Date.now() - start)
    await new Promise((r) => setTimeout(r, 1000))
    res = await poll(locationUrl)
  }
  return res
}

type ExchangeOutcome =
  | { kind: 'token'; authToken: string }
  | { kind: 'interaction'; interaction: Interaction }
  /** The PS is reaching the person by its own channels; poll `pollUrl`. */
  | { kind: 'pending'; pollUrl: string }
  | { kind: 'result'; status: number; body: unknown }

// How long the agent waits on a PS that is reaching the person itself before
// handing the wait back to the caller as `pending`. One invoke can wait twice
// (person token, then the exchange), and MCP clients abandon a tool call at
// about 60 s, so each wait stays well under half of that.
const PS_REACH_TIMEOUT_MS = 20_000

// Exchange a resource token at the PS for an auth token. `capabilities` tells the
// PS the agent can relay interactions to the user, so it returns a 202 consent
// interaction (surfaced for the caller to drive + retry) rather than requiring a
// registered mobile device. On PS endpoints this is a request-body parameter,
// not a header (the AAuth-Capabilities header is for resource requests).
//
// The mission does not appear here: it travels in the person token's
// `mission_s256`, which the resource copies into the resource token and the PS
// into the auth token.
//
// `presentedToken` is the token the agent presented to the resource on the
// request that produced this resource token — the person token, or on a
// step-up the auth token. AAuth -11 (§PS Token Endpoint, step 6) has the PS
// verify it against the `presented_jti` / `ps` / `sub` the resource copied;
// a PS refuses the exchange without it when the resource token names one.
//
// cfg.psHints (if set) are spread into the body — all §Auth Token Request
// optional params. cfg.onAuthToken (if set) is called with the auth_token before
// it is returned.
async function exchangeAtPS(
  cfg: ProxyConfig,
  ps: PSMetadata,
  resourceToken: string,
  presentedToken?: string,
): Promise<ExchangeOutcome> {
  const { capabilities, ...otherHints } = cfg.psHints ?? {}
  const res = await signWith(cfg, { kind: 'agent' }, { psOrAs: true })(ps.auth_token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      resource_token: resourceToken,
      ...(presentedToken ? { presented_token: presentedToken } : {}),
      capabilities: capabilities ?? ['interaction'],
      ...otherHints,
    }),
  })
  if (res.status === 202) {
    const interaction = interactionFrom(res, ps.interaction_endpoint)
    if (interaction) return { kind: 'interaction', interaction }
    const pollUrl = pendingFrom(res)
    return pollUrl ? { kind: 'pending', pollUrl } : { kind: 'result', status: res.status, body: await safeBody(res) }
  }
  if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }
  return tokenFrom(cfg, (await res.json()) as { auth_token?: string })
}

async function tokenFrom(cfg: ProxyConfig, body: { auth_token?: string }): Promise<Exclude<ExchangeOutcome, { kind: 'pending' }>> {
  if (typeof body.auth_token !== 'string' || !body.auth_token) {
    return { kind: 'result', status: 200, body: { error: 'ps_returned_no_auth_token', detail: body } }
  }
  if (cfg.onAuthToken) await cfg.onAuthToken(body.auth_token)
  return { kind: 'token', authToken: body.auth_token }
}

// Exchange, and when the PS is reaching the person itself, wait for it —
// the invoke path has nothing else to do until the token exists.
async function exchangeAtPSAndWait(cfg: ProxyConfig, ps: PSMetadata, resourceToken: string, presentedToken?: string): Promise<ExchangeOutcome> {
  const ex = await exchangeAtPS(cfg, ps, resourceToken, presentedToken)
  if (ex.kind !== 'pending') return ex
  const driven = await drivePending(cfg, ex.pollUrl, ps.interaction_endpoint, PS_REACH_TIMEOUT_MS)
  if (driven.kind === 'interaction') return driven
  if (driven.kind === 'pending') return ex
  if (driven.kind === 'result') return driven
  return tokenFrom(cfg, driven.body as { auth_token?: string })
}

// ── Authorize-first ──

/**
 * POST the resource's authorization endpoint, declaring the operations the
 * token should grant, and take back a resource token. The request MUST present a person token via
 * Signature-Key (protocol §Authorization Endpoint Request) — an agent token gets
 * `requirement=person-token`.
 */
async function authorizeAtResource(
  cfg: ProxyConfig,
  endpoint: string,
  personToken: string,
  vocabulary: string,
  operations: Array<Record<string, string>>,
  account?: string,
): Promise<{ kind: 'resourceToken'; resourceToken: string } | { kind: 'result'; status: number; body: unknown }> {
  const res = await signWith(cfg, { kind: 'person', jwt: personToken })(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      r3_operations: {
        vocabulary,
        // Bare identifiers, scoped to the one discovery endpoint the resource
        // advertises for this vocabulary (R3 -02 §Operation Identifier Scope),
        // in the vocabulary's own entry shape: `{ operationId }` for OpenAPI,
        // `{ tool }` for MCP.
        operations,
      },
      // N2: bind the authorization to one of the person's connected accounts.
      ...(account ? { account } : {}),
    }),
  })
  if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }
  const { resource_token } = (await res.json()) as { resource_token?: string }
  if (!resource_token) {
    // The resource handled authorization itself and issued no resource token.
    return { kind: 'result', status: res.status, body: await safeBody(res) }
  }
  return { kind: 'resourceToken', resourceToken: resource_token }
}

// ── The held auth token ──
//
// One auth token per (resource, account, mission) — tokens.ts. The opening
// credential for an authorize-first call is the held token while it grants the
// operation: one request, no PS round trip, and the budget it carries keeps
// being spent instead of a fresh allocation being drawn per call. When it does
// not grant the operation the agent authorizes for the union of what it holds
// and what it needs (plus whatever the ScopePolicy adds), and the new token
// takes the held one's place.
//
// It is presented until it lapses — not refreshed inside the margin. Its `exp`
// is capped by the agent token and, at a budgeted resource, by the access
// server's budget period, neither of which a refresh moves; a refresh would
// only draw another allocation. When it lapses, what happens next depends on
// whether the work was still going on: a token used within ACTIVE_WITHIN_SECS
// is renewed with its whole grant; one that sat idle lapsed with the activity
// that needed it, and the agent starts over from the one operation.

type Opened = { kind: 'cred'; cred: Credential; held?: TokenRecord } | Exclude<InvokeResult, { kind: 'skipped' }>

async function openWithAuthToken(
  cfg: ProxyConfig,
  l1: L1Entry,
  route: RoutedOperation,
  operationId: string,
  key: TokenKey,
  missionS256: string | undefined,
  account: string | undefined,
  needPS: () => Promise<PSMetadata>,
): Promise<Opened> {
  const vocabulary = route.adapter.vocabUri
  const entry = route.adapter.operationEntry(operationId)
  const presentable = (rec: TokenRecord | undefined): rec is TokenRecord =>
    rec !== undefined && grantsOperation(rec, vocabulary, entry)
  const present = (rec: TokenRecord): Opened => {
    cfg.log?.('token.hit', { kind: 'auth', resource: l1.issuer, ...(rec.jti ? { jti: rec.jti } : {}) })
    return { kind: 'cred', cred: { kind: 'auth', jwt: rec.value }, held: rec }
  }

  const held = await liveToken(cfg, key)
  if (presentable(held)) return present(held)

  // Without an authorization endpoint the resource issues resource tokens only
  // in a 401 (protocol §Resource Access and Resource Tokens): open with the
  // person token and let the requirement loop pick up the challenge.
  if (!l1.authorization_endpoint) {
    const pt = await obtainPersonToken(cfg, await needPS(), l1.issuer, missionS256)
    if (pt.kind !== 'token') return pt
    return { kind: 'cred', cred: { kind: 'person', jwt: pt.personToken } }
  }

  const store = tokenStore(cfg)
  const lease = await store.acquire?.(key)
  try {
    // Another call may have obtained what this one needs while it waited.
    const current = await liveToken(cfg, key)
    if (presentable(current)) return present(current)

    // Live but not granting this operation: grow it. Nothing live: renew what
    // lapsed while in use, or start over.
    const lapsed = current ? undefined : await store.get(key)
    const reason = current ? 'grow' : lapsed && wasInUse(lapsed) ? 'refresh' : 'initial'
    const operations = await requestedOperations(cfg, { l1, route, operationId, entry, key, reason, held: current, lapsed })

    const pt = await obtainPersonToken(cfg, await needPS(), l1.issuer, missionS256)
    if (pt.kind !== 'token') return pt
    const authz = await authorizeAtResource(cfg, l1.authorization_endpoint, pt.personToken, vocabulary, operations, account)
    if (authz.kind !== 'resourceToken') return authz
    const ex = await exchangeAtPSAndWait(cfg, await needPS(), authz.resourceToken, pt.personToken)
    if (ex.kind !== 'token') return ex
    const rec = await adoptAuthToken(cfg, key, ex.authToken, reason, pt.personToken)
    return { kind: 'cred', cred: { kind: 'auth', jwt: ex.authToken }, ...(rec ? { held: rec } : {}) }
  } finally {
    await releaseLease(cfg, key, lease)
  }
}

async function releaseLease(cfg: ProxyConfig, key: TokenKey, lease: string | undefined): Promise<void> {
  if (lease === undefined) return
  try {
    await tokenStore(cfg).release?.(key, lease)
  } catch {
    // The lease lapses on its own; a failed release must not fail the call.
  }
}

// What to declare in `r3_operations`: everything the token being grown or
// renewed grants (in the same vocabulary), the operation being invoked, and
// whatever the ScopePolicy adds. The policy only ever adds.
async function requestedOperations(
  cfg: ProxyConfig,
  r: {
    l1: L1Entry
    route: RoutedOperation
    operationId: string
    entry: Record<string, string>
    key: TokenKey
    reason: 'initial' | 'grow' | 'refresh'
    held?: TokenRecord
    lapsed?: TokenRecord
  },
): Promise<Array<Record<string, string>>> {
  const vocabulary = r.route.adapter.vocabUri
  const from = r.reason === 'grow' ? r.held : r.reason === 'refresh' ? r.lapsed : undefined
  const carried = from?.granted?.vocabulary === vocabulary ? from.granted.operations : []
  let extra: Array<Record<string, string>> = []
  try {
    const lapsed = r.lapsed
    extra = await (cfg.scopePolicy ?? minimalScope)({
      resource: r.l1,
      vocabulary,
      opId: r.operationId,
      operation: r.entry,
      reason: r.reason,
      ...(r.held ? { held: r.held } : {}),
      ...(lapsed ? { lapsed } : {}),
      operations: () => listOperationsForResource(r.l1),
      entryFor: (opId) => r.route.adapter.operationEntry(opId),
    })
  } catch (err) {
    // A policy is a refinement: when it fails, ask for what the call needs.
    cfg.log?.('scope.policy_error', { resource: r.l1.issuer, error: (err as Error)?.message ?? String(err) })
  }
  return uniqueOperations([...carried, r.entry, ...extra])
}

/** Keep an auth token as the one held for `key`. Undefined when it cannot be kept (not a JWT, no `exp`). */
async function adoptAuthToken(
  cfg: ProxyConfig,
  key: TokenKey,
  jwt: string,
  reason: string,
  presented?: string,
): Promise<TokenRecord | undefined> {
  const presentedJti = presented ? jtiOf(presented) : undefined
  const rec = authTokenRecord(key, jwt, { agentJkt: await agentJkt(cfg), ...(presentedJti ? { presentedJti } : {}) })
  if (!rec) return undefined
  await keepToken(cfg, rec, reason)
  return rec
}

// After a response to the held token: when it was used, and what the resource
// says is left of its budget (draft-hardt-aauth-budgets §AAuth-Budget Response
// Header). Advisory — shown to the model, never used to refuse a call.
async function noteUse(cfg: ProxyConfig, key: TokenKey, held: TokenRecord, res: Response): Promise<void> {
  const reported = parseBudget(res.headers.get('aauth-budget'))
  const patch: Partial<TokenRecord> = { last_used: Math.floor(Date.now() / 1000) }
  if (reported?.remaining !== undefined && held.budget) patch.budget = { ...held.budget, remaining: reported.remaining }
  await tokenStore(cfg).update(key, held.jti, patch)
}

// Whether a token a settled pending delivered is this key's to hold: bound to
// the same account and mission, granting the operation being invoked, and
// taking nothing away from the token the key already holds.
function resumeFits(
  rec: TokenRecord,
  key: TokenKey,
  vocabulary: string,
  entry: Record<string, string>,
  current: TokenRecord | undefined,
): boolean {
  let claims: Record<string, unknown>
  try {
    claims = decodeJwtPayload(rec.value)
  } catch {
    return false
  }
  if ((claims.account ?? undefined) !== key.account) return false
  if ((claims.mission_s256 ?? undefined) !== key.mission_s256) return false
  if (!grantsOperation(rec, vocabulary, entry)) return false
  return !current || grantsAtLeast(rec, current)
}

// A step-up: the resource answered the credential with `requirement=auth-token`
// and a resource token — the held token's budget is spent, it was revoked, or
// the call needs more than it grants. Serialized per key like acquisition, so
// concurrent calls presenting the same spent token step it up once.
//
// The new token takes the held one's place when it grants at least as much, or
// when the held one is spent. Anything narrower (a proposal for one call, a
// grant for one operation) is presented for this call and the held token kept.
async function stepUp(
  cfg: ProxyConfig,
  key: TokenKey,
  route: RoutedOperation,
  operationId: string,
  req: ParsedRequirement,
  presented: string | undefined,
  presentedHeld: TokenRecord | undefined,
  needPS: () => Promise<PSMetadata>,
): Promise<{ kind: 'cred'; cred: Credential; held?: TokenRecord } | Exclude<InvokeResult, { kind: 'skipped' }>> {
  const vocabulary = route.adapter.vocabUri
  const entry = route.adapter.operationEntry(operationId)
  const store = tokenStore(cfg)
  const lease = await store.acquire?.(key)
  try {
    // Another call stepped the same token up while this one waited.
    const current = await liveToken(cfg, key)
    if (current && current.value !== presented && grantsOperation(current, vocabulary, entry)) {
      cfg.log?.('token.hit', { kind: 'auth', resource: key.resource, ...(current.jti ? { jti: current.jti } : {}) })
      return { kind: 'cred', cred: { kind: 'auth', jwt: current.value }, held: current }
    }

    const ex = await exchangeAtPSAndWait(cfg, await needPS(), req.resourceToken!, presented)
    if (ex.kind !== 'token') return ex
    const cred: Credential = { kind: 'auth', jwt: ex.authToken }

    const presentedJti = presented ? jtiOf(presented) : undefined
    const rec = authTokenRecord(key, ex.authToken, { agentJkt: await agentJkt(cfg), ...(presentedJti ? { presentedJti } : {}) })
    const spent = req.reason === 'budget-exhausted' || req.reason === 'insufficient-budget'
    if (rec && (!current || spent || grantsAtLeast(rec, current))) {
      await keepToken(cfg, rec, 'step-up')
      return { kind: 'cred', cred, held: rec }
    }
    // Not kept. A token the resource just refused as spent still goes.
    if (!rec && presentedHeld && spent) await dropPresented(cfg, key, presentedHeld.value, 'replaced')
    return { kind: 'cred', cred }
  } finally {
    await releaseLease(cfg, key, lease)
  }
}

// Drop the record for `key` only while it is still the token presented, so a
// refusal of an old token never removes the one a concurrent call just stored.
async function dropPresented(cfg: ProxyConfig, key: TokenKey, value: string, reason: string): Promise<void> {
  const store = tokenStore(cfg)
  const cur = await store.get(key)
  if (!cur || cur.value !== value) return
  await store.drop(key, cur.jti)
  cfg.log?.('token.drop', { ...tokenLogFields(key), reason, ...(cur.jti ? { jti: cur.jti } : {}) })
}

// ── invoke ──

const MAX_ROUNDS = 6

export async function invokeAtResource(
  cfg: ProxyConfig,
  l1: L1Entry,
  operationId: string,
  args: InvokeArgs = {},
  opts: InvokeOptions = {},
): Promise<InvokeResult> {
  const route = await routeOperation(l1, operationId, args)
  if (route.plan.kind !== 'sync.request') {
    return {
      kind: 'result',
      status: 501,
      body: { error: `${route.plan.kind}_not_yet_supported`, opId: operationId },
    }
  }
  const plan = route.plan
  const apiUrl = `${l1.origin}${plan.path}${plan.query ? `?${plan.query}` : ''}`
  // Fixed for the whole flow. A per-call retry MUST present exactly the
  // parameters the proposal was approved for (R3 -02 §Per-Call Proposals step 3):
  // the resource recovers the proposal by its hash and rejects any difference.
  const init: SignedRequestInit = {
    method: plan.method,
    ...(plan.headers ? { headers: plan.headers } : {}),
    ...(plan.body !== undefined ? { body: plan.body } : {}),
  }

  const missionS256 = opts.missionS256 ?? cfg.missionS256

  // Three-way access_mode plan against the mode that applies to THIS operation:
  // its own annotation when it carries one, the resource-wide access_mode
  // otherwise (R3 -02 §Applying Annotations).
  const accessPlan: AccessModePlan = planAccessMode(route.accessMode, {
    hasPersonServer: agentTokenPs(cfg.agentToken) !== undefined,
  })
  if (accessPlan.kind === 'unsatisfiable') {
    return {
      kind: 'skipped',
      resource: l1.resource,
      opId: operationId,
      mode: accessPlan.mode,
      reason: accessPlan.reason,
    }
  }

  let ps: PSMetadata | undefined
  const needPS = async (): Promise<PSMetadata> => {
    ps ??= await psMetadata(cfg.psUrl)
    return ps
  }

  // The one auth token held for this resource, account and mission.
  const authKey: TokenKey = {
    kind: 'auth',
    resource: l1.issuer,
    ...(opts.account ? { account: opts.account } : {}),
    ...(missionS256 ? { mission_s256: missionS256 } : {}),
  }
  // An operation authorized per call gets a single-use token bound to this
  // call's parameters (R3 -02 §Per-Call Proposals). It is presented once and
  // never takes the held token's place.
  const perCall = route.accessMode === 'per-call'
  // The held token, while it is what this call presents: its budget is tracked
  // from the resource's AAuth-Budget, and a token the resource steps up
  // replaces it.
  let held: TokenRecord | undefined

  // ── Opening credential ──
  //
  // The plan only decides where to start. Everything after this point is the
  // requirement loop, which is identical in every mode.
  let cred: Credential = { kind: 'agent' }

  // A named account (the AAuth `account` extension) only travels in an auth
  // token: it is bound at the authorization endpoint and the resource routes
  // on it. A person-token read carries no account, so with more than one
  // account connected the resource can only answer account_required — take
  // the auth-token path whenever the caller named one.
  const mode = accessPlan.kind === 'satisfiable' && accessPlan.mode === 'person-token' && opts.account ? 'auth-token' : accessPlan.kind === 'satisfiable' ? accessPlan.mode : undefined

  if (opts.authToken) {
    // A settled pending delivered the token a previous call went to get. The
    // pending is tracked per host, so it may have been for another account,
    // another operation, or one call's per-call approval: present it for this
    // call, and hold it only when it is plainly this key's token (resumeFits).
    cred = { kind: 'auth', jwt: opts.authToken }
    if (!perCall) {
      const vocabulary = route.adapter.vocabUri
      const entry = route.adapter.operationEntry(operationId)
      const rec = authTokenRecord(authKey, opts.authToken, { agentJkt: await agentJkt(cfg) })
      const current = await liveToken(cfg, authKey)
      if (rec && resumeFits(rec, authKey, vocabulary, entry, current)) {
        await keepToken(cfg, rec, 'settled')
        held = rec
      }
    }
  } else if (accessPlan.kind === 'satisfiable') {
    switch (mode) {
      case 'agent-token':
        break

      case 'session-token': {
        // Resource-managed. Present the session token if we already hold one;
        // otherwise call with the agent token and let the resource start its own
        // consent flow with a 202 interaction.
        const session = await heldSession(cfg, l1)
        if (session) cred = { kind: 'session', token: session }
        break
      }

      case 'person-token': {
        const pt = await obtainPersonToken(cfg, await needPS(), l1.issuer, missionS256)
        if (pt.kind !== 'token') return pt
        cred = { kind: 'person', jwt: pt.personToken }
        break
      }

      case 'auth-token':
      case 'per-call': {
        // Authorize-first when the resource publishes an authorization_endpoint:
        // declare the operations, take back a resource token, exchange it at the
        // PS. Without one, the resource issues resource tokens via 401 instead
        // (protocol §Resource Access and Resource Tokens) — start with the
        // person token and let the requirement loop pick up the challenge.
        const opened = await openWithAuthToken(cfg, l1, route, operationId, authKey, missionS256, opts.account, needPS)
        if (opened.kind !== 'cred') return opened
        cred = opened.cred
        held = opened.held
        break
      }
    }
  }

  // ── Requirement loop ──
  //
  // Make the request, read any AAuth-Requirement, satisfy it, retry. `satisfied`
  // stops the loop from chasing the same requirement twice with the same
  // credential, which is what a resource that will never be satisfiable looks
  // like from here.
  const satisfied = new Set<string>()

  for (let round = 0; round < MAX_ROUNDS; round++) {
    const res = await signWith(cfg, cred)(apiUrl, init)

    // A resource MAY replace the agent's session token on any response.
    const access = res.headers.get('aauth-access')
    if (access) {
      await keepSession(cfg, l1, access)
      if (cred.kind !== 'auth' && cred.kind !== 'person') cred = { kind: 'session', token: access }
    }

    const presentedHeld = held !== undefined && cred.kind === 'auth' && cred.jwt === held.value ? held : undefined
    if (presentedHeld) await noteUse(cfg, authKey, presentedHeld, res)

    const req = parseRequirement(res.headers.get('aauth-requirement'))
    if (!req) return { kind: 'result', status: res.status, body: await safeBody(res), ...withBudget(res) }

    const marker = `${req.requirement}:${cred.kind}`
    if (satisfied.has(marker)) {
      // Same requirement, same credential kind, second time — e.g. the budget of
      // the auth token we just re-acquired is exhausted again. Stop and surface
      // the challenge (with its reason) rather than spin.
      return terminalChallenge(res, req)
    }
    satisfied.add(marker)

    switch (req.requirement) {
      case 'agent-token': {
        // The resource wants the agent's own identity token specifically.
        if (cred.kind === 'agent') {
          return { kind: 'result', status: res.status, body: await safeBody(res) }
        }
        cred = { kind: 'agent' }
        continue
      }

      case 'person-token': {
        // The resource will not take the token presented. A held auth token it
        // refuses this way is dead to it (expired, revoked); a person token it
        // refuses is replaced rather than presented again.
        if (presentedHeld) {
          await dropPresented(cfg, authKey, presentedHeld.value, 'refused')
          held = undefined
        }
        if (cred.kind === 'person') await dropPresented(cfg, personKey(l1.issuer, missionS256), cred.jwt, 'refused')
        const pt = await obtainPersonToken(cfg, await needPS(), l1.issuer, missionS256)
        if (pt.kind !== 'token') return pt
        cred = { kind: 'person', jwt: pt.personToken }
        continue
      }

      case 'auth-token': {
        // A step-up: the held token's budget is spent, it was revoked, or the
        // call needs more than it grants — and the per-call path: for an
        // `r3_per_call` operation the resource builds a proposal from this
        // call's concrete parameters, persists it under its hash, and returns a
        // resource token carrying only the `r3_uri`/`r3_s256` reference. The
        // agent exchanges it and retries the identical call (R3 -02 §Per-Call
        // Proposals).
        if (!req.resourceToken) {
          return terminalChallenge(res, req)
        }
        // The credential that drew the challenge is what the resource copied
        // out of; the PS checks the exchange against it.
        const presented = cred.kind === 'person' || cred.kind === 'auth' ? cred.jwt : undefined
        if (perCall) {
          // Good for this one call: never held.
          const ex = await exchangeAtPSAndWait(cfg, await needPS(), req.resourceToken, presented)
          if (ex.kind !== 'token') return ex
          cred = { kind: 'auth', jwt: ex.authToken }
          continue
        }
        const stepped = await stepUp(cfg, authKey, route, operationId, req, presented, presentedHeld, needPS)
        if (stepped.kind !== 'cred') return stepped
        cred = stepped.cred
        held = stepped.held
        continue
      }

      case 'interaction': {
        // A resource-owned 202 (resource-managed session consent). The agent
        // opens `{interaction_endpoint}?code=` itself — the caller surfaces it
        // (local OS open, native elicitation, or text + QR) and polls. There
        // is no relay to the PS (ONBOARDING-PLAN-2.md Q5): the PS drives only
        // the interactions it is told about inside a resource token.
        const interaction = interactionFrom(res, l1.interaction_endpoint)
        if (!interaction) {
          return { kind: 'result', status: res.status, body: await safeBody(res) }
        }
        return { kind: 'interaction', interaction }
      }

      default:
        // A requirement value this build does not know. The agent MUST NOT
        // treat the response as satisfiable; surface it verbatim.
        return {
          kind: 'result',
          status: res.status,
          body: {
            error: 'unsupported_requirement',
            requirement: req.requirement,
            detail: await safeBody(res),
          },
        }
    }
  }

  return {
    kind: 'result',
    status: 429,
    body: { error: 'requirement_loop', detail: `${l1.resource} kept challenging after ${MAX_ROUNDS} rounds` },
  }
}

// Drive invokeAtResource to completion: perform each interaction via
// `onInteraction`, poll until it resolves, and retry. For programmatic / test
// use; the MCP tool surface is non-blocking by design and surfaces interaction
// URLs to the LLM caller instead.
export async function invokeAtResourceComplete(
  cfg: ProxyConfig,
  l1: L1Entry,
  operationId: string,
  onInteraction: InteractionHandler,
  args: InvokeArgs = {},
  maxRounds = 5,
  pollTimeoutMs = 180_000,
  onPoll?: (elapsedMs: number) => void | Promise<void>,
  opts: InvokeOptions = {},
): Promise<{ status: number; body: unknown }> {
  const poll = makeAgentPoll(cfg)
  for (let round = 0; round < maxRounds; round++) {
    const result = await invokeAtResource(cfg, l1, operationId, args, opts)
    if (result.kind === 'result') return { status: result.status, body: result.body }
    if (result.kind === 'skipped') {
      return { status: 0, body: { error: 'access_mode_unsatisfiable', ...result } }
    }
    if (result.kind === 'pending') {
      // The PS is still reaching the person. Keep waiting; if it falls back
      // to an interaction, the next round surfaces it.
      await pollUntilDone(poll, result.pollUrl, pollTimeoutMs, onPoll, advertisesInteraction)
      continue
    }
    await onInteraction(result.interaction.url, result.interaction.code)
    const completed = await pollUntilDone(poll, result.interaction.pollUrl, pollTimeoutMs, onPoll)
    // A resource-managed consent settles with the session token on the poll
    // (AAuth-Access); keep it so the retry presents it.
    const settled = completed.headers.get('aauth-access')
    if (settled) await keepSession(cfg, l1, settled)
  }
  throw new Error('invoke did not complete after interactions')
}

// Signed DELETE to an admin endpoint on the resource (e.g. /admin/tokens).
// Uses the agent token so the resource can verify the caller owns the key.
export async function deleteAtAdmin(cfg: ProxyConfig, l1: L1Entry, path: string): Promise<Response> {
  return signWith(cfg, { kind: 'agent' })(`${l1.origin}${path}`, { method: 'DELETE' })
}

// ── Connections (ONBOARDING-PLAN.md §3.0, N3–N6) ──
//
// The link ceremony. Where `invoke` authorizes an AGENT for operations,
// `connectAtResource` links the PERSON's upstream account: POST on the
// resource's connection collection with a person token, take back a
// connection-only resource token (an interaction and no `scope`), exchange it
// at the PS, and surface the interaction the PS answers with — the person
// goes to `{ps.interaction_endpoint}?code=`, where the PS explains and sends
// them on to the resource's own flow. The PS issues no auth token for this
// shape; it terminates with `connection_established`.

export interface ConnectArgs {
  /** Present iff the resource declares `connection.account_description`. */
  account?: string
  /** Subset of the declared `connection.scopes[]`; omitted → the resource's defaults. */
  scopes?: string[]
}

export type ConnectOutcome =
  /** Nothing to connect: no `connection` published (an agent-token resource), or already connected. */
  | { kind: 'ready'; reason: 'no_connection_needed' | 'already_connected'; account?: string; scopes?: string[] }
  /**
   * The flow completed at the PS. From `pollConnection`, `body` is the terminal
   * response body and `access` its AAuth-Access header: a pending delivers the
   * token it settled with there, and nowhere else (`adoptSettled`).
   */
  | { kind: 'connected'; account?: string; body?: unknown; access?: string }
  /** The person must act: the caller surfaces `{url}?code=`, then polls `pollUrl` (`pollConnection`). */
  | { kind: 'interaction'; interaction: Interaction }
  /**
   * Not finished yet: poll `pollUrl` or call again. `interaction` is present
   * when the person has a URL to open; absent while the PS is reaching them by
   * its own channels (an open wallet tab, a device) — a later poll may
   * advertise one.
   */
  | { kind: 'still_pending'; pollUrl: string; interaction?: Interaction }
  | { kind: 'error'; status: number; body: unknown }

/**
 * POST the connection collection and exchange the resulting token at the PS.
 * Non-blocking: the PS's 202 comes back as `interaction` for the caller to
 * surface; the caller decides how long to wait (`pollConnection`).
 */
export async function connectAtResource(cfg: ProxyConfig, l1: L1Entry, args: ConnectArgs = {}): Promise<ConnectOutcome> {
  if (!l1.connection) return { kind: 'ready', reason: 'no_connection_needed' }
  const ps = await psMetadata(cfg.psUrl)
  const pt = await obtainPersonToken(cfg, ps, l1.issuer, cfg.missionS256)
  if (pt.kind === 'interaction') return { kind: 'interaction', interaction: pt.interaction }
  if (pt.kind === 'pending') return { kind: 'still_pending', pollUrl: pt.pollUrl }
  if (pt.kind !== 'token') return { kind: 'error', status: pt.status, body: pt.body }

  const res = await signWith(cfg, { kind: 'person', jwt: pt.personToken })(l1.connection.endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      ...(args.scopes ? { scopes: args.scopes } : {}),
      ...(args.account ? { account: args.account } : {}),
    }),
  })
  if (!res.ok) return { kind: 'error', status: res.status, body: await safeBody(res) }
  const body = (await res.json()) as { resource_token?: string; status?: string; account?: string; scopes?: string[] }
  if (body.status === 'already_connected') {
    return { kind: 'ready', reason: 'already_connected', ...(body.account ? { account: body.account } : {}), ...(body.scopes ? { scopes: body.scopes } : {}) }
  }
  if (!body.resource_token) return { kind: 'error', status: res.status, body }

  const ex = await exchangeAtPS(cfg, ps, body.resource_token, pt.personToken)
  if (ex.kind === 'token') return { kind: 'connected', ...(args.account ? { account: args.account } : {}) }
  // The PS is reaching the person itself (open wallet tab, device): nothing
  // to surface yet; the caller polls.
  if (ex.kind === 'pending') return { kind: 'still_pending', pollUrl: ex.pollUrl }
  if (ex.kind === 'result') {
    // N6: a terminal answer that carries no token is the connection-only
    // ceremony completing on the spot.
    if (ex.status >= 200 && ex.status < 300) return { kind: 'connected', ...(args.account ? { account: args.account } : {}) }
    return { kind: 'error', status: ex.status, body: ex.body }
  }
  // The PS wants the person: hand the caller the URL (composed from the PS
  // metadata when the header carried only the code). The PS reaches an open
  // wallet tab on its own when it can; either way the caller polls.
  return { kind: 'interaction', interaction: ex.interaction }
}

/**
 * The bounded wait (D14 B2): poll the PS pending URL for up to `budgetMs`.
 * Resolves `connected` on any terminal 2xx — with or without a token (N6) —
 * `still_pending` when the slice elapses (adopting an interaction the poll
 * advertises, if the PS gave up reaching the person itself), and `error` on a
 * terminal failure. `pollUrl` may be the URL or a prior `Interaction`.
 */
export async function pollConnection(cfg: ProxyConfig, pending: string | Interaction, budgetMs: number, onPoll?: (elapsedMs: number) => void | Promise<void>): Promise<ConnectOutcome> {
  const pollUrl = typeof pending === 'string' ? pending : pending.pollUrl
  const prior = typeof pending === 'string' ? undefined : pending
  // With no interaction known yet, one the PS starts advertising ends the wait:
  // the person needs its URL now, not at the end of the slice.
  const res = await pollUntilDone(makeAgentPoll(cfg), pollUrl, budgetMs, onPoll, prior ? undefined : advertisesInteraction)
  if (res.status === 202) {
    const advertised = interactionFrom(res, prior?.url ?? (await psMetadata(cfg.psUrl).catch(() => undefined))?.interaction_endpoint)
    const interaction = advertised ?? prior
    return { kind: 'still_pending', pollUrl, ...(interaction ? { interaction } : {}) }
  }
  if (res.status >= 200 && res.status < 300) {
    const access = res.headers.get('aauth-access')
    return { kind: 'connected', body: await safeBody(res), ...(access ? { access } : {}) }
  }
  return { kind: 'error', status: res.status, body: await safeBody(res) }
}

/**
 * Keep what a settled pending delivered. The PS answers the pending URL with
 * the token it issued on approval — `person_token` for a person token request,
 * `auth_token` for an exchange — and a resource-owned consent settles with
 * AAuth-Access. That response is the only delivery: a fresh request is a new
 * request, and a PS that prompts per request mints a new interaction for it.
 * The person token goes into the cache `obtainPersonToken` reads, the session
 * token into the session store; the auth token is returned for the caller to
 * present (`InvokeOptions.authToken`).
 */
export async function adoptSettled(
  cfg: ProxyConfig,
  l1: L1Entry,
  settled: { body?: unknown; access?: string },
  missionS256 = cfg.missionS256,
): Promise<{ adopted: Array<'person_token' | 'auth_token' | 'session_token'>; authToken?: string }> {
  const adopted: Array<'person_token' | 'auth_token' | 'session_token'> = []
  const body = (settled.body && typeof settled.body === 'object' ? settled.body : {}) as {
    person_token?: unknown
    auth_token?: unknown
    expires_in?: unknown
  }
  if (typeof body.person_token === 'string' && body.person_token) {
    const key = personKey(l1.issuer, missionS256)
    const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : undefined
    await keepToken(cfg, await personRecord(cfg, key, body.person_token, expiresIn), 'settled')
    adopted.push('person_token')
  }
  if (settled.access) {
    await keepSession(cfg, l1, settled.access)
    adopted.push('session_token')
  }
  let authToken: string | undefined
  if (typeof body.auth_token === 'string' && body.auth_token) {
    if (cfg.onAuthToken) await cfg.onAuthToken(body.auth_token)
    authToken = body.auth_token
    adopted.push('auth_token')
  }
  return { adopted, ...(authToken ? { authToken } : {}) }
}

/** `GET {connection.endpoint}` — this person's connections, as the resource believes them. */
export async function listConnections(cfg: ProxyConfig, l1: L1Entry): Promise<{ kind: 'rows'; rows: ConnectionRow[] } | { kind: 'error'; status: number; body: unknown }> {
  if (!l1.connection) return { kind: 'rows', rows: [] }
  const ps = await psMetadata(cfg.psUrl)
  const pt = await obtainPersonToken(cfg, ps, l1.issuer, cfg.missionS256)
  if (pt.kind !== 'token') return { kind: 'error', status: pt.kind === 'result' ? pt.status : 202, body: pt.kind === 'result' ? pt.body : { error: 'person_token_interaction' } }
  const res = await signWith(cfg, { kind: 'person', jwt: pt.personToken })(l1.connection.endpoint, { method: 'GET' })
  if (!res.ok) return { kind: 'error', status: res.status, body: await safeBody(res) }
  const body = (await res.json()) as { connections?: ConnectionRow[] }
  return { kind: 'rows', rows: Array.isArray(body.connections) ? body.connections : [] }
}

export interface DisconnectRow {
  account: string
  status: number
  /** What the resource says happened at the upstream: revoked, not_supported, failed, … */
  upstream?: string
  detail?: unknown
}

/** `DELETE {connection.endpoint}/{account}` for every account the resource lists. */
export async function disconnectAll(cfg: ProxyConfig, l1: L1Entry): Promise<DisconnectRow[]> {
  if (!l1.connection) return []
  const listed = await listConnections(cfg, l1)
  const accounts = listed.kind === 'rows' ? listed.rows.map((r) => r.account) : (l1.connections ?? []).map((r) => r.account)
  if (accounts.length === 0) return []
  const ps = await psMetadata(cfg.psUrl)
  const pt = await obtainPersonToken(cfg, ps, l1.issuer, cfg.missionS256)
  if (pt.kind !== 'token') return accounts.map((account) => ({ account, status: 0, detail: 'no person token' }))
  const out: DisconnectRow[] = []
  for (const account of accounts) {
    const res = await signWith(cfg, { kind: 'person', jwt: pt.personToken })(`${l1.connection.endpoint}/${encodeURIComponent(account)}`, { method: 'DELETE' })
    const body = (await safeBody(res)) as { upstream?: string; detail?: unknown; action_required?: string }
    out.push({
      account,
      status: res.status,
      ...(body && typeof body === 'object' && typeof body.upstream === 'string' ? { upstream: body.upstream } : {}),
      ...(body && typeof body === 'object' && (body.action_required ?? body.detail) !== undefined ? { detail: body.action_required ?? body.detail } : {}),
    })
  }
  return out
}
