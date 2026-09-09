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
import { agentTokenPs, jwkThumbprint } from './jwt.js'
import { routeOperation } from './resource.js'
import { createMemoryPersonTokenStore } from './store.js'
import type { ConnectionRow, L1Entry, PersonTokenStore } from './store.js'

export type AgentSigningKey = Parameters<typeof signedFetch>[1]['signingKey']

/**
 * Optional hints forwarded verbatim as extra body parameters in every POST to
 * the PS auth token endpoint (protocol §Agent Token Request). All fields are
 * optional; include only those the host has learned about the user.
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

/** Opaque per-resource session token from the AAuth-Access header. */
export interface SessionTokenStore {
  get(resource: string): Promise<string | undefined>
  set(resource: string, token: string): Promise<void>
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
   * Person-token cache. Keyed (resource, mission_s256); flushed whole when the
   * agent's signing key changes. Defaults to a per-config in-memory store.
   */
  personTokens?: PersonTokenStore
  /** Session-token store for `session-token` resources. Defaults to per-config memory. */
  sessionTokens?: SessionTokenStore
  /**
   * Called with each auth_token received from the PS before it is used.
   * Hosts can use this to record or validate the PS sub across exchanges.
   */
  onAuthToken?: (token: string) => void | Promise<void>
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
}

export interface Interaction {
  url: string
  code: string
  pollUrl: string
}

export type InvokeResult =
  | { kind: 'result'; status: number; body: unknown }
  | { kind: 'interaction'; interaction: Interaction }
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
    return signedFetch(url, {
      ...init,
      headers,
      signingKey: cfg.agentPrivateJwk,
      signatureKey: { type: 'jwt', jwt },
      ...(list ? { components: list } : {}),
    })
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

// A terminal challenge response, annotated with the challenge's `reason` when
// one was sent so the caller (ultimately the LLM) sees `budget-exhausted` /
// `insufficient-budget` instead of a bare status.
async function terminalChallenge(res: Response, req: ParsedRequirement): Promise<InvokeResult> {
  const body = await safeBody(res)
  return {
    kind: 'result',
    status: res.status,
    body: req.reason ? { error: req.reason, detail: body } : body,
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

async function safeBody(res: Response): Promise<unknown> {
  const text = await res.text()
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

// ── Per-config default stores ──
//
// Keyed on the ProxyConfig object, which the identity provider resolves
// per-principal. A process-global cache would leak person and session tokens
// across tenants in a multi-user host.

const defaultPersonTokens = new WeakMap<ProxyConfig, PersonTokenStore>()
const defaultSessionTokens = new WeakMap<ProxyConfig, SessionTokenStore>()

function personTokenStore(cfg: ProxyConfig): PersonTokenStore {
  if (cfg.personTokens) return cfg.personTokens
  let store = defaultPersonTokens.get(cfg)
  if (!store) {
    store = createMemoryPersonTokenStore()
    defaultPersonTokens.set(cfg, store)
  }
  return store
}

function sessionTokenStore(cfg: ProxyConfig): SessionTokenStore {
  if (cfg.sessionTokens) return cfg.sessionTokens
  let store = defaultSessionTokens.get(cfg)
  if (!store) {
    const m = new Map<string, string>()
    store = {
      async get(resource) {
        return m.get(resource)
      },
      async set(resource, token) {
        m.set(resource, token)
      },
    }
    defaultSessionTokens.set(cfg, store)
  }
  return store
}

// ── Person tokens ──

type PersonTokenOutcome =
  | { kind: 'token'; personToken: string }
  | { kind: 'interaction'; interaction: Interaction }
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

  const store = personTokenStore(cfg)
  const jkt = await jwkThumbprint(cfg.agentPrivateJwk as { kty?: string })
  const key = { resource, ...(missionS256 ? { mission_s256: missionS256 } : {}) }

  const cached = await store.get(key, jkt)
  if (cached) return { kind: 'token', personToken: cached }

  // `capabilities` tells the PS this agent can put a URL in front of the
  // person (§Person Token Request): without it a first binding at a PS that
  // cannot reach them another way (no open wallet tab, no push device) is
  // refused with user_unreachable instead of a 202 interaction.
  const res = await signWith(cfg, { kind: 'agent' }, { psOrAs: true })(ps.person_token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      resource,
      capabilities: cfg.psHints?.capabilities ?? ['interaction'],
      ...(missionS256 ? { mission_s256: missionS256 } : {}),
    }),
  })

  if (res.status === 202) {
    const interaction = interactionFrom(res, ps.interaction_endpoint)
    if (interaction) return { kind: 'interaction', interaction }
  }
  if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }

  const { person_token, expires_in } = (await res.json()) as {
    person_token: string
    expires_in?: number
  }
  if (!person_token) {
    return { kind: 'result', status: res.status, body: { error: 'ps_returned_no_person_token' } }
  }
  const expiresAt = Math.floor(Date.now() / 1000) + (expires_in ?? 3600)
  await store.set(key, jkt, person_token, expiresAt)
  return { kind: 'token', personToken: person_token }
}

/**
 * Drop every cached person token. Call when the agent's signing key rotates —
 * every person token binds the same key through `cnf`, so none of them survive.
 * `obtainPersonToken` also detects rotation on its own via the key thumbprint;
 * this is the explicit hook for a host that knows a rotation happened.
 */
export async function flushPersonTokens(cfg: ProxyConfig): Promise<void> {
  await personTokenStore(cfg).flush()
}

type Poller = (url: string) => Promise<Response>

// Poll a deferred (202) Location until terminal. The poll MUST be signed — the
// PS pending endpoint verifies the agent signature (an unsigned poll gets 401,
// which would look like an instant terminal response).
//
// `onPoll` (optional) is invoked once per poll iteration with elapsed ms — a
// heartbeat hook for hosts that hold a request open (e.g. emit progress
// notifications over a long-running tool call).
export async function pollUntilDone(
  poll: Poller,
  locationUrl: string,
  timeoutMs = 180_000,
  onPoll?: (elapsedMs: number) => void | Promise<void>,
): Promise<Response> {
  const start = Date.now()
  const deadline = start + timeoutMs
  let res = await poll(locationUrl)
  while (res.status === 202 && Date.now() < deadline) {
    await onPoll?.(Date.now() - start)
    await new Promise((r) => setTimeout(r, 1000))
    res = await poll(locationUrl)
  }
  return res
}

type ExchangeOutcome =
  | { kind: 'token'; authToken: string }
  | { kind: 'interaction'; interaction: Interaction }
  | { kind: 'result'; status: number; body: unknown }

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
// cfg.psHints (if set) are spread into the body — all §Agent Token Request
// optional params. cfg.onAuthToken (if set) is called with the auth_token before
// it is returned.
async function exchangeAtPS(
  cfg: ProxyConfig,
  ps: PSMetadata,
  resourceToken: string,
): Promise<ExchangeOutcome> {
  const { capabilities, ...otherHints } = cfg.psHints ?? {}
  const res = await signWith(cfg, { kind: 'agent' }, { psOrAs: true })(ps.auth_token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      resource_token: resourceToken,
      capabilities: capabilities ?? ['interaction'],
      ...otherHints,
    }),
  })
  if (res.status === 202) {
    const interaction = interactionFrom(res, ps.interaction_endpoint)
    if (interaction) return { kind: 'interaction', interaction }
  }
  if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }
  const { auth_token } = (await res.json()) as { auth_token: string }
  if (cfg.onAuthToken) await cfg.onAuthToken(auth_token)
  return { kind: 'token', authToken: auth_token }
}

// ── Authorize-first ──

/**
 * POST the resource's authorization endpoint, declaring the operation, and take
 * back a resource token. The request MUST present a person token via
 * Signature-Key (protocol §Authorization Endpoint Request) — an agent token gets
 * `requirement=person-token`.
 */
async function authorizeAtResource(
  cfg: ProxyConfig,
  endpoint: string,
  personToken: string,
  vocabulary: string,
  operationId: string,
  account?: string,
): Promise<{ kind: 'resourceToken'; resourceToken: string } | { kind: 'result'; status: number; body: unknown }> {
  const res = await signWith(cfg, { kind: 'person', jwt: personToken })(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      r3_operations: {
        vocabulary,
        // Bare identifiers, scoped to the one discovery endpoint the resource
        // advertises for this vocabulary (R3 -02 §Operation Identifier Scope).
        operations: [{ operationId }],
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
  const sessions = sessionTokenStore(cfg)

  // ── Opening credential ──
  //
  // The plan only decides where to start. Everything after this point is the
  // requirement loop, which is identical in every mode.
  let cred: Credential = { kind: 'agent' }

  if (accessPlan.kind === 'satisfiable') {
    switch (accessPlan.mode) {
      case 'agent-token':
        break

      case 'session-token': {
        // Resource-managed. Present the session token if we already hold one;
        // otherwise call with the agent token and let the resource start its own
        // consent flow with a 202 interaction.
        const held = await sessions.get(l1.resource)
        if (held) cred = { kind: 'session', token: held }
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
        // declare the operation, take back a resource token, exchange it at the
        // PS. Without one, the resource issues resource tokens via 401 instead
        // (protocol §Resource Access and Resource Tokens) — start with the
        // person token and let the requirement loop pick up the challenge.
        const pt = await obtainPersonToken(cfg, await needPS(), l1.issuer, missionS256)
        if (pt.kind !== 'token') return pt
        cred = { kind: 'person', jwt: pt.personToken }

        if (l1.authorization_endpoint) {
          const authz = await authorizeAtResource(
            cfg,
            l1.authorization_endpoint,
            pt.personToken,
            route.adapter.vocabUri,
            operationId,
            opts.account,
          )
          if (authz.kind !== 'resourceToken') return authz
          const ex = await exchangeAtPS(cfg, await needPS(), authz.resourceToken)
          if (ex.kind !== 'token') return ex
          cred = { kind: 'auth', jwt: ex.authToken }
        }
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
      await sessions.set(l1.resource, access)
      if (cred.kind !== 'auth' && cred.kind !== 'person') cred = { kind: 'session', token: access }
    }

    const req = parseRequirement(res.headers.get('aauth-requirement'))
    if (!req) return { kind: 'result', status: res.status, body: await safeBody(res) }

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
        const pt = await obtainPersonToken(cfg, await needPS(), l1.issuer, missionS256)
        if (pt.kind !== 'token') return pt
        cred = { kind: 'person', jwt: pt.personToken }
        continue
      }

      case 'auth-token': {
        // Also the per-call path: for an `r3_per_call` operation the resource
        // builds a proposal from this call's concrete parameters, persists it
        // under its hash, and returns a resource token carrying only the
        // `r3_uri`/`r3_s256` reference. The agent exchanges it and retries the
        // identical call (R3 -02 §Per-Call Proposals).
        if (!req.resourceToken) {
          return terminalChallenge(res, req)
        }
        const ex = await exchangeAtPS(cfg, await needPS(), req.resourceToken)
        if (ex.kind !== 'token') return ex
        cred = { kind: 'auth', jwt: ex.authToken }
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
    await onInteraction(result.interaction.url, result.interaction.code)
    const completed = await pollUntilDone(poll, result.interaction.pollUrl, pollTimeoutMs, onPoll)
    // A resource-managed consent settles with the session token on the poll
    // (AAuth-Access); keep it so the retry presents it.
    const settled = completed.headers.get('aauth-access')
    if (settled) await sessionTokenStore(cfg).set(l1.resource, settled)
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
  /** The flow completed at the PS. */
  | { kind: 'connected'; account?: string }
  /** The person must act: the caller surfaces `{url}?code=`, then polls `pollUrl` (`pollConnection`). */
  | { kind: 'interaction'; interaction: Interaction }
  /** The interaction was surfaced and the bounded wait elapsed. Poll `pollUrl` or call again. */
  | { kind: 'still_pending'; interaction: Interaction }
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

  const ex = await exchangeAtPS(cfg, ps, body.resource_token)
  if (ex.kind === 'token') return { kind: 'connected', ...(args.account ? { account: args.account } : {}) }
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
 * `still_pending` when the slice elapses, and `error` on a terminal failure.
 */
export async function pollConnection(cfg: ProxyConfig, interaction: Interaction, budgetMs: number, onPoll?: (elapsedMs: number) => void | Promise<void>): Promise<ConnectOutcome> {
  const res = await pollUntilDone(makeAgentPoll(cfg), interaction.pollUrl, budgetMs, onPoll)
  if (res.status === 202) return { kind: 'still_pending', interaction }
  if (res.status >= 200 && res.status < 300) return { kind: 'connected' }
  return { kind: 'error', status: res.status, body: await safeBody(res) }
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
