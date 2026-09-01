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
import type { L1Entry, PersonTokenStore } from './store.js'

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

function interactionFrom(res: Response): Interaction | undefined {
  const parsed = parseRequirement(res.headers.get('aauth-requirement'))
  const pollUrl = res.headers.get('location') ?? ''
  return parsed?.requirement === 'interaction' && parsed.url && parsed.code && pollUrl
    ? { url: parsed.url, code: parsed.code, pollUrl }
    : undefined
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

  const res = await signWith(cfg, { kind: 'agent' }, { psOrAs: true })(ps.person_token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      resource,
      ...(missionS256 ? { mission_s256: missionS256 } : {}),
    }),
  })

  if (res.status === 202) {
    const interaction = interactionFrom(res)
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

// POST the interaction to the PS so it can try to reach the user (live web
// session, registered mobile push). On 2xx the PS owns user-reach; the agent
// blocks on the pollUrl until the user completes there. On any non-2xx
// (including the spec-pending interaction_unavailable error — see AAuth#34) the
// agent falls back to driving the URL itself.
async function relayInteractionToPS(
  signAgent: SignedFetch,
  endpoint: string,
  interaction: Interaction,
): Promise<boolean> {
  try {
    const res = await signAgent(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'interaction',
        url: interaction.url,
        code: interaction.code,
      }),
    })
    return res.ok
  } catch {
    return false
  }
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
  authTokenEndpoint: string,
  resourceToken: string,
): Promise<ExchangeOutcome> {
  const { capabilities, ...otherHints } = cfg.psHints ?? {}
  const res = await signWith(cfg, { kind: 'agent' }, { psOrAs: true })(authTokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      resource_token: resourceToken,
      capabilities: capabilities ?? ['interaction'],
      ...otherHints,
    }),
  })
  if (res.status === 202) {
    const interaction = interactionFrom(res)
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
          )
          if (authz.kind !== 'resourceToken') return authz
          const ex = await exchangeAtPS(cfg, (await needPS()).auth_token_endpoint, authz.resourceToken)
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
        const ex = await exchangeAtPS(cfg, (await needPS()).auth_token_endpoint, req.resourceToken)
        if (ex.kind !== 'token') return ex
        cred = { kind: 'auth', jwt: ex.authToken }
        continue
      }

      case 'interaction': {
        const interaction = interactionFrom(res)
        if (!interaction) {
          return { kind: 'result', status: res.status, body: await safeBody(res) }
        }
        // Try the PS's interaction endpoint first so it can use its own
        // user-reach channels (live web session, mobile push). On any non-2xx —
        // including the spec-pending interaction_unavailable error (AAuth#34)
        // and any PS that hasn't implemented the endpoint yet — surface the
        // interaction so the caller can drive it (layer 2: local OS open;
        // layer 3: text + QR).
        const meta = await needPS().catch(() => undefined)
        const engaged = meta?.interaction_endpoint
          ? await relayInteractionToPS(
              signWith(cfg, { kind: 'agent' }),
              meta.interaction_endpoint,
              interaction,
            )
          : false
        if (!engaged) return { kind: 'interaction', interaction }
        const completed = await pollUntilDone(makeAgentPoll(cfg), interaction.pollUrl, 180_000)
        if (completed.status === 202) return { kind: 'interaction', interaction }
        const settled = completed.headers.get('aauth-access')
        if (settled) {
          await sessions.set(l1.resource, settled)
          cred = { kind: 'session', token: settled }
        }
        continue
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
    await pollUntilDone(poll, result.interaction.pollUrl, pollTimeoutMs, onPoll)
  }
  throw new Error('invoke did not complete after interactions')
}

// Signed DELETE to an admin endpoint on the resource (e.g. /admin/tokens).
// Uses the agent token so the resource can verify the caller owns the key.
export async function deleteAtAdmin(cfg: ProxyConfig, l1: L1Entry, path: string): Promise<Response> {
  return signWith(cfg, { kind: 'agent' })(`${l1.origin}${path}`, { method: 'DELETE' })
}
