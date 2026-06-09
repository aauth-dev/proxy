// praca — the user's AAuth agent. v0 core: the authorize-first R3 invoke flow
// against Ponte, exchanging at the PS.
//
// invoke() is non-blocking: when an interaction is required (PS consent or the
// resource's OAuth bootstrap) it RETURNS the interaction (url + code + poll URL)
// rather than completing it, so a caller — the MCP server — can surface the URL
// to the user. invokeComplete() drives it to completion for programmatic use,
// performing the interaction via a callback and polling.
//
// Built directly on @hellocoop/httpsig (the @aauth/mcp-agent package is
// 401-challenge-driven and has no R3/authorize-first path, mirroring the
// resource-side finding).

import { fetch as signedFetch } from '@hellocoop/httpsig'
import { fetchResource, routeOperation, toL1Entry } from './resource.js'
import type { L1Entry } from './store.js'

export type AgentSigningKey = Parameters<typeof signedFetch>[1]['signingKey']

export interface PracaConfig {
  psUrl: string
  agentPrivateJwk: AgentSigningKey // the agent's private JWK
  agentToken: string // aa-agent+jwt (cnf = agent pubkey, ps = psUrl)
}

export interface InvokeArgs {
  pathParams?: Record<string, string>
  query?: string
  body?: unknown // string or object; vocab adapters serialize non-string bodies as JSON. The proxy packs it into r3_context on escalation.
  contentType?: string // defaults to application/json when a body is present
}

export interface Interaction {
  url: string
  code: string
  pollUrl: string
}

export type InvokeResult =
  | { kind: 'result'; status: number; body: unknown }
  | { kind: 'interaction'; interaction: Interaction }

export type InteractionHandler = (url: string, code: string) => Promise<void> | void

function signWith(cfg: PracaConfig, token: string) {
  return (url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) =>
    signedFetch(url, { ...init, signingKey: cfg.agentPrivateJwk, signatureKey: { type: 'jwt', jwt: token } })
}

function parseInteraction(requirement: string | null): { url: string; code: string } | undefined {
  if (!requirement || !requirement.includes('requirement=interaction')) return undefined
  const url = /url="([^"]+)"/.exec(requirement)?.[1]
  const code = /code="([^"]+)"/.exec(requirement)?.[1]
  return url && code ? { url, code } : undefined
}

// A per-call escalation challenge (W2): the resource returns 401 with
// `requirement=auth-token; resource-token="…"` for a conditional/irreversible op.
// The agent takes that resource token (which carries the call as r3_context) to
// the PS for a per-call auth token, then retries.
function parseAuthTokenChallenge(requirement: string | null): string | undefined {
  if (!requirement || !requirement.includes('requirement=auth-token')) return undefined
  return /resource-token="([^"]+)"/.exec(requirement)?.[1]
}

function interactionFrom(res: Response): Interaction | undefined {
  const parsed = parseInteraction(res.headers.get('aauth-requirement'))
  const pollUrl = res.headers.get('location') ?? ''
  return parsed && pollUrl ? { ...parsed, pollUrl } : undefined
}

async function safeBody(res: Response): Promise<unknown> {
  const text = await res.text()
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

interface PSMetadata {
  token_endpoint: string
  interaction_endpoint?: string
}

async function psMetadata(psUrl: string): Promise<PSMetadata> {
  return (await (await fetch(`${psUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`)).json()) as PSMetadata
}

// POST the interaction to the PS so it can try to reach the user (live web
// session, registered mobile push). On 2xx the PS owns user-reach; the agent
// blocks on the resource pollUrl until the user completes there. On any
// non-2xx (including the spec-pending interaction_unavailable error — see
// AAuth#34) the agent falls back to driving the URL itself.
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
export async function pollUntilDone(poll: Poller, locationUrl: string, timeoutMs = 180_000): Promise<Response> {
  const deadline = Date.now() + timeoutMs
  let res = await poll(locationUrl)
  while (res.status === 202 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000))
    res = await poll(locationUrl)
  }
  return res
}

type SignedFetch = ReturnType<typeof signWith>

type ExchangeOutcome =
  | { kind: 'token'; authToken: string }
  | { kind: 'interaction'; interaction: Interaction }
  | { kind: 'result'; status: number; body: unknown }

// Exchange a resource token at the PS for an auth token. capabilities tells the
// PS the agent can relay interactions to the user, so it returns a 202 consent
// interaction (surfaced for the caller to drive + retry) rather than requiring a
// registered mobile device. On PS endpoints this is a token-request parameter,
// not a header (the AAuth-Capabilities header is for resource requests).
async function exchangeAtPS(signAgent: SignedFetch, tokenEndpoint: string, resourceToken: string): Promise<ExchangeOutcome> {
  const res = await signAgent(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ resource_token: resourceToken, capabilities: ['interaction'] }),
  })
  if (res.status === 202) {
    const interaction = interactionFrom(res)
    if (interaction) return { kind: 'interaction', interaction }
  }
  if (!res.ok) return { kind: 'result', status: res.status, body: await safeBody(res) }
  const { auth_token } = (await res.json()) as { auth_token: string }
  return { kind: 'token', authToken: auth_token }
}

// Resource-parameterized invoke. The new tool surface in server.ts calls into
// this directly with an L1 entry from store.ts; the legacy invoke() below
// wraps it for cfg.ponteBase-based callers (tests, demo scripts).
export async function invokeAtResource(
  cfg: PracaConfig,
  l1: L1Entry,
  operationId: string,
  args: InvokeArgs = {},
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
  const requestInit = {
    method: plan.method,
    ...(plan.headers ? { headers: plan.headers } : {}),
    ...(plan.body !== undefined ? { body: plan.body } : {}),
  }

  // agent-token access mode: sign with the agent token + go. No PS exchange.
  if (l1.access_mode === 'agent-token') {
    const res = await signWith(cfg, cfg.agentToken)(apiUrl, requestInit)
    return { kind: 'result', status: res.status, body: await safeBody(res) }
  }

  // aauth-access-token / auth-token: R3 flow.
  if (!l1.authorization_endpoint) {
    throw new Error(
      `resource ${l1.resource}: no authorization_endpoint (access_mode ${l1.access_mode} requires R3)`,
    )
  }
  const signAgent = signWith(cfg, cfg.agentToken)
  const ps = await psMetadata(cfg.psUrl)

  // 1. authorize-first: declare the operation, get a resource token.
  const authzRes = await signAgent(l1.authorization_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      r3_operations: {
        vocabulary: route.adapter.vocabUri,
        operations: [{ operationId }],
      },
    }),
  })
  if (!authzRes.ok)
    return { kind: 'result', status: authzRes.status, body: await safeBody(authzRes) }
  const { resource_token } = (await authzRes.json()) as { resource_token: string }

  // 2. exchange at the PS for an auth token (surface a consent interaction if any).
  const ex = await exchangeAtPS(signAgent, ps.token_endpoint, resource_token)
  if (ex.kind !== 'token') return ex

  // 3. call the resource. Writes carry the body; the agent signs over it so the
  // proxy's content-digest check (and the r3_context it packs on escalation)
  // match the actual call.
  const callWith = (token: string) => signWith(cfg, token)(apiUrl, requestInit)

  let apiRes = await callWith(ex.authToken)

  // First contact: a resource-issued interaction (e.g. OAuth bootstrap). Try
  // the PS's interaction_endpoint first so it can use its own user-reach
  // channels (live web session, mobile push). On any non-2xx — including the
  // spec-pending interaction_unavailable error (AAuth#34) and any PS that
  // hasn't implemented the endpoint yet — surface the interaction so the
  // caller can drive it (layer 2: local OS open / layer 3: text+QR).
  if (apiRes.status === 202) {
    const interaction = interactionFrom(apiRes)
    if (interaction) {
      const engaged = ps.interaction_endpoint
        ? await relayInteractionToPS(signAgent, ps.interaction_endpoint, interaction)
        : false
      if (!engaged) return { kind: 'interaction', interaction }
      const poll: Poller = (url) =>
        signWith(cfg, cfg.agentToken)(url, { method: 'GET', headers: { Prefer: 'wait=20' } })
      const completed = await pollUntilDone(poll, interaction.pollUrl, 180_000)
      if (completed.status === 202) return { kind: 'interaction', interaction }
      apiRes = await callWith(ex.authToken)
    }
  }

  // Per-call escalation (W2): a conditional/irreversible op returns a 401
  // auth-token challenge. Take its resource token (which carries the call as
  // r3_context) to the PS for a per-call auth token, then retry the same call.
  // If the PS needs consent first, it returns a 202 interaction we surface.
  const challenge =
    apiRes.status === 401 ? parseAuthTokenChallenge(apiRes.headers.get('aauth-requirement')) : undefined
  if (challenge) {
    const stepEx = await exchangeAtPS(signAgent, ps.token_endpoint, challenge)
    if (stepEx.kind !== 'token') return stepEx
    apiRes = await callWith(stepEx.authToken)
    if (apiRes.status === 202) {
      const interaction = interactionFrom(apiRes)
      if (interaction) return { kind: 'interaction', interaction }
    }
  }

  return { kind: 'result', status: apiRes.status, body: await safeBody(apiRes) }
}

// Drive invokeAtResource to completion: perform each interaction via
// `onInteraction`, poll until it resolves, and retry. For programmatic / test
// use; the MCP tool surface is non-blocking by design and surfaces interaction
// URLs to the LLM caller instead.
export async function invokeAtResourceComplete(
  cfg: PracaConfig,
  l1: L1Entry,
  operationId: string,
  onInteraction: InteractionHandler,
  args: InvokeArgs = {},
  maxRounds = 5,
  pollTimeoutMs = 180_000,
): Promise<{ status: number; body: unknown }> {
  // Poll deferred URLs signed with the agent token (long-poll via Prefer: wait).
  const poll: Poller = (url) =>
    signWith(cfg, cfg.agentToken)(url, { method: 'GET', headers: { Prefer: 'wait=20' } })
  for (let round = 0; round < maxRounds; round++) {
    const result = await invokeAtResource(cfg, l1, operationId, args)
    if (result.kind === 'result') return { status: result.status, body: result.body }
    await onInteraction(result.interaction.url, result.interaction.code)
    await pollUntilDone(poll, result.interaction.pollUrl, pollTimeoutMs)
  }
  throw new Error('invoke did not complete after interactions')
}
