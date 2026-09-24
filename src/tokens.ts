// The agent's tokens — one store for every token in the chain.
//
// Agent token → person token → auth token, plus the opaque session token a
// resource-managed resource hands back. They are one chain: each token's `exp`
// is capped by the one it was obtained with (protocol §Refresh Margin), and
// rotating the agent key invalidates all of them at once (every one binds the
// key through `cnf`). One store gives one expiry rule, one flush, and one place
// to see what the agent holds.
//
// ONE RECORD PER KEY. The key says what a token is FOR:
//
//   agent    ()                                   — held by the host, not the core
//   person   (resource, mission_s256)             — -11 person tokens are per resource
//   auth     (resource, account, mission_s256)    — ONE auth token per key
//   session  (resource)
//
// `put` replaces whatever the key held. That is the whole invariant behind "one
// auth token per resource / account / mission": when the agent needs more access
// than the held token grants it obtains a token for the union and it takes the
// held token's place (agent.ts). An expired record stays until replaced — the
// next acquisition can see what the key last held — but is never presented.
//
// `acquire` / `release` serialize acquisition per key, so two concurrent invokes
// that both miss obtain one token between them rather than two. Every token a
// budgeted resource issues is an allocation against the person's allowance at
// its access server, so a duplicate is not free.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { decodeJwtPayload } from './jwt.js'

export type TokenKind = 'agent' | 'person' | 'auth' | 'session'

export interface TokenKey {
  kind: TokenKind
  /** The resource's HTTPS URL (its issuer). Absent for the agent token. */
  resource?: string
  /** auth: the connected upstream account the token is bound to. */
  account?: string
  /** person, auth: the mission the agent is operating under. */
  mission_s256?: string
}

/** A vocabulary's operation set, as `r3_operations`, `r3_granted` and `r3_per_call` carry it. */
export interface OperationSet {
  vocabulary: string
  /** Entries in the vocabulary's own shape: OpenAPI `{ operationId }`, MCP `{ tool }`. */
  operations: Array<Record<string, string>>
}

export interface TokenBudget {
  amount: number
  unit: string
  decimals: number
  /** From the resource's last AAuth-Budget response. Advisory: the resource is authoritative. */
  remaining?: number
}

export interface TokenRecord extends TokenKey {
  /** The token itself: a JWT, or the opaque AAuth-Access value. */
  value: string
  /** RFC 7638 thumbprint of the agent key the token's `cnf` binds. */
  agent_jkt?: string
  jti?: string
  iat?: number
  /** Seconds since the epoch. Absent: no known expiry. */
  exp?: number
  /** Seconds since the epoch. */
  obtained_at: number
  /** Seconds since the epoch. */
  last_used?: number
  /** auth: the jti of the token presented to obtain it (a person token, or the auth token it stepped up). */
  presented_jti?: string
  /** auth: `r3_granted`. */
  granted?: OperationSet
  /** auth: `r3_per_call`. */
  per_call?: OperationSet
  /** auth: `scope`. */
  scope?: string
  /** auth: the `budget` claim, and what the resource last said remains of it. */
  budget?: TokenBudget
}

export interface TokenStore {
  /** The record held for this key, expired or not. The caller decides whether it is usable. */
  get(key: TokenKey): Promise<TokenRecord | undefined>
  /** Hold `record` for its key, replacing whatever the key held. */
  put(record: TokenRecord): Promise<void>
  /** Merge `patch` into the record for `key` — only while it is still the token `jti`. */
  update(key: TokenKey, jti: string | undefined, patch: Partial<TokenRecord>): Promise<void>
  /** Remove the record for `key`; when `jti` is given, only while it is still that token. */
  drop(key: TokenKey, jti?: string): Promise<void>
  /** Every record held, expired ones included. */
  list(): Promise<TokenRecord[]>
  /** Remove every record (the agent key rotated). */
  flush(): Promise<void>
  /**
   * Take the acquisition lease for `key`, waiting while another holder has it.
   * Resolves with a lease id for `release`. A lease that is never released
   * lapses after `LEASE_MS`; a caller that has waited `LEASE_WAIT_MS` goes
   * ahead with `NO_LEASE`. Optional: a store without it does not serialize. A
   * store that implements `acquire` MUST implement `release`.
   */
  acquire?(key: TokenKey): Promise<string>
  release?(key: TokenKey, lease: string): Promise<void>
}

/** The storage key for a record — stable, and distinct for every TokenKey. */
export function tokenKeyString(key: TokenKey): string {
  return [key.kind, key.resource ?? '', key.account ?? '', key.mission_s256 ?? ''].join(' ')
}

/** Just the key fields of a record or key. */
export function tokenKeyOf(k: TokenKey): TokenKey {
  return {
    kind: k.kind,
    ...(k.resource !== undefined ? { resource: k.resource } : {}),
    ...(k.account !== undefined ? { account: k.account } : {}),
    ...(k.mission_s256 !== undefined ? { mission_s256: k.mission_s256 } : {}),
  }
}

// ── Lifetime ──

/**
 * 30 s of slack: a token this close to `exp` could expire in flight, so it is
 * treated as already gone.
 */
export const EXPIRY_SKEW_SECS = 30

/**
 * Protocol §Refresh Margin: refresh an agent, person, or auth token when fewer
 * than five minutes remain.
 */
export const REFRESH_MARGIN_SECS = 300

/**
 * A held auth token that lapsed within this long of its last use lapsed while
 * the work that needed it was still going on: the agent renews it with the same
 * grant. One that sat unused longer lapsed because the activity died down, and
 * the agent starts over from what the next call needs.
 */
export const ACTIVE_WITHIN_SECS = 300

const nowSecs = () => Math.floor(Date.now() / 1000)

/** Whether the record can still be presented at all. */
export function isLive(rec: TokenRecord, now = nowSecs()): boolean {
  return rec.exp === undefined || rec.exp - EXPIRY_SKEW_SECS > now
}

/**
 * Whether a live record is inside the refresh margin AND a refresh could buy a
 * longer one. Every token is capped by the one above it in the chain (a person
 * token by the agent token, an auth token by both, protocol §Refresh Margin), so
 * when the cap `capExp` does not reach past this token's `exp` by more than the
 * margin, a refresh returns a token that expires just as soon. And a token that
 * was issued with no more than the margin to live is presented until it
 * expires: refreshing it would only buy another as short.
 *
 * Auth tokens are not refreshed this way: an access server may clip `exp` to
 * the end of its budget period, which the agent cannot see, and every refresh
 * is another allocation against the person's allowance. See `wasInUse`.
 */
export function isDueForRefresh(rec: TokenRecord, capExp?: number, now = nowSecs()): boolean {
  if (rec.exp === undefined) return false
  if (rec.exp - now >= REFRESH_MARGIN_SECS || rec.exp - rec.obtained_at <= REFRESH_MARGIN_SECS) return false
  return capExp === undefined || capExp - rec.exp > REFRESH_MARGIN_SECS
}

/** Whether a record that lapsed was in use when it did (see `ACTIVE_WITHIN_SECS`). */
export function wasInUse(rec: TokenRecord, now = nowSecs()): boolean {
  return now - (rec.last_used ?? rec.obtained_at) <= ACTIVE_WITHIN_SECS
}

// ── Auth token claims ──

function isOperationSet(v: unknown): v is OperationSet {
  if (!v || typeof v !== 'object') return false
  const s = v as { vocabulary?: unknown; operations?: unknown }
  return (
    typeof s.vocabulary === 'string' &&
    Array.isArray(s.operations) &&
    s.operations.every((o) => o && typeof o === 'object' && Object.values(o).every((x) => typeof x === 'string'))
  )
}

function isBudgetClaim(v: unknown): v is { amount: number; unit: string; decimals: number } {
  if (!v || typeof v !== 'object') return false
  const b = v as Record<string, unknown>
  return typeof b.amount === 'number' && typeof b.unit === 'string' && typeof b.decimals === 'number'
}

/**
 * The record for an auth token, read from its own claims (not verified: the
 * agent holds the token, the resource verifies it). Undefined for a token that
 * is not a JWT or carries no `exp` — without one the agent cannot tell when to
 * stop presenting it, so it is used once and not kept.
 */
export function authTokenRecord(
  key: TokenKey,
  jwt: string,
  opts: { agentJkt?: string; presentedJti?: string; now?: number } = {},
): TokenRecord | undefined {
  let p: Record<string, unknown>
  try {
    p = decodeJwtPayload(jwt)
  } catch {
    return undefined
  }
  if (typeof p.exp !== 'number') return undefined
  return {
    ...tokenKeyOf(key),
    value: jwt,
    ...(opts.agentJkt ? { agent_jkt: opts.agentJkt } : {}),
    ...(typeof p.jti === 'string' ? { jti: p.jti } : {}),
    ...(typeof p.iat === 'number' ? { iat: p.iat } : {}),
    exp: p.exp,
    obtained_at: opts.now ?? nowSecs(),
    ...(opts.presentedJti ? { presented_jti: opts.presentedJti } : {}),
    ...(isOperationSet(p.r3_granted) ? { granted: p.r3_granted } : {}),
    ...(isOperationSet(p.r3_per_call) ? { per_call: p.r3_per_call } : {}),
    ...(typeof p.scope === 'string' ? { scope: p.scope } : {}),
    ...(isBudgetClaim(p.budget) ? { budget: { amount: p.budget.amount, unit: p.budget.unit, decimals: p.budget.decimals } } : {}),
  }
}

/** The `jti` of a JWT, when it has one. */
export function jtiOf(jwt: string): string | undefined {
  try {
    const jti = decodeJwtPayload(jwt).jti
    return typeof jti === 'string' ? jti : undefined
  } catch {
    return undefined
  }
}

// ── Operations ──

export function sameOperation(a: Record<string, string>, b: Record<string, string>): boolean {
  const ka = Object.keys(a)
  return ka.length === Object.keys(b).length && ka.every((k) => a[k] === b[k])
}

/** `list` with duplicates removed, first occurrence kept. */
export function uniqueOperations(list: Array<Record<string, string>>): Array<Record<string, string>> {
  const out: Array<Record<string, string>> = []
  for (const op of list) if (!out.some((o) => sameOperation(o, op))) out.push(op)
  return out
}

/** The identifier an entry names (`operationId`, `tool`, …), for display. */
export function operationName(entry: Record<string, string>): string {
  return Object.values(entry)[0] ?? ''
}

/**
 * Whether `next` grants everything `held` does — so it can take `held`'s place
 * without the agent losing access it had. A token that grants by `scope` alone
 * (no R3 claims) is taken to grant everything.
 */
export function grantsAtLeast(next: TokenRecord, held: TokenRecord): boolean {
  if (!next.granted && !next.per_call) return true
  if (!held.granted) return true
  const vocab = held.granted.vocabulary
  return held.granted.operations.every((op) => grantsOperation(next, vocab, op))
}

/**
 * Whether presenting `rec` for this operation can succeed on its grant. A token
 * with no R3 claims grants by `scope`, which the agent cannot map to operations,
 * so it is presented and the resource decides.
 */
export function grantsOperation(rec: TokenRecord, vocabulary: string, entry: Record<string, string>): boolean {
  if (!rec.granted && !rec.per_call) return true
  const inSet = (s?: OperationSet) => s?.vocabulary === vocabulary && s.operations.some((o) => sameOperation(o, entry))
  return inSet(rec.granted) || inSet(rec.per_call)
}

// ── Leases ──

/**
 * How long an unreleased acquisition lease holds before the next waiter may take
 * it. A holder can legitimately take about 40 s (two in-call waits on the PS).
 */
export const LEASE_MS = 60_000

/**
 * The longest a caller waits for a lease before going ahead without one. MCP
 * clients abandon a tool call at about 60 s; a waiter that outlived that would
 * fail the call to save an allocation.
 */
export const LEASE_WAIT_MS = 30_000

/** What `acquire` resolves with when it stopped waiting: releasing it does nothing. */
export const NO_LEASE = ''

/**
 * An in-memory lease table: the `acquire` / `release` half of a TokenStore.
 * Exported so a host whose store lives elsewhere (a Durable Object) can run the
 * same table where its requests meet.
 */
export function createLeaseTable(leaseMs = LEASE_MS, maxWaitMs = LEASE_WAIT_MS): {
  acquire(key: string): Promise<string>
  release(key: string, lease: string): Promise<void>
} {
  const leases = new Map<string, { id: string; expires: number; waiters: Array<() => void> }>()
  return {
    async acquire(key) {
      const giveUpAt = Date.now() + maxWaitMs
      for (;;) {
        const cur = leases.get(key)
        if (!cur || cur.expires <= Date.now()) {
          const id = crypto.randomUUID()
          leases.set(key, { id, expires: Date.now() + leaseMs, waiters: cur?.waiters ?? [] })
          return id
        }
        if (Date.now() >= giveUpAt) return NO_LEASE
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, Math.max(0, Math.min(cur.expires, giveUpAt) - Date.now()))
          cur.waiters.push(() => {
            clearTimeout(timer)
            resolve()
          })
        })
      }
    },
    async release(key, lease) {
      const cur = leases.get(key)
      if (!cur || cur.id !== lease) return
      leases.delete(key)
      for (const wake of cur.waiters) wake()
    },
  }
}

// ── Stores ──

/** Process-lifetime token store. The default for hosts that inject none. */
export function createMemoryTokenStore(): TokenStore {
  const records = new Map<string, TokenRecord>()
  const leases = createLeaseTable()
  return {
    async get(key) {
      return records.get(tokenKeyString(key))
    },
    async put(record) {
      records.set(tokenKeyString(record), record)
    },
    async update(key, jti, patch) {
      const k = tokenKeyString(key)
      const cur = records.get(k)
      if (!cur || cur.jti !== jti) return
      records.set(k, { ...cur, ...patch, ...tokenKeyOf(cur) })
    },
    async drop(key, jti) {
      const k = tokenKeyString(key)
      const cur = records.get(k)
      if (!cur || (jti !== undefined && cur.jti !== jti)) return
      records.delete(k)
    },
    async list() {
      return [...records.values()]
    },
    async flush() {
      records.clear()
    },
    acquire: (key) => leases.acquire(tokenKeyString(key)),
    release: (key, lease) => leases.release(tokenKeyString(key), lease),
  }
}

interface TokenFile {
  tokens: TokenRecord[]
}

/** Filesystem-backed token store at ~/.aauth/proxy/tokens.json (mode 0600). */
export function createFsTokenStore(opts: { dir?: string } = {}): TokenStore {
  const stateDir = opts.dir ?? join(homedir(), '.aauth', 'proxy')
  const path = join(stateDir, 'tokens.json')
  const leases = createLeaseTable()

  function load(): TokenFile {
    if (!existsSync(path)) return { tokens: [] }
    try {
      return JSON.parse(readFileSync(path, 'utf8')) as TokenFile
    } catch {
      return { tokens: [] }
    }
  }

  function save(file: TokenFile): void {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, JSON.stringify(file, null, 2), { mode: 0o600 })
  }

  const find = (file: TokenFile, key: TokenKey) => {
    const k = tokenKeyString(key)
    return file.tokens.findIndex((t) => tokenKeyString(t) === k)
  }

  return {
    async get(key) {
      const file = load()
      const i = find(file, key)
      return i < 0 ? undefined : file.tokens[i]
    },
    async put(record) {
      const file = load()
      const i = find(file, record)
      if (i < 0) file.tokens.push(record)
      else file.tokens[i] = record
      save(file)
    },
    async update(key, jti, patch) {
      const file = load()
      const i = find(file, key)
      const cur = i < 0 ? undefined : file.tokens[i]
      if (!cur || cur.jti !== jti) return
      file.tokens[i] = { ...cur, ...patch, ...tokenKeyOf(cur) }
      save(file)
    },
    async drop(key, jti) {
      const file = load()
      const i = find(file, key)
      const cur = i < 0 ? undefined : file.tokens[i]
      if (!cur || (jti !== undefined && cur.jti !== jti)) return
      file.tokens.splice(i, 1)
      save(file)
    },
    async list() {
      return load().tokens
    },
    async flush() {
      save({ tokens: [] })
    },
    acquire: (key) => leases.acquire(tokenKeyString(key)),
    release: (key, lease) => leases.release(tokenKeyString(key), lease),
  }
}
