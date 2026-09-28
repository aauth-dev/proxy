// L1 — added resources. (The agent's tokens live in tokens.ts.)
//
// The L1Store interface lets a host inject its own backend; the stdio server
// uses the filesystem default (createFsL1Store), backed by
// ~/.aauth/proxy/resources.json.
//
// The agent proxy writes here on add_resource (always), on first successful auth at a
// resource (touches last_used), and on remove_resource. No PS-side state is
// mutated by this module; remove is agent-proxy-local only.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import type { KnownAccessMode } from './access-mode.js'

export type { KnownAccessMode } from './access-mode.js'

/**
 * `access_mode` as it arrives from a resource's well-known document.
 *
 * Not a closed union: the value set is an IANA registry (protocol §AAuth Access
 * Mode Value Registry), so an agent must carry unrecognized values intact rather
 * than reject them. `KnownAccessMode` names the ones this build can plan against;
 * anything else is treated as undeclared (see access-mode.ts).
 */
export type AccessMode = KnownAccessMode | (string & {})

/**
 * One declared upstream scope on a resource's `connection` object
 * (ONBOARDING-PLAN.md §3.0). Raw upstream vocabulary, not a profile layer:
 * `default: true` marks what a bare connect requests; the description is
 * agent-facing English.
 */
export interface ConnectionScope {
  scope: string
  default?: boolean
  description?: string
}

/**
 * The `connection` object from a resource's well-known. Its PRESENCE is the
 * capability signal: this resource fronts an upstream the person must link.
 * `account_description` present ⟺ the agent MUST name an account at connect.
 */
export interface ConnectionMetadata {
  endpoint: string
  upstream_name?: string
  scopes?: ConnectionScope[]
  account_description?: string
}

/** One row of `GET {connection.endpoint}` — what the resource believes it holds. */
export interface ConnectionRow {
  account: string
  account_label?: string
  scopes: string[]
  connected_at?: string
  status?: string
}

export interface L1Entry {
  resource: string // canonical host (LLM-facing identifier)
  origin: string // https://{host} or http://{host} for local — what the agent proxy calls
  issuer: string // https://{host} (or http for local) — from well-known
  name: string
  description: string
  access_mode: AccessMode
  logo_uri?: string
  authorization_endpoint?: string
  // Where a person is sent for any ceremony the resource owns (§3.8). The
  // agent composes `{interaction_endpoint}?code=` from this when a 202
  // carries only a code.
  interaction_endpoint?: string
  // The whole `connection` object, when the resource publishes one (N1).
  connection?: ConnectionMetadata
  // The resource's `documentation_uri` (protocol §Resource Metadata). When it
  // serves text or markdown, get_operation_schemas returns it as `context`
  // (resource.ts loadResourceContext).
  documentation_uri?: string
  // Known connections for this person, as last read from
  // `GET {connection.endpoint}` (N2/N5). A cache: list_resources refreshes it,
  // connect_resources refreshes it after a flow completes.
  connections?: ConnectionRow[]
  // One discovery endpoint per vocabulary (R3 -02 §Operation Identifier Scope).
  picked_vocabs: Array<{ vocabUri: string; docUrl: string }>
  added: string // ISO timestamp
  last_used?: string // ISO timestamp
  // How long the metadata above may be used before the well-known is read
  // again (resource.ts refreshResourceEntry): from the resource's Cache-Control,
  // at most one hour. An entry stored before 4.10.0 has none and is refreshed on
  // its next use.
  meta_expires_at?: number // ms since the epoch
  meta_max_age_ms?: number // the lifetime that came from, reused when a 304 carries no Cache-Control
  meta_etag?: string // sent back as If-None-Match once expired
}

// Per-user added-resource store. Async so non-filesystem backends (KV, a
// database, Durable Object storage) can implement it; the filesystem default
// resolves synchronously under the hood.
export interface L1Store {
  list(): Promise<L1Entry[]>
  get(host: string): Promise<L1Entry | undefined>
  upsert(entry: L1Entry): Promise<void>
  remove(host: string): Promise<boolean>
  touch(host: string): Promise<void>
}

interface L1File {
  resources: L1Entry[]
}

// Filesystem-backed L1Store — the default for the stdio server. `dir` overrides
// the state directory (default ~/.aauth/proxy).
export function createFsL1Store(opts: { dir?: string } = {}): L1Store {
  const stateDir = opts.dir ?? join(homedir(), '.aauth', 'proxy')
  const l1Path = join(stateDir, 'resources.json')

  function load(): L1File {
    if (!existsSync(l1Path)) return { resources: [] }
    try {
      return JSON.parse(readFileSync(l1Path, 'utf8')) as L1File
    } catch {
      return { resources: [] }
    }
  }

  function save(file: L1File): void {
    mkdirSync(dirname(l1Path), { recursive: true })
    writeFileSync(l1Path, JSON.stringify(file, null, 2))
  }

  return {
    async list() {
      return load().resources
    },
    async get(host) {
      return load().resources.find((r) => r.resource === host)
    },
    async upsert(entry) {
      const file = load()
      const idx = file.resources.findIndex((r) => r.resource === entry.resource)
      if (idx >= 0) file.resources[idx] = entry
      else file.resources.push(entry)
      save(file)
    },
    async remove(host) {
      const file = load()
      const next = file.resources.filter((r) => r.resource !== host)
      if (next.length === file.resources.length) return false
      save({ resources: next })
      return true
    },
    async touch(host) {
      const file = load()
      const entry = file.resources.find((r) => r.resource === host)
      if (!entry) return
      entry.last_used = new Date().toISOString()
      save(file)
    },
  }
}
