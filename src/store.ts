// L1 — added resources. The L1Store interface lets a host inject its own
// backend; the stdio server uses the filesystem default (createFsL1Store),
// backed by ~/.aauth/praca/resources.json.
//
// Praca writes here on add_resource (always), on first successful auth at a
// resource (touches last_used), and on remove_resource. No PS-side state is
// mutated by this module; remove is praca-local only.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export type AccessMode = 'agent-token' | 'aauth-access-token' | 'auth-token'

export interface L1Entry {
  resource: string // canonical host (LLM-facing identifier)
  origin: string // https://{host} or http://{host} for local — what praca calls
  issuer: string // https://{host} (or http for local) — from well-known
  name: string
  description: string
  access_mode: AccessMode
  logo_uri?: string
  authorization_endpoint?: string
  picked_vocabs: Array<{ vocabUri: string; docUrl: string }>
  added: string // ISO timestamp
  last_used?: string // ISO timestamp
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
// the state directory (default ~/.aauth/praca).
export function createFsL1Store(opts: { dir?: string } = {}): L1Store {
  const stateDir = opts.dir ?? join(homedir(), '.aauth', 'praca')
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
