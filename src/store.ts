// L1 — added resources. File-backed at ~/.aauth/praca/resources.json.
//
// Praca writes here on add_resource (always), on first successful auth at a
// resource (touches last_used), and on remove_resource. No PS-side state is
// mutated by this module; remove_resource is praca-local only.

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

interface L1File {
  resources: L1Entry[]
}

const STATE_DIR = join(homedir(), '.aauth', 'praca')
const L1_PATH = join(STATE_DIR, 'resources.json')

function load(): L1File {
  if (!existsSync(L1_PATH)) return { resources: [] }
  try {
    return JSON.parse(readFileSync(L1_PATH, 'utf8')) as L1File
  } catch {
    return { resources: [] }
  }
}

function save(file: L1File): void {
  mkdirSync(dirname(L1_PATH), { recursive: true })
  writeFileSync(L1_PATH, JSON.stringify(file, null, 2))
}

export function list(): L1Entry[] {
  return load().resources
}

export function get(host: string): L1Entry | undefined {
  return load().resources.find((r) => r.resource === host)
}

export function upsert(entry: L1Entry): void {
  const file = load()
  const idx = file.resources.findIndex((r) => r.resource === entry.resource)
  if (idx >= 0) file.resources[idx] = entry
  else file.resources.push(entry)
  save(file)
}

export function remove(host: string): boolean {
  const file = load()
  const next = file.resources.filter((r) => r.resource !== host)
  if (next.length === file.resources.length) return false
  save({ resources: next })
  return true
}

export function touch(host: string): void {
  const file = load()
  const entry = file.resources.find((r) => r.resource === host)
  if (!entry) return
  entry.last_used = new Date().toISOString()
  save(file)
}
