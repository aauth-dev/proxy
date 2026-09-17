// Response media types: an OpenAPI invocation asks for what the operation's
// success responses declare (JSON when offered), and a body that is not text
// comes back base64-encoded instead of mangled through a UTF-8 decode.

import { describe, it, expect } from 'vitest'
import { safeBody } from '../agent.js'
import { acceptFor, OpenAPIAdapter, type OpenAPIVocabDoc } from '../vocab/openapi.js'

describe('acceptFor', () => {
  it('picks JSON when a success response offers it alongside bytes', () => {
    expect(acceptFor({ '200': { content: { 'application/octet-stream': {}, 'application/json': {} } } })).toBe('application/json')
  })
  it('accepts +json types', () => {
    expect(acceptFor({ '201': { content: { 'application/problem+json': {} } } })).toBe('application/problem+json')
  })
  it('lists the declared types when none is JSON', () => {
    expect(acceptFor({ '200': { content: { 'application/octet-stream': {}, 'image/png': {} } } })).toBe('application/octet-stream, image/png')
  })
  it('ignores error responses and responses without content', () => {
    expect(acceptFor({ '404': { content: { 'application/json': {} } }, '204': { description: 'none' } })).toBeUndefined()
    expect(acceptFor({ '2XX': { content: { 'text/csv': {} } }, default: { content: { 'text/plain': {} } } })).toBe('text/csv, text/plain')
    expect(acceptFor(undefined)).toBeUndefined()
  })
})

describe('OpenAPI buildInvocation headers', () => {
  const DOC = {
    openapi: '3.1.0',
    paths: {
      '/messages/{id}': { get: { operationId: 'getMessage', responses: { '200': { content: { 'application/json': {}, 'application/octet-stream': {} } } } } },
      '/messages': { post: { operationId: 'sendMessage', responses: { '201': { content: { 'application/json': {} } } } } },
      '/ping': { get: { operationId: 'ping', responses: { '204': { description: 'ok' } } } },
    },
  }
  const adapter = new OpenAPIAdapter()
  // ops is re-indexed from raw when it is not a Map (the cache round-trip shape).
  const doc = { raw: DOC, ops: {} } as unknown as OpenAPIVocabDoc

  it('sends Accept from the declared responses', () => {
    const plan = adapter.buildInvocation(doc, 'getMessage', { pathParams: { id: 'm1' } })
    expect(plan).toEqual({ kind: 'sync.request', method: 'GET', path: '/messages/m1', headers: { accept: 'application/json' } })
  })
  it('keeps content-type with a body', () => {
    const plan = adapter.buildInvocation(doc, 'sendMessage', { body: { to: 'x' } })
    expect(plan).toMatchObject({ headers: { accept: 'application/json', 'content-type': 'application/json' }, body: '{"to":"x"}' })
  })
  it('sends no headers when nothing is declared and there is no body', () => {
    expect(adapter.buildInvocation(doc, 'ping', {})).toEqual({ kind: 'sync.request', method: 'GET', path: '/ping' })
  })
})

describe('safeBody', () => {
  it('returns bytes intact as base64', async () => {
    const bytes = new Uint8Array([0x00, 0xff, 0xfe, 0x80, 0xc3, 0x28, 0x41])
    const body = await safeBody(new Response(bytes, { headers: { 'content-type': 'application/octet-stream' } }))
    expect(body).toEqual({ content_type: 'application/octet-stream', size: 7, base64: Buffer.from(bytes).toString('base64') })
  })
  it('handles bodies larger than one chunk', async () => {
    const bytes = new Uint8Array(100_000).map((_, i) => i % 256)
    const body = (await safeBody(new Response(bytes, { headers: { 'content-type': 'image/png' } }))) as { base64: string; size: number }
    expect(body.size).toBe(100_000)
    expect(Buffer.from(body.base64, 'base64').equals(Buffer.from(bytes))).toBe(true)
  })
  it('still parses JSON and returns text', async () => {
    expect(await safeBody(new Response('{"a":1}', { headers: { 'content-type': 'application/json; charset=utf-8' } }))).toEqual({ a: 1 })
    expect(await safeBody(new Response('{"a":1}', { headers: { 'content-type': 'application/problem+json' } }))).toEqual({ a: 1 })
    expect(await safeBody(new Response('hello', { headers: { 'content-type': 'text/plain' } }))).toBe('hello')
    expect(await safeBody(new Response('{"a":1}'))).toEqual({ a: 1 })
  })
})
