// get_operation_schemas inlines local `$ref`s.
//
// The regression: the adapter handed back the Operation Object's schemas
// untouched, so a body of `{"$ref": "#/components/schemas/Identifier"}` told
// the LLM nothing about the shape. Two people onboarding to secret.agent.coop
// (2026-09-17, 2026-09-18) had their agents guess the `mailto:` form out of
// prose. Components live in the same document the adapter already holds.

import { describe, it, expect } from 'vitest'
import { OpenAPIAdapter } from '../vocab/index.js'

const adapter = new OpenAPIAdapter()

const doc = {
  openapi: '3.1.0',
  paths: {
    '/account': {
      post: {
        operationId: 'createAccount',
        parameters: [{ name: 'trace', in: 'query', schema: { $ref: '#/components/schemas/Trace' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['identifier'],
                properties: {
                  identifier: { $ref: '#/components/schemas/Identifier' },
                  parent: { $ref: '#/components/schemas/Node' },
                  note: { $ref: '#/components/schemas/Identifier', description: 'overrides the target' },
                  elsewhere: { $ref: 'https://other.example/schema.json#/X' },
                  missing: { $ref: '#/components/schemas/Nope' },
                },
              },
            },
          },
        },
        responses: { '200': { content: { 'application/json': { schema: { $ref: '#/components/schemas/Account' } } } } },
      },
    },
  },
  components: {
    schemas: {
      Identifier: { type: 'string', format: 'uri', description: 'A mailto: URI, e.g. mailto:a@b.co' },
      Account: { type: 'object', properties: { status: { type: 'string' } } },
      Trace: { type: 'string' },
      // Self-referential: a node whose children are nodes.
      Node: { type: 'object', properties: { children: { type: 'array', items: { $ref: '#/components/schemas/Node' } } } },
    },
  },
}

const detail = () => adapter.getOperations({ raw: doc } as never, ['createAccount'])[0]!

const props = (d = detail()) =>
  ((d.bodySchema as Record<string, never>).content['application/json'].schema as { properties: Record<string, unknown> })
    .properties

describe('getOperations inlines $ref', () => {
  it('replaces a local component ref with the schema it names', () => {
    expect(props().identifier).toEqual({ type: 'string', format: 'uri', description: 'A mailto: URI, e.g. mailto:a@b.co' })
  })

  it('inlines refs in params and responses too', () => {
    const d = detail()
    expect(d.paramsSchema).toEqual([{ name: 'trace', in: 'query', schema: { type: 'string' } }])
    expect(d.responseSchema).toEqual({ '200': { content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string' } } } } } } })
  })

  it('keeps a sibling of $ref, which overrides the target (OpenAPI 3.1)', () => {
    expect(props().note).toEqual({ type: 'string', format: 'uri', description: 'overrides the target' })
  })

  it('stops at a cycle, leaving the $ref in place rather than recursing forever', () => {
    expect(props().parent).toEqual({
      type: 'object',
      properties: { children: { type: 'array', items: { $ref: '#/components/schemas/Node' } } },
    })
  })

  it('leaves a non-local or unresolvable ref alone', () => {
    expect(props().elsewhere).toEqual({ $ref: 'https://other.example/schema.json#/X' })
    expect(props().missing).toEqual({ $ref: '#/components/schemas/Nope' })
  })

  it('does not mutate the loaded document', () => {
    detail()
    expect(doc.paths['/account'].post.requestBody.content['application/json'].schema.properties.identifier).toEqual({
      $ref: '#/components/schemas/Identifier',
    })
  })
})
