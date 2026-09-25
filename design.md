# agent proxy — the user's AAuth agent in MCP form

**Status: v1 invoke spine ✅ proven live (2026-05-25); discovery layer redesigned 2026-06-09; AAuth -11 / R3 -02 landed 2026-08-11 (v0.6.0).** The agent proxy drives the authorize-first R3 flow end-to-end against a real Person Server + AAuth resource, signing with the bootstrapped `@aauth/local-keys` identity. -11 adds person-token acquisition and caching in front of the authorize-first path, the `auth_token_endpoint` / `person_token_endpoint` split in PS metadata, and three-way `access_mode` planning; R3 -02 adds operation access annotations and the per-call proposal flow, and removes the openapi-gateway vocabulary. Discovery generalizes to multi-resource: signed-call registry client, three-layer state (added / discoverable / per-resource ops), vocabulary-adapter abstraction (OpenAPI and MCP tools today, AsyncAPI partial, GraphQL later). v.next (sub-agents, WASM runtime) is still ahead.

Reference implementation of an AAuth agent for MCP-aware agent hosts. The agent proxy represents the user as an AAuth agent, exposes that agent's capabilities to an LLM via MCP, and opens the AAuth interactions that need the person. Published as `@aauth/proxy` from `aauth-dev/praca`.

## Objectives

1. Demonstrate AAuth's value end-to-end: cross-domain agent access with genuine user oversight.
2. Give MCP hosts (Claude Code, Claude Desktop, Cursor, CLI tools) access to AAuth resources via a single integration.
3. Reusable across agent platforms. Nothing in the agent proxy is host-specific.
4. No raw credentials in the agent proxy. The agent proxy's compromise surface is one AAuth agent identity, not a vault of third-party credentials.
5. Cryptographic identity per user. Parent agent keypair (software) + AP signing key (enclave-backed via `@aauth/local-keys`).
6. Real oversight via AAuth missions / resource tokens / interactions.
7. Trust integrity for PS↔user interactions — never relayed through agents, hosts, or chat platforms.

## Architecture context

```
┌──────────────────────────────────────────────────┐
│ Agent host  (Claude Code / Claude Desktop / CLI) │
│                                                  │
│   LLM ──MCP tool calls─────────┐                 │
└────────────────────────────────┼─────────────────┘
                                 ▼
            ┌─────────────────────────────────┐
            │ agent proxy  (stdio MCP server) │   ← this doc
            │  - AAuth agent for the user     │
            │  - software parent keypair      │
            │  - AP signing key in enclave    │
            │  - service catalog              │
            │  - interactions (open + poll)   │
            │  - state in ~/.aauth/proxy/     │
            └────────────────┬────────────────┘
                             │ AAuth-signed HTTPS
            ┌────────────────▼────────────────┐
            │ AAuth resource                  │
            │  - mints resource_tokens        │
            │  - issues interactions /        │
            │    escalation tokens            │
            └─────────────────────────────────┘
                ▲ governs grants, mints
                │ auth_tokens, hosts user
                │ approval flows
   ┌────────────┴────────────────────────────────┐
   │ Person Server (e.g. person.hello.coop)      │
   └─────────────────────────────────────────────┘
```

The agent proxy sits between the MCP host and AAuth resources. It is the user's signing principal; resources verify its AAuth signature, and PS holds the grants that the agent proxy's identity is authorized against. AAuth resources may be native AAuth services or AAuth-fronted wrappers over OAuth APIs — the agent proxy doesn't care which.

## Tool surface

A small fixed set of meta-tools — Mechanism B in the dynamic-discovery taxonomy (Stainless, Speakeasy, GitHub MCP) — keeps init-time tool-definition tokens flat regardless of how many resources the user has added or how many ops each resource exposes. Token-bloat research (`docs/research-notes.md` if we keep one) puts naive one-tool-per-endpoint at ~1.17M tokens for the Cloudflare API and ~405K for a 400-tool static MCP server; the meta-tool pattern keeps the agent proxy at ~1K of tool descriptions regardless of L1/L2 size.

Each tool's description embeds a short literal snapshot of L1 ("currently added resources: a, b, c") so the common path needs no extra round-trip; `list_resources` gives the canonical fresh view.

### v1 surface (eight tools)

**Resource lifecycle (L1 / L2):**
- `find_resources(query)` — search the registry (L2) by name, description, host and `upstream`. Returns `{ resource, name, description, access_mode, added, connected, upstream? }[]`, available entries first. A coming entry (registry `availability` set) is listed last with `availability` (the reason, verbatim) and `interest_count`. `connect_resources` still tries it — the provider may already let this person in — and its row carries `availability`. Until 5.1.0 it was refused with `not_available` before the host was touched.
- `add_resource(host_or_url)` — fetch `{host}/.well-known/aauth-resource.json`, validate, pick the resource's vocabularies, write to L1. Accepts bare host, `https://host`, or full URL; canonicalizes to bare lowercased host.
- `list_resources()` — return L1 with `{ resource, name, description, access_mode, ops_count, last_used }`.
- `remove_resource(resource)` — unregister from L1. Agent-proxy-local only; does not revoke PS-side grants.
- `connect(resource)` — pre-authorize a resource (typically a PS-side consent step). No-op for `access_mode: agent-token` resources.

**Operations within a resource (L3):**
- `list_operations(resource, query?)` — return ops across all vocabularies the resource advertises, as `{ opId, kind, summary, method?, path?, channel?, tags }[]`. `query` is **either** free-text (matched against `summary`/`tags`/`opId`) **or** a path/channel prefix (`/crm/v3/objects/contacts/*`). Bounded result size with explicit "N more — refine query" marker.
- `get_operation_schemas(resource, op_ids[])` — batch fetch full schemas for one or more operations. Schemas dominate token cost, so this is intentionally separate from `list_operations` (per Speakeasy / OpenMCP).
- `invoke(resource, op_id, args)` — execute. Routes internally on the op's `kind`: `sync.request` → R3 HTTP call; `async.send` → publish via the resource's send channel; `async.receive` → returns `async_subscribe_requires_subagent` (v.next). On first call to a session-token or auth-token resource that hasn't been authorized, returns the interaction URL — the LLM hands it to the user, then retries. An operation whose access mode this agent cannot complete is refused without a request being made (see "Access modes").

`kind` values: `sync.request` | `async.send` | `async.receive`. The LLM never sees `vocab`; that's an agent-proxy-internal routing detail (see "Vocabularies"). OpIds are the natural value from the vocab doc; the agent proxy deterministically prefixes (`openapi:`/`asyncapi:`) only when two vocabularies at the same resource happen to expose colliding ids.

`resource` is always the canonical bare lowercased host (e.g., `api-hubapi-com.proxy.aauth.dev`). Input accepts host / scheme+host / full URL; the agent proxy normalizes.

### v.next surface (saved-function runtime)

Each saved function is a real MCP tool surfaced in `tools/list` via `notifications/tools/list_changed` (Option A). The LLM calls it like any other tool; the agent proxy runs the saved code in a QuickJS-WASM isolate as an AAuth sub-agent (per issue #23). The runtime is also driven by a small lifecycle meta-surface:

- `run_code(code, scope?)` — ephemeral one-shot in a disposable isolate.
- `register_function(name, description, code, scope)` — promote a snippet to a saved tool. Adds to `tools/list`.
- `list_functions()` — return saved tools with descriptions and scopes (the canonical snapshot; `tools/list` is the LLM's primary view).
- `remove_function(name)` — delete; removes from `tools/list`.
- (v.next.next) `register_handler(name, event_pattern, code, scope)` — webhook/event handler; only fires when matching events arrive over the DO event tier.

`scope` is the AAuth scope (resources + operations the function may use). At register time, the agent proxy seeds the isolate's import closure with bindings only for those operations; identity is captured in the closure so sub-agent code can't impersonate or escalate. See "v.next: programmable runtime + sub-agents".

## Transport

stdio MCP server in v1. The same code can be exposed over HTTP for container-resident hosts (reaching the agent proxy at `host.docker.internal`); host-launched stdio ships first.

## State

Three layers, all file-backed, all per-machine.

**Agent identity** lives outside the agent proxy, in `~/.aauth/` via `@aauth/local-keys` (bootstrapped once per machine via `@aauth/bootstrap`). The agent proxy reads from it at startup; it owns no key material itself. This is what lets the same identity back multiple agent surfaces (the agent proxy, future CLI tools) without each carrying its own bootstrap.

**The agent proxy's own state** at `~/.aauth/proxy/`:

| Path | What | Refresh |
|---|---|---|
| `resources.json` | **L1** — added resources: `{ resource, name, description, access_mode, picked_vocabs[], last_used }[]` | written on `add_resource` / `remove_resource` / first successful auth |
| `catalog/registry.json` | **L2** — cached `GET registry.aauth.dev/resources` result | refreshed on startup + 24h background; ETag-conditional |
| `catalog/{host}/{vocab}.json` | **L3** — cached vocabulary docs (OpenAPI / AsyncAPI / …) per resource | fetched on first `list_operations`/`get_operation_schemas`; cached per the resource's `Cache-Control`, at most one hour; ETag-conditional on expiry |
| `pending-interactions.json` | open interactions awaiting user resolution | written/cleared as interactions open and resolve |

JSON files for v1; promote to SQLite if concurrent writes get painful. File-lock for concurrent writes (multiple host clients OK).

v.next adds:
- `functions/{name}.json` — saved-function source + scope + sub-agent identity
- `functions/{name}.wasm` (optional) — pre-compiled QuickJS bytecode if we end up caching that
- daemon mode (one persistent agent proxy per user, hosts connect via Unix socket — the SSH_AUTH_SOCK pattern)

## Bootstrap

Once per machine:

1. the agent proxy generates the parent keypair (software)
2. the agent-proxy-as-AP signs the parent's agent token (one enclave signature)
3. User completes parent grant at PS (mobile app, web)
4. Subsequent host launches reuse all of this

## Catalog & discovery

The discovery layer is built around the three-layer state model (`L1` added / `L2` discoverable / `L3` per-resource ops) and a small set of meta-tools that walk it lazily.

### L2 — discoverable resources (the registry)

The registry at `registry.aauth.dev` is an agent-token-gated Worker. The agent proxy calls `GET /resources` over a **signed** request using the same agent-token + HTTP-signature path it already uses for any AAuth resource. The response is `{ resources: RegistryEntry[], updated }`; each entry carries `{ issuer, name, description, access_mode, logo_uri?, added, submitted_by }` — and only that. The agent proxy caches at `~/.aauth/proxy/catalog/registry.json`, refreshes on startup + 24h background, ETag-conditional.

`PROXY_REGISTRY_URL` overrides the default for tests / self-hosted registries. Operators may also publish their own resource directory: for example, Hello's resource proxy operator advertises its hosted proxies at `proxy.aauth.dev` and the agent proxy treats it as a registry source under the same signed-call contract.

### L1 — added resources

The agent calls `add_resource(host_or_url)`. The agent proxy:

1. Normalizes the input to a bare lowercased host.
2. Fetches `https://{host}/.well-known/aauth-resource.json` (manual redirect, timeout, size cap — same SSRF guards the registry applies).
3. Validates: `issuer === https://{host}`, present description, valid `access_mode`, at least one supported entry in `r3_vocabularies` (or — explicit choice — accepts a vocab-less resource and exposes only `invoke` as a generic call).
4. Picks the vocabulary adapters it can use (see "Vocabularies").
5. Writes the entry to `~/.aauth/proxy/resources.json`.

After `add_resource`:
- `access_mode: agent-token` resources are immediately invokable.
- `access_mode: person-token` / `auth-token` resources need a person token from the PS first; the agent proxy obtains one lazily on the first `invoke` (see "Person tokens").
- `access_mode: session-token` resources are *added* but `invoke` will return an interaction URL on first call so the user can complete the resource's own consent flow; `connect(resource)` is the explicit pre-auth path.
- A resource declaring a mode this agent cannot complete is listed with a `skip_reason` and never called.

`add_resource` is the canonical entry point for both registry-found and direct-URL resources. No registry inclusion is required — direct URL is first-class. The agent proxy never gatekeeps on registry membership.

### L3 — operations within a resource

Per-resource ops are fetched on first `list_operations`/`get_operation_schemas` call against that resource, cached at `~/.aauth/proxy/catalog/{host}/{vocab}.json`. The agent proxy reads the resource's `r3_vocabularies` and loads each one through the matching adapter; vocab docs are cached and refreshed lazily.

**Vocab doc lifetime (4.9.0).** The resource's `Cache-Control` on the vocabulary document decides how long a copy is served, never more than one hour: `s-maxage` or `max-age` when present (capped at an hour); `no-cache` means ask every time; `no-store` means ask every time and keep nothing; no header means one hour, as since 4.5.1. When a copy has expired and the resource sent an `ETag`, the refetch carries `If-None-Match`, and a `304` renews the copy without a new body. An unreachable resource still gets the stale copy, except under `no-store`. An adapter opts in with `loadCached`; the OpenAPI adapter does, and the MCP adapter (whose document is a `tools/list` exchange, not one GET) keeps the one-hour default. **Resource metadata lifetime (4.10.0).** `/.well-known/aauth-resource.json` follows the same rule. It is read at `connect_resources` and stored on the L1 entry with `meta_expires_at`, `meta_max_age_ms` and `meta_etag`; when the entry is next used after that time (`list_operations`, `get_operation_schemas`, `invoke`, `connect_resources`) the well-known is read again, conditionally when there is an ETag, and the metadata fields are replaced. `added`, `last_used` and `connections` are the person's and are kept. The entry itself is never dropped, so `no-store` means what `no-cache` means: ask every time. A fetch that fails leaves the stored entry in use; a resource that stops advertising a usable vocabulary keeps the one that worked. An entry stored before 4.10.0 has no lifetime and is re-read on its next use. Until 4.10.0 the well-known was read once and never again, so a changed `access_mode`, `connection` object or vocabulary URL did not reach a person who was already connected.

`list_operations` returns a bounded summary list (no schemas); `get_operation_schemas` is the explicit "give me the full schemas for these op_ids" call. This separation matters because schemas dominate token cost — Speakeasy's published numbers show schema-bearing tool listings 5-10× larger than summary-only listings. (See "Tool surface".)

## Person tokens

AAuth -11 makes the person token load-bearing: a resource MUST have verified one before it issues a resource token, and the agent MUST present one via `Signature-Key` on every authorization endpoint request. The agent proxy therefore obtains a person token before the authorize-first path, not only for `access_mode: person-token` resources.

Acquisition is a signed POST to the PS's `person_token_endpoint` (published in `/.well-known/aauth-person.json` alongside `auth_token_endpoint`, renamed from `token_endpoint` in -11), presenting the agent token via `Signature-Key`, with `{ resource, mission_s256? }` as the body. Requests carrying a body to a PS or AS additionally cover `content-digest` and `content-type` in the signature. `200` returns `{ person_token, expires_in }`; `202` with `requirement=interaction` is the deferred path — the PS wants the user to approve this agent acting at this resource, and the agent proxy surfaces it like any other interaction rather than blocking.

**Caching.** A person token is scoped to one resource and, when it carries `mission_s256`, to one mission, so it is held under that pair in the token store (see "Tokens"). It is refreshed inside the refresh margin when the agent token lets a replacement live longer, because every auth token obtained with it is capped at its `exp`; if the refresh fails, the held one is presented until it expires.

## Tokens

One store holds every token the agent holds (`tokens.ts`, `ProxyConfig.tokens` / `ProxyDeps.tokens`). They are one chain — agent token → person token → auth token — whose `exp`s are capped downward (protocol §Refresh Margin), and all of them bind the agent key through `cnf`, so one store gives one expiry rule and one flush. Each record carries the RFC 7638 thumbprint of the key it binds; a record under another thumbprint means the key rotated, and the whole store is flushed.

**One record per key.** `agent ()`, `person (resource, mission_s256)`, `auth (resource, account, mission_s256)`, `session (resource)`. `put` replaces what the key held, so the agent holds exactly one auth token per resource, account and mission.

**The held auth token.** On an authorize-first call (`auth-token` / `per-call`):

| State at use time | Action |
|---|---|
| Held, grants the operation | Present it. One request. Inside the refresh margin too (below). |
| Held, does not grant the operation | Authorize for the union of what it grants and the operation. The new token replaces it. |
| Lapsed while in use (used in the last `ACTIVE_WITHIN_SECS`, 5 min) | Authorize for everything it granted plus the operation — the work is still going on. |
| None, or lapsed idle | Authorize for the operation (plus what the ScopePolicy adds). The activity that needed the old grant is over. |
| The resource answers `requirement=auth-token` (budget spent, revoked, step-up) | Exchange that resource token with the presented token as `presented_token`, under the key's lease. The result replaces the held token when it grants at least as much, or when the held one's budget is spent; anything narrower is used for this call only. |
| A `per-call` operation's proposal token | Presented once, never held. |
| A token a settled pending delivered | Presented. Held only when its `account` and `mission_s256` match the call's key, it grants the operation, and it grants at least what the key holds — the pending is tracked per host, not per key. |

"Grants" reads the token's own `r3_granted` / `r3_per_call`; a token that grants by `scope` alone is presented and the resource decides. Budgets are why this matters: an access server that meters a person's allowance reserves every auth token it issues in full until it expires, so an agent that obtains one per call exhausts the allowance on a handful of calls (senzing.aauth.dev, 2026-09-24). What the resource reports in `AAuth-Budget` is kept on the record and shown by `list_resources`, but never used to refuse a call — an exhausted token is presented so the resource answers with the step-up that carries its consumption record.

**No refresh inside the margin for auth tokens.** An auth token's `exp` is capped by the agent token, and an access server may clip it to the end of its budget period (access.aauth.dev: the top of the UTC hour). Neither is moved by a refresh, and every refresh is another allocation — so a held auth token is presented until it lapses (30 s of skew), and renewal is driven by activity instead. Person tokens cost nothing to refresh and cap every auth token obtained with them, so they are refreshed inside the margin — when the agent token lets a new one live longer — and presented anyway if the refresh fails. Hosts re-mint the agent token inside the margin for the same reason.

**ScopePolicy** (`scope.ts`) decides what to declare in `r3_operations` beyond what the call needs. It sees the reason (`initial` / `grow` / `refresh`), the held token, the lapsed one, and the resource's operations. It only adds: the agent always asks for the operation and, when growing or renewing, everything the held (or lapsed-in-use) token grants. The default adds nothing.

**Where the stdio bin keeps them.** In memory, for the life of the process. Its signing key is a software key minted per process and bound by the enclave-signed agent token, so no token outlives the process that obtained it, and a file shared by two concurrent sessions would have each flush the other's tokens as a key rotation. `createFsTokenStore` (`tokens.json`, mode 0600) is there for a host whose key persists.

**Concurrency.** `acquire` / `release` on the store serialize acquisition and step-ups per key, so concurrent calls that all miss — or all present the same spent token — obtain one token between them. A caller waits at most `LEASE_WAIT_MS` (30 s) and then goes ahead without the lease rather than outlive the MCP client's patience; a lease never released lapses after `LEASE_MS` (60 s). A host whose requests land in different processes runs the lease table where they meet (`createLeaseTable`).

**Hints.** `psHints.login_hint`, `domain_hint`, `tenant`, `prompt` and `justification` are forwarded on the person token request as well as on the auth token exchange. The person token is where the PS first picks the account the agent acts for; a PS with more than one binding for the agent needs `login_hint` there, not only later.

**Missions.** `mission_s256` is forwarded to the person token endpoint, stamped into the person token, copied by the resource into the resource token, and copied by the PS into the auth token. It appears in no auth-token request body — the claim travels inside the tokens. No PS implements `mission_endpoint` yet; the claim path is built regardless.

## Access modes

`access_mode` is an IANA registry, not a closed list, and the declaration is advisory: a resource MAY return any `AAuth-Requirement` at runtime whatever it published. The agent proxy plans three ways and only three:

| Plan | When | What the agent proxy does |
|---|---|---|
| **undeclared** | absent, or a value this build does not recognize | call the resource and read the `AAuth-Requirement`. Never an error. |
| **satisfiable** | recognized, and this agent's setup can complete it | plan against it and skip the speculative call |
| **unsatisfiable** | recognized, and this agent cannot complete it | skip the resource / operation, with the reason stated |

The third case is the one that pays. An agent whose agent token carries no `ps` claim has no person server, so it cannot obtain a person token and cannot complete `person-token`, `auth-token` or `per-call` — and it should learn that while planning, not at a 401. `find_resources` and `list_resources` carry a `skip_reason` on such resources; `invoke` refuses them without sending a request.

Whatever the plan, the runtime loop is the same: make the request, read any `AAuth-Requirement`, satisfy it, retry. The plan only chooses the opening credential.

### Operation access annotations

An agent cannot read R3 documents, so R3 alone tells it nothing about what any one operation needs. The vocabulary is what it *can* read — it has to parse that to make the call at all — so R3 -02 puts the annotations there:

| Vocabulary | Location | Access mode | Budget |
|---|---|---|---|
| OpenAPI / AsyncAPI | Operation Object | `x-aauth-access-mode` | `x-aauth-budget` |
| MCP | Tool `_meta` | `aauth.dev/access-mode` | `aauth.dev/budget` |

The agent proxy reads them off the vocab doc it already fetches for L3 and flattens them onto every `list_operations` / `get_operation_schemas` result as `access_mode` (always present — the mode that actually applies to that operation) and `budget: true` (only when set). Three rules:

- **Sparse.** An unannotated operation takes the resource-wide `access_mode`.
- **Replacing, not intersecting.** A `person-token` annotation on an `auth-token` resource *lowers* the requirement for that operation — which is what lets a metered resource serve balance and history calls without an authorization round trip.
- **Advisory.** Never enforced, in either direction. The runtime requirement is authoritative.

`session-token` MUST NOT appear in an annotation; a value seen anyway is dropped. `budget: true` implies at least `auth-token`, since a budget rides in the auth token's `budget` claim.

The LLM sees this before it plans: which operations need only the agent token, which cost an authorization round trip, and which are `per-call` and will block on a person every time.

### Per-call

A `per-call` operation is authorized in principle but not for any specific call. The resource challenges the invocation, builds a **proposal document** carrying that call's concrete `parameters`, persists it under its content hash, and returns a resource token whose `r3_uri`/`r3_s256` reference it — the token never carries the parameters. The agent proxy exchanges that resource token at the PS for a per-call auth token (the grant lands in `r3_per_call`, renamed from `r3_conditional` in R3 -02) and retries **the identical call**: the resource recovers the proposal by hash and rejects any parameter that differs. The request init is fixed for the whole invoke flow so the retry is byte-identical by construction.

## Operator selection

> **Deferred (2026-06-09).** Operator-selection policy needs `kind`/`wraps`/`operator` signals per registry entry to operate on. The live `registry.aauth.dev` does not carry those fields today — entries are `{ issuer, name, description, access_mode, logo_uri?, added, submitted_by }`. Until the agent proxy can either (a) get those fields surfaced in the registry or (b) derive them from each resource's well-known (`kind` is implicit from the resource being a proxy at all; `wraps` is not currently advertised; `operator` would need a new well-known field), there's nothing to choose between, so the design below is held against future need rather than implemented. The deferred path is most likely (a) — extend the registry schema once we have a second operator fronting the same upstream.

When the catalog holds more than one entry sharing a `wraps` value — several operators fronting the same upstream (e.g., Hello and Acme both proxy `api.hubapi.com`) — the agent proxy picks one **by default, without prompting**. The registry carries no ranking signals (it stays pure discovery); the selection policy lives here, in the agent.

**Resolution order.** For a given upstream, the agent proxy resolves to a single operator using, in order:

1. **User-pinned operator** — if the user has pinned an operator for this upstream, use it.
2. **Trust set** — the user's (or org's) configured set of trusted operators; the highest-ranked trusted candidate wins.
3. **Fallback ordering** — a built-in default preference: the agent vendor's first-party operator first, then a curated default list.

**Escalation.** The agent proxy surfaces the choice to the user (and the LLM) only when the policy can't decide cleanly:

- no candidate operator is in the trust set,
- two or more candidates rank equally, or
- the user's policy says "always ask" for this upstream or operator.

**Policy storage.** The policy lives in the agent proxy's state dir as `~/.aauth/proxy/operator-policy.json`:

```json
{
  "pins": { "api.hubapi.com": "hello" },
  "trust_set": ["hello", "acme"],
  "fallback": ["hello"],
  "always_ask": []
}
```

Defaults on a fresh install: all four lists empty. With no trust set and no fallback, the agent proxy prompts the user (and the LLM) the first time an upstream resolves to more than one operator. Distributions / agent vendors may ship a populated `fallback` and `trust_set` to silently prefer their first-party operator; that's a packaging concern, not an agent-proxy-core default. The agent proxy needs nothing more from the registry than the `kind`, `operator`, and `wraps` fields it already exposes to run this policy.

## Vocabularies

A resource self-describes by advertising one or more **vocabularies** in `r3_vocabularies` — each a `{ urn → vocab_doc_url }` pair. The vocab doc tells the agent proxy what operations exist, how to format requests, and what kinds of responses to expect. Multiple vocabularies per resource are first-class: a HubSpot proxy can carry both OpenAPI (CRM operations) and AsyncAPI (webhook events); a Slack proxy can carry OpenAPI (Web API) and AsyncAPI (RTM events).

The vocabulary is **internal to the agent proxy**. The LLM never sees the URN, the adapter, or the spec doc; it sees only the operations themselves with a `kind` tag (`sync.request` / `async.send` / `async.receive`) that captures the semantically-load-bearing distinction.

### URN registry (v1)

| URN | Status | Notes |
|---|---|---|
| `urn:aauth:vocabulary:openapi` | v1 adapter, full | OpenAPI 3.x. All ops have `kind: sync.request`. |
| `urn:aauth:vocabulary:asyncapi` | v1 adapter, partial | AsyncAPI 3.x. `send` operations → `kind: async.send` (invokable). `receive` operations → `kind: async.receive` (listed; `invoke` returns `async_subscribe_requires_subagent`). |
| `urn:aauth:vocabulary:mcp` | adapter, full | MCP tools (R3 -02 §MCP Vocabulary). All ops have `kind: sync.request`. See "MCP tools" below. |
| `urn:aauth:vocabulary:graphql` | future | GraphQL schema as a vocab. |

The URN registry now lives in the R3 spec (`urn:aauth:vocabulary:`), which defines seven standard vocabularies.

`urn:aauth:vocabulary:openapi-gateway` was **removed in R3 -02** (AAuth issue #72), and its adapter with it. Operation identifiers are scoped to the one discovery endpoint a resource advertises per vocabulary, so there is no composite `service:operationId` identity and no `{service, operationId}` entry shape in `r3_operations` / `r3_granted` / `r3_per_call`. A resource fronting several backend services either presents them as one valid definition at its discovery endpoint (renaming collisions) or exposes them under separate resource identifiers, where `aud` distinguishes them.

### Adapter interface

```ts
interface VocabAdapter {
  vocabUri: string                                        // e.g. urn:aauth:vocabulary:openapi
  load(url: string): Promise<VocabDoc>                    // fetch + parse + cache
  listOperations(doc: VocabDoc, query?: string): OpSummary[]
  getOperations(doc: VocabDoc, opIds: string[]): OpDetail[]
  buildInvocation(doc: VocabDoc, opId: string, args: unknown): InvocationPlan
  annotationsFor(doc: VocabDoc, opId: string): OperationAnnotations   // access mode + budget
  operationEntry(opId: string): Record<string, string>   // r3_operations entry: { operationId } | { tool }
  usableAt?(docUrl: string, origin: string): boolean      // optional; MCP requires same origin
}

type InvocationPlan =
  | { kind: 'sync.request'; method: string; path: string; query?: string; headers?: Record<string,string>; body?: unknown }
  | { kind: 'async.send'; channel: string; message: unknown }
  | { kind: 'async.receive'; channel: string; filter?: unknown }     // v.next-only via the runtime
```

The agent proxy's adapter table is keyed by URN. At `add_resource` time, the agent proxy walks `r3_vocabularies`, picks every URN it has an adapter for, and stores the picked list on the L1 entry. `list_operations` runs all picked adapters and flattens results; `get_operation_schemas` and `invoke` look up the owning adapter by `(resource, opId)`.

### MCP tools

The discovery endpoint is the MCP server URL. `load` speaks Streamable HTTP directly (no SDK client): `initialize`, `notifications/initialized`, then `tools/list` following `nextCursor`, with `accept: application/json, text/event-stream`, carrying `Mcp-Session-Id` and `MCP-Protocol-Version` once the server returns them, and reading either a JSON or an SSE answer. The cached doc is `{ endpoint, protocolVersion, tools[] }` — plain JSON, so it survives a JSON-backed DocCache.

- opId = tool name; summary = title and description; `bodySchema` = `inputSchema`, `responseSchema` = `outputSchema`; annotations from the tool's `_meta` (`aauth.dev/access-mode`, `aauth.dev/budget`).
- The authorize request names the operation as `{ "tool": "<name>" }` (`operationEntry`).
- `invoke` POSTs `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":opId,"arguments":body}}` to the endpoint path. The call goes to the resource's own origin, so an MCP endpoint on another origin is not picked (`usableAt`). AAuth challenges stay HTTP-level (401 + `AAuth-Requirement`, `AAuth-Budget`) and are read before the body; an SSE answer is reduced to its JSON-RPC response.
- The discovery session is not carried into `invoke`. A server that requires `Mcp-Session-Id` on `tools/call` is not supported.

An L1 entry stored with no picked vocabularies (a resource added before its vocabulary had an adapter) is re-read from the well-known when a tool next touches it, keeping `added`, `last_used`, and `connections`.

### OpId namespacing

OpIds come from the vocab doc as-is (OpenAPI `operationId`, AsyncAPI operation key, etc.). When two vocabularies at the same resource expose the same opId — rare in practice, since the conventions differ — the agent proxy's resource loader detects the collision deterministically and prefixes both (`openapi:contact.created`, `asyncapi:contact.created`) before the ops ever reach the LLM. The prefix scheme is stable, so saved-function code referencing an opId never silently breaks.

### Sync vs async lifecycle

- **`sync.request`** (OpenAPI): `invoke` runs the R3 path. Today's flow.
- **`async.send`** (AsyncAPI publish): `invoke` builds the publish request, signs, calls the resource. Fire-and-forget; response is a delivery ack. Works in v1.
- **`async.receive`** (AsyncAPI subscribe): listed by `list_operations` so the LLM knows it exists; `invoke` returns `async_subscribe_requires_subagent`. Subscribe semantics live in v.next, behind `register_handler` — the only way a subscription is useful is paired with code that decides per event, which is exactly what the sub-agent runtime is for.

### Vocab-less resources

A resource MAY advertise no `r3_vocabularies`. The agent proxy still adds it; `list_operations` returns empty and the LLM falls back to calling `invoke(resource, '/some/path', args)` with `op_id` interpreted as the raw path. This is the escape hatch for resources that haven't (yet) published a spec — the LLM has to know what it's doing, but the door isn't closed.

## Trust & key model

| Key | Location | Used for | Cost per use |
|---|---|---|---|
| **AP signing key** | enclave (SE/PIV via `@aauth/local-keys`) | Signing agent tokens (parent's, and v.next sub-agents') | SE ~30–50ms, PIV/YubiKey ~150–300ms |
| **Parent agent keypair** | software (in agent proxy memory) | Parent's request signatures, HTTP signatures to PS | software Ed25519, ~50µs |

**The agent proxy *is* the AP in v1.** The MCP server holds both the AP key (enclave-backed) and the parent's software key. The "spawn protocol" question from AAuth issue #23 collapses to an internal function call in this deployment. For multi-tenant agent-proxy deployments, AP and parent agent identity would be separated; for personal-install, the collapse is appropriate.

Enclave signature accounting:
- One sig at first run (mint parent's agent token; reused until expiry)
- Zero sigs per API call
- v.next: one sig per sub-agent spawn

Compromise model: process compromise leaks AP key (forge any future agent for this user/machine), parent's software key (impersonate parent until agent token expires), in-memory sub-agent keys. Does **not** leak the user's PS grant — that's at PS, keyed on parent identity. Revoke at PS → all forged agents become useless within auth_token TTL.

## Interactions

> Superseded in 4.0.0. There is no relay: the agent does not POST an
> interaction to the PS, and it *does* construct the URL the person opens.
> The v1 flow this section described is kept below the line as design history.

When a party cannot proceed without the person, it answers `202` with
`AAuth-Requirement: requirement=interaction; code="XXXX-XXXX"` — the code
alone. The recipient composes `{interaction_endpoint}?code=…` from the
issuer's published metadata: the resource's own `interaction_endpoint` when
the resource answered, the PS's when the PS did. The agent opens that URL and
polls; it never forwards the interaction anywhere.

Two shapes reach the agent:

1. **The PS needs the person** — consent for a grant, or approval of a per-call
   proposal. The agent composes the URL from PS metadata and polls the
   `Location` until the PS answers with an auth token, or terminally denies.
2. **The resource needs the person** — an upstream account has to be linked.
   The resource mints a connection-only resource token (no `scope`, an
   `interaction_code`); the PS holds a pending record, sends the person to the
   *resource's* `interaction_endpoint`, and terminates on the resource's
   bounce with `{ "status": "connection_established" }` and no token.

A `202` carrying no code at all is the third case: the PS is reaching the
person by its own channel (an open wallet tab, a device push). There is
nothing for the agent to open — it polls, and a later poll may hand it an
interaction after all.

Sensitive operations still follow the AAuth escalation path: the resource
mints a resource_token packed with operation context, the agent presents it at
the PS, and the PS mints an auth token bound to the agent's key only on
approval.

<details>
<summary>v1 design history — the interaction relay (removed in 4.0.0)</summary>

When an AAuth resource issues an interaction (escalation needed, fingerprint check, step-up auth), the agent proxy is the conduit between resource and PS:

1. Resource responds to a signed request with an interaction payload + resource_token
2. the agent proxy forwards the resource_token to PS along with parent's agent token
3. PS drives the user-approval flow (mobile app preferred, web fallback)
4. PS returns resolution (auth_token, denied, deferred)
5. the agent proxy returns auth_token to resource (and surfaces deny/defer to the LLM)

Sensitive operations follow the AAuth escalation path: resource mints a resource_token packed with operation context (sender, recipient, body excerpt), the agent proxy carries it to PS, PS drives mobile-app approval, only on approval mints auth_token bound to the agent proxy's parent key. **The agent proxy never sees or constructs the consent URL the user sees.**

</details>

### Notification fallback

When PS can't reach the user via mobile push (offline, no app installed), PS may fall back to host-provided notification surfaces. The agent proxy does not participate in that fallback — it's a PS↔host arrangement, not an agent-proxy concern.

## v1 scope (locked)

What ships:

- the agent proxy as `@aauth/proxy`, stdio MCP server, eight-tool v1 surface (`find_resources`, `add_resource`, `list_resources`, `remove_resource`, `connect`, `list_operations`, `get_operation_schemas`, `invoke`)
- Three-layer state at `~/.aauth/proxy/` (resources / registry cache / vocab cache + connections)
- Signed `GET registry.aauth.dev/resources` for L2 discovery; direct URL add via `add_resource` works without registry
- Vocabulary adapter abstraction with one full OpenAPI adapter and one partial AsyncAPI adapter (publish only)
- Interactions: compose the URL from the issuer's metadata, open it, poll
- MCP-as-AP key model
- Integration tested against at least one real AAuth resource

What v1 doesn't ship:

- Sub-agents and the WASM programmable runtime
- Dynamic code execution
- Saved-function tools surfaced in `tools/list`
- AsyncAPI subscribe (`async.receive`) invocation
- GraphQL vocabulary adapter
- Operator-selection policy (registry doesn't carry `kind`/`wraps`/`operator` signals yet)
- Per-host AAuth identities (AAuth issue #22's `class` claim is deferred)
- Daemon mode / Unix socket bridge

## v.next: programmable runtime + sub-agents

A coherent additive bundle. Doesn't require rewriting v1 components.

### Motivation

In v1, the LLM emits one MCP `tool_use` per upstream call. Multi-step workflows ("summarize unread Gmail from family@, post to Slack") are token-expensive. v.next extends Anthropic's "MCP code execution" pattern (late 2025): the model writes a script that imports tools as functions and runs in a sandbox. The agent proxy makes each script a verifiable AAuth sub-agent with its own identity and audit trail.

### Sub-agents via AAuth issue #23

Each registered function, webhook handler, or one-shot is an AAuth sub-agent of the parent:

```
agent-proxy parent (top-level agent)
├── register_function("send_digest")    → sub-agent parent+send_digest
├── register_handler("slack.message")   → sub-agent parent+on_slack_message
└── run_code(code, scope)               → sub-agent parent+oneshot-{uuid}
```

### LLM surfacing — Option A

Each saved function appears as a real MCP tool in `tools/list` (added via `notifications/tools/list_changed` after `register_function`). The LLM calls `mySalesDigest(args)` like any other tool; the agent proxy routes the call to the saved code in a fresh QuickJS-WASM isolate. The lifecycle meta-tools (`register_function` / `list_functions` / `remove_function` / `run_code`) sit alongside the saved tools; `list_functions` is the canonical fresh snapshot for clients that don't honor `list_changed`. (See "v.next surface" under "Tool surface".)

Sub-agent has its own software keypair and an agent token signed by AP (one enclave sig per spawn) with `act.agent = parent`. When sub-agent code calls upstream, AAuth challenges produce a resource_token bound to sub-agent's key; the agent proxy (parent) takes it to PS as `resource_token: sub.rt, actor_token: parent.at`; PS returns auth_token bound to sub-agent. PS audit reads "parent, acting via sub-agent X, did Y." Revoking parent's grant kills all sub-agents at next auth.

### Runtime

QuickJS-compiled-to-WASM via `quickjs-emscripten`. Each invocation runs in its own `QuickJSContext` with isolated heap, memory limit, execution timeout.

Why WASM:
- Cap-based isolation — a WASM module has zero capabilities except what the host injects as imports
- The cap model maps 1:1 to AAuth scopes — sub-agent's WASM imports = its declared scope
- Per-call cold start ~1ms; per-instance memory ~1MB
- Cross-language path open (Rust, Go sub-agents later)

Why `quickjs-emscripten`:
- Mature, production-used in AI tooling (langchain, Effect, etc.)
- JS-native API for binding host functions
- We don't need WASI HTTP/filesystem — the import surface IS the API

### Import surface bound at instantiation

Identity is captured in the import closure, never passed by the WASM module — sub-agent has no API surface to identify itself or impersonate another sub-agent.

Per-spawn binding generation walks declared scope against catalog, materializes named bindings backed by one host dispatcher:

```js
for (const service of subAgent.scope.services) {
  const serviceObj = vm.newObject()
  for (const method of service.methods) {
    const h = vm.newFunction(method.name, (...argHandles) => {
      const args = argHandles.map(a => JSON.parse(vm.getString(a)))
      const result = hostCall(subAgent, service.name, method.name, args)
      return vm.newString(JSON.stringify(result))
    })
    vm.setProp(serviceObj, method.name, h); h.dispose()
  }
  vm.setProp(vm.global, service.name, serviceObj); serviceObj.dispose()
}
// plus a generic escape hatch:
vm.setProp(aauthObj, 'call', vm.newFunction('call', (s, m, a) =>
  hostCall(subAgent, vm.getString(s), vm.getString(m), JSON.parse(vm.getString(a)))))
```

Agent code reads naturally:

```js
const msgs = gmail.list({ query: "from:dad is:unread" });
for (const m of msgs) slack.post({ channel: "#fam", text: `Dad: ${m.subject}` });
// or dynamically:
const result = aauth.call(svc, method, args);
```

### `hostCall` — the single chokepoint

```
hostCall(callerIdentity, service, method, args)
```

Owns AAuth signing, scope validation, resource_token bubbling, interaction handling, audit attribution. **v1's MCP `invoke` tool handler calls into the same dispatcher** with `callerIdentity = parent`. v.next bindings call it with `callerIdentity = sub_agent`. One code path; v.next is purely additive.

### Interactions block import calls

Sub-agent calls `gmail.send(...)` requiring user approval → import handler stays inside `hostCall` waiting on resolution → WASM module suspended (linear memory held) → PS drives approval → host retries, returns into WASM. Sub-agent sees `gmail.send` "just took longer."

If memory-while-blocked becomes a concern: quickjs-emscripten supports snapshot/resume of linear memory.

### Three design invariants make v.next additive

Ship these in v1 even though v.next won't use them yet:

1. **Central host-side dispatcher** `hostCall(callerIdentity, service, method, args)` owns all upstream calls
2. **Catalog is data, not code** — services as JSON entries, single source of truth for both MCP tool descriptions and WASM bindings
3. **Caller identity as first-class parameter to `hostCall`** — in v1 always parent; in v.next per-sub-agent

Get these right in v1 and v.next is a runtime bolt-on.

### Rebuild cadence (v.next)

| Change | Restart the agent proxy? | Rebuild WASM? |
|---|---|---|
| New service in catalog | no | no |
| New method on existing service | no | no |
| Update to agent proxy host code | yes (normal release) | no |
| Add host primitive (e.g. `register_handler`) | yes | yes (rare) |
| QuickJS-WASM version bump | yes | yes (rare) |

## Rejected

| Rejected | Why |
|---|---|
| Native AAuth client embedded in host (instead of agent-proxy-as-MCP) | Per-host implementation effort; agent-proxy-as-MCP works for any MCP-aware host |
| Many MCP servers (one per upstream) | Catalog churn; agent-proxy-as-discovery scales better |
| Sibling HTTPS signing proxy | Loses MCP's structured tool descriptions |
| Embedding `@aauth/local-keys` directly in host process | Reduces cross-host reusability |
| Routing PS↔user clarifications through chat | Breaks trust model — too many boundaries |
| Letting the model see or craft consent URLs | Prompt injection can substitute URLs and phish |
| Per-host AAuth identities in v1 | Issue #22's `class` claim is the right mechanism, deferred |
| Per-service typed WIT bindings for v.next WASM runtime | Per-service rebuild loop; catalog-driven named bindings give same ergonomics with zero rebuilds |
| V8 isolates (`isolated-vm`) for v.next runtime | WASM cap-model gives stronger isolation — absence of an import IS the deny |
| Wasmtime-hosted QuickJS over `quickjs-emscripten` | We don't need WASI HTTP/FS; import surface IS the API |
| Registry entries carrying full method/scope metadata | That belongs at the resource via `.well-known/aauth-resource.json`; registry stays a thin directory |
| Vocab string exposed to the LLM in OpSummary/invoke | Vocab is agent-proxy-internal routing; `kind` carries the LLM-relevant distinction (sync vs async, publish vs subscribe). Smaller surface, no learned vocabulary in the prompt. |
| Always-prefixing opIds with vocab | Collisions are rare; prefix-on-collision keeps the common case clean while staying collision-safe |
| Code-mode (single `execute` tool over typed TS API, Cloudflare style) in v1 | Mechanism B (meta-tools) is portable across MCP clients today; Mechanism A (code-mode) is exactly what v.next's QuickJS-WASM sub-agent runtime delivers, locally |
| Embedding-ranked tool retrieval (Portkey-style) in v1 | At ~10²–10³ ops per resource, structural path-prefix search is sufficient; revisit when L3 exceeds comfortable scan budget |
| Resource path-prefixed AAuth resources (`https://api.foo.com/aauth/v2`) | AAuth is origin-rooted today; bare-host canonical form covers everything until/unless that changes |
| `remove_resource` cascading into PS-side revocation | Tight coupling to a PS revoke API that may not exist; user might still want the grant alive for other agents. Agent-proxy-local only; PS revoke is a separate user-driven concern. |

## Deferred

- Sub-agents and the WASM programmable runtime (v.next, full design above)
- Saved-function tools surfaced in `tools/list` (v.next, Option A — Anthropic clients support `list_changed`; coverage for non-Claude clients is uneven, so an Option-B fallback may land alongside)
- AsyncAPI subscribe invocation — only useful behind a sub-agent, so deferred to v.next
- GraphQL vocabulary adapter
- Operator-selection policy (waiting on registry `kind`/`wraps`/`operator` signals)
- **Multiple accounts per service** — hold more than one connected upstream account at the same resource (e.g. two Gmail accounts behind the same proxy host), with the user/LLM choosing which account an `invoke` runs against. Today the agent proxy keeps a single `connections/{host}.json` per resource; this needs per-account connection state (`connections/{host}/{account}.json`), an `account` selector on `connect`/`invoke` (default when one is connected, disambiguate when several), and `list_resources`/`connect` surfacing the connected-account set. Distinct from operator-selection (which operator fronts an upstream) — this is *which end-user account* at the chosen operator. Falls out of user-held identity: each account is just another grant under the same AAuth identity, not a new operator-scoped token slot. Contrast: Arcade Omni caps at one account per provider per Arcade user — `switch_account` replaces rather than adds (see `ponte/omni-compete.md` §2).
- AAuth issue #22's `class` claim for distinguishing hosts on shared per-machine agent proxy
- AAuth-spec home for the vocabulary URN registry — lift from this doc into the AAuth spec once we have a second adapter to validate against
- Daemon mode with Unix-socket bridge
- AP separation from the agent proxy for multi-tenant deployments
- Snapshot/resume of WASM linear memory during long blocking interactions
- Cross-language sub-agents (Rust, Go, Python via Pyodide)
- SEP-1821 alignment: when MCP `tools/list?query=…` lands with real client support, fold `find_resources` + `list_operations` into thin wrappers over the spec primitive

## Phased plan

1. ✅ **Phase 0 — Skeleton.** the agent proxy stdio MCP server with single-resource `discover`/`invoke`/`connect`. Central `hostCall` dispatcher, catalog-driven, caller identity as parameter. Validated against Claude Code.
2. ✅ **Phase 1 — First real resource.** Connected to a real AAuth-fronted upstream and ran the full AAuth dance end-to-end: resource_tokens, escalation, interactions.
3. ✅ **Phase 2 — Discovery layer (multi-resource).** Refactored `catalog.ts` into a `VocabAdapter` interface (one OpenAPI adapter); added registry client (signed `GET /resources` + ETag); added L1 store at `~/.aauth/proxy/resources.json`; rewired `server.ts` to the eight-tool surface; added `PROXY_REGISTRY_URL`.
4. **Phase 3 — AsyncAPI partial.** AsyncAPI adapter listing `send` + `receive` ops; `invoke` runs `async.send`; `async.receive` returns `async_subscribe_requires_subagent`. Drives the second-vocab validation of the adapter interface.
5. **Phase 4 — Container host bridge.** the agent proxy exposes HTTP listener for container-resident hosts. Register via host's MCP config pointing at `host.docker.internal:<port>`. Validate signing + invoke from inside container.
6. **Phase 5 — Approval UX.** Wire up notification fallback path (PS → host notification surface) for cases where mobile push is unavailable.
7. **Phase 6 — v.next bundle.** Sub-agents per issue #23, MCP-as-AP minting sub-agent tokens, QuickJS-emscripten runtime, catalog-driven named bindings + generic escape hatch, central `hostCall` extended with sub-agent identities. Adds `run_code`/`register_function`/`list_functions`/`remove_function` MCP tools; saved functions surfaced via `tools/list_changed` (Option A). AsyncAPI subscribe becomes invokable via `register_handler`.
8. **Phase 7+.** Issue #22 `class` claim, daemon mode, multi-tenant AP separation, multi-language sub-agents, AAuth-spec home for the vocabulary URN registry.

## Single-sentence summary

the agent proxy is the user's AAuth agent in MCP form — a stdio-launched Node process that holds the user's parent identity, exposes a fixed eight-tool meta-surface (`find_resources` / `add_resource` / `list_resources` / `remove_resource` / `connect` / `list_operations` / `get_operation_schemas` / `invoke`) over three layers of state (added resources / cached registry / per-resource ops), dispatches via vocabulary adapters (OpenAPI and MCP tools today; AsyncAPI partial; GraphQL later) through a single `hostCall(caller, resource, opId, args)` chokepoint, and opens the AAuth interactions that need the person — so that v1 ships as a clean, token-flat MCP↔AAuth bridge and v.next bolts on a QuickJS-WASM sub-agent runtime whose saved functions appear as first-class MCP tools without rewriting a line of v1.
