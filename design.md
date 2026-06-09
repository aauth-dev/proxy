# praca — the user's AAuth agent in MCP form

**Status: v1 invoke spine ✅ proven live (2026-05-25); discovery layer redesigned 2026-06-09.** praca drove the authorize-first R3 flow end-to-end against prod `person.hello.coop` + a real proxy, signing with the bootstrapped `@aauth/local-keys` (enclave) identity. Discovery now generalizes to multi-resource: signed-call registry client, three-layer state (added / discoverable / per-resource ops), vocabulary-adapter abstraction (OpenAPI today, AsyncAPI partial, MCP-tools/GraphQL later). Token-bloat research (Cloudflare Code Mode ~99.9% cut, Anthropic ~98.7%, Speakeasy ~100×) validates the meta-tool/hierarchical pattern we already landed on. v.next (sub-agents, WASM runtime) is still ahead. Repo split + roadmap: `v1-plan.md`.

Reference implementation of an AAuth agent for MCP-aware agent hosts. praca represents the user as an AAuth agent, exposes that agent's capabilities to an LLM via MCP, and relays AAuth interactions to PS. Published as `@aauth/praca` from `aauth-dev/praca`.

## Objectives

1. Demonstrate AAuth's value end-to-end: cross-domain agent access with genuine user oversight.
2. Give MCP hosts (Claude Desktop, Claude Code, NanoClaw, CLI tools) access to popular services via a single integration.
3. Reusable across agent platforms. Nothing in praca is host-specific.
4. No raw credentials in praca. praca's compromise surface is one AAuth agent identity, not a vault of third-party credentials.
5. Cryptographic identity per user. Parent agent keypair (software) + AP signing key (enclave-backed via `@aauth/local-keys`).
6. Real oversight via AAuth missions / resource tokens / interactions.
7. Trust integrity for PS↔user interactions — never relayed through agents, hosts, or chat platforms.

## Architecture context

```
┌──────────────────────────────────────────────────┐
│ Agent host  (Claude Desktop / NanoClaw / CLI)    │
│                                                  │
│   LLM ──MCP tool calls─────────┐                 │
└────────────────────────────────┼─────────────────┘
                                 ▼
            ┌─────────────────────────────────┐
            │ praca  (stdio MCP server)       │   ← this doc
            │  - AAuth agent for the user     │
            │  - software parent keypair      │
            │  - AP signing key in enclave    │
            │  - service catalog              │
            │  - interaction relay to PS      │
            │  - state in ~/.aauth/praca/     │
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
   │ PS  (person.hello.coop or other)            │
   └─────────────────────────────────────────────┘
```

praca sits between the MCP host and AAuth resources. It is the user's signing principal; resources verify its AAuth signature, and PS holds the grants that praca's identity is authorized against. AAuth resources may be native AAuth services or AAuth-fronted wrappers over OAuth APIs — praca doesn't care which.

## Tool surface

A small fixed set of meta-tools — Mechanism B in the dynamic-discovery taxonomy (Stainless, Speakeasy, GitHub MCP) — keeps init-time tool-definition tokens flat regardless of how many resources the user has added or how many ops each resource exposes. Token-bloat research (`docs/research-notes.md` if we keep one) puts naive one-tool-per-endpoint at ~1.17M tokens for the Cloudflare API and ~405K for a 400-tool static MCP server; the meta-tool pattern keeps praca at ~1K of tool descriptions regardless of L1/L2 size.

Each tool's description embeds a short literal snapshot of L1 ("currently added resources: a, b, c") so the common path needs no extra round-trip; `list_resources` gives the canonical fresh view.

### v1 surface (eight tools)

**Resource lifecycle (L1 / L2):**
- `find_resources(query)` — search the registry (L2). Returns `{ resource, name, description, access_mode, added: bool }[]`.
- `add_resource(host_or_url)` — fetch `{host}/.well-known/aauth-resource.json`, validate, pick the resource's vocabularies, write to L1. Accepts bare host, `https://host`, or full URL; canonicalizes to bare lowercased host.
- `list_resources()` — return L1 with `{ resource, name, description, access_mode, ops_count, last_used }`.
- `remove_resource(resource)` — unregister from L1. Praca-local only; does not revoke PS-side grants.
- `connect(resource)` — pre-authorize a resource (typically a PS-side consent step). No-op for `access_mode: agent-token` resources.

**Operations within a resource (L3):**
- `list_operations(resource, query?)` — return ops across all vocabularies the resource advertises, as `{ opId, kind, summary, method?, path?, channel?, tags }[]`. `query` is **either** free-text (matched against `summary`/`tags`/`opId`) **or** a path/channel prefix (`/crm/v3/objects/contacts/*`). Bounded result size with explicit "N more — refine query" marker.
- `get_operations(resource, op_ids[])` — batch fetch full schemas for one or more operations. Schemas dominate token cost, so this is intentionally separate from `list_operations` (per Speakeasy / OpenMCP).
- `invoke(resource, op_id, args)` — execute. Routes internally on the op's `kind`: `sync.request` → R3 HTTP call; `async.send` → publish via the resource's send channel; `async.receive` → returns `async_subscribe_requires_subagent` (v.next). On first call to an aauth-access-token or auth-token resource that hasn't been authorized, returns the interaction URL — the LLM hands it to the user, then retries.

`kind` values: `sync.request` | `async.send` | `async.receive`. The LLM never sees `vocab`; that's a praca-internal routing detail (see "Vocabularies"). OpIds are the natural value from the vocab doc; praca deterministically prefixes (`openapi:`/`asyncapi:`) only when two vocabularies at the same resource happen to expose colliding ids.

`resource` is always the canonical bare lowercased host (e.g., `api-hubapi-com.hello-proxy.net`). Input accepts host / scheme+host / full URL; praca normalizes.

### v.next surface (saved-function runtime)

Each saved function is a real MCP tool surfaced in `tools/list` via `notifications/tools/list_changed` (Option A). The LLM calls it like any other tool; praca runs the saved code in a QuickJS-WASM isolate as an AAuth sub-agent (per issue #23). The runtime is also driven by a small lifecycle meta-surface:

- `run_code(code, scope?)` — ephemeral one-shot in a disposable isolate.
- `register_function(name, description, code, scope)` — promote a snippet to a saved tool. Adds to `tools/list`.
- `list_functions()` — return saved tools with descriptions and scopes (the canonical snapshot; `tools/list` is the LLM's primary view).
- `remove_function(name)` — delete; removes from `tools/list`.
- (v.next.next) `register_handler(name, event_pattern, code, scope)` — webhook/event handler; only fires when matching events arrive over the DO event tier.

`scope` is the AAuth scope (resources + operations the function may use). At register time, praca seeds the isolate's import closure with bindings only for those operations; identity is captured in the closure so sub-agent code can't impersonate or escalate. See "v.next: programmable runtime + sub-agents".

## Transport

stdio MCP server in v1. The same code can be exposed over HTTP for container-resident hosts (e.g., NanoClaw reaching praca at `host.docker.internal`); host-launched stdio ships first.

## State

Three layers, all file-backed, all per-machine.

**Agent identity** lives outside praca, in `~/.aauth/` via `@aauth/local-keys` (bootstrapped once per machine via `@aauth/bootstrap`). Praca reads from it at startup; it owns no key material itself. This is what lets the same identity back multiple agent surfaces (praca, future CLI tools) without each carrying its own bootstrap.

**Praca's own state** at `~/.aauth/praca/`:

| Path | What | Refresh |
|---|---|---|
| `resources.json` | **L1** — added resources: `{ resource, name, description, access_mode, picked_vocabs[], last_used }[]` | written on `add_resource` / `remove_resource` / first successful auth |
| `catalog/registry.json` | **L2** — cached `GET registry.aauth.dev/resources` result | refreshed on startup + 24h background; ETag-conditional |
| `catalog/{host}/{vocab}.json` | **L3** — cached vocabulary docs (OpenAPI / AsyncAPI / …) per resource | fetched on first `list_operations`/`get_operations`; cached with TTL |
| `connections/{host}.json` | per-resource session state — stored auth-tokens, refresh state, last interaction | written by R3 flow |
| `pending-interactions.json` | open interactions awaiting user resolution | written/cleared by interaction relay |

JSON files for v1; promote to SQLite if concurrent writes get painful. File-lock for concurrent writes (multiple host clients OK).

v.next adds:
- `functions/{name}.json` — saved-function source + scope + sub-agent identity
- `functions/{name}.wasm` (optional) — pre-compiled QuickJS bytecode if we end up caching that
- daemon mode (one persistent praca per user, hosts connect via Unix socket — the SSH_AUTH_SOCK pattern)

## Bootstrap

Once per machine:

1. praca generates the parent keypair (software)
2. praca-as-AP signs the parent's agent token (one enclave signature)
3. User completes parent grant at PS (mobile app, web)
4. Subsequent host launches reuse all of this

## Catalog & discovery

The discovery layer is built around the three-layer state model (`L1` added / `L2` discoverable / `L3` per-resource ops) and a small set of meta-tools that walk it lazily.

### L2 — discoverable resources (the registry)

The registry at `registry.aauth.dev` is a live agent-token-gated Worker (KV + R2; see `~/github/AAuth-dev/registry`). praca calls `GET /resources` over a **signed** request using the same agent-token + HTTP-signature path it already uses for any AAuth resource. The response is `{ resources: RegistryEntry[], updated }`; each entry carries `{ issuer, name, description, access_mode, logo_uri?, added, submitted_by }` — and only that. praca caches at `~/.aauth/praca/catalog/registry.json`, refreshes on startup + 24h background, ETag-conditional.

`PRACA_REGISTRY_URL` overrides the default for tests / self-hosted registries.

### L1 — added resources

The agent calls `add_resource(host_or_url)`. praca:

1. Normalizes the input to a bare lowercased host.
2. Fetches `https://{host}/.well-known/aauth-resource.json` (manual redirect, timeout, size cap — same SSRF guards the registry applies).
3. Validates: `issuer === https://{host}`, present description, valid `access_mode`, at least one supported entry in `r3_vocabularies` (or — explicit choice — accepts a vocab-less resource and exposes only `invoke` as a generic call).
4. Picks the vocabulary adapters it can use (see "Vocabularies").
5. Writes the entry to `~/.aauth/praca/resources.json`.

After `add_resource`:
- `access_mode: agent-token` resources are immediately invokable.
- `access_mode: aauth-access-token` / `auth-token` resources are *added* but `invoke` will return an interaction URL on first call; `connect(resource)` is the explicit pre-auth path.

`add_resource` is the canonical entry point for both registry-found and direct-URL resources. No registry inclusion is required — direct URL is first-class. Praca never gatekeeps on registry membership.

### L3 — operations within a resource

Per-resource ops are fetched on first `list_operations`/`get_operations` call against that resource, cached at `~/.aauth/praca/catalog/{host}/{vocab}.json`. praca reads the resource's `r3_vocabularies` and loads each one through the matching adapter; vocab docs are cached with a TTL and refreshed lazily.

`list_operations` returns a bounded summary list (no schemas); `get_operations` is the explicit "give me the full schemas for these op_ids" call. This separation matters because schemas dominate token cost — Speakeasy's published numbers show schema-bearing tool listings 5-10× larger than summary-only listings. (See "Tool surface".)

## Operator selection

> **Deferred (2026-06-09).** Operator-selection policy needs `kind`/`wraps`/`operator` signals per registry entry to operate on. The live `registry.aauth.dev` does not carry those fields today — entries are `{ issuer, name, description, access_mode, logo_uri?, added, submitted_by }`. Until praca can either (a) get those fields surfaced in the registry or (b) derive them from each resource's well-known (`kind` is implicit from the resource being a proxy at all; `wraps` is not currently advertised; `operator` would need a new well-known field), there's nothing to choose between, so the design below is held against future need rather than implemented. The deferred path is most likely (a) — extend the registry schema once we have a second operator fronting the same upstream.

When the catalog holds more than one entry sharing a `wraps` value — several operators fronting the same upstream (e.g., Hello and Acme both proxy `api.hubapi.com`) — praca picks one **by default, without prompting**. The registry carries no ranking signals (it stays pure discovery); the selection policy lives here, in the agent.

**Resolution order.** For a given upstream, praca resolves to a single operator using, in order:

1. **User-pinned operator** — if the user has pinned an operator for this upstream, use it.
2. **Trust set** — the user's (or org's) configured set of trusted operators; the highest-ranked trusted candidate wins.
3. **Fallback ordering** — a built-in default preference: the agent vendor's first-party operator first, then a curated default list.

**Escalation.** praca surfaces the choice to the user (and the LLM) only when the policy can't decide cleanly:

- no candidate operator is in the trust set,
- two or more candidates rank equally, or
- the user's policy says "always ask" for this upstream or operator.

**Policy storage.** The policy lives in praca's state dir as `~/.aauth/praca/operator-policy.json`:

```json
{
  "pins": { "api.hubapi.com": "hello" },
  "trust_set": ["hello", "acme"],
  "fallback": ["hello"],
  "always_ask": []
}
```

Defaults on a fresh install: empty `pins`, `trust_set` seeded with the agent vendor's operator (`hello`), `fallback` of `["hello"]`, empty `always_ask` — so out of the box praca silently prefers the first-party operator and prompts only when a needed upstream has no first-party option. praca needs nothing more from the registry than the `kind`, `operator`, and `wraps` fields it already exposes to run this policy.

## Vocabularies

A resource self-describes by advertising one or more **vocabularies** in `r3_vocabularies` — each a `{ urn → vocab_doc_url }` pair. The vocab doc tells praca what operations exist, how to format requests, and what kinds of responses to expect. Multiple vocabularies per resource are first-class: a HubSpot proxy can carry both OpenAPI (CRM operations) and AsyncAPI (webhook events); a Slack proxy can carry OpenAPI (Web API) and AsyncAPI (RTM events).

The vocabulary is **internal to praca**. The LLM never sees the URN, the adapter, or the spec doc; it sees only the operations themselves with a `kind` tag (`sync.request` / `async.send` / `async.receive`) that captures the semantically-load-bearing distinction.

### URN registry (v1)

| URN | Status | Notes |
|---|---|---|
| `urn:aauth:vocabulary:openapi` | v1 adapter, full | OpenAPI 3.x. All ops have `kind: sync.request`. |
| `urn:aauth:vocabulary:asyncapi` | v1 adapter, partial | AsyncAPI 3.x. `send` operations → `kind: async.send` (invokable). `receive` operations → `kind: async.receive` (listed; `invoke` returns `async_subscribe_requires_subagent`). |
| `urn:aauth:vocabulary:mcp-tools` | future | MCP tool-list as a vocab — useful for resources that ARE MCP servers fronted by AAuth. |
| `urn:aauth:vocabulary:graphql` | future | GraphQL schema as a vocab. |

URN convention is praca-design today; the right long-term home is the AAuth spec at `~/github/DickHardt/AAuth` (alongside `r3_vocabularies` itself). Lift it when a second adapter ships.

### Adapter interface

```ts
interface VocabAdapter {
  vocabUri: string                                        // e.g. urn:aauth:vocabulary:openapi
  load(url: string): Promise<VocabDoc>                    // fetch + parse + cache
  listOperations(doc: VocabDoc, query?: string): OpSummary[]
  getOperations(doc: VocabDoc, opIds: string[]): OpDetail[]
  buildInvocation(doc: VocabDoc, opId: string, args: unknown): InvocationPlan
}

type InvocationPlan =
  | { kind: 'sync.request'; method: string; path: string; query?: string; headers?: Record<string,string>; body?: unknown }
  | { kind: 'async.send'; channel: string; message: unknown }
  | { kind: 'async.receive'; channel: string; filter?: unknown }     // v.next-only via the runtime
```

praca's adapter table is keyed by URN. At `add_resource` time, praca walks `r3_vocabularies`, picks every URN it has an adapter for, and stores the picked list on the L1 entry. `list_operations` runs all picked adapters and flattens results; `get_operations` and `invoke` look up the owning adapter by `(resource, opId)`.

### OpId namespacing

OpIds come from the vocab doc as-is (OpenAPI `operationId`, AsyncAPI operation key, etc.). When two vocabularies at the same resource expose the same opId — rare in practice, since the conventions differ — praca's resource loader detects the collision deterministically and prefixes both (`openapi:contact.created`, `asyncapi:contact.created`) before the ops ever reach the LLM. The prefix scheme is stable, so saved-function code referencing an opId never silently breaks.

### Sync vs async lifecycle

- **`sync.request`** (OpenAPI): `invoke` runs the R3 path. Today's flow.
- **`async.send`** (AsyncAPI publish): `invoke` builds the publish request, signs, calls the resource. Fire-and-forget; response is a delivery ack. Works in v1.
- **`async.receive`** (AsyncAPI subscribe): listed by `list_operations` so the LLM knows it exists; `invoke` returns `async_subscribe_requires_subagent`. Subscribe semantics live in v.next, behind `register_handler` — the only way a subscription is useful is paired with code that decides per event, which is exactly what the sub-agent runtime is for.

### Vocab-less resources

A resource MAY advertise no `r3_vocabularies`. praca still adds it; `list_operations` returns empty and the LLM falls back to calling `invoke(resource, '/some/path', args)` with `op_id` interpreted as the raw path. This is the escape hatch for resources that haven't (yet) published a spec — the LLM has to know what it's doing, but the door isn't closed.

## Trust & key model

| Key | Location | Used for | Cost per use |
|---|---|---|---|
| **AP signing key** | enclave (SE/PIV via `@aauth/local-keys`) | Signing agent tokens (parent's, and v.next sub-agents') | SE ~30–50ms, PIV/YubiKey ~150–300ms |
| **Parent agent keypair** | software (in praca memory) | Parent's request signatures, HTTP signatures to PS | software Ed25519, ~50µs |

**praca *is* the AP in v1.** The MCP server holds both the AP key (enclave-backed) and the parent's software key. The "spawn protocol" question from AAuth issue #23 collapses to an internal function call in this deployment. For multi-tenant praca deployments, AP and parent agent identity would be separated; for personal-install, the collapse is appropriate.

Enclave signature accounting:
- One sig at first run (mint parent's agent token; reused until expiry)
- Zero sigs per API call
- v.next: one sig per sub-agent spawn

Compromise model: process compromise leaks AP key (forge any future agent for this user/machine), parent's software key (impersonate parent until agent token expires), in-memory sub-agent keys. Does **not** leak the user's PS grant — that's at PS, keyed on parent identity. Revoke at PS → all forged agents become useless within auth_token TTL.

## Interaction relay

When an AAuth resource issues an interaction (escalation needed, fingerprint check, step-up auth), praca is the conduit between resource and PS:

1. Resource responds to a signed request with an interaction payload + resource_token
2. praca forwards the resource_token to PS along with parent's agent token
3. PS drives the user-approval flow (mobile app preferred, web fallback)
4. PS returns resolution (auth_token, denied, deferred)
5. praca returns auth_token to resource (and surfaces deny/defer to the LLM)

Sensitive operations follow the AAuth escalation path: resource mints a resource_token packed with operation context (sender, recipient, body excerpt), praca carries it to PS, PS drives mobile-app approval, only on approval mints auth_token bound to praca's parent key. **praca never sees or constructs the consent URL the user sees.**

### Notification fallback

When PS can't reach the user via mobile push (offline, no app installed), PS may fall back to host-provided notification surfaces. praca does not participate in that fallback — it's a PS↔host arrangement, not an praca concern. (For Hello-operated PS + NanoClaw, see Hello's internal notification routing.)

## v1 scope (locked)

What ships:

- praca as `@aauth/praca`, stdio MCP server, eight-tool v1 surface (`find_resources`, `add_resource`, `list_resources`, `remove_resource`, `connect`, `list_operations`, `get_operations`, `invoke`)
- Three-layer state at `~/.aauth/praca/` (resources / registry cache / vocab cache + connections)
- Signed `GET registry.aauth.dev/resources` for L2 discovery; direct URL add via `add_resource` works without registry
- Vocabulary adapter abstraction with one full OpenAPI adapter and one partial AsyncAPI adapter (publish only)
- Interaction relay to PS
- MCP-as-AP key model
- Integration tested against at least one real AAuth resource

What v1 doesn't ship:

- Sub-agents and the WASM programmable runtime
- Dynamic code execution
- Saved-function tools surfaced in `tools/list`
- AsyncAPI subscribe (`async.receive`) invocation
- MCP-tools / GraphQL vocabulary adapters
- Operator-selection policy (registry doesn't carry `kind`/`wraps`/`operator` signals yet)
- Per-host AAuth identities (AAuth issue #22's `class` claim is deferred)
- Daemon mode / Unix socket bridge

## v.next: programmable runtime + sub-agents

A coherent additive bundle. Doesn't require rewriting v1 components.

### Motivation

In v1, the LLM emits one MCP `tool_use` per upstream call. Multi-step workflows ("summarize unread Gmail from family@, post to Slack") are token-expensive. v.next extends Anthropic's "MCP code execution" pattern (late 2025): the model writes a script that imports tools as functions and runs in a sandbox. praca makes each script a verifiable AAuth sub-agent with its own identity and audit trail.

### Sub-agents via AAuth issue #23

Each registered function, webhook handler, or one-shot is an AAuth sub-agent of the parent:

```
praca-parent (top-level agent)
├── register_function("send_digest")    → sub-agent parent+send_digest
├── register_handler("slack.message")   → sub-agent parent+on_slack_message
└── run_code(code, scope)               → sub-agent parent+oneshot-{uuid}
```

### LLM surfacing — Option A

Each saved function appears as a real MCP tool in `tools/list` (added via `notifications/tools/list_changed` after `register_function`). The LLM calls `mySalesDigest(args)` like any other tool; praca routes the call to the saved code in a fresh QuickJS-WASM isolate. The lifecycle meta-tools (`register_function` / `list_functions` / `remove_function` / `run_code`) sit alongside the saved tools; `list_functions` is the canonical fresh snapshot for clients that don't honor `list_changed`. (See "v.next surface" under "Tool surface".)

Sub-agent has its own software keypair and an agent token signed by AP (one enclave sig per spawn) with `act.agent = parent`. When sub-agent code calls upstream, AAuth challenges produce a resource_token bound to sub-agent's key; praca (parent) takes it to PS as `resource_token: sub.rt, actor_token: parent.at`; PS returns auth_token bound to sub-agent. PS audit reads "parent, acting via sub-agent X, did Y." Revoking parent's grant kills all sub-agents at next auth.

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

Owns AAuth signing, scope validation, resource_token bubbling, interaction relay, audit attribution. **v1's MCP `invoke` tool handler calls into the same dispatcher** with `callerIdentity = parent`. v.next bindings call it with `callerIdentity = sub_agent`. One code path; v.next is purely additive.

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

| Change | Restart praca? | Rebuild WASM? |
|---|---|---|
| New service in catalog | no | no |
| New method on existing service | no | no |
| Update to praca host code | yes (normal release) | no |
| Add host primitive (e.g. `register_handler`) | yes | yes (rare) |
| QuickJS-WASM version bump | yes | yes (rare) |

## Rejected

| Rejected | Why |
|---|---|
| Native AAuth client embedded in host (instead of praca-as-MCP) | Per-host implementation effort; praca-as-MCP works for any MCP-aware host |
| Many MCP servers (one per upstream) | Catalog churn; praca-as-discovery scales better |
| Sibling HTTPS signing proxy | Loses MCP's structured tool descriptions |
| Embedding `@aauth/local-keys` directly in host process | Reduces cross-host reusability |
| Routing PS↔user clarifications through chat | Breaks trust model — too many boundaries |
| Letting the model see or craft consent URLs | Prompt injection can substitute URLs and phish |
| Per-host AAuth identities in v1 | Issue #22's `class` claim is the right mechanism, deferred |
| Per-service typed WIT bindings for v.next WASM runtime | Per-service rebuild loop; catalog-driven named bindings give same ergonomics with zero rebuilds |
| V8 isolates (`isolated-vm`) for v.next runtime | WASM cap-model gives stronger isolation — absence of an import IS the deny |
| Wasmtime-hosted QuickJS over `quickjs-emscripten` | We don't need WASI HTTP/FS; import surface IS the API |
| Registry entries carrying full method/scope metadata | That belongs at the resource via `.well-known/aauth-resource.json`; registry stays a thin directory |
| Vocab string exposed to the LLM in OpSummary/invoke | Vocab is praca-internal routing; `kind` carries the LLM-relevant distinction (sync vs async, publish vs subscribe). Smaller surface, no learned vocabulary in the prompt. |
| Always-prefixing opIds with vocab | Collisions are rare; prefix-on-collision keeps the common case clean while staying collision-safe |
| Code-mode (single `execute` tool over typed TS API, Cloudflare style) in v1 | Mechanism B (meta-tools) is portable across MCP clients today; Mechanism A (code-mode) is exactly what v.next's QuickJS-WASM sub-agent runtime delivers, locally |
| Embedding-ranked tool retrieval (Portkey-style) in v1 | At ~10²–10³ ops per resource, structural path-prefix search is sufficient; revisit when L3 exceeds comfortable scan budget |
| Resource path-prefixed AAuth resources (`https://api.foo.com/aauth/v2`) | AAuth is origin-rooted today; bare-host canonical form covers everything until/unless that changes |
| `remove_resource` cascading into PS-side revocation | Tight coupling to a PS revoke API that may not exist; user might still want the grant alive for other agents. Praca-local only; PS revoke is a separate user-driven concern. |

## Deferred

- Sub-agents and the WASM programmable runtime (v.next, full design above)
- Saved-function tools surfaced in `tools/list` (v.next, Option A — Anthropic clients support `list_changed`; coverage for non-Claude clients is uneven, so an Option-B fallback may land alongside)
- AsyncAPI subscribe invocation — only useful behind a sub-agent, so deferred to v.next
- MCP-tools and GraphQL vocabulary adapters
- Operator-selection policy (waiting on registry `kind`/`wraps`/`operator` signals)
- AAuth issue #22's `class` claim for distinguishing hosts on shared per-machine praca
- AAuth-spec home for the vocabulary URN registry — lift from this doc to `~/github/DickHardt/AAuth` once we have a second adapter to validate against
- Daemon mode with Unix-socket bridge
- AP separation from praca for multi-tenant deployments
- Snapshot/resume of WASM linear memory during long blocking interactions
- Cross-language sub-agents (Rust, Go, Python via Pyodide)
- SEP-1821 alignment: when MCP `tools/list?query=…` lands with real client support, fold `find_resources` + `list_operations` into thin wrappers over the spec primitive

## Phased plan

1. ✅ **Phase 0 — Skeleton.** praca stdio MCP server with single-resource `discover`/`invoke`/`connect`. Central `hostCall` dispatcher, catalog-driven, caller identity as parameter. Validated against Claude Code.
2. ✅ **Phase 1 — First real resource.** Connected to `api-hubapi-com.hello-proxy.net` (Ponte/HubSpot). Full AAuth dance: resource_tokens, escalation, interactions. Interaction relay wired. W1/W2 demos proven.
3. ✅ **Phase 2 — Discovery layer (multi-resource).** Refactored `catalog.ts` into a `VocabAdapter` interface (one OpenAPI adapter); added registry client (signed `GET registry.aauth.dev/resources` + ETag); added L1 store at `~/.aauth/praca/resources.json`; rewired `server.ts` to the eight-tool surface; dropped `PRACA_PONTE_BASE` (+ legacy `invoke`/`invokeComplete` wrappers + demo scripts) in Phase A cleanup; added `PRACA_REGISTRY_URL`.
4. **Phase 3 — AsyncAPI partial.** AsyncAPI adapter listing `send` + `receive` ops; `invoke` runs `async.send`; `async.receive` returns `async_subscribe_requires_subagent`. Drives the second-vocab validation of the adapter interface.
5. **Phase 4 — Container host bridge.** praca exposes HTTP listener for container-resident hosts. Register via host's MCP config pointing at `host.docker.internal:<port>`. Validate signing + invoke from inside container.
6. **Phase 5 — Approval UX.** Wire up notification fallback path (PS → host notification surface) for cases where mobile push is unavailable.
7. **Phase 6 — v.next bundle.** Sub-agents per issue #23, MCP-as-AP minting sub-agent tokens, QuickJS-emscripten runtime, catalog-driven named bindings + generic escape hatch, central `hostCall` extended with sub-agent identities. Adds `run_code`/`register_function`/`list_functions`/`remove_function` MCP tools; saved functions surfaced via `tools/list_changed` (Option A). AsyncAPI subscribe becomes invokable via `register_handler`.
8. **Phase 7+.** Issue #22 `class` claim, daemon mode, multi-tenant AP separation, multi-language sub-agents, AAuth-spec home for the vocabulary URN registry.

## Single-sentence summary

praca is the user's AAuth agent in MCP form — a stdio-launched Node process that holds the user's parent identity, exposes a fixed eight-tool meta-surface (`find_resources` / `add_resource` / `list_resources` / `remove_resource` / `connect` / `list_operations` / `get_operations` / `invoke`) over three layers of state (added resources / cached registry / per-resource ops), dispatches via vocabulary adapters (OpenAPI today; AsyncAPI partial; MCP-tools and GraphQL later) through a single `hostCall(caller, resource, opId, args)` chokepoint, and relays AAuth interactions between resources and PS — so that v1 ships as a clean, token-flat MCP↔AAuth bridge and v.next bolts on a QuickJS-WASM sub-agent runtime whose saved functions appear as first-class MCP tools without rewriting a line of v1.
