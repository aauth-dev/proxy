# Holding the tool call until the work is done

Status: steps 1–3 implemented in `@aauth/proxy` 5.8.0 and `hellocoop/aauth-mcp`,
2026-10-08. They ship together, straight to production; no beta trial. Repos:
`aauth-dev/proxy` and `hellocoop/aauth-mcp`. No SDK fork. See "Implementation
notes" at the end for where the code differs from this design.

## The rule

Answer the MCP client only when the person has a URL to open that they have not
been given, or when the work is finished. Hold every other wait inside the call.

A reply from the Person Server (PS) is not a reason to answer. Neither is a
pending that is still pending.

## How a call works today (Claude Code)

1. The model calls `invoke` or `connect_resources`.
2. The proxy starts the authorization. The PS answers with an interaction code,
   so the person must open a URL.
3. The proxy returns `input_required` with a url-mode `elicitation/create`
   (`surfaceNatively`, `src/tools.ts:524`). This ends the HTTP request, but it
   is not a model turn.
4. Claude Code's MCP client shows the URL. When the person accepts, the client
   resends the same `tools/call` with `inputResponses`.
5. On that retry the proxy resumes the flight from the flight store and waits.
   Only the final result reaches the model.

Step 3 is forced. Protocol revision 2026-07-28 has no server→client request
mid-call, so `input_required` is the only way to hand over a URL.

Claude Code's client (2.1.295 bundle) runs this loop itself:

- `autoFulfill` defaults to `true` and `maxRounds` to `10`.
- A round with no `inputRequests` waits 250 ms and retries.
- Round 11 throws `InputRequiredRoundsExceeded`.

Prod example: agt `agt_JjDP…`, 2026-10-07.

| Time (UTC) | Event |
|---|---|
| 11:59:11.9 | invoke id 202 |
| 11:59:23.3 | `input_required` |
| 11:59:35.2 | retry, id 203 |
| 11:59:35.9 | `invoke.resume settled` → 200 |

### Keeping a call open

The call stays open as long as the proxy sends `notifications/progress` on the
response stream. Claude Code aborts a call only after five minutes with no
progress. `connect_resources` already sends progress every `POLL_SLICE_MS`
(25 s) and holds a call for up to 30 min. Waiting on a Worker costs no CPU.

This needs the client to send a progress token. A client that sends none
times the call out on its own clock (unmeasured; the TS SDK default is 60 s).

## Where we answer early today

| # | Where | What happens | Model turn? |
|---|---|---|---|
| E1 | `invoke` resume (`src/tools.ts:1262`) | Polls `budgetMs` (30 s), then text "still in progress … retry invoke" | yes |
| E2 | `invoke` `pending` (`src/tools.ts:1330`) | PS reaches the person itself; text "Retry invoke now" | yes |
| E3 | `connect_resources`, no progress token | 30 s slice, then `next` text | yes |
| E4 | Decline or cancel of the URL dialog | Ignored; the retry waits up to 10 min on a refused flight | — |
| E5 | 2025-era client that declared `elicitation.url` on `initialize` | Capabilities lost; URL goes back as text | yes |

E1 and E2 use a 30 s budget sized for clients without a progress token. Claude
Code sends a progress token on every call, retries included.

## Client matrix

Freezer, aauth-mcp `tools/call`, 14 days to 2026-10-08. Capabilities on 2025-era
rows come from `initialize`; on 2026-07-28 rows from the request envelope.

| Client | Protocol | `elicitation.url` | Progress token | MCP Apps (`io.modelcontextprotocol/ui`) | Calls | Today |
|---|---|---|---|---|---|---|
| claude-code 2.1.28x–2.1.295 | 2026-07-28 | yes | yes | no | 1048 | Native URL, MRTR loop |
| codex-mcp-client | 2025-06-18 | yes (on `initialize`) | yes | some installs | 147 | **Text (E5)** |
| Claude-User (claude.ai), most | 2026-07-28 | no | no | yes | 115 | Text |
| Cursor | 2025-11-25 | form only | no | no | 107 | Text |
| Claude-User, some | 2026-07-28 | yes | yes | no | 109 | Native URL |
| opencode | 2025-11-25 | yes (on `initialize`) | yes | no | 75 | **Text (E5)** |
| copilot-cli | 2026-07-28 | yes | yes | yes | 26 | Native URL |
| openai-mcp (ChatGPT) | 2026-07-28 | no | no | yes | 19 | Text |

E5 cause: `createMcpHandler` builds a fresh server per request. A 2025-era
`tools/call` carries no capabilities, and that server never saw `initialize`.
So `surfaceNatively` finds no `elicitation` and falls back to text. The
`interaction.no-elicitation` events for Codex come from this.

## Steps

### Step 1 — Remember `initialize` capabilities (fixes E5)

**The client behind an agent changes.**

- A person upgrades Claude Code, Codex or opencode.
- Two sessions on one machine share one MCP credential store, so they share
  one `agt`.
- With CIMD (planned), the same person and `client_id` reuse an `agt` across
  installs.

So capabilities are not a property of the agent. They are a property of the
client that sent the last `initialize`, and that can change at any time.

- **aauth-mcp, on every `initialize`.**
  - Store `{ capabilities, protocolVersion, clientInfo, user_agent, at }` in
    the UserStore, keyed by agent and client: `mcp:caps:<client name from
    User-Agent>`.
  - Overwrite on every `initialize`. Latest wins, never first wins.
  - Keep it apart from `mcp:client-info`. A change there drops the agent token
    (`setMcpClientInfo`), and a capability change must not.
- **On a 2025-era `tools/call`.**
  - Look up the record for this request's `User-Agent` client name.
  - Use it only if `user_agent` matches the request's `User-Agent` exactly
    (name and version) and the record is younger than 24 h.
  - Otherwise treat the capabilities as unknown and fall back to text. A wrong
    "yes" turns a link into an error the person never sees. A wrong "no" only
    costs a model turn.
- **On a 2026-07-28 request**, the envelope is authoritative. Never read the
  stored record.
- **Proxy.** Add a dep, `clientCapabilities?: (ctx) => Promise<ClientCapabilities | undefined>`.
  `surfaceNatively` consults it when the request has no envelope, before
  `server.server.getClientCapabilities()`. Then a declared `elicitation.url`
  sends a 2025-era client the -32042 `UrlElicitationRequiredError`.
- **Log.** Add `caps_source: envelope | initialize | none` on `tools/call`
  rows.

Unverified: whether Codex and opencode retry after -32042. Production logs
answer it (`legacy.url_error` → `legacy.followup`). Hedge: put the URL and code
in the -32042 error message, so a client that only shows the error still gives
the model a link.

### Step 2 — Hold `invoke`; honour decline (fixes E1, E2, E4)

- **`invoke` resume (E1).** When the request has a progress token, poll in
  `POLL_SLICE_MS` slices and send progress each slice. Stop when the flight
  settles, or at `CONNECT_MAX_MS` from `flight.startedAt`. On `connected`,
  adopt the token and make the call. If the PS re-advertises a code, return a
  new `input_required` (or -32042) with that URL. Without a progress token,
  keep today's 30 s behaviour.
- **`invoke` `pending` (E2).** Same hold when there is a progress token.
- **Decline or cancel (E4).**
  - Read `inputResponse(ctx.mcpReq.inputResponses, 'connect')` (SDK).
  - On `decline` or `cancel`, clear the flights the URL covered and call
    `authPending.resolve`.
  - `connect_resources` answers those items `declined`, a new outcome; the
    rest continue. `invoke` returns "The person declined authorization for
    host. Do not retry unless they ask."
  - A key in `droppedInputResponseKeys` counts as accept.

`connect_resources` already holds on a retry (Pass 2), so it needs only the
decline handling.


### Step 3 — Keepalive rounds for 2026-07-28 clients without progress (fixes E3)

Ships with steps 1–2, behind a kill switch.

**State.**

- Mint `requestState` with the SDK's `createRequestStateCodec`:
  - `key`: Worker secret `MRTR_STATE_KEY`
  - `ttlSeconds: 900`
  - `bind`: agent key + method
- Verify it with `ServerOptions.requestState.verify` on `new McpServer`.
- Payload: `{ tool, hosts, codes, round, started_at }`.
- Every `input_required` the proxy returns carries it: URL rounds and
  keepalive rounds.

**Keepalive.**

- On a 2026-07-28 request with no progress token, when the 30 s slice runs
  out, return `inputRequired({ requestState })` with no `inputRequests`
  instead of `next` text.
- Stop at round 8 and fall back to today's `next` text, so a client with
  `maxRounds` 10 never hits the limit.
- The flight store stays authoritative. A fresh model call has no state and
  still resumes by host.

**Fail safe.**

- No `MRTR_STATE_KEY` in the environment, or the env var `MRTR_KEEPALIVE=off`:
  no keepalive and no state minted. Behaviour is the same as after steps 1–2.
  Log `mrtr.disabled` once per request with the reason.
- A refused state (`-32602` "Invalid or expired requestState") is logged by
  the SDK's `onerror`. Log it as `mrtr.state_rejected` with the reason code.

### Logging — what production tells us

There is no beta trial. Every decision point logs, so Freezer answers the open
questions within days.

Every row carries `agt`, the `User-Agent` client name and version, the
protocol era, and `commit`.

| Event | When | Fields |
|---|---|---|
| `mcp.request` (extend) | every `tools/call` | `caps_source` (`envelope`/`initialize`/`none`), `has_request_state`, `round`, `input_responses` (key → action), `dropped_input_response_keys`, `progress_token` |
| `mcp.caps.stored` | `initialize` writes a record | client, `user_agent`, `elicitation` (form/url), changed (bool), previous `user_agent` |
| `mcp.caps.skipped` | 2025-era `tools/call` finds a record it won't use | reason (`ua_mismatch`/`stale`/`none`), stored vs request `user_agent` |
| `mrtr.input_required` | proxy returns `input_required` | tool, kind (`url`/`keepalive`), round, hosts, codes, ms since round 1 |
| `mrtr.retry` | a request arrives carrying our state | tool, round, ms since the previous round, `input_responses` actions |
| `legacy.url_error` | proxy throws -32042 | tool, hosts, code, `caps_source` |
| `legacy.followup` | a fresh call resumes a flight whose URL went out as -32042 | ms since the -32042, same tool (bool) |
| `hold.start` / `hold.end` | `invoke` or `connect_resources` holds a call | tool, hosts, slices, progress sent, outcome, duration ms |
| `call.aborted` | `ctx.mcpReq.signal` fires during a hold or poll | tool, ms since start, progress sent (count), last progress ms ago |
| `connect.declined` / `invoke.declined` | a decline or cancel ends a wait | tool, hosts, action, round |

### What the logs answer

| Question | Query |
|---|---|
| Do Codex and opencode retry after -32042? | `legacy.url_error` followed by `legacy.followup` per client, and the gap |
| Does a no-progress client time out, and when? | `call.aborted` by client: ms since start, progress sent = 0 |
| Do claude.ai and ChatGPT run the MRTR loop on a keepalive round? | `mrtr.input_required` kind `keepalive` followed by `mrtr.retry` with round+1, by client |
| Do clients drop `inputResponses`? | `dropped_input_response_keys` non-empty, by client |
| How often do people decline? | `connect.declined`, `invoke.declined` |
| Does capability matching skip too often? | `mcp.caps.skipped` by reason |

Answers turn into a client-name allow or deny list in the proxy. They don't
need a redesign.

### Later

- **Mid-call URL for 2025-era clients.** Send url-mode `elicitation/create`
  on the open SSE stream and hold the call. This needs an SDK patch if the
  stateless legacy path refuses server→client requests. Do it after
  `legacy.followup` shows how -32042 performs.
- **MCP App view for claude.ai and ChatGPT.** Both declare
  `io.modelcontextprotocol/ui` but not URL elicitation or a progress token.
  The view shows an Authorize button, the QR code and live status, and tells
  the model when everything is connected. Prototype it first.
- **MCP Tasks** (`seps/2663-tasks-extension.md`). No client declares
  `io.modelcontextprotocol/tasks` to us yet. Claude Code's bundle contains a
  Tasks client.

## What does not change

- The text fallback for clients with no native path.
- One URL per PS per connect (5.7.0).
- `adaptUrlElicitation` (aauth-mcp) as a guard.
- The background poll in `interactionHook`.

## Release (straight to production)

1. **`aauth-dev/proxy` 5.8.0.** PR into `main`, merge, push tag `v5.8.0`
   (`publish.yml`). npm may 404 on the tarball for a few minutes after
   publish.
2. **Secrets.** `wrangler secret put MRTR_STATE_KEY` on `aauth-mcp` and on
   `--env beta` (32+ random bytes; a different key each). Do this before the
   merge in step 3, or keepalive stays off (fail safe).
3. **`hellocoop/aauth-mcp`.** Bump `@aauth/proxy` to `^5.8.0`, PR into `main`,
   merge (deploys `mcp.aauth.dev`), then back-merge `main` → `beta`.
4. **Verify.**
   - `npx wrangler deployments list` shows the new version.
   - Freezer rows carry the new `commit`, `caps_source` on `tools/call`, and
     `mcp.caps.stored` from the next Codex or opencode `initialize`.
   - A Claude Code `invoke` that needs approval produces `hold.start` /
     `hold.end` and one tool result.
5. **Rollback.**
   - Keepalive only: set `MRTR_KEEPALIVE=off`.
   - Everything else: `npx wrangler rollback` to the previous version.

## Implementation notes (5.8.0)

- **Remembered capabilities need `elicitation.url`.** The proxy's 2025-era rule
  was "any declared `elicitation` gets -32042" (Claude Code 2.1.268 declared a
  bare `elicitation: {}` over stdio). A record from `clientCapabilities` counts
  only with `elicitation.url`: Cursor declares `elicitation.form` only, and
  -32042 to it would be a link the person never sees. The stdio path keeps the
  old rule.
- **Keepalive is `connect_resources` only.** `invoke` without a progress token
  keeps its 30 s slice and text answer, as step 2 says.
- **State payload carries `at`**, the time the round was minted, for
  `mrtr.retry` `ms_since_previous`.
- **`mrtr.state_rejected`** is logged by aauth-mcp's wrapper around
  `codec.verify` (same reason codes: `malformed`, `mac`, `expired`, `bind`),
  not from `onerror`: the wrapper has the request's agent and client.
- **A new advertised code ends a poll at once.** Polls stop on an advertised
  code other than the one handed over (`pollConnection` `except`), for
  `connect_resources` too; before, a handed-over item learned of a new code
  only at the end of its slice.
- **An aborted call stops polling** within one poll (`pollConnection`
  `signal`) and hands nothing over.

