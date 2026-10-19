# MCP security gateway

**Status:** Two paths, both implemented and executed end to end.

1. **Evaluation** (`POST /v1/mcp/evaluate`) decides about calls that are
   *described* to it. Sentinel makes no network call on this path.
2. **The wire proxy** (`POST /v1/mcp/proxy/{server_id}`, off by default) speaks
   JSON-RPC over the MCP Streamable HTTP transport and sits BETWEEN an MCP
   client and an enrolled server, so the call passes through the gate on its
   way rather than being reported after the fact.

What the proxy is **not**: transparent interception. A client must be pointed
at the proxy URL; nothing rewrites traffic that does not arrive here. Protocol
support is one versioned revision and an allowlist of methods — everything else
is refused as `NOT_SUPPORTED` rather than forwarded unevaluated. Both limits are
stated in the module docstrings and repeated below, so no reader infers more
reach than exists.

## The three questions a generic tool gate cannot answer

`ProtectGate` already decides `ALLOW` / `WARN` / `REQUIRE_APPROVAL` / `BLOCK`
from a tool call's content, and the MCP gateway **reuses** it rather than
forking a second decision path. One rule set governs both, so there is no second
place for them to disagree. What MCP adds is context a bare tool call has no
room for:

| # | Question | Failure if unasked |
|---|---|---|
| 1 | Is this server one we enrolled? | An agent is pointed at a server nobody reviewed, and every call to it looks like an ordinary tool call |
| 2 | Is this tool what it was when it was approved? | A server ships a benign `search_docs` on Monday and a data-exfiltrating `search_docs` on Friday. The **name is identical**, so an allowlist sees nothing |
| 3 | Is the tool's *description* itself the attack? | A description is prose the model reads as instructions, supplied by the server. Inspecting the **arguments** never finds it |

Checks run in that order, and the order is load-bearing: an `UNKNOWN` or
`BLOCKED` server is refused **before any of its text is read**, so a hostile
server cannot reach the parser or spend the detector's time. Asserted by
`test_an_unknown_server_is_refused_before_its_content_is_read`, which requires
`evaluation.protect` to be `None` rather than merely requiring a refusal.

## Trust is a stored fact, never a request field

`McpCallPayload` has **no** field for MCP server trust. `UNKNOWN` is the only
thing standing between an attacker-introduced server and the rest of the
pipeline, so a caller able to declare its own server `enrolled` would step over
the whole gateway in one request.

`trustLevel` *is* accepted and is a different axis — it is the calling **agent's**
`TrustLevel`, exactly as on `ProtectPayload`, and says how sure we are of who is
calling rather than whether the server they reached is one we know.

Enforced from both sides:

- `test_a_caller_cannot_declare_its_own_server_enrolled` posts `trust`,
  `serverTrust` and `server_trust` in the request body and requires the server
  to stay `unknown`.
- `test_a_caller_cannot_promote_its_own_server_by_claiming_trust` asserts the
  **signature** of `McpGateway.evaluate_request` — no parameter is annotated
  `McpServerTrust`. It resolves annotations with `typing.get_type_hints`; the
  first version compared `inspect.signature(...).annotation` against the class
  under `from __future__ import annotations`, where every annotation is a
  *string*, so the sweep scanned an empty set and passed while checking nothing.

## Enrolment is CLI-only

Enrolling a server decides which servers an agent may reach and what their tools
are allowed to be. That is a trust-anchor change, and
`sentinel/domain/authorization.py` records the standing decision that
trust-anchor changes are guarded by shell access to the host rather than by a
bearer token — a credential that could enrol its own MCP server could enrol a
hostile one.

```bash
python -m sentinel.interface.cli mcp-enrol acme docs-mcp tools.json https://mcp.example/docs
```

`tools.json` accepts either a bare list or the `{"tools": [...]}` shape an MCP
client prints, because hand-reshaping the artifact being security-reviewed is
where mistakes come from. It is a **file and not a live fetch** on purpose:
enrolment is the moment an operator says "these are the tools I reviewed", and
fetching at enrolment time would mean approving whatever the server happened to
serve, unread.

`mcp-block` refuses every call to a server, and `mcp-enrol` will **not** launder a
blocked server back to enrolled — `test_a_blocked_server_cannot_be_enrolled_back_without_unblocking`.

Because this is the only path out of `UNKNOWN`, a broken `mcp-enrol` would not
fail loudly; it would refuse every MCP call forever while looking like a strict
security posture. `test_enrolment_turns_a_refused_call_into_an_allowed_one`
executes the loop and asserts the **before** state as well as the after, so it
cannot pass on a build that allows everything.

## Storage

`mcp_servers` and `mcp_tool_pins` are both in `PROTECTED_TABLES`, so the RLS
migration and the catalogue check in `test_tenant_isolation_rls.py` cover them
without being told about them — that test iterates `PROTECTED_TABLES` and asks
PostgreSQL's own catalogue whether `relrowsecurity` **and**
`relforcerowsecurity` are set with a policy attached.

Every query is scoped twice: `conn.set_tenant(...)` **and** an explicit
`tenant_id =` predicate. The predicate is not redundant — **SQLite has no
row-level security**, so on SQLite it is the only tenant boundary there is.
Verified by mutation: removing `AND server_id=` / the tenant predicate from
`SqlMcpRegistry.lookup` makes
`test_one_tenants_enrolment_does_not_admit_another_tenants_call` fail, and
restoring it makes the module pass again.

Pinning **replaces** a server's tool set in one transaction rather than merging.
Merging would leave a tool pinned that the operator has since removed; splitting
the delete and insert across transactions would open a window with no pins at
all, which under `require_pin` turns a re-approval into an outage.

## `SENTINEL_MCP_REQUIRE_PIN`

Defaults to `true`. Setting it `false` is the OBSERVE-mode escape for a rollout
where an operator is still discovering which servers exist. It relaxes **check 2
only** — server trust and description scanning are unaffected, and an unknown
server is still refused either way
(`test_an_unpinned_server_is_refused_by_default_and_allowed_in_observe_mode`
asserts the policy still ran in the permissive case).

## A defect this found in itself

Running the CLI drill end to end showed `evaluate` diffing the **one** tool being
called against the **whole** pinned set, so every tool that simply was not the
subject of the call was reported as `TOOL_REMOVED`. With twenty pinned tools,
every call would have written nineteen false "a pinned tool is no longer
offered" entries into its audit record.

A single call is not an observation of the server's tool listing. Per-call drift
is now scoped to the called tool; `diff_tools`, which is given a real listing,
still reports removals. Both halves are pinned by
`test_one_call_does_not_report_every_other_pinned_tool_as_removed` and
`test_a_full_listing_still_reports_a_removed_tool`.

This is the same correction the detector needed after F-10, where 51.7% of
ordinary tool actions were being flagged: narrow the input to what the check can
actually speak to.

## The wire proxy

`POST /v1/mcp/proxy/{server_id}` (capability `execute_tool`) is an MCP
Streamable HTTP endpoint an MCP client points at **instead of** the real
server. It exists only when `SENTINEL_MCP_PROXY_ENABLED` is set — when off,
the route is not registered and a scanner sees the same 404 as no feature.
Implementation: `sentinel/infrastructure/mcp_wire.py` (JSON-RPC over
`HardenedHttpClient`, so redirect refusal, post-resolution address validation
and bounded responses are inherited, not re-implemented) fronted by
`sentinel/interface/mcp_proxy_routes.py`.

Properties the evaluation API cannot provide, each pinned by
`tests_arch/test_mcp_wire_proxy.py`:

- **Default-deny egress.** The endpoint comes from the enrolment record; the
  request has no field to name one. A server that is not `ENROLLED` is refused
  before any network activity — the tests assert the upstream call log is
  EMPTY, not merely that the caller was told no
  (`test_an_unknown_server_is_refused_and_nothing_is_dialled`). `OBSERVED` is
  refused here even though `evaluate` accepts it: this route is the thing
  *making* the call, and dialling a server an operator merely saw would turn
  observation into authorisation.
- **The rug pull is caught against the LIVE definition.** `tools/call` first
  fetches the server's current `tools/list` and evaluates the called tool's
  live definition against the pin, so a definition changed after enrolment
  refuses the call without forwarding it
  (`test_a_rug_pulled_tool_is_refused_before_the_call_is_forwarded`). Cost:
  one extra upstream round trip per call, stated here rather than hidden.
- **A drifted listing is refused, not filtered.** Descriptions in `tools/list`
  are prose the model reads as instructions. A listing with an added or
  changed tool is refused whole; filtering it would hand the client upstream
  state Sentinel partly authored. Removal-only drift passes with an audit
  record — a server that dropped a tool narrowed, not widened.
- **Delegated identity rides every record.** `X-Sentinel-Agent-Id` (required),
  `X-Sentinel-Principal` and `X-Sentinel-Session-Id` carry human → agent →
  session attribution into the audit trail; refusals carry it too, which is
  when it matters (`test_the_delegation_chain_is_recorded_on_the_refusal`).
  `X-Sentinel-Upstream-Authorization` forwards the client's own OAuth
  credential for the upstream verbatim; it is never logged, stored or minted.

Protocol support is versioned and allowlisted: revision `2025-06-18`
(`MCP_PROTOCOL_VERSION`), methods `initialize`, `ping`, `tools/list`,
`tools/call` and the client lifecycle notifications. Everything else answers
JSON-RPC `-32601` with an explicit `NOT_SUPPORTED` marker and is **not**
forwarded — a pass-through nobody evaluated would be an unevaluated side
channel. Policy refusals travel in-band as JSON-RPC error `-32050` with the
full evaluation under `error.data.sentinel`, because the caller is an MCP
client mid-session and an in-band error is the shape it can handle.

### OAuth through the proxy

An upstream `401`/`403` is **relayed** with its `WWW-Authenticate` header
(`test_an_upstream_401_is_relayed_with_its_challenge`) — that header carries
the RFC 9728 protected-resource-metadata pointer the client's
authorization-server discovery starts from, so relaying it is what makes the
MCP authorization flow work *through* the proxy. Sentinel never mints, stores
or logs upstream credentials; it carries the client's own.

It is **not relayed unread**. That pointer is supplied by the resource whose
trustworthiness is the open question: a compromised server answering
`resource_metadata="https://attacker.example/…"` aims the client's entire OAuth
flow at an authorization server the attacker runs. Sentinel is the one party in
the exchange that knows which endpoint an operator actually enrolled, so it is
the only party positioned to notice. A pointer that is not same-origin with the
enrolled endpoint is **stripped**, and the refusal is recorded as
`oauth_issuer_confusion`
(`test_a_challenge_naming_a_foreign_issuer_is_not_relayed`). The client still
learns it is unauthorized — from a challenge naming nobody, which fails closed
rather than sending it somewhere hostile. Same-origin challenges pass through
untouched (`test_a_same_origin_challenge_is_relayed`).

Credential audience restriction (`SENTINEL_MCP_PROXY_REQUIRE_TOKEN_AUDIENCE`,
default on): a forwarded JWT whose `aud` claim names no origin matching the
enrolled endpoint is refused before any network activity
(`test_a_token_bound_to_another_resource_is_not_replayed`) — a token minted
for server A must not be replayed against server B through the proxy. This is
**structural inspection, not verification**: Sentinel holds none of the
upstream's keys, so it checks what a token plainly claims about its audience
and nothing more. Opaque tokens are not inspectable and always pass
(`test_an_opaque_token_is_not_inspectable_and_passes`); that limit is stated
here rather than papered over.

### Server discovery

```bash
python -m sentinel.interface.cli mcp-discover acme docs-mcp https://mcp.example/rpc tools.json
```

Contacts a candidate server, runs `initialize` + `tools/list`, records what it
served, writes the file `mcp-enrol` takes — and **enrols nothing**
(`test_discovery_records_the_server_as_observed_never_enrolled`). The server is
left `OBSERVED`, which the proxy refuses to dial, so discovering a server
grants it nothing. The review step survives; only the hand-authoring of JSON
goes away, because enrolment is still the moment an operator says "these are
the tools I reviewed" and fetching at enrolment time would mean approving
whatever the server happened to serve, unread.

This command takes an endpoint from argv, which the proxy deliberately refuses
to do from a request. The difference is the trust anchor: an argv is an
operator at a shell on the host, which is already how enrolment is guarded. The
same egress policy applies, so discovery cannot reach anywhere the proxy could
not. A server that answers `401` is reported, not worked around — discovery
holds no upstream credential and will not invent one
(`test_an_authorization_challenge_is_reported_not_worked_around`).

### Server identity

`mcp_servers.server_info` records what a server says it *is* at `initialize`
(`serverInfo` name/version). The tool pins catch a changed TOOL and catch
nothing about a changed SERVER: an endpoint can be rehosted, a DNS record
moved, or an approved address taken over, and in each case the tools may be
byte-identical while the party serving them is not.

A changed **name** is refused as impersonation
(`test_a_different_server_answering_an_enrolled_endpoint_is_refused`); a changed
**version** is recorded and allowed (`test_a_version_bump_is_recorded_and_allowed`),
because refusing every upgrade would make routine maintenance an outage and
train operators to ignore the signal. First contact is learned and recorded
rather than refused — enrolment approves an endpoint and its tools, and that
identity is trust-on-first-use, stated here rather than dressed up as
verification.

### Duplicate tool names

A listing serving one name twice is refused rather than resolved, on both the
call and the listing path (`test_tool_name_collision_is_refused_rather_than_resolved`).
Whichever copy Sentinel evaluates, the **server** decides which copy actually
runs, so picking one silently means a benign definition can be inspected while
a hostile one executes under the same name. This was a real defect found by
writing the attack test: `_evaluate_tools_call` took the FIRST match while
`diff_tools` built a dict in which the LAST won, so an attacker choosing the
order chose which copy got inspected.

### Tool provenance

Every LIVE listing the proxy obtains is recorded before any decision is made
about it. `mcp_tool_provenance` holds one row per (tool, definition version)
with separate description/schema hashes, `first_seen`, `last_seen` and
`times_seen` — a changed definition opens a **new** row and leaves the old one
intact, so after a rug pull the investigation reads "when did the old
definition stop appearing" and "when did the new one start" straight off two
rows (`test_a_changed_definition_opens_a_new_provenance_row_keeping_the_old`).
`mcp_tool_changes` is the append-only drift log; every drift the gateway
observes lands there whether or not the caller kept the error
(`test_a_refused_rug_pull_lands_in_the_change_log`). Both tables carry FORCE
row-level security via `PROTECTED_TABLES`. The tool description itself is
still never stored — hashes only, per this module's standing rule about
retaining attacker-controlled text. Operator view:

```bash
python -m sentinel.interface.cli mcp-provenance acme docs-mcp
```

### Egress classification

Every proxied call's audit record carries a `destination_class` — `internal`,
`allowlisted` or `external` (`sentinel/domain/mcp.py::classify_destination`),
judged without resolution: hostnames are classified by literal form and
allowlist membership only, because a pure function that pretended to know a
hostname's address would be a classification the attacker picks. The
resolution-aware refusal of private addresses stays where it is, in
`infrastructure/outbound.py` at connection time.

### The definition cache

`SENTINEL_MCP_PROXY_DEFINITION_CACHE_SECONDS` (default `0`) lets a deployment
reuse a server's `tools/list` for `tools/call` evaluation for up to that many
seconds, removing the extra round trip per call. `0` means every call is
evaluated against the LIVE listing. Non-zero is an explicit trade: the
rug-pull detection window widens to at most the TTL
(`test_with_a_cache_ttl_the_second_call_skips_the_listing`). Per-process, and
keyed by (tenant, server) so one tenant's cache cannot answer another's.

## Adversarial coverage

`tests_arch/test_mcp_attacks.py` carries one test per attack named in
specification section 71, kept in a dedicated module so the coverage is
auditable — eleven named attacks, eleven checkable names, rather than trusting
they are covered somewhere across four files. Each asserts the **side effect**
was prevented (the upstream was never dialled, the hostile definition never
reached policy), not merely that an error came back: a gateway that returns an
error and performs the action anyway passes the weak version of every one.

Writing them found the duplicate-tool-name defect described above.

## Measured overhead

`scripts/run_mcp_proxy_bench.py` measures Sentinel's own per-call cost against
a stub upstream that returns instantly; results in `docs/mcp_proxy_bench.json`.
It is **not** end-to-end MCP latency — a real server's response time is added
on top and dominates in any deployment — and quoting it as such would be the
fake-benchmark failure section 127 bans. It is the gateway's tax, which is the
part Sentinel controls and the only part it should claim.

Measured on SQLite with the cache off (every call fetches a live listing),
300 requests per point: p95 2.03 ms at concurrency 1, rising to 18.73 ms at
concurrency 16; p99 2.16 ms rising to 89.35 ms. Both inside the section 79
targets (p95 < 50 ms, p99 < 100 ms), with no server errors. The refusal path
for an unenrolled server costs p50 0.85 ms single-threaded — a gate that cost
more than the thing it guards would be a denial-of-service primitive. The tail
at higher concurrency is SQLite write contention on the audit and provenance
rows, not policy evaluation; PostgreSQL numbers are not claimed here because
they have not been measured.

## What is not built

- **No transparent interception.** The client must be pointed at the proxy
  URL; nothing rewrites traffic that does not arrive here.
- **No `resources/*`, `prompts/*`, sampling or roots.** Refused as
  `NOT_SUPPORTED`, not silently forwarded. Each future method addition must
  arrive with its evaluation, never as bare pass-through.
- **No relay of intermediate SSE traffic.** An upstream answering a POST with
  an SSE stream is parsed for the response that closes the interaction;
  server-initiated requests on that stream are not relayed.
- **No automatic server discovery.** `mcp-discover` contacts a candidate an
  operator names and records it as OBSERVED; nothing scans a network or a
  registry for servers, and nothing is ever enrolled without a second
  deliberate command.
- **No automatic re-pinning.** Drift refuses; a human re-approves.
- **No UI.** `mcp-list` is the only view of enrolled servers.
